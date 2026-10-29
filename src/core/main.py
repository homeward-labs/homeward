"""
家卫 — 核心服务入口

架构:
  collectors (采集层) → analyzer (分析层) → engine (决策层) → actions (动作层)
"""

import asyncio
import json
import logging
import signal
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("homeward")

# 项目根目录
SRC_DIR = Path(__file__).resolve().parent.parent  # src/ 目录（main.py 在 src/core/ 下，parent.parent = src/）
ROOT = SRC_DIR.parent

# 导入各模块
import sys
sys.path.insert(0, str(SRC_DIR))

from knowledge_base.constants import KB_DIR_NAME, BEHAVIORS_JSON

# 知识库目录名取自常量，必须在 constants 导入之后才能使用
KB_DIR = SRC_DIR / KB_DIR_NAME

from rule_engine.engine import (
    KnowledgeBase,
    BehaviorMatcher,
    DecisionEngine,
    FlowRecord,
    Decision,
)
from ai.analyzer import AIAnalyzer, AnalysisRequest, AnalysisResult
from knowledge_base.updater import KnowledgeBaseUpdater
from inventory.device import Device, DeviceRegistry, _SELF_DEVICE_KEY
from inventory.attribution import AttributionResult, DomainAttribution
from core.netclass import is_address_like
from analysis.behavior import BehaviorDetector
from analysis.alerting import Alert, AlertCenter
from analysis.profiler import build_profiles
from adapters.base import ActionRegistry
from adapters.sqlite_registry import SqliteActionRegistry, SqliteObservationStore


# ---------------------------------------------------------------- 观测状态序列化

# 设备 / 归属结果 / 告警 在「内存对象 ↔ 可持久化字典」之间互转的纯函数。
# 集中放在这里，便于快照持久化与报告导出共用，也方便做版本迁移。

def _device_to_state(dev: "Device") -> dict:
    return {
        "key": dev.key,
        "mac": dev.mac,
        "ips": sorted(dev.ips),
        "hostname": dev.hostname,
        "vendor": dev.vendor,
        "vendor_cn": dev.vendor_cn,
        "device_type": dev.device_type,
        "type_source": dev.type_source,
        "first_seen": dev.first_seen,
        "last_seen": dev.last_seen,
        "domains": dict(dev.domains),
    }


def _state_to_device(st: dict) -> "Device":
    dev = Device(key=st.get("key", ""))
    dev.mac = st.get("mac")
    dev.ips = set(st.get("ips") or [])
    dev.hostname = st.get("hostname")
    dev.vendor = st.get("vendor")
    dev.vendor_cn = st.get("vendor_cn")
    dev.device_type = st.get("device_type", "unknown")
    dev.type_source = st.get("type_source", "none")
    dev.first_seen = st.get("first_seen", 0.0) or 0.0
    dev.last_seen = st.get("last_seen", 0.0) or 0.0
    dev.domains = dict(st.get("domains") or {})
    return dev


def _attr_result_to_state(r: "AttributionResult") -> dict:
    return {
        "domain": r.domain,
        "organization": r.organization,
        "category": r.category,
        "confidence": r.confidence,
        "description": r.description,
        "action": r.action,
        "side_effects": list(r.side_effects),
        "matched_domain": r.matched_domain,
        "matched_by": r.matched_by,
    }


def _state_to_attr_result(st: dict) -> "AttributionResult":
    return AttributionResult(
        domain=st.get("domain", ""),
        organization=st.get("organization"),
        category=st.get("category", "unknown"),
        confidence=st.get("confidence", "none"),
        description=st.get("description", ""),
        action=st.get("action", "allow"),
        side_effects=list(st.get("side_effects") or []),
        matched_domain=st.get("matched_domain"),
        matched_by=st.get("matched_by", "none"),
    )


# 「自有 / 局域网」域名后缀：本地网络命名，不是外部外联目的地。
_OWN_DOMAIN_SUFFIXES = (".lan", ".local", ".localdomain", ".home.arpa",
                        ".internal", ".intranet")


def _is_own_domain(d: str) -> bool:
    """是否「自有 / 局域网」域名：本地命名或反向解析，**不构成外部外联**。

    典型例子：自家路由 ``istoreos.lan``、mDNS 的 ``*.local``、内网反向解析
    ``*.in-addr.arpa`` / ``*.ip6.arpa``、``localhost``。

    这些名字本就不需要、也无法在知识库里查到「组织归属」。把它们算进「未知域名」
    只会让数字虚高、在 UI 上制造「有 N 个未知外联」的恐慌 —— 而实际上它们是
    **你自己家里的名字**，根本不是外联。故单独归为「自有」，不计入未知。
    """
    if not d:
        return False
    dl = d.lower().rstrip(".")
    if not dl or dl == "localhost":
        return True
    if dl.endswith(".arpa"):
        return True  # 反向解析（PTR）查询，不是外联目的地
    return any(dl.endswith(sfx) for sfx in _OWN_DOMAIN_SUFFIXES)


def _is_observable_domain(d: str) -> bool:
    """是否应计入覆盖率分母：必须是真正的域名，排除 IP 直连 / 自有局域网名 / 空串。

    直连 IP（如 192.168.1.1、239.255.255.250）和 .lan 主机名不需要、也无法在知识库
    里查到「组织归属」，把它们算进覆盖率分母只会虚假拉低数字，故剔除。
    """
    if not d:
        return False
    if _is_own_domain(d):
        return False
    if is_address_like(d):
        return False
    return True


class HomewardService:
    """家卫 主服务

    命名说明：早期叫 ``IoTSentinel``，两个词都不合适 ——
      · ``IoT`` 前缀与「家庭联网设备」的定位不符（手机 / 电脑同样在观测范围内）；
      · ``Sentinel``（哨兵）属于「守望者 / 执法者」隐喻族，与同类竞品命名撞车，
        本项目刻意避开这一族语义（裁决 / 开合，而非守望）。
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        # 观测状态锁：采集线程（写）与 HTTP / 后台快照线程（读）共享设备台账、
        # 归属缓存、告警中心。dict 在遍历中被并发修改会抛
        # "dictionary changed size during iteration"，所以读写两侧都要持锁。
        # 用 RLock：读路径内部会互相调用（如 export_report → get_stats）。
        self._state_lock = threading.RLock()
        self.kb = KnowledgeBase(str(KB_DIR))
        # 域名归属解析器须在行为匹配器之前建好：crypto_mining 等规则用
        # destination_categories 证据键，需要它把每条流的目标域名归到 KB 类别。
        # required=False：社区版默认不带内容源、不内置知识库（见 constants.KB_SOURCE_DEFAULT_URL），
        # 开箱即可能缺本地 KB 数据；缺失时以空表启动、记告警，服务仍可用、/api/health 正常。
        # 标准版携带数据，required=False 也不影响（文件存在即正常加载）。
        try:
            self.attribution = DomainAttribution(required=False)
            self.behavior_matcher = BehaviorMatcher(
                str(KB_DIR / BEHAVIORS_JSON), attribution=self.attribution, required=False
            )
        except Exception as e:  # 兜底：即便是 required=False 仍异常（如文件存在但损坏），也不让服务起不来
            logger.warning("知识库加载失败，以空表启动（社区版未配置内容源时正常）：%s", e)
            self.attribution = DomainAttribution("__kb_absent__.csv", required=False)
            self.behavior_matcher = BehaviorMatcher(
                "__kb_behaviors_absent__.json", attribution=self.attribution, required=False
            )
        self.engine = DecisionEngine(self.kb, self.behavior_matcher)

        # AI 分析器（默认关闭）
        self.ai = AIAnalyzer(
            backend=self.config.get("ai_backend", "none"),
            api_key=self.config.get("ai_api_key"),
            base_url=self.config.get("ai_base_url"),
        )

        # 知识库更新器
        # 源优先级：config["kb_source"] > 环境变量 HOMEWARD_KB_SOURCE > 默认源。
        # 留空（默认）时行为与之前完全一致，不会意外改变任何人的联网目标。
        self.kb_updater = KnowledgeBaseUpdater(
            kb_dir=str(KB_DIR),
            repo_url=self.config.get("kb_source"),
            # 默认关闭：隐私工具默认不联网，知识库更新需用户显式开启
            auto_update=self.config.get("kb_auto_update", False),
            interval=self.config.get("kb_update_interval", 604800),
        )

        # 建议阻断队列（社区版只产出"建议"，从不产生已生效的阻断规则）
        self.suggested_rules: list[dict] = []
        # 建议去重索引：同一「设备 + 域名」只保留一条建议，避免重复刷屏
        self._suggestion_index: dict[str, dict] = {}

        # W3：行为识别 + 中文告警
        # 行为规则按自己声明的窗口/粒度跑，判定结果进告警中心做去重收敛。
        self.behavior_detector = BehaviorDetector(self.behavior_matcher)
        self.alert_center = AlertCenter(
            cooldown_seconds=self.config.get("alert_cooldown", 1800),
        )
        self._rules_by_id = {
            r["id"]: r for r in self.behavior_matcher.supported_rules
        }
        # 每喂进多少条观测跑一次行为扫描（行为判定是窗口级运算，没必要逐条跑）
        self.behavior_scan_every = int(self.config.get("behavior_scan_every", 20))
        self._flows_since_scan = 0

        # W2：设备台账 + 域名归属
        # 两者都可能在缺少本地数据源时"识别不出东西" —— 那是预期行为，
        # 由 blind_spots() 显式告诉 UI，而不是假装认得。
        self.device_registry = DeviceRegistry(self_ips=self._resolve_self_ips())
        if self.config.get("load_system_devices", True):
            stat = self.device_registry.load_from_system()
            logger.info(f"devices loaded: leases={stat['leases']} arp={stat['arp']}")

        # 设备身份周期刷新（W2 修复，2026-10-19 真机教训）：
        # DHCP 租约 / ARP 表在运行期持续变化（新设备接入、静态 IP 设备首次通信、
        # 租约续期换 IP），而身份数据原先只在 __init__ 读过一次 —— 先被
        # observe_ip 按 IP 兜底建档的设备永远拿不到 MAC，厂商 / 品类识别全部落空
        # （真机表现：设备列表一片裸 IP，UI 只能显示 IP）。
        # 这里起一个低频刷新线程重读租约 + ARP：既补全新接入设备的身份，也给
        # IP 兜底设备回填 MAC（device.py 的 load_arp / load_leases 已支持
        # 「主键迁移 + 观测合并」，重复刷新幂等）。
        # 🔴 为什么不起在 async start() 里：run_server 的生产路径从不调用 start()
        # （见 ui/server.py 与 test_suggestion_persistence.py 的同款注释 ——
        # 「service.start() 从未被调用」正是 suggested_rules 重启清零事故的根因），
        # 挂在从未被调用的方法上 = 刷新永远不生效。故在此直接起，可显式停止。
        self._device_refresh_interval = float(
            self.config.get("device_refresh_interval", 30))
        self._device_refresh_stop = threading.Event()
        self._device_refresh_thread: Optional[threading.Thread] = None
        # 上次刷新时的「台账结构签名」（总台数, 已识别 MAC 台数）：只在变化时打日志，
        # 否则 30s 一行会把路由器的 syslog 淹掉。
        self._device_refresh_sig: Optional[tuple[int, int]] = None
        if self.config.get("load_system_devices", True):
            self.start_device_refresh()

        # 统计
        self.stats = {
            "flows_processed": 0,
            "decisions_made": 0,
            "suggestions_pending": 0,
            "unknown_domains": set(),
        }

        # F6 设备画像缓存：None 表示尚未计算过（首次访问时才算）
        self._profiles = None
        self._profiles_ts = 0.0
        self._profile_ttl = float(self.config.get("profile_ttl_seconds", 15))

        # F7 域名归类：用户手动标记 domain -> "own"(自有) / "benign"(良性)。
        # 自动判定的「自有/局域网」见 _is_own_domain()，不进这张表（那是结构性的、无需存）。
        # 落盘持久化：标记是用户的判断，重启不该丢。
        self._domain_marks: dict[str, str] = {}
        self._load_domain_marks()

        # 采集可用性：由 CollectorRunner 写入，供 /api/overview 的盲区视图
        # 如实展示「当前到底有几个采集器在干活、哪个不可用」（看不见要说清楚）
        self.collection_status: list[dict] = []

        # —— Tier 1 + Tier 2 合并：DNS ↔ IP 双向关联缓存 ——
        # Tier 1 DNS flow 产出 domain → dst_ip 映射，写入这里；
        # Tier 2 conntrack flow 只有 dst_ip（没有域名），从这里反查域名填回 flow.dns_query。
        # 30 分钟 TTL：DNS 查询与连接通常时间接近，太久远的映射会误导。
        # 用 dict + 内联 TTL 字段，不引第三方 cache 库。
        self._dns_ip_cache: dict[str, dict] = {}       # dst_ip -> {domain, ts}
        self._dns_domain_cache: dict[str, dict] = {}   # domain -> {dst_ip, ts}
        self._dns_cache_ttl = float(self.config.get("dns_cache_ttl", 1800))

        # 动作注册表（SQLite 持久化）：进程重启不丢动作记录，避免孤儿规则。
        # 社区版只产出「建议」不产生已生效阻断，但标准版接同一服务时这条记录就关键了。
        # 演示模式（actions_db_path=None）用纯内存注册表：与 observations.db 的处理
        # 保持一致，避免一次 --demo 把演示动作写进真实动作库污染生产数据。
        act_db = self.config.get("actions_db_path", ROOT / "data" / "actions.db")
        if act_db is None:
            self.action_registry = ActionRegistry()
        else:
            self.action_registry = SqliteActionRegistry(act_db)
            restored = self.action_registry.restore_all()
            if restored:
                logger.info(f"已从 SQLite 恢复 {len(restored)} 条动作记录")

        # 由信号处理器置位，由事件循环侧的关闭逻辑消费
        self._shutdown_requested = False

        logger.info(f"家卫 initialized with {len(self.kb.domains)} domain rules")

    async def start(self):
        """启动服务"""
        logger.info("Starting 家卫...")

        # 启动知识库更新
        self.kb_updater.start()

        # 加载待确认的建议阻断队列
        self._load_suggestions()

        # 注册信号处理
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("家卫 started successfully")

    async def stop(self):
        """停止服务"""
        logger.info("Stopping 家卫...")
        self.kb_updater.stop()
        self.stop_device_refresh()
        self._save_suggestions()
        logger.info("家卫 stopped")

    # ---------------------------------------------------------------- W2 设备身份刷新

    def start_device_refresh(self) -> None:
        """启动设备身份周期刷新线程（幂等）。

        interval <= 0 表示关闭刷新（测试 / 演示可用）；已在跑则直接返回。
        """
        if self._device_refresh_interval <= 0:
            return
        if self._device_refresh_thread is not None and self._device_refresh_thread.is_alive():
            return
        self._device_refresh_stop.clear()
        t = threading.Thread(target=self._device_refresh_loop,
                             name="homeward-device-refresh", daemon=True)
        self._device_refresh_thread = t
        t.start()
        logger.info("设备身份刷新已启动（每 %.0fs 重读 DHCP 租约 / ARP）",
                    self._device_refresh_interval)

    def stop_device_refresh(self) -> None:
        """停止设备身份刷新线程（幂等；未启动也安全）。"""
        self._device_refresh_stop.set()
        t = self._device_refresh_thread
        if t is not None and t.is_alive():
            t.join(timeout=5)
        self._device_refresh_thread = None

    def _device_refresh_loop(self) -> None:
        """周期重读租约 / ARP：补全新设备身份，把 IP 兜底设备升级回 MAC 主键。

        失败不退出线程：采集文件可能暂时不可读（路由器重启中、leases 被清空），
        下个周期再试即可。单次失败不应演变成「从此再不识别设备」。
        """
        while not self._device_refresh_stop.wait(self._device_refresh_interval):
            try:
                with self._state_lock:
                    stat = self.device_registry.load_from_system()
                    devices = self.device_registry.devices
                    total = len(devices)
                    with_mac = sum(1 for d in devices.values() if d.mac)
                sig = (total, with_mac)
                if sig != self._device_refresh_sig:
                    logger.info(
                        "设备身份刷新：租约 %d / ARP %d → 台账 %d 台（%d 台已识别 MAC）",
                        stat["leases"], stat["arp"], total, with_mac)
                    self._device_refresh_sig = sig
            except Exception:
                logger.exception("设备身份刷新失败（下个周期重试）")

    def process_flow(self, flow: FlowRecord) -> Decision:
        """
        处理一条流量记录
        这是核心入口，被采集层调用

        社区版**只产出建议，绝不自行下发阻断**：产品承诺「不默认自动阻断，一切以你
        确认为准」。        这里即使命中了阻断类规则，也只是把建议放进队列等用户确认。
        """
        with self._state_lock:
            return self._process_flow_locked(flow)

    def _process_flow_locked(self, flow: FlowRecord) -> Decision:
        """``process_flow`` 的实现体（调用方必须已持有 ``_state_lock``）。"""
        self.stats["flows_processed"] += 1

        # —— Tier 1 + Tier 2 关联层 ——
        # Tier 1 DNS flow（有 dns_query、dst_ip）→ 写入双向缓存
        # Tier 2 conntrack flow（没 dns_query）→ 从 IP 缓存反查域名回填
        now = flow.timestamp or time.time()
        if flow.dns_query and flow.dst_ip:
            # 清旧：同一 IP 在缓存里可能指向不同域名（设备刚换联网目标），直接覆盖即可
            self._dns_ip_cache[flow.dst_ip] = {"domain": flow.dns_query, "ts": now}
            self._dns_domain_cache[flow.dns_query] = {"dst_ip": flow.dst_ip, "ts": now}
        elif flow.dst_ip and not flow.dns_query:
            # Tier 2 conntrack flow：查缓存回填域名
            entry = self._dns_ip_cache.get(flow.dst_ip)
            if entry and (now - entry.get("ts", 0)) < self._dns_cache_ttl:
                flow.dns_query = entry["domain"]
            # 顺便清过期（1% 概率，避免每条都扫）
            if not entry or (now - entry.get("ts", 0)) >= self._dns_cache_ttl:
                if len(self._dns_ip_cache) > 128:  # 攒够 128 条再清
                    self._purge_dns_cache(now)

        # W2：把这条流量归到某台设备上，并解析域名归属
        self.device_registry.observe_flow(flow)

        # W3：同一条观测也喂给行为窗口（与域名判定正交 —— 一个看"是谁"，一个看"在干什么"）
        self.behavior_detector.feed(flow)
        self._flows_since_scan += 1
        if self._flows_since_scan >= self.behavior_scan_every:
            self._flows_since_scan = 0
            self.run_behavior_scan(now=flow.timestamp)

        decision = self.engine.evaluate(flow)
        self.stats["decisions_made"] += 1

        if decision.action == "unknown":
            # 未知域名可能来自 SNI（Tier3）或 DNS 查询（Tier1）；真实 DNS 采集器
            # 只填 dns_query、sni 为 None，所以两者都要认，否则生产环境 DNS 查出的
            # 未知域名不会进「未知域名」视图（演示数据因同时填了 sni 才没暴露）
            unknown = flow.sni or flow.dns_query
            if unknown:
                self.stats["unknown_domains"].add(unknown)

        # 命中阻断类规则 → 降级为「建议」，等待用户在 UI 上确认
        if decision.action.startswith("block"):
            self._record_suggestion(flow, decision)

        return decision

    def _purge_dns_cache(self, now: float) -> None:
        """清过期 DNS↔IP 缓存项（攒够阈值才扫，避免每条 flow 都全表扫描）。"""
        ttl = self._dns_cache_ttl
        self._dns_ip_cache = {
            ip: e for ip, e in self._dns_ip_cache.items()
            if (now - e.get("ts", 0)) < ttl
        }
        self._dns_domain_cache = {
            d: e for d, e in self._dns_domain_cache.items()
            if (now - e.get("ts", 0)) < ttl
        }

    @staticmethod
    def _suggestion_key(domain: str, device: str) -> str:
        return f"{domain}|{device}"

    def _rebuild_suggestion_index(self) -> None:
        """从 ``suggested_rules`` 重建去重索引（启动加载 / 反序列化后调用）"""
        self._suggestion_index = {
            self._suggestion_key(r.get("domain", ""), r.get("device", "")): r
            for r in self.suggested_rules
            if isinstance(r, dict) and r.get("domain") and r.get("device")
        }

    def _record_suggestion(self, flow: FlowRecord, decision: Decision):
        """把「建议阻断」写入待确认队列 —— 社区版到此为止，不碰任何网络配置

        同一「设备 + 域名」只保留一条建议、次数累加（occurrences）：真实场景里同一信标
        （如 ``otheve.beacon.qq.com``）会被命中几十次，若每条都追加，建议列表会刷成
        15 条同域名，既难看又掩盖了真正不同的建议。

        真实下发属于**标准版（闭源付费）**，经由 ``src/adapters/base.py`` 的
        ``Enforcer.apply(action)`` + ``ActionRegistry`` 完成；本仓库不实现、也不调用
        任何 nftables / dnsmasq 写入操作。此处若出现真实下发代码，即为开源边界事故。
        """
        hit = decision.rule_hits[0] if decision.rule_hits else None
        domain = flow.sni or flow.dns_query
        device = flow.src_ip
        key = self._suggestion_key(domain, device)
        existing = self._suggestion_index.get(key)
        if existing is not None:
            # 同设备 + 同域名：只更新计数与结论，不新增条目
            existing["occurrences"] = int(existing.get("occurrences", 1)) + 1
            existing["reason"] = decision.reason
            if hit:
                existing["side_effects"] = hit.side_effects
            existing["last_seen"] = getattr(flow, "timestamp", None)
            self.maybe_save_suggestions()
            return
        rule = {
            "domain": domain,
            "device": device,
            "level": decision.action,
            "reason": decision.reason,
            "source": hit.rule_type if hit else "manual",
            "side_effects": hit.side_effects if hit else "",
            "status": "suggested",  # 等待用户确认；社区版不会把它变成 applied
            "occurrences": 1,
            "first_seen": getattr(flow, "timestamp", None),
            "last_seen": getattr(flow, "timestamp", None),
        }
        self.suggested_rules.append(rule)
        self._suggestion_index[key] = rule
        self.stats["suggestions_pending"] += 1
        # 周期落盘：不依赖退出路径，避免"重启即清零"
        self.maybe_save_suggestions()
        logger.info(f"[SUGGEST] {rule['domain']} → {decision.reason}（等待用户确认）")

    # ---------------------------------------------------------------- W2 本机身份

    def _resolve_self_ips(self) -> set[str]:
        """算出「跑家卫的那台设备」自身占用的 IP，用于设备合并与告警降级。

        优先级：配置 ``homeward_self_ips``（显式、最可靠）> 主机名尽力解析（含 LAN IP，
        避免每次都靠手配）。只取非回环地址；回环/链路本地等噪声地址由 netclass 另走合并。

        注意：容器内无法 100% 可靠判定哪个私网 IP 是宿主（见 FEATURE-EVOLUTION §5.3），
        故显式配置仍是推荐路径；这里做尽力而为的自动兜底。
        """
        ips: set[str] = set()
        cfg = self.config.get("homeward_self_ips")
        if isinstance(cfg, str) and cfg.strip():
            for part in cfg.split(","):
                p = part.strip()
                if p:
                    ips.add(p)
        try:
            import socket
            host = socket.gethostname()
            for info in socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip and ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                    ips.add(ip)
        except Exception:  # 解析失败不应阻断启动
            pass
        return ips

    # ---------------------------------------------------------------- W3 行为与告警

    def run_behavior_scan(self, now: Optional[float] = None) -> list:
        """跑一轮行为识别，把命中的行为渲染成中文告警收进告警中心

        返回本轮**新建**的告警（重复命中的只是更新，不占新条目）。
        传入 ``now`` 是为了让离线回放 / 单测能按数据里的时间戳判定，而不是按挂钟时间。
        """
        with self._state_lock:
            findings = self.behavior_detector.scan(now=now)
            new_alerts = self.alert_center.ingest(
                findings,
                device_view_of=self.get_device,
                attribution_of=self.describe_domain,
                rule_of=lambda rid: self._rules_by_id.get(rid, {}),
                is_self_ip=self.device_registry.is_self_ip,
                now=now,
            )
        for alert in new_alerts:
            logger.info(
                f"[ALERT][{alert.severity_label}] {alert.device_name} → "
                f"{alert.destination}：{alert.title}"
            )
        return new_alerts

    def get_alerts(self, include_dismissed: bool = False) -> list[dict]:
        """给 UI / API 用的告警视图（已按严重度排序）"""
        with self._state_lock:
            items = (self.alert_center.all() if include_dismissed
                     else self.alert_center.active())
            return [a.to_dict() for a in items]

    def dismiss_alert(self, alert_id: str) -> bool:
        """忽略一条告警"""
        with self._state_lock:
            return self.alert_center.dismiss(alert_id)

    def reset_observations(self) -> dict:
        """清空全部观测态（设备 / 归属缓存 / 未知域名 / 告警），只动内存。

        不触碰动作注册表（actions.db，许可指纹）与知识库。落盘快照由调用方
        （Web handler 持有 ``observation_store``）随后一并 clear。

        用途：用户想"重新分析"——把修复前的旧证据与重新采集到的新数据彻底分开。
        清完后实时流量会重新建档，所以"清除后看到的"保证是全新的。
        """
        with self._state_lock:
            before = {
                "devices": len(self.device_registry.devices),
                "alerts": len(self.alert_center.active()),
                "unknown_domains": len(self.stats["unknown_domains"]),
            }
            n_dev = self.device_registry.clear()
            n_attr = self.attribution.clear_cache()
            n_alert = self.alert_center.clear()
            self.stats["unknown_domains"].clear()
            after = {
                "devices": len(self.device_registry.devices),
                "alerts": len(self.alert_center.active()),
                "unknown_domains": len(self.stats["unknown_domains"]),
            }
            logger.info("已清空观测态：设备 %d / 归属缓存 %d / 告警 %d",
                        n_dev, n_attr, n_alert)
            return {"before": before, "after": after, "cleared": {
                "devices": n_dev, "attribution_cache": n_attr, "alerts": n_alert,
            }}

    def get_alert_stats(self) -> dict:
        """告警统计：数量、按严重度分布、模板渲染是否健康"""
        with self._state_lock:
            missing = sorted({
                k for a in self.alert_center.active() for k in a.missing_keys
            })
            return {
                "active": len(self.alert_center.active()),
                "by_severity": self.alert_center.counts_by_severity(),
                "created": self.alert_center.stats["created"],
                "updated": self.alert_center.stats["updated"],
                "behaviors_supported": len(self.behavior_matcher.supported_rules),
                "behaviors_unsupported": self.behavior_matcher.unsupported(),
                # 正常应为空；非空说明文案与渲染器脱节
                "missing_template_keys": missing,
            }

    def request_ai_analysis(self, domain: str, behavior: dict) -> Optional[AnalysisResult]:
        """
        用户手动触发的 AI 分析
        """
        if not self.ai.is_enabled():
            logger.warning("AI analyzer is not enabled. Please configure backend first.")
            return None

        request = AnalysisRequest(
            domain=domain,
            total_connections=behavior.get("total_connections", 0),
            total_bytes=behavior.get("total_bytes", 0),
            time_span_hours=behavior.get("time_span_hours", 0),
            avg_interval_seconds=behavior.get("avg_interval_seconds", 0),
            destination_asn=behavior.get("asn"),
            destination_country=behavior.get("country"),
        )

        result = self.ai.analyze(request)
        if result:
            logger.info(f"[AI] {domain} → {result.predicted_organization} ({result.category}, {result.confidence})")
        return result

    def confirm_ai_result(self, result: AnalysisResult) -> bool:
        """
        用户确认 AI 分析结果后，回灌到知识库
        生成一条可审核的规则草稿
        """
        # 写入待审核目录（人工 review 后合入主库）
        pending_dir = KB_DIR / "pending"
        pending_dir.mkdir(exist_ok=True)

        rule = {
            "domain": result.domain,
            "organization": result.predicted_organization,
            "category": result.category,
            "confidence": result.confidence,
            "description": result.explanation,
            "action": result.suggested_action,
            "side_effects": result.side_effects,
        }

        fname = pending_dir / f"{result.domain}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(rule, f, ensure_ascii=False, indent=2)

        logger.info(f"[AI] Result saved to pending: {fname}")
        return True

    # ---------------------------------------------------------------- W2 查询接口

    def get_device(self, ip: str) -> Optional[dict]:
        """给 UI / 告警用的设备视图：查不到 MAC 也会返回一个 IP 兜底设备"""
        with self._state_lock:
            # observe_ip 会往台账里插新设备（写操作），必须持锁
            dev = self.device_registry.get_by_ip(ip)
            if dev is None:
                dev = self.device_registry.observe_ip(ip)
        return {
            "name": dev.display_name,
            "mac": dev.mac,
            "ips": sorted(dev.ips),
            "vendor": dev.vendor_cn or dev.vendor,
            "device_type": dev.device_type,
            "type_source": dev.type_source,
            "top_domains": dev.top_domains(10),
        }

    def get_devices(self) -> list[dict]:
        """
        设备台账视图 + F6 设备画像 / 风险分级。

        排序按「风险高的在前，同级按观测次数」—— 用户打开设备页第一眼看到的
        应该是**最值得看一眼的那台**，而不是最近碰巧发了条查询的那台。

        画像要逐域名查归属，代价随域名数线性增长；UI 轮询没必要每次重算，
        故带 TTL 缓存（默认 15 秒）。告警/归属变化最多延迟一个 TTL 反映，
        这对「画像」这种概览视图是可接受的（告警页本身是实时的）。
        """
        with self._state_lock:
            devices = list(self.device_registry.list_devices())
            now = time.time()
            if self._profiles is None or now - self._profiles_ts >= self._profile_ttl:
                alert_dicts = [a.to_dict() for a in self.alert_center.active()]
                self._profiles = build_profiles(
                    devices, self.attribution.resolve, alert_dicts)
                self._profiles_ts = now
            profiles = self._profiles

            # 台账与画像都在锁内取：采集线程可能正在插入新设备，
            # 锁外遍历 devices dict 有 RuntimeError 风险
            by_key = {d.key: d for d in devices}
            items: list[dict] = []
            covered: set[str] = set()
            for p in profiles:
                dev = by_key.get(p.key)
                if dev is None:
                    continue
                covered.add(p.key)
                items.append({**dev.to_dict(), **p.to_dict()})
            # 极少数情况下台账里可能有画像没覆盖到的设备（并发插入），补在末尾，不丢数据
            for dev in devices:
                if dev.key not in covered:
                    items.append(dev.to_dict())
        return items

    def get_destinations(self) -> dict:
        """去向地图：域名 → 组织 → 哪些设备在跟它说话

        只报**真实观测到过**的边；归属查不到就如实标 unknown，不做相似域名猜测。
        """
        # 遍历设备台账期间采集线程可能正在插入新设备，须持锁并先取快照
        with self._state_lock:
            device_snapshot = list(self.device_registry.devices.values())

        edges: dict[str, list[dict]] = {}
        for dev in device_snapshot:
            # dev.domains 也会被采集线程并发改写，逐台取副本
            for domain, count in list(dev.domains.items()):
                edges.setdefault(domain, []).append({
                    "name": dev.display_name,
                    "ip": next(iter(sorted(dev.ips)), ""),
                    "count": count,
                })

        with self._state_lock:
            items = []
            seen: set[str] = set()
            for r in self.attribution.resolved_view():
                seen.add(r["domain"])
                items.append({**r, "devices": edges.get(r["domain"], [])})
            # 缓存里没有、但设备确实访问过的域名（例如缓存被整体清空过）也要补上
            for domain in sorted(set(edges) - seen):
                items.append({**self.describe_domain(domain), "devices": edges[domain]})
            # 判定为 unknown 的单次观测同样要露出来 —— 「不知道」也是一种结论
            for domain in self.get_unknown_domains():
                if domain in seen or domain in edges:
                    continue
                items.append({**self.describe_domain(domain), "devices": []})

        items.sort(key=lambda x: (-len(x["devices"]), x["domain"]))
        known = sum(1 for x in items if x["known"])
        return {
            "items": items,
            "total": len(items),
            "known": known,
            "hit_rate": (known / len(items)) if items else 0.0,
        }

    def describe_domain(self, domain: str) -> dict:
        """域名归属视图；未知时 organization 为 None，上层应把它交给未知域名列表"""
        # attribution 无自有锁，resolve() 会写 _cache 字典、缓存满（4096）时整体 clear()
        # —— 无锁调用方（/api/domain）与持锁读方（get_destinations 的 resolved_view、
        # attribution_coverage 的 cached_domains、snapshot_observations 的 cached_results）
        # 并发时，clear() 撞上迭代会抛 "dictionary changed size during iteration"。
        # 包上主锁后 _cache 的读写即被序列化（RLock，嵌套调用安全）。
        with self._state_lock:
            r = self.attribution.resolve(domain or "")
            return {
                "domain": r.domain,
                "organization": r.organization,
                "category": r.category,
                "confidence": r.confidence,
                "known": r.known,
                "side_effects": r.side_effects,
                "explain": r.explain(),
            }

    # ---------------------------------------------------------------- F7 域名归类

    def _marks_path(self) -> Path:
        """域名标记落盘路径（可用 ``marks_path`` 配置覆盖，便于测试与只读根fs）"""
        override = self.config.get("marks_path")
        if override:
            return Path(override)
        return ROOT / "data" / "domain_marks.json"

    def _load_domain_marks(self) -> None:
        """载入用户标记过的域名（own / benign）"""
        p = self._marks_path()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            logger.warning("读取域名标记失败（%s），本次按空标记继续", p)
            return
        if isinstance(data, dict):
            self._domain_marks = {
                str(k).lower(): v for k, v in data.items() if v in ("own", "benign")
            }

    def _save_domain_marks(self) -> None:
        """持久化用户标记。失败只告警 —— 标记丢了不影响观测，不能因此崩掉服务。"""
        p = self._marks_path()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(self._domain_marks, ensure_ascii=False, indent=2),
                         encoding="utf-8")
        except OSError:
            logger.warning("保存域名标记失败（%s）：本次标记仅存在于内存", p)

    def _domain_kind(self, domain: str) -> Optional[str]:
        """域名归类：``own``（自有/局域网）| ``benign``（用户标记良性）| None（真正未知）。

        ``own`` 优先走结构性判定（.lan/.local/.arpa 等，见 :func:`_is_own_domain`），
        其次看用户是否手动标为自有；``benign`` 只来自用户显式标记 ——
        **系统绝不自动把外部域名判为良性**（误判良性 = 漏报，比多列几个未知更危险）。
        """
        if not domain:
            return None
        if _is_own_domain(domain):
            return "own"
        return self._domain_marks.get(domain.lower())

    def mark_domain(self, domain: str, kind: str) -> bool:
        """把域名标记为 ``own`` / ``benign``；``kind`` 为空串表示**取消标记**。

        这是 F7 的「用户可确认、可撤销」入口：家卫不替用户猜，但用户说
        「这个是我自己的 / 这个是更新源」之后必须生效、且能随时撤回。
        """
        d = (domain or "").strip().lower()
        kind = (kind or "").strip().lower()
        if not d or kind not in ("own", "benign", ""):
            return False
        with self._state_lock:
            if kind:
                self._domain_marks[d] = kind
            else:
                self._domain_marks.pop(d, None)
        self._save_domain_marks()
        return True

    def _unknown_domains_locked(self) -> list[str]:
        """真正未知的域名（调用方须持有 ``_state_lock``）：已剔除自有与已标记良性。"""
        return sorted(d for d in self.stats["unknown_domains"]
                      if self._domain_kind(d) is None)

    def get_classified_domains(self) -> dict:
        """未知域名按「未知 / 自有 / 良性」分桶。

        目的：**别把自家路由（istoreos.lan）也算成「未知外联」吓人**。
        自有 = 结构性本地命名；良性 = 用户显式标记；其余才是真正需要关注的未知。
        """
        with self._state_lock:
            unknown: list[str] = []
            own: list[str] = []
            benign: list[str] = []
            for d in sorted(self.stats["unknown_domains"]):
                k = self._domain_kind(d)
                if k == "own":
                    own.append(d)
                elif k == "benign":
                    benign.append(d)
                else:
                    unknown.append(d)
        return {"unknown": unknown, "own": own, "benign": benign}

    def get_unknown_domains(self) -> list[str]:
        """获取所有未识别域名（已剔除自有/局域网与用户标记的良性域名）"""
        with self._state_lock:
            return self._unknown_domains_locked()

    def get_domain_marks(self) -> dict:
        """用户**手动**标记的域名 → ``own`` / ``benign``。

        UI 用它判断某个「自有」域名是结构性自动判定的（不可取消）
        还是用户手动标的（可取消）—— 避免给自动项摆一个点了没用的按钮。
        """
        with self._state_lock:
            return dict(self._domain_marks)

    def get_blind_spots(self) -> list[str]:
        """当前部署形态下，家卫**看不见 / 认不出**的地方 —— UI 必须展示"""
        # device_registry.blind_spots() 要遍历设备台账，而采集线程（process_flow /
        # 租约刷新）会并发增删设备 —— 不持锁遍历可能抛
        # "dictionary changed size during iteration"（export_report 读路径实测复现）。
        # _state_lock 是 RLock，下方 attribution_coverage() 再取锁嵌套安全。
        with self._state_lock:
            spots = list(self.device_registry.blind_spots())
            cov = self.attribution_coverage()
            if cov["total"] and cov["hit_rate"] < 0.8:
                spots.append(f"域名归属覆盖偏低：观测到的 {cov['total']} 个域名里 "
                             f"只有 {cov['hit']} 个能在知识库中查到组织，"
                             f"其余 {cov['total'] - cov['hit']} 个仍属未知（可手动触发 AI 分析）。")
            return spots

    def attribution_coverage(self) -> dict:
        """归属覆盖率：衡量知识库够不够用，也是社区共建的进度指标。

        口径统一为「观测到过的全部域名」：设备台账去向 ∪ 未知域名 ∪ 归属缓存，
        三者取并集（不再混用「当前窗口」与「累计」两套分母）。
        同时剔除内网地址 / 直连 IP / .lan 这类「不需要归属」的项，避免分母被灌水、
        虚假拉低覆盖率（实机曾出现 5.56% 与 57% 并存）。
        """
        with self._state_lock:
            observed = set()
            for dev in self.device_registry.devices.values():
                if dev.key == _SELF_DEVICE_KEY:
                    continue
                observed |= set(dev.domains.keys())
            observed |= self.stats["unknown_domains"]
            observed |= self.attribution.cached_domains()
            # 只保留「真正的域名」：排除 IP 直连 / .lan 主机名 / 空串
            observed = {d for d in observed if d and _is_observable_domain(d)}
            # coverage() 内部会对首见域名 resolve 并写 attribution._cache（无自有锁）——
            # 与上面的台账遍历同属共享状态，必须在锁内序列化。曾经的疏漏：该调用在
            # with 块外执行，CPython 上因读方 C 原子而观测不到，free-threaded 下会相撞。
            rep = self.attribution.coverage(observed)
        return {
            "total": rep.total,
            "hit": rep.hit,
            "hit_rate": rep.rate,
            "by_parent": rep.by_parent,
        }

    def visibility_coverage(self) -> dict:
        """设备观测覆盖比：衡量「看得见」—— 已发现设备里有多少留下过域名级观测。

        与 :func:`attribution_coverage`（知识库厚度，衡量「看得懂」）是两件事，
        分母不同、不可互相替代：归属命中率的分母只是「我们已经看见的域名」，
        而这个指标的分母是「已经发现的设备」。

        口径（快照语义，随台账实时变化）：
            可见 X         = 在册设备中 domains 非空的台数（剔除「本机」设备）
            疑似不可见 Y   = domains 为空的台数（剔除「本机」设备）
            分母           = X + Y = 当前在册设备总数
        分母诚实性：只含 DHCP 租约 / ARP / 流量兜底能发现的设备；
        「从未被发现的设备」不在分母，比例只是下界。

        no_mac / random_mac / no_identity 只统计 Y 集合，用于解释 Y 的可能构成
        （三类互相重叠，且 Y 也包含「当期闲置」这种非盲区），不进比例算术。

        注意：Y 叫「疑似」不可见而不是「不可见」—— domains 为空只说明没观测到
        域名级外联，可能是设备当期没发任何查询（闲置），现有数据无法区分成因，
        UI 必须把四种可能成因列清楚，不能让用户以为 Y 台全是盲区。
        """
        with self._state_lock:
            visible = suspected = no_mac = random_mac = no_identity = 0
            for dev in self.device_registry.devices.values():
                if dev.key == _SELF_DEVICE_KEY:
                    continue
                if dev.domains:
                    visible += 1
                    continue
                suspected += 1
                if not dev.mac:
                    no_mac += 1
                if dev.random_mac:
                    random_mac += 1
                if not dev.hostname and not dev.vendor:
                    no_identity += 1
            total = visible + suspected
            rate = round(visible / total, 4) if total else 0.0
        return {
            "visible": visible,
            "suspected_invisible": suspected,
            "total": total,
            "rate": rate,
            "no_mac": no_mac,
            "random_mac": random_mac,
            "no_identity": no_identity,
            "denominator_note": "仅统计已发现设备（DHCP 租约/ARP/流量兜底）；"
                                "从未被发现的设备不在分母，比例为当前快照",
        }

    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._state_lock:
            return self._get_stats_locked()

    def _get_stats_locked(self) -> dict:
        """``get_stats`` 的实现体（调用方必须已持有 ``_state_lock``）。"""
        # F7：未知域名已剔除「自有/局域网」与用户标记的良性域名 —— 避免把自家路由
        # （istoreos.lan）当成未知外联计入，既不虚高数字、也不制造恐慌。
        unknowns = self._unknown_domains_locked()
        return {
            **self.stats,
            "collection": self.collection_status,
            "unknown_domains_count": len(unknowns),
            "unknown_domains": unknowns,
            "own_domains": sorted(d for d in self.stats["unknown_domains"]
                                  if self._domain_kind(d) == "own"),
            "benign_domains": sorted(d for d in self.stats["unknown_domains"]
                                     if self._domain_kind(d) == "benign"),
            "devices_total": len(self.device_registry.devices),
            "vendors_resolved": sum(
                1 for d in self.device_registry.devices.values() if d.vendor
            ),
            "vendor_lookup_enabled": self.device_registry.vendor_lookup_enabled,
            "attribution_queries": self.attribution.stats["queries"],
            "alerts_active": len(self.alert_center.active()),
            "alerts_by_severity": self.alert_center.counts_by_severity(),
            "behaviors_supported": len(self.behavior_matcher.supported_rules),
            "behaviors_unsupported": len(self.behavior_matcher.unsupported_rules),
        }

    # ---------------------------------------------------------------- 观测状态持久化

    def snapshot_observations(self) -> dict:
        """导出当前观测状态（仅用户自己的遥测），供持久化 / 报告复用。

        不含知识库：这里只用到了「用户观测到的域名 + 其在本地查到的归属结论」
        （即 :class:`AttributionResult` 里的组织名），不导出知识库本体。
        """
        # 后台快照线程每 60s 调一次，与采集线程并发：持锁并先做浅拷贝，
        # 避免遍历过程中 dict 被改写而抛 RuntimeError。
        with self._state_lock:
            reg = self.device_registry
            attr_cache = [_attr_result_to_state(r)
                          for r in self.attribution.cached_results()]
            return {
                "version": 1,
                "saved_at": time.time(),
                "devices": {k: _device_to_state(d)
                            for k, d in list(reg.devices.items())},
                "attribution_cache": attr_cache,
                "unknown_domains": sorted(self.stats["unknown_domains"]),
                "alerts": [a.to_dict() for a in self.alert_center.active()],
            }

    def restore_observations(self, state: dict) -> int:
        """从快照恢复观测状态（合并式：不覆盖系统刚加载的设备 / 租约）。

        返回恢复的设备 + 告警数量（用于日志）。知识库本体不参与还原。
        """
        with self._state_lock:
            return self._restore_observations_locked(state)

    def _restore_observations_locked(self, state: dict) -> int:
        """``restore_observations`` 的实现体（调用方必须已持有 ``_state_lock``）。"""
        if not state:
            return 0
        reg = self.device_registry
        restored_devices = 0
        for k, st in (state.get("devices") or {}).items():
            if k in reg.devices:
                continue  # 系统已加载的设备（如当前 DHCP 租约）优先，避免覆盖
            reg.devices[k] = _state_to_device(st)
            restored_devices += 1
        reg.reindex()

        # 归属缓存：合并（已存在的覆盖）。
        # 关键：快照里的旧结论必须拿**当前知识库**重判 —— 知识库会随版本扩量
        # （实机教训：补录 GitHub 生态后，旧快照的「未知」若原样 put() 回缓存，
        # 会永久顶住新规则，面板永远显示未知）。已知的新结论优先，旧的「未知」不落缓存。
        for st in (state.get("attribution_cache") or []):
            old = _state_to_attr_result(st)
            fresh = self.attribution.resolve(old.domain)
            if not fresh.known and old.known:
                # 知识库反而收窄（理论上不该发生）：保留旧的已知结论，不丢信息
                self.attribution.put(old)

        # 未知域名：取并集，但先剔除当前知识库已能归属的 ——
        # 否则域名一旦进过未知名单，知识库补录后会仍然挂在「未知域名」列表里
        unknown_set = {
            d for d in (state.get("unknown_domains") or [])
            if not self.attribution.resolve(d).known
        }
        self.stats["unknown_domains"] |= unknown_set

        # 告警：合并（已存在的跳过）
        restored_alerts = 0
        for d in (state.get("alerts") or []):
            aid = d.get("alert_id")
            if not aid or self.alert_center.has(aid):
                continue
            try:
                if self.alert_center.restore(Alert(**d)):
                    restored_alerts += 1
            except (TypeError, KeyError):
                logger.warning("跳过一条无法还原的告警快照：%s", aid)
        logger.info("已恢复观测快照：设备 %d 台、告警 %d 条",
                    restored_devices, restored_alerts)
        return restored_devices + restored_alerts

    def privacy_checkup(self) -> dict:
        """一键隐私体检：结论先行，把一堆数字压成一句话结论 + 几个关键指标。

        这是「看见 → 理解」的关键一步：让人一眼知道「我家现在隐私状况怎么样」，
        而不是面对一堆原始统计发呆。打分规则刻意透明、可解释（见下方扣分逻辑），
        不是黑箱分数 —— 每一项扣分都对应界面上能看到的具体事实。
        """
        with self._state_lock:
            stats = self._get_stats_locked()
            cov = self.attribution_coverage()
            # 设备观测覆盖（「看得见」）：与归属命中率（「看得懂」）分开展示。
            # 刻意不计入 score 扣分 —— 低可见性往往是部署形态（旁路 / 单播 DNS）
            # 的结构性上限，不是用户的隐私失误，用它扣分等于用部署形态惩罚用户。
            vis = self.visibility_coverage()
            alerts = self.alert_center.active()
            # 已剔除自有/局域网与用户标记良性的域名（见 _unknown_domains_locked）
            unknowns = stats["unknown_domains"]
            blind_n = len(self.get_blind_spots())

        high = [a for a in alerts if a.severity in ("high", "critical")]
        rate = cov["hit_rate"]
        score = 100
        # 高危/严重告警是头号风险信号：每条扣 12 分，最多扣到 5 条封顶
        score -= min(len(high), 5) * 12
        # 归属覆盖率低于 50% 说明「看不懂家里一半的外联」，按比例扣分
        if rate < 0.5:
            score -= int((0.5 - rate) * 40)
        # 未知域名过多：超过 30 个后每 10 个扣 1 分（最多扣 20）
        if len(unknowns) > 30:
            score -= min((len(unknowns) - 30) // 10, 20)
        score = max(0, min(100, score))
        verdict = "基本可控" if score >= 80 else ("需要关注" if score >= 50 else "风险较高")

        return {
            "score": score,
            "verdict": verdict,
            "devices_total": stats["devices_total"],
            "vendors_resolved": stats["vendors_resolved"],
            "alerts_active": len(alerts),
            "alerts_high": len(high),
            "coverage_hit": cov["hit"],
            "coverage_total": cov["total"],
            "coverage_rate": rate,
            "visible_devices": vis["visible"],
            "suspected_invisible_devices": vis["suspected_invisible"],
            "unknown_count": len(unknowns),
            "top_unknown": unknowns[:5],
            "blind_spots": blind_n,
        }

    def export_report(self) -> dict:
        """导出一份「观测报告」结构化数据 —— 只含用户自己的观测遥测。

        结论先行：``checkup`` 段放在最前，一眼看到整体判断；后面才是分项明细。

        安全边界（见 open-core 约定）：**绝不 Dump 知识库**（不输出 ``domains.csv`` /
        ``behaviors.json`` / ``oui`` 全表），也不提供「浏览全部已知域名」接口。
        报告里出现的归属结论（组织名 / 类别）只是用户自己观测到的域名经本地查询后返回的
        标签，不构成知识库导出。
        """
        return {
            "report": {
                "generated_at": time.time(),
                "edition": "community",
                "scope": "用户自己的观测遥测（不含知识库）",
            },
            "checkup": self.privacy_checkup(),
            "stats": self.get_stats(),
            "coverage": self.attribution_coverage(),
            "devices": self.get_devices(),
            "destinations": self.get_destinations(),
            "unknown_domains": self.get_unknown_domains(),
            "alerts": self.get_alerts(),
            "blind_spots": self.get_blind_spots(),
        }

    def _load_suggestions(self):
        """加载待确认的「建议阻断」队列"""
        rules_file = self._suggestions_path()
        if not rules_file.exists():
            return
        try:
            with open(rules_file, encoding="utf-8") as f:
                loaded = json.load(f)
        except (OSError, ValueError) as e:
            # 坏文件绝不能让整个服务起不来：建议队列是可重建的派生数据，
            # 丢一次不影响采集与判定。记日志后当作空队列继续。
            logger.warning("建议队列读取失败（按空队列继续）: %s", e)
            return
        # 历史上落过两种结构：裸list与 {"items": [...]}。两种都认。
        if isinstance(loaded, dict):
            loaded = loaded.get("items") or []
        if isinstance(loaded, list):
            self.suggested_rules = [r for r in loaded if isinstance(r, dict)]
            self.stats["suggestions_pending"] = len(self.suggested_rules)
            self._rebuild_suggestion_index()

    def _suggestions_path(self) -> Path:
        """建议队列落盘路径（可用 ``suggestions_path`` 配置覆盖，便于测试与只读根fs）"""
        override = self.config.get("suggestions_path")
        if override:
            return Path(override)
        return ROOT / "data" / "suggested_rules.json"

    def _save_suggestions(self):
        """保存「建议阻断」队列

        原子写（临时文件 + replace），避免进程被杀时留下半截JSON；
        写失败只记日志不抛 —— 建议队列是派生数据，持久化失败不该拖垮主服务。
        """
        rules_file = self._suggestions_path()
        try:
            rules_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = rules_file.with_suffix(rules_file.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.suggested_rules, f, ensure_ascii=False, indent=2)
            tmp.replace(rules_file)
        except OSError as e:
            logger.warning("建议队列落盘失败（本轮建议仅存内存）: %s", e)

    def maybe_save_suggestions(self, force: bool = False) -> None:
        """按 ``suggestions_save_every`` 条增量周期性落盘。

        🔴 起因（2026-10-11 真机实测）：容器里SIGTERM 只置停止标志，
        而 ``stop()`` 的调用链从未接上``run_server``，导致
        ``suggested_rules.json`` **从未生成** —— 重启即清零，
        历史观测在、建议不在。周期落盘让建议不再依赖"优雅退出"这一条脆弱路径。
        """
        every = int(self.config.get("suggestions_save_every", 20))
        if every <= 0:
            return
        if force or len(self.suggested_rules) >= every:
            self._save_suggestions()

    def _signal_handler(self, signum, frame):
        """信号处理器

        信号处理运行在事件循环之外，此刻没有正在运行的 loop，直接
        ``asyncio.create_task`` 会抛 RuntimeError（no running event loop）。
        这里只置停止标志，真正的 stop() 由事件循环侧的关闭逻辑执行。
        """
        logger.info(f"Received signal {signum}, requesting shutdown...")
        self._shutdown_requested = True


# ==================== 演示 ====================

if __name__ == "__main__":
    # 演示剧本抽到 src/core/demo.py —— 与 Web UI 的 --demo 共用同一份，
    # 避免两处各写一套、日后各自漂移。
    from core.demo import seed_demo

    service = HomewardService()

    print("=" * 70)
    print("家卫 — 核心服务演示")
    print("=" * 70)

    demo = seed_demo(service)

    print("\n演示设备（MAC 前缀从真实 OUI 表反查，表里没有该厂商就不编）：")
    for hostname, ip, mac in demo["devices"]["devices"]:
        print(f"  {hostname:16s} {ip:15s} {mac or '（OUI 表无此厂商 → 显示为裸 IP）'}")

    for item in demo["intro"]:
        flow = item["flow"]
        dev = item["device"]
        attr = item["attribution"]
        decision = item["decision"]
        print(f"\n观测: {dev['name']} ({flow.src_ip}) → {attr['domain']}")
        print(f"   归属: {attr['organization'] or '未知'} "
              f"[{attr['category']} / 置信度 {attr['confidence']}]")
        print(f"   决策: [{decision.action}] {decision.reason}")
        if decision.requires_user_input:
            print("   提示: 可点击「帮我分析」进行 AI 辅助分析")

    print(f"\n{'=' * 70}")
    print(f"统计: {json.dumps(service.get_stats(), ensure_ascii=False, indent=2)}")

    # ------------------------------------------------------------ 行为识别
    # 演示剧本见 src/core/demo.py：一台卧室摄像头的一小时（心跳 / 突发上传 / 正常服务）
    # + 一台客厅电视的 DNS 隧道特征。行为判定必须看「一段时间里的若干次观测」，
    # 单条记录判不出任何行为，所以剧本构造的是序列而非单包。
    print(f"\n{'=' * 70}")
    print("行为识别：一台卧室摄像头的一小时")
    print("=" * 70)

    alerts = demo["alerts"]
    if not alerts:
        print("  未产生告警")
    for a in alerts:
        target = a['domain'] or a['destination']
        print(f"\n  [{a['severity_label']}] {a['title']} · 置信度 {a['confidence']}")
        print(f"   对象: {a['device_name']} → {target}（归属：{a['organization']}）")
        print(f"   说明: {a['summary']}")
        print(f"   建议: {a['action_label']}")
        print(f"   后果: {a['side_effects']}")

    print(f"\n{'=' * 70}")
    print("当前识别能力的盲区（UI 应如实展示）")
    print("=" * 70)
    spots = service.get_blind_spots()
    if spots:
        for s in spots:
            print(f"  - {s}")
    else:
        print("  （无）")

    # AI 分析演示（模拟）
    print(f"\n{'=' * 70}")
    print("AI 分析演示（需配置 backend）")
    print("=" * 70)

    result = service.request_ai_analysis(
        "unknown-tracking-domain.xyz",
        {
            "total_connections": 1440,
            "total_bytes": 50000,
            "time_span_hours": 24,
            "avg_interval_seconds": 60,
            "asn": "AS13335",
            "country": "US",
        },
    )

    if result:
        print(f"  域名: {result.domain}")
        print(f"  归属: {result.predicted_organization}")
        print(f"  类型: {result.category}")
        print(f"  置信度: {result.confidence}")
        print(f"  解释: {result.explanation}")
        print(f"  建议: {result.suggested_action}")
        if result.side_effects:
            print(f"  影响: {result.side_effects}")
    else:
        print("  AI 未启用（默认关闭）。需在配置中设置 ai_backend 和 api_key。")
        print("  支持后端: ollama (本地) / openai (自备 API Key)")
