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
from inventory.device import Device, DeviceRegistry
from inventory.attribution import AttributionResult, DomainAttribution
from analysis.behavior import BehaviorDetector
from analysis.alerting import Alert, AlertCenter
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
        self.behavior_matcher = BehaviorMatcher(str(KB_DIR / BEHAVIORS_JSON))
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
        self.device_registry = DeviceRegistry()
        self.attribution = DomainAttribution()
        if self.config.get("load_system_devices", True):
            stat = self.device_registry.load_from_system()
            logger.info(f"devices loaded: leases={stat['leases']} arp={stat['arp']}")

        # 统计
        self.stats = {
            "flows_processed": 0,
            "decisions_made": 0,
            "suggestions_pending": 0,
            "unknown_domains": set(),
        }

        # 采集可用性：由 CollectorRunner 写入，供 /api/overview 的盲区视图
        # 如实展示「当前到底有几个采集器在干活、哪个不可用」（看不见要说清楚）
        self.collection_status: list[dict] = []

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
        self._save_suggestions()
        logger.info("家卫 stopped")

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

    def _record_suggestion(self, flow: FlowRecord, decision: Decision):
        """把「建议阻断」写入待确认队列 —— 社区版到此为止，不碰任何网络配置

        真实下发属于**标准版（闭源付费）**，经由 ``src/adapters/base.py`` 的
        ``Enforcer.apply(action)`` + ``ActionRegistry`` 完成；本仓库不实现、也不调用
        任何 nftables / dnsmasq 写入操作。此处若出现真实下发代码，即为开源边界事故。
        """
        hit = decision.rule_hits[0] if decision.rule_hits else None
        rule = {
            "domain": flow.sni or flow.dns_query,
            "device": flow.src_ip,
            "level": decision.action,
            "reason": decision.reason,
            "source": hit.rule_type if hit else "manual",
            "side_effects": hit.side_effects if hit else "",
            "status": "suggested",  # 等待用户确认；社区版不会把它变成 applied
        }
        self.suggested_rules.append(rule)
        self.stats["suggestions_pending"] += 1
        # 周期落盘：不依赖退出路径，避免"重启即清零"
        self.maybe_save_suggestions()
        logger.info(f"[SUGGEST] {rule['domain']} → {decision.reason}（等待用户确认）")

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
        """设备台账视图（按最近活跃排序）"""
        with self._state_lock:
            devices = list(self.device_registry.list_devices())
        return [d.to_dict() for d in devices]

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

    def get_unknown_domains(self) -> list[str]:
        """获取所有未识别域名"""
        with self._state_lock:
            return sorted(self.stats["unknown_domains"])

    def get_blind_spots(self) -> list[str]:
        """当前部署形态下，家卫**看不见 / 认不出**的地方 —— UI 必须展示"""
        spots = list(self.device_registry.blind_spots())
        cov = self.attribution_coverage()
        if cov["total"] and cov["hit_rate"] < 0.8:
            spots.append(f"域名归属覆盖偏低：观测到的 {cov['total']} 个域名里 "
                         f"只有 {cov['hit']} 个能在知识库中查到组织，"
                         f"其余 {cov['total'] - cov['hit']} 个仍属未知（可手动触发 AI 分析）。")
        return spots

    def attribution_coverage(self) -> dict:
        """归属覆盖率：衡量知识库够不够用，也是社区共建的进度指标"""
        with self._state_lock:
            domains = sorted(self.stats["unknown_domains"]
                             | self.attribution.cached_domains())
        rep = self.attribution.coverage(domains)
        return {
            "total": rep.total,
            "hit": rep.hit,
            "hit_rate": rep.rate,
            "by_parent": rep.by_parent,
        }

    def get_stats(self) -> dict:
        """获取统计信息"""
        with self._state_lock:
            return self._get_stats_locked()

    def _get_stats_locked(self) -> dict:
        """``get_stats`` 的实现体（调用方必须已持有 ``_state_lock``）。"""
        return {
            **self.stats,
            "collection": self.collection_status,
            "unknown_domains_count": len(self.stats["unknown_domains"]),
            "unknown_domains": sorted(self.stats["unknown_domains"]),
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

    def export_report(self) -> dict:
        """导出一份「观测报告」结构化数据 —— 只含用户自己的观测遥测。

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
