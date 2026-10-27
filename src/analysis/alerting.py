"""
中文告警：把行为认定渲染成人看得懂的话，并把重复告警收敛掉。

三条硬规矩：

1. **不猜、不吓人。** 严重度低不等于没事，严重度高也不等于定罪 —— 每条告警都写清
   证据（多少次、多少字节、什么时间）和置信度。置信度是 ``low`` 的规则，文案里必须
   自己声明「这是弱证据」，不能靠 severity 制造压迫感。

2. **说后果。** ``side_effects`` 是必填的：告诉用户「点了之后会怎样」。这是本项目
   「不默认自动阻断、一切以你确认为准」承诺的一部分 —— 让人在知情的前提下决定。

3. **模板占位符必须可穷举。** ``TEMPLATE_KEYS`` 列出渲染器能提供的全部键；单测会
   遍历 ``behaviors.json`` 的每条文案，断言其中用到的占位符都在这个集合里。
   否则一旦有人改了文案加了新占位符，用户就会在界面上看到 ``{device_name}``
   这种没渲染的花括号 —— 那是不可接受的。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, Optional

from analysis.behavior import BehaviorFinding
from core.netclass import is_address_like, is_internal, is_noise_address

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LABEL = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}

ACTION_LABEL = {
    "allow": "放通",
    "warn": "仅提示，不需要处理",
    "block_soft": "建议阻断该域名",
    "block_medium": "建议阻断该组织名下域名",
    "block_hard": "建议将该设备隔离到独立网段",
    "unknown": "暂不处理，可手动触发分析",
}

# 「突发大流量上传」命中这些归属类别时，不应按数据外泄处理：
# 真实家庭网络里手机 iCloud/Google 相册备份、系统/App 更新、CDN 拉取都符合
# 「单位时间内向单一目的地传大量数据」，直接判 high + block_medium 是误报。
# 仅当目的地归属为下列良性大流量类别才降级为 low/warn；目的地未知（attribution 为空）
# 仍保持原严重度 —— 未知目的地的大流量上传更可疑，宁严勿松（失败关闭）。
_BENIGN_BULK_CATEGORIES = frozenset({
    "cloud_storage", "cloud_backup", "os_update", "app_update",
    "cdn", "system_update", "backup",
})


def _dest_host(dst: str) -> str:
    """从 finding.destination（可能是 domain 或 ip:port，IPv6 可能带 ``[ ]``）取出主机部分。"""
    if not dst:
        return ""
    if dst.startswith("["):  # [fe80::1]:1900
        end = dst.find("]")
        if end != -1:
            return dst[1:end]
        return dst[1:]
    return dst.rsplit(":", 1)[0]


def _dest_is_internal(dst: str) -> bool:
    """bulk_upload 的目的地是否是「内网 / 非公网可达」地址（组播/广播/链路本地/私网）。

    注意：只有真的是 IP 且属内网时才算；域名（即使是 ``.lan``）走归属类别判定，
    不在这里降级，避免把所有未知域名也误判成「内网」而漏报。
    """
    host = _dest_host(dst)
    if not host or not is_address_like(host):
        return False
    return is_noise_address(host) or is_internal(host)


def _bulk_upload_is_benign(finding, attribution: dict) -> bool:
    """bulk_upload 是否应降级：目的地是内网控制流量，或归属为良性大流量类别。"""
    if _dest_is_internal(finding.destination or ""):
        return True
    return bool(attribution.get("category") in _BENIGN_BULK_CATEGORIES)


# 方案 B：未知公网 bulk_upload 形态分级阈值。详见 docs/01-规划进度/误报诊断与未决清单。
_BULK_ROUTINE_MIN_AVG_PACKET = 800.0   # 接近 MTU 的批量传输（云同步/备份/串流），非碎包心跳/C2
_BULK_ROUTINE_MIN_SPAN_RATIO = 0.3     # 持续覆盖窗口相当比例，而非一瞬间突发


def _bulk_upload_shape(finding) -> str:
    """把**未知公网**的 bulk_upload 按流量形状分档（方案 B 核心）。

    - ``routine``：单终点、持续、大包 —— 更像云同步 / 备份 / 视频串流等正常行为；
    - ``suspicious``：突发 / 碎包 / 不规则 —— 更像数据泄露（或扫描）。

    仅作置信度下调依据，**不替代**「目的地已知恶意类别」的判定（那由 crypto_mining /
    c2_beacon / firmware_backdoor 等规则负责）。

    局限（刻意的）：单终点持续大包的真外泄也会被判 ``routine`` —— 被动元数据无法
    100% 区分，故 routine 档只降为低危并**声明弱证据**，而非静音。要彻底区分需
    主动载荷检测，超出社区版范围。
    """
    ev = finding.evidence or {}
    avg_packet = float(ev.get("avg_packet", 0) or 0)
    span = float(ev.get("span_seconds", 0) or 0)
    window = float(getattr(finding, "window_seconds", 600) or 600)
    occurrences = int(ev.get("occurrences", 0) or 0)
    if (
        avg_packet >= _BULK_ROUTINE_MIN_AVG_PACKET
        and span >= _BULK_ROUTINE_MIN_SPAN_RATIO * window
        and occurrences >= 5
    ):
        return "routine"
    return "suspicious"

TEMPLATE_KEYS = frozenset({
    "device_name", "device_ip", "vendor", "device_type",
    "destination", "domain", "organization",
    "interval", "period", "avg_packet",
    "total_mb", "total_bytes",
    "start_time", "end_time", "duration_min", "window_minutes",
    "occurrences", "length", "rate", "connections",
    # P1-3 新增：跨设备追踪 / 作息节律
    "devices_hit", "device_list",
    "top_active_hour", "active_hours", "concentration_pct",
})

_UNKNOWN_ORG = "未识别"
_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")


def _hhmmss(ts: float) -> str:
    """时间戳 → 本地时间 HH:MM:SS"""
    if not ts:
        return "--:--:--"
    return time.strftime("%H:%M:%S", time.localtime(ts))


def extract_placeholders(template: str) -> list[str]:
    """取出文案里用到的全部占位符（用于自检与单测）"""
    return _PLACEHOLDER_RE.findall(template or "")


def build_context(
    finding: BehaviorFinding,
    device_view: Optional[dict] = None,
    attribution: Optional[dict] = None,
) -> dict:
    """把一条行为认定 + 设备视图 + 归属视图，压成渲染文案所需的全部键值"""
    ev = finding.evidence or {}
    device_view = device_view or {}
    attribution = attribution or {}

    span = float(ev.get("span_seconds", 0.0))
    avg_gap = float(ev.get("avg_interval_seconds", 0.0))
    total = int(ev.get("total_bytes", 0) or 0)

    return {
        "device_name": device_view.get("name") or finding.src_ip,
        "device_ip": finding.src_ip,
        "vendor": device_view.get("vendor") or "未知厂商",
        "device_type": device_view.get("device_type") or "unknown",
        "destination": finding.destination_label,
        "domain": finding.domain or finding.destination_label,
        "organization": attribution.get("organization") or _UNKNOWN_ORG,
        "interval": int(round(avg_gap)),
        "period": f"{avg_gap / 60:.1f}" if avg_gap else "0.0",
        "avg_packet": int(round(float(ev.get("avg_packet", 0.0) or 0.0))),
        "total_mb": f"{total / 1048576:.1f}",
        "total_bytes": str(total),
        "start_time": _hhmmss(float(ev.get("start_ts", 0.0))),
        "end_time": _hhmmss(float(ev.get("end_ts", 0.0))),
        "duration_min": f"{span / 60:.1f}",
        "window_minutes": int(round(finding.window_seconds / 60)),
        "occurrences": int(ev.get("occurrences", 0) or 0),
        "length": int(ev.get("longest_label", 0) or 0),
        "rate": f"{float(ev.get('dns_rate', 0.0) or 0.0):.1f}",
        "connections": int(ev.get("distinct_connections", 0) or 0),
        # P1-3 新增：跨设备追踪 / 作息节律 —— evidence 里直接取，
        # 没有时返回 0 / 空字符串，渲染器会自动替换成占位符
        "devices_hit": int(ev.get("devices_hit", ev.get("device_count", 0)) or 0),
        "device_list": str(ev.get("device_list", "")),
        "top_active_hour": int(ev.get("top_active_hour", -1) or -1),
        "active_hours": str(ev.get("active_hours", "")),
        "concentration_pct": int(ev.get("concentration_pct", 0) or 0),
    }


class AlertRenderer:
    """渲染行为库里的中文模板

    渲染不出的占位符不会被静默丢掉，而是替换成可见的 ``（xxx：未知）`` 并记进
    :attr:`Alert.missing_keys` —— 界面上出现这种字样就是模板与上下文脱节了。
    """

    def render(self, template: str, context: dict) -> tuple[str, list[str]]:
        missing: list[str] = []

        def _sub(match: re.Match) -> str:
            key = match.group(1)
            if key in context:
                return str(context[key])
            missing.append(key)
            return f"（{key}：未知）"

        return _PLACEHOLDER_RE.sub(_sub, template or ""), missing


@dataclass
class Alert:
    """一条给人看的告警"""

    alert_id: str
    rule_id: str
    title: str                 # 规则名
    summary: str               # 渲染后的中文说明
    side_effects: str          # 「点了之后会怎样」—— 必填
    severity: str              # critical / high / medium / low
    severity_label: str
    confidence: str
    category: str
    suggested_action: str      # 建议动作（社区版只建议，不下发）
    action_label: str

    device_name: str
    device_ip: str
    vendor: str
    device_type: str
    destination: str
    domain: Optional[str]
    organization: str

    first_seen: float
    last_seen: float
    occurrences: int = 0
    episodes: int = 1
    status: str = "open"       # open / dismissed
    missing_keys: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "summary": self.summary,
            "side_effects": self.side_effects,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "confidence": self.confidence,
            "category": self.category,
            "suggested_action": self.suggested_action,
            "action_label": self.action_label,
            "device_name": self.device_name,
            "device_ip": self.device_ip,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "destination": self.destination,
            "domain": self.domain,
            "organization": self.organization,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "episodes": self.episodes,
            "status": self.status,
            "missing_keys": list(self.missing_keys),
            "evidence": dict(self.evidence),
        }


class AlertCenter:
    """告警收敛：同一台设备 + 同一条规则 + 同一个目的地，只占一条

    没有这层，行为规则会以扫描频率持续命中（心跳信标每 30 秒一次，扫一次命中一次），
    UI 会在几分钟内被同一件事刷满 —— 用户一旦被刷屏，真正的严重告警就没人看了。

    冷却期内重复命中：更新 last_seen 与证据，不新增条目；
    冷却期外再次命中：仍是同一条，但 ``episodes`` +1（说明它**又来了**）。
    """

    def __init__(
        self,
        cooldown_seconds: float = 1800.0,
        max_alerts: int = 500,
        renderer: Optional[AlertRenderer] = None,
    ):
        self.cooldown_seconds = float(cooldown_seconds)
        self.max_alerts = int(max_alerts)
        self.renderer = renderer or AlertRenderer()
        self._alerts: dict[str, Alert] = {}
        self.stats = {"ingested": 0, "created": 0, "updated": 0}

    def ingest(
        self,
        findings: Iterable[BehaviorFinding],
        device_view_of: Optional[Callable[[str], dict]] = None,
        attribution_of: Optional[Callable[[str], dict]] = None,
        now: Optional[float] = None,
        rule_of: Optional[Callable[[str], dict]] = None,
        is_self_ip: Optional[Callable[[str], bool]] = None,
    ) -> list[Alert]:
        """把本轮的行为认定收进告警列表，返回**本轮新建**的告警"""
        now = time.time() if now is None else now
        created: list[Alert] = []

        for finding in findings:
            self.stats["ingested"] += 1
            device_view = device_view_of(finding.src_ip) if device_view_of else {}
            attribution = (
                attribution_of(finding.domain or finding.destination)
                if attribution_of and (finding.domain or finding.destination)
                else {}
            )
            rule = rule_of(finding.rule_id) if rule_of else {}
            context = build_context(finding, device_view or {}, attribution or {})

            # 源设备是否为「跑家卫的那台设备」自身（宿主 LAN IP）。宿主自身的系统流量
            # （系统更新 / telemetry / NTP / 包下载）天然是大流量上传，不应当成数据外泄。
            src_is_self = bool(is_self_ip and is_self_ip(finding.src_ip))

            explanation_template = rule.get("explanation", "") or _fallback_explanation(finding)

            # bulk_upload 误报收敛（方案 B 扩展）：
            # 1) 目的地是内网控制流量（组播/广播/链路本地/私网）——
            #    SSDP/mDNS 等局域网发现协议符合「单目的大量包」特征，绝不可能是真实
            #    数据外泄，直接降级，别把路由器自身和局域网设备的正常发现流量判成高危；
            # 2) 目的地归属为良性大流量类别（云备份/系统更新/CDN）降级为 low/warn；
            # 3) 源是宿主自身（src_is_self）：路由器/NAS 自己更新自己，属预期行为，降级；
            # 4) 未知公网目的地 —— 方案 B 新增：**不靠信任豁免**，按流量形状分级：
            #      · routine（单终点·持续·大包，像云同步/备份/串流）→ 降为 low/warn、
            #        置信度 low，并改用「常规大流量」诚实文案（声明弱证据）；
            #      · suspicious（突发/碎包/不规则）→ 保留原 high，不降级（更像泄露）。
            #    仅降级 bulk_upload，其它规则不受影响；目的地已知恶意类别仍由其它规则覆盖。
            if finding.rule_id == "bulk_upload":
                if _bulk_upload_is_benign(finding, attribution) or src_is_self:
                    finding = replace(finding, severity="low", action="warn")
                else:
                    shape = _bulk_upload_shape(finding)
                    if shape == "routine":
                        finding = replace(
                            finding, severity="low", action="warn", confidence="low"
                        )
                        explanation_template = (
                            rule.get("explain_routine") or explanation_template
                        )

            summary, missing = self.renderer.render(explanation_template, context)

            key = f"{finding.rule_id}@{finding.src_ip}#{finding.destination}"
            existing = self._alerts.get(key)
            if existing is not None:
                if now - existing.last_seen >= self.cooldown_seconds:
                    existing.episodes += 1
                existing.last_seen = now
                existing.occurrences = int(finding.evidence.get("occurrences", 0))
                existing.evidence = dict(finding.evidence)
                existing.summary = summary
                existing.missing_keys = missing
                existing.organization = context["organization"]
                existing.device_name = context["device_name"]
                self.stats["updated"] += 1
                continue

            if len(self._alerts) >= self.max_alerts:
                continue  # 满了就不再新增，避免内存无限涨；运维该看 stats 里的告警数

            alert = Alert(
                alert_id=key,
                rule_id=finding.rule_id,
                title=rule.get("name", finding.rule_name),
                summary=summary,
                side_effects=rule.get("side_effects", "")
                             or "未标注影响范围，处置前请先确认该设备的用途",
                severity=finding.severity,
                severity_label=SEVERITY_LABEL.get(finding.severity, finding.severity),
                confidence=finding.confidence,
                category=finding.category,
                suggested_action=finding.action,
                action_label=ACTION_LABEL.get(finding.action, finding.action),
                device_name=context["device_name"],
                device_ip=finding.src_ip,
                vendor=context["vendor"],
                device_type=context["device_type"],
                destination=finding.destination,
                domain=finding.domain,
                organization=context["organization"],
                first_seen=now,
                last_seen=now,
                occurrences=int(finding.evidence.get("occurrences", 0)),
                missing_keys=missing,
                evidence=dict(finding.evidence),
            )
            self._alerts[key] = alert
            self.stats["created"] += 1
            created.append(alert)

        return created

    # ---------------------------------------------------------------- 查询

    def active(self) -> list[Alert]:
        """未忽略的告警，按严重度 → 最近发生时间排序"""
        items = [a for a in self._alerts.values() if a.status != "dismissed"]
        items.sort(key=lambda a: (SEVERITY_RANK.get(a.severity, 9), -a.last_seen))
        return items

    def all(self) -> list[Alert]:
        return list(self._alerts.values())

    def get(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(alert_id)

    def dismiss(self, alert_id: str) -> bool:
        alert = self._alerts.get(alert_id)
        if alert is None:
            return False
        alert.status = "dismissed"
        return True

    def clear(self) -> int:
        """清空全部告警（含已忽略的）。返回清掉的条数。

        只在用户主动「清除观测记录」时调用 —— 让用户能干净地重新开始分析，
        把"修复前的旧证据"和"重新采集到的新数据"彻底分开。
        """
        n = len(self._alerts)
        self._alerts.clear()
        return n

    def has(self, alert_id: str) -> bool:
        """该告警是否已存在。

        给快照恢复去重用 —— 以前外部要直读 ``_alerts`` 才能判断，
        一旦内部结构改名就会静默出错，故提供公开查询入口。
        """
        return alert_id in self._alerts

    def restore(self, alert: "Alert") -> bool:
        """把快照还原出来的告警放回中心（已存在则跳过）。返回是否新增。"""
        if alert.alert_id in self._alerts:
            return False
        self._alerts[alert.alert_id] = alert
        return True

    def to_dict(self) -> list[dict]:
        return [a.to_dict() for a in self.active()]

    def counts_by_severity(self) -> dict[str, int]:
        out = {k: 0 for k in SEVERITY_RANK}
        for alert in self.active():
            out[alert.severity] = out.get(alert.severity, 0) + 1
        return out


def _fallback_explanation(finding: BehaviorFinding) -> str:
    """行为库里没有 explanation 时的兜底文案 —— 宁可朴素，也不能空着"""
    ev = finding.evidence or {}
    return (
        f"设备 {finding.src_ip} 的行为命中规则「{finding.rule_name}」："
        f"{int(ev.get('occurrences', 0))} 次观测，"
        f"累计 {int(ev.get('total_bytes', 0))} 字节。"
        f"（该规则未配置说明文案，请补充 behaviors.json 中的 explanation。）"
    )
