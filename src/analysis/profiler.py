"""
F6 —— 设备画像与风险分级（社区版开源范围）

为什么要有这一层
----------------
到 F6 为止，家卫能回答「192.168.1.135 问了 tencent.yuanbao 800 次」，
但用户的真实问题是：**「我家里哪台设备最值得担心？」**
画像层把散落的观测收敛成每台设备的一张卡片：它是谁、跟谁说话、说得有多频繁、
以及**凭什么说它有风险**。

三条设计红线
------------
1. **分级必须可解释**。每个等级都带 ``risk_reasons``，写清楚是哪条规则触发的、
   触发的观测数字是多少。用户看到的不能是一个凭空蹦出来的「高危」标签。
2. **只报事实，不做概率性猜测**。域名查不到归属就说查不到，不因为「看起来像」
   就判成追踪器；设备没异常就老老实实给 low。
3. **分级不等于判定有罪**。风险等级是「值得你看一眼」的排序依据，
   社区版从不因此下发任何阻断 —— 拦不拦永远由用户决定。

纯函数优先
----------
:func:`assess_risk` 只吃数字、返回 (等级, 理由列表)，不依赖任何运行时对象，
所以规则调整可以全量单测，在 Windows 开发机上也能跑。
"""

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

# ---------------------------------------------------------------- 风险规则（数据驱动）

# 出现即高危：家庭网络里不该有这类流量
_HIGH_CATEGORIES = ("crypto_mining",)

# 追踪/广告类：不是"有罪"，但占比过高说明这台设备在被持续画像
_TRACKING_CATEGORIES = (
    "tracker", "advertising", "advertising_sdk", "analytics", "telemetry",
)

# 触发占比类规则的最小样本量。样本太小就下结论等于瞎猜 —— 一台设备只问了 3 次 DNS，
# 就算 3 次全是追踪域名，也不足以说明它的行为模式。
_MIN_OBS_FOR_RATIO = 20
_TRACKING_RATIO_THRESHOLD = 0.30

# 未知域名占比：查不到归属不等于有害，但占比过高时值得提示
_MIN_DOMAINS_FOR_UNKNOWN_RATIO = 5
_UNKNOWN_RATIO_THRESHOLD = 0.60

_LEVEL_ORDER = ("low", "medium", "high")


def _bump(level: str, target: str) -> str:
    """取两者中较高的等级（只升不降，保证 high 不被后面的 medium 规则覆盖）"""
    return target if _LEVEL_ORDER.index(target) > _LEVEL_ORDER.index(level) else level


def assess_risk(*,
                observations: int,
                known_count: int,
                unknown_count: int,
                categories: dict[str, int],
                alerts: list[dict]) -> tuple[str, list[str]]:
    """
    按观测事实给一台设备定级，返回 ``(risk_level, risk_reasons)``。

    入参全是数字/字典，便于单测。规则按危害程度从高到低逐条判定，
    等级只升不降；每一条命中的规则都往 ``risk_reasons`` 里追加一句人话。
    """
    level = "low"
    reasons: list[str] = []

    # 1) 挖矿：家庭网络里出现就是异常，无需看占比
    mine = sum(categories.get(c, 0) for c in _HIGH_CATEGORIES)
    if mine:
        level = _bump(level, "high")
        reasons.append(f"观测到 {mine} 次挖矿相关域名的访问")

    # 2) 行为告警：由 behavior + alerting 层判定，这里只做汇总引用
    high_alerts = [a for a in alerts if a.get("severity") in ("critical", "high")]
    if high_alerts:
        level = _bump(level, "high")
        titles = sorted({a.get("title", "") for a in high_alerts if a.get("title")})
        reasons.append("命中高危行为：" + "、".join(titles) if titles
                       else "命中高危行为告警")
    medium_alerts = [a for a in alerts if a.get("severity") == "medium"]
    if medium_alerts:
        level = _bump(level, "medium")
        titles = sorted({a.get("title", "") for a in medium_alerts if a.get("title")})
        if titles:
            reasons.append("命中可疑行为：" + "、".join(titles))

    # 3) 追踪/广告占比：单看域名数会被"装了很多带广告 SDK 的 App"干扰，
    #    所以按**查询次数**占比算，更贴近"它在被持续画像"这件事
    track = sum(categories.get(c, 0) for c in _TRACKING_CATEGORIES)
    if observations >= _MIN_OBS_FOR_RATIO and track / observations >= _TRACKING_RATIO_THRESHOLD:
        level = _bump(level, "medium")
        reasons.append(
            f"{track}/{observations} 次查询（{track / observations:.0%}）"
            f"指向追踪 / 广告类域名"
        )

    # 4) 未知归属占比：查不到归属不等于有害，只提示"这里有一片盲区"
    total = known_count + unknown_count
    if total >= _MIN_DOMAINS_FOR_UNKNOWN_RATIO and unknown_count / total >= _UNKNOWN_RATIO_THRESHOLD:
        level = _bump(level, "medium")
        reasons.append(
            f"{unknown_count}/{total} 个外联域名在知识库里查不到归属"
        )

    return level, reasons


# ---------------------------------------------------------------- 画像

@dataclass
class DeviceProfile:
    """一台设备的画像卡片 —— 直接给 UI / 报告用"""
    key: str
    name: str
    mac: Optional[str] = None
    ips: list[str] = field(default_factory=list)
    vendor: Optional[str] = None
    device_type: str = "unknown"
    type_source: str = "unknown"
    random_mac: bool = False

    first_seen: float = 0.0
    last_seen: float = 0.0
    observations: int = 0        # 观测到的查询总次数
    domain_count: int = 0        # 去过多少个不同的域名
    known_count: int = 0
    unknown_count: int = 0
    categories: dict[str, int] = field(default_factory=dict)  # 类别 → 查询次数
    top_domains: list[dict] = field(default_factory=list)

    risk_level: str = "low"
    risk_reasons: list[str] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "mac": self.mac,
            "ips": self.ips,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "type_source": self.type_source,
            "random_mac": self.random_mac,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observations": self.observations,
            "domain_count": self.domain_count,
            "known_count": self.known_count,
            "unknown_count": self.unknown_count,
            "categories": dict(self.categories),
            "top_domains": list(self.top_domains),
            "risk_level": self.risk_level,
            "risk_reasons": list(self.risk_reasons),
            "alerts": list(self.alerts),
        }


def _alert_belongs(alert: dict, ips: set[str], name: str) -> bool:
    """告警是否归属这台设备：按 IP 命中优先，其次按设备名（IP 缺失时的降级匹配）"""
    a_ip = alert.get("device_ip") or ""
    if a_ip and a_ip in ips:
        return True
    return bool(a_ip == "" and name and alert.get("device_name") == name)


def build_profiles(devices: Iterable,
                   resolve: Callable[[str], object],
                   alerts: Optional[list[dict]] = None,
                   top_n: int = 5) -> list[DeviceProfile]:
    """
    给一批设备生成画像。

    ``resolve`` 是域名 → 归属结果的查询函数（运行期传 :meth:`DomainAttribution.resolve`，
    测试期传假函数），这样画像层不依赖任何具体数据源，规则可全量单测。
    """
    alerts = list(alerts or [])
    out: list[DeviceProfile] = []

    for dev in devices:
        categories: dict[str, int] = {}
        known = unknown = observations = 0

        # dev.domains 会被采集线程并发改写，先取副本再遍历
        for domain, count in list(getattr(dev, "domains", {}).items()):
            observations += count
            result = resolve(domain)
            # 归属结果只需 known / category 两个字段；None 也按未知处理，不抛错
            is_known = bool(getattr(result, "known", False))
            category = (getattr(result, "category", "") or "unknown")
            if is_known:
                known += 1
                # 知识库里存在 iot_core / IoT_core 这类大小写不一致的写法，统一小写归并
                categories[category.lower()] = categories.get(category.lower(), 0) + count
            else:
                unknown += 1

        ips = set(getattr(dev, "ips", set()) or set())
        name = getattr(dev, "display_name", "") or ""
        mine_alerts = [a for a in alerts if _alert_belongs(a, ips, name)]

        level, reasons = assess_risk(
            observations=observations,
            known_count=known,
            unknown_count=unknown,
            categories=categories,
            alerts=mine_alerts,
        )

        top = getattr(dev, "top_domains", None)
        top_list = [{"domain": d, "count": c} for d, c in (top(top_n) if top else [])]

        out.append(DeviceProfile(
            key=getattr(dev, "key", ""),
            name=name,
            mac=getattr(dev, "mac", None),
            ips=sorted(ips),
            vendor=(getattr(dev, "vendor_cn", None) or getattr(dev, "vendor", None)),
            device_type=getattr(dev, "device_type", "unknown"),
            type_source=getattr(dev, "type_source", "unknown"),
            random_mac=bool(getattr(dev, "random_mac", False)),
            first_seen=getattr(dev, "first_seen", 0.0),
            last_seen=getattr(dev, "last_seen", 0.0),
            observations=observations,
            domain_count=known + unknown,
            known_count=known,
            unknown_count=unknown,
            categories=categories,
            top_domains=top_list,
            risk_level=level,
            risk_reasons=reasons,
            alerts=[{
                "rule_id": a.get("rule_id", ""),
                "title": a.get("title", ""),
                "severity": a.get("severity", ""),
                "severity_label": a.get("severity_label", ""),
                "summary": a.get("summary", ""),
            } for a in mine_alerts],
        ))

    # 风险高的排前面，同级按观测次数降序 —— 用户第一眼看到的就是最该看的那台
    out.sort(key=lambda p: (
        -_LEVEL_ORDER.index(p.risk_level),
        -p.observations,
        p.name,
    ))
    return out
