"""
规则匹配引擎 - 核心判定逻辑
"""

import csv
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("homeward.engine")


# ==================== 数据结构 ====================

@dataclass
class FlowRecord:
    """流量记录（纯元数据）"""
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    sni: Optional[str] = None
    dns_query: Optional[str] = None
    packet_size: int = 0
    direction: str = "out"
    interface: str = ""


@dataclass
class RuleHit:
    """规则命中结果"""
    domain: str
    organization: str
    category: str
    confidence: str  # high / medium / low
    description: str
    action: str  # allow / block_soft / block_medium / block_hard / warn
    side_effects: str = ""
    rule_type: str = "exact"  # exact / pattern / behavior


@dataclass
class Decision:
    """最终决策"""
    action: str
    reason: str
    rule_hits: list[RuleHit] = field(default_factory=list)
    requires_user_input: bool = False  # 是否需要用户手动触发 AI 分析


# ==================== 知识库加载器 ====================

class KnowledgeBase:
    """域名归属知识库"""

    def __init__(self, base_dir: str = None):
        if base_dir is None:
            base_dir = Path(__file__).parent.parent / "knowledge_base"
        self.base_dir = Path(base_dir)
        self.domains: dict[str, dict] = {}
        self.patterns: list[tuple[re.Pattern, dict]] = []
        self.load()

    def load(self):
        """加载 domains.csv"""
        csv_path = self.base_dir / "domains.csv"
        if not csv_path.exists():
            return

        with open(csv_path, encoding="utf-8") as f:
            lines = [line for line in f if not line.strip().startswith("#")]
            if not lines:
                return
            reader = csv.DictReader(lines)
            for row in reader:
                # 跳过空行或注释行
                if not row or row.get("domain", "").startswith("#"):
                    continue
                domain = row["domain"].strip()
                if not domain:
                    continue
                self.domains[domain] = row
                # 含通配符的模式编译成正则
                if "*" in domain:
                    pattern = domain.replace(".", r"\.").replace("*", r"[^.]*")
                    self.patterns.append((re.compile(f"^{pattern}$"), row))

    def lookup(self, domain: str) -> Optional[dict]:
        """精确查找"""
        return self.domains.get(domain)

    def match_pattern(self, domain: str) -> Optional[dict]:
        """通配符模式匹配"""
        for pattern, row in self.patterns:
            if pattern.match(domain):
                return row
        return None

    def query(self, domain: str) -> Optional[dict]:
        """查询域名归属（先精确后模式）"""
        result = self.lookup(domain)
        if result:
            return result
        return self.match_pattern(domain)


# ==================== 行为特征匹配 ====================

FILTER_KEYS = frozenset({"direction", "protocol", "dst_port"})
"""只决定「哪些观测参与判定」，不构成命中证据。"""

EVIDENCE_KEYS = frozenset({
    "min_occurrences",        # 窗口内至少出现 N 次（窗口有界 ⇒ 这本身就是速率证据）
    "duration_min",           # 观测窗口跨度（秒）
    "total_bytes_min",        # 窗口内累计字节
    "packet_size",            # {min,max} 平均包大小区间
    "interval",               # {min,max} 相邻间隔**全部**落在区间（心跳）
    "interval_min",           # 与 interval_max 配合：间隔落在区间的**占比**
    "interval_max",
    "periodicity_threshold",  # 上面那个占比的阈值，默认 1.0
    "min_connections",        # 窗口内不同目的地数量
    "destination_pattern",    # 目标域名正则
    "destination_keywords",   # 目标域名关键词（要求落在标签边界）
    "subdomain_length_min",   # 最长标签长度（DNS 隧道）
    "dns_rate_min",           # DNS 查询速率（次/秒）
})
"""命中一条规则所需的**证据**。一条规则至少要用到其中一个。"""

STRUCTURE_KEYS = frozenset({"any_of"})
"""组合键：任一子模式成立即可。"""

SUPPORTED_PATTERN_KEYS = FILTER_KEYS | EVIDENCE_KEYS | STRUCTURE_KEYS


def _as_list(value) -> list:
    """把单值或列表统一成列表"""
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def _has_evidence(pattern: dict) -> bool:
    """pattern 里是否含至少一个证据键 —— 没有的话命中即恒真"""
    return any(k in EVIDENCE_KEYS for k in pattern) or "any_of" in pattern


def _gaps(flows: list[FlowRecord]) -> list[float]:
    """相邻观测的时间间隔序列"""
    return [b.timestamp - a.timestamp for a, b in zip(flows, flows[1:])]


def _distinct_connections(flows: list[FlowRecord]) -> int:
    """窗口内连过多少个不同的目的地（IP + 端口 + 域名）"""
    return len({(f.dst_ip, f.dst_port, f.sni or f.dns_query or "") for f in flows})


def _longest_label(flow: FlowRecord) -> int:
    """观测目标里最长的域名标签长度"""
    domain = flow.dns_query or flow.sni or ""
    return max((len(label) for label in domain.split(".")), default=0)


def _dns_rate(flows: list[FlowRecord]) -> float:
    """DNS 查询速率（次/秒）。窗口跨度为 0 时按 1 秒计，避免除零。"""
    queries = [f for f in flows if f.dns_query]
    if not queries:
        return 0.0
    span = flows[-1].timestamp - flows[0].timestamp
    return len(queries) / (span if span > 0 else 1.0)


def _dest_matches_regex(flow: FlowRecord, pattern: str) -> bool:
    """目标域名是否匹配正则（对整域名做 search）"""
    domain = (flow.sni or flow.dns_query or "").strip().rstrip(".")
    if not domain:
        return False
    try:
        return re.search(pattern, domain, re.IGNORECASE) is not None
    except re.error:
        logger.warning("行为规则的 destination_pattern 不是合法正则：%s", pattern)
        return False


def _dest_matches_keywords(flow: FlowRecord, keywords) -> bool:
    """目标域名是否含任一关键词，**关键词必须落在标签边界上**

    边界指「前后不能紧邻字母数字」（`.`、`-`、`_`、`+`、端口冒号、串首串尾都算边界）。
    少了这条约束，`c2` 会把 `abc2.example.com`、`svc2-api.example.com`
    这类完全正常的域名误判成 C2 服务器 —— 而这类规则的建议动作是 block_hard
    （把设备隔离进 IoT VLAN），误报代价极高。
    """
    domain = (flow.sni or flow.dns_query or "").strip().rstrip(".").lower()
    if not domain:
        return False
    for kw in _as_list(keywords):
        kw = str(kw).strip().lower()
        if not kw:
            continue
        rx = r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])"
        if re.search(rx, domain):
            return True
    return False


class BehaviorMatcher:
    """行为特征规则匹配

    pattern 里的键分三类，语义是硬约定，改动前先看懂：

    · **过滤键** ``direction`` / ``protocol`` / ``dst_port``
      只决定哪些观测参与判定，**不构成证据**。
    · **证据键**（``min_occurrences`` 及其余全部 + ``any_of``）
      必须至少命中一个，规则才算成立。``min_occurrences`` 算证据是因为观测窗口
      有界（见规则里的 ``window_seconds``），「N 秒内出现 ≥K 次」本身就是速率陈述。

    「至少有一个证据键」是**失败关闭**的关键。早期实现只认得
    ``direction``/``interval``/``packet_size`` 等少数键，而 ``behaviors.json`` 里
    有 5 条规则的证据键全部落在不认识的键上（``destination_pattern``、
    ``dns_rate_min``、``periodicity_threshold``……），判定函数默默跳过它们、直接
    返回 True —— 结果**随便一条 60 字节的普通外联包，都能命中「疑似 C2 通信」
    「疑似固件后门」这类 critical 规则，并建议 block_hard 隔离设备**。

    现在的行为：
      · 认知不了的键 → 规则判为「不支持」，不参与匹配，且由 :meth:`unsupported`
        暴露出来（单测断言随库发布的规则里一条都不许有）；
      · 没有任何证据键 → 规则判为「退化」（恒真），同样不参与匹配；
      · ``_matches`` 自身对未知键一律返回 False —— 宁可漏报，不能乱报。
    """

    def __init__(self, behaviors_path: str = None):
        if behaviors_path is None:
            # 目录名是**下划线** knowledge_base，不是连字符 knowledge-base。
            # 早期这里写错过，结果是默认构造时行为库静默加载为空、所有行为类判定
            # （心跳信标 / 突发上传 / DNS 隧道……）无声失效 —— 故改为显式报错。
            behaviors_path = Path(__file__).parent.parent / "knowledge_base" / "behaviors.json"
        self.behaviors_path = Path(behaviors_path)
        self.rules: list[dict] = []
        self.supported_rules: list[dict] = []
        self.unsupported_rules: list[dict] = []
        self.load()

    def load(self):
        """加载 behaviors.json 并做规则体检

        加载不到规则**必须显式失败**，不允许静默置空：行为库为空会让全部行为类判定
        失效，且失败得毫无征兆（判不出告警和"没有异常"看起来一模一样）。
        """
        path = self.behaviors_path
        if not path.exists():
            raise FileNotFoundError(f"行为模式库不存在：{path}")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        # 下划线开头的顶层键留给元信息（如 _schema_version），不作为规则
        rules = [{"id": k, **v} for k, v in data.items() if not k.startswith("_")]
        if not rules:
            raise ValueError(f"行为模式库为空：{path}")

        self.rules = rules
        self.supported_rules = []
        self.unsupported_rules = []
        for rule in rules:
            issue = self._validate(rule)
            if issue:
                self.unsupported_rules.append({"id": rule["id"], "reason": issue})
            else:
                self.supported_rules.append(rule)

        if self.unsupported_rules:
            logger.warning(
                "行为库中有 %d 条规则不可用，已跳过：%s",
                len(self.unsupported_rules),
                "; ".join(f"{u['id']}（{u['reason']}）" for u in self.unsupported_rules),
            )

    def unsupported(self) -> list[dict]:
        """返回被跳过的规则及原因 —— 这条通道是为了让「规则腐化」能被看见"""
        return list(self.unsupported_rules)

    @staticmethod
    def _validate(rule: dict) -> str:
        """体检一条规则：返回空串表示可用，否则返回不可用原因"""
        pattern = rule.get("pattern") or {}
        unknown = sorted(k for k in pattern if k not in SUPPORTED_PATTERN_KEYS)
        if unknown:
            return f"pattern 含未知键 {unknown}"
        if not _has_evidence(pattern):
            return "pattern 没有任何证据键（命中即恒真）"
        for sub in pattern.get("any_of", []) or []:
            if not isinstance(sub, dict):
                return "any_of 的子项必须是对象"
            unknown = sorted(k for k in sub if k not in SUPPORTED_PATTERN_KEYS)
            if unknown:
                return f"any_of 含未知键 {unknown}"
            if not _has_evidence(sub):
                return "any_of 子模式没有任何证据键（命中即恒真）"
        return ""

    def match(self, flow_history: list[FlowRecord]) -> list[dict]:
        """
        对一组 flow 记录做行为特征匹配
        flow_history: 某个设备在某段时间内的所有 flow
        """
        results = []
        for rule in self.supported_rules:
            pattern = rule.get("pattern") or {}
            if self._matches(flow_history, pattern):
                results.append(rule)
        return results

    def _matches(self, flows: list[FlowRecord], pattern: dict) -> bool:
        """判断 flow 序列是否满足行为模式

        两个早期踩过的语义坑，这里刻意写死，别再退化回去：

        1. ``duration_min`` 的单位是**秒**（观测窗口长度），不是「记录条数」。
           早期把它当条数比，等于拿时间阈值去卡样本量，判定含义完全跑偏。
        2. ``interval`` 必须真的去算**相邻观测的时间差**。早期只比了平均包大小、
           把 interval 读出来就丢掉，结果任何小包流量都会被判成心跳信标。
        判定顺序：过滤 → 样本量守卫 → **确认有证据键（失败关闭）** → 逐项证据。

        两个早期踩过的语义坑，这里刻意写死，别再退化回去：

        1. ``duration_min`` 的单位是**秒**（观测窗口长度），不是「记录条数」。
           早期把它当条数比，等于拿时间阈值去卡样本量，判定含义完全跑偏。
        2. ``interval`` 必须真的去算**相邻观测的时间差**。早期只比了平均包大小、
           把 interval 读出来就丢掉，结果任何小包流量都会被判成心跳信标。
        """
        if not pattern:
            return False

        # 认知不了的键一律拒绝 —— 宁可漏报，绝不能因为"看不懂"就放行
        if any(k not in SUPPORTED_PATTERN_KEYS for k in pattern):
            return False

        direction = pattern.get("direction", "out")
        relevant = sorted(
            (f for f in flows if f.direction == direction),
            key=lambda f: f.timestamp,
        )

        # 协议过滤
        proto = pattern.get("protocol")
        if proto:
            wanted = {str(p).lower() for p in _as_list(proto)}
            relevant = [f for f in relevant if str(f.protocol or "").lower() in wanted]

        # 目的端口过滤
        port = pattern.get("dst_port")
        if port is not None:
            wanted = {int(p) for p in _as_list(port)}
            relevant = [f for f in relevant if f.dst_port in wanted]

        if not relevant:
            return False

        # 样本量下限：出现次数不够，不敢下任何行为结论
        min_occurrences = pattern.get("min_occurrences")
        if min_occurrences and len(relevant) < int(min_occurrences):
            return False

        # 失败关闭：没有任何证据键的规则是恒真的，不许命中
        if not _has_evidence(pattern):
            return False

        # 观测窗口长度（秒）—— 首尾观测的时间跨度，不是条数
        duration_min = pattern.get("duration_min")
        if duration_min is not None:
            span = relevant[-1].timestamp - relevant[0].timestamp
            if span < float(duration_min):
                return False

        # 突发流量：窗口内累计字节数
        if "total_bytes_min" in pattern:
            total = sum(f.packet_size for f in relevant)
            if total < float(pattern["total_bytes_min"]):
                return False

        # 包大小范围：按窗口内平均包大小判定（逐包判定太脆，噪声一多就漏报）
        packet_size = pattern.get("packet_size")
        if packet_size:
            avg_size = sum(f.packet_size for f in relevant) / len(relevant)
            lo = float(packet_size.get("min", 0))
            hi = float(packet_size.get("max", float("inf")))
            if not (lo <= avg_size <= hi):
                return False

        # 心跳信标：相邻观测的时间间隔是否**全部**稳定落在 [min, max]
        interval = pattern.get("interval")
        if interval:
            gaps = _gaps(relevant)
            if not gaps:
                return False
            lo = float(interval.get("min", 0))
            hi = float(interval.get("max", float("inf")))
            if any(not (lo <= gap <= hi) for gap in gaps):
                return False

        # 周期性外联：允许少量抖动，要求落在区间内的间隔**占比**达到阈值
        if "interval_min" in pattern or "interval_max" in pattern:
            gaps = _gaps(relevant)
            if not gaps:
                return False
            lo = float(pattern.get("interval_min", 0))
            hi = float(pattern.get("interval_max", float("inf")))
            threshold = float(pattern.get("periodicity_threshold", 1.0))
            ratio = sum(1 for gap in gaps if lo <= gap <= hi) / len(gaps)
            if ratio < threshold:
                return False

        # 目标数量：窗口内连过多少个不同的目的地（IP+端口+域名）
        min_conn = pattern.get("min_connections")
        if min_conn is not None:
            if _distinct_connections(relevant) < int(min_conn):
                return False

        # 目标域名：正则（锚定到整域名，调用方自己负责别写得太宽）
        dest_pat = pattern.get("destination_pattern")
        if dest_pat:
            if not any(_dest_matches_regex(f, dest_pat) for f in relevant):
                return False

        # 目标域名关键词：**必须落在标签边界上**（前后不能紧邻字母数字）。
        # 否则 `c2` 会把 `abc2.example.com`、`svc2...` 全误判成 C2 服务器。
        keywords = pattern.get("destination_keywords")
        if keywords:
            if not any(_dest_matches_keywords(f, keywords) for f in relevant):
                return False

        # DNS 隧道特征一：超长子域标签
        subdomain_len = pattern.get("subdomain_length_min")
        if subdomain_len is not None:
            longest = max((_longest_label(f) for f in relevant), default=0)
            if longest < int(subdomain_len):
                return False

        # DNS 隧道特征二：查询速率（次/秒）
        dns_rate = pattern.get("dns_rate_min")
        if dns_rate is not None:
            if _dns_rate(relevant) < float(dns_rate):
                return False

        # 任一成立即可（用于「长子域 OR 高频查询」这类并列特征）
        any_of = pattern.get("any_of")
        if any_of:
            if not any(
                self._matches(relevant, dict(sub, direction=direction))
                for sub in any_of
                if isinstance(sub, dict)
            ):
                return False

        return True


# ==================== 决策引擎 ====================

class DecisionEngine:
    """核心决策引擎"""

    def __init__(self, kb: KnowledgeBase = None, bm: BehaviorMatcher = None):
        self.kb = kb or KnowledgeBase()
        self.bm = bm or BehaviorMatcher()

    def evaluate(self, flow: FlowRecord) -> Decision:
        """
        对一条流量记录做完整判定
        返回 Decision
        """
        rule_hits: list[RuleHit] = []

        # ===== 第 1 层：域名精确/模式匹配 =====
        domain = flow.sni or flow.dns_query
        if domain:
            result = self.kb.query(domain)
            if result:
                hit = RuleHit(
                    domain=domain,
                    organization=result.get("organization", "unknown"),
                    category=result.get("category", "unknown"),
                    confidence=result.get("confidence", "low"),
                    description=result.get("description", ""),
                    action=result.get("action", "warn"),
                    side_effects=result.get("side_effects", ""),
                    rule_type="exact" if result == self.kb.lookup(domain) else "pattern",
                )
                rule_hits.append(hit)

        # ===== 第 2 层：行为特征匹配 =====
        # (实际使用时需要传入 flow 历史序列)
        # behavior_hits = self.bm.match(flow_history)
        # for bh in behavior_hits:
        #     rule_hits.append(RuleHit(...))

        # ===== 决策 =====
        return self._decide(rule_hits, domain)

    def _decide(self, hits: list[RuleHit], domain: str) -> Decision:
        """根据命中规则做决策"""

        # 白名单（action=allow 的规则优先）
        for hit in hits:
            if hit.action == "allow":
                return Decision(
                    action="allow",
                    reason=f"{domain} 属于 {hit.organization} 的核心服务，放通",
                    rule_hits=[hit],
                )

        # 高置信度命中 → 直接阻断
        for hit in hits:
            if hit.confidence == "high":
                return Decision(
                    action=hit.action,
                    reason=f"{domain} → {hit.organization}（{hit.description}）",
                    rule_hits=[hit],
                )

        # 中置信度 → 告警
        for hit in hits:
            if hit.confidence == "medium":
                return Decision(
                    action="warn",
                    reason=f"{domain} 疑似 {hit.organization} 的 {hit.category}，建议确认",
                    rule_hits=[hit],
                )

        # 完全未知 → 需要用户手动触发 AI
        if domain:
            return Decision(
                action="unknown",
                reason=f"域名 {domain} 不在知识库中，可点击「帮我分析」",
                rule_hits=[],
                requires_user_input=True,
            )

        return Decision(action="allow", reason="无域名信息，默认放通", rule_hits=[])


# ==================== 演示 ====================

if __name__ == "__main__":
    engine = DecisionEngine()

    # 测试用例
    test_cases = [
        ("api.ad.tuya.com", "涂鸦广告SDK → 应建议阻断"),
        ("ot.io.mi.com", "小米核心服务 → 应放通"),
        ("data.mistat.xiaomi.com", "小米遥测 → 应软阻断"),
        ("storage.ml-ops.samsung.com", "未知域名 → 需 AI 分析"),
        ("umeng.com", "友盟统计 → 应软阻断"),
        ("cdn.tuya.com", "涂鸦CDN → 应放通"),
    ]

    print("=" * 70)
    print("家卫 — 规则引擎演示")
    print("=" * 70)

    for domain, expected in test_cases:
        flow = FlowRecord(
            timestamp=1705316400,
            src_ip="192.168.1.100",
            dst_ip="203.0.113.1",
            dst_port=443,
            protocol="tcp",
            sni=domain,
            dns_query=domain,
            packet_size=1500,
            direction="out",
        )

        decision = engine.evaluate(flow)
        print(f"\n📡 域名: {domain}")
        print(f"   预期: {expected}")
        print(f"   决策: [{decision.action}] {decision.reason}")
        if decision.rule_hits:
            hit = decision.rule_hits[0]
            print(f"   归属: {hit.organization} / {hit.category}")
            if hit.side_effects:
                print(f"   影响: {hit.side_effects}")
