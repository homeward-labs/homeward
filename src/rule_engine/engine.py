"""
规则匹配引擎 - 核心判定逻辑
"""

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


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

class BehaviorMatcher:
    """行为特征规则匹配"""

    def __init__(self, behaviors_path: str = None):
        if behaviors_path is None:
            # 目录名是**下划线** knowledge_base，不是连字符 knowledge-base。
            # 早期这里写错过，结果是默认构造时行为库静默加载为空、所有行为类判定
            # （心跳信标 / 突发上传 / DNS 隧道……）无声失效 —— 故改为显式报错。
            behaviors_path = Path(__file__).parent.parent / "knowledge_base" / "behaviors.json"
        self.behaviors_path = Path(behaviors_path)
        self.rules: list[dict] = []
        self.load()

    def load(self):
        """加载 behaviors.json

        加载不到规则**必须显式失败**，不允许静默置空：行为库为空会让全部行为类判定
        失效，且失败得毫无征兆（判不出告警和"没有异常"看起来一模一样）。
        """
        path = self.behaviors_path
        if not path.exists():
            raise FileNotFoundError(f"行为模式库不存在：{path}")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        self.rules = [
            {"id": k, **v} for k, v in data.items()
        ]
        if not self.rules:
            raise ValueError(f"行为模式库为空：{path}")

    def match(self, flow_history: list[FlowRecord]) -> list[dict]:
        """
        对一组 flow 记录做行为特征匹配
        flow_history: 某个设备在某段时间内的所有 flow
        """
        results = []
        for rule in self.rules:
            pattern = rule.get("pattern", {})
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
        """
        direction = pattern.get("direction", "out")
        relevant = sorted(
            (f for f in flows if f.direction == direction),
            key=lambda f: f.timestamp,
        )

        if not relevant:
            return False

        # 样本量下限：出现次数不够，不敢下任何行为结论
        min_occurrences = pattern.get("min_occurrences")
        if min_occurrences and len(relevant) < min_occurrences:
            return False

        # 观测窗口长度（秒）—— 首尾观测的时间跨度，不是条数
        duration_min = pattern.get("duration_min")
        if duration_min is not None:
            span = relevant[-1].timestamp - relevant[0].timestamp
            if span < duration_min:
                return False

        # 突发流量：窗口内累计字节数
        if "total_bytes_min" in pattern:
            total = sum(f.packet_size for f in relevant)
            if total < pattern["total_bytes_min"]:
                return False

        # 包大小范围：按窗口内平均包大小判定（逐包判定太脆，噪声一多就漏报）
        packet_size = pattern.get("packet_size")
        if packet_size:
            avg_size = sum(f.packet_size for f in relevant) / len(relevant)
            lo = packet_size.get("min", 0)
            hi = packet_size.get("max", float("inf"))
            if not (lo <= avg_size <= hi):
                return False

        # 心跳信标：相邻观测的时间间隔是否稳定落在 [min, max]
        interval = pattern.get("interval")
        if interval:
            if len(relevant) < 2:
                return False
            lo = interval.get("min", 0)
            hi = interval.get("max", float("inf"))
            gaps = [b.timestamp - a.timestamp for a, b in zip(relevant, relevant[1:])]
            if any(not (lo <= gap <= hi) for gap in gaps):
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
