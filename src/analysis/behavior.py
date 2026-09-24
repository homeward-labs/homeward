"""
行为识别：把「一串流量记录」变成「一条有证据的行为认定」。

规则引擎（``BehaviorMatcher``）回答的是「这组观测满足不满足某个模式」，它只看被塞进来的
那一组记录。真实场景里还需要回答三个它不负责的问题：

1. **窗口**：判定应该基于多长时间的观测？心跳信标看 30 分钟，DNS 隧道看 60 秒，
   周期性外联要看好几个小时 —— 一律用同一个窗口会两头不讨好。
   窗口长度由规则自带（``window_seconds``），本模块按它切分。
2. **粒度**：是看「这台设备的全部外联」还是「这台设备到某个目的地」？
   挖矿要看设备连了多少个不同的池子（设备级），突发上传要看具体传到哪儿（目的地级）。
   由规则自带 ``scope`` 决定。
3. **证据**：命中之后要留下可复核的数字 —— 多少次、多少字节、什么时间、间隔多长。
   没有证据的告警等于没法复核的指控，本项目不做。

产出是 :class:`BehaviorFinding`，交给 ``alerting`` 渲染成人话。
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from rule_engine.engine import BehaviorMatcher, FlowRecord

DEFAULT_WINDOW_SECONDS = 3600.0


@dataclass
class BehaviorFinding:
    """一次行为认定 —— 带证据，不带情绪"""

    rule_id: str
    rule_name: str
    severity: str            # critical / high / medium / low
    category: str
    confidence: str          # high / medium / low
    action: str              # 建议动作；社区版到此为止，不会真的下发
    scope: str               # device / destination

    src_ip: str
    destination: str         # 域名，没有域名时退回 ip:port
    domain: Optional[str]

    window_seconds: float
    start_ts: float
    end_ts: float

    # 证据（renderer 负责把它格式化成人话）
    evidence: dict = field(default_factory=dict)

    @property
    def destination_label(self) -> str:
        return self.domain or self.destination


def destination_of(flow: FlowRecord) -> str:
    """观测目标的稳定标识：有域名用域名，否则用 ip:port"""
    domain = (flow.sni or flow.dns_query or "").strip().rstrip(".")
    if domain:
        return domain
    if flow.dst_ip:
        return f"{flow.dst_ip}:{flow.dst_port}" if flow.dst_port else flow.dst_ip
    return ""


def summarize(records: list[FlowRecord]) -> dict:
    """把一组观测压成可复核的证据数字

    刻意保留**原始数值**（秒、字节、次数），不做本地化格式化 —— 格式化是渲染层的
    职责。同一份证据既能渲染成中文告警，也能直接进日志或导出给人工复核。
    """
    if not records:
        return {}
    ordered = sorted(records, key=lambda f: f.timestamp)
    total_bytes = sum(f.packet_size for f in ordered)
    span = ordered[-1].timestamp - ordered[0].timestamp
    gaps = [b.timestamp - a.timestamp for a, b in zip(ordered, ordered[1:])]
    queries = [f for f in ordered if f.dns_query]
    labels: list[int] = []
    for f in ordered:
        dom = f.dns_query or f.sni or ""
        if dom:
            labels.append(max((len(x) for x in dom.split(".")), default=0))
    return {
        "occurrences": len(ordered),
        "total_bytes": total_bytes,
        "avg_packet": (total_bytes / len(ordered)) if ordered else 0.0,
        "span_seconds": span,
        "avg_interval_seconds": (sum(gaps) / len(gaps)) if gaps else 0.0,
        "start_ts": ordered[0].timestamp,
        "end_ts": ordered[-1].timestamp,
        "longest_label": max(labels) if labels else 0,
        "dns_queries": len(queries),
        "dns_rate": (len(queries) / span) if span > 0 else float(len(queries)),
        "distinct_connections": len({
            (f.dst_ip, f.dst_port, f.sni or f.dns_query or "") for f in ordered
        }),
    }


class BehaviorDetector:
    """按规则自带的窗口与粒度，持续判定行为"""

    def __init__(
        self,
        matcher: Optional[BehaviorMatcher] = None,
        max_records: int = 2000,
    ):
        self.matcher = matcher or BehaviorMatcher()
        self.max_records = int(max_records)
        self.rules = list(self.matcher.supported_rules)

        windows = [float(r.get("window_seconds", DEFAULT_WINDOW_SECONDS)) for r in self.rules]
        self.retention_seconds = max(windows) if windows else DEFAULT_WINDOW_SECONDS

        # 两个粒度的观测池，都是 FIFO 有界队列
        self.device_flows: dict[str, deque] = {}
        self.dest_flows: dict[tuple[str, str], deque] = {}

        self.stats = {"fed": 0, "scans": 0, "findings": 0}

    # ---------------------------------------------------------------- 喂数据

    def feed(self, flow: FlowRecord, now: Optional[float] = None) -> None:
        """把一条观测放进对应的窗口。没有源 IP 的记录无处安放，丢弃。

        ``now`` 省略时**按观测自带的时间戳裁剪**，而不是按挂钟时间 —— 否则离线回放
        历史日志（时间戳是过去的时间）时，记录一进窗口就被判为过期、立刻清空。
        """
        if not flow.src_ip:
            return
        self.stats["fed"] += 1
        ts = now if now is not None else flow.timestamp

        bucket = self.device_flows.get(flow.src_ip)
        if bucket is None:
            bucket = deque(maxlen=self.max_records)
            self.device_flows[flow.src_ip] = bucket
        bucket.append(flow)

        dest = destination_of(flow)
        if dest:
            key = (flow.src_ip, dest)
            d_bucket = self.dest_flows.get(key)
            if d_bucket is None:
                d_bucket = deque(maxlen=self.max_records)
                self.dest_flows[key] = d_bucket
            d_bucket.append(flow)

        self._prune(flow.src_ip, dest, ts)

    def _prune(self, src_ip: str, dest: str, now: float) -> None:
        """丢掉超出最长窗口的旧记录，避免内存随运行时间线性膨胀"""
        cutoff = now - self.retention_seconds
        for bucket in (self.device_flows.get(src_ip), self.dest_flows.get((src_ip, dest))):
            if not bucket:
                continue
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()

    def feed_many(self, flows, now: Optional[float] = None) -> None:
        for flow in flows:
            self.feed(flow, now)

    # ---------------------------------------------------------------- 判定

    def scan(self, now: Optional[float] = None) -> list[BehaviorFinding]:
        """跑一遍全部规则，返回本轮的行为认定"""
        now = time.time() if now is None else now
        self.stats["scans"] += 1
        findings: list[BehaviorFinding] = []

        for rule in self.rules:
            scope = rule.get("scope", "destination")
            window = float(rule.get("window_seconds", DEFAULT_WINDOW_SECONDS))
            buckets = self.device_flows if scope == "device" else self.dest_flows
            pattern = rule.get("pattern") or {}

            for key, bucket in buckets.items():
                if not bucket:
                    continue
                # 只取窗口内的观测：窗口长度由规则自己声明
                records = [f for f in bucket if now - window <= f.timestamp <= now]
                if not records:
                    continue
                if not self.matcher._matches(records, pattern):
                    continue

                src_ip, dest = key if scope == "destination" else (key, "")
                findings.append(self._build(rule, src_ip, dest, records, window, scope))

        self.stats["findings"] += len(findings)
        return findings

    def _build(
        self,
        rule: dict,
        src_ip: str,
        dest: str,
        records: list[FlowRecord],
        window: float,
        scope: str,
    ) -> BehaviorFinding:
        evidence = summarize(records)
        domain: Optional[str] = None
        for f in records:
            domain = f.sni or f.dns_query or None
            if domain:
                break
        return BehaviorFinding(
            rule_id=rule["id"],
            rule_name=rule.get("name", rule["id"]),
            severity=rule.get("severity", "low"),
            category=rule.get("category", "unknown"),
            confidence=rule.get("confidence", "medium"),
            action=rule.get("action", "warn"),
            scope=scope,
            src_ip=src_ip,
            destination=dest or "（多个目的地）",
            domain=domain,
            window_seconds=window,
            start_ts=evidence.get("start_ts", 0.0),
            end_ts=evidence.get("end_ts", 0.0),
            evidence=evidence,
        )

    # ---------------------------------------------------------------- 运维

    def tracked_keys(self) -> dict[str, int]:
        """当前维护了多少个观测池 —— 规模失控时该看这个数字"""
        return {
            "devices": len(self.device_flows),
            "destinations": len(self.dest_flows),
        }

    def reset(self) -> None:
        self.device_flows.clear()
        self.dest_flows.clear()
        self.stats = {"fed": 0, "scans": 0, "findings": 0}
