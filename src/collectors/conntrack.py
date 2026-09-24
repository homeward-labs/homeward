"""
Tier 2 —— 连接元数据采集器（conntrack，社区版）

为什么补这一层（ROADMAP P0.5，2026-09-24 已定纳入社区版）
--------------------------------------------------------
Tier 1（DNS）有两个硬伤，conntrack 正好补上：

· **看不见直连 IP 的流量** —— 设备硬编码 IP 或用加密 DNS 时，DNS 日志里什么都没有，
  但连接是真实存在的。conntrack 直接给出「设备 ↔ 对端 IP/端口」，盲区大幅收窄。
· **拿不到字节数** —— 「突发大流量上传」这类体积型判定（behaviors.json 的
  ``bulk_upload``）没有字节数根本判不了，而它恰恰是摄像头隐私故事里最有说服力的一条。

成本远低于抓包：读 ``/proc/net/nf_conntrack`` 或调 ``conntrack -L`` 即可，
**不需要 CAP_NET_RAW 抓包权限**，这也是它留在社区版而非标准版的理由。

看不到的（如实作为盲区上报）
----------------------------
· **域名** —— conntrack 只有 IP；域名要靠 Tier 1 的 DNS 记录做 IP↔域名 关联；
· **加密域名（SNI）** —— 那是 Tier 3（深度抓包 / DPI），归标准版；
· **包内容** —— 家卫全程不解密、不看 payload。

一个前提
--------
``/proc/net/nf_conntrack`` 默认**不带字节数**，需要内核开启连接计费：
``sysctl -w net.netfilter.nf_conntrack_acct=1``。没开的话本采集器仍然能报
「有哪些连接」，但 ``bytes_total`` 为 ``None`` —— 此时必须如实上报，
不能假装字节数是 0（0 和「不知道」是两回事）。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import Callable, Iterator, Optional

from adapters.base import Capabilities, Collector, Observation, ProbeResult

from .dns import DnsLogCollector

__all__ = ["ConntrackCollector", "parse_conntrack_line", "compute_flow_deltas"]


# ==================== 解析（纯函数，便于单测） ====================

# 关心的键；其余（mark / zone / use / secctx / delta-time …）一律忽略
_TRACKED_KEYS = ("src", "dst", "sport", "dport", "bytes", "packets")
_PROTOS = ("tcp", "udp", "icmp", "gre", "sctp", "dccp", "udplite")


def parse_conntrack_line(line: str) -> Optional[dict]:
    """解析一行 conntrack 记录

    同时兼容两种来源格式：

    · ``/proc/net/nf_conntrack``（内核 procfs，字节数需 ``nf_conntrack_acct=1``）::

          ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.50 dst=1.2.3.4 sport=54321 dport=443 ...

    · ``conntrack -L -o extended``（conntrack-tools，自带 packets/bytes）::

          ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.50 dst=1.2.3.4 sport=54321 dport=443 packets=5 bytes=300 ...

    两种格式里 **第一次出现** 的 src/dst/sport/dport/bytes 都属于「原始方向」
    （设备 → 外网），即我们要的「上传」方向；第二次出现的是回程方向。
    这里用 ``setdefault`` 取首次出现值，正好对应原始方向。

    Returns:
        解析成功返回 ``{"proto", "src_ip", "dst_ip", "src_port", "dst_port",
        "bytes_total", "packets"}``（后两者可能为 ``None``）；非连接行 / 解析失败返回 ``None``。
    """
    if not line:
        return None

    parts = line.split()
    if len(parts) < 4:
        return None

    proto = parts[2].lower()
    if proto not in _PROTOS:
        return None

    kv: dict[str, str] = {}
    for token in parts[3:]:
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        if key in _TRACKED_KEYS and key not in kv:
            kv[key] = value

    src = kv.get("src")
    dst = kv.get("dst")
    if not src or not dst:
        return None

    def _int(key: str) -> Optional[int]:
        raw = kv.get(key)
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    return {
        "proto": proto,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": _int("sport"),
        "dst_port": _int("dport"),
        "bytes_total": _int("bytes"),
        "packets": _int("packets"),
    }


def compute_flow_deltas(
    records: list[dict],
    last_bytes: dict[tuple, int],
) -> list[tuple[tuple, int, int]]:
    """按五元组算「本轮新增字节数」，并原地更新 / 清理 ``last_bytes``

    单独抽成纯函数的理由：conntrack 是快照而非事件流，增量算错就会把累计值重复灌给
    上层，导致流量统计翻倍——这种 bug 在集成环境下极难复现，必须能单测。

    Args:
        records: ``parse_conntrack_line`` 的输出列表
        last_bytes: 上轮各连接的累计字节数，**会被原地更新**（同时清掉已消失的连接）

    Returns:
        ``[(五元组, 增量字节, 累计字节), ...]``。
        · 新连接：增量 == 累计（首次按累计值上报）；
        · 已有连接且无新增：不产生条目（避免刷屏）；
        · ``bytes_total`` 为 ``None`` 的连接：跳过（没开连接计费，不伪造 0）。
    """
    deltas: list[tuple[tuple, int, int]] = []
    alive: set[tuple] = set()

    for rec in records:
        key = (
            rec["proto"],
            rec["src_ip"],
            rec["dst_ip"],
            rec["src_port"],
            rec["dst_port"],
        )
        alive.add(key)

        total = rec.get("bytes_total")
        if total is None:
            # 没开连接计费：拿不到字节数就别伪造，交给上层按「未知」处理
            continue

        previous = last_bytes.get(key)
        delta = total if previous is None else max(0, total - previous)
        last_bytes[key] = total

        # 已知连接且本轮没有新增流量 → 不上报，避免每轮重复灌数据
        if previous is not None and delta == 0:
            continue
        deltas.append((key, delta, total))

    # 连接已消失 → 清掉记账，防止表无限膨胀
    for key in list(last_bytes):
        if key not in alive:
            del last_bytes[key]

    return deltas


# ==================== 采集器 ====================

class ConntrackCollector(Collector):
    """轮询 conntrack 连接表，产出 ``kind="flow"`` 的 Observation 流

    与 Tier 1 的关键差异：DNS 是**事件流**（来一行算一次），conntrack 是**快照**
    （每次读到的是「当前有哪些连接」）。所以这里做增量处理：按五元组记住上次
    字节数，只上报**新增的字节数**，避免每轮把累计值重复灌给上层造成流量翻倍。
    """

    DEFAULT_PROC_PATH = "/proc/net/nf_conntrack"
    DEFAULT_COMMAND = ("conntrack", "-L", "-o", "extended")

    def __init__(
        self,
        proc_path: str = DEFAULT_PROC_PATH,
        *,
        command: tuple[str, ...] = DEFAULT_COMMAND,
        poll_interval: float = 5.0,
        source: Optional[Callable[[], list[str]]] = None,
    ) -> None:
        """
        Args:
            proc_path: procfs 连接表路径
            command: procfs 不可读时退而调用的命令（argv 形式，不经 shell）
            poll_interval: 轮询间隔（秒）
            source: **测试注入用**，返回若干行文本；提供时完全不碰系统
        """
        self.proc_path = proc_path
        self.command = command
        self.poll_interval = poll_interval
        self._source = source

    # —— 能力声明 ——

    def capabilities(self) -> Capabilities:
        """Tier 2 能力位：有字节数与时序，没有域名与 SNI"""
        return Capabilities(
            dns_query=False,
            flow_bytes=True,
            sni=False,
            timing=True,
        )

    def probe(self) -> ProbeResult:
        caps = self.capabilities()
        if self._source is not None:
            return ProbeResult(True, "使用注入的连接表源（测试/离线回放）", caps)
        if os.access(self.proc_path, os.R_OK):
            return ProbeResult(True, f"可读连接表：{self.proc_path}", caps)
        if shutil.which(self.command[0] if self.command else ""):
            return ProbeResult(True, f"可用命令：{' '.join(self.command)}", caps)
        return ProbeResult(
            False,
            f"既读不到 {self.proc_path}，也没有 {' '.join(self.command)} 命令；"
            f"Tier 2 不可用，将降级到 Tier 1（DNS）",
            caps,
        )

    def degrade_to(self) -> Optional["Collector"]:
        """Tier 2 不可用时退到 Tier 1（只降级采集视野，不影响执行侧能力）"""
        return DnsLogCollector()

    # —— 记录流 ——

    def records(self) -> Iterator[Observation]:
        last_bytes: dict[tuple, int] = {}
        by_key: dict[tuple, dict] = {}

        while True:
            records = []
            for line in self._snapshot():
                parsed = parse_conntrack_line(line)
                if parsed is not None:
                    records.append(parsed)

            now = time.time()
            for rec in records:
                by_key.setdefault(
                    (
                        rec["proto"],
                        rec["src_ip"],
                        rec["dst_ip"],
                        rec["src_port"],
                        rec["dst_port"],
                    ),
                    rec,
                )

            for key, delta, total in compute_flow_deltas(records, last_bytes):
                rec = by_key.get(key)
                if rec is None:
                    continue
                yield Observation(
                    timestamp=now,
                    kind="flow",
                    device_id=rec["src_ip"],
                    fields={
                        "proto": rec["proto"],
                        "src_ip": rec["src_ip"],
                        "dst_ip": rec["dst_ip"],
                        "src_port": rec["src_port"],
                        "dst_port": rec["dst_port"],
                        "bytes": delta,            # 本轮增量
                        "bytes_total": total,      # 连接累计
                        "packets": rec["packets"],
                    },
                )

            by_key.clear()

            if self._source is not None:
                # 注入源只跑一轮，便于单测断言
                return
            time.sleep(self.poll_interval)

    # —— 内部 ——

    def _snapshot(self) -> list[str]:
        """取一次连接表快照（注入源 > procfs > 命令）"""
        if self._source is not None:
            return list(self._source())

        if os.access(self.proc_path, os.R_OK):
            try:
                with open(self.proc_path, "r", errors="replace") as handle:
                    return handle.readlines()
            except OSError:
                return []

        try:
            completed = subprocess.run(
                self.command, capture_output=True, text=True, timeout=10
            )
            if completed.returncode == 0:
                return completed.stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            pass
        return []
