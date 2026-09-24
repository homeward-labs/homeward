"""
Tier 1 —— DNS 查询采集器（社区版开源范围）

为什么 MVP 先做 DNS
-------------------
· **轻量、低权限、低资源**：读 dnsmasq 的查询日志即可，不需要抓包权限（CAP_NET_RAW），
  也不需要把自己塞进转发路径。这是「先 Linux、先 DNS」技术选型里最关键的一条——
  它决定了家卫能在低配 NAS 上常驻而不拖慢家庭网络。
· **已经够撑起旗舰告警**：「客厅摄像头半夜向陌生 ASN 问了 73 次」查的是
  **DNS 查询次数与时刻**，不依赖字节数。所以 Tier 1  alone 就能交付核心叙事。
· **配合知识库即可归属**：拿到域名后，交给 ``src/knowledge_base/domains.csv``
  做「域名 → 组织」，这是差异化的第一张牌。

看不到的（必须如实作为盲区上报，见 ROADMAP P0-6）
------------------------------------------------
· **加密 DNS（DoH / DoT）里的域名** —— 设备自己加密问了谁，本机 DNS 日志里没有；
· **直连 IP 的流量** —— 不经 DNS 解析，Tier 1 完全看不见（这才是补 Tier 2 的原因）；
· **字节数 / 包内容** —— 分别属于 Tier 2（conntrack）与 Tier 3（深度抓包，标准版）。

「看得见就说看得见，看不见就写清楚看不见」是家卫的承诺，实现上不允许含糊过去。
"""

from __future__ import annotations

import os
import re
import time
from typing import Callable, Iterator, Optional

from adapters.base import Capabilities, Collector, Observation, ProbeResult

__all__ = ["DnsLogCollector", "parse_dnsmasq_line"]


# ==================== 日志解析（纯函数，便于单测） ====================

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# dnsmasq 查询行两种形态都兼容：
#   带 syslog 前缀：Feb 11 12:34:56 dnsmasq[1234]: query[A] www.example.com from 192.168.1.50
#   不带前缀（部分容器 / 直写 stderr）：dnsmasq[1234]: query[A] www.example.com from 192.168.1.50
_QUERY_RE = re.compile(
    r"^(?:(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{1,2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+)?"
    r"dnsmasq(?:\[(?P<pid>\d+)\])?:\s+"
    r"query\[(?P<qtype>[A-Za-z0-9]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)\s*$"
)


def _now(now: Optional[float] = None) -> float:
    return time.time() if now is None else now


def _syslog_timestamp(match: re.Match, now: Optional[float] = None) -> float:
    """把 syslog 的「Mon DD HH:MM:SS」还原成时间戳

    syslog 不带年份，按「当前年」补齐；跨年场景（12 月的日志在 1 月被读）会导致
    算出来的时间落在未来，此时回退一年。解析不出就退回当前时间——宁可时间戳不精确，
    也不能因为一行日志格式怪异而丢掉整条观测记录。
    """
    mon = match.group("mon")
    if not mon:
        return _now(now)
    month = _MONTHS.get(mon)
    if month is None:
        return _now(now)

    t = _now(now)
    lt = time.localtime(t)
    try:
        day = int(match.group("day"))
        hh = int(match.group("hh"))
        mm = int(match.group("mm"))
        ss = int(match.group("ss"))
    except (TypeError, ValueError):
        return t

    def _mktime(year: int) -> Optional[float]:
        try:
            return time.mktime((year, month, day, hh, mm, ss, 0, 0, lt.tm_isdst))
        except (ValueError, OverflowError):
            return None

    stamp = _mktime(lt.tm_year)
    if stamp is None:
        return t
    # 日志时间比「现在」还晚一天以上，基本可以断定是跨年（去年 12 月 vs 今年 1 月）
    if stamp > t + 86400:
        stamp = _mktime(lt.tm_year - 1) or stamp
    return stamp


def parse_dnsmasq_line(line: str, *, now: Optional[float] = None) -> Optional[dict]:
    """解析一行 dnsmasq 查询日志

    只认 ``query[...]`` 行，其余（reply / cached / forwarded / DHCP / DNSSEC）一律返回
    ``None``——它们不是「设备主动问了谁」的证据，混进来会把频次统计算重。

    Returns:
        ``{"timestamp", "domain", "client_ip", "query_type"}`` 或 ``None``（非查询行 / 解析失败）
    """
    if not line:
        return None
    match = _QUERY_RE.match(line.strip())
    if not match:
        return None
    domain = match.group("domain")
    if not domain:
        return None
    return {
        "timestamp": _syslog_timestamp(match, now),
        "domain": domain.rstrip("."),
        "client_ip": match.group("client"),
        "query_type": match.group("qtype"),
    }


# ==================== 采集器 ====================

class DnsLogCollector(Collector):
    """跟随 dnsmasq 查询日志，产出 ``kind="dns"`` 的 Observation 流

    降级链位置：**最底层**。它不需要任何特权，也没有更弱的采集形态可退，
    因此 ``degrade_to()`` 返回 ``None``（Tier 2 conntrack 会降级到它，它没有下一级）。
    """

    DEFAULT_LOG_PATHS = (
        "/var/log/dnsmasq.log",
        "/var/log/dnsmasq/dnsmasq.log",
    )

    def __init__(
        self,
        log_path: Optional[str] = None,
        *,
        poll_interval: float = 0.5,
        source: Optional[Callable[[], Iterator[str]]] = None,
    ) -> None:
        """
        Args:
            log_path: 显式指定日志路径；留空则按 ``DEFAULT_LOG_PATHS`` 依次探测
            poll_interval: 无新行时的休眠间隔（秒）
            source: **测试注入用**的可调用对象，返回若干行文本；提供时完全不碰文件系统
        """
        self.log_path = log_path
        self.poll_interval = poll_interval
        self._source = source

    # —— 能力声明 ——

    def capabilities(self) -> Capabilities:
        """Tier 1 能力位：能看到域名与时序，看不到字节数与 SNI"""
        return Capabilities(
            dns_query=True,
            flow_bytes=False,
            sni=False,
            timing=True,
            is_lan_dns=True,
        )

    def probe(self) -> ProbeResult:
        caps = self.capabilities()
        if self._source is not None:
            return ProbeResult(True, "使用注入的日志源（测试/离线回放）", caps)

        path = self._resolve_path()
        if path is None:
            tried = "、".join(self.DEFAULT_LOG_PATHS)
            return ProbeResult(
                False,
                f"未找到 dnsmasq 日志文件（已尝试：{tried}）。"
                f"请确认 dnsmasq 开启了 log-queries 并指定了 log-facility",
                caps,
            )
        if not os.access(path, os.R_OK):
            return ProbeResult(False, f"日志文件存在但不可读：{path}（需要读权限）", caps)
        return ProbeResult(True, f"可读日志：{path}", caps)

    def degrade_to(self) -> Optional["Collector"]:
        """Tier 1 已是采集降级链的末端"""
        return None

    # —— 记录流 ——

    def records(self) -> Iterator[Observation]:
        if self._source is not None:
            for line in self._source():
                rec = parse_dnsmasq_line(line)
                if rec is not None:
                    yield self._to_observation(rec)
            return

        path = self._resolve_path()
        if path is None:
            return

        try:
            handle = open(path, "r", errors="replace")
        except OSError:
            return

        with handle:
            # 只从「现在」开始读：历史日志不该被当成实时事件重放一遍
            handle.seek(0, os.SEEK_END)
            try:
                last_inode = os.fstat(handle.fileno()).st_ino
            except OSError:
                last_inode = None

            while True:
                line = handle.readline()
                if line:
                    rec = parse_dnsmasq_line(line)
                    if rec is not None:
                        yield self._to_observation(rec)
                    continue

                time.sleep(self.poll_interval)

                # 日志轮转 / 截断：inode 变了或文件变小了，重新打开
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if last_inode is not None and (
                    st.st_ino != last_inode or st.st_size < handle.tell()
                ):
                    try:
                        new_handle = open(path, "r", errors="replace")
                    except OSError:
                        return
                    handle.close()
                    handle = new_handle
                    try:
                        last_inode = os.fstat(handle.fileno()).st_ino
                    except OSError:
                        last_inode = None

    # —— 内部 ——

    def _resolve_path(self) -> Optional[str]:
        if self.log_path:
            return self.log_path if os.path.exists(self.log_path) else None
        for candidate in self.DEFAULT_LOG_PATHS:
            if os.path.exists(candidate):
                return candidate
        return None

    @staticmethod
    def _to_observation(rec: dict) -> Observation:
        # device_id 先用 client_ip 占位：IP → MAC / 厂商 / 设备名的解析属于 W2 的职责
        return Observation(
            timestamp=rec["timestamp"],
            kind="dns",
            device_id=rec["client_ip"],
            fields={
                "domain": rec["domain"],
                "client_ip": rec["client_ip"],
                "query_type": rec["query_type"],
            },
        )
