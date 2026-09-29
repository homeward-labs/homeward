"""
Tier 1 —— 系统 syslog 里的 DNS 查询采集器（社区版开源范围）

**为什么需要第二种 DNS 数据源**
-----------------------------
``DnsLogCollector`` 读的是 dnsmasq 的专属日志文件（``log-facility`` 落点）。
但很多部署里 dnsmasq **不写专属文件、而是把查询日志发到系统 syslog**：

· OpenWrt / iStoreOS 上 ``log-queries`` 默认进 ``/var/log/messages``（或
  ``/var/log/syslog`` / ``/var/log/localmessages``，取决于发行版 syslog 配置）；
· 软路由 / NAS 把 dnsmasq 当作系统服务，查询日志混在系统 syslog 里。

更重要的是：在使用**代理软件**的家庭网络里，这是「方案 2」的数据源基础 ——
当代理以 fake-ip / redir-host（非 TUN）模式运行、且家卫处在 DNS 解析路径上
（网关或 DNS 转发器）时，客户端发出的**真实域名查询仍然会落到 syslog 里的
dnsmasq 查询行**，家卫照样能看见。本采集器就是为这种「换数据源、架构不变」
的场景准备的，与 ``DnsLogCollector`` 通过 ``dns_source`` 配置共存、可切换。

它与 ``DnsLogCollector`` 是**同一层（Tier 1）**、同一套解析，只是默认的落盘位置
不同；syslog 里非查询行（dhcp / kernel / 其他 daemon）由 ``parse_dnsmasq_line``
统一过滤，不会污染频次统计。

**看不见的（必须如实作为盲区上报）**
-----------------------------------
· **TUN 模式**：代理在内核层（``tun.dns-hijack: any:53``）把查询劫持进自身 DNS 引擎，
  查询不经过系统 dnsmasq，**syslog 里也没有**。此种情况本采集器同样全盲，
  需家卫处于网关 / 旁路抓包路径 + 标准版的 pcap 采集器（SNI / SOCKS5 域名）；
· **系统代理 / 应用层 HTTP+SOCKS**：客户端不本地解析、远端解析，syslog 里无查询；
· **加密 DNS（DoH / DoT）**：设备自己加密问了谁，本机日志里没有。

「看得见就说看得见，看不见就写清楚看不见」是家卫的承诺，实现上不允许含糊过去。
"""

from __future__ import annotations

import os
from typing import Optional

from adapters.base import Capabilities, Collector, Observation, ProbeResult

from .dns import DnsLogCollector, parse_dnsmasq_line


class SyslogDnsCollector(DnsLogCollector):
    """跟随系统 syslog 里的 dnsmasq 查询行，产出 ``kind="dns"`` 的 Observation 流

    实现上直接复用 ``DnsLogCollector`` 的全部行为（文件尾读、轮转重开、半行保护、
    ``parse_dnsmasq_line`` 解析），只是把默认落点从 dnsmasq 专属日志换成系统 syslog。
    这样两种数据源共享同一套经过实机打磨的健壮逻辑，不会出现「换源就换一套、各写各的」。
    """

    # 覆盖数据源标签：probe 文案、UI 盲区说明会随之显示「syslog」而不是「dnsmasq」
    SOURCE_LABEL = "syslog"

    # 系统 syslog 的常见落点（按发行版常见顺序探测）
    DEFAULT_LOG_PATHS = (
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/localmessages",
        # 某些容器 / 经 journald 导出到文件的情形
        "/var/log/user.log",
    )

    def __init__(
        self,
        log_path: Optional[str] = None,
        *,
        poll_interval: float = 0.5,
        source=None,
    ) -> None:
        """
        Args:
            log_path: 显式指定 syslog 文件路径；留空则按 ``DEFAULT_LOG_PATHS`` 依次探测
            poll_interval: 无新行时的休眠间隔（秒）
            source: **测试注入用**的可调用对象，返回若干行文本；提供时完全不碰文件系统
        """
        # 复用父类构造（父类把 source / log_path / poll_interval 都存好了）
        super().__init__(log_path=log_path, poll_interval=poll_interval, source=source)

    # —— 能力声明（与 DnsLogCollector 完全一致：同属 Tier 1）——
    def capabilities(self) -> Capabilities:
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
                f"未找到 {self.SOURCE_LABEL} 日志文件（已尝试：{tried}）。"
                f"请确认系统 syslog 开启了 dnsmasq 查询日志"
                f"（OpenWrt / iStoreOS 需 log-queries，且未把查询单独导向 dnsmasq 文件）",
                caps,
            )
        if not os.access(path, os.R_OK):
            return ProbeResult(False, f"日志文件存在但不可读：{path}（需要读权限）", caps)
        return ProbeResult(True, f"可读日志：{path}", caps)

    def degrade_to(self) -> Optional[Collector]:
        """Tier 1 已是采集降级链的末端"""
        return None


__all__ = ["SyslogDnsCollector"]
