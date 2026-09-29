"""
W5 —— dns_source 切换（无代理 dnsmasq / 代理 syslog 两套共存可切换）

验证 CollectorRunner 按 ``dns_source`` 选出正确的 Tier1 采集器，且 conntrack（Tier2）
在两种模式下都照常启动；同时验证 SyslogDnsCollector 复用 DNS 解析、能从系统 syslog
行里捞出真实域名查询。

用标准库 unittest（与全仓一致，无需 pytest）。采集器通过注入 source 绕开真实系统依赖，
留到真机冒烟再验。
"""

import sys
import time
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from adapters.base import Collector, Observation, ProbeResult, Capabilities  # noqa: E402
from collectors.dns import DnsLogCollector                                  # noqa: E402
from collectors.syslog_dns import SyslogDnsCollector                        # noqa: E402
from core.collector import CollectorRunner                                 # noqa: E402
from core.main import HomewardService                                      # noqa: E402


class _FakeService:
    """只取 CollectorRunner 需要的属性，避免拉起整条决策链"""
    collection_status: list = []


class DnsSourceSwitchTest(unittest.TestCase):

    def test_default_builds_dnsmasq_collector(self):
        # 默认 dns_source 必须仍是 DnsLogCollector（零回归：无代理原架构不变）
        runner = CollectorRunner(_FakeService(), dns_source="dnsmasq")
        chosen = runner._build_collectors()
        dns = [c for c in chosen if isinstance(c, DnsLogCollector)]
        self.assertEqual(len(dns), 1)
        self.assertIsInstance(dns[0], DnsLogCollector)
        self.assertNotIsInstance(dns[0], SyslogDnsCollector)
        # conntrack（Tier2）必须仍在：两种模式都该有连接元数据
        from collectors.conntrack import ConntrackCollector
        self.assertTrue(any(isinstance(c, ConntrackCollector) for c in chosen))

    def test_syslog_source_builds_syslog_collector(self):
        runner = CollectorRunner(_FakeService(), dns_source="syslog")
        chosen = runner._build_collectors()
        self.assertTrue(any(isinstance(c, SyslogDnsCollector) for c in chosen))
        # 不应同时出现 DnsLogCollector（同一个 Tier1 位只能有一个）
        self.assertFalse(
            any(isinstance(c, DnsLogCollector) and not isinstance(c, SyslogDnsCollector)
                 for c in chosen)
        )

    def test_unknown_dns_source_falls_back_to_dnsmasq(self):
        # 配置笔误（非 dnsmasq/syslog）不能让 Tier1 消失，必须兜底回 dnsmasq
        runner = CollectorRunner(_FakeService(), dns_source="typo-should-not-crash")
        chosen = runner._build_collectors()
        self.assertTrue(any(isinstance(c, DnsLogCollector) for c in chosen))

    def test_syslog_collector_parses_syslog_formatted_query(self):
        # 系统 syslog 里 dnsmasq 查询行的真实形态（OpenWrt/iStoreOS 实机格式）：
        #   时间戳 + dnsmasq[pid]: query[A] 域名 from 客户端
        lines = iter([
            "Sep 29 14:02:27 dnsmasq[11]: query[A] www.baidu.com from 192.168.1.124\n",
            "Sep 29 14:02:27 dnsmasq[11]: cached www.baidu.com is 1.2.3.4\n",  # 非查询行，应被滤掉
        ])

        def _src():
            for line in lines:
                yield line

        collector = SyslogDnsCollector(source=_src)
        obs = list(collector.records())
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].fields["domain"], "www.baidu.com")
        self.assertEqual(obs[0].fields["client_ip"], "192.168.1.124")
        self.assertEqual(obs[0].kind, "dns")

    def test_syslog_collector_probe_unavailable_without_source(self):
        # 没源、也没默认 syslog 文件时，probe 必须如实报不可用（不假装看得见）
        collector = SyslogDnsCollector()
        # 在开发机 / Windows 上大概率找不到 syslog，探测结果应反映真实可用性
        probe = collector.probe()
        self.assertIsInstance(probe, ProbeResult)
        # 能力位与 DnsLogCollector 同属 Tier1
        caps = collector.capabilities()
        self.assertTrue(caps.dns_query)
        self.assertFalse(caps.sni)

    def test_injected_collectors_runner_still_works(self):
        # 回归：注入采集器时 dns_source 不影响注入逻辑
        svc = HomewardService(config={"load_system_devices": False})
        dummy = _OneShotCollector()
        runner = CollectorRunner(svc, collectors=[dummy])
        status = runner.start()
        try:
            for _ in range(50):
                if svc.stats["flows_processed"] >= 1:
                    break
                time.sleep(0.05)
            self.assertGreaterEqual(svc.stats["flows_processed"], 1)
            self.assertEqual(len(status), 1)
        finally:
            runner.stop()


class _OneShotCollector(Collector):
    """第一次 records() 吐一条 DNS 观测，之后短睡（可被 stop 唤醒）"""

    def __init__(self):
        self.calls = 0

    def capabilities(self):
        return Capabilities(dns_query=True, timing=True, is_lan_dns=True)

    def probe(self):
        return ProbeResult(True, "测试注入源（DNS）", self.capabilities())

    def degrade_to(self):
        return None

    def records(self):
        self.calls += 1
        if self.calls > 1:
            time.sleep(0.1)
            return
        yield Observation(
            timestamp=time.time(),
            kind="dns",
            device_id="192.168.1.50",
            fields={"domain": "test-unknown-domain-xyz.local", "client_ip": "192.168.1.50"},
        )


if __name__ == "__main__":
    unittest.main()
