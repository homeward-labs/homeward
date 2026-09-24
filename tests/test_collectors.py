"""
采集层单测（Tier 1 DNS / Tier 2 conntrack）

用标准库 unittest，与 tests/test_revert_contract.py 保持一致（无需装 pytest）。

设计取向：把「解析」与「增量计算」都做成**纯函数**，这样在 Windows 开发机上也能
全量验证；真正依赖 Linux 的部分（读 /proc、跟日志文件）通过注入 source 绕开，
留到真机冒烟时再验。
"""

import sys
import unittest
from pathlib import Path

# 与 src/core/main.py 一致：把 src/ 加进 sys.path 后用扁平导入
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from collectors.conntrack import (  # noqa: E402
    ConntrackCollector,
    compute_flow_deltas,
    parse_conntrack_line,
)
from collectors.dns import DnsLogCollector, parse_dnsmasq_line  # noqa: E402


# ==================== 样本数据 ====================

DNS_WITH_SYSLOG = (
    "Feb 11 12:34:56 dnsmasq[1234]: query[A] api.ad.tuya.com from 192.168.1.50"
)
DNS_NO_SYSLOG = "dnsmasq[1234]: query[AAAA] www.example.com from 192.168.1.51"
DNS_REPLY = "Feb 11 12:34:56 dnsmasq[1234]: reply api.ad.tuya.com is 1.2.3.4"
DNS_CACHED = "Feb 11 12:34:56 dnsmasq[1234]: cached www.example.com is 1.2.3.4"
DNS_DHCP = "Feb 11 12:34:56 dnsmasq-dhcp[1234]: DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:ff"

CT_EXTENDED = (
    "ipv4     2 tcp      6 431999 ESTABLISHED "
    "src=192.168.1.50 dst=1.2.3.4 sport=54321 dport=443 packets=5 bytes=300 "
    "src=1.2.3.4 dst=192.168.1.50 sport=443 dport=54321 packets=4 bytes=200 "
    "[ASSURED] mark=0 zone=0 use=2"
)
CT_PROCFS_NO_ACCT = (
    "ipv4     2 tcp      6 431999 ESTABLISHED "
    "src=192.168.1.50 dst=1.2.3.4 sport=54321 dport=443 "
    "src=1.2.3.4 dst=192.168.1.50 sport=443 dport=54321 "
    "[ASSURED] mark=0 zone=0 use=2"
)
CT_UDP = (
    "ipv4     2 udp      17 29 "
    "src=192.168.1.60 dst=8.8.8.8 sport=51000 dport=53 "
    "src=8.8.8.8 dst=192.168.1.60 sport=53 dport=51000 mark=0 zone=0 use=2"
)
CT_JUNK = "total 12"


# ==================== Tier 1：DNS 解析 ====================

class TestDnsParsing(unittest.TestCase):
    def test_parse_with_syslog_prefix(self):
        rec = parse_dnsmasq_line(DNS_WITH_SYSLOG)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["domain"], "api.ad.tuya.com")
        self.assertEqual(rec["client_ip"], "192.168.1.50")
        self.assertEqual(rec["query_type"], "A")
        self.assertIsInstance(rec["timestamp"], float)

    def test_parse_without_syslog_prefix(self):
        rec = parse_dnsmasq_line(DNS_NO_SYSLOG)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["domain"], "www.example.com")
        self.assertEqual(rec["query_type"], "AAAA")
        self.assertEqual(rec["client_ip"], "192.168.1.51")

    def test_non_query_lines_are_ignored(self):
        """reply / cached / DHCP 都不是「设备主动问了谁」，计入会算重频次"""
        self.assertIsNone(parse_dnsmasq_line(DNS_REPLY))
        self.assertIsNone(parse_dnsmasq_line(DNS_CACHED))
        self.assertIsNone(parse_dnsmasq_line(DNS_DHCP))

    def test_empty_and_garbage(self):
        self.assertIsNone(parse_dnsmasq_line(""))
        self.assertIsNone(parse_dnsmasq_line("random noise"))

    def test_trailing_dot_is_stripped(self):
        rec = parse_dnsmasq_line(
            "dnsmasq[1]: query[A] example.com. from 192.168.1.5"
        )
        self.assertIsNotNone(rec)
        self.assertEqual(rec["domain"], "example.com")


# ==================== Tier 2：conntrack 解析 ====================

class TestConntrackParsing(unittest.TestCase):
    def test_extended_format_takes_original_direction(self):
        """首次出现的 src/dst/bytes 属于原始方向（设备→外网），即「上传」"""
        rec = parse_conntrack_line(CT_EXTENDED)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["proto"], "tcp")
        self.assertEqual(rec["src_ip"], "192.168.1.50")
        self.assertEqual(rec["dst_ip"], "1.2.3.4")
        self.assertEqual(rec["src_port"], 54321)
        self.assertEqual(rec["dst_port"], 443)
        self.assertEqual(rec["bytes_total"], 300)
        self.assertEqual(rec["packets"], 5)

    def test_no_accounting_means_unknown_not_zero(self):
        """没开 nf_conntrack_acct 就根本没有字节数 —— 不能伪造 0"""
        rec = parse_conntrack_line(CT_PROCFS_NO_ACCT)
        self.assertIsNotNone(rec)
        self.assertIsNone(rec["bytes_total"])
        self.assertIsNone(rec["packets"])

    def test_udp_entry(self):
        rec = parse_conntrack_line(CT_UDP)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["proto"], "udp")
        self.assertEqual(rec["dst_port"], 53)

    def test_junk_returns_none(self):
        self.assertIsNone(parse_conntrack_line(CT_JUNK))
        self.assertIsNone(parse_conntrack_line(""))
        self.assertIsNone(parse_conntrack_line("ipv4 2 tcp"))


# ==================== Tier 2：增量计算（最易错，重点测） ====================

class TestFlowDeltas(unittest.TestCase):
    def _rec(self, total, src="192.168.1.50", sport=54321):
        return {
            "proto": "tcp",
            "src_ip": src,
            "dst_ip": "1.2.3.4",
            "src_port": sport,
            "dst_port": 443,
            "bytes_total": total,
            "packets": 5,
        }

    def test_new_flow_reports_cumulative(self):
        last: dict = {}
        deltas = compute_flow_deltas([self._rec(300)], last)
        self.assertEqual(len(deltas), 1)
        _, delta, total = deltas[0]
        self.assertEqual(delta, 300)
        self.assertEqual(total, 300)

    def test_unchanged_flow_is_not_reported(self):
        last: dict = {}
        compute_flow_deltas([self._rec(300)], last)
        self.assertEqual(compute_flow_deltas([self._rec(300)], last), [])

    def test_growth_reports_increment_only(self):
        last: dict = {}
        compute_flow_deltas([self._rec(300)], last)
        deltas = compute_flow_deltas([self._rec(500)], last)
        self.assertEqual(len(deltas), 1)
        _, delta, total = deltas[0]
        self.assertEqual(delta, 200)   # 只报增量，否则流量统计会翻倍
        self.assertEqual(total, 500)

    def test_disappeared_flow_is_evicted(self):
        last: dict = {}
        compute_flow_deltas([self._rec(300)], last)
        self.assertEqual(len(last), 1)
        compute_flow_deltas([], last)
        self.assertEqual(len(last), 0)

    def test_unknown_bytes_are_skipped(self):
        """没有字节数的连接既不产生增量，也不污染记账表"""
        last: dict = {}
        rec = self._rec(300)
        rec["bytes_total"] = None
        self.assertEqual(compute_flow_deltas([rec], last), [])
        self.assertEqual(len(last), 0)


# ==================== 采集器契约 ====================

class TestCollectorContract(unittest.TestCase):
    def test_dns_capabilities(self):
        caps = DnsLogCollector().capabilities()
        self.assertTrue(caps.dns_query)
        self.assertTrue(caps.timing)
        self.assertFalse(caps.flow_bytes)   # 字节数是 Tier 2 的事
        self.assertFalse(caps.sni)
        self.assertTrue(caps.is_lan_dns)

    def test_conntrack_capabilities(self):
        caps = ConntrackCollector().capabilities()
        self.assertTrue(caps.flow_bytes)
        self.assertTrue(caps.timing)
        self.assertFalse(caps.dns_query)    # 域名靠 Tier 1 关联
        self.assertFalse(caps.sni)

    def test_degrade_chain_tier2_to_tier1_to_none(self):
        """降级链：conntrack → DNS → 到底"""
        tier2 = ConntrackCollector()
        tier1 = tier2.degrade_to()
        self.assertIsInstance(tier1, DnsLogCollector)
        self.assertIsNone(tier1.degrade_to())

    def test_dns_records_from_injected_source(self):
        collector = DnsLogCollector(
            source=lambda: iter([DNS_WITH_SYSLOG, DNS_REPLY, DNS_DHCP])
        )
        observations = list(collector.records())
        self.assertEqual(len(observations), 1)   # reply 与 DHCP 行被正确丢弃
        obs = observations[0]
        self.assertEqual(obs.kind, "dns")
        self.assertEqual(obs.device_id, "192.168.1.50")
        self.assertEqual(obs.fields["domain"], "api.ad.tuya.com")

    def test_conntrack_records_from_injected_source(self):
        collector = ConntrackCollector(source=lambda: [CT_EXTENDED])
        observations = list(collector.records())
        self.assertEqual(len(observations), 1)
        obs = observations[0]
        self.assertEqual(obs.kind, "flow")
        self.assertEqual(obs.device_id, "192.168.1.50")
        self.assertEqual(obs.fields["bytes"], 300)
        self.assertEqual(obs.fields["bytes_total"], 300)

    def test_probe_with_injected_source_is_available(self):
        self.assertTrue(DnsLogCollector(source=lambda: iter([])).probe().available)
        self.assertTrue(ConntrackCollector(source=lambda: []).probe().available)


if __name__ == "__main__":
    unittest.main(verbosity=2)
