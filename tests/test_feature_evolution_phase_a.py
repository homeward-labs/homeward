"""
Phase A（信任修复 + 隐私体检）回归测试。

覆盖 FEATURE-EVOLUTION.md 里 Phase A 的五项功能演进：
  F1 设备去噪与归并（噪声地址不单独建档，归并到「本机」）
  F2 bulk_upload 误报修复（内网/组播/广播目的地不再误判为外泄）
  F3 建议去重与聚合（同设备+同域名只留一条、次数累加）
  F4 覆盖率口径统一（累计并集、剔除直连 IP / .lan）
  F5 一键隐私体检（结论先行，导出报告含体检结论）

用标准库 unittest（与全仓一致）。仅用 RFC5737 文档段 / 公开域名，不含真实 MAC/IP/凭证。
"""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from inventory.device import DeviceRegistry, _SELF_DEVICE_KEY  # noqa: E402
from core.netclass import (  # noqa: E402
    is_noise_address, is_internal, is_address_like,
)
from analysis.behavior import BehaviorFinding  # noqa: E402
from analysis.alerting import AlertCenter, _bulk_upload_is_benign  # noqa: E402
from core.main import HomewardService, _is_observable_domain  # noqa: E402
from rule_engine.engine import Decision, FlowRecord, RuleHit  # noqa: E402


# ============================================================ F1 设备去噪

class F1DeviceDenoiseTest(unittest.TestCase):
    def test_noise_addresses_merge_to_self_device(self):
        """回环/未指定/组播/链路本地/广播/脏串都应归并到一台「本机」设备，不各自建档"""
        reg = DeviceRegistry()
        for ip in ("127.0.0.1", "::1", "0.0.0.0", "239.255.255.250",
                  "fe80::1", "255.255.255.255", "zzz.not-an-ip"):
            reg.observe_ip(ip)
        self.assertEqual(len(reg.devices), 1, "噪声地址不应各自建档")
        self.assertIn(_SELF_DEVICE_KEY, reg.devices)
        self.assertEqual(reg.devices[_SELF_DEVICE_KEY].display_name, "本机（路由器自身）")

    def test_private_ip_still_its_own_device(self):
        """私网真实设备（如 10.0.0.55）必须仍单独建档，F1 不能误伤"""
        reg = DeviceRegistry()
        reg.observe_ip("127.0.0.1")
        reg.observe_ip("10.0.0.55")
        self.assertEqual(len(reg.devices), 2)
        self.assertNotIn("10.0.0.55", _SELF_DEVICE_KEY)
        self.assertEqual(reg.get_by_ip("10.0.0.55").key, "10.0.0.55")

    def test_self_device_excluded_from_ip_only_blind_spot(self):
        """本机设备没有 MAC 是预期的，盲区不应把它算作「未拿到 MAC」"""
        reg = DeviceRegistry()
        reg.observe_ip("127.0.0.1")
        spots = reg.blind_spots()
        # 只可能有「未加载 MAC 厂商库」这一类，不该出现因本机设备产生的 ip_only 提示
        self.assertFalse(any("未拿到 MAC" in s for s in spots))


# ============================================================ F2 bulk_upload 误报

class F2BulkUploadFpTest(unittest.TestCase):
    def test_helper_internal_destinations_are_benign(self):
        for dst in ("239.255.255.250:1900", "fe80::1:1900",
                    "192.168.1.30:443", "127.0.0.1:8080", "0.0.0.0:53"):
            f = SimpleNamespace(rule_id="bulk_upload", destination=dst)
            self.assertTrue(_bulk_upload_is_benign(f, {}),
                            f"{dst} 是内网/控制流量，应判为良性")

    def test_helper_public_unknown_stays_flagged(self):
        # 公网 IP（无归属）不应被误判良性 —— 未知大流量上传更可疑，宁严勿松
        f = SimpleNamespace(rule_id="bulk_upload", destination="8.8.8.8:443")
        self.assertFalse(_bulk_upload_is_benign(f, {}))
        # 未知域名也不应被当成内网而漏报
        f2 = SimpleNamespace(rule_id="bulk_upload", destination="mystery-backup.example.net")
        self.assertFalse(_bulk_upload_is_benign(f2, {}))

    def test_helper_benign_category_still_downgraded(self):
        f = SimpleNamespace(rule_id="bulk_upload", destination="p53-ckicloudws.icloud.com")
        self.assertTrue(_bulk_upload_is_benign(f, {"category": "cloud_storage"}))

    def _finding(self, destination, domain, severity="high", action="block_medium"):
        return BehaviorFinding(
            rule_id="bulk_upload", rule_name="突发大流量上传", severity=severity,
            category="bulk_upload", confidence="medium", action=action,
            scope="destination", src_ip="192.168.1.254",
            destination=destination, domain=domain,
            window_seconds=3600, start_ts=1.0, end_ts=2.0,
            evidence={"occurrences": 10, "total_bytes": 60000000},
        )

    def test_multicast_dest_downgraded_end_to_end(self):
        """SSDP 组播 239.255.255.250:1900 这种「单目的大量包」必须降级，不当外泄"""
        center = AlertCenter()
        alerts = center.ingest([self._finding("239.255.255.250:1900", None)],
                               attribution_of=lambda d: {})
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "low")
        self.assertEqual(alerts[0].suggested_action, "warn")

    def test_public_unknown_stays_high_end_to_end(self):
        """公网未知目的地仍保持高危，证明修复没有「一刀切」漏报"""
        center = AlertCenter()
        alerts = center.ingest([self._finding("8.8.8.8:443", None)],
                               attribution_of=lambda d: {})
        self.assertEqual(alerts[0].severity, "high")


# ============================================================ F3 建议去重

def _blocking_decision(domain: str) -> Decision:
    return Decision(
        action="block_soft",
        rule_hits=[RuleHit(
            domain=domain, organization="测试组织", category="telemetry",
            confidence="high", description="遥测", action="block_soft",
            side_effects="停止遥测上报", rule_type="exact",
        )],
        reason=f"{domain} → 测试组织（遥测）",
    )


class F3SuggestionDedupTest(unittest.TestCase):
    def _service(self) -> HomewardService:
        return HomewardService(config={
            "load_system_devices": False,
            "actions_db_path": None,
            "suggestions_save_every": 0,  # 本测试只验内存去重，不落盘
        })

    def test_same_domain_device_deduped_to_one(self):
        """同一设备 + 同一域名命中 15 次，只应留 1 条建议、次数累加为 15"""
        svc = self._service()
        for i in range(15):
            flow = FlowRecord(
                timestamp=1_700_000_000.0 + i, src_ip="192.168.1.9",
                dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
                dns_query="otheve.beacon.qq.com",
            )
            svc._record_suggestion(flow, _blocking_decision("otheve.beacon.qq.com"))
        self.assertEqual(len(svc.suggested_rules), 1)
        self.assertEqual(svc.suggested_rules[0]["occurrences"], 15)
        self.assertEqual(svc.stats["suggestions_pending"], 1)

    def test_distinct_domains_kept_separate(self):
        svc = self._service()
        for i in range(3):
            flow = FlowRecord(
                timestamp=1_700_000_000.0 + i, src_ip="192.168.1.9",
                dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
                dns_query=f"t{i}.example.com",
            )
            svc._record_suggestion(flow, _blocking_decision(f"t{i}.example.com"))
        self.assertEqual(len(svc.suggested_rules), 3)

    def test_distinct_devices_same_domain_kept_separate(self):
        svc = self._service()
        for ip in ("192.168.1.9", "192.168.1.10"):
            flow = FlowRecord(
                timestamp=1_700_000_000.0, src_ip=ip,
                dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
                dns_query="otheve.beacon.qq.com",
            )
            svc._record_suggestion(flow, _blocking_decision("otheve.beacon.qq.com"))
        self.assertEqual(len(svc.suggested_rules), 2)


# ============================================================ F4 覆盖率统一

class F4CoverageUnificationTest(unittest.TestCase):
    def test_observable_domain_filter(self):
        self.assertFalse(_is_observable_domain("192.168.1.1"))
        self.assertFalse(_is_observable_domain("239.255.255.250"))
        self.assertFalse(_is_observable_domain("router.lan"))
        self.assertFalse(_is_observable_domain("localhost"))
        self.assertFalse(_is_observable_domain(""))
        self.assertTrue(_is_observable_domain("example.com"))
        self.assertTrue(_is_observable_domain("sub.example.co.uk"))

    def test_ip_direct_connect_excluded_from_denominator(self):
        """直连 IP 作为「域名」出现时，不应灌进覆盖率分母（实机曾 5.56% vs 57%）"""
        svc = HomewardService(config={
            "load_system_devices": False, "actions_db_path": None,
            "suggestions_save_every": 0,
        })
        svc._process_flow_locked(FlowRecord(
            timestamp=1_700_000_000.0, src_ip="192.168.1.9",
            dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
            dns_query="example.com"))
        svc._process_flow_locked(FlowRecord(
            timestamp=1_700_000_001.0, src_ip="192.168.1.9",
            dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
            dns_query="192.168.1.1"))  # 直连 IP，应被剔除
        cov = svc.attribution_coverage()
        # 分母里只该有 example.com（192.168.1.1 被 _is_observable_domain 过滤）
        self.assertEqual(cov["total"], 1)
        self.assertGreaterEqual(cov["hit_rate"], 0.0)
        self.assertLessEqual(cov["hit_rate"], 1.0)


# ============================================================ F5 隐私体检

class F5PrivacyCheckupTest(unittest.TestCase):
    def _service(self) -> HomewardService:
        return HomewardService(config={
            "load_system_devices": False, "actions_db_path": None,
            "suggestions_save_every": 0,
        })

    def test_checkup_shape_and_bounds(self):
        svc = self._service()
        c = svc.privacy_checkup()
        self.assertIn(c["verdict"], ("基本可控", "需要关注", "风险较高"))
        self.assertGreaterEqual(c["score"], 0)
        self.assertLessEqual(c["score"], 100)
        for k in ("devices_total", "vendors_resolved", "alerts_active",
                  "alerts_high", "coverage_hit", "coverage_total",
                  "coverage_rate", "unknown_count", "blind_spots"):
            self.assertIn(k, c)

    def test_export_report_includes_checkup(self):
        svc = self._service()
        rep = svc.export_report()
        self.assertIn("checkup", rep)
        self.assertEqual(rep["checkup"]["verdict"], svc.privacy_checkup()["verdict"])

    def test_report_markdown_has_checkup_section(self):
        from ui.server import _report_markdown
        svc = self._service()
        md = _report_markdown(svc.export_report())
        self.assertIn("体检结论", md)
        self.assertIn(svc.privacy_checkup()["verdict"], md)


if __name__ == "__main__":
    unittest.main()
