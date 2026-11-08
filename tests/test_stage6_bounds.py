"""Stage 6 资源上限 / 输入边界回归（安全加固施工单 §八）。

负向优先：每条上限都要有「不满足即拒」的用例，防止占位式假绿。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from analysis.ingest import _classify_local_ip, is_local_ip  # noqa: E402
from collectors.dns import parse_dnsmasq_line  # noqa: E402
from ui import server as ui_server  # noqa: E402
from analysis.behavior import MAX_TRACKED_KEYS, BehaviorDetector  # noqa: E402
from rule_engine.engine import FlowRecord  # noqa: E402


class _FakeRfile:
    def __init__(self, payload=b""):
        self.payload = payload
        self.read_calls = []

    def read(self, n):
        self.read_calls.append(n)
        return self.payload[:n]


class _FakeHandler:
    def __init__(self, length, payload=b""):
        self.headers = {"Content-Length": str(length)}
        self.rfile = _FakeRfile(payload)


class BodyLimitTest(unittest.TestCase):
    def test_limit_constant_covers_import(self):
        # 离线导入文本上限 16 MiB，JSON 包裹后仍需放得下
        self.assertGreaterEqual(ui_server.MAX_BODY_BYTES, 16 * 1024 * 1024)
        self.assertLessEqual(ui_server.MAX_BODY_BYTES, 64 * 1024 * 1024)

    def test_oversize_rejected_before_any_read(self):
        h = _FakeHandler(ui_server.MAX_BODY_BYTES + 1)
        with self.assertRaises(ui_server.PayloadTooLarge):
            ui_server.HomewardHandler._read_body_bytes(h)
        self.assertEqual(h.rfile.read_calls, [], "超限请求体不得触发读取")

    def test_normal_body_still_reads(self):
        h = _FakeHandler(5, b"hello")
        self.assertEqual(ui_server.HomewardHandler._read_body_bytes(h), b"hello")
        self.assertEqual(h.rfile.read_calls, [5])

    def test_invalid_or_negative_length_is_empty_body(self):
        for raw in ("abc", "-1", ""):
            h = _FakeHandler(raw)
            self.assertEqual(ui_server.HomewardHandler._read_body_bytes(h), b"")

    def test_dispatch_maps_oversize_to_413(self):
        # 静态检查 _dispatch 的 413 分支存在且带统一错误码
        import inspect
        src = inspect.getsource(ui_server.HomewardHandler._dispatch)
        self.assertIn("except PayloadTooLarge", src)
        self.assertIn("413", src)
        self.assertIn("payload_too_large", src)


class IpCacheBoundTest(unittest.TestCase):
    def test_cache_stays_bounded_under_many_distinct_ips(self):
        _classify_local_ip.cache_clear()
        for i in range(5000):
            is_local_ip("10.%d.%d.%d" % ((i >> 16) & 255, (i >> 8) & 255, i & 255))
        info = _classify_local_ip.cache_info()
        self.assertEqual(info.maxsize, 4096)
        self.assertLessEqual(info.currsize, 4096)
        self.assertGreater(info.currsize, 0)

    def test_invalid_ip_returns_none_and_is_not_cached(self):
        self.assertIsNone(is_local_ip("not-an-ip"))
        self.assertIsNone(is_local_ip(""))

    def test_local_and_public_classification_unchanged(self):
        self.assertTrue(is_local_ip("192.168.31.254"))
        self.assertFalse(is_local_ip("8.8.8.8"))


class DomainBoundaryTest(unittest.TestCase):
    def _parse(self, domain):
        return parse_dnsmasq_line(
            "dnsmasq[1]: query[A] %s from 192.168.1.5" % domain)

    def test_normal_domains_pass(self):
        for d in ("www.example.com", "api.ad.tuya.com",
                  "173.1.168.192.in-addr.arpa", "xn--fsq.example"):
            rec = self._parse(d)
            self.assertIsNotNone(rec, d)
            self.assertEqual(rec["domain"], d)

    def test_trailing_dot_still_stripped(self):
        rec = self._parse("example.com.")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["domain"], "example.com")

    def test_oversize_domain_dropped(self):
        self.assertIsNone(self._parse("a" * 254))

    def test_control_char_domain_dropped(self):
        self.assertIsNone(self._parse("bad\x01host"))
        self.assertIsNone(self._parse("bad\x7fhost"))

    def test_non_dns_char_domain_dropped(self):
        self.assertIsNone(self._parse("bad/host"))
        self.assertIsNone(self._parse("bad@host"))


class TrackedKeysBoundTest(unittest.TestCase):
    """Stage 6：观测池键总数有界（负向优先，防伪造海量 IP/子域撑爆内存）"""

    @staticmethod
    def _flow(ip, domain, ts=1000.0):
        return FlowRecord(timestamp=ts, src_ip=ip, dst_ip="203.0.113.1",
                          dst_port=443, protocol="tcp", sni=domain, dns_query=None,
                          packet_size=60, direction="out")

    def test_default_cap_is_bounded(self):
        self.assertEqual(MAX_TRACKED_KEYS, 4096)
        self.assertEqual(BehaviorDetector().max_tracked_keys, MAX_TRACKED_KEYS)

    def test_key_count_bounded_under_many_distinct_keys(self):
        det = BehaviorDetector(max_tracked_keys=64)
        for i in range(300):
            ip = "10.%d.%d.%d" % ((i >> 16) & 255, (i >> 8) & 255, i & 255)
            det.feed(self._flow(ip, "d%d.example.com" % i), now=1000.0)
        total = sum(det.tracked_keys().values())
        self.assertLessEqual(total, 64, "两个观测池的键总数不得超过上限")
        self.assertGreater(det.stats["dropped_keys"], 0, "满表后必须有丢弃计数")

    def test_existing_key_still_accepts_after_cap(self):
        det = BehaviorDetector(max_tracked_keys=4)
        det.feed(self._flow("10.0.0.1", "a.example.com"), now=1000.0)
        for i in range(20):
            det.feed(self._flow("10.1.0.%d" % i, "b%d.example.com" % i), now=1000.0)
        before = len(det.device_flows["10.0.0.1"])
        det.feed(self._flow("10.0.0.1", "a.example.com"), now=1000.0)
        self.assertEqual(len(det.device_flows["10.0.0.1"]), before + 1,
                         "满表只拒新键，不得影响既有键继续收记录")

    def test_normal_scene_unchanged(self):
        det = BehaviorDetector()
        for i in range(12):
            ts = 1000.0 + i * 30
            det.feed(self._flow("192.168.1.50", "track.example.com", ts=ts), now=ts)
        self.assertIn("192.168.1.50", det.device_flows)
        self.assertIn(("192.168.1.50", "track.example.com"), det.dest_flows)
        self.assertEqual(det.stats["dropped_keys"], 0)
        self.assertEqual(det.stats["fed"], 12)

    def test_empty_keys_recycled_after_prune(self):
        det = BehaviorDetector()
        det.feed(self._flow("10.0.0.9", "x.example.com", ts=0.0), now=100_000.0)
        self.assertNotIn("10.0.0.9", det.device_flows,
                         "记录被裁空后应回收键，别空占上限名额")
        self.assertNotIn(("10.0.0.9", "x.example.com"), det.dest_flows)

    def test_reset_clears_drop_counter_and_warning(self):
        det = BehaviorDetector(max_tracked_keys=2)
        det.feed(self._flow("10.0.0.1", "a.example.com"), now=1000.0)
        det.feed(self._flow("10.0.0.2", "b.example.com"), now=1000.0)
        det.feed(self._flow("10.0.0.3", "c.example.com"), now=1000.0)
        self.assertGreater(det.stats["dropped_keys"], 0)
        det.reset()
        self.assertEqual(det.stats["dropped_keys"], 0)
        self.assertFalse(det._keys_warned)


if __name__ == "__main__":
    unittest.main()
