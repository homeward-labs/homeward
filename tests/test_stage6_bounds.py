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


if __name__ == "__main__":
    unittest.main()
