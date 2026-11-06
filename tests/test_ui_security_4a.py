"""Stage 4A 安全加固回归用例（配套 docs/07-调研与诊断/安全加固最小补丁-2026-11-06.diff）

覆盖七项：HI-4 登录限流 / LO-1 health 精简 / LO-8 Server 头 / LO-9 Host 校验 /
LO-10 + LO-6 OPTIONS 与错误页安全头 / ME-1 Fetch Metadata / ME-2 500 去堆栈。

真起 HTTP 服务（127.0.0.1 临时端口），用标准库打真实请求，与全仓测试风格一致。
"""

import http.client
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.demo import seed_demo                     # noqa: E402
from core.main import HomewardService               # noqa: E402
from ui.auth import WebAuth                        # noqa: E402
from ui import server as ui_server                  # noqa: E402

TOKEN = "stage4a-test-token-123"
SENTINEL = "SENTINEL_INTERNAL_PATH_DO_NOT_LEAK"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随 302：用于断言登录接口本身的状态码与 Set-Cookie"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _ServerCase(unittest.TestCase):
    """每个用例类独享一个服务实例（HI-4 的登录计数也随之隔离）"""

    @classmethod
    def setUpClass(cls):
        svc = HomewardService(config={"load_system_devices": False})
        seed_demo(svc)
        cls.svc = svc
        cls.httpd = ui_server.make_server(svc, host="127.0.0.1", port=0,
                                          auth=WebAuth(token=TOKEN))
        cls.port = cls.httpd.server_address[1]
        cls.base = "http://127.0.0.1:%d" % cls.port
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def req(self, path, data=None, headers=None, method=None):
        r = urllib.request.Request(self.base + path, data=data,
                                   headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8", "replace"), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), e.headers

    def req_no_redirect(self, path, data=None, headers=None, method=None):
        r = urllib.request.Request(self.base + path, data=data,
                                   headers=headers or {}, method=method)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(r, timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8", "replace"), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), e.headers

    def raw_request(self, path, host, method="GET", body=None, extra=None):
        """绕过 urllib 自动补 Host，用于构造空 / 伪造 Host 头"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest(method, path, skip_host=True)
        if host is not None:
            conn.putheader("Host", host)
        for k, v in (extra or {}).items():
            conn.putheader(k, v)
        conn.endheaders(body)
        resp = conn.getresponse()
        out = (resp.status, resp.read().decode("utf-8", "replace"), resp.headers)
        conn.close()
        return out

    def login_data(self):
        return urllib.parse.urlencode({"token": TOKEN}).encode("utf-8")


class HeaderAndHealthTest(_ServerCase):

    def test_health_is_minimal(self):
        status, body, headers = self.req("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_server_header_hides_python_version(self):
        _, _, headers = self.req("/api/health")
        server = headers.get("Server", "")
        self.assertNotIn("Python", server)
        self.assertEqual(server, "homeward")

    def test_options_has_security_headers(self):
        status, body, headers = self.req("/api/health", method="OPTIONS")
        self.assertEqual(status, 405)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertTrue(headers.get("Content-Security-Policy", "").startswith("default-src"))
        self.assertIn("method_not_allowed", body)

    def test_unsupported_method_error_has_security_headers(self):
        status, body, headers = self.req("/", method="TRACE")
        self.assertEqual(status, 501)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertNotIn("Traceback", body)

    def test_500_returns_ref_only(self):
        original = self.svc.get_stats

        def boom():
            raise RuntimeError(SENTINEL)

        self.svc.get_stats = boom
        try:
            status, body, _ = self.req(
                "/api/overview",
                headers={"Cookie": "homeward_session=" + TOKEN})
            self.assertEqual(status, 500)
            self.assertNotIn(SENTINEL, body)
            self.assertNotIn("detail", body)
            self.assertEqual(len(json.loads(body).get("ref", "")), 32)
        finally:
            self.svc.get_stats = original


class WriteGuardTest(_ServerCase):

    def test_cross_site_write_blocked(self):
        status, body, _ = self.req(
            "/api/login", data=self.login_data(),
            headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        self.assertIn("cross_site_write_blocked", body)

    def test_same_origin_write_allowed(self):
        status, _, headers = self.req_no_redirect(
            "/api/login", data=self.login_data(),
            headers={"Sec-Fetch-Site": "same-origin"})
        # 302 = 口令正确、已种 cookie；说明校验没有误伤正常请求
        self.assertEqual(status, 302)
        self.assertIn("homeward_session=", headers.get("Set-Cookie", ""))

    def test_origin_mismatch_blocked(self):
        status, _, _ = self.req(
            "/api/login", data=self.login_data(),
            headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 403)

    def test_bad_content_type_rejected(self):
        status, _, _ = self.req(
            "/api/login", data=b"x",
            headers={"Content-Type": "application/xml"})
        self.assertEqual(status, 415)

    def test_legacy_client_without_fetch_metadata_still_works(self):
        # curl / 现有单测不带任何 Fetch Metadata 头：兼容放行
        status, _, _ = self.req("/api/logout", data=b"")
        self.assertEqual(status, 200)

    def test_bad_host_syntax_rejected(self):
        for bad in ("", "bad host", "a" * 300):
            status, _, _ = self.raw_request("/api/health", bad)
            self.assertEqual(status, 400, "Host=%r" % bad)


class HostAllowlistTest(_ServerCase):
    """显式配置白名单后，非白名单 Host 必须被拒（LO-9 的收紧路径）"""

    @classmethod
    def setUpClass(cls):
        os.environ["HOMEWARD_ALLOWED_HOSTS"] = "homeward.test"
        try:
            super().setUpClass()
        finally:
            del os.environ["HOMEWARD_ALLOWED_HOSTS"]

    def test_unlisted_host_rejected(self):
        status, body, _ = self.raw_request("/api/health", "evil.example")
        self.assertEqual(status, 400)
        self.assertIn("host_not_allowed", body)

    def test_default_local_host_allowed(self):
        status, _, _ = self.raw_request("/api/health", "127.0.0.1")
        self.assertEqual(status, 200)


class LoginRateLimitTest(_ServerCase):

    def test_five_failures_then_429_with_retry_after(self):
        wrong = urllib.parse.urlencode({"token": "wrong"}).encode("utf-8")
        for i in range(5):
            status, _, _ = self.req("/api/login", data=wrong)
            self.assertEqual(status, 401, "第 %d 次" % (i + 1))
        status, body, headers = self.req("/api/login", data=wrong)
        self.assertEqual(status, 429)
        self.assertIn("too_many_attempts", body)
        self.assertGreater(int(headers.get("Retry-After", "0")), 0)


if __name__ == "__main__":
    unittest.main()
