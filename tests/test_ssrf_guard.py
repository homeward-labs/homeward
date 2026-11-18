"""
SSRF 出网守卫单测（M1-4 / 待办-122 · 2026-11-17 第 577 批）

覆盖判据原文的四类目标（私网 / 环回外 / 云元数据 / `file://`）全拒，
外加五要素里另外三条可机械验证的部分：重定向逐跳（跨主机丢凭据）、
响应体上限、非白名单目标零凭据头。

不联网：所有"服务器"都是本机起的临时 HTTP 端口。
"""

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.ssrf_guard import (  # noqa: E402
    SsrfError,
    check_url,
    guarded_open,
    is_loopback_host,
    may_carry_credentials,
)


class _Handler(BaseHTTPRequestHandler):
    """按路径决定行为：/ok 正常、/big 超大体、/hop 跳到别的端口、记录收到的 Authorization。"""

    seen_auth: list = []
    redirect_to: str = ""

    def log_message(self, *a):  # 静音
        pass

    def do_GET(self):  # noqa: N802
        _Handler.seen_auth.append(self.headers.get("Authorization"))
        if self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", str(3 * 1024 * 1024))
            self.end_headers()
            self.wfile.write(b"x" * (3 * 1024 * 1024))
            return
        if self.path == "/hop":
            self.send_response(302)
            self.send_header("Location", _Handler.redirect_to)
            self.end_headers()
            return
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


def _serve():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestCheckUrl(unittest.TestCase):
    """① scheme / 凭据 / 目标地址三类拒绝。"""

    def test_scheme_rejected(self):
        for url in ("file:///etc/passwd", "ftp://example.com/x",
                    "gopher://example.com/", "data:text/plain,hi"):
            with self.assertRaises(SsrfError, msg=url):
                check_url(url)

    def test_private_ranges_rejected(self):
        for url in ("http://10.0.0.1/", "http://192.168.1.252:9595/",
                    "http://172.16.0.5/", "http://192.168.31.150/"):
            with self.assertRaises(SsrfError, msg=url):
                check_url(url)

    def test_cloud_metadata_rejected(self):
        with self.assertRaises(SsrfError):
            check_url("http://169.254.169.254/latest/meta-data/")

    def test_loopback_gated(self):
        with self.assertRaises(SsrfError):
            check_url("http://127.0.0.1:11434/api/generate")
        self.assertEqual(check_url("http://127.0.0.1:11434/api/generate",
                                   allow_loopback=True), "127.0.0.1")
        self.assertEqual(check_url("http://localhost:11434", allow_loopback=True), "localhost")
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("[::1]"))

    def test_reserved_and_unspecified_rejected(self):
        for url in ("http://0.0.0.0/", "http://240.0.0.1/"):
            with self.assertRaises(SsrfError, msg=url):
                check_url(url)

    def test_url_with_credentials_rejected(self):
        with self.assertRaises(SsrfError):
            check_url("https://user:pw@api.openai.com/v1/chat/completions")

    def test_empty_and_garbage(self):
        for url in ("", "   ", "not-a-url", None):
            with self.assertRaises(SsrfError, msg=repr(url)):
                check_url(url)


class TestCredentials(unittest.TestCase):
    """⑤ 非白名单目标零凭据头。"""

    def test_official_host_only_by_default(self):
        self.assertTrue(may_carry_credentials("api.openai.com"))
        self.assertTrue(may_carry_credentials("API.OpenAI.com"))
        self.assertFalse(may_carry_credentials("evil.example.com"))
        self.assertFalse(may_carry_credentials("api.openai.com.evil.io"))

    def test_trusted_hosts_opt_in(self):
        self.assertTrue(may_carry_credentials("relay.example.cn",
                                              trusted_hosts=("relay.example.cn",)))
        self.assertFalse(may_carry_credentials("relay.example.cn"))


class TestGuardedOpen(unittest.TestCase):
    """③ 重定向逐跳（跨主机丢凭据）、④ 响应体上限。"""

    @classmethod
    def setUpClass(cls):
        cls.srv = _serve()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        _Handler.seen_auth = []

    def test_ok_body(self):
        body = guarded_open(f"{self.base}/ok", allow_loopback=True)
        self.assertEqual(body, b'{"ok": true}')

    def test_body_limit(self):
        with self.assertRaises(SsrfError):
            guarded_open(f"{self.base}/big", allow_loopback=True, max_bytes=1024)

    def test_redirect_cross_host_drops_authorization(self):
        # 第二跳换端口 = 换 host:port，等同跨主机；Authorization 必须丢
        other = _serve()
        try:
            _Handler.redirect_to = f"http://127.0.0.1:{other.server_address[1]}/ok"
            body = guarded_open(f"{self.base}/hop",
                                headers={"Authorization": "Bearer SECRET"},
                                allow_loopback=True)
            self.assertEqual(body, b'{"ok": true}')
            self.assertEqual(_Handler.seen_auth[0], "Bearer SECRET")   # 第一跳带
            self.assertIsNone(_Handler.seen_auth[1])                   # 第二跳不带
        finally:
            other.shutdown()
            _Handler.redirect_to = ""

    def test_redirect_to_private_is_rejected(self):
        # 跳到私网且在 allow_loopback=False 时，逐跳校验必须拦下
        _Handler.redirect_to = "http://10.0.0.1/hop"
        try:
            with self.assertRaises(SsrfError):
                guarded_open(f"{self.base}/hop", allow_loopback=True)
        finally:
            _Handler.redirect_to = ""


class TestAnalyzerWiring(unittest.TestCase):
    """集成：非白名单 base_url 不得收到 api_key。"""

    def test_api_key_absent_for_untrusted_host(self):
        from ai.analyzer import AIAnalyzer, AnalysisRequest

        captured = {}

        def _fake_open(url, data=None, headers=None, **kw):
            captured["url"] = url
            captured["headers"] = dict(headers or {})
            return ('{"choices":[{"message":{"content":'
                    '"{\\"predicted_organization\\":\\"x\\",\\"category\\":\\"unknown\\"}"}}]}').encode()

        import ai.analyzer as mod
        orig = mod.guarded_open
        mod.guarded_open = _fake_open
        try:
            ai = AIAnalyzer(backend="openai", api_key="sk-SECRET",
                            base_url="https://relay.example.cn/v1/chat/completions")
            ai.analyze(AnalysisRequest(domain="example.com"))
            self.assertNotIn("Authorization", captured["headers"])
            ai2 = AIAnalyzer(backend="openai", api_key="sk-SECRET",
                             base_url="https://relay.example.cn/v1/chat/completions",
                             trusted_hosts=("relay.example.cn",))
            ai2.analyze(AnalysisRequest(domain="example.com"))
            self.assertEqual(captured["headers"].get("Authorization"), "Bearer sk-SECRET")
        finally:
            mod.guarded_open = orig


if __name__ == "__main__":
    unittest.main()
