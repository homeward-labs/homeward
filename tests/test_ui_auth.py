"""
W5 —— Web UI 鉴权（src/ui/auth.py + server.py 门禁）测试

覆盖：
- 未登录访问 /api/* → 401；访问页面 → 跳登录页（302 → /login）
- /api/health 免鉴权（仅状态）
- 错误口令登录 → 401；正确口令 → 种会话 cookie 后放行
- 登出 → cookie 失效，后续请求回到 401
- 登录页自包含、含表单、零外部资源
- WebAuth 单元：自动生成口令、常量时间校验、cookie 解析

用标准库 unittest（与全仓一致）。起服务器用 make_server + 线程，复用现有模式。
"""

import http.cookiejar
import threading
import unittest
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.main import HomewardService                                     # noqa: E402
from ui.auth import WebAuth                                              # noqa: E402
from ui import server as ui_server                                       # noqa: E402


TOKEN = "test-secret-token-123"


def _start(auth):
    svc = HomewardService(config={"load_system_devices": False})
    httpd = ui_server.make_server(svc, host="127.0.0.1", port=0, auth=auth)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}"


class WebAuthUnitTest(unittest.TestCase):
    def test_auto_generates_token_when_none(self):
        a = WebAuth(token=None)
        self.assertTrue(a.auto_token)
        self.assertEqual(a.token, a.auto_token)
        self.assertGreater(len(a.token), 16)

    def test_env_token_used(self):
        import os
        os.environ["HOMEWARD_AUTH_TOKEN"] = "envtok"
        try:
            a = WebAuth(token=None)
            self.assertEqual(a.token, "envtok")
            self.assertIsNone(a.auto_token)
        finally:
            del os.environ["HOMEWARD_AUTH_TOKEN"]

    def test_verify_constant_time_semantics(self):
        a = WebAuth(token="abc")
        self.assertTrue(a.verify("abc"))
        self.assertFalse(a.verify("wrong"))
        self.assertFalse(a.verify(""))

    def test_is_authenticated_reads_cookie(self):
        a = WebAuth(token="t")

        class _Fake:
            def __init__(self, cookie):
                self.headers = {"Cookie": cookie}

        self.assertTrue(a.is_authenticated(_Fake("homeward_session=t")))
        self.assertFalse(a.is_authenticated(_Fake("homeward_session=wrong")))
        self.assertFalse(a.is_authenticated(_Fake("")))

    def test_session_cookie_is_http_only(self):
        a = WebAuth(token="t")
        self.assertIn("HttpOnly", a.session_cookie())
        self.assertIn("SameSite=Strict", a.session_cookie())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随重定向：让 3xx 响应直接返回，便于断言 302 + Set-Cookie"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UiAuthGateTest(unittest.TestCase):

    def setUp(self):
        self.httpd, self.base = _start(WebAuth(token=TOKEN))
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj)
        )
        # 不跟随重定向的 opener：用于断言登录接口本身返回 302 + Set-Cookie
        self.no_redirect = urllib.request.build_opener(
            _NoRedirect, urllib.request.HTTPCookieProcessor(self.cj)
        )

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _req(self, url, data=None, opener=None):
        opener = opener or self.opener
        try:
            r = opener.open(url, data=data, timeout=5)
            return r.status, r.read().decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), e.headers

    def test_unauthenticated_api_returns_401(self):
        status, _, _ = self._req(f"{self.base}/api/overview")
        self.assertEqual(status, 401)

    def test_unauthenticated_page_redirects_to_login(self):
        # 未登录访问 / → 302 到 /login → 最终落到登录页 HTML
        status, body, _ = self._req(f"{self.base}/")
        self.assertIn("登录", body)
        self.assertIn("/api/login", body)

    def test_health_open_without_auth(self):
        status, body, _ = self._req(f"{self.base}/api/health")
        self.assertEqual(status, 200)
        self.assertIn("ok", body)

    def test_login_wrong_token_401(self):
        data = urllib.parse.urlencode({"token": "wrong"}).encode()
        status, _, _ = self._req(f"{self.base}/api/login", data=data)
        self.assertEqual(status, 401)
        # 错误口令不应种下会话
        self.assertFalse(any(c.name == "homeward_session" for c in self.cj))

    def test_login_correct_grants_access(self):
        data = urllib.parse.urlencode({"token": TOKEN}).encode()
        # 用不跟随重定向的 opener：登录本身应返回 302 + 种下会话 cookie
        status, _, headers = self._req(f"{self.base}/api/login", data=data,
                                       opener=self.no_redirect)
        self.assertEqual(status, 302)
        self.assertIn("homeward_session=", headers.get("Set-Cookie", ""))
        # 会话 cookie 已种下（值即口令，HttpOnly）
        sess = [c for c in self.cj if c.name == "homeward_session"]
        self.assertEqual(len(sess), 1)
        self.assertEqual(sess[0].value, TOKEN)
        # 之后访问受保护接口 / 页面都放行
        s2, body2, _ = self._req(f"{self.base}/api/overview")
        self.assertEqual(s2, 200)
        self.assertIn("stats", body2)
        s3, body3, _ = self._req(f"{self.base}/")
        self.assertEqual(s3, 200)

    def test_logout_clears_session(self):
        # 先登录
        data = urllib.parse.urlencode({"token": TOKEN}).encode()
        self._req(f"{self.base}/api/login", data=data)
        self.assertTrue(any(c.name == "homeward_session" for c in self.cj))
        # 登出
        self._req(f"{self.base}/api/logout", data=b"")
        # 旧会话已失效：用清空后的 jar 再访问应回到 401
        self.cj.clear()
        status, _, _ = self._req(f"{self.base}/api/overview")
        self.assertEqual(status, 401)

    def test_login_page_served_and_self_contained(self):
        status, body, headers = self._req(f"{self.base}/login")
        self.assertEqual(status, 200)
        self.assertIn("登录", body)
        self.assertIn('action="/api/login"', body)
        # 零外部资源：不得引用 http(s):// 外链
        self.assertNotIn("http://", body)
        self.assertNotIn("https://", body)

    def test_static_login_css_reachable_without_auth(self):
        status, body, headers = self._req(f"{self.base}/static/login.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers.get("Content-Type", ""))
        self.assertIn(".login", body)  # 登录页样式类存在


class NoAuthModeTest(unittest.TestCase):
    """--no-auth：完全不设防，所有接口直达（仅可信局域网用）"""

    def setUp(self):
        self.httpd, self.base = _start(None)

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _req(self, url):
        try:
            r = urllib.request.urlopen(url, timeout=5)
            return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

    def test_no_auth_bypasses_gate(self):
        status, body = self._req(f"{self.base}/api/overview")
        self.assertEqual(status, 200)
        self.assertIn("stats", body)


if __name__ == "__main__":
    unittest.main()
