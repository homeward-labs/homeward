"""Stage 6 请求体上限：真实 HTTP 回环复现（补第 397 批遗留）。

第 397 批的 413 分支只有源码级静态断言 + 单元级异常验证，未发过真实 HTTP 请求。
这里真起 127.0.0.1 临时端口服务，用标准库发单条 POST：
**只声明越界 Content-Length、不实发 32 MiB 实体**——服务端在读取动作之前就拒，
真发实体反而会撑满 TCP 发送窗口，属 DoS 式请求，本用例刻意不做。

覆盖两条读取入口：/api/login 走 _read_form()，/api/import 走 _read_text_body()。
"""
import http.client
import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.main import HomewardService  # noqa: E402
from ui import server as ui_server  # noqa: E402


class BodyLimitHTTPTest(unittest.TestCase):
    """共享一个服务实例；每例前清登录限流计数，避免 HI-4 跨用例串扰。"""

    @classmethod
    def setUpClass(cls):
        svc = HomewardService(config={"load_system_devices": False})
        cls.httpd = ui_server.make_server(svc, host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.httpd.RequestHandlerClass.login_failures.clear()

    def _post_declared_only(self, path, length, extra=None):
        """只发请求头，声明一个 Content-Length，但不发送任何实体字节。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.putrequest("POST", path)
            conn.putheader("Content-Length", str(length))
            for k, v in (extra or {}).items():
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
            return resp.status, resp.read().decode("utf-8", "replace")
        finally:
            conn.close()

    def _post_real(self, path, body: bytes):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request("POST", path, body=body,
                         headers={"Content-Length": str(len(body))})
            resp = conn.getresponse()
            return resp.status, resp.read().decode("utf-8", "replace")
        finally:
            conn.close()

    def test_oversize_declared_length_returns_413_on_form_path(self):
        status, body = self._post_declared_only(
            "/api/login", ui_server.MAX_BODY_BYTES + 1)
        self.assertEqual(status, 413)
        payload = json.loads(body)
        self.assertEqual(payload["error"], "payload_too_large")
        self.assertEqual(payload["max_bytes"], ui_server.MAX_BODY_BYTES)

    def test_oversize_declared_length_returns_413_on_text_body_path(self):
        status, body = self._post_declared_only(
            "/api/import", ui_server.MAX_BODY_BYTES + 1)
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body)["error"], "payload_too_large")

    def test_invalid_content_length_is_not_413(self):
        status, _ = self._post_declared_only("/api/login", "not-a-number")
        self.assertNotEqual(status, 413)
        self.assertNotEqual(status, 500)

    def test_normal_small_post_is_not_413(self):
        status, body = self._post_real("/api/login", b"token=wrong")
        self.assertNotEqual(status, 413)
        self.assertNotEqual(status, 500)
        self.assertIn("error", json.loads(body))


if __name__ == "__main__":
    unittest.main()
