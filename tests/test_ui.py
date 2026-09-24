"""W4 Web UI —— 服务端集成测试

测试策略：**真起一个 HTTP 服务**（绑 127.0.0.1 的临时端口），用标准库 urllib 打真实
请求。理由是这个模块的价值全在"HTTP 这一层" —— 状态码、响应头、路径穿越防护、
动词约束，单测函数内的调用都测不到。
"""

import json
import re
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.demo import seed_demo                      # noqa: E402
from core.main import HomewardService                # noqa: E402
from ui import server as ui_server                   # noqa: E402


class ServerTestCase(unittest.TestCase):
    """起一个带演示数据的服务，每个用例共享（只读用例居多，够用且快）"""

    @classmethod
    def setUpClass(cls):
        cls.service = HomewardService(config={"load_system_devices": False})
        seed_demo(cls.service)
        cls.httpd = ui_server.make_server(cls.service, host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    # ---- 工具 ----

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, r.headers, r.read()

    def get_json(self, path):
        status, _h, body = self.get(path)
        self.assertEqual(status, 200)
        return json.loads(body.decode("utf-8"))

    def post(self, path):
        req = urllib.request.Request(self.base + path, data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def status_of(self, path, method="GET"):
        req = urllib.request.Request(self.base + path, data=b"", method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code


# ---------------------------------------------------------------- 静态资源

class TestStatic(ServerTestCase):

    def test_index_served(self):
        status, headers, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("家卫", body.decode("utf-8"))

    def test_static_assets_served(self):
        for path, ctype in (("/static/app.css", "text/css"),
                            ("/static/app.js", "javascript")):
            status, headers, body = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(ctype, headers.get("Content-Type", ""))
            self.assertGreater(len(body), 200, path)

    def test_path_traversal_blocked(self):
        """目录穿越必须打不穿 static/ —— 否则等于把源码和知识库全端出去"""
        for probe in ("/../README.md", "/static/../server.py",
                      "/static/../../src/core/main.py", "/..%2fLICENSE"):
            self.assertEqual(self.status_of(probe), 404, probe)

    def test_unknown_static_404(self):
        self.assertEqual(self.status_of("/static/nope.js"), 404)

    def test_no_external_resources(self):
        """隐私工具自己的界面不许请求任何第三方：无 CDN、无外链字体、无统计脚本"""
        html = (ui_server.STATIC_DIR / "index.html").read_text(encoding="utf-8")
        externals = re.findall(r"(?:src|href)\s*=\s*[\"'](https?:)?//", html)
        self.assertEqual(externals, [], "index.html 引了外部资源")
        for name in ("app.js", "app.css"):
            text = (ui_server.STATIC_DIR / name).read_text(encoding="utf-8")
            self.assertNotIn("https://", text.replace("https://github.com", ""),
                             f"{name} 里出现了外部 URL")

    def test_no_emoji_icons(self):
        """界面图标一律内联 SVG，不用 emoji（各平台字形不一致、读屏器读不出语义）"""
        emoji = re.compile(
            "[" "\U0001f300-\U0001faff" "\U00002600-\U000027bf" "\U0001f000-\U0001f2ff" "]"
        )
        for name in ("index.html", "app.js", "app.css"):
            text = (ui_server.STATIC_DIR / name).read_text(encoding="utf-8")
            self.assertIsNone(emoji.search(text), f"{name} 里出现了 emoji")


# ---------------------------------------------------------------- 响应头与安全

class TestHeaders(ServerTestCase):

    def test_security_headers_present(self):
        _s, headers, _b = self.get("/")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        # 家庭网络的观测数据不该留在浏览器缓存里
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_csp_is_self_only(self):
        _s, headers, _b = self.get("/")
        csp = headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertNotIn("*", csp)


# ---------------------------------------------------------------- API

class TestApi(ServerTestCase):

    def test_health(self):
        d = self.get_json("/api/health")
        self.assertTrue(d["ok"])
        self.assertEqual(d["edition"]["edition"], "community")
        self.assertFalse(d["edition"]["can_enforce"], "社区版不得声称能拦截")
        self.assertGreater(d["kb_domains"], 0)
        self.assertEqual(d["behaviors_unsupported"], [],
                         "行为库里不能有引擎不认的规则（会导致静默恒真）")

    def test_overview(self):
        d = self.get_json("/api/overview")
        self.assertIn("stats", d)
        self.assertIn("coverage", d)
        self.assertIn("blind_spots", d)
        self.assertGreater(d["stats"]["devices_total"], 0)
        self.assertIsInstance(d["blind_spots"], list)

    def test_devices_have_identity_and_destinations(self):
        d = self.get_json("/api/devices")
        self.assertGreater(len(d["items"]), 0)
        cam = next(x for x in d["items"] if "192.168.1.50" in (x["ips"] or []))
        # 演示设备的 MAC 取自真实 OUI 表，所以厂商应当查得到
        self.assertTrue(cam["mac"])
        self.assertTrue(cam["vendor"])
        self.assertGreater(cam["domain_count"], 0)
        self.assertTrue(cam["top_domains"])

    def test_destinations(self):
        d = self.get_json("/api/destinations")
        self.assertGreater(d["total"], 0)
        self.assertLessEqual(d["known"], d["total"])
        self.assertGreaterEqual(d["hit_rate"], 0.0)
        domains = {x["domain"] for x in d["items"]}
        self.assertIn("track.tuya.com", domains)
        # 每条去向都要带"哪些设备在跟它说话"，否则去向地图画不出来
        self.assertTrue(any(x["devices"] for x in d["items"]))

    def test_alerts(self):
        d = self.get_json("/api/alerts")
        self.assertGreater(len(d["items"]), 0)
        for a in d["items"]:
            self.assertTrue(a["title"])
            self.assertTrue(a["side_effects"], "告警必须写清后果")
            self.assertEqual(a["missing_keys"], [], "文案占位符缺失会渲染成原始花括号")

    def test_dismiss_alert(self):
        before = self.get_json("/api/alerts")["items"]
        target = before[0]["alert_id"]
        status, body = self.post(f"/api/alerts/{urllib.parse.quote(target)}/dismiss")
        self.assertEqual(status, 200)
        self.assertTrue(body["dismissed"])
        after = self.get_json("/api/alerts")["items"]
        self.assertNotIn(target, [a["alert_id"] for a in after])
        # 但历史不丢：显式带上 include_dismissed 还能查到
        with_dismissed = self.get_json("/api/alerts?include_dismissed=1")["items"]
        self.assertIn(target, [a["alert_id"] for a in with_dismissed])

    def test_dismiss_unknown_id(self):
        req = urllib.request.Request(self.base + "/api/alerts/nope/dismiss",
                                     data=b"", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 404)

    def test_suggestions_are_never_applied(self):
        d = self.get_json("/api/suggestions")
        self.assertGreater(len(d["items"]), 0)
        self.assertIn("标准版", d["note"], "必须说明实际拦截属标准版")
        for r in d["items"]:
            self.assertEqual(r["status"], "suggested",
                             "社区版不得产出已生效的阻断规则")

    def test_unknown_domains(self):
        d = self.get_json("/api/unknown-domains")
        self.assertIn("unknown-tracking-domain.xyz", d["items"])

    def test_domain_lookup(self):
        d = self.get_json("/api/domain?q=ot.io.mi.com")
        self.assertTrue(d["known"])
        self.assertEqual(d["organization"], "Xiaomi")
        miss = self.get_json("/api/domain?q=totally-unknown.example.org")
        self.assertFalse(miss["known"])

    def test_scan_is_readonly(self):
        status, body = self.post("/api/scan")
        self.assertEqual(status, 200)
        self.assertIn("alerts", body)

    def test_unknown_api_path_404(self):
        req = urllib.request.Request(self.base + "/api/nope", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 404)

    def test_write_methods_rejected(self):
        """只读接口的动词约束：POST 一律 405"""
        for path in ("/api/health", "/api/devices", "/api/destinations",
                     "/api/alerts", "/api/suggestions"):
            self.assertEqual(self.status_of(path, method="POST"), 405, path)


# ---------------------------------------------------------------- 启动行为

class TestBootstrap(unittest.TestCase):

    def test_default_port_and_host(self):
        self.assertEqual(ui_server.DEFAULT_PORT, 9595)
        self.assertEqual(ui_server.DEFAULT_HOST, "127.0.0.1")

    def test_warn_only_when_exposed(self, ):
        """回环地址不该告警；绑 0.0.0.0 必须告警（当前版本无鉴权）"""
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ui_server._warn_if_exposed("127.0.0.1")
        self.assertEqual(buf.getvalue(), "")

        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            ui_server._warn_if_exposed("0.0.0.0")
        self.assertIn("没有鉴权", buf2.getvalue())

    def test_make_server_binds(self):
        svc = HomewardService(config={"load_system_devices": False})
        httpd = ui_server.make_server(svc, host="127.0.0.1", port=0)
        try:
            self.assertIsInstance(httpd, ThreadingHTTPServer)
            self.assertGreater(httpd.server_address[1], 0)
        finally:
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
