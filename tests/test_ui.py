"""W4 Web UI —— 服务端集成测试

测试策略：**真起一个 HTTP 服务**（绑 127.0.0.1 的临时端口），用标准库 urllib 打真实
请求。理由是这个模块的价值全在"HTTP 这一层" —— 状态码、响应头、路径穿越防护、
动词约束，单测函数内的调用都测不到。
"""

import json
import os
import re
import sys
import tempfile
import time
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

    def post_text(self, path, body, content_type="text/plain"):
        req = urllib.request.Request(
            self.base + path, data=body.encode("utf-8"),
            headers={"Content-Type": content_type}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def get_raw(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()


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

    def test_clear_observations_endpoint(self):
        """一键清除观测记录：清掉设备/归属缓存/告警，但不碰许可（actions.db 独立）

        用独立 service 实例，避免污染 TestApi 共享的 cls.service。
        """
        from core.main import HomewardService
        svc = HomewardService(config={"load_system_devices": False})
        # 喂一点真实数据进去，确保清空前有东西可清
        svc.device_registry.observe_ip("203.0.113.9")
        svc.attribution.resolve("track.io.mi.com")
        svc.stats["unknown_domains"].add("zzz.unknown.example.org")
        from analysis.alerting import Alert
        svc.alert_center._alerts["test-alert-x"] = Alert(
            alert_id="test-alert-x", rule_id="r", title="测试规则",
            summary="测试告警", side_effects="无", severity="high",
            severity_label="高", confidence="high", category="test",
            suggested_action="allow", action_label="允许",
            device_name="测试设备", device_ip="203.0.113.9", vendor="",
            device_type="unknown", destination="track.io.mi.com",
            domain="track.io.mi.com", organization="Xiaomi",
            first_seen=time.time(), last_seen=time.time())

        # 直接调服务方法（不依赖 httpd/store），验证内核行为
        res = svc.reset_observations()
        self.assertEqual(res["cleared"]["alerts"], 1)
        self.assertGreater(res["cleared"]["devices"], 0)
        self.assertEqual(len(svc.device_registry.devices), 0)
        self.assertEqual(len(svc.alert_center.active()), 0)
        self.assertEqual(len(svc.stats["unknown_domains"]), 0)
        # 许可注册表（actions.db）路径不受影响
        self.assertIsNotNone(svc.action_registry)

    def test_restore_rejudges_stale_unknowns(self):
        """快照恢复时旧「未知」归属必须用当前知识库重判（iStoreOS 实机教训）

        场景：旧版本知识库认不出 fastly.jsdelivr.net，快照里存了「未知」结论；
        知识库补录 jsdelivr.net 父域后重启，恢复快照不应把旧「未知」原样放回，
        未知域名列表也要同步剔除已能归属的条目。
        """
        from core.main import HomewardService
        svc = HomewardService(config={"load_system_devices": False})
        stale_unknown = {
            "domain": "fastly.jsdelivr.net", "organization": None,
            "category": "unknown", "confidence": "none", "description": "",
            "action": "allow", "side_effects": [],
            "matched_domain": None, "matched_by": "none",
        }
        state = {
            "version": 1, "saved_at": time.time(),
            "devices": {},
            "attribution_cache": [stale_unknown],
            "unknown_domains": ["fastly.jsdelivr.net", "api.ip.sb",
                                "still-unknown.example.org"],
            "alerts": [],
        }
        svc.restore_observations(state)

        # 旧「未知」必须被当前知识库转正（父域 jsdelivr.net 兜上）
        r = svc.attribution.resolve("fastly.jsdelivr.net")
        self.assertTrue(r.known, "快照恢复后旧未知结论必须用当前知识库重判")
        self.assertIn("jsDelivr", r.organization)
        self.assertEqual(r.matched_domain, "jsdelivr.net")

        # 未知域名列表：已能归属的剔除，真未知的保留
        unknowns = svc.get_unknown_domains()
        self.assertNotIn("fastly.jsdelivr.net", unknowns)
        self.assertNotIn("api.ip.sb", unknowns)
        self.assertIn("still-unknown.example.org", unknowns)

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
        """回环地址不该告警；绑 0.0.0.0 必须告警，且按鉴权开关给出不同措辞"""
        import io
        import contextlib
        from ui.auth import WebAuth
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ui_server._warn_if_exposed("127.0.0.1", auth=WebAuth(token="x"))
        self.assertEqual(buf.getvalue(), "")

        # 未启用鉴权（--no-auth）：明确提示暴露风险
        buf2 = io.StringIO()
        with contextlib.redirect_stdout(buf2):
            ui_server._warn_if_exposed("0.0.0.0", auth=None)
        self.assertIn("未启用鉴权", buf2.getvalue())

        # 已启用鉴权：措辞转为「已启用口令鉴权」
        buf3 = io.StringIO()
        with contextlib.redirect_stdout(buf3):
            ui_server._warn_if_exposed("0.0.0.0", auth=WebAuth(token="x"))
        self.assertIn("已启用口令鉴权", buf3.getvalue())

    def test_make_server_binds(self):
        svc = HomewardService(config={"load_system_devices": False})
        httpd = ui_server.make_server(svc, host="127.0.0.1", port=0)
        try:
            self.assertIsInstance(httpd, ThreadingHTTPServer)
            self.assertGreater(httpd.server_address[1], 0)
        finally:
            httpd.server_close()


# ---------------------------------------------------------------- 升级 / 许可接口（Task #12）

class TestUpgradeApi(ServerTestCase):
    """升级面板接口：/api/license/status、/api/qr、/api/activate、/api/license/deactivate。

    许可文件写入临时目录（HOMEWARD_DATA_DIR），不污染用户主目录；用例结束即清理。
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._prev_data_dir = os.environ.get("HOMEWARD_DATA_DIR")
        cls._tmp = tempfile.mkdtemp(prefix="homeward-lic-")
        os.environ["HOMEWARD_DATA_DIR"] = cls._tmp

    @classmethod
    def tearDownClass(cls):
        if cls._prev_data_dir is None:
            os.environ.pop("HOMEWARD_DATA_DIR", None)
        else:
            os.environ["HOMEWARD_DATA_DIR"] = cls._prev_data_dir
        import shutil
        shutil.rmtree(cls._tmp, ignore_errors=True)
        super().tearDownClass()

    def test_license_status_shape(self):
        d = self.get_json("/api/license/status")
        self.assertEqual(d["edition"]["edition"], "community")
        self.assertIn("license", d)
        self.assertIn("order_url", d)
        self.assertFalse(d["license"]["valid"])
        self.assertEqual(d["license"]["reason"], "none")

    def test_qr_returns_svg(self):
        text = "https://pay.homeward.dev/order?o=WX20260928"
        status, headers, body = self.get("/api/qr?text=" + urllib.parse.quote(text))
        self.assertEqual(status, 200)
        self.assertIn("image/svg+xml", headers.get("Content-Type", ""))
        self.assertIn(b"<svg", body)
        self.assertIn(b"</svg>", body)

    def test_qr_too_long(self):
        big = "x" * 300
        req = urllib.request.Request(self.base + "/api/qr?text=" + urllib.parse.quote(big))
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 400)

    def test_qr_missing_text(self):
        self.assertEqual(self.status_of("/api/qr"), 400)

    def test_activate_garbage_token(self):
        # 无效令牌仍会被保存（便于离线查看），但 status 标记为无效；端点本身返回 200。
        data = urllib.parse.urlencode({"token": "not-a-valid-token.xyz"}).encode()
        req = urllib.request.Request(self.base + "/api/activate", data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
        self.assertTrue(d["saved"])
        self.assertFalse(d["status"]["valid"])

    def test_write_method_constraints(self):
        """只读接口 POST 必须 405；仅写接口 GET 必须 405。"""
        self.assertEqual(self.status_of("/api/license/status", method="POST"), 405)
        self.assertEqual(self.status_of("/api/qr", method="POST"), 405)
        self.assertEqual(self.status_of("/api/activate", method="GET"), 405)
        self.assertEqual(self.status_of("/api/license/deactivate", method="GET"), 405)

    def test_deactivate_clears(self):
        req = urllib.request.Request(self.base + "/api/license/deactivate",
                                     data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read().decode("utf-8"))
        self.assertTrue(d["cleared"])


# ---------------------------------------------------------------- 离线导入 / 报告 / 持久化（P0 三件套）

class TestImportAndReportApi(ServerTestCase):
    """离线日志导入 + 观测报告导出接口。

    约束（见 open-core 边界约定）：报告只导用户自己的观测遥测，**绝不 Dump 知识库**，
    也不提供「浏览全部已知域名」接口。导入只喂用户给的原始日志，不读取知识库。
    """

    SAMPLE_DNS = (
        "Jun 1 12:00:01 dnsmasq[1234]: query[A] example.com from 192.168.1.177\n"
        "Jun 1 12:00:02 dnsmasq[1234]: query[A] tracker.acme-iot.net from 192.168.1.177\n"
        "Jun 1 12:00:03 dnsmasq[1234]: query[A] weather.google.com from 192.168.1.177\n"
        "this line is garbage and should be ignored\n"
    )
    SAMPLE_DNS_2 = (
        "Jun 1 12:00:01 dnsmasq[1234]: query[A] example.org from 192.168.1.178\n"
        "Jun 1 12:00:02 dnsmasq[1234]: query[A] ad.doubleclick.net from 192.168.1.178\n"
    )

    def test_import_returns_stats(self):
        status, body = self.post_text("/api/import", self.SAMPLE_DNS)
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        s = body["stats"]
        self.assertGreater(s["parsed"], 0, "应当解析出至少一行 DNS 查询")
        self.assertGreater(s["flows"], 0)
        self.assertGreaterEqual(s["new_devices"], 1, "应当识别出一台新设备")

    def test_import_accepts_json_and_form(self):
        # JSON：{"log": "..."}
        status, body = self.post_text(
            "/api/import", json.dumps({"log": self.SAMPLE_DNS_2}),
            content_type="application/json")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertGreaterEqual(body["stats"]["new_devices"], 1)
        # form-urlencoded：log=...
        status, body = self.post_text(
            "/api/import", "log=" + urllib.parse.quote(self.SAMPLE_DNS_2),
            content_type="application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])

    def test_import_rejects_get(self):
        # /api/import 是写操作，GET 必须 405
        self.assertEqual(self.status_of("/api/import", method="GET"), 405)

    def test_report_markdown(self):
        status, ctype, raw = self.get_raw("/api/report?format=markdown")
        self.assertEqual(status, 200)
        self.assertIn("text/markdown", ctype)
        text = raw.decode("utf-8")
        self.assertIn("家卫 Homeward · 观测报告", text)
        self.assertIn("概览", text)
        self.assertIn("盲区", text)
        # 绝不出现「浏览全部已知域名」式的能力
        self.assertNotIn("知识库全表", text)

    def test_report_json_structure(self):
        d = self.get_json("/api/report?format=json")
        self.assertIn("devices", d)
        self.assertIn("destinations", d)
        self.assertIn("alerts", d)
        self.assertIn("blind_spots", d)
        # 报告里出现的域名应当都是「用户观测到」的，而非知识库全部域名
        kb = self.get_json("/api/health")["kb_domains"]
        reported_domains = {x["domain"] for x in d["destinations"]["items"]}
        self.assertLessEqual(len(reported_domains), kb,
                             "报告不应把整个知识库都列出来")

    def test_report_rejects_post(self):
        self.assertEqual(self.status_of("/api/report", method="POST"), 405)


class TestObservationPersistence(unittest.TestCase):
    """观测状态持久化（SQLite 快照 + 服务还原）"""

    def test_store_roundtrip(self):
        from adapters.sqlite_registry import SqliteObservationStore
        import tempfile, shutil
        tmp = tempfile.mkdtemp(prefix="homeward-obs-")
        try:
            db = SqliteObservationStore(Path(tmp) / "obs.db")
            db.save({"version": 1, "x": 42})
            loaded = db.load()
            self.assertEqual(loaded["x"], 42)
            db.clear()
            self.assertIsNone(db.load())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_service_snapshot_restore(self):
        from core.main import HomewardService
        svc_a = HomewardService(config={"load_system_devices": False})
        seed_demo(svc_a)
        snap = svc_a.snapshot_observations()
        self.assertGreater(len(snap["devices"]), 0)
        self.assertGreater(len(snap["alerts"]), 0)

        # 全新服务：从快照还原，应当拿回设备与告警
        svc_b = HomewardService(config={"load_system_devices": False})
        self.assertEqual(len(svc_b.device_registry.devices), 0)
        restored = svc_b.restore_observations(snap)
        self.assertGreater(restored, 0)
        self.assertGreater(len(svc_b.device_registry.devices), 0)
        self.assertGreater(len(svc_b.alert_center.active()), 0)


if __name__ == "__main__":
    unittest.main()
