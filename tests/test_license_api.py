"""tests/test_license_api.py —— 许可导入 / 状态 / 停用 端到端（S0-3 验收）

策略（同 test_ui.py）：真起 HTTP 服务打真实请求。但许可模块的公钥与数据目录
必须在**服务构造之前**注入（verify.py 在 import 时绑定公钥、store.py 在 import
时绑定 verify 的函数），因此本文件自建服务实例，并在 tearDownClass 还原环境
变量 + 重载模块，避免影响同进程其他测试。

覆盖拍板验收（商业化计划 §3.4 · S0-3 行）：
  · 导入测试令牌 → status.valid=True 且 features 解锁（mock 功能位）
  · 过期令牌 → reason=expired 正确回落
  · 篡改令牌 → reason=invalid；停用 → 回到社区版（reason=none）
"""

import base64
import importlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from license.ed25519 import derive_public, sign_message  # noqa: E402
from license.verify import canonical  # noqa: E402


def _sign_token(seed: bytes, payload: dict) -> str:
    """用测试种子签出令牌（与签发端同款 canonical + base64 格式）。"""
    sig = sign_message(canonical(payload), seed)
    head = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode()
    return f"{head}.{base64.b64encode(sig).decode()}"


def _payload(valid_days: int = 365, device_fp: str = "fp-test-001",
             order_id: str = "TEST-S0-3") -> dict:
    now = int(time.time())
    return {
        "kid": "2026-10",
        "edition": "standard",
        "device_fp": device_fp,
        "features": ["dns_block"],
        "issued_at": now,
        "valid_until": now + valid_days * 86400,
        "order_id": order_id,
        "nonce": os.urandom(8).hex(),
    }


class TestLicenseApi(unittest.TestCase):
    """自建服务：测试公钥 + 隔离数据目录在服务构造前注入，tearDown 还原。"""

    @classmethod
    def setUpClass(cls):
        from core.main import HomewardService
        from ui import server as ui_server

        cls._seed = os.urandom(32)
        cls._pub_b64 = base64.b64encode(derive_public(cls._seed)).decode()
        cls._env_saved = {k: os.environ.get(k) for k in
                          ("HOMEWARD_LICENSE_PUBLIC_KEY_B64", "HOMEWARD_DATA_DIR")}
        os.environ["HOMEWARD_LICENSE_PUBLIC_KEY_B64"] = cls._pub_b64
        cls._tmp = tempfile.mkdtemp(prefix="homeward-lic-test-")
        os.environ["HOMEWARD_DATA_DIR"] = cls._tmp
        # 重载顺序：verify（绑新公钥）→ store（绑新 verify）→ ui.server（绑新 store）
        import license.store
        import license.verify
        importlib.reload(license.verify)
        importlib.reload(license.store)
        importlib.reload(ui_server)

        cls.service = HomewardService(config={"load_system_devices": False})
        cls.httpd = ui_server.make_server(cls.service, host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        # 服务端 /api/license/status 传的是**真实设备指纹**（D2 拍板的设备绑定），
        # 测试令牌必须按同一指纹签，否则走的是「设备不符」而非目标场景。
        cls._fp = license.store.device_fingerprint()
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        for k, v in cls._env_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import license.store
        import license.verify
        from ui import server as ui_server
        importlib.reload(license.verify)
        importlib.reload(license.store)
        importlib.reload(ui_server)

    # ---- 工具 ----

    def _post_form(self, path: str, form: dict):
        data = urllib.parse.urlencode(form).encode("utf-8")
        req = urllib.request.Request(
            self.base + path, data=data, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            try:
                return e.code, json.loads(body)
            except Exception:
                return e.code, {"raw": body}

    def _get_json(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def _license_status(self) -> dict:
        _st, body = self._get_json("/api/license/status")
        return body["license"]

    # ---- 拍板验收 ----

    def test_activate_valid_token_unlocks_features(self):
        """验收①：导入测试令牌 → valid + features 解锁（mock 功能位）。"""
        token = _sign_token(self._seed, _payload(device_fp=self._fp))
        st, body = self._post_form("/api/activate", {"token": token})
        self.assertEqual(st, 200)
        self.assertTrue(body["saved"])
        lic = self._license_status()
        self.assertTrue(lic["valid"], f"有效令牌未通过: {lic}")
        self.assertEqual(lic["reason"], "ok")
        self.assertEqual(lic["edition"], "standard")
        self.assertIn("dns_block", lic["features"], "mock 功能位未解锁")
        self.assertGreater(lic["days_remaining"], 360)

    def test_expired_token_falls_back(self):
        """验收②：过期令牌 → reason=expired 正确回落（保存不拦截、状态如实）。"""
        token = _sign_token(self._seed, _payload(valid_days=-1, device_fp=self._fp))
        st, _body = self._post_form("/api/activate", {"token": token})
        self.assertEqual(st, 200, "离线/过期令牌也应允许保存（status 如实反映）")
        lic = self._license_status()
        self.assertFalse(lic["valid"])
        self.assertEqual(lic["reason"], "expired")
        self.assertEqual(lic["days_remaining"], 0)

    # ---- S1-1 手动签发链路：设备指纹可达（客户→作者的绑定依据）----

    def test_status_includes_device_fp(self):
        """手动签发时客户需要把设备指纹发给作者（EDITIONS 试用条款 2）——
        status 响应必须带 device_fp，且为 64 位 sha256 十六进制（非原始硬件信息）。"""
        _st, body = self._get_json("/api/license/status")
        fp = body.get("device_fp") or ""
        self.assertEqual(len(fp), 64, f"device_fp 应为 64 位 sha256: {fp!r}")
        int(fp, 16)  # 非十六进制会抛错

    def test_status_includes_external_entry_kvs(self):
        """升级面板的外部入口（付款 / 早鸟）统一由服务端下发，前端不硬编码外部 URL。"""
        _st, body = self._get_json("/api/license/status")
        self.assertIn("order_url", body)
        self.assertIn("earlybird_url", body)
        self.assertTrue(body["order_url"], "order_url 不应为空（有默认付款页）")
        # earlybird_url 未配置时为空串，前端据以降级为「待上线」
        self.assertIsInstance(body["earlybird_url"], str)

    # ---- S1-2 试用链路（EDITIONS 试用条款：order_id=trial-* 的时间受限标准版许可）----

    def test_trial_token_recognized(self):
        """条款1：试用令牌 → is_trial=True、edition=standard、≈30 天。"""
        token = _sign_token(self._seed, _payload(
            valid_days=30, device_fp=self._fp, order_id="trial-abc123"))
        st, body = self._post_form("/api/activate", {"token": token})
        self.assertEqual(st, 200)
        lic = self._license_status()
        self.assertTrue(lic["valid"], f"试用令牌未通过: {lic}")
        self.assertTrue(lic["is_trial"], f"试用令牌未被识别: {lic}")
        self.assertEqual(lic["edition"], "standard")
        self.assertGreaterEqual(lic["days_remaining"], 29)
        self.assertLessEqual(lic["days_remaining"], 30)

    def test_expired_trial_keeps_trial_marker(self):
        """条款3：到期回落时 UI 要区分「试用已到期」与「订阅已过期」
        → 无效分支也必须带 is_trial。"""
        token = _sign_token(self._seed, _payload(
            valid_days=-1, device_fp=self._fp, order_id="trial-xyz789"))
        self._post_form("/api/activate", {"token": token})
        lic = self._license_status()
        self.assertFalse(lic["valid"])
        self.assertEqual(lic["reason"], "expired")
        self.assertTrue(lic["is_trial"], f"过期试用令牌丢失试用标记: {lic}")

    def test_paid_token_is_not_trial(self):
        """付费令牌（order_id 非 trial-*）→ is_trial=False。"""
        token = _sign_token(self._seed, _payload(
            device_fp=self._fp, order_id="WX-PAID-20261020"))
        self._post_form("/api/activate", {"token": token})
        lic = self._license_status()
        self.assertTrue(lic["valid"])
        self.assertFalse(lic["is_trial"], f"付费令牌被误标为试用: {lic}")

    # ---- 边界 ----

    def test_tampered_token_rejected(self):
        token = _sign_token(self._seed, _payload(device_fp=self._fp))
        head, tail = token.split(".", 1)
        p = json.loads(base64.b64decode(head))
        p["edition"] = "pro"
        bad_head = base64.b64encode(
            json.dumps(p, ensure_ascii=False).encode()).decode()
        self._post_form("/api/activate", {"token": f"{bad_head}.{tail}"})
        lic = self._license_status()
        self.assertFalse(lic["valid"])
        self.assertEqual(lic["reason"], "invalid")

    def test_deactivate_returns_to_community(self):
        token = _sign_token(self._seed, _payload(device_fp=self._fp))
        self._post_form("/api/activate", {"token": token})
        self.assertTrue(self._license_status()["valid"])
        st, body = self._post_form("/api/license/deactivate", {})
        self.assertEqual(st, 200)
        self.assertTrue(body["cleared"])
        self.assertEqual(self._license_status()["reason"], "none")

    def test_activate_missing_token_400(self):
        st, body = self._post_form("/api/activate", {})
        self.assertEqual(st, 400)
        self.assertEqual(body["error"], "missing_token")

    def test_activate_get_method_405(self):
        req = urllib.request.Request(self.base + "/api/activate", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        self.assertEqual(code, 405)

    def test_qr_endpoint_smoke(self):
        url = self.base + "/api/qr?" + urllib.parse.urlencode(
            {"text": "https://pay.homeward.dev/order?test=1"})
        with urllib.request.urlopen(url, timeout=10) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers.get("Content-Type"), "image/svg+xml")
            body = r.read().decode("utf-8")
        self.assertTrue(body.lstrip().startswith("<svg"), "QR 应返回 SVG")

    def test_qr_missing_text_400(self):
        try:
            with urllib.request.urlopen(self.base + "/api/qr", timeout=10) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
            body = json.loads(e.read().decode("utf-8"))
            self.assertEqual(body["error"], "missing_text")
        self.assertEqual(code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
