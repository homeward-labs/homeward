# -*- coding: utf-8 -*-
"""S1-4 盲区覆盖率指标 —— 回归测试

被测对象（S1-4 实现，授权范围内未提交）：
  · ``HomewardService.visibility_coverage()``（src/core/main.py）——设备观测覆盖比；
  · ``privacy_checkup()`` 纯新增的 ``visible_devices`` / ``suspected_invisible_devices``；
  · ``/api/overview`` 的 ``visibility`` 键；
  · 导出报告 JSON / Markdown 双端的「设备观测覆盖」行。

测试策略（参照 tests/test_ui.py）：
  · 单元层直测 ``HomewardService``，台账数据全部手工构造；
  · API 层真起 HTTP 服务（127.0.0.1 临时端口）+ urllib 打真实请求；
  · 每个用例只断言一件事，用例名说人话。

被测口径（实现报告 §2 + 队长拍板口径 1-2，本文件负责锁死）：
  可见 X          = 在册设备中 domains 非空的台数（剔除「本机」设备）
  疑似不可见 Y    = domains 为空的台数（剔除「本机」设备）
  no_mac / random_mac / no_identity 只统计 Y 集合，三类互相重叠，不进比例算术
"""

import json
import re
import sys
import threading
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.demo import seed_demo                                # noqa: E402
from core.main import HomewardService                          # noqa: E402
from inventory.device import _SELF_DEVICE_KEY, is_random_mac   # noqa: E402
from rule_engine.engine import FlowRecord                      # noqa: E402
from ui import server as ui_server                             # noqa: E402

# RFC 5737 TEST-NET-3 文档段地址：与仓库既有用法（demo.py / test_ui.py）一致，
# 且绝不可能是运行测试这台机器的真实 IP（不会被 _resolve_self_ips 归并成「本机」）。
IP_CAM = "203.0.113.10"       # 构造场景：唯一一台「可见」设备
IP_NO_MAC = "203.0.113.20"    # 构造场景：无 MAC / 无主机名 / 无厂商的 IP 兜底设备
IP_RAND_MAC = "203.0.113.30"  # 构造场景：随机 MAC 设备的 IP
# MAC 首字节 02:.. —— U/L 位置 1，即设备临时生成的「隐私保护地址」（device.py:180-201）
RAND_MAC = "02:00:00:00:00:02"

VISIBILITY_KEYS = ("visible", "suspected_invisible", "total", "rate",
                   "no_mac", "random_mac", "no_identity", "denominator_note")

# privacy_checkup 在 S1-4 之前就存在的键（test_feature_evolution_phase_a.py:215-224
# 的同款断言）——S1-4 只许纯新增，这些键一个都不能少
CHECKUP_LEGACY_KEYS = ("score", "verdict", "devices_total", "vendors_resolved",
                       "alerts_active", "alerts_high", "coverage_hit",
                       "coverage_total", "coverage_rate", "unknown_count",
                       "top_unknown", "blind_spots")


def _service() -> HomewardService:
    """不起系统采集、不落盘（内存动作库 + 关闭建议周期保存）的干净服务实例"""
    return HomewardService(config={
        "load_system_devices": False,
        "actions_db_path": None,
        "suggestions_save_every": 0,
    })


def _flow(src_ip: str, domain: str, ts: float = 1_700_000_000.0) -> FlowRecord:
    return FlowRecord(timestamp=ts, src_ip=src_ip, dst_ip="203.0.113.99",
                      dst_port=443, protocol="tcp", dns_query=domain)


def _seed_partial(svc: HomewardService) -> None:
    """构造「1 台可见 + 2 台疑似」台账：

    · 可见：IP_CAM，喂过一条 DNS 查询（domains 非空）；
    · 疑似 ①：IP_NO_MAC，只被 observe_ip 见过——无 MAC / 无主机名 / 无厂商；
    · 疑似 ②：随机 MAC 设备（02:00:00:00:00:02），有主机名、无域名观测。
    """
    svc.process_flow(_flow(IP_CAM, "api.example.com"))
    svc.device_registry.observe_ip(IP_NO_MAC)
    lease = f"{int(time.time()) + 86400} {RAND_MAC} {IP_RAND_MAC} Pixel-9\n"
    svc.device_registry.load_leases(lease)


# ============================================================ A 层：单元（不起服务）

class VisibilityCoverageUnitTest(unittest.TestCase):

    def test_空台账_返回全零且不抛错(self):
        svc = _service()
        vis = svc.visibility_coverage()
        self.assertEqual(vis["total"], 0)
        self.assertEqual(vis["visible"], 0)
        self.assertEqual(vis["suspected_invisible"], 0)
        self.assertEqual(vis["rate"], 0.0)
        self.assertIsInstance(vis["rate"], float)
        self.assertEqual(vis["no_mac"], 0)
        self.assertEqual(vis["random_mac"], 0)
        self.assertEqual(vis["no_identity"], 0)

    def test_全可见_比率为一且分解数清零(self):
        svc = _service()
        for i, ip in enumerate(("203.0.113.11", "203.0.113.12", "203.0.113.13")):
            svc.process_flow(_flow(ip, f"api{i}.example.com"))
        vis = svc.visibility_coverage()
        self.assertEqual(vis["visible"], 3)
        self.assertEqual(vis["suspected_invisible"], 0)
        self.assertEqual(vis["rate"], 1.0)
        self.assertEqual(vis["no_mac"], 0)
        self.assertEqual(vis["random_mac"], 0)
        self.assertEqual(vis["no_identity"], 0)

    def test_部分可见_分解数只统计疑似集合(self):
        svc = _service()
        _seed_partial(svc)
        # 前置条件：三台设备确实按预期建档，否则后面的精确值没有意义
        self.assertTrue(svc.device_registry.devices[IP_CAM].domains)
        no_mac_dev = svc.device_registry.devices[IP_NO_MAC]
        self.assertIsNone(no_mac_dev.mac)
        self.assertFalse(no_mac_dev.hostname)
        self.assertFalse(no_mac_dev.vendor)
        rand_dev = svc.device_registry.devices[RAND_MAC]
        self.assertTrue(is_random_mac(RAND_MAC))
        self.assertTrue(rand_dev.random_mac)
        self.assertEqual(rand_dev.hostname, "Pixel-9")
        # 02:00:00 是本地管理位前缀，IEEE 不会分配，OUI 表查不到；
        # 若将来厂商表收录了该前缀，no_identity 的预期值要随之复核
        self.assertIsNone(rand_dev.vendor)

        vis = svc.visibility_coverage()
        self.assertEqual(vis["visible"], 1)
        self.assertEqual(vis["suspected_invisible"], 2)
        self.assertEqual(vis["total"], 3)
        self.assertEqual(vis["rate"], round(1 / 3, 4))
        # 核心口径：分解数只统计 Y 集合。注意可见设备同样是「无 MAC 无身份」的
        # IP 兜底设备——若误按全部设备统计，no_mac / no_identity 都会变成 2
        self.assertEqual(vis["no_mac"], 1)
        self.assertEqual(vis["random_mac"], 1)
        self.assertEqual(vis["no_identity"], 1)

    def test_本机设备被剔除_不虚增可见数(self):
        svc = _service()
        svc.process_flow(_flow(IP_CAM, "api.example.com"))
        before = svc.visibility_coverage()
        # 本机（跑家卫的设备）自身的域名查询：进得了台账，进不了指标
        self_dev = svc.device_registry.observe_ip("127.0.0.1")
        self_dev.observe_domain("self-noise.example.com")
        self.assertIn(_SELF_DEVICE_KEY, svc.device_registry.devices)
        self.assertTrue(
            svc.device_registry.devices[_SELF_DEVICE_KEY].domains,
            "前置条件：本机设备必须带着域名观测，否则本条用例没在测剔除")
        after = svc.visibility_coverage()
        self.assertEqual(after, before)

    def test_checkup_新键与指标一致_既有键不回退(self):
        svc = _service()
        _seed_partial(svc)
        vis = svc.visibility_coverage()
        checkup = svc.privacy_checkup()
        self.assertEqual(checkup["visible_devices"], vis["visible"])
        self.assertEqual(checkup["suspected_invisible_devices"],
                         vis["suspected_invisible"])
        for k in CHECKUP_LEGACY_KEYS:
            self.assertIn(k, checkup)

    def test_denominator_note_存在且非空(self):
        svc = _service()
        _seed_partial(svc)
        note = svc.visibility_coverage()["denominator_note"]
        self.assertIsInstance(note, str)
        self.assertTrue(note.strip())


# ============================================================ B 层：API（真起服务）

class _ServerHarness(unittest.TestCase):
    """真起 HTTP 服务的公共骨架（起服务方式参照 tests/test_ui.py:29-46）"""

    seed = False  # 子类覆盖：是否灌演示数据

    @classmethod
    def setUpClass(cls):
        cls.service = _service()
        if cls.seed:
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

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, r.headers, r.read()

    def get_json(self, path):
        status, _headers, body = self.get(path)
        self.assertEqual(status, 200, path)
        return json.loads(body.decode("utf-8"))

    def get_text(self, path):
        status, _headers, body = self.get(path)
        self.assertEqual(status, 200, path)
        return body.decode("utf-8")


class VisibilityApiTest(_ServerHarness):
    """演示数据下的 API 契约"""

    seed = True

    def test_overview_visibility_八键齐全且类型正确(self):
        d = self.get_json("/api/overview")
        vis = d["visibility"]
        self.assertEqual(set(vis), set(VISIBILITY_KEYS))
        for k in ("visible", "suspected_invisible", "total",
                  "no_mac", "random_mac", "no_identity"):
            self.assertIsInstance(vis[k], int, k)
        self.assertIsInstance(vis["rate"], float)
        self.assertIsInstance(vis["denominator_note"], str)
        # 双端同源：overview 内 checkup 两键必须与 visibility 数值一致
        self.assertEqual(d["checkup"]["visible_devices"], vis["visible"])
        self.assertEqual(d["checkup"]["suspected_invisible_devices"],
                         vis["suspected_invisible"])

    def test_demo数据_疑似不可见为零(self):
        vis = self.get_json("/api/overview")["visibility"]
        # demo 剧本里每台设备都喂过域名级流量（seed_demo_flows），Y=0 是预期行为；
        # 「有盲区」路径由单元层 _seed_partial 构造的场景覆盖
        self.assertEqual(vis["suspected_invisible"], 0)
        self.assertEqual(vis["visible"], 5)
        self.assertEqual(vis["total"], 5)
        self.assertEqual(vis["rate"], 1.0)

    def test_blind_spots_契约不回退(self):
        d = self.get_json("/api/blind-spots")
        self.assertEqual(set(d), {"items"})
        self.assertIsInstance(d["items"], list)
        for item in d["items"]:
            self.assertIsInstance(item, str)

    def test_report_双端同步_设备观测覆盖(self):
        rep = self.get_json("/api/report?format=json")
        checkup = rep["checkup"]
        self.assertIsInstance(checkup["visible_devices"], int)
        self.assertIsInstance(checkup["suspected_invisible_devices"], int)
        md = self.get_text("/api/report")  # 不传 format 默认走 Markdown
        lines = re.findall(
            r"设备观测覆盖：可见 \d+ / 疑似不可见 \d+（\d+\.\d%）", md)
        # 「体检结论」与「概览」双端都要有——防「JSON 有、Markdown 无」的回归
        self.assertGreaterEqual(len(lines), 2)
        # Markdown 上的数字必须与 JSON 端一致
        self.assertIn(
            f"设备观测覆盖：可见 {checkup['visible_devices']} / "
            f"疑似不可见 {checkup['suspected_invisible_devices']}", md)


class EmptyLedgerApiTest(_ServerHarness):
    """空台账（不起 demo）：零分母不除零、不 500"""

    seed = False

    def test_空台账_overview_全零(self):
        vis = self.get_json("/api/overview")["visibility"]
        self.assertEqual(vis["visible"], 0)
        self.assertEqual(vis["suspected_invisible"], 0)
        self.assertEqual(vis["total"], 0)
        self.assertEqual(vis["rate"], 0.0)

    def test_空台账_markdown_不除零(self):
        md = self.get_text("/api/report?format=markdown")
        self.assertIn("设备观测覆盖：可见 0 / 疑似不可见 0（0.0%）", md)


if __name__ == "__main__":
    unittest.main()
