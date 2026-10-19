"""tests/test_concurrency.py —— 采集线程与快照/查询线程的并发安全。

背景（真实缺陷）：后台 ``_ObservationSaver`` 每 60 秒调一次
``snapshot_observations()``，它遍历设备台账 / 归属缓存 / 告警中心；
同时采集线程在 ``process_flow`` 里往同一批 dict 里塞数据。
Python 在「遍历中 dict 被改大小」时抛
``RuntimeError: dictionary changed size during iteration`` ——
高流量下必现，表现为后台快照线程反复报错、持久化静默失效。

修复方式：读写两侧都持有 ``HomewardService._state_lock``。
本文件用「写线程狂喂 + 读线程狂取」把它钉住，防止将来有人绕过锁改回去。

运行：python -m pytest tests/test_concurrency.py -q
"""
import os
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rule_engine.engine import FlowRecord          # noqa: E402
from core.main import HomewardService              # noqa: E402


def _flow(i: int) -> FlowRecord:
    return FlowRecord(
        timestamp=time.time(),
        src_ip=f"10.9.{i // 250}.{i % 250 + 1}",
        dst_ip="93.184.216.34",
        dst_port=443,
        protocol="tcp",
        dns_query=f"d{i % 50}.example.com",
        packet_size=120,
    )


class SnapshotRaceTest(unittest.TestCase):
    """写线程喂数据 + 读线程取快照：不得抛 RuntimeError"""

    def _run(self, reader, duration=1.2):
        svc = HomewardService(config={"load_system_devices": False,
                                      "actions_db_path": None})
        stop = threading.Event()
        errors = []

        def writer():
            i = 0
            try:
                while not stop.is_set():
                    svc.process_flow(_flow(i))
                    i += 1
            except Exception as exc:          # 写线程自身异常也要被看见
                errors.append(f"writer: {exc!r}")

        def reader_loop():
            try:
                while not stop.is_set():
                    reader(svc)
            except Exception as exc:
                errors.append(f"reader: {exc!r}")

        threads = [threading.Thread(target=writer, daemon=True)]
        threads += [threading.Thread(target=reader_loop, daemon=True) for _ in range(2)]
        for t in threads:
            t.start()
        time.sleep(duration)
        stop.set()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"并发访问出现异常: {errors}")
        self.assertGreater(svc.stats["flows_processed"], 0, "写线程没有真正产生数据")

    def test_snapshot_observations_under_load(self):
        self._run(lambda s: s.snapshot_observations())

    def test_read_views_under_load(self):
        def reader(s):
            s.get_stats()
            s.get_devices()
            s.get_destinations()
            s.get_alerts()
            s.attribution_coverage()

        self._run(reader)

    def test_export_report_under_load(self):
        self._run(lambda s: s.export_report())


class DeviceRefreshTest(unittest.TestCase):
    """设备身份周期刷新（W2 修复，2026-10-19）。

    背景：DHCP 租约 / ARP 原先只在 ``__init__`` 读一次，运行期先被
    ``observe_ip`` 按 IP 兜底建档的设备永远拿不到 MAC —— 真机上设备列表
    一片裸 IP。修复：起一个低频刷新线程重读租约 / ARP，把 IP 兜底设备
    升级回 MAC 主键（device.py ``_attach_mac``）。

    本文件钉住两件事：① 刷新线程的启停生命周期；② 刷新确实发生、
    且确实完成身份升级（用假租约替换真实系统读取，测试 hermetic）。
    """

    LEASE_LINE = (f"{int(time.time()) + 3600} "
                  "aa:bb:cc:00:11:22 192.168.9.10 Bedroom-Cam *\n")

    def _service(self, interval):
        return HomewardService(config={"load_system_devices": False,
                                       "actions_db_path": None,
                                       "device_refresh_interval": interval})

    def test_interval_zero_means_no_thread(self):
        """interval<=0 = 显式关闭刷新；不起线程，停止也要安全"""
        svc = self._service(0)
        self.assertIsNone(svc._device_refresh_thread)
        svc.start_device_refresh()
        self.assertIsNone(svc._device_refresh_thread)
        svc.stop_device_refresh()  # 未启动时调用不得抛

    def test_refresh_upgrades_ip_only_device(self):
        svc = self._service(0.05)
        calls = {"n": 0}

        def fake_load():
            calls["n"] += 1
            svc.device_registry.load_leases(self.LEASE_LINE)
            return {"leases": 1, "arp": 0}

        svc.device_registry.load_from_system = fake_load
        # 先按 IP 兜底建档（模拟采集线程先于租约刷新看到流量）
        dev = svc.device_registry.observe_ip("192.168.9.10")
        self.assertIsNone(dev.mac)

        svc.start_device_refresh()
        try:
            deadline = time.time() + 3
            while time.time() < deadline:
                d = svc.device_registry.get_by_ip("192.168.9.10")
                if d is not None and d.mac:
                    break
                time.sleep(0.02)
        finally:
            svc.stop_device_refresh()

        self.assertGreaterEqual(calls["n"], 1, "刷新线程没有真正跑起来")
        d = svc.device_registry.get_by_ip("192.168.9.10")
        self.assertIsNotNone(d, "升级后按 IP 应仍查得到设备")
        self.assertEqual(d.mac, "aa:bb:cc:00:11:22")
        self.assertEqual(d.key, "aa:bb:cc:00:11:22")
        self.assertNotIn("192.168.9.10", svc.device_registry.devices,
                         "IP 兜底条目必须撤销，同一台设备不能拆成两台")

    def test_stop_is_prompt(self):
        """stop 后线程应很快退出（不得挂 30s 拖住进程退出）"""
        svc = self._service(30)
        svc.start_device_refresh()
        t = svc._device_refresh_thread
        self.assertTrue(t.is_alive())
        t0 = time.time()
        svc.stop_device_refresh()
        self.assertLess(time.time() - t0, 2)
        self.assertFalse(t.is_alive())


if __name__ == "__main__":
    unittest.main()
