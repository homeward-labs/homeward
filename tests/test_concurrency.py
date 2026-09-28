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


if __name__ == "__main__":
    unittest.main()
