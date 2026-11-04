"""历史累加器（热路径口径）测试。

重点是把「计量口径」钉死：
- ``dns_count`` 只来自 DNS 查询 / SNI 事件；
- conntrack 回填了域名的流量**不算** DNS，只累加字节；
- 去向归一化 ``dns_query > sni > dst_ip:port``；
- 小时桶与天桶独立累加，``drain`` 后清空、``clear`` 可联动清除；
- 超上限时丢弃**新键**并计数（热路径不做 O(n) 淘汰）。
"""

import sys
import time
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analysis.history_rollup import HistoryRollup  # noqa: E402
from core.main import HomewardService  # noqa: E402
from rule_engine.engine import FlowRecord  # noqa: E402


class _Dev:
    def __init__(self, key, ip="192.168.1.5"):
        self.key = key
        self.ip = ip


def _flow(**kw):
    base = dict(timestamp=time.time(), src_ip="192.168.1.5", dst_ip="",
                dst_port=53, protocol="udp", dns_query="", sni="",
                packet_size=0)
    base.update(kw)
    return FlowRecord(**base)


class HistoryRollupTest(unittest.TestCase):

    def test_dns_event_counts_and_bytes_zero(self):
        r = HistoryRollup()
        r.add(_flow(dns_query="Api.TUYA.com", dst_port=53, dst_ip="", packet_size=0),
              _Dev("dev-a"))
        hourly, daily = r.drain()
        self.assertEqual(len(hourly), 1)
        self.assertEqual(hourly[0].dest_key, "api.tuya.com")
        self.assertEqual(hourly[0].dns_count, 1)
        self.assertEqual(hourly[0].bytes, 0)
        self.assertEqual(len(daily), 1)

    def test_conntrack_backfilled_domain_is_not_dns_count(self):
        """conntrack 流量即使有 dns_query（被 Tier2 回填），也只加字节。"""
        r = HistoryRollup()
        r.add(_flow(dst_ip="10.0.0.9", dst_port=443, protocol="tcp",
                    dns_query="cdn.example.net", packet_size=2048),
              _Dev("dev-a"))
        hourly, _ = r.drain()
        self.assertEqual(hourly[0].dest_key, "cdn.example.net")
        self.assertEqual(hourly[0].dns_count, 0)
        self.assertEqual(hourly[0].bytes, 2048)

    def test_dest_key_precedence_and_ip_fallback(self):
        r = HistoryRollup()
        # sni 优先于 ip:port
        r.add(_flow(dns_query="", sni="Svc.Example.COM", dst_ip="1.2.3.4",
                    dst_port=443, packet_size=10), _Dev("dev-a"))
        hourly, _ = r.drain()
        self.assertEqual(hourly[0].dest_key, "svc.example.com")
        # dns_query 优先于 sni
        r.add(_flow(dns_query="Q.Example.com", sni="svc.example.com",
                    dst_ip="1.2.3.4", dst_port=443), _Dev("dev-a"))
        hourly, _ = r.drain()
        self.assertEqual(hourly[0].dest_key, "q.example.com")
        # 无域名时退回 ip:port
        r.add(_flow(dns_query="", sni="", dst_ip="1.2.3.4", dst_port=8080,
                    packet_size=5), _Dev("dev-a"))
        hourly, _ = r.drain()
        self.assertEqual(hourly[0].dest_key, "1.2.3.4:8080")
        self.assertEqual(hourly[0].dns_count, 0)
        self.assertEqual(hourly[0].bytes, 5)

    def test_accumulates_first_last_ts_and_device(self):
        r = HistoryRollup()
        t0 = time.time() - 100
        for ts in (t0, t0 + 20, t0 + 50):
            r.add(_flow(timestamp=ts, dns_query="x.com", packet_size=7),
                  _Dev("dev-a", "192.168.1.5"))
        hourly, _ = r.drain()
        self.assertEqual(hourly[0].dns_count, 3)
        self.assertEqual(hourly[0].bytes, 21)
        self.assertAlmostEqual(hourly[0].first_ts, t0, places=3)
        self.assertAlmostEqual(hourly[0].last_ts, t0 + 50, places=3)
        self.assertEqual(hourly[0].device_ip, "192.168.1.5")

    def test_hour_and_day_are_independent_drains(self):
        r = HistoryRollup()
        r.add(_flow(dns_query="x.com"), _Dev("dev-a"))
        self.assertEqual(r.pending(), 2)  # 1 小时键 + 1 天键
        hourly, daily = r.drain()
        self.assertEqual(r.pending(), 0)
        self.assertEqual(len(hourly), 1)
        self.assertEqual(len(daily), 1)

    def test_cap_drops_new_keys(self):
        r = HistoryRollup(max_keys=2)
        for i in range(5):
            r.add(_flow(dns_query=f"d{i}.example.com"), _Dev("dev-a"))
        hourly, _ = r.drain()
        self.assertEqual(len(hourly), 2)
        self.assertEqual(r.dropped, 3)

    def test_clear_discards_pending(self):
        r = HistoryRollup()
        r.add(_flow(dns_query="x.com"), _Dev("dev-a"))
        r.clear()
        hourly, daily = r.drain()
        self.assertEqual((hourly, daily), ([], []))


class ServiceHistoryHookTest(unittest.TestCase):
    """HomewardService 的接线：开关、drain、clear 联动。"""

    def test_disabled_by_default(self):
        svc = HomewardService(config={"load_system_devices": False, "actions_db_path": None})
        svc.process_flow(_flow(dns_query="x.com"))
        self.assertFalse(svc.history_enabled)
        hourly, daily = svc.drain_history()
        self.assertEqual((hourly, daily), ([], []))

    def test_enabled_accumulates_and_clear_resets(self):
        svc = HomewardService(config={"load_system_devices": False,
                                      "actions_db_path": None,
                                      "history_enabled": True})
        svc.process_flow(_flow(dns_query="x.com"))
        hourly, daily = svc.drain_history()
        self.assertEqual(len(hourly), 1)
        self.assertEqual(hourly[0].dest_key, "x.com")
        self.assertEqual(len(daily), 1)
        # 再次观测后清除：内存桶必须一起清，否则旧累计会被下一轮 flush 写回
        svc.process_flow(_flow(dns_query="x.com"))
        svc.reset_observations()
        hourly, daily = svc.drain_history()
        self.assertEqual((hourly, daily), ([], []))


if __name__ == "__main__":
    unittest.main()
