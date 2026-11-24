"""
待办-526 · 采集侧哨兵（方案 §5）—— 日志缺失时必须显式告警，不许静默空转

只测最容易回归、且不依赖时间的两条：
  1. 三个默认路径都不可读 → WARNING 写明「无 DNS 观测状态」，且不产出任何记录；
  2. 显式路径不存在 → 同样告警。
轮转丢行与停更告警走时间驱动，留给真机；这里不伪造 5 分钟等待。
"""

import logging
import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from collectors.dns import DnsLogCollector  # noqa: E402


class DnsMissingLogSentinelTest(unittest.TestCase):

    def test_missing_default_paths_warns_and_yields_nothing(self):
        c = DnsLogCollector(log_path=None)
        with self.assertLogs("homeward.collectors.dns", level="WARNING") as cap:
            out = list(c.records())
        self.assertEqual(out, [])
        self.assertTrue(any("无 DNS 观测" in m for m in cap.output), cap.output)

    def test_missing_explicit_path_warns(self):
        c = DnsLogCollector(log_path="/nonexistent/homeward/dnsmasq.log")
        with self.assertLogs("homeward.collectors.dns", level="WARNING") as cap:
            out = list(c.records())
        self.assertEqual(out, [])
        self.assertTrue(any("无 DNS 观测" in m for m in cap.output), cap.output)


if __name__ == "__main__":
    unittest.main()
