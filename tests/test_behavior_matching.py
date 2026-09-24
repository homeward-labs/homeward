"""
行为特征匹配单测（src/rule_engine/engine.py::BehaviorMatcher）

这些用例专门锁住两个**修复过**的语义坑，防止以后又被改回错误实现：

  1. ``duration_min`` 的单位是秒（观测窗口长度），不是「记录条数」。
     旧实现写成 ``len(relevant) < duration_min``，拿时间阈值去卡样本量。
  2. ``interval`` 必须真的去算相邻观测的时间差。
     旧实现只比了平均包大小，把 interval 读出来就丢掉 —— 任何小包流量
     都会被误判成心跳信标。

用标准库 unittest，与同目录其它测试保持一致（无需装 pytest）。
"""

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from rule_engine.engine import BehaviorMatcher, FlowRecord  # noqa: E402


def _flow(ts: float, size: int = 64, direction: str = "out") -> FlowRecord:
    return FlowRecord(
        timestamp=ts,
        src_ip="192.168.1.50",
        dst_ip="203.0.113.1",
        dst_port=443,
        protocol="tcp",
        packet_size=size,
        direction=direction,
    )


def _matches(pattern: dict, flows: list[FlowRecord]) -> bool:
    matcher = BehaviorMatcher.__new__(BehaviorMatcher)  # 不加载知识库，只测判定逻辑
    return matcher._matches(flows, pattern)


class TestDurationIsSecondsNotCount(unittest.TestCase):
    """duration_min 是秒，不是条数"""

    def test_two_records_spanning_120s_pass_a_60s_window(self):
        """两条观测跨度 120 秒，应通过 60 秒窗口（旧实现会因条数 2 < 60 而漏判）"""
        flows = [_flow(1000.0), _flow(1120.0)]
        self.assertTrue(_matches({"direction": "out", "duration_min": 60}, flows))

    def test_many_records_within_a_short_window_fail(self):
        """观测很密但总跨度只有 10 秒，不应通过 60 秒窗口（条数多不代表窗口够长）"""
        flows = [_flow(1000.0 + i) for i in range(20)]  # 20 条，跨度 19 秒
        self.assertFalse(_matches({"direction": "out", "duration_min": 60}, flows))


class TestHeartbeatIntervalIsReallyChecked(unittest.TestCase):
    """心跳信标必须校验时间间隔，不能只看包大小"""

    def test_steady_30s_interval_small_packets_match(self):
        flows = [_flow(1000.0 + 30 * i, size=60) for i in range(12)]
        pattern = {
            "direction": "out",
            "interval": {"min": 30, "max": 60},
            "packet_size": {"min": 40, "max": 100},
            "min_occurrences": 10,
        }
        self.assertTrue(_matches(pattern, flows))

    def test_irregular_interval_does_not_match(self):
        """包大小合规但间隔忽快忽慢 —— 旧实现会误判成心跳"""
        flows = [_flow(1000.0 + gap, size=60) for gap in (0, 5, 305, 310, 900, 905, 1500, 1505)]
        pattern = {
            "direction": "out",
            "interval": {"min": 30, "max": 60},
            "packet_size": {"min": 40, "max": 100},
            "min_occurrences": 5,
        }
        self.assertFalse(_matches(pattern, flows))

    def test_too_few_occurrences_does_not_match(self):
        """样本量不足，即便间隔完美也不下结论"""
        flows = [_flow(1000.0 + 30 * i, size=60) for i in range(3)]
        pattern = {
            "direction": "out",
            "interval": {"min": 30, "max": 60},
            "min_occurrences": 10,
        }
        self.assertFalse(_matches(pattern, flows))


class TestBulkUpload(unittest.TestCase):
    """突发大流量上传：字节数 + 窗口长度一起判"""

    def test_one_megabyte_over_two_minutes_matches(self):
        flows = [
            _flow(1000.0 + i, size=20_000) for i in range(0, 120, 10)
        ]  # 12 条 × 20KB ≈ 240KB
        flows += [_flow(1000.0 + 120, size=900_000)]
        pattern = {
            "direction": "out",
            "duration_min": 60,
            "total_bytes_min": 1_048_576,
        }
        self.assertTrue(_matches(pattern, flows))

    def test_small_traffic_does_not_match(self):
        flows = [_flow(1000.0 + i * 10, size=100) for i in range(10)]
        pattern = {
            "direction": "out",
            "duration_min": 60,
            "total_bytes_min": 1_048_576,
        }
        self.assertFalse(_matches(pattern, flows))


class TestWrongDirectionIsIgnored(unittest.TestCase):
    """方向不匹配的观测不参与判定"""

    def test_only_inbound_flows_never_match_outbound_pattern(self):
        flows = [_flow(1000.0 + i, size=60, direction="in") for i in range(12)]
        pattern = {"direction": "out", "min_occurrences": 2}
        self.assertFalse(_matches(pattern, flows))


class TestBehaviorLibraryLoads(unittest.TestCase):
    """知识库本身必须能被加载出来（早期因目录名写错而静默为空）"""

    def test_default_path_loads_all_behaviors(self):
        matcher = BehaviorMatcher()
        self.assertGreaterEqual(len(matcher.rules), 8)
        ids = {r["id"] for r in matcher.rules}
        self.assertIn("heartbeat_beacon", ids)
        self.assertIn("bulk_upload", ids)


if __name__ == "__main__":
    unittest.main()
