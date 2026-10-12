"""
方案 B 回归测试：bulk_upload 未知公网流量按形态分级。

背景：153（用户单位本机）的正常上行（代码同步/云盘/视频会议）被 bulk_upload 判 high，
属「未知公网 fail-closed」设计取舍带来的噪声。方案 B 不靠信任豁免，而是用流量形状把
未知公网大流量分成两类：

  · routine（单终点·持续·大包，像云同步/备份/串流）→ 低危 + 常规大流量诚实文案（声明弱证据）
  · suspicious（突发/碎包/不规则）→ 保持高危（更像泄露）

同时守住原逻辑：内网控制流量 / 良性大流量类别 / 宿主自身 → 低危。
"""

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analysis.alerting import AlertCenter, TEMPLATE_KEYS, extract_placeholders  # noqa: E402
from analysis.behavior import BehaviorFinding  # noqa: E402

WINDOW = 600.0

BULK_RULE = {
    "id": "bulk_upload",
    "name": "突发大流量上传",
    "severity": "high",
    "category": "data_exfiltration",
    "confidence": "high",
    "action": "block_medium",
    "explanation": "（默认文案，本测试不依赖）",
    "explain_routine": (
        "设备 {device_name} 在 {start_time} 至 {end_time} 的 {duration_min} 分钟内，向 "
        "{destination}（{organization}）累计上传了约 {total_mb}MB（{occurrences} 次传输）。"
        "这条被判定为「常规大流量形态」：单终点、持续、大包，更像云同步/备份/视频串流这类正常行为，"
        "不是典型数据泄露。置信度低——仅凭流量形态无法排除单终点持续外传的可能，"
        "若你近期并未进行云同步、备份或视频通话等操作，仍建议核查该去向。"
    ),
    "side_effects": "阻断后该设备的云功能会失效",
    "scope": "destination",
    "window_seconds": WINDOW,
}


def _finding(evidence: dict, *, dest="203.0.113.9:443", src="192.168.1.153",
             domain=None) -> BehaviorFinding:
    return BehaviorFinding(
        rule_id="bulk_upload",
        rule_name="突发大流量上传",
        severity="high",          # 规则原始严重度，降级由 ingest 决定
        category="data_exfiltration",
        confidence="high",
        action="block_medium",
        scope="destination",
        src_ip=src,
        destination=dest,
        domain=domain,
        window_seconds=WINDOW,
        start_ts=evidence.get("start_ts", 0.0),
        end_ts=evidence.get("end_ts", 0.0),
        evidence=evidence,
    )


def _ingest_one(f, *, is_self_ip=None) -> list:
    center = AlertCenter()
    return center.ingest(
        [f],
        rule_of=lambda rid: BULK_RULE,
        is_self_ip=is_self_ip or (lambda ip: False),
    )


class TestBulkUploadGrade(unittest.TestCase):

    def test_routine_unknown_public_downgraded(self):
        """153 真实形态：大包、持续覆盖大半窗口、多次观测 → routine → 低危 + 常规文案"""
        ev = {
            "avg_packet": 2000.0, "span_seconds": 500.0, "occurrences": 30,
            "total_bytes": 60_000_000, "start_ts": 0.0, "end_ts": 500.0,
        }
        alerts = _ingest_one(_finding(ev, dest="113.240.76.236:443"))
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual(a.severity, "low")
        self.assertEqual(a.confidence, "low")
        self.assertEqual(a.suggested_action, "warn")
        self.assertIn("常规大流量", a.summary)
        self.assertIn("置信度低", a.summary)

    def test_suspicious_burst_stays_high(self):
        """突发、碎包、短跨度 → suspicious → 保持高危（注意：用真实公网 IP，文档段 IP 会被 is_private 误判内网）"""
        ev = {
            "avg_packet": 180.0, "span_seconds": 20.0, "occurrences": 12,
            "total_bytes": 2_000_000, "start_ts": 580.0, "end_ts": 600.0,
        }
        alerts = _ingest_one(_finding(ev, dest="8.8.8.8:4444"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "high")

    def test_large_packet_but_short_burst_stays_high(self):
        """大包但极短突发（不是持续）→ suspicious → 保持高危（用真实公网 IP）"""
        ev = {
            "avg_packet": 2000.0, "span_seconds": 5.0, "occurrences": 5,
            "total_bytes": 2_000_000, "start_ts": 595.0, "end_ts": 600.0,
        }
        alerts = _ingest_one(_finding(ev, dest="1.1.1.1:4444"))
        self.assertEqual(alerts[0].severity, "high")

    def test_internal_destination_still_low(self):
        """内网组播（SSDP）→ 原 benign 逻辑降级，与方案 B 无关"""
        ev = {
            "avg_packet": 200.0, "span_seconds": 100.0, "occurrences": 10,
            "total_bytes": 1_500_000, "start_ts": 0.0, "end_ts": 100.0,
        }
        alerts = _ingest_one(_finding(ev, dest="239.255.255.250:1900"))
        self.assertEqual(alerts[0].severity, "low")

    def test_self_ip_still_low(self):
        """宿主自身上行 → 降级"""
        ev = {
            "avg_packet": 2000.0, "span_seconds": 500.0, "occurrences": 30,
            "total_bytes": 60_000_000, "start_ts": 0.0, "end_ts": 500.0,
        }
        alerts = _ingest_one(
            _finding(ev, src="192.168.1.252"),
            is_self_ip=lambda ip: ip == "192.168.1.252",
        )
        self.assertEqual(alerts[0].severity, "low")

    def test_explain_routine_uses_only_renderable_placeholders(self):
        """常规大流量文案不许出现渲染器填不出的占位符（否则界面露出 {xxx}）"""
        unknown = set(extract_placeholders(BULK_RULE["explain_routine"])) - TEMPLATE_KEYS
        self.assertEqual(unknown, set())


if __name__ == "__main__":
    unittest.main()
