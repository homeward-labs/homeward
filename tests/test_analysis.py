"""
分析层单测：ingest（观测转换）/ behavior（窗口与粒度）/ alerting（中文告警与收敛）
"""

import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from adapters.base import Observation  # noqa: E402
from rule_engine.engine import BehaviorMatcher, FlowRecord  # noqa: E402
from analysis.ingest import observation_to_flow, observations_to_flows  # noqa: E402
from analysis.behavior import BehaviorDetector, BehaviorFinding, summarize  # noqa: E402
from analysis.alerting import (  # noqa: E402
    AlertCenter,
    AlertRenderer,
    TEMPLATE_KEYS,
    build_context,
    extract_placeholders,
)


def mkflow(ts, *, src="192.168.1.50", dst="203.0.113.1", port=443, proto="tcp",
           sni=None, dns=None, size=60, direction="out") -> FlowRecord:
    return FlowRecord(timestamp=ts, src_ip=src, dst_ip=dst, dst_port=port, protocol=proto,
                      sni=sni, dns_query=dns, packet_size=size, direction=direction)


# ============================================================================ ingest

class TestObservationToFlow(unittest.TestCase):
    """采集层 → 规则层的转换（W1 到 W2 之间原本断掉的一截）"""

    def test_dns_observation(self):
        obs = Observation(timestamp=1000.0, kind="dns", device_id="192.168.1.50",
                          fields={"domain": "api.example.com.", "client_ip": "192.168.1.50"})
        flow = observation_to_flow(obs)
        self.assertIsNotNone(flow)
        self.assertEqual(flow.dns_query, "api.example.com")   # 结尾的点要去掉
        self.assertEqual(flow.dst_port, 53)
        self.assertEqual(flow.direction, "out")
        self.assertEqual(flow.packet_size, 0)  # DNS 日志没有字节数，不编造

    def test_outbound_flow(self):
        obs = Observation(timestamp=1000.0, kind="flow", device_id="192.168.1.50",
                          fields={"proto": "tcp", "src_ip": "192.168.1.50",
                                  "dst_ip": "8.8.8.8", "dst_port": 443, "bytes": 1200})
        flow = observation_to_flow(obs)
        self.assertEqual(flow.direction, "out")
        self.assertEqual(flow.packet_size, 1200)
        self.assertEqual(flow.protocol, "tcp")

    def test_inbound_flow(self):
        obs = Observation(timestamp=1000.0, kind="flow", device_id="192.168.1.50",
                          fields={"proto": "tcp", "src_ip": "8.8.8.8",
                                  "dst_ip": "192.168.1.50", "dst_port": 443, "bytes": 300})
        self.assertEqual(observation_to_flow(obs).direction, "in")

    def test_lan_internal_counts_as_out(self):
        """局域网内部互访（含 mDNS 组播）以源端为主体，记 out"""
        obs = Observation(timestamp=1000.0, kind="flow", device_id="192.168.1.50",
                          fields={"proto": "udp", "src_ip": "192.168.1.50",
                                  "dst_ip": "224.0.0.251", "dst_port": 5353, "bytes": 90})
        self.assertEqual(observation_to_flow(obs).direction, "out")

    def test_unknown_kind_and_missing_fields_return_none(self):
        self.assertIsNone(observation_to_flow(Observation(timestamp=1.0, kind="timing")))
        self.assertIsNone(observation_to_flow(
            Observation(timestamp=1.0, kind="dns", fields={"domain": "a.com"})))

    def test_batch_skips_unconvertible(self):
        batch = [
            Observation(timestamp=1.0, kind="dns",
                        fields={"domain": "a.com", "client_ip": "192.168.1.5"}),
            Observation(timestamp=1.0, kind="timing", fields={}),
        ]
        self.assertEqual(len(observations_to_flows(batch)), 1)


# ============================================================================ behavior

class TestSummarize(unittest.TestCase):
    """证据数字必须可复核"""

    def test_metrics(self):
        sample = [mkflow(1000.0 + i * 30, sni="t.example.com", size=60) for i in range(5)]
        ev = summarize(sample)
        self.assertEqual(ev["occurrences"], 5)
        self.assertEqual(ev["total_bytes"], 300)
        self.assertEqual(ev["avg_packet"], 60.0)
        self.assertEqual(ev["avg_interval_seconds"], 30.0)
        self.assertEqual(ev["span_seconds"], 120.0)
        self.assertEqual(ev["distinct_connections"], 1)
        self.assertEqual(ev["start_ts"], 1000.0)
        self.assertEqual(ev["end_ts"], 1120.0)

    def test_dns_metrics(self):
        sample = [mkflow(1000.0 + i * 0.5, dns="a.example.com", port=53, proto="udp", size=0)
                  for i in range(6)]
        ev = summarize(sample)
        self.assertEqual(ev["dns_queries"], 6)
        self.assertAlmostEqual(ev["dns_rate"], 6 / 2.5, places=3)
        self.assertEqual(ev["longest_label"], 7)  # a / example / com 里最长的是 example

    def test_empty(self):
        self.assertEqual(summarize([]), {})


class TestDetectorWindow(unittest.TestCase):
    """窗口由规则声明，观测超出窗口就不参与判定"""

    def _heartbeat(self, t0=1000.0):
        return [mkflow(t0 + i * 30, sni="track.example.com", size=60) for i in range(12)]

    def test_finding_inside_window(self):
        det = BehaviorDetector()
        det.feed_many(self._heartbeat())
        findings = det.scan(now=1000.0 + 11 * 30)
        ids = {f.rule_id for f in findings}
        self.assertIn("heartbeat_beacon", ids)

    def test_same_observations_outside_window_produce_nothing(self):
        """窗口是 1800 秒，一小时后再扫就不该再提这件事"""
        det = BehaviorDetector()
        det.feed_many(self._heartbeat())
        self.assertEqual(det.scan(now=1000.0 + 11 * 30 + 10000), [])

    def test_destination_scope_key(self):
        det = BehaviorDetector()
        det.feed_many(self._heartbeat())
        self.assertIn(("192.168.1.50", "track.example.com"), det.dest_flows)
        self.assertIn("192.168.1.50", det.device_flows)

    def test_finding_carries_evidence(self):
        det = BehaviorDetector()
        det.feed_many(self._heartbeat())
        findings = det.scan(now=1000.0 + 11 * 30)
        beat = next(f for f in findings if f.rule_id == "heartbeat_beacon")
        self.assertEqual(beat.evidence["occurrences"], 12)
        self.assertEqual(beat.evidence["total_bytes"], 720)
        self.assertEqual(beat.domain, "track.example.com")
        self.assertEqual(beat.scope, "destination")

    def test_retention_prunes_old_records(self):
        det = BehaviorDetector()
        det.feed(mkflow(0.0, sni="old.example.com"))
        det.feed(mkflow(100_000.0, sni="new.example.com"), now=100_000.0)
        self.assertEqual(len(det.device_flows["192.168.1.50"]), 1)

    def test_no_source_ip_is_dropped(self):
        det = BehaviorDetector()
        det.feed(mkflow(1000.0, src=""))
        self.assertEqual(det.stats["fed"], 0)


# ============================================================================ alerting

def _finding(rule_id="heartbeat_beacon", severity="low", src="192.168.1.50",
             domain="track.example.com", **ev) -> BehaviorFinding:
    base = {"occurrences": 12, "total_bytes": 720, "avg_packet": 60.0,
            "span_seconds": 330.0, "avg_interval_seconds": 30.0,
            "start_ts": 1000.0, "end_ts": 1330.0, "longest_label": 6,
            "dns_queries": 0, "dns_rate": 0.0, "distinct_connections": 1}
    base.update(ev)
    return BehaviorFinding(
        rule_id=rule_id, rule_name=rule_id, severity=severity, category="telemetry",
        confidence="medium", action="warn", scope="destination", src_ip=src,
        destination=domain, domain=domain, window_seconds=1800.0,
        start_ts=base["start_ts"], end_ts=base["end_ts"], evidence=base,
    )


class TestRenderContext(unittest.TestCase):
    """渲染上下文必须覆盖模板能用到的全部键"""

    def test_context_covers_all_template_keys(self):
        ctx = build_context(_finding(), {"name": "卧室摄像头"}, {"organization": "涂鸦"})
        self.assertTrue(TEMPLATE_KEYS.issubset(set(ctx)))

    def test_device_and_organization_fall_back_gracefully(self):
        ctx = build_context(_finding())
        self.assertEqual(ctx["device_name"], "192.168.1.50")  # 没有设备名就退回 IP
        self.assertEqual(ctx["organization"], "未识别")

    def test_shipped_templates_render_without_missing_keys(self):
        """每条随库文案都要能完整渲染 —— 界面上绝不能露出 {xxx}"""
        matcher = BehaviorMatcher()
        renderer = AlertRenderer()
        for rule in matcher.supported_rules:
            with self.subTest(rule=rule["id"]):
                ctx = build_context(
                    _finding(rule_id=rule["id"]),
                    {"name": "卧室摄像头", "vendor": "小米", "device_type": "camera"},
                    {"organization": "示例组织"},
                )
                text, missing = renderer.render(rule["explanation"], ctx)
                self.assertEqual(missing, [])
                self.assertNotIn("{", text)
                self.assertNotIn("}", text)

    def test_unknown_placeholder_is_visible_not_silent(self):
        text, missing = AlertRenderer().render("设备 {device_name} / {nope}", {"device_name": "X"})
        self.assertEqual(missing, ["nope"])
        self.assertIn("nope", text)  # 宁可难看，也不能静默丢掉

    def test_extract_placeholders(self):
        self.assertEqual(extract_placeholders("{a} 和 {b}"), ["a", "b"])


class TestAlertCenter(unittest.TestCase):
    """告警收敛：同一件事只占一条"""

    def _rule_of(self, rule_id):
        for r in BehaviorMatcher().supported_rules:
            if r["id"] == rule_id:
                return r
        return {}

    def test_repeat_hit_does_not_create_new_alert(self):
        center = AlertCenter()
        created = center.ingest([_finding()], rule_of=self._rule_of, now=1000.0)
        self.assertEqual(len(created), 1)
        again = center.ingest([_finding()], rule_of=self._rule_of, now=1060.0)
        self.assertEqual(again, [])
        self.assertEqual(len(center.active()), 1)
        self.assertEqual(center.stats["updated"], 1)

    def test_episode_increments_after_cooldown(self):
        center = AlertCenter(cooldown_seconds=1800.0)
        center.ingest([_finding()], rule_of=self._rule_of, now=1000.0)
        center.ingest([_finding()], rule_of=self._rule_of, now=1000.0 + 3600)
        alert = center.active()[0]
        self.assertEqual(alert.episodes, 2)
        self.assertEqual(len(center.active()), 1)

    def test_different_destinations_are_separate_alerts(self):
        center = AlertCenter()
        center.ingest([_finding(domain="a.example.com"), _finding(domain="b.example.com")],
                      rule_of=self._rule_of, now=1000.0)
        self.assertEqual(len(center.active()), 2)

    def test_sorted_by_severity_then_recency(self):
        center = AlertCenter()
        center.ingest([
            _finding(rule_id="heartbeat_beacon", severity="low", domain="a.example.com"),
            _finding(rule_id="bulk_upload", severity="high", domain="b.example.com"),
        ], rule_of=self._rule_of, now=1000.0)
        self.assertEqual([a.severity for a in center.active()], ["high", "low"])

    def test_dismiss(self):
        center = AlertCenter()
        created = center.ingest([_finding()], rule_of=self._rule_of, now=1000.0)
        self.assertTrue(center.dismiss(created[0].alert_id))
        self.assertEqual(center.active(), [])
        self.assertEqual(len(center.all()), 1)

    def test_side_effects_are_always_present(self):
        """「点了之后会怎样」是必填项 —— 没有就给兜底，不能空着"""
        center = AlertCenter()
        created = center.ingest([_finding()], rule_of=lambda rid: {}, now=1000.0)
        self.assertTrue(created[0].side_effects)

    def test_counts_by_severity(self):
        center = AlertCenter()
        center.ingest([_finding(severity="high", domain="b.example.com")],
                      rule_of=self._rule_of, now=1000.0)
        self.assertEqual(center.counts_by_severity()["high"], 1)

    def test_to_dict_is_json_ready(self):
        center = AlertCenter()
        center.ingest([_finding()], rule_of=self._rule_of, now=1000.0)
        payload = center.to_dict()[0]
        for key in ("alert_id", "title", "summary", "severity_label", "action_label",
                    "device_name", "organization", "evidence"):
            self.assertIn(key, payload)


if __name__ == "__main__":
    unittest.main()
