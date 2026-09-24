"""
行为规则语义单测 —— 重点是「失败关闭」。

背景（2026-09-24 实测到的真实事故）：``behaviors.json`` 中有 5 条规则的证据键
（``destination_pattern`` / ``dns_rate_min`` / ``periodicity_threshold`` /
``min_connections`` / ``interval_min``）当时的判定函数**一个都不认**，被静默忽略后
直接返回 True —— 结果随便一条 60 字节的普通外联包，都能命中「疑似 C2 通信」
「疑似固件后门」这类 critical 规则，并建议 block_hard（把设备隔离进 IoT VLAN）。

这些用例把该行为钉死：
  · 普通流量不许命中任何规则；
  · 不认识的键 → 不命中；
  · 没有任何证据键的规则（恒真）→ 不命中，且不进 supported_rules；
  · 关键词必须落在域名标签边界上（否则 c2 会误伤 abc2.example.com）。
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from rule_engine.engine import (  # noqa: E402
    BehaviorMatcher,
    FlowRecord,
    EVIDENCE_KEYS,
    SUPPORTED_PATTERN_KEYS,
)
from analysis.alerting import TEMPLATE_KEYS, extract_placeholders  # noqa: E402

BEHAVIORS = SRC_DIR / "knowledge_base" / "behaviors.json"


def flows(
    count: int,
    *,
    t0: float = 1000.0,
    step: float = 1.0,
    size: int = 60,
    direction: str = "out",
    domain: str = None,
    dns: bool = False,
    port: int = 443,
    proto: str = "tcp",
    spread_dst: int = 1,
) -> list[FlowRecord]:
    """造一组观测。spread_dst>1 时把目的 IP 打散，用于「连了多少个目的地」类规则。"""
    out = []
    for i in range(count):
        out.append(
            FlowRecord(
                timestamp=t0 + i * step,
                src_ip="192.168.1.50",
                dst_ip=f"203.0.113.{1 + (i % spread_dst)}",
                dst_port=port,
                protocol=proto,
                sni=domain,
                dns_query=(domain if dns else None),
                packet_size=size,
                direction=direction,
            )
        )
    return out


def hit_ids(sample: list[FlowRecord]) -> set[str]:
    return {r["id"] for r in BehaviorMatcher().match(sample)}


class TestFailClosed(unittest.TestCase):
    """失败关闭：看不懂 / 没证据，就不许命中"""

    def test_a_single_ordinary_packet_matches_nothing(self):
        """一条最普通的外联包不许命中任何规则（曾命中 5 条，含 2 条 critical）"""
        self.assertEqual(hit_ids(flows(1, domain="example.com")), set())

    def test_normal_traffic_does_not_match_critical_rules(self):
        """正常上网流量不许触发 C2 / 后门 / DNS 隧道"""
        sample = flows(6, step=20, size=800, domain="www.example.com")
        self.assertNotIn("c2_beacon", hit_ids(sample))
        self.assertNotIn("firmware_backdoor", hit_ids(sample))
        self.assertNotIn("dns_tunneling", hit_ids(sample))
        self.assertNotIn("crypto_mining", hit_ids(sample))

    def test_unknown_pattern_key_never_matches(self):
        """认知不了的键一律拒绝 —— 宁可漏报，不能因为看不懂就放行"""
        matcher = BehaviorMatcher.__new__(BehaviorMatcher)
        sample = flows(10, step=30, size=60)
        self.assertFalse(matcher._matches(sample, {"direction": "out", "totally_new_key": 1}))

    def test_pattern_without_evidence_never_matches(self):
        """只有方向、没有任何证据键的规则是恒真的，不许命中"""
        matcher = BehaviorMatcher.__new__(BehaviorMatcher)
        sample = flows(50, step=1, size=60)
        self.assertFalse(matcher._matches(sample, {"direction": "out"}))
        self.assertFalse(matcher._matches(sample, {}))

    def test_degenerate_rule_is_excluded_from_supported(self):
        """退化规则不进 supported_rules，且原因要能被看见"""
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "b.json"
            path.write_text(
                json.dumps({
                    "always_true": {"name": "恒真", "pattern": {"direction": "out"}},
                    "unknown_key": {"name": "未知键", "pattern": {"direction": "out", "nope": 1}},
                    "good": {
                        "name": "正常", "pattern": {"direction": "out", "min_occurrences": 3},
                    },
                }, ensure_ascii=False),
                encoding="utf-8",
            )
            matcher = BehaviorMatcher(str(path))
            self.assertEqual([r["id"] for r in matcher.supported_rules], ["good"])
            reasons = {u["id"]: u["reason"] for u in matcher.unsupported()}
            self.assertIn("恒真", reasons["always_true"])
            self.assertIn("未知键", reasons["unknown_key"])


class TestKeywordBoundary(unittest.TestCase):
    """关键词必须落在域名标签边界上"""

    def test_legit_domains_containing_c2_are_not_flagged(self):
        for domain in ("abc2.example.com", "svc2-api.example.com", "proc2.example.net"):
            with self.subTest(domain=domain):
                self.assertNotIn("c2_beacon", hit_ids(flows(4, domain=domain)))

    def test_real_c2_naming_is_flagged(self):
        for domain in ("c2.botnet.example.org", "mirai.xip.io", "mozi.example.net"):
            with self.subTest(domain=domain):
                self.assertIn("c2_beacon", hit_ids(flows(4, domain=domain)))

    def test_backdoor_keywords(self):
        self.assertIn("firmware_backdoor", hit_ids(flows(4, domain="backdoor.example.net")))
        self.assertNotIn("firmware_backdoor", hit_ids(flows(4, domain="backdoorsafe.example.com")))


class TestEachRuleFires(unittest.TestCase):
    """8 条规则各有一个能真正命中的样本 —— 防止规则变成死代码"""

    def test_heartbeat_beacon(self):
        self.assertIn("heartbeat_beacon",
                      hit_ids(flows(12, step=30, size=60, domain="track.example.com")))

    def test_heartbeat_needs_steady_interval(self):
        """间隔里混进一次 15 分钟的空档，就不再是稳定心跳"""
        irregular = flows(8, step=30, size=60, domain="t.example.com")
        irregular[3] = FlowRecord(timestamp=irregular[3].timestamp + 900, src_ip="192.168.1.50",
                                  dst_ip="203.0.113.1", dst_port=443, protocol="tcp",
                                  sni="t.example.com", packet_size=60, direction="out")
        ordered = sorted(irregular, key=lambda f: f.timestamp)
        self.assertNotIn("heartbeat_beacon", hit_ids(ordered))

    def test_bulk_upload(self):
        self.assertIn("bulk_upload",
                      hit_ids(flows(10, step=10, size=200_000, domain="up.example.com")))

    def test_bulk_upload_needs_real_volume(self):
        self.assertNotIn("bulk_upload",
                         hit_ids(flows(10, step=10, size=100, domain="up.example.com")))

    def test_periodic_activity(self):
        self.assertIn("periodic_activity",
                      hit_ids(flows(10, step=600, size=300, domain="a.example.com")))

    def test_periodic_activity_rejects_noisy_traffic(self):
        # 间隔忽快忽慢，落在 5~60 分钟区间的比例远低于 0.8
        self.assertNotIn("periodic_activity",
                         hit_ids(flows(10, step=30, size=300, domain="a.example.com")))

    def test_lateral_mdns_scan(self):
        self.assertIn("lateral_mdns_scan",
                      hit_ids(flows(25, step=2, size=90, port=5353, proto="udp",
                                    domain=None)))

    def test_mdns_requires_the_right_port(self):
        self.assertNotIn("lateral_mdns_scan",
                         hit_ids(flows(25, step=2, size=90, port=443, proto="udp")))

    def test_dns_tunneling_by_long_label(self):
        long_domain = "a" * 58 + ".exfil.example.net"
        self.assertIn("dns_tunneling",
                      hit_ids(flows(8, step=0.2, size=0, dns=True, domain=long_domain, port=53,
                                    proto="udp")))

    def test_dns_tunneling_by_high_rate(self):
        self.assertIn("dns_tunneling",
                      hit_ids(flows(30, step=0.05, size=0, dns=True,
                                    domain="a.example.com", port=53, proto="udp")))

    def test_normal_dns_is_not_tunneling(self):
        self.assertNotIn("dns_tunneling",
                         hit_ids(flows(8, step=8, size=0, dns=True,
                                       domain="www.example.com", port=53, proto="udp")))

    def test_crypto_mining(self):
        self.assertIn("crypto_mining",
                      hit_ids(flows(25, step=1, size=500, domain="eth.pool.example.com",
                                    spread_dst=4)))

    def test_mining_needs_pool_keywords(self):
        self.assertNotIn("crypto_mining",
                         hit_ids(flows(25, step=1, size=500, domain="api.example.com",
                                       spread_dst=4)))


class TestShippedLibraryHealth(unittest.TestCase):
    """随库发布的行为库必须是健康的"""

    def setUp(self):
        self.matcher = BehaviorMatcher()

    def test_no_unsupported_rules(self):
        """规则腐化（用了引擎不认的键）必须在这里暴露，而不是静默误报"""
        self.assertEqual(self.matcher.unsupported(), [])

    def test_every_rule_has_required_fields(self):
        for rule in self.matcher.supported_rules:
            with self.subTest(rule=rule["id"]):
                for field in ("name", "severity", "category", "confidence", "action",
                              "explanation", "side_effects", "scope", "window_seconds"):
                    self.assertTrue(rule.get(field), f"{rule['id']} 缺字段 {field}")
                self.assertIn(rule["severity"], {"critical", "high", "medium", "low"})
                self.assertIn(rule["scope"], {"device", "destination"})
                self.assertGreater(float(rule["window_seconds"]), 0)

    def test_explanations_only_use_renderable_placeholders(self):
        """文案里不许出现渲染器填不出的占位符（否则界面上会露出 {device_name}）"""
        for rule in self.matcher.supported_rules:
            with self.subTest(rule=rule["id"]):
                unknown = set(extract_placeholders(rule["explanation"])) - TEMPLATE_KEYS
                self.assertEqual(unknown, set(), f"{rule['id']} 用了未知占位符 {unknown}")

    def test_every_rule_uses_only_supported_pattern_keys(self):
        data = json.loads(BEHAVIORS.read_text(encoding="utf-8"))
        for rid, rule in data.items():
            if rid.startswith("_"):
                continue
            with self.subTest(rule=rid):
                keys = set((rule.get("pattern") or {}).keys())
                self.assertTrue(keys <= SUPPORTED_PATTERN_KEYS,
                                f"{rid} 用了不支持的键 {keys - SUPPORTED_PATTERN_KEYS}")
                self.assertTrue(keys & EVIDENCE_KEYS, f"{rid} 没有任何证据键")

    def test_all_eight_behaviors_present(self):
        self.assertEqual(len(self.matcher.supported_rules), 8)


if __name__ == "__main__":
    unittest.main()
