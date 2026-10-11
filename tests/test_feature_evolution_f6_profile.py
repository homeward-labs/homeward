"""
F6（设备画像 / 风险分级）：把「哪台设备最值得看一眼」算出来，且每档风险都可追溯。

真机诊断（iStoreOS 192.168.1.254，宿主网络模式容器）得出的两条事实驱动本轮设计：
· 容器以 network_mode: host 运行，/proc/net/arp **可见且含真实 MAC** —— 所以
  厂商识别不是"没有数据源"，而是"OUI 精简表覆盖不到 + 随机 MAC 查不到"；
· 7 台在网设备里 3 台是随机 MAC（手机/平板的隐私保护地址），查厂商必然失败。
  若 UI 只显示"未知厂商"，用户会以为家卫没查到 —— 因此必须单独识别并明示。

本测试覆盖：
1) is_random_mac 的判定（U/L 位）与随机 MAC 的盲区明示；
2) assess_risk 各条规则的阈值与小样本保护（样本不足不下结论 = 不猜）；
3) build_profiles 的聚合、排序与告警归属。

仅用文档保留段 / RFC 5737 示例 IP 与示例 MAC，不含任何真实设备数据。
"""
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from inventory.device import (  # noqa: E402
    DeviceRegistry, Device, is_random_mac, normalize_mac,
)
from analysis.profiler import assess_risk, build_profiles  # noqa: E402


# 随机 MAC：第一字节 U/L 位置 1（示例值，非真实设备）
RANDOM_MACS = ("72:13:49:ac:e0:ed", "0e:9c:07:38:f4:6c", "82:eb:55:a1:d9:81")
# 真实 OUI：U/L 位为 0（示例值）
REAL_MACS = ("1c:1b:0d:c7:56:39", "8c:8e:0d:5e:25:92", "00:90:4c:0f:f2:a7")

ARP_HEADER = "IP address       HW type     Flags       HW address            Mask     Device"


class RandomMacTest(unittest.TestCase):
    """随机 MAC 判定：这是"查不到厂商"的**原因**，必须能被识别出来"""

    def test_random_mac_detected(self):
        for m in RANDOM_MACS:
            self.assertTrue(is_random_mac(m), f"{m} 应为随机 MAC")

    def test_real_oui_not_random(self):
        for m in REAL_MACS:
            self.assertFalse(is_random_mac(m), f"{m} 应为真实 OUI")

    def test_invalid_mac_is_false(self):
        # 非法输入返回 False：不因为解析失败就把它标成随机 MAC
        for bad in ("", "zz:zz:zz", "abc", None):
            self.assertFalse(is_random_mac(bad))

    def test_arp_load_flags_random_mac(self):
        lines = [ARP_HEADER]
        for i, m in enumerate(RANDOM_MACS):
            lines.append(f"192.0.2.{10 + i}    0x1         0x2         {m}     *        br-lan")
        reg = DeviceRegistry(oui_table={})
        reg.load_arp("\n".join(lines))
        flagged = [d for d in reg.devices.values() if d.random_mac]
        self.assertEqual(len(flagged), len(RANDOM_MACS))
        # 随机 MAC 查不到厂商是必然结果，vendor 必须保持 None（不猜）
        self.assertTrue(all(d.vendor is None for d in flagged))

    def test_blind_spot_states_random_mac(self):
        lines = [ARP_HEADER,
                 "192.0.2.10    0x1         0x2         72:13:49:ac:e0:ed     *        br-lan"]
        reg = DeviceRegistry(oui_table={})
        reg.load_arp("\n".join(lines))
        spots = reg.blind_spots()
        self.assertTrue(any("随机 MAC" in s for s in spots),
                        "随机 MAC 必须作为盲区明示，不能只显示「未知厂商」")

    def test_random_mac_exposed_in_view(self):
        d = Device(key="72:13:49:ac:e0:ed", mac="72:13:49:ac:e0:ed")
        d.random_mac = True
        self.assertTrue(d.to_dict()["random_mac"])


class AssessRiskTest(unittest.TestCase):
    """风险规则：每条都要有依据，且小样本不下结论"""

    def test_no_signal_is_low(self):
        level, reasons = assess_risk(
            observations=0, known_count=0, unknown_count=0,
            categories={}, alerts=[])
        self.assertEqual(level, "low")
        self.assertEqual(reasons, [])

    def test_mining_is_high(self):
        level, reasons = assess_risk(
            observations=5, known_count=1, unknown_count=0,
            categories={"crypto_mining": 5}, alerts=[])
        self.assertEqual(level, "high")
        self.assertTrue(any("挖矿" in r for r in reasons))

    def test_high_alert_is_high(self):
        level, reasons = assess_risk(
            observations=100, known_count=3, unknown_count=0,
            categories={}, alerts=[{"severity": "high", "title": "定时外联"}])
        self.assertEqual(level, "high")
        self.assertTrue(any("定时外联" in r for r in reasons))

    def test_medium_alert_is_medium(self):
        level, reasons = assess_risk(
            observations=100, known_count=3, unknown_count=0,
            categories={}, alerts=[{"severity": "medium", "title": "疑似批量上传"}])
        self.assertEqual(level, "medium")
        self.assertTrue(any("疑似批量上传" in r for r in reasons))

    def test_tracking_ratio_over_threshold(self):
        level, reasons = assess_risk(
            observations=100, known_count=5, unknown_count=0,
            categories={"tracker": 40, "cdn": 60}, alerts=[])
        self.assertEqual(level, "medium")
        self.assertTrue(any("追踪" in r for r in reasons))

    def test_small_sample_not_concluded(self):
        """只问了 3 次 DNS 就判"被追踪"等于瞎猜 —— 样本不足必须保持 low"""
        level, reasons = assess_risk(
            observations=3, known_count=1, unknown_count=0,
            categories={"tracker": 3}, alerts=[])
        self.assertEqual(level, "low")
        self.assertEqual(reasons, [])

    def test_unknown_ratio_over_threshold(self):
        level, reasons = assess_risk(
            observations=50, known_count=1, unknown_count=9,
            categories={"cdn": 50}, alerts=[])
        self.assertEqual(level, "medium")
        self.assertTrue(any("查不到归属" in r for r in reasons))

    def test_high_not_downgraded_by_medium_rule(self):
        """等级只升不降：高危设备不会因为"追踪占比没到线"被抹掉理由"""
        level, reasons = assess_risk(
            observations=100, known_count=5, unknown_count=0,
            categories={"crypto_mining": 2},
            alerts=[{"severity": "medium", "title": "疑似批量上传"}])
        self.assertEqual(level, "high")
        self.assertTrue(any("挖矿" in r for r in reasons))
        self.assertTrue(any("疑似批量上传" in r for r in reasons))


# ---------------------------------------------------------------- 画像聚合

@dataclass
class _FakeResult:
    known: bool
    category: str


class _FakeDev:
    """够画像层用的最小设备替身（不需要真实 OUI / ARP）"""

    def __init__(self, key, domains, ips, name=None, mac=None, random_mac=False):
        self.key = key
        self.domains = domains
        self.ips = set(ips)
        self.mac = mac
        self.random_mac = random_mac
        self.vendor = None
        self.vendor_cn = None
        self.device_type = "unknown"
        self.type_source = "none"
        self.first_seen = 0.0
        self.last_seen = 0.0
        self._name = name

    @property
    def display_name(self):
        return self._name or self.key

    def top_domains(self, n=5):
        items = sorted(self.domains.items(), key=lambda kv: (-kv[1], kv[0]))
        return items[:n]


class BuildProfilesTest(unittest.TestCase):
    def _resolve(self, mapping):
        return lambda d: _FakeResult(*mapping.get(d, (False, "unknown")))

    def test_aggregates_counts_and_categories(self):
        dev = _FakeDev("d1", {"a.example.net": 30, "b.example.net": 10}, ["192.0.2.10"])
        resolve = self._resolve({
            "a.example.net": (True, "tracker"),
            "b.example.net": (False, "unknown"),
        })
        profiles = build_profiles([dev], resolve)
        self.assertEqual(len(profiles), 1)
        p = profiles[0]
        self.assertEqual(p.observations, 40)
        self.assertEqual(p.known_count, 1)
        self.assertEqual(p.unknown_count, 1)
        self.assertEqual(p.categories, {"tracker": 30})

    def test_category_case_normalized(self):
        """知识库里 iot_core / IoT_core 混写，画像必须归并成一类"""
        dev = _FakeDev("d1", {"x.example.net": 5}, ["192.0.2.10"])
        profiles = build_profiles([dev], self._resolve({"x.example.net": (True, "IoT_core")}))
        self.assertEqual(profiles[0].categories, {"iot_core": 5})

    def test_high_risk_sorted_first(self):
        quiet = _FakeDev("quiet", {"c.example.net": 1}, ["192.0.2.11"])
        noisy = _FakeDev("noisy", {"m.example.net": 9}, ["192.0.2.12"])
        resolve = self._resolve({
            "c.example.net": (True, "cdn"),
            "m.example.net": (True, "crypto_mining"),
        })
        profiles = build_profiles([quiet, noisy], resolve)
        self.assertEqual(profiles[0].key, "noisy")
        self.assertEqual(profiles[0].risk_level, "high")
        self.assertEqual(profiles[1].risk_level, "low")

    def test_alerts_attach_by_ip(self):
        dev = _FakeDev("d1", {"a.example.net": 5}, ["192.0.2.10"])
        alerts = [
            {"device_ip": "192.0.2.10", "severity": "high", "title": "定时外联",
             "rule_id": "beacon", "severity_label": "高危", "summary": "..."},
            {"device_ip": "192.0.2.99", "severity": "high", "title": "不该算到我这",
             "rule_id": "beacon", "severity_label": "高危", "summary": "..."},
        ]
        profiles = build_profiles([dev], self._resolve({"a.example.net": (True, "cdn")}),
                                  alerts)
        self.assertEqual(len(profiles[0].alerts), 1)
        self.assertEqual(profiles[0].alerts[0]["title"], "定时外联")
        self.assertEqual(profiles[0].risk_level, "high")

    def test_random_mac_surfaces_in_profile(self):
        dev = _FakeDev("d1", {}, ["192.0.2.10"], mac="72:13:49:ac:e0:ed", random_mac=True)
        profiles = build_profiles([dev], self._resolve({}))
        self.assertTrue(profiles[0].random_mac)
        self.assertTrue(profiles[0].to_dict()["random_mac"])


class RealMachineMacTest(unittest.TestCase):
    """把真机那批 MAC 的性质固定下来：3 台随机 + 4 台真实 OUI（示例化后的同型值）"""

    def test_u_l_bit_rule(self):
        # 随机 MAC 的第一字节：0x72 / 0x0e / 0x82 → (b >> 1) & 1 == 1
        for mac in RANDOM_MACS:
            first = int(normalize_mac(mac).split(":")[0], 16)
            self.assertEqual((first >> 1) & 1, 1)
        for mac in REAL_MACS:
            first = int(normalize_mac(mac).split(":")[0], 16)
            self.assertEqual((first >> 1) & 1, 0)


if __name__ == "__main__":
    unittest.main()
