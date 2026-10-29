"""
F6（设备画像入口）：本机身份信号。

Phase A 故意遗留的两个误报/去噪残留，根因都是「缺本机身份信号」：
- F1 残留：宿主自身 LAN IP（如 192.168.1.254）没并进「本机」设备，单独成一台；
- F2 残留：宿主自身系统更新/telemetry（如 254 → 35.212.246.40）被判 high。

本测试验证：用 self_ips 声明「哪些 IP 是家卫宿主自身」后，
1) 这些 IP 的观测归并到「本机」设备（不再单独建档）；
2) 这些 IP 作为源的高流量上传在告警层降级（不当数据外泄）；
3) 非宿主设备不受影响（不误降级）。

仅用文档保留段 / 公开域名与示例 IP，不含任何真实 MAC/凭证。
"""
import sys
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from rule_engine.engine import FlowRecord, KnowledgeBase  # noqa: E402
from analysis.behavior import BehaviorDetector  # noqa: E402
from analysis.alerting import AlertCenter  # noqa: E402
from inventory.device import DeviceRegistry, _SELF_DEVICE_KEY  # noqa: E402

# 真实 behaviors.json 已闭源、不进公开仓；CI 中缺该文件时，依赖真实规则库的测试跳过。
_REAL_BEHAVIORS = SRC_DIR / "knowledge_base" / "behaviors.json"

BASE = 1700000000.0
SELF_IP = "192.168.1.254"
OTHER_IP = "192.0.2.10"
PUBLIC_IP_STR = "35.212.246.40"  # 示例公网 IP（Google 段，仅作占位）


def _bulk_flows(src, domain, dst_ip="203.0.113.9"):
    """模拟一次 70 秒、约 6.3MB 的单目的地上传（正常云备份 / 系统更新量级）"""
    return [FlowRecord(BASE + i, src, dst_ip, 443, "tcp",
                       sni=domain, dns_query=domain, packet_size=180000,
                       direction="out")
            for i in range(0, 70, 2)]


def _scan(src, domain):
    kb = KnowledgeBase()
    det = BehaviorDetector()
    det.feed_many(_bulk_flows(src, domain))
    return det.scan(now=BASE + 75)


class HostIdentityDeviceMergeTest(unittest.TestCase):
    def test_self_ip_merges_into_self_device(self):
        """宿主自身 LAN IP 的观测应归并到「本机」设备，不单独建档"""
        reg = DeviceRegistry(self_ips={SELF_IP})
        dev = reg.observe_ip(SELF_IP)
        self.assertEqual(dev.key, _SELF_DEVICE_KEY)
        self.assertEqual(dev.display_name, "本机（路由器自身）")
        others = [d for d in reg.list_devices() if d.key != _SELF_DEVICE_KEY]
        self.assertEqual(others, [], "宿主 IP 不应再单独成一台设备")

    def test_self_ip_lease_skipped(self):
        """DHCP 租约里出现宿主自身 IP 时，不应建为独立设备（普通设备仍正常建档）"""
        reg = DeviceRegistry(self_ips={SELF_IP})
        # 格式：<expiry> <mac> <ip> <hostname>（expiry 取 2100+ 视为永久、不过期）
        reg.load_leases(
            f"4102444801 00:11:22:33:44:55 {SELF_IP} host\n"
            "4102444801 aa:bb:cc:dd:ee:ff 192.168.1.99 phone"
        )
        self.assertNotIn("00:11:22:33:44:55", reg.devices,
                         "宿主 IP 的租约不应单独建档")
        self.assertIn("aa:bb:cc:dd:ee:ff", reg.devices, "普通设备仍应正常建档")
        self.assertIn("192.168.1.99", reg.devices["aa:bb:cc:dd:ee:ff"].ips)

    def test_self_ip_arp_skipped(self):
        """ARP 表里出现宿主自身 IP 时，不应建为独立设备（其它设备仍正常建档）"""
        reg = DeviceRegistry(self_ips={SELF_IP})
        # /proc/net/arp 真实格式：首行是表头（parse_arp_table 会跳过），之后每行
        # <ip> <hw_type> <flags> <mac> <mask> <device>
        reg.load_arp(
            "IP address  HW type  Flags  HW address  Mask  Device\n"
            "192.168.1.99 0x1 0x2 00:11:22:33:44:66 * eth0\n"
            f"{SELF_IP} 0x1 0x2 00:11:22:33:44:55 * eth0"
        )
        self.assertNotIn("00:11:22:33:44:55", reg.devices,
                         "宿主 IP 的 ARP 不应单独建档")
        # 其它真实设备仍正常建档
        self.assertIn("00:11:22:33:44:66", reg.devices)

    def test_is_self_ip_helper(self):
        reg = DeviceRegistry(self_ips={SELF_IP})
        self.assertTrue(reg.is_self_ip(SELF_IP))
        self.assertFalse(reg.is_self_ip(OTHER_IP))


@unittest.skipUnless(_REAL_BEHAVIORS.is_file(), "需要真实 behaviors.json（闭源，CI 中跳过；本地有数据时才跑）")
class HostIdentityAlertDowngradeTest(unittest.TestCase):
    def test_self_bulk_upload_downgraded(self):
        """源是宿主自身、目的地是未知公网 IP 的大流量上传应降级（不当外泄）"""
        findings = _scan(SELF_IP, PUBLIC_IP_STR)
        center = AlertCenter()
        alerts = center.ingest(
            findings,
            attribution_of=lambda d: {},
            is_self_ip=lambda ip: ip == SELF_IP,
        )
        self.assertTrue(alerts, "应产生告警")
        for a in alerts:
            self.assertEqual(a.rule_id, "bulk_upload")
            self.assertEqual(a.severity, "low",
                             "宿主自身的大流量上传应降级为 low")
            self.assertEqual(a.suggested_action, "warn")

    def test_non_self_bulk_upload_stays_high(self):
        """非宿主设备、目的地未知公网 IP 的大流量上传必须保持高危（不误降级）"""
        findings = _scan(OTHER_IP, PUBLIC_IP_STR)
        center = AlertCenter()
        alerts = center.ingest(
            findings,
            attribution_of=lambda d: {},
            is_self_ip=lambda ip: ip == SELF_IP,  # OTHER_IP 不是宿主
        )
        self.assertTrue(alerts)
        for a in alerts:
            self.assertEqual(a.severity, "high",
                             "非宿主设备的公网大流量上传应保持高危")

    def test_self_ip_default_no_downgrade(self):
        """未传 is_self_ip 时，行为应与 Phase A 一致（不静默降级）"""
        findings = _scan(SELF_IP, PUBLIC_IP_STR)
        center = AlertCenter()
        alerts = center.ingest(findings, attribution_of=lambda d: {})
        self.assertTrue(alerts)
        for a in alerts:
            self.assertEqual(a.severity, "high",
                             "缺 is_self_ip 时不应降级（保持默认严格）")


class HostIdentityConfigWiringTest(unittest.TestCase):
    """配置 → 台账 的端到端接线（HOMEWARD_SELF_IPS 环境变量 / --self-ips 参数）"""

    def _svc(self, self_ips):
        from core.main import HomewardService
        return HomewardService(config={
            "load_system_devices": False,
            "homeward_self_ips": self_ips,
        })

    def test_config_parses_comma_separated(self):
        svc = self._svc("192.168.1.254, 10.0.0.1")
        self.assertTrue(svc.device_registry.is_self_ip("192.168.1.254"))
        self.assertTrue(svc.device_registry.is_self_ip("10.0.0.1"))
        self.assertFalse(svc.device_registry.is_self_ip("192.168.1.50"))

    def test_self_ip_not_counted_as_device(self):
        svc = self._svc(SELF_IP)
        svc.device_registry.observe_ip(SELF_IP)
        svc.device_registry.observe_ip("192.168.1.50")
        keys = {d.key for d in svc.device_registry.list_devices()}
        self.assertNotIn(SELF_IP, keys, "宿主 IP 不应单独成台设备")
        self.assertIn(_SELF_DEVICE_KEY, keys, "宿主 IP 应归并到本机设备")
        self.assertIn("192.168.1.50", keys, "真实设备仍正常建档")


if __name__ == "__main__":
    unittest.main()
