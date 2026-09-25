# -*- coding: utf-8 -*-
"""
W2 —— 设备发现 与 域名归属 的单元测试

两个原则贯穿本文件：
1. **全部可在 Windows 跑**。解析逻辑走纯函数 + fixture，不依赖 /proc、不依赖 Linux。
2. **锁住"不猜"这条红线**。凡是查不到信息的场景，断言必须是 None / unknown，
   而不是"看起来合理"的兜底值 —— 家卫识别错了比不识别更伤信任。
"""

import tempfile
import time
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from inventory import attribution, device


# ============================================================ 设备发现

MINI_OUI = (
    "# 测试用迷你表\n"
    "prefix,vendor,vendor_cn,device_hint\n"
    "aa:bb:cc,Hikvision Digital,海康威视,camera\n"
    "dd:ee:ff,Xiaomi Communications,小米,\n"
    "11:22:33,Roborock,石头科技,vacuum\n"
)

_NOW = int(time.time())
SOON_FN = _NOW + 3600      # 未来：有效租约
PAST_TS = _NOW - 100000    # 过去：已过期租约

# 租约时间戳必须动态生成 —— 写死无�̨定值的话，几年后 fixture 会整体过期，测试会全线崩
SAMPLE_LEASES = f"""\
{SOON_FN} aa:bb:cc:00:11:22 192.168.1.10 Bedroom-Cam 01:aa:bb:cc:00:11:22
{SOON_FN + 1} dd:ee:ff:00:00:01 192.168.1.11 Mi-Phone *
{SOON_FN + 2} ff:ff:ff:00:00:02 192.168.1.12 * 01:ff:ff:ff:00:00:02
zzz bad-mac-address 192.168.1.13 should-skip
{SOON_FN + 3}
{PAST_TS} aa:bb:cc:00:99:99 192.168.1.99 Old-Cam
"""

SAMPLE_ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.10     0x1         0x2         aa:bb:cc:00:11:22     *        br-lan
192.168.1.20     0x1         0x2         DD-EE-FF-00-00-20     *        br-lan
192.168.1.99     0x1         0x0         11:22:33:44:55:66     *        br-lan
192.168.1.98     0x1         0x2         00:00:00:00:00:00     *        br-lan
"""


class TestMacNormalization(unittest.TestCase):

    def test_various_formats(self):
        expect = "aa:bb:cc:00:11:22"
        for raw in ("AA:BB:CC:00:11:22", "aa-bb-cc-00-11-22",
                    "aabb.cc00.1122", "aabbcc001122"):
            with self.subTest(raw=raw):
                self.assertEqual(device.normalize_mac(raw), expect)

    def test_three_byte_prefix_supported(self):
        # OUI 表里的条目只有 3 字节；这部分若被判非法，厂商表就永远加载不出来
        self.assertEqual(device.normalize_mac("aa:bb:cc"), "aa:bb:cc")
        self.assertEqual(device.oui_of("aa:bb:cc"), "aa:bb:cc")

    def test_mask_suffix_stripped(self):
        # manuf 的 `AA:BB:CC/24` 写法：掩码必须剥掉，否则 24 会被当成一个字节
        self.assertEqual(device.normalize_mac("aa:bb:cc/24"), "aa:bb:cc")
        self.assertEqual(device.normalize_mac("aa:bb:cc:dd:ee:ff/28"),
                         "aa:bb:cc:dd:ee:ff")

    def test_invalid_returns_empty(self):
        for raw in ("", "nope", "aa:bb", "zz:zz:zz:zz:zz:zz"):
            with self.subTest(raw=raw):
                self.assertEqual(device.normalize_mac(raw), "")

    def test_oui_of(self):
        self.assertEqual(device.oui_of("aa:bb:cc:00:11:22"), "aa:bb:cc")
        self.assertEqual(device.oui_of("bad"), "")


class TestDhcpLeases(unittest.TestCase):

    def setUp(self):
        self.leases = device.parse_dhcp_leases(SAMPLE_LEASES)

    def test_parse_count_skips_bad_lines(self):
        # 5 行里：坏 MAC 1 行、字段不足 1 行被跳过，剩 4 条
        self.assertEqual(len(self.leases), 4)

    def test_mac_ip_hostname(self):
        first = self.leases[0]
        self.assertEqual(first.mac, "aa:bb:cc:00:11:22")
        self.assertEqual(first.ip, "192.168.1.10")
        self.assertEqual(first.hostname, "Bedroom-Cam")

    def test_missing_hostname_becomes_empty(self):
        self.assertEqual(self.leases[2].hostname, "")

    def test_expired_lease_detected(self):
        old = [l for l in self.leases if l.ip == "192.168.1.99"][0]
        self.assertTrue(old.expired)

    def test_fresh_lease_not_expired(self):
        self.assertFalse(self.leases[0].expired)

    def test_empty_input(self):
        self.assertEqual(device.parse_dhcp_leases(""), [])


class TestArpTable(unittest.TestCase):

    def setUp(self):
        self.table = device.parse_arp_table(SAMPLE_ARP)

    def test_valid_entries(self):
        self.assertEqual(self.table.get("192.168.1.10"), "aa:bb:cc:00:11:22")
        self.assertEqual(self.table.get("192.168.1.20"), "dd:ee:ff:00:00:20")

    def test_incomplete_entry_skipped(self):
        """Flags 0x0 = 邻居不可达，不可信"""
        self.assertNotIn("192.168.1.99", self.table)

    def test_all_zero_mac_skipped(self):
        self.assertNotIn("192.168.1.98", self.table)


class TestOuiLookup(unittest.TestCase):

    def setUp(self):
        self.table = device.parse_oui_table(MINI_OUI)

    def test_hint_entry_wins(self):
        v, cn, hint = device.lookup_vendor("aa:bb:cc:00:11:22", self.table)
        self.assertEqual((v, cn, hint), ("Hikvision Digital", "海康威视", "camera"))

    def test_entry_without_hint(self):
        v, cn, hint = device.lookup_vendor("dd:ee:ff:00:00:01", self.table)
        self.assertEqual((v, cn, hint), ("Xiaomi Communications", "小米", ""))

    def test_unknown_mac_returns_none_not_guess(self):
        self.assertEqual(device.lookup_vendor("99:88:77:00:00:01", self.table),
                         (None, None, ""))

    def test_empty_table_returns_none(self):
        # 红线：表里没数据时**不能**猜，必须返回空
        self.assertEqual(device.lookup_vendor("aa:bb:cc:00:11:22", {}), (None, None, ""))

    def test_empty_csv_yields_empty_table(self):
        self.assertEqual(device.parse_oui_table("# 只有注释\n"), {})


class TestDeviceTypeInference(unittest.TestCase):

    def test_hostname_hit(self):
        self.assertEqual(device.infer_device_type(hostname="IPC-FrontDoor"),
                         ("camera", "hostname"))

    def test_vendor_hit(self):
        self.assertEqual(device.infer_device_type(vendor="Hangzhou Hikvision"),
                         ("camera", "vendor"))

    def test_oui_hint_takes_priority(self):
        more_specific = device.infer_device_type(hostname="someone", vendor="X",
                                                 vendor_hint="vacuum")
        self.assertEqual(more_specific, ("vacuum", "vendor_hint"))

    def test_unknown_is_default(self):
        # 红线：没有依据就 unknown，不做概率猜测
        self.assertEqual(device.infer_device_type(hostname="abcdef", vendor="X"),
                         ("unknown", "none"))


class TestDeviceRegistry(unittest.TestCase):

    def build(self, oui_text=MINI_OUI, leases=SAMPLE_LEASES):
        return device.DeviceRegistry(oui_table=device.parse_oui_table(oui_text),
                                     leases_paths=[], arp_path="")

    def test_lease_creates_device_with_vendor(self):
        reg = self.build()
        reg.load_leases(SAMPLE_LEASES)
        dev = reg.get_by_ip("192.168.1.10")
        self.assertIsNotNone(dev)
        self.assertEqual(dev.display_name, "Bedroom-Cam")
        self.assertEqual(dev.vendor_cn, "海康威视")
        self.assertEqual(dev.device_type, "camera")

    def test_mac_reuse_across_ips_is_one_device(self):
        """同一台设备换了 IP，必须仍是同一台 —— 这是用 MAC 做主键的全部理由"""
        reg = self.build()
        reg.load_leases(SAMPLE_LEASES)
        reg.load_leases(f"{SOON_FN + 10} aa:bb:cc:00:11:22 192.168.1.77 Bedroom-Cam\n")
        dev = reg.get_by_ip("192.168.1.77")
        self.assertEqual(dev.key, "aa:bb:cc:00:11:22")
        self.assertEqual(sorted(dev.ips), ["192.168.1.10", "192.168.1.77"])
        self.assertEqual(len([d for d in reg.list_devices() if d.mac == "aa:bb:cc:00:11:22"]), 1)

    def test_no_hostname_device_falls_back_to_vendor(self):
        reg = self.build()
        reg.load_leases(f"{SOON_FN} dd:ee:ff:00:00:01 192.168.1.11 *\n")
        dev = reg.get_by_ip("192.168.1.11")
        self.assertEqual(dev.display_name, "小米")

    def test_unknown_ip_becomes_ip_only_device(self):
        reg = self.build()
        dev = reg.observe_ip("10.0.0.55", ts=1000.0)
        self.assertIsNone(dev.mac)
        self.assertEqual(dev.key, "10.0.0.55")
        self.assertEqual(dev.display_name, "10.0.0.55")

    def test_observe_updates_last_seen(self):
        reg = self.build()
        reg.load_leases(SAMPLE_LEASES)
        reg.observe_ip("192.168.1.10", ts=999999.0)
        self.assertEqual(reg.get_by_ip("192.168.1.10").last_seen, 999999.0)

    def test_arp_adds_static_ip_device(self):
        reg = self.build()
        reg.load_arp(SAMPLE_ARP)
        dev = reg.get_by_ip("192.168.1.20")
        self.assertEqual(dev.mac, "dd:ee:ff:00:00:20")
        self.assertEqual(dev.vendor_cn, "小米")

    def test_blind_spot_when_no_oui_table(self):
        reg = device.DeviceRegistry(oui_table={}, leases_paths=[], arp_path="")
        reg.load_leases(SAMPLE_LEASES)
        spots = reg.blind_spots()
        self.assertTrue(any("未加载 MAC 厂商库" in s for s in spots))

    def test_blind_spot_for_ip_only_devices(self):
        reg = self.build()
        reg.observe_ip("10.0.0.55")
        self.assertTrue(any("未拿到 MAC" in s for s in reg.blind_spots()))

    def test_no_blind_spot_when_fully_resolved(self):
        reg = self.build()
        reg.load_leases(f"{SOON_FN} aa:bb:cc:00:11:22 192.168.1.10 Cam\n")
        self.assertEqual(reg.blind_spots(), [])


# ============================================================ 域名归属

REAL_CSV = attribution.DEFAULT_DOMAINS_CSV


class TestDomainNormalization(unittest.TestCase):

    def test_case_and_trailing_dot(self):
        self.assertEqual(attribution.normalize_domain("Track.IO.MI.com."),
                         "track.io.mi.com")

    def test_strip_scheme_and_port(self):
        self.assertEqual(attribution.normalize_domain("https://a.example.com:443/x"),
                         "a.example.com")

    def test_empty(self):
        self.assertEqual(attribution.normalize_domain("   "), "")
        self.assertEqual(attribution.normalize_domain(None), "")


class TestRegistrableDomain(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(attribution.registrable_domain("a.b.example.com"), "example.com")

    def test_multi_suffix(self):
        self.assertEqual(attribution.registrable_domain("a.b.example.com.cn"), "example.com.cn")

    def test_deep_iot_domain(self):
        self.assertEqual(attribution.registrable_domain("ot.io.mi.com"), "mi.com")


class TestParentCandidates(unittest.TestCase):

    def test_walks_down_to_registrable(self):
        cands = attribution._parent_candidates("abc.track.io.mi.com")
        self.assertEqual(cands, ["abc.track.io.mi.com", "track.io.mi.com",
                                 "io.mi.com", "mi.com"])

    def test_never_reaches_bare_suffix(self):
        # 红线：不许拿 com 去匹配规则
        cands = attribution._parent_candidates("a.b.example.com")
        self.assertEqual(cands[-1], "example.com")
        self.assertNotIn("com", cands)

    def test_two_label_domain(self):
        self.assertEqual(attribution._parent_candidates("example.com"), ["example.com"])


@unittest.skipUnless(REAL_CSV.is_file(), "需要真实 domains.csv")
class TestAttributionWithRealKB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.attr = attribution.DomainAttribution()

    def test_knowledge_base_loaded(self):
        self.assertGreater(len(self.attr._rules), 50)

    def test_exact_match(self):
        r = self.attr.resolve("track.io.mi.com")
        self.assertTrue(r.known)
        self.assertEqual(r.matched_by, "exact")
        self.assertEqual(r.organization, "Xiaomi")

    def test_parent_match(self):
        r = self.attr.resolve("edge123.track.io.mi.com")
        self.assertTrue(r.known)
        self.assertEqual(r.matched_by, "parent")
        self.assertEqual(r.matched_domain, "track.io.mi.com")
        self.assertEqual(r.organization, "Xiaomi")

    def test_unknown_domain_is_unknown_not_guess(self):
        # 红线：认输。不模糊匹配，不猜相似域名
        r = self.attr.resolve("totally-unknown-brand.example.org")
        self.assertFalse(r.known)
        self.assertIsNone(r.organization)
        self.assertEqual(r.category, "unknown")
        self.assertEqual(r.confidence, "none")
        self.assertEqual(r.matched_by, "none")

    def test_side_effects_split(self):
        r = self.attr.resolve("track.io.mi.com")
        self.assertIn("数据统计停止", r.side_effects)

    def test_explain_is_human_readable(self):
        self.assertIn("Xiaomi", self.attr.resolve("track.io.mi.com").explain())
        self.assertIn("没有归属记录", self.attr.resolve("x.nonexistent-zzz.org").explain())

    def test_cache_used(self):
        self.attr._cache.clear()
        self.attr.stats["cache_hits"] = 0
        self.attr.resolve("ot.io.mi.com")
        self.attr.resolve("ot.io.mi.com")
        self.assertEqual(self.attr.stats["cache_hits"], 1)

    def test_case_insensitive_and_cached_consistently(self):
        a = self.attr.resolve("AD.XIAOMI.COM")
        b = self.attr.resolve("ad.xiaomi.com")
        self.assertEqual(a.matched_domain, b.matched_domain)
        self.assertTrue(a.known)

    def test_coverage_report(self):
        rep = self.attr.coverage(["track.io.mi.com", "zzz-unknown-test.org"])
        self.assertEqual(rep.total, 2)
        self.assertEqual(rep.hit, 1)
        self.assertEqual(rep.unknown, ["zzz-unknown-test.org"])
        self.assertIn("归属覆盖率", rep.summary())

    def test_kb_expanded_domestic_brands(self):
        """W5 扩量：国产设备厂商与常见嵌入式广告/统计 SDK 应可被归属"""
        # 新增的主流国产设备厂商根域名（精确命中）
        exact = {
            "hisense.com": "Hisense (海信)",
            "tcl.com": "TCL (TCL)",
            "gree.com": "Gree (格力)",
            "roborock.com": "Roborock (石头科技)",
            "ecovacs.com": "Ecovacs (科沃斯)",
            "dji.com": "DJI (大疆)",
            "ninebot.com": "Ninebot (九号)",
            "aqara.com": "Aqara (绿米)",
            "yeelight.com": "Yeelight (易来)",
            "viomi.com": "Viomi (云米)",
            "orvibo.com": "Orvibo (欧瑞博)",
            "jd.com": "JD (京东)",
            "suning.com": "Suning (苏宁)",
            "meizu.com": "Meizu (魅族)",
            "iflytek.com": "iFlytek (科大讯飞)",
            "mi.com": "Xiaomi",
            "huawei.com": "Huawei",
        }
        for domain, org in exact.items():
            r = self.attr.resolve(domain)
            self.assertTrue(r.known, f"{domain} 应可归属")
            self.assertEqual(r.matched_by, "exact", f"{domain} 应精确命中")
            self.assertEqual(r.organization, org, f"{domain} 归属组织错误")

        # 设备内嵌广告/联盟/统计 SDK（精确命中，建议 block_soft）
        sdk = {
            "gdt.qq.com": "Tencent (广点通)",
            "cpro.baidu.com": "Baidu (百度联盟)",
            "tanx.com": "Alibaba (阿里妈妈)",
            "ad.360.cn": "Qihoo 360 (360广告)",
            "kuaishou.com": "Kuaishou (快手)",
            "pinduoduo.com": "Pinduoduo (拼多多)",
        }
        for domain, org in sdk.items():
            r = self.attr.resolve(domain)
            self.assertTrue(r.known, f"{domain} 应可归属")
            self.assertEqual(r.organization, org)
            self.assertIn(r.action, ("block_soft", "block_medium"))

        # 修复项：msmart.meizu.com 曾被误归为 Midea，应为魅族
        self.assertEqual(self.attr.resolve("msmart.meizu.com").organization, "Meizu (魅族)")

        # 子域名向上匹配：根域名覆盖其下所有子域
        self.assertEqual(self.attr.resolve("account.mi.com").organization, "Xiaomi")
        self.assertEqual(self.attr.resolve("api.hisense.com").organization, "Hisense (海信)")

        # 红线不被破坏：仍未知就不猜
        self.assertFalse(self.attr.resolve("zzz-no-such-brand.example.org").known)

    def test_kb_size_after_expansion(self):
        """扩量后规则数应明显大于初始规模（初始约 100 条，扩量后 >140）"""
        self.assertGreater(len(self.attr._rules), 140)


class TestAttributionLoading(unittest.TestCase):

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            attribution.DomainAttribution(Path("definitely-not-here.csv"))

    def test_empty_table_raises(self):
        """静默加载成空表是最难排查的假故障 —— 必须抛错"""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "empty.csv"
            p.write_text("domain,organization,category,confidence,description,action,side_effects\n",
                         encoding="utf-8")
            with self.assertRaises(ValueError):
                attribution.DomainAttribution(p)

    def test_custom_table_resolves(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "kb.csv"
            p.write_text(
                "domain,organization,category,confidence,description,action,side_effects\n"
                "example.com,Example Inc,analytics,high,测试,block_soft,会停摆\n",
                encoding="utf-8")
            attr = attribution.DomainAttribution(p)
            r = attr.resolve("x.y.example.com")
            self.assertEqual(r.organization, "Example Inc")
            self.assertEqual(r.matched_by, "parent")


if __name__ == "__main__":
    unittest.main(verbosity=2)
