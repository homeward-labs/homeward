"""
F7：未知域名良性 / 自有自动归类。

要解决的真问题（FEATURE-EVOLUTION §1.4 / §5.3 延伸）：
真实数据里「未知域名 12 个」把自家路由 `istoreos.lan`、mDNS 的 `*.local`、
内网反向解析 `*.arpa` 都算成了「未知外联」——既让用户恐慌，又在体检里虚高扣分。
这些都是**自己家里的名字**，根本不是外联。

归类规则（保守、不猜）：
- own（自有/局域网）：结构性判定 —— .lan/.local/.localdomain/.home.arpa/
  .internal/.intranet/.arpa/localhost。零误判风险，因为它们本地命名、不是外联目的地。
- benign（良性）：**只来自用户显式标记** —— 系统绝不自动把外部域名判为良性
  （误判良性 = 漏报，比多列几个未知更危险）。
- 其余才是真正未知，计入「未知域名」。

仅用文档保留段 / 示例域名，不含任何真实 MAC/IP/凭证。
"""
import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.main import (  # noqa: E402
    HomewardService, _is_observable_domain, _is_own_domain,
)


class _MarksIsolatedTest(unittest.TestCase):
    """标记必须落在**临时目录**，不能写进真实 data/ —— 否则既污染本机数据，
    又会让上一次跑测试写下的标记被下一次加载，造成跨用例串味。"""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.marks_path = str(Path(self._td.name) / "marks.json")

    def tearDown(self):
        self._td.cleanup()

    def svc(self, **cfg):
        base = {"load_system_devices": False, "marks_path": self.marks_path}
        base.update(cfg)
        return HomewardService(config=base)


class OwnDomainClassificationTest(unittest.TestCase):
    def test_own_suffixes(self):
        """自家路由 / mDNS / 内网反向解析 / localhost 都应判为「自有」"""
        for d in ("istoreos.lan", "printer.local", "box.localdomain",
                  "router.home.arpa", "nas.internal", "pc.intranet",
                  "1.0.168.192.in-addr.arpa", "localhost"):
            self.assertTrue(_is_own_domain(d), f"{d} 应判为自有/局域网")

    def test_external_not_own(self):
        """真正的外部域名不能被自动判为自有"""
        for d in ("example.com", "mirrors.ustc.edu.cn", "beacon.qq.com"):
            self.assertFalse(_is_own_domain(d), f"{d} 不应判为自有")

    def test_observable_domain_excludes_own_and_ip(self):
        self.assertFalse(_is_observable_domain("istoreos.lan"))
        self.assertFalse(_is_observable_domain("1.0.168.192.in-addr.arpa"))
        self.assertFalse(_is_observable_domain("192.168.1.1"))
        self.assertTrue(_is_observable_domain("example.com"))


class DomainMarkingTest(_MarksIsolatedTest):
    def test_auto_own_not_counted_unknown(self):
        """自有/局域网域名不应计入「未知域名」"""
        svc = self.svc()
        svc.stats["unknown_domains"].update({"istoreos.lan", "mystery.example.net"})
        self.assertEqual(svc.get_unknown_domains(), ["mystery.example.net"])
        c = svc.get_classified_domains()
        self.assertEqual(c["own"], ["istoreos.lan"])
        self.assertEqual(c["unknown"], ["mystery.example.net"])

    def test_mark_benign_removes_from_unknown(self):
        """用户标记为良性后，应从未知里移除"""
        svc = self.svc()
        svc.stats["unknown_domains"].add("mirrors.ustc.edu.cn")
        self.assertIn("mirrors.ustc.edu.cn", svc.get_unknown_domains())
        self.assertTrue(svc.mark_domain("mirrors.ustc.edu.cn", "benign"))
        self.assertNotIn("mirrors.ustc.edu.cn", svc.get_unknown_domains())
        self.assertEqual(svc.get_classified_domains()["benign"],
                         ["mirrors.ustc.edu.cn"])

    def test_no_auto_benign_for_external(self):
        """系统绝不自动把外部域名判为良性（防漏报）"""
        svc = self.svc()
        svc.stats["unknown_domains"].add("totally-unknown.example.net")
        c = svc.get_classified_domains()
        self.assertEqual(c["benign"], [])
        self.assertEqual(c["unknown"], ["totally-unknown.example.net"])

    def test_unmark_restores_unknown(self):
        """取消标记后应回到未知（用户可撤销）"""
        svc = self.svc()
        svc.stats["unknown_domains"].add("tool.example.dev")
        svc.mark_domain("tool.example.dev", "benign")
        self.assertNotIn("tool.example.dev", svc.get_unknown_domains())
        self.assertTrue(svc.mark_domain("tool.example.dev", ""))  # 空 kind = 取消
        self.assertIn("tool.example.dev", svc.get_unknown_domains())

    def test_invalid_kind_rejected(self):
        svc = self.svc()
        self.assertFalse(svc.mark_domain("x.example.com", "evil"))
        self.assertFalse(svc.mark_domain("", "benign"))
        self.assertFalse(svc.mark_domain("y.example.com", "OWN-ish"))

    def test_checkup_unknown_excludes_own_and_benign(self):
        """体检的「未知域名数」不应把自有与已标记良性算进去（修假扣分）"""
        svc = self.svc()
        svc.stats["unknown_domains"].update(
            {"istoreos.lan", "a.example.net", "b.example.net"})
        svc.mark_domain("b.example.net", "benign")
        ck = svc.privacy_checkup()
        self.assertEqual(ck["unknown_count"], 1)
        self.assertEqual(ck["top_unknown"], ["a.example.net"])

    def test_marks_persisted(self):
        """标记要落盘：重启不该丢用户的判断"""
        p = Path(self.marks_path)
        self.svc().mark_domain("mirrors.example.org", "benign")
        self.assertTrue(p.exists(), "标记应落盘")
        # 新实例 = 模拟重启，应把标记读回来
        svc2 = self.svc()
        self.assertEqual(svc2.get_domain_marks().get("mirrors.example.org"),
                         "benign", "重启后标记应还在")

    def test_get_domain_marks_only_manual(self):
        """get_domain_marks 只返回用户手动标的（UI 据此判断能否取消）"""
        svc = self.svc()
        svc.stats["unknown_domains"].update({"istoreos.lan", "m.example.net"})
        svc.mark_domain("m.example.net", "benign")
        marks = svc.get_domain_marks()
        self.assertNotIn("istoreos.lan", marks, "自动判定的自有不算手动标记")
        self.assertEqual(marks.get("m.example.net"), "benign")


if __name__ == "__main__":
    unittest.main()
