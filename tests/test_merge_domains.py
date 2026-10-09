# -*- coding: utf-8 -*-
"""merge_domains.py 归一化 / 解析 / 冲突合并 的回归测试。"""
import os
import sys
import unittest
from pathlib import Path

# 让测试能直接 import 仓内脚本
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import merge_domains as m  # noqa: E402


class NormalizeTest(unittest.TestCase):
    def test_lowercase_and_strip(self):
        self.assertEqual(m.Row("Example.COM.", "", "", "", "", "", "").norm(), "example.com")

    def test_www_stripped(self):
        self.assertEqual(m.Row("www.Example.com", "", "", "", "", "", "").norm(), "example.com")

    def test_wildcard_preserved(self):
        # 通配 *.x.com 与精确 x.com 必须作为不同键共存
        self.assertEqual(m.Row("*.huaweicloud.com", "", "", "", "", "", "").norm(), "*.huaweicloud.com")
        self.assertEqual(m.Row("huaweicloud.com", "", "", "", "", "", "").norm(), "huaweicloud.com")
        self.assertNotEqual(
            m.Row("*.huaweicloud.com", "", "", "", "", "", "").norm(),
            m.Row("huaweicloud.com", "", "", "", "", "", "").norm(),
        )


class ParseCsvSeedTest(unittest.TestCase):
    def test_bom_tolerant(self):
        text = "\ufeffdomain,organization,category,confidence,description,action,side_effects\n"
        text += "*.ads.com,Acme,advertising_sdk,high,广告,block_soft,广告停止\n"
        rows = m.parse_csv_seed(text, "seed:x")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].domain, "*.ads.com")
        self.assertEqual(rows[0].category, "advertising_sdk")

    def test_skips_empty_domain(self):
        text = "domain,organization,category,confidence,description,action,side_effects\n"
        text += ",Acme,ads,high,,block_soft,\n"
        text += "ok.com,Acme,ads,high,,block_soft,\n"
        rows = m.parse_csv_seed(text, "seed:x")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].domain, "ok.com")


class ResolveTest(unittest.TestCase):
    def _r(self, cat, conf, src="seed:x"):
        return m.Row("d.com", "o", cat, conf, "", "", "", source=src)

    def test_negative_beats_benign(self):
        # tracker(负向) 应覆盖 cdn(正向)
        win = m.resolve(self._r("cdn", "high", "baseline"), self._r("tracker", "high"))
        self.assertEqual(win.category, "tracker")

    def test_higher_confidence_wins_within_tier(self):
        win = m.resolve(self._r("analytics", "low", "baseline"), self._r("analytics", "high"))
        self.assertEqual(win.confidence, "high")

    def test_baseline_preserved_on_tie(self):
        # 同档同置信：保留已有 baseline，减少知识库抖动
        win = m.resolve(self._r("cdn", "high", "baseline"), self._r("cdn", "high"))
        self.assertEqual(win.source, "baseline")

    def test_benign_kept_when_no_negative(self):
        win = m.resolve(self._r("cdn", "high", "baseline"), self._r("cloud", "high"))
        # 二者都属正向档，平手 → baseline
        self.assertEqual(win.category, "cdn")


class HostsParseTest(unittest.TestCase):
    def test_skips_comments_and_localhost(self):
        text = "# comment\n0.0.0.0 ads.example.com\n127.0.0.1 localhost\n0.0.0.0 track.foo.com\n"
        rows = m.parse_hosts(text, "tracker", "block_soft", "StevenBlack", "stevenblack", 100)
        hosts = {r.domain for r in rows}
        self.assertEqual(hosts, {"ads.example.com", "track.foo.com"})


class UrlhausParseTest(unittest.TestCase):
    def test_extracts_host(self):
        text = "id,date_added,url,url_status,threat,tags,urlhaus_link,reporter\n"
        text += '1,2024-01-01,http://evil.example.com/x,online,malware,,https://a,a\n'
        text += '2,2024-01-01,https://other.example.org/y,online,malware,,https://b,b\n'
        rows = m.parse_urlhaus_csv(text, "urlhaus", 100)
        hosts = {r.domain for r in rows}
        self.assertEqual(hosts, {"evil.example.com", "other.example.org"})
        self.assertTrue(all(r.category == "malware" for r in rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
