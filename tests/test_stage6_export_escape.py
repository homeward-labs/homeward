"""Stage 6 导出转义回归：Markdown 报告必须中和网络侧可控外部值。

对应审计报告 ME-5「导出对外部值 esc()/json.dumps」。本仓只有 Markdown / JSON
两种导出格式，未发现 CSV 导出，故 CSV 公式注入不成立；这里只验 Markdown 分支。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ui.server import _md_escape, _report_markdown  # noqa: E402


def _payload(**kw):
    base = {
        "report": {"generated_at": 0, "scope": "user"},
        "checkup": {},
        "stats": {},
        "coverage": {},
        "devices": [],
        "destinations": {},
        "unknown_domains": [],
        "alerts": [],
        "blind_spots": [],
    }
    base.update(kw)
    return base


class MarkdownEscapeTest(unittest.TestCase):

    def test_pipe_and_crlf_in_device_name_escaped(self):
        p = _payload(devices=[{
            "name": "evil|fake\n## FORGED", "ips": ["1.2.3.4"], "mac": "aa",
            "vendor": "v", "device_type": "pc", "top_domains": [],
        }])
        lines = _report_markdown(p).splitlines()
        row = next(l for l in lines if l.startswith("| evil"))
        self.assertIn("\\|", row)
        self.assertFalse(any(l.startswith("## FORGED") for l in lines),
                         "换行不得伪造标题")
        self.assertEqual(sum(1 for l in lines if l.startswith("| evil")), 1,
                         "换行不得伪造表格新行")

    def test_html_metachars_in_domain_escaped(self):
        p = _payload(destinations={"items": [{
            "domain": "<script>alert(1)</script>", "organization": "o",
            "category": "c", "confidence": "high",
        }], "known": 1})
        md = _report_markdown(p)
        self.assertIn("&lt;script&gt;", md)
        self.assertNotIn("<script>", md)

    def test_unknown_domain_cannot_forge_heading_or_list(self):
        p = _payload(unknown_domains=["a.example\n## FORGED"],
                     blind_spots=["b.example\n- FORGED"])
        md = _report_markdown(p)
        self.assertNotIn("\n## FORGED", md)
        self.assertNotIn("\n- FORGED", md)
        self.assertIn("a.example ## FORGED", md)

    def test_alert_fields_escaped(self):
        p = _payload(alerts=[{
            "severity_label": "低", "title": "心跳|信标", "device_name": "phone",
            "domain": "track.example.com", "organization": "Org",
            "summary": "说明\n- 伪造", "action_label": "查看", "side_effects": "无",
        }])
        md = _report_markdown(p)
        self.assertIn("心跳\\|信标", md)
        self.assertNotIn("\n- 伪造", md)

    def test_plain_report_unchanged(self):
        p = _payload(
            devices=[{"name": "my-phone", "ips": ["192.168.1.5"], "mac": "aa:bb",
                      "vendor": "Apple", "device_type": "phone",
                      "top_domains": [{"domain": "example.com", "count": 3}]}],
            destinations={"items": [{"domain": "example.com", "organization": "Example",
                                     "category": "web", "confidence": "high"}], "known": 1},
            unknown_domains=["unknown.example"],
            alerts=[{"severity_label": "低", "title": "心跳信标", "device_name": "phone",
                     "domain": "track.example.com", "organization": "Org",
                     "summary": "周期性外联", "action_label": "查看", "side_effects": "无"}],
            blind_spots=["无覆盖"],
        )
        md = _report_markdown(p)
        for s in ("my-phone", "192.168.1.5", "aa:bb", "Apple", "example.com(3)",
                  "unknown.example", "心跳信标", "track.example.com", "周期性外联",
                  "无覆盖", "查看", "Org"):
            self.assertIn(s, md, "正常值不得被过度转义: %s" % s)

    def test_limit_and_none(self):
        self.assertEqual(_md_escape(None), "")
        self.assertLessEqual(len(_md_escape("x" * 1000)), 257)

    def test_escape_does_not_mutate_payload(self):
        p = _payload(unknown_domains=["a|b"])
        md = _report_markdown(p)
        self.assertIn("a\\|b", md)
        self.assertEqual(p["unknown_domains"], ["a|b"],
                         "JSON 分支与原始 payload 不受 Markdown 转义影响")


if __name__ == "__main__":
    unittest.main()
