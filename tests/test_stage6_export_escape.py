"""Stage 6 导出转义回归：Markdown 报告必须中和网络侧可控外部值。

对应审计报告 ME-5「导出对外部值 esc()/json.dumps」。本仓只有 Markdown / JSON
两种导出格式，未发现 CSV 导出，故 CSV 公式注入不成立；这里只验 Markdown 分支。
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ui.server import (  # noqa: E402
    MAX_EXPORT_CELL,
    _md_escape,
    _report_markdown,
)


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


class Stage400EscapeHardeningTest(unittest.TestCase):
    """第 400 批：反斜杠与 & 绕过、转义顺序、膨胀限长与边界完整性。"""

    B = chr(92)

    def test_backslash_before_pipe_cannot_forge_column(self):
        # 旧实现：输入 `\|` 先变成 `\\|`，Markdown 中 `\\` 是字面反斜杠，
        # 紧随的 `|` 成了未转义的列分隔符，可伪造表格列。
        self.assertEqual(_md_escape("a" + self.B + "|b"),
                         "a" + self.B * 3 + "|b")
        p = _payload(devices=[{
            "name": "evil" + self.B + "|FAKE", "ips": ["1.2.3.4"],
            "mac": "aa", "vendor": "v", "device_type": "pc", "top_domains": [],
        }])
        row = next(l for l in _report_markdown(p).splitlines()
                   if l.startswith("| evil"))
        self.assertIn(self.B * 3 + "|FAKE", row)

    def test_ampersand_entity_input_is_neutralized(self):
        out = _md_escape("&lt;script&gt;")
        self.assertIn("&amp;lt;", out)
        self.assertNotIn("<script", out)
        # 正常含 & 的值在 Markdown 源里变成实体，渲染后仍是原文
        self.assertEqual(_md_escape("AT&T"), "AT&amp;T")

    def test_escape_units_are_exact_and_not_double_escaped(self):
        self.assertEqual(_md_escape("<"), "&lt;")
        self.assertEqual(_md_escape(">"), "&gt;")
        self.assertEqual(_md_escape("&"), "&amp;")
        self.assertEqual(_md_escape("&<"), "&amp;&lt;")
        self.assertEqual(_md_escape("|"), self.B + "|")
        self.assertEqual(_md_escape("`"), self.B + "`")
        self.assertEqual(_md_escape(self.B), self.B * 2)

    def _assert_no_partial_unit(self, body):
        """输出必须能按「完整转义单元」逐个切回。按单元消费而非逐字符，
        既检得出切在 &am 中间或末尾单个悬空反斜杠，也不会把完整的
        \\（两个反斜杠，表示一个字面反斜杠）误判成残缺。"""
        units = ("&amp;", "&lt;", "&gt;", self.B * 2,
                 self.B + "|", self.B + "`")
        i = 0
        while i < len(body):
            if body[i] in ("&", self.B):
                hit = next((u for u in units if body.startswith(u, i)), None)
                self.assertIsNotNone(
                    hit, "边界存在残缺转义单元，位置 %d：%r"
                    % (i, body[i:i + 8]))
                i += len(hit)
            else:
                i += 1

    def test_expansion_respects_output_limit_at_unit_boundary(self):
        lt = _md_escape("<" * 1000)
        self.assertLessEqual(len(lt), MAX_EXPORT_CELL)
        self.assertTrue(lt.endswith("…"))
        # 去掉省略号后必须全由完整的 &lt; 单元组成
        body = lt[:-1]
        self.assertEqual(body, "&lt;" * (len(body) // 4))
        amp = _md_escape("&" * 1000)
        self.assertLessEqual(len(amp), MAX_EXPORT_CELL)
        self.assertEqual(amp[:-1], "&amp;" * (len(amp[:-1]) // 5))
        # 反斜杠与竖线混合串的预算可能停在整组中间（\ 已入、\| 未入），
        # 故不假设完整组数，只断言边界不残缺、无悬空反斜杠。
        mix = _md_escape((self.B + "|") * 1000)
        self.assertLessEqual(len(mix), MAX_EXPORT_CELL)
        self.assertTrue(mix.endswith("…"))
        for out in (lt[:-1], amp[:-1], mix[:-1]):
            self._assert_no_partial_unit(out)

    def test_none_and_plain_values_unchanged(self):
        self.assertEqual(_md_escape(None), "")
        self.assertEqual(_md_escape("my-phone"), "my-phone")
        self.assertEqual(_md_escape("192.168.1.5"), "192.168.1.5")


if __name__ == "__main__":
    unittest.main()
