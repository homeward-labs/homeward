"""tests/test_import_log.py —— 离线日志导入（src/core/import_log.py）纯单测。

之前这块只有经 ``test_ui.py`` 的 API 级覆盖：一旦解析层面的回归发生，
报错会表现为「HTTP 500」而不是「第几行解析失败」，定位成本高。
这里补纯函数级用例，把「单行解析 / 统计口径 / 上限保护 / 脏数据不拖垮整个导入」
四件事钉死。

运行：python -m pytest tests/test_import_log.py -q
      或：python -m unittest tests.test_import_log -v
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.import_log import import_log_text, parse_log_line  # noqa: E402
from core.main import HomewardService                        # noqa: E402

DNS_LINE = "Feb 11 12:34:56 dnsmasq[1234]: query[A] www.example.com from 192.168.1.50"
# /proc/net/nf_conntrack 形态（内核 procfs，conntrack-tools 的 -o extended 亦兼容）
CONNTRACK_LINE = (
    "ipv4     2 tcp      6 431999 ESTABLISHED "
    "src=192.168.1.50 dst=93.184.216.34 sport=51234 dport=443 "
    "packets=10 bytes=1024 "
    "src=93.184.216.34 dst=192.168.1.50 sport=443 dport=51234 "
    "packets=8 bytes=2048 [ASSURED] mark=0 use=2"
)


def _service() -> HomewardService:
    # 不加载系统设备：单测要的是确定性，不受本机 lease/ARP 影响
    return HomewardService(config={"load_system_devices": False,
                                   "actions_db_path": None})


class ParseLineTest(unittest.TestCase):
    def test_dns_line(self):
        obs = parse_log_line(DNS_LINE)
        self.assertIsNotNone(obs)
        self.assertEqual(obs.kind, "dns")
        self.assertEqual(obs.device_id, "192.168.1.50")
        self.assertEqual(obs.fields["domain"], "www.example.com")

    def test_unrecognised_line_returns_none(self):
        # 认不出 ≠ 错误：返回 None 让调用方跳过，不计数为 error
        self.assertIsNone(parse_log_line(""))
        self.assertIsNone(parse_log_line("一行完全无关的日志"))

    def test_conntrack_line(self):
        obs = parse_log_line(CONNTRACK_LINE)
        self.assertIsNotNone(obs, "样例 conntrack 行应被识别")
        self.assertEqual(obs.kind, "flow")
        self.assertEqual(obs.device_id, "192.168.1.50")
        self.assertEqual(obs.fields["bytes"], 1024)


class ImportTextTest(unittest.TestCase):
    def test_stats_and_devices(self):
        svc = _service()
        text = "\n".join(
            f"Feb 11 12:34:{i:02d} dnsmasq[1]: query[A] d{i}.example.com "
            f"from 192.168.1.{50 + i}"
            for i in range(5)
        )
        stats = import_log_text(text, svc)
        self.assertEqual(stats["lines"], 5)
        self.assertEqual(stats["parsed"], 5)
        self.assertEqual(stats["flows"], 5)
        self.assertEqual(stats["new_devices"], 5)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual(stats["truncated"], 0)

    def test_dirty_lines_do_not_fail_whole_import(self):
        """脏行只被跳过，不能让整次导入抛异常。"""
        svc = _service()
        text = "\n".join([
            "这行不是日志",
            DNS_LINE,
            "",
            "dnsmasq[1]: query[A] 缺字段 from",
        ])
        stats = import_log_text(text, svc)
        self.assertGreaterEqual(stats["parsed"], 1)
        self.assertEqual(stats["errors"], 0)

    def test_truncation_counted(self):
        svc = _service()
        text = "\n".join([DNS_LINE] * 10)
        stats = import_log_text(text, svc, max_lines=3)
        self.assertEqual(stats["lines"], 10)
        self.assertEqual(stats["truncated"], 7)
        self.assertLessEqual(stats["parsed"], 3)

    def test_oversized_text_rejected(self):
        import core.import_log as mod

        svc = _service()
        old = mod.MAX_TEXT_BYTES
        mod.MAX_TEXT_BYTES = 16          # 缩小上限，避免真造 16MiB 字符串
        try:
            with self.assertRaises(ValueError):
                import_log_text("x" * 100, svc)
        finally:
            mod.MAX_TEXT_BYTES = old

    def test_none_text_is_noop(self):
        svc = _service()
        stats = import_log_text(None, svc)
        self.assertEqual(stats["lines"], 0)
        self.assertEqual(stats["errors"], 0)


if __name__ == "__main__":
    unittest.main()
