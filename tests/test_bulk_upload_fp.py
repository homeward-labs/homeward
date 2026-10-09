"""
回归测试：bulk_upload（突发大流量上传）的误报收敛。

真实家庭网络里，手机 iCloud/Google 相册备份、系统/App 更新、CDN 拉取都符合
「单位时间内向单一目的地传大量数据」，直接判 high + block_medium 是误报。
修复后：目的地归属为良性大流量类别（云备份/系统更新/CDN）时降级为 low/warn；
目的地未知仍保持原严重度（未知大流量上传更可疑，宁严勿松）。

仅用 RFC5737 文档保留段 IP（192.0.2.x）与公开域名，不含任何真实 MAC/IP/凭证。
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

BASE = 1700000000.0


def _flow(ts, src, domain, size):
    return FlowRecord(ts, src, "203.0.113.9", 443, "tcp",
                      sni=domain, dns_query=domain, packet_size=size, direction="out")


def _bulk_flows(src, domain):
    """模拟一次 70 秒、约 6.3MB 的单目的地上传（正常云备份量级）"""
    return [_flow(BASE + i, src, domain, 180000) for i in range(0, 70, 2)]


def _run(domains_per_device):
    kb = KnowledgeBase()
    det = BehaviorDetector()
    for src, domain in domains_per_device:
        det.feed_many(_bulk_flows(src, domain))
    findings = det.scan(now=BASE + 75)
    center = AlertCenter()
    alerts = center.ingest(
        findings,
        attribution_of=lambda d: (kb.query(d) or {}),
    )
    return {a.destination: a for a in alerts}


class BulkUploadFalsePositiveTest(unittest.TestCase):
    def test_icloud_backup_downgraded(self):
        """iCloud（良性云存储）的大流量上传应降级，不当数据外泄"""
        alerts = _run([("192.0.2.10", "p53-ckicloudws.icloud.com")])
        self.assertIn("p53-ckicloudws.icloud.com", alerts)
        a = alerts["p53-ckicloudws.icloud.com"]
        self.assertEqual(a.rule_id, "bulk_upload")
        self.assertEqual(a.severity, "low", "已知云备份不应判高危")
        self.assertEqual(a.suggested_action, "warn", "已知云备份不应建议阻断")

    def test_unknown_destination_stays_high(self):
        """未知目的地的大流量上传必须保持高危（不能因修复而漏报）"""
        alerts = _run([("192.0.2.11", "mystery-backup.example.net")])
        self.assertIn("mystery-backup.example.net", alerts)
        a = alerts["mystery-backup.example.net"]
        self.assertEqual(a.rule_id, "bulk_upload")
        self.assertEqual(a.severity, "high")
        self.assertEqual(a.suggested_action, "block_medium")

    def test_both_paths_independent(self):
        """同一次扫描里，良性与未知应分别得到降级/保持，互不干扰"""
        alerts = _run([
            ("192.0.2.10", "p53-ckicloudws.icloud.com"),
            ("192.0.2.11", "mystery-backup.example.net"),
        ])
        self.assertEqual(alerts["p53-ckicloudws.icloud.com"].severity, "low")
        self.assertEqual(alerts["mystery-backup.example.net"].severity, "high")


if __name__ == "__main__":
    unittest.main()
