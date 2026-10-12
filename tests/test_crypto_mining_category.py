"""
crypto_mining 判定回归测试（src/rule_engine/engine.py + src/analysis/behavior.py）

锁定 2026-10 一次真实误报的根因修复：

  旧规则用 destination_keywords 子串匹配（含裸词 "pool"），把 NTP pool
  （cn.pool.ntp.org → 归属 "Pool Project"）误判成矿池，导致用户本机
  （192.168.1.153，华硕主板台式机）被报成"疑似加密货币挖矿"。
  commit 2b73562 移除了裸词 pool，但仍靠子串匹配，理论上还能误中其它良性域名。

  现改为 destination_categories: ["crypto_mining"]——只有目标域名真正归入
  知识库 crypto_mining 类别（NoCoin 精选 + 主流矿池）才命中。本测试验证：

  1. 用户本机的真实外联（GitHub CDN / NTP pool / 腾讯 / 微软 / 阿里云 …）
     绝不触发 crypto_mining（不会再误报矿机）。
  2. 真实矿池连接（nanopool / f2pool / ethermine / nicehash …）仍稳定命中。
  3. 告警展示的域名是"真正命中的矿池域名"，而不是窗口里第一条任意域名
     （修掉 _build 把 GitHub CDN 当矿池域名展示的显示 bug）。
"""

import sys
import time
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from analysis.behavior import BehaviorDetector, BehaviorFinding  # noqa: E402
from inventory.attribution import DomainAttribution  # noqa: E402
from rule_engine.engine import BehaviorMatcher, FlowRecord  # noqa: E402

KB_DIR = SRC_DIR / "knowledge_base"
BEHAVIORS = str(KB_DIR / "behaviors.json")


def _flow(src_ip, domain, ts, *, sni=False, packet_size=0, port=443):
    """构造一条外联记录；domain 走 dns_query，sni=True 时走 sni。"""
    return FlowRecord(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip="203.0.113.9",
        dst_port=port,
        protocol="tcp",
        sni=domain if sni else None,
        dns_query=None if sni else domain,
        packet_size=packet_size,
        direction="out",
    )


def _detector():
    """用真实知识库归因器构造检测器（与运行时一致）。"""
    attribution = DomainAttribution(str(KB_DIR / "domains.csv"))
    matcher = BehaviorMatcher(BEHAVIORS, attribution=attribution)
    return BehaviorDetector(matcher, attribution=attribution)


def _crypto_findings(detector, flows, now):
    detector.feed_many(flows)
    return [f for f in detector.scan(now=now) if f.rule_id == "crypto_mining"]


class CryptoMiningCategoryTest(unittest.TestCase):

    # 用户本机 153 的真实外联样本（来自真机 observations.db 的 domains 聚合）
    BENIGN_153 = [
        "cdn-yb.icon.qq.com", "aiguardai.com", "www.softaid.net", "www.pistack.xyz",
        "feodotracker.abuse.ch", "1600119611l4b.my-imcloud.com",
        "www.globalthreatwatch.com", "tranco-list.eu", "www.oki-oids.jp",
        "docs.danami.com", "settings-win.data.microsoft.com", "dns.msftncsi.com",
        "conn.yuanbao.tencent.com", "mmwxalite.wxqcloud.qq.com", "rmonitor.qq.com",
        "h-adashx.ut.taobao.com", "nexusrules.officeapps.live.com",
        "android.clients.google.com", "www.qianwen.com", "chat-api-quark2.qianwen.com",
        "safebrowsing.googleapis.com", "www.trae.cn", "avatars3.githubusercontent.com",
        "api.github.com", "cn.pool.ntp.org", "0.cn.pool.ntp.org",
        "commander-prod.oss-cn-hangzhou.aliyuncs.com",
        "rpa-college.oss-cn-hangzhou.aliyuncs.com",
    ]

    def test_153_real_traffic_never_flags_miner(self):
        """用户本机真实外联（含 NTP pool / GitHub CDN）绝不误报矿机。"""
        t0 = time.time()
        flows = []
        # 跨 200 域名、足够 occurrences/connections，但全为良性
        for i, dom in enumerate(self.BENIGN_153 * 8):
            flows.append(_flow("192.168.1.153", dom, t0 + (i % 580),
                               packet_size=120))
        findings = _crypto_findings(_detector(), flows, now=t0 + 600)
        self.assertEqual(findings, [],
                         f"本机 153 被误报为矿机：{[f.domain for f in findings]}")

    def test_ntp_pool_no_longer_flags(self):
        """专门回归：NTP pool（旧规则的误报源）不再命中。"""
        t0 = time.time()
        flows = [_flow("192.168.1.153", f"{i}.cn.pool.ntp.org", t0 + i,
                       packet_size=80) for i in range(40)]
        findings = _crypto_findings(_detector(), flows, now=t0 + 600)
        self.assertEqual(findings, [], "NTP pool 仍被误判为矿池")

    def test_real_miner_still_detected(self):
        """真实矿池连接仍稳定命中，且展示域名是真正的矿池。"""
        t0 = time.time()
        pools = ["xmr.nanopool.org", "eth.nanopool.org", "f2pool.com",
                 "ethermine.org", "nicehash.com"]
        flows = []
        for i in range(60):  # > min_occurrences(20)，> min_connections(3)
            dom = pools[i % len(pools)]
            flows.append(_flow("192.168.1.99", dom, t0 + i * 8,
                               sni=True, packet_size=300))
        findings = _crypto_findings(_detector(), flows, now=t0 + 600)
        self.assertEqual(len(findings), 1, f"矿机未被检出：{findings}")
        f = findings[0]
        self.assertIn(f.domain, pools,
                      f"展示域名不是真矿池：{f.domain}")
        self.assertEqual(f.rule_id, "crypto_mining")

    def test_display_picks_real_pool_not_first_record(self):
        """显示修复：混入良性首条记录时，展示域名仍应是真矿池。"""
        t0 = time.time()
        flows = [
            # 先来一堆良性记录（GitHub CDN 等），确保"第一条任意域名"是良性的
            _flow("192.168.1.99", "avatars3.githubusercontent.com", t0,
                  sni=True, packet_size=200),
            _flow("192.168.1.99", "api.github.com", t0 + 1,
                  sni=True, packet_size=200),
        ]
        pools = ["xmr.nanopool.org", "eth.nanopool.org"]
        for i in range(40):
            flows.append(_flow("192.168.1.99", pools[i % len(pools)],
                               t0 + 2 + i, sni=True, packet_size=300))
        findings = _crypto_findings(_detector(), flows, now=t0 + 600)
        self.assertEqual(len(findings), 1)
        self.assertIn(findings[0].domain, pools,
                      f"_build 仍把首条良性记录当矿池域名：{findings[0].domain}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
