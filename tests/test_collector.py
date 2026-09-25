"""
W5 —— 采集泵（CollectorRunner）集成测试

把「采集器 → service」这一截泵验证掉：采集器吐的 Observation 真能被喂进
HomewardService.process_flow()，并在设备 / 域名 / 未知域名上体现出来；
不可用（probe 失败）的采集器要被记为盲区、绝不把服务拖垮；stop() 能优雅退出。

用标准库 unittest（与全仓一致，无需 pytest）。采集器通过注入 source / 自定义子类绕开
真实系统依赖，留到真机冒烟再验。
"""

import sys
import time
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from adapters.base import Capabilities, Collector, Observation, ProbeResult  # noqa: E402
from core.collector import CollectorRunner                                      # noqa: E402
from core.main import HomewardService                                           # noqa: E402


class _OneShotDnsCollector(Collector):
    """测试用：第一次 records() 吐一条 DNS 观测，之后短睡轮询（模拟长轮询、可被 stop 唤醒）"""

    def __init__(self):
        self.calls = 0

    def capabilities(self):
        return Capabilities(dns_query=True, timing=True, is_lan_dns=True)

    def probe(self):
        return ProbeResult(True, "测试注入源（DNS）", self.capabilities())

    def degrade_to(self):
        return None

    def records(self):
        self.calls += 1
        if self.calls > 1:
            # 第二次及以后：短睡后返回，泵会在下次循环检查 stop（不热自旋、不重放）
            time.sleep(0.1)
            return
        yield Observation(
            timestamp=time.time(),
            kind="dns",
            device_id="192.168.1.50",
            fields={"domain": "test-unknown-domain-xyz.local", "client_ip": "192.168.1.50"},
        )


class _UnavailableCollector(Collector):
    """probe 故意失败：用于验证「不可用 → 记盲区、不崩溃、不阻塞其他采集器」"""

    def capabilities(self):
        return Capabilities()

    def probe(self):
        return ProbeResult(False, "故意不可用（测试）", self.capabilities())

    def degrade_to(self):
        return None

    def records(self):
        return iter(())


class CollectorRunnerTest(unittest.TestCase):

    def test_pump_feeds_service_with_real_observations(self):
        svc = HomewardService(config={"load_system_devices": False})
        collector = _OneShotDnsCollector()
        runner = CollectorRunner(svc, collectors=[collector])
        status = runner.start()
        try:
            # 等待泵处理完第一条观测
            for _ in range(50):
                if svc.stats["flows_processed"] >= 1:
                    break
                time.sleep(0.05)

            self.assertGreaterEqual(svc.stats["flows_processed"], 1)
            # 设备应被识别（192.168.1.50 出现）
            dev = svc.get_device("192.168.1.50")
            self.assertIn("192.168.1.50", dev.get("ips") or [])
            # 域名归属应被收录（未知域名进 unknown 集合）
            self.assertIn("test-unknown-domain-xyz.local", svc.get_unknown_domains())
            # 采集状态写入 service，供 /api/overview 盲区视图展示
            self.assertEqual(len(status), 1)
            self.assertTrue(status[0]["active"])
        finally:
            runner.stop()

    def test_unavailable_collector_reported_as_blind_spot(self):
        svc = HomewardService(config={"load_system_devices": False})
        runner = CollectorRunner(svc, collectors=[_UnavailableCollector()])
        status = runner.start()
        self.assertEqual(len(status), 1)
        self.assertFalse(status[0]["active"])
        self.assertIn("故意不可用", status[0]["reason"])
        # 状态已写入 service
        self.assertEqual(svc.collection_status, status)
        # 无线程，stop() 应立即返回、不报错
        runner.stop()

    def test_default_build_does_not_crash_on_probe(self):
        # 回归锁：CollectorRunner 不能把 command=None 传给 ConntrackCollector，
        # 否则非 demo 模式服务起不来。默认构造应平滑 probe 出「不可用」而非崩溃。
        svc = HomewardService(config={"load_system_devices": False})
        runner = CollectorRunner(svc)  # 不注入，走真实 _build_collectors
        statuses = runner.start()
        self.assertEqual(len(statuses), 2)  # DNS + conntrack 两个采集器
        runner.stop()


if __name__ == "__main__":
    unittest.main()
