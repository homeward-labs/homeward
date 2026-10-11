"""
「建议阻断」队列持久化测试

🔴 起因（2026-10-11 真机实测）：iStoreOS 上``suggested_rules.json``
**从未生成**，容器重启后建议清零（历史观测在、建议不在）。
根因有两条，都锁进本测试：
1. ``run_server`` 的 finally 从不调 ``service.stop()``，而 ``_save_suggestions()``
   只挂在 ``stop()`` 上 → 退出路径永不落盘；
2. ``service.start()`` 从未被调用 → 启动时也不加载队列。

修法是「周期落盘 + 关闭落盘 + 启动加载」，本测试用真实 ``_record_suggestion``
走一遍，确保**不依赖优雅退出**也能持久化、且重启能读回。

用标准库 unittest（与全仓一致）。
"""

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.main import HomewardService                                           # noqa: E402
from rule_engine.engine import Decision, FlowRecord, RuleHit                   # noqa: E402


def _blocking_decision(domain: str) -> Decision:
    return Decision(
        action="block_soft",
        rule_hits=[RuleHit(
            domain=domain, organization="测试组织", category="telemetry",
            confidence="high", description="遥测", action="block_soft",
            side_effects="停止遥测上报", rule_type="exact",
        )],
        reason=f"{domain} → 测试组织（遥测）",
    )


class SuggestionPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "suggested_rules.json"

    def tearDown(self):
        self.tmp.cleanup()

    def _service(self) -> HomewardService:
        return HomewardService(config={
            "load_system_devices": False,
            "actions_db_path": None,
            "suggestions_path": str(self.path),
            "suggestions_save_every": 3,
        })

    def test_periodic_save_writes_file_without_any_stop_call(self):
        """周期落盘：不调 stop() 也应落盘（真机 bug 的核心回归）"""
        svc = self._service()
        for i in range(3):
            flow = FlowRecord(
                timestamp=1_700_000_000.0 + i, src_ip="192.168.1.9",
                dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
                dns_query=f"t{i}.example.com",
            )
            svc._record_suggestion(flow, _blocking_decision(flow.dns_query))

        self.assertTrue(self.path.exists(), "达到阈值后必须自动落盘")
        saved = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(len(saved), 3)
        self.assertTrue(all(r["status"] == "suggested" for r in saved))

    def test_restart_restores_pending_suggestions(self):
        """重启读回：第二个 service 能加载上一个留下的队列"""
        svc = self._service()
        flow = FlowRecord(
            timestamp=1_700_000_100.0, src_ip="192.168.1.9",
            dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
            dns_query="keep.example.com",
        )
        svc._record_suggestion(flow, _blocking_decision("keep.example.com"))
        svc._save_suggestions()

        reborn = self._service()
        reborn._load_suggestions()
        self.assertEqual(len(reborn.suggested_rules), 1)
        self.assertEqual(reborn.suggested_rules[0]["domain"], "keep.example.com")
        self.assertEqual(reborn.stats["suggestions_pending"], 1)

    def test_load_tolerates_dict_wrapped_and_corrupt_file(self):
        """坏文件 / 新旧两种结构都不该让服务起不来"""
        self.path.write_text(json.dumps({"items": [
            {"domain": "a.example.com", "status": "suggested"},
        ]}), encoding="utf-8")
        svc = self._service()
        svc._load_suggestions()
        self.assertEqual(len(svc.suggested_rules), 1)

        self.path.write_text("{ this is not json", encoding="utf-8")
        svc2 = self._service()
        svc2._load_suggestions()          # 不抛异常即通过
        self.assertEqual(svc2.suggested_rules, [])

    def test_stop_is_callable_and_persists(self):
        """stop() 本身仍能落盘（run_server 的 finally 现在会调它）"""
        svc = self._service()
        flow = FlowRecord(
            timestamp=1_700_000_200.0, src_ip="192.168.1.9",
            dst_ip="1.2.3.4", dst_port=443, protocol="tcp",
            dns_query="one.example.com",
        )
        svc._record_suggestion(flow, _blocking_decision("one.example.com"))
        self.assertFalse(self.path.exists(), "未到阈值本就不落盘")

        asyncio.run(svc.stop())
        self.assertTrue(self.path.exists())


if __name__ == "__main__":
    unittest.main()