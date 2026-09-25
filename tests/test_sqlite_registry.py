"""
W5 —— SQLite 动作注册表（SqliteActionRegistry）测试

验证「进程重启不丢动作记录，避免孤儿规则」：
- 覆盖式 UPSERT（save 同 id 更新而非新增）
- evict 真删除
- 重启恢复（新实例从同一 db 读回全部）
- revert_payload 往返（已注册子类按 kind 还原）
- 未知 kind 兜底（本仓库未注册 → _UnknownRevertPayload 保留原始信息，不丢数据）
- from_dict 对未知 kind 抛错
- HomewardService 默认接线的是 SQLite 实现 + 启动恢复

用标准库 unittest（与全仓一致）。
"""

import shutil
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from adapters.base import EnforceAction, RevertPayload                          # noqa: E402
from adapters.sqlite_registry import SqliteActionRegistry, _UnknownRevertPayload  # noqa: E402
from core.main import HomewardService                                           # noqa: E402


@dataclass
class _TestPayload(RevertPayload):
    """测试用具体回滚载荷，刻意注册进 RevertPayload 以便验证 from_dict 还原"""
    kind = "test_dns"
    backup_path: str = ""
    entry: str = ""

    def is_complete(self) -> bool:
        return bool(self.backup_path and self.entry)

    def describe(self) -> str:
        return f"删除 {self.entry}（备份于 {self.backup_path}）"


RevertPayload.register(_TestPayload)


def _make_action(action_id, payload=None):
    return EnforceAction(
        action_id=action_id,
        scope="domain",
        target="ads.example.com",
        device_id="aa:bb:cc:dd:ee:ff",
        applied_at=1000.0,
        redeemable_until=1030.0,
        auto_release_at=None,
        revert_payload=payload,
    )


class SqliteActionRegistryTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="homeward_act_"))
        self.db = self.tmp / "actions.db"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_upsert_and_load_roundtrip(self):
        r1 = SqliteActionRegistry(self.db)
        r1.save(_make_action("a1"))
        self.assertEqual(len(r1), 1)
        r1.close()

        # 模拟「进程重启」：新实例读同一 db
        r2 = SqliteActionRegistry(self.db)
        restored = r2.restore_all()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].action_id, "a1")
        self.assertEqual(restored[0].target, "ads.example.com")
        self.assertEqual(restored[0].device_id, "aa:bb:cc:dd:ee:ff")
        r2.close()

    def test_update_overwrites_same_id(self):
        r = SqliteActionRegistry(self.db)
        r.save(_make_action("a1"))
        # 同 id 改 target：应覆盖而非新增
        updated = _make_action("a1")
        updated.target = "tracker.example.com"
        r.save(updated)
        self.assertEqual(len(r), 1)
        r.close()

        r2 = SqliteActionRegistry(self.db)
        restored = r2.restore_all()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].target, "tracker.example.com")
        r2.close()

    def test_evict_removes_row(self):
        r = SqliteActionRegistry(self.db)
        r.save(_make_action("a1"))
        r.save(_make_action("a2"))
        self.assertEqual(len(r), 2)
        r.remove("a1")
        self.assertEqual(len(r), 1)
        self.assertNotIn("a1", r)
        r.close()

        r2 = SqliteActionRegistry(self.db)
        restored = r2.restore_all()
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].action_id, "a2")
        r2.close()

    def test_restart_recovery_multiple(self):
        r = SqliteActionRegistry(self.db)
        for i in range(3):
            r.save(_make_action(f"a{i}"))
        r.close()

        r2 = SqliteActionRegistry(self.db)
        restored = r2.restore_all()
        self.assertEqual({a.action_id for a in restored}, {"a0", "a1", "a2"})
        r2.close()

    def test_payload_roundtrip_registered(self):
        payload = _TestPayload(backup_path="/tmp/bak.conf", entry="address=/ads/0.0.0.0")
        r = SqliteActionRegistry(self.db)
        r.save(_make_action("a1", payload=payload))
        r.close()

        r2 = SqliteActionRegistry(self.db)
        restored = r2.restore_all()
        self.assertEqual(len(restored), 1)
        rp = restored[0].revert_payload
        self.assertIsInstance(rp, _TestPayload)
        self.assertEqual(rp.backup_path, "/tmp/bak.conf")
        self.assertEqual(rp.entry, "address=/ads/0.0.0.0")
        r2.close()

    def test_unknown_kind_falls_back_without_data_loss(self):
        # 用兜底载体存一个本仓库不认识的 kind（标准版 dnsmasq 之类）
        stray = _UnknownRevertPayload(raw={"kind": "dnsmasq", "entry": "x", "backup": "/b"})
        r = SqliteActionRegistry(self.db)
        r.save(_make_action("a1", payload=stray))
        r.close()

        r2 = SqliteActionRegistry(self.db)
        restored = r2.restore_all()
        rp = restored[0].revert_payload
        self.assertIsInstance(rp, _UnknownRevertPayload)
        # 原始字典不丢
        self.assertEqual(rp.raw.get("kind"), "dnsmasq")
        self.assertEqual(rp.raw.get("entry"), "x")
        r2.close()

    def test_from_dict_raises_on_unknown_kind(self):
        with self.assertRaises(ValueError):
            RevertPayload.from_dict({"kind": "no_such_enforcer"})


class ServiceWiresSqliteRegistryTest(unittest.TestCase):
    """HomewardService 默认接线 SQLite 注册表 + 启动恢复"""

    def test_service_uses_sqlite_registry(self):
        svc = HomewardService(config={"load_system_devices": False})
        self.assertIsInstance(svc.action_registry, SqliteActionRegistry)
        # 启动恢复返回列表（可能为空，但类型正确、不崩）
        self.assertIsInstance(svc.action_registry.restore_all(), list)
        svc.action_registry.close()
        # 清理本次在仓库 data/ 下创建的运行时 db
        db = Path(__file__).resolve().parent.parent / "data" / "actions.db"
        if db.exists():
            db.unlink()


if __name__ == "__main__":
    unittest.main()
