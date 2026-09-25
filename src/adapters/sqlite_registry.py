"""SQLite 持久化的动作注册表

``ActionRegistry`` 的内存实现进程重启即丢 —— 已生效的阻断规则会变成「孤儿规则」
（重启后 UI / Enforcer 都查不到它，却仍在底层生效）。本模块把 ``_persist`` /
``_evict`` / ``_load_all`` 三个钩子接到 SQLite，使动作记录跨重启存活。

设计要点
--------
- 数据库落在 ``data/``（已被 .gitignore，含用户隐私，绝不入库），默认
  ``data/actions.db``，路径可注入便于测试。
- ``revert_payload`` 是 ``RevertPayload`` 子类实例，用 ``to_dict()`` 序列化成 JSON。
  反序列化时按 ``kind`` 还原具体类；本仓库（社区版）未注册具体子类时，用
  ``_UnknownRevertPayload`` 兜底保留原始字典，绝不丢信息（只是当前环境无法回滚）。
- 写入加锁，允许采集 / API 线程并发访问同一连接。
- 表用 ``ON CONFLICT(action_id) DO UPDATE`` 做覆盖式 UPSERT，与内存端 save() 的
  「覆盖式」语义一致。
"""

import json
import logging
import sqlite3
import threading
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from adapters.base import ActionRegistry, EnforceAction, RevertPayload

logger = logging.getLogger("homeward.adapters.sqlite_registry")


@dataclass
class _UnknownRevertPayload(RevertPayload):
    """反序列化遇到本仓库未注册的 kind（阻断实现在标准版独立仓库）时的兜底载体。

    保留原始字典不丢信息；``is_complete()=False`` 表示该动作在当前环境无法执行回滚，
    调用方据此告知用户「需对应 Enforcer 模块才能撤销」，而不是假装能撤。
    """

    kind = "unknown"
    raw: dict = field(default_factory=dict)

    def is_complete(self) -> bool:
        return False

    def describe(self) -> str:
        k = self.raw.get("kind", "?")
        return f"未知回滚载荷（kind={k}），需对应 Enforcer 模块注册后才可还原 / 回滚"

    def to_dict(self) -> dict:
        return dict(self.raw)


class SqliteActionRegistry(ActionRegistry):
    """``action_id -> EnforceAction`` 的 SQLite 持久化实现"""

    def __init__(self, db_path: "str | Path") -> None:
        super().__init__()
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False：注册表可能被采集 / API 线程共享
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        # 兜底：对象被回收时自动关连接，避免测试 / 短生命周期场景的 ResourceWarning
        weakref.finalize(self, self._conn.close)
        self._lock = threading.Lock()
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS actions ("
            " action_id TEXT PRIMARY KEY,"
            " scope TEXT NOT NULL,"
            " target TEXT NOT NULL,"
            " device_id TEXT,"
            " applied_at REAL,"
            " redeemable_until REAL,"
            " auto_release_at REAL,"
            " revert_payload TEXT"
            ")"
        )
        self._conn.commit()

    # —— 持久化钩子 ——

    def _persist(self, action: EnforceAction) -> None:
        payload = (
            json.dumps(action.revert_payload.to_dict(), ensure_ascii=False)
            if action.revert_payload is not None
            else None
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO actions ("
                " action_id, scope, target, device_id, applied_at,"
                " redeemable_until, auto_release_at, revert_payload"
                ") VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(action_id) DO UPDATE SET"
                " scope=excluded.scope, target=excluded.target,"
                " device_id=excluded.device_id, applied_at=excluded.applied_at,"
                " redeemable_until=excluded.redeemable_until,"
                " auto_release_at=excluded.auto_release_at,"
                " revert_payload=excluded.revert_payload",
                (
                    action.action_id,
                    action.scope,
                    action.target,
                    action.device_id,
                    action.applied_at,
                    action.redeemable_until,
                    action.auto_release_at,
                    payload,
                ),
            )
            self._conn.commit()

    def _evict(self, action_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM actions WHERE action_id=?", (action_id,))
            self._conn.commit()

    def _load_all(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT action_id, scope, target, device_id, applied_at,"
                " redeemable_until, auto_release_at, revert_payload FROM actions"
            ).fetchall()
        out: list = []
        for (
            aid,
            scope,
            target,
            dev,
            applied,
            redeem,
            release,
            payload_json,
        ) in rows:
            payload = self._decode_payload(payload_json)
            out.append(
                EnforceAction(
                    action_id=aid,
                    scope=scope,
                    target=target,
                    device_id=dev,
                    applied_at=applied or 0.0,
                    redeemable_until=redeem,
                    auto_release_at=release,
                    revert_payload=payload,
                )
            )
        return out

    # —— 辅助 ——

    @staticmethod
    def _decode_payload(payload_json: "str | None") -> "RevertPayload | None":
        if not payload_json:
            return None
        try:
            data = json.loads(payload_json)
        except json.JSONDecodeError:
            logger.warning("revert_payload JSON 损坏，丢弃该载荷")
            return None
        try:
            return RevertPayload.from_dict(data)
        except ValueError:
            # 本仓库未注册该 kind：用兜底载体保留原始信息，不丢数据
            return _UnknownRevertPayload(raw=data)

    def close(self) -> None:
        """关闭底层连接（测试 / 重启切换时用）"""
        with self._lock:
            self._conn.close()
