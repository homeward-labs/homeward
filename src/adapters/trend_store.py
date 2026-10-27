"""时间序列趋势数据持久化 — 供 7 天/30 天活跃趋势 + 告警趋势图消费。

设计要点
--------
- **独立表、独立文件**：和 ``observations.db`` 同目录下的 ``trends.db``，完全隔离。
  现有 ObservationStore 升级不碰这个表；旧 observations.db 也不升级 trend_store。
- **采样周期**：由上游 ``_ObservationSaver`` 控制（默认每小时一行）。本模块只负责
  存储 + 读取，不做定时逻辑。
- **保留策略**：30 天（720 小时）上限，超过自动清，避免 SQLite 无限膨胀。
  家庭场景单小时一行、每行 <1KB，30 天 <1MB。
- **取数同源**：由上游传入 stats dict —— 上游从 ``_get_stats_locked()`` /
  ``privacy_checkup()`` 拿，本模块不重复计算，不引入新的依赖链。
- **安全边界**：只存统计数字，不存设备 MAC / 域名内容 —— 就算 trends.db 被导出也
  没有隐私敏感字段（和 ObservationStore 的全量设备/告警快照不同）。
"""

import logging
import sqlite3
import threading
import time
import weakref
from pathlib import Path

logger = logging.getLogger("homeward.adapters.trend_store")

HOUR_SECS = 3600          # 1 小时的秒数
RETENTION_HOURS = 720     # 30 天 = 720 行（上限）


class TrendStore:
    """时间序列统计点 SQLite 存储"""

    def __init__(self, db_path: "str | Path") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        weakref.finalize(self, self._conn.close)
        self._lock = threading.Lock()
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS trend_hourly ("
            " hour_epoch INTEGER PRIMARY KEY,"
            " devices_total INTEGER NOT NULL,"
            " devices_seen_24h INTEGER NOT NULL,"
            " alerts_active INTEGER NOT NULL,"
            " alerts_high INTEGER NOT NULL,"
            " privacy_score INTEGER NOT NULL,"
            " unknown_domains INTEGER NOT NULL,"
            " vendor_hit_rate REAL NOT NULL"
            ")"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_trend_hourly_epoch "
            "ON trend_hourly(hour_epoch)"
        )
        self._conn.commit()

    # —— 写入 ——

    def record_hourly(
        self,
        hour_epoch: int,
        devices_total: int,
        devices_seen_24h: int,
        alerts_active: int,
        alerts_high: int,
        privacy_score: int,
        unknown_domains: int,
        vendor_hit_rate: float,
    ) -> None:
        """写入一条小时统计点。

        ``hour_epoch`` 必须是整点（``int(time.time() / 3600) * 3600``）。
        同一个整点会被覆盖（UPSERT）—— 避免重跑导致重复。
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO trend_hourly ("
                " hour_epoch, devices_total, devices_seen_24h,"
                " alerts_active, alerts_high, privacy_score,"
                " unknown_domains, vendor_hit_rate"
                ") VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(hour_epoch) DO UPDATE SET"
                " devices_total=excluded.devices_total,"
                " devices_seen_24h=excluded.devices_seen_24h,"
                " alerts_active=excluded.alerts_active,"
                " alerts_high=excluded.alerts_high,"
                " privacy_score=excluded.privacy_score,"
                " unknown_domains=excluded.unknown_domains,"
                " vendor_hit_rate=excluded.vendor_hit_rate",
                (
                    hour_epoch,
                    int(devices_total),
                    int(devices_seen_24h),
                    int(alerts_active),
                    int(alerts_high),
                    max(0, min(100, int(privacy_score))),
                    int(unknown_domains),
                    max(0.0, min(1.0, float(vendor_hit_rate))),
                ),
            )
            # 清理超期数据（30 天上限）
            cutoff = int(time.time()) - RETENTION_HOURS * HOUR_SECS
            self._conn.execute(
                "DELETE FROM trend_hourly WHERE hour_epoch < ?", (cutoff,)
            )
            self._conn.commit()

    # —— 读取 ——

    def get_hourly(self, days: int = 7) -> list[dict]:
        """返回最近 ``days`` 天的小时统计点（按 hour_epoch 升序）。

        返回 list[dict]，每条带 epoch 秒 + 可直接转 Date 的 hour_epoch。
        没有数据时返回空 list（不会报错）。
        """
        cutoff = int(time.time()) - days * 24 * HOUR_SECS
        with self._lock:
            rows = self._conn.execute(
                "SELECT hour_epoch, devices_total, devices_seen_24h,"
                " alerts_active, alerts_high, privacy_score,"
                " unknown_domains, vendor_hit_rate"
                " FROM trend_hourly WHERE hour_epoch >= ?"
                " ORDER BY hour_epoch ASC",
                (cutoff,),
            ).fetchall()
        return [
            {
                "hour_epoch": row[0],
                "devices_total": row[1],
                "devices_seen_24h": row[2],
                "alerts_active": row[3],
                "alerts_high": row[4],
                "privacy_score": row[5],
                "unknown_domains": row[6],
                "vendor_hit_rate": row[7],
            }
            for row in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
