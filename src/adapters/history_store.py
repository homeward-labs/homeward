"""旁路历史库 —— 有界流量历史（小时 / 天）+ 首访语义。

设计边界
--------
- **完全不碰 ``observations.db``**：那边的 ``observation_state`` 依旧是单 slot 全量
  覆盖快照（见 ``sqlite_registry.py``），schema 与写入方式零改动。本模块是**旁路**：
  同一目录下独立的 ``data/history.db``，只回答「过去一段时间这条去向出现了多少次」。
- **计量口径是硬规则**：conntrack 是快照轮询、只上报增量字节（见
  ``collectors/conntrack.py``），因此这里只累加两个量：
  ``dns_count``（DNS 查询/SNI 事件次数）与 ``bytes``（增量字节）。
  **绝不把 FlowRecord 条数当连接数**；任何 UI/API 文案都不得出现「连接数」。
- **两张表 + 一张首访表**：``flow_hourly`` 保留 7 天、``flow_daily`` 保留 30 天，
  ``entity_meta`` 只记「某设备某去向第一次/最后一次出现」，用于「本时段新出现」，
  并随「清除观测记录」一起清空。
- **写入由 saver 批量完成**：热路径只在内存字典自增（见 ``analysis/history_rollup.py``），
  本模块的 ``flush`` 由 ``_ObservationSaver`` 每 60 秒调用一次，``executemany`` 批量
  UPSERT，不逐条提交。

键与时间口径
------------
- ``hour_epoch`` / ``day_epoch`` 都是**本地时区**的整点 / 零点 epoch 秒，方便前端
  直接按本地日期展示；家庭场景无夏令时切换（若部署在夏令时区，日界会按本地零点）。
- ``dest_key`` 归一化优先级：``dns_query`` > ``sni`` > ``dst_ip:port``（全部小写）。
- ``device_key`` 用设备台账主键（已识别 MAC 时就是 MAC），并冗余一列 ``device_ip``，
  便于按 IP 追查「同一台设备换 IP 前」的历史。
"""

import logging
import sqlite3
import threading
import time
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger("homeward.adapters.history_store")

HOUR_SECS = 3600
DAY_SECS = 86400

RETENTION_HOURS_DAYS = 7       # flow_hourly 保留 7 天
RETENTION_DAILY_DAYS = 30      # flow_daily 保留 30 天
PRUNE_INTERVAL_SECS = 3600     # 每小时最多裁剪一次，避免每次 flush 都删
MAX_ENTITY_ROWS = 20000        # entity_meta 行数上限（首访语义需要长期保留）

# range → (跨度秒数, 使用的表 / 桶粒度)。不少于 1h / 6h / 24h / 7d 四档；
# 30d 走日表（小时表只留 7 天，不能支撑 30 天窗口）。
RANGES = {
    "1h": (HOUR_SECS, "hour"),
    "6h": (6 * HOUR_SECS, "hour"),
    "24h": (24 * HOUR_SECS, "hour"),
    # 7d / 30d 走日表：7 天 = 7 个日点足够看趋势，且查询量从「168 小时 × 设备 × 去向」
    # 降到「7 天 × 设备 × 去向」（实测 672k 行小时表 1.2s → 28k 行日表 ~40ms）
    "7d": (7 * DAY_SECS, "day"),
    "30d": (30 * DAY_SECS, "day"),
}

MAX_DESTINATIONS = 200   # 单次查询返回的目地上限（按次数排序后的长尾不返回）
MAX_SERIES = 20          # 带逐桶时间序列的目地上限（控制响应体大小）


@dataclass
class HistoryBucket:
    """一个「时间桶 × 设备 × 去向」的累计量。

    由 ``analysis.history_rollup.HistoryRollup`` 在内存中累加，由 ``HistoryStore.flush``
    批量落盘。``epoch`` 语义随表而定：入 ``flow_hourly`` 时是整点，入 ``flow_daily``
    时是零点。
    """

    epoch: int
    device_key: str
    device_ip: str
    dest_key: str
    dns_count: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0


# ---------------------------------------------------------------- 时间对齐

def _local_epoch(ts: float, daily: bool) -> int:
    lt = time.localtime(ts)
    parts = (lt.tm_year, lt.tm_mon, lt.tm_mday,
             0 if daily else lt.tm_hour, 0, 0, 0, 0, -1)
    return int(time.mktime(parts))


def hour_epoch_of(ts: float) -> int:
    """本地时区的整点 epoch"""
    return _local_epoch(ts, daily=False)


def day_epoch_of(ts: float) -> int:
    """本地时区的零点 epoch"""
    return _local_epoch(ts, daily=True)


# ---------------------------------------------------------------- 存储

class HistoryStore:
    """有界流量历史 SQLite 存储（读 + 批量写 + 保留裁剪）"""

    def __init__(
        self,
        db_path: "str | Path",
        *,
        hourly_days: int = RETENTION_HOURS_DAYS,
        daily_days: int = RETENTION_DAILY_DAYS,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.hourly_retention = max(1, int(hourly_days)) * 24 * HOUR_SECS
        self.daily_retention = max(1, int(daily_days)) * DAY_SECS
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        weakref.finalize(self, self._conn.close)
        self._lock = threading.Lock()
        self._last_prune = 0.0
        # WAL：读写不互相堵死；synchronous=NORMAL 足够应对「进程被杀」场景
        # （历史数据可丢最后一个未 flush 的 60 秒，但不能拖慢热路径）。
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:  # 极端只读挂载等场景：不因此拒绝启动
            logger.warning("history.db 无法启用 WAL（继续以默认模式运行）")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS flow_hourly ("
            " hour_epoch INTEGER NOT NULL,"
            " device_key TEXT NOT NULL,"
            " device_ip TEXT NOT NULL,"
            " dest_key TEXT NOT NULL,"
            " dns_count INTEGER NOT NULL DEFAULT 0,"
            " bytes INTEGER NOT NULL DEFAULT 0,"
            " first_ts REAL NOT NULL DEFAULT 0,"
            " last_ts REAL NOT NULL DEFAULT 0,"
            " PRIMARY KEY (hour_epoch, device_key, dest_key)"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS flow_daily ("
            " day_epoch INTEGER NOT NULL,"
            " device_key TEXT NOT NULL,"
            " device_ip TEXT NOT NULL,"
            " dest_key TEXT NOT NULL,"
            " dns_count INTEGER NOT NULL DEFAULT 0,"
            " bytes INTEGER NOT NULL DEFAULT 0,"
            " first_ts REAL NOT NULL DEFAULT 0,"
            " last_ts REAL NOT NULL DEFAULT 0,"
            " PRIMARY KEY (day_epoch, device_key, dest_key)"
            ")"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS entity_meta ("
            " device_key TEXT NOT NULL,"
            " dest_key TEXT NOT NULL,"
            " first_seen REAL NOT NULL,"
            " last_seen REAL NOT NULL,"
            " PRIMARY KEY (device_key, dest_key)"
            ")"
        )
        # 只保留主键索引（时间范围扫描）+ 首访表的目的地索引。
        # 刻意**不建** dest/device 二级索引：实测 30 天 120k 行时，二级索引做
        # GROUP BY 反而走「索引回表 + 临时 B 树」，1.0s；改为整表顺序扫描 + 临时
        # B 树只要 ~90ms（见 get_window 里的 NOT INDEXED 说明）。
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_entity_meta_dest "
            "ON entity_meta(dest_key)"
        )
        self._conn.commit()

    # ---------------------------------------------------------------- 写入

    def flush(
        self,
        hourly: Iterable[HistoryBucket],
        daily: Iterable[HistoryBucket],
        *,
        now: Optional[float] = None,
    ) -> dict:
        """批量 UPSERT 小时桶 / 天桶，并按保留策略裁剪。

        同一个桶键重复写入时**累加** ``dns_count`` / ``bytes``，首末时间取 MIN/MAX ——
        这样进程重启、saver 重跑都不会把已落盘的量覆盖掉。
        """
        now = time.time() if now is None else now
        h_rows = [
            (b.epoch, b.device_key, b.device_ip, b.dest_key,
             int(b.dns_count), int(b.bytes), float(b.first_ts), float(b.last_ts))
            for b in hourly if b.dest_key
        ]
        d_rows = [
            (b.epoch, b.device_key, b.device_ip, b.dest_key,
             int(b.dns_count), int(b.bytes), float(b.first_ts), float(b.last_ts))
            for b in daily if b.dest_key
        ]
        stats = {"hourly": len(h_rows), "daily": len(d_rows)}
        with self._lock:
            if h_rows:
                self._conn.executemany(
                    "INSERT INTO flow_hourly ("
                    " hour_epoch, device_key, device_ip, dest_key,"
                    " dns_count, bytes, first_ts, last_ts"
                    ") VALUES (?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(hour_epoch, device_key, dest_key) DO UPDATE SET"
                    " dns_count=flow_hourly.dns_count+excluded.dns_count,"
                    " bytes=flow_hourly.bytes+excluded.bytes,"
                    " device_ip=excluded.device_ip,"
                    " first_ts=MIN(flow_hourly.first_ts, excluded.first_ts),"
                    " last_ts=MAX(flow_hourly.last_ts, excluded.last_ts)",
                    h_rows,
                )
                # 首访语义只用小时桶（最新鲜），天桶重复写入不影响 MIN/MAX
                self._conn.executemany(
                    "INSERT INTO entity_meta (device_key, dest_key, first_seen, last_seen)"
                    " VALUES (?,?,?,?)"
                    " ON CONFLICT(device_key, dest_key) DO UPDATE SET"
                    " first_seen=MIN(entity_meta.first_seen, excluded.first_seen),"
                    " last_seen=MAX(entity_meta.last_seen, excluded.last_seen)",
                    [(b.device_key, b.dest_key, float(b.first_ts), float(b.last_ts))
                     for b in hourly if b.dest_key],
                )
            if d_rows:
                self._conn.executemany(
                    "INSERT INTO flow_daily ("
                    " day_epoch, device_key, device_ip, dest_key,"
                    " dns_count, bytes, first_ts, last_ts"
                    ") VALUES (?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(day_epoch, device_key, dest_key) DO UPDATE SET"
                    " dns_count=flow_daily.dns_count+excluded.dns_count,"
                    " bytes=flow_daily.bytes+excluded.bytes,"
                    " device_ip=excluded.device_ip,"
                    " first_ts=MIN(flow_daily.first_ts, excluded.first_ts),"
                    " last_ts=MAX(flow_daily.last_ts, excluded.last_ts)",
                    d_rows,
                )
            if now - self._last_prune >= PRUNE_INTERVAL_SECS:
                stats["pruned"] = self._prune_locked(now)
            self._conn.commit()
        return stats

    def _prune_locked(self, now: float) -> dict:
        """按表裁剪（调用方必须已持锁）：小时表 7 天、天表 30 天、首访表行数上限。"""
        h_cutoff = int(now) - self.hourly_retention
        d_cutoff = int(now) - self.daily_retention
        h_deleted = self._conn.execute(
            "DELETE FROM flow_hourly WHERE hour_epoch < ?", (h_cutoff,)
        ).rowcount
        d_deleted = self._conn.execute(
            "DELETE FROM flow_daily WHERE day_epoch < ?", (d_cutoff,)
        ).rowcount
        # 首访表：按「最近一次出现」淘汰最久未活跃的行，保证 first_seen 长期可用
        # 但总行数有界（家庭场景几乎永远碰不到上限）。
        total = self._conn.execute(
            "SELECT COUNT(*) FROM entity_meta").fetchone()[0]
        e_deleted = 0
        if total > MAX_ENTITY_ROWS:
            e_deleted = self._conn.execute(
                "DELETE FROM entity_meta WHERE rowid IN ("
                " SELECT rowid FROM entity_meta"
                " ORDER BY last_seen ASC LIMIT ?)",
                (total - MAX_ENTITY_ROWS,),
            ).rowcount
        self._last_prune = now
        if h_deleted or d_deleted or e_deleted:
            logger.info("历史库裁剪：小时表 -%d、天表 -%d、首访表 -%d 行",
                        h_deleted, d_deleted, e_deleted)
        return {"hourly": h_deleted, "daily": d_deleted, "entity": e_deleted}

    def clear(self) -> None:
        """清空三张表（随「清除观测记录」联动调用，保证新旧数据不混）。"""
        with self._lock:
            self._conn.execute("DELETE FROM flow_hourly")
            self._conn.execute("DELETE FROM flow_daily")
            self._conn.execute("DELETE FROM entity_meta")
            self._conn.commit()
            self._last_prune = 0.0

    # ---------------------------------------------------------------- 读取

    def get_window(
        self,
        range_key: str = "24h",
        *,
        device: Optional[str] = None,
        now: Optional[float] = None,
    ) -> dict:
        """按时间窗口聚合：总量时间序列 + 逐目的地汇总 + Top 目的地时间序列。

        ``device`` 同时匹配 ``device_key`` 与 ``device_ip``（设备换 IP 后仍能追到）。
        返回结构（前端直接消费）::

            {
              "range": "24h", "range_start": <epoch>, "bucket": "hour",
              "points":   [{"ts": ..., "dns_count": n, "bytes": b}, ...],
              "destinations": [{"dest": ..., "dns_count": n, "bytes": b,
                                "device_count": k, "first_seen": ts}, ...],
              "series":   [{"dest": ..., "points": [{ts, dns_count, bytes}]}, ...],
              "totals":   {"dns_count": n, "bytes": b, "destinations": k},
              "new_destinations": ["...", ...],
            }
        """
        now = time.time() if now is None else now
        span, unit = RANGES.get(range_key, RANGES["24h"])
        if unit == "day":
            table, epoch_col, step = "flow_daily", "day_epoch", DAY_SECS
            start_aligned = day_epoch_of(now - span)
        else:
            table, epoch_col, step = "flow_hourly", "hour_epoch", HOUR_SECS
            start_aligned = hour_epoch_of(now - span)
        start = now - span

        where = [f"{epoch_col} >= ?"]
        params: list = [start_aligned]
        if device:
            where.append("(device_key = ? OR device_ip = ?)")
            params += [device, device]
        where_sql = " AND ".join(where)

        with self._lock:
            # 为什么不建 dest 二级索引：30 天 120k 行时，按 dest 分组若走二级索引会
            # 「逐条回表 + 临时 B 树」≈1.0s；只有主键（时间）索引时是「一次范围顺序扫
            # + 临时 B 树」≈90~140ms。窄窗口（1h）也能只扫该时间段的少量行。
            point_rows = self._conn.execute(
                f"SELECT {epoch_col}, SUM(dns_count), SUM(bytes)"
                f" FROM {table} WHERE {where_sql} GROUP BY {epoch_col}"
                f" ORDER BY {epoch_col}",
                params,
            ).fetchall()
            dest_rows = self._conn.execute(
                f"SELECT dest_key, SUM(dns_count), SUM(bytes),"
                f" COUNT(DISTINCT device_key)"
                f" FROM {table} WHERE {where_sql} GROUP BY dest_key"
                f" ORDER BY SUM(dns_count) DESC, SUM(bytes) DESC, dest_key",
                params,
            ).fetchall()
            top_keys = [r[0] for r in dest_rows[:MAX_SERIES]]
            series_rows = []
            if top_keys:
                placeholders = ",".join("?" * len(top_keys))
                series_rows = self._conn.execute(
                    f"SELECT {epoch_col}, dest_key, SUM(dns_count), SUM(bytes)"
                    f" FROM {table} WHERE {where_sql}"
                    f" AND dest_key IN ({placeholders})"
                    f" GROUP BY {epoch_col}, dest_key"
                    f" ORDER BY {epoch_col}",
                    params + top_keys,
                ).fetchall()
            if top_keys:
                placeholders = ",".join("?" * len(top_keys))
                first_rows = self._conn.execute(
                    "SELECT dest_key, MIN(first_seen), MAX(last_seen)"
                    f" FROM entity_meta WHERE dest_key IN ({placeholders})"
                    + (" AND device_key = ?" if device else "")
                    + " GROUP BY dest_key",
                    top_keys + ([device] if device else []),
                ).fetchall()
            else:
                first_rows = []

        # 零填充总量时间序列：让前端横轴连续，不因空桶导致折线错位
        point_map = {r[0]: (int(r[1] or 0), int(r[2] or 0)) for r in point_rows}
        end_aligned = (day_epoch_of(now) if unit == "day" else hour_epoch_of(now))
        points = []
        for ts in range(int(start_aligned), int(end_aligned) + 1, step):
            dns, byt = point_map.get(ts, (0, 0))
            points.append({"ts": ts, "dns_count": dns, "bytes": byt})

        first_map = {r[0]: float(r[1] or 0) for r in first_rows}
        destinations = [
            {
                "dest": r[0],
                "dns_count": int(r[1] or 0),
                "bytes": int(r[2] or 0),
                "device_count": int(r[3] or 0),
                "first_seen": first_map.get(r[0], 0.0),
            }
            for r in dest_rows[:MAX_DESTINATIONS]
        ]

        series_map: dict[str, list[dict]] = {k: [] for k in top_keys}
        for ts, dest, dns, byt in series_rows:
            series_map.setdefault(dest, []).append(
                {"ts": int(ts), "dns_count": int(dns or 0), "bytes": int(byt or 0)})
        series = [{"dest": k, "points": series_map.get(k, [])} for k in top_keys]

        totals = {
            "dns_count": sum(int(r[1] or 0) for r in point_rows),
            "bytes": sum(int(r[2] or 0) for r in point_rows),
            "destinations": len(dest_rows),
        }
        new_destinations = [
            r[0] for r in dest_rows
            if first_map.get(r[0]) and first_map[r[0]] >= start
        ]
        return {
            "range": range_key,
            "range_start": start,
            "range_end": now,
            "bucket": unit,
            "points": points,
            "destinations": destinations,
            "series": series,
            "totals": totals,
            "new_destinations": new_destinations,
        }

    # ---------------------------------------------------------------- 生命周期

    def close(self) -> None:
        with self._lock:
            self._conn.close()
