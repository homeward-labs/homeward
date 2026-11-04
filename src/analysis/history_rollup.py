"""历史累加器 —— 热路径只做内存自增，不写库、不加锁。

为什么单独一层
--------------
``HomewardService._process_flow_locked`` 已经在 ``_state_lock`` 内，**绝不能再在
每条流量上做 SQLite 写入**：家庭网关上流量是每秒几十到几百条，一次 ``commit``
就足以让采集线程掉队。所以这里只做两件事：

1. 把一条 ``FlowRecord`` 归到「当前小时 × 设备 × 去向」与「当天 × 设备 × 去向」
   两个内存桶里，``dns_count`` / ``bytes`` / 首末时间自增；
2. 由 ``_ObservationSaver`` 每 60 秒调用 ``drain()`` 一次性取走并清空，交给
   ``HistoryStore.flush`` 批量 UPSERT。

线程安全
--------
``add()`` 要求调用方**已持有 ``HomewardService._state_lock``**（生产路径天然满足），
因此内存桶本身不加锁；``drain()`` 由 ``HomewardService.drain_history()`` 在同一把
锁内调用后交换，不存在「边遍历边改写」的竞态。热路径的锁开销为零。

计量口径（硬规则）
------------------
conntrack 是快照轮询、只报**新增字节**，所以：

- ``dns_count`` 只在 DNS 查询 / SNI 事件上 +1；
- ``bytes`` 累加 ``flow.packet_size``（conntrack 增量字节）；
- **FlowRecord 的条数永远不是「连接数」**，任何文案不得这么写。
"""

import logging
import time
from typing import Optional

from adapters.history_store import HistoryBucket

logger = logging.getLogger("homeward.analysis.history_rollup")

MAX_KEYS_PER_HOUR = 5000          # 单小时桶键上限
MAX_KEYS_PER_DAY_FACTOR = 6       # 天桶上限 = 小时上限 × 6（覆盖一天的长尾去向）


class HistoryRollup:
    """有界内存累加器：小时桶 + 天桶"""

    def __init__(self, max_keys: int = MAX_KEYS_PER_HOUR) -> None:
        self.max_hour_keys = max(1, int(max_keys))
        self.max_day_keys = self.max_hour_keys * MAX_KEYS_PER_DAY_FACTOR
        self._hour: dict[tuple, HistoryBucket] = {}
        self._day: dict[tuple, HistoryBucket] = {}
        self.dropped = 0              # 因超上限被丢弃的新键数（用于观测「有没有爆表」）
        self._warned_hour = 0         # 上一次告警的小时，避免刷屏

    # ---------------------------------------------------------------- 热路径

    @staticmethod
    def _is_dns_event(flow) -> bool:
        """是不是「DNS 查询 / SNI 事件」（只有这类才计 dns_count）。

        DNS 采集器产出的 FlowRecord 固定 ``dst_ip=""``、``dst_port=53``；
        conntrack 流量即使被回填了域名，也**不算**一次 DNS 查询。
        """
        if getattr(flow, "sni", None):
            return True
        return int(getattr(flow, "dst_port", 0) or 0) == 53 and not getattr(flow, "dst_ip", "")

    @staticmethod
    def dest_key(flow) -> Optional[str]:
        """去向归一化：dns_query > sni > dst_ip:port；都没有则不记账。"""
        dom = getattr(flow, "dns_query", None) or getattr(flow, "sni", None)
        if dom:
            return str(dom).strip().lower()
        ip = getattr(flow, "dst_ip", "") or ""
        if not ip:
            return None
        port = int(getattr(flow, "dst_port", 0) or 0)
        return f"{ip.lower()}:{port}" if port else ip.lower()

    def add(self, flow, device) -> None:
        """累加一条流量（调用方必须已持有服务状态锁）"""
        ts = float(getattr(flow, "timestamp", 0) or time.time())
        dest = self.dest_key(flow)
        if not dest:
            return
        dkey = str(getattr(device, "key", "") or getattr(flow, "src_ip", "") or "")
        if not dkey:
            return
        ip = str(getattr(flow, "src_ip", "") or "")
        is_dns = self._is_dns_event(flow)
        size = max(0, int(getattr(flow, "packet_size", 0) or 0))

        lt = time.localtime(ts)
        hour = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour,
                                0, 0, 0, 0, -1)))
        day = int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0,
                               0, 0, 0, 0, -1)))

        self._bump(self._hour, hour, dkey, ip, dest, is_dns, size, ts,
                   self.max_hour_keys)
        self._bump(self._day, day, dkey, ip, dest, is_dns, size, ts,
                   self.max_day_keys)

    def _bump(self, buckets, epoch, dkey, ip, dest, is_dns, size, ts, cap) -> None:
        key = (epoch, dkey, dest)
        bucket = buckets.get(key)
        if bucket is None:
            if len(buckets) >= cap:
                # 有界优先：满了就丢**新键**，不做 O(n) 淘汰扫描（热路径不能有全表扫）。
                # 每个小时只告警一次，避免日志被刷爆。
                self.dropped += 1
                if self._warned_hour != epoch:
                    self._warned_hour = epoch
                    logger.warning(
                        "历史累加器键数达上限（%d），本小时起丢弃新的去向键；"
                        "详情见 history.db 保留策略", cap)
                return
            bucket = HistoryBucket(epoch=epoch, device_key=dkey, device_ip=ip,
                                   dest_key=dest, first_ts=ts, last_ts=ts)
            buckets[key] = bucket
        if is_dns:
            bucket.dns_count += 1
        bucket.bytes += size
        if ts < bucket.first_ts:
            bucket.first_ts = ts
        if ts > bucket.last_ts:
            bucket.last_ts = ts

    # ---------------------------------------------------------------- 周期性

    def drain(self) -> "tuple[list[HistoryBucket], list[HistoryBucket]]":
        """取走并清空全部内存桶（调用方须持服务状态锁）。"""
        hourly = list(self._hour.values())
        daily = list(self._day.values())
        self._hour = {}
        self._day = {}
        return hourly, daily

    def clear(self) -> None:
        """清空内存桶（随「清除观测记录」联动）。"""
        self._hour = {}
        self._day = {}

    def pending(self) -> int:
        """尚未落盘的桶数（小时桶与天桶，两者独立累加，不是同一批数据的两份）。"""
        return len(self._hour) + len(self._day)
