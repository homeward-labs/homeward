"""历史库（旁路 data/history.db）测试。

覆盖四块：
1. **写入**：批量 UPSERT 累加、首末时间 MIN/MAX、entity_meta 往返；
2. **保留裁剪**：小时表 7 天、天表 30 天真的生效；
3. **清理联动**：clear 后三张表全空（HTTP 层另有用例）；
4. **时间轴聚合口径**：dns_count/bytes 的来源、零填充、设备过滤、新出现判定；
   外加一条 **30 天窗口性能**用例（打印真实耗时，断言 ≤ 500ms）。
"""

import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from adapters.history_store import (  # noqa: E402
    HistoryBucket,
    HistoryStore,
    day_epoch_of,
    hour_epoch_of,
)
from core.main import HomewardService  # noqa: E402
from rule_engine.engine import FlowRecord  # noqa: E402
from ui import server as ui_server  # noqa: E402


def _bucket(epoch, device, dest, dns=0, byt=0, ts=None, ip="192.168.1.5"):
    ts = epoch if ts is None else ts
    return HistoryBucket(epoch=epoch, device_key=device, device_ip=ip,
                         dest_key=dest, dns_count=dns, bytes=byt,
                         first_ts=ts, last_ts=ts)


class HistoryStoreWriteTest(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="homeward_hist_"))
        self.store = HistoryStore(self.tmp / "history.db")

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_flush_accumulates_same_bucket(self):
        now = time.time()
        h = hour_epoch_of(now)
        b1 = _bucket(h, "aa:bb:cc:dd:ee:ff", "api.tuya.com", dns=3, byt=100, ts=now)
        self.store.flush([b1], [_bucket(day_epoch_of(now), "aa:bb:cc:dd:ee:ff",
                                        "api.tuya.com", dns=3, byt=100, ts=now)])
        # 同一个桶再写一次：必须累加，不能覆盖
        b2 = _bucket(h, "aa:bb:cc:dd:ee:ff", "api.tuya.com", dns=2, byt=200, ts=now + 1)
        self.store.flush([b2], [_bucket(day_epoch_of(now), "aa:bb:cc:dd:ee:ff",
                                        "api.tuya.com", dns=2, byt=200, ts=now + 1)])
        row = self.store._conn.execute(
            "SELECT dns_count, bytes FROM flow_hourly"
            " WHERE hour_epoch=? AND device_key=? AND dest_key=?",
            (h, "aa:bb:cc:dd:ee:ff", "api.tuya.com")).fetchone()
        self.assertEqual(row, (5, 300))

    def test_entity_meta_keeps_first_seen(self):
        now = time.time()
        first = now - 3600
        self.store.flush([_bucket(hour_epoch_of(first), "dev-a", "x.com",
                                  dns=1, ts=first)], [])
        # 一小时后再次出现：first_seen 必须停在第一次，last_seen 前移
        self.store.flush([_bucket(hour_epoch_of(now), "dev-a", "x.com",
                                  dns=1, ts=now)], [])
        row = self.store._conn.execute(
            "SELECT first_seen, last_seen FROM entity_meta"
            " WHERE device_key=? AND dest_key=?", ("dev-a", "x.com")).fetchone()
        self.assertAlmostEqual(row[0], first, places=3)
        self.assertAlmostEqual(row[1], now, places=3)

    def test_retention_prunes_hourly_and_daily(self):
        now = time.time()
        old_h = hour_epoch_of(now - 8 * 86400)   # 超过 7 天 → 应删
        keep_h = hour_epoch_of(now - 6 * 86400)  # 未超 → 应留
        old_d = day_epoch_of(now - 31 * 86400)   # 超过 30 天 → 应删
        keep_d = day_epoch_of(now - 29 * 86400)  # 未超 → 应留
        # 先在「旧时间」落盘（此时按旧时间裁剪，不会删掉这些行）
        self.store.flush([_bucket(old_h, "dev-a", "old.com"),
                          _bucket(keep_h, "dev-a", "keep.com")],
                         [_bucket(old_d, "dev-a", "old.com"),
                          _bucket(keep_d, "dev-a", "keep.com")],
                         now=now - 8 * 86400)
        # 再以「当前时间」触发一次裁剪
        self.store.flush([], [], now=now)
        h_rows = self.store._conn.execute(
            "SELECT hour_epoch FROM flow_hourly ORDER BY hour_epoch").fetchall()
        d_rows = self.store._conn.execute(
            "SELECT day_epoch FROM flow_daily ORDER BY day_epoch").fetchall()
        self.assertEqual([r[0] for r in h_rows], [keep_h])
        self.assertEqual([r[0] for r in d_rows], [keep_d])

    def test_clear_empties_all_tables(self):
        now = time.time()
        self.store.flush([_bucket(hour_epoch_of(now), "dev-a", "x.com", dns=1)],
                         [_bucket(day_epoch_of(now), "dev-a", "x.com", dns=1)])
        self.store.clear()
        for table in ("flow_hourly", "flow_daily", "entity_meta"):
            n = self.store._conn.execute(
                f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            self.assertEqual(n, 0, table)

    def test_window_aggregation(self):
        now = time.time()
        h1 = hour_epoch_of(now - 2 * 3600)
        h2 = hour_epoch_of(now - 1 * 3600)
        self.store.flush([
            _bucket(h1, "dev-a", "api.tuya.com", dns=3, byt=100, ts=now - 2 * 3600),
            _bucket(h2, "dev-a", "api.tuya.com", dns=2, byt=200, ts=now - 3600),
            _bucket(h2, "dev-b", "1.2.3.4:443", dns=0, byt=500, ts=now - 3600,
                    ip="192.168.1.6"),
        ], [])
        data = self.store.get_window("6h", now=now)
        self.assertEqual(data["bucket"], "hour")
        self.assertEqual(data["totals"]["dns_count"], 5)
        self.assertEqual(data["totals"]["bytes"], 800)
        self.assertEqual(data["totals"]["destinations"], 2)
        # Top 目的地按请求次数优先（再按字节）
        self.assertEqual(data["destinations"][0]["dest"], "api.tuya.com")
        self.assertEqual(data["destinations"][0]["dns_count"], 5)
        self.assertEqual(data["destinations"][0]["bytes"], 300)
        self.assertEqual(data["destinations"][0]["device_count"], 1)
        self.assertEqual(data["destinations"][1]["dest"], "1.2.3.4:443")
        self.assertEqual(data["destinations"][1]["device_count"], 1)
        # 零填充：从起点到当前整点连续，且总量落在对应点上
        self.assertGreaterEqual(len(data["points"]), 7)
        self.assertEqual(sum(p["dns_count"] for p in data["points"]), 5)
        self.assertEqual([p["ts"] for p in data["points"]],
                         sorted(p["ts"] for p in data["points"]))
        # 两个目的地都在本窗口首次出现 → 都算「本时段新出现」
        self.assertEqual({d["dest"] for d in data["destinations"]},
                         set(data["new_destinations"]))
        # 带时间序列的目地上限（本轮只有 2 个）
        self.assertEqual({s["dest"] for s in data["series"]},
                         {"api.tuya.com", "1.2.3.4:443"})
        self.assertEqual(sum(p["dns_count"] for p in
                             next(s for s in data["series"]
                                  if s["dest"] == "api.tuya.com")["points"]), 5)

    def test_window_device_filter_and_new_destination_semantics(self):
        now = time.time()
        # dev-a 的老去向：首次出现于 8 小时前（7 天表内，但不在 6h 窗口）
        self.store.flush([_bucket(hour_epoch_of(now - 8 * 3600), "dev-a",
                                  "old.example.com", dns=1, ts=now - 8 * 3600)], [])
        self.store.flush([_bucket(hour_epoch_of(now - 3600), "dev-a",
                                  "old.example.com", dns=2, ts=now - 3600),
                          _bucket(hour_epoch_of(now - 3600), "dev-b",
                                  "new.example.com", dns=4, ts=now - 3600,
                                  ip="192.168.1.6")], [])
        data = self.store.get_window("6h", now=now)
        self.assertIn("new.example.com", data["new_destinations"])
        self.assertNotIn("old.example.com", data["new_destinations"])
        # 设备过滤：dev-b 只看得到自己的去向
        only_b = self.store.get_window("6h", device="dev-b", now=now)
        self.assertEqual([d["dest"] for d in only_b["destinations"]],
                         ["new.example.com"])
        self.assertEqual(only_b["totals"]["dns_count"], 4)
        # 也支持按 IP 过滤（换 IP 前也能追到）
        by_ip = self.store.get_window("6h", device="192.168.1.6", now=now)
        self.assertEqual([d["dest"] for d in by_ip["destinations"]],
                         ["new.example.com"])

    def test_day_bucket_used_for_30d(self):
        now = time.time()
        self.store.flush(
            [_bucket(hour_epoch_of(now - 3600), "dev-a", "x.com", dns=1, byt=10)],
            [_bucket(day_epoch_of(now - 5 * 86400), "dev-a", "x.com", dns=9, byt=90),
             _bucket(day_epoch_of(now), "dev-a", "x.com", dns=1, byt=10)])
        data = self.store.get_window("30d", now=now)
        self.assertEqual(data["bucket"], "day")
        self.assertEqual(data["totals"]["dns_count"], 10)  # 只读天表，不含小时表
        self.assertEqual(data["points"][-1]["dns_count"], 1)
        # 7 天档也走日表（7 个日点足够看趋势，且查询量远小于 168 个小时点）
        self.assertEqual(self.store.get_window("7d", now=now)["bucket"], "day")


class HistoryPerfTest(unittest.TestCase):
    """30 天窗口查询必须 ≤ 500ms（真实耗时打印出来，不靠感觉）。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="homeward_hist_perf_"))
        self.store = HistoryStore(self.tmp / "history.db")
        now = time.time()
        rows = []
        # 40 台设备 × 100 个目的地 × 30 天 = 120,000 行（超过典型家庭 30 天体量）
        day0 = day_epoch_of(now - 30 * 86400)
        for d in range(30):
            epoch = day0 + d * 86400
            for dev in range(40):
                for dest in range(100):
                    rows.append((epoch, f"dev-{dev:02d}", "192.168.1.10",
                                 f"d{dest:03d}.example.com", 10, 4096,
                                 epoch, epoch))
        with self.store._lock:
            self.store._conn.executemany(
                "INSERT INTO flow_daily (day_epoch, device_key, device_ip,"
                " dest_key, dns_count, bytes, first_ts, last_ts)"
                " VALUES (?,?,?,?,?,?,?,?)", rows)
            self.store._conn.commit()

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_30d_query_under_500ms(self):
        t0 = time.perf_counter()
        data = self.store.get_window("30d")
        elapsed = time.perf_counter() - t0
        print(f"\n[PERF] 30d 窗口查询（120,000 行）：{elapsed * 1000:.1f} ms，"
              f"目的地 {data['totals']['destinations']} 个")
        self.assertLess(elapsed, 0.5,
                        f"30 天查询超时：{elapsed * 1000:.1f} ms > 500 ms")


class HistoryClearLinkageApiTest(unittest.TestCase):
    """HTTP 层集成：/api/history 可用 + 清除观测时两个库一起清。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="homeward_hist_api_"))
        cls.store = HistoryStore(cls.tmp / "history.db")
        cls.service = HomewardService(config={
            "load_system_devices": False,
            "actions_db_path": cls.tmp / "actions.db",
            "history_enabled": True,
        })
        cls.httpd = ui_server.make_server(
            cls.service, host="127.0.0.1", port=0, history_store=cls.store)
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

        # 喂两条观测并立即经「服务 drain → store.flush」落盘（不等 saver 的 60 秒）
        for i, (domain, dns) in enumerate((("api.tuya.com", True),
                                           ("cdn.example.net", False))):
            cls.service.process_flow(FlowRecord(
                timestamp=time.time() - 60 + i * 10,
                src_ip="192.168.1.5",
                dst_ip="" if dns else "10.0.0.9",
                dst_port=53 if dns else 443,
                protocol="udp" if dns else "tcp",
                dns_query=domain,
                packet_size=0 if dns else 2048,
            ))
        hourly, daily = cls.service.drain_history()
        cls.store.flush(hourly, daily)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        cls.store.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _get_json(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))

    def test_history_endpoint_and_clear_linkage(self):
        status, data = self._get_json("/api/history?range=24h")
        self.assertEqual(status, 200)
        self.assertEqual(data["totals"]["destinations"], 2)
        # DNS 事件记请求次数，conntrack 只记流量 —— 不出现「连接数」
        by_dest = {d["dest"]: d for d in data["destinations"]}
        self.assertGreaterEqual(by_dest["api.tuya.com"]["dns_count"], 1)
        self.assertEqual(by_dest["cdn.example.net"]["dns_count"], 0)
        self.assertEqual(by_dest["cdn.example.net"]["bytes"], 2048)
        self.assertNotIn("connections", data)
        self.assertNotIn("连接数", json.dumps(data, ensure_ascii=False))

        # 清除观测：observations.db 与 history.db 必须一起清
        req = urllib.request.Request(self.base + "/api/observations/clear",
                                     data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            self.assertEqual(r.status, 200)
        status, data = self._get_json("/api/history?range=24h")
        self.assertEqual(status, 200)
        self.assertEqual(data["destinations"], [])
        self.assertEqual(data["totals"]["dns_count"], 0)
        # 内存桶也清了：再 drain 一次不应吐出旧数据
        hourly, daily = self.service.drain_history()
        self.assertEqual(hourly, [])
        self.assertEqual(daily, [])


class HistoryEndpointDisabledTest(unittest.TestCase):
    """未启用历史库时接口返回 404，前端据此显示「未启用」而不是空数据。"""

    def test_404_when_store_missing(self):
        tmp = Path(tempfile.mkdtemp(prefix="homeward_hist_off_"))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        svc = HomewardService(config={"load_system_devices": False,
                                      "actions_db_path": tmp / "actions.db"})
        httpd = ui_server.make_server(svc, host="127.0.0.1", port=0)
        self.addCleanup(httpd.server_close)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.shutdown)
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/history?range=24h", timeout=5)
            self.fail("应返回 404")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)
        finally:
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
