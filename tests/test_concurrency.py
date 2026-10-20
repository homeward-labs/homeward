"""tests/test_concurrency.py —— 采集线程与快照/查询线程的并发安全。

背景（真实缺陷）：后台 ``_ObservationSaver`` 每 60 秒调一次
``snapshot_observations()``，它遍历设备台账 / 归属缓存 / 告警中心；
同时采集线程在 ``process_flow`` 里往同一批 dict 里塞数据。
Python 在「遍历中 dict 被改大小」时抛
``RuntimeError: dictionary changed size during iteration`` ——
高流量下必现，表现为后台快照线程反复报错、持久化静默失效。

修复方式：读写两侧都持有 ``HomewardService._state_lock``。
本文件用「写线程狂喂 + 读线程狂取」把它钉住，防止将来有人绕过锁改回去。

文件内还有一组 S1-4 竞态修复回归（2026-10-20，``LockedReadPathRaceTest``）：
盯 ``get_blind_spots``（main.py:849）与 ``describe_domain``（main.py:726）
两条读路径的持锁，防回归目标写在该类的 docstring 里。

运行：python -m pytest tests/test_concurrency.py -q
"""
import itertools
import os
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rule_engine.engine import FlowRecord          # noqa: E402
from core.main import HomewardService              # noqa: E402


def _flow(i: int) -> FlowRecord:
    return FlowRecord(
        timestamp=time.time(),
        src_ip=f"10.9.{i // 250}.{i % 250 + 1}",
        dst_ip="93.184.216.34",
        dst_port=443,
        protocol="tcp",
        dns_query=f"d{i % 50}.example.com",
        packet_size=120,
    )


def _flow_new_ip(i: int) -> FlowRecord:
    """与 ``_flow`` 类似，但 src_ip 走 10.99.x.x 示例段且同样逐条递增。

    设备台账按 src_ip 兜底建档：每条新 IP 都是往 ``devices`` dict 里插一把
    新键 —— 台账 dict 持续增大，这正是「遍历中 dict 被改大小」竞态的触发条件。
    """
    return FlowRecord(
        timestamp=time.time(),
        src_ip=f"10.99.{(i // 250) % 256}.{i % 250 + 1}",
        dst_ip="93.184.216.34",
        dst_port=443,
        protocol="tcp",
        dns_query=f"d{i % 50}.example.com",
        packet_size=120,
    )


class SnapshotRaceTest(unittest.TestCase):
    """写线程喂数据 + 读线程取快照：不得抛 RuntimeError"""

    def _run(self, reader, duration=1.2):
        svc = HomewardService(config={"load_system_devices": False,
                                      "actions_db_path": None})
        stop = threading.Event()
        errors = []

        def writer():
            i = 0
            try:
                while not stop.is_set():
                    svc.process_flow(_flow(i))
                    i += 1
            except Exception as exc:          # 写线程自身异常也要被看见
                errors.append(f"writer: {exc!r}")

        def reader_loop():
            try:
                while not stop.is_set():
                    reader(svc)
            except Exception as exc:
                errors.append(f"reader: {exc!r}")

        threads = [threading.Thread(target=writer, daemon=True)]
        threads += [threading.Thread(target=reader_loop, daemon=True) for _ in range(2)]
        for t in threads:
            t.start()
        time.sleep(duration)
        stop.set()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"并发访问出现异常: {errors}")
        self.assertGreater(svc.stats["flows_processed"], 0, "写线程没有真正产生数据")

    def test_snapshot_observations_under_load(self):
        self._run(lambda s: s.snapshot_observations())

    def test_read_views_under_load(self):
        def reader(s):
            s.get_stats()
            s.get_devices()
            s.get_destinations()
            s.get_alerts()
            s.attribution_coverage()

        self._run(reader)

    def test_export_report_under_load(self):
        self._run(lambda s: s.export_report())


class DeviceRefreshTest(unittest.TestCase):
    """设备身份周期刷新（W2 修复，2026-10-19）。

    背景：DHCP 租约 / ARP 原先只在 ``__init__`` 读一次，运行期先被
    ``observe_ip`` 按 IP 兜底建档的设备永远拿不到 MAC —— 真机上设备列表
    一片裸 IP。修复：起一个低频刷新线程重读租约 / ARP，把 IP 兜底设备
    升级回 MAC 主键（device.py ``_attach_mac``）。

    本文件钉住两件事：① 刷新线程的启停生命周期；② 刷新确实发生、
    且确实完成身份升级（用假租约替换真实系统读取，测试 hermetic）。
    """

    LEASE_LINE = (f"{int(time.time()) + 3600} "
                  "aa:bb:cc:00:11:22 192.168.9.10 Bedroom-Cam *\n")

    def _service(self, interval):
        return HomewardService(config={"load_system_devices": False,
                                       "actions_db_path": None,
                                       "device_refresh_interval": interval})

    def test_interval_zero_means_no_thread(self):
        """interval<=0 = 显式关闭刷新；不起线程，停止也要安全"""
        svc = self._service(0)
        self.assertIsNone(svc._device_refresh_thread)
        svc.start_device_refresh()
        self.assertIsNone(svc._device_refresh_thread)
        svc.stop_device_refresh()  # 未启动时调用不得抛

    def test_refresh_upgrades_ip_only_device(self):
        svc = self._service(0.05)
        calls = {"n": 0}

        def fake_load():
            calls["n"] += 1
            svc.device_registry.load_leases(self.LEASE_LINE)
            return {"leases": 1, "arp": 0}

        svc.device_registry.load_from_system = fake_load
        # 先按 IP 兜底建档（模拟采集线程先于租约刷新看到流量）
        dev = svc.device_registry.observe_ip("192.168.9.10")
        self.assertIsNone(dev.mac)

        svc.start_device_refresh()
        try:
            deadline = time.time() + 3
            while time.time() < deadline:
                d = svc.device_registry.get_by_ip("192.168.9.10")
                if d is not None and d.mac:
                    break
                time.sleep(0.02)
        finally:
            svc.stop_device_refresh()

        self.assertGreaterEqual(calls["n"], 1, "刷新线程没有真正跑起来")
        d = svc.device_registry.get_by_ip("192.168.9.10")
        self.assertIsNotNone(d, "升级后按 IP 应仍查得到设备")
        self.assertEqual(d.mac, "aa:bb:cc:00:11:22")
        self.assertEqual(d.key, "aa:bb:cc:00:11:22")
        self.assertNotIn("192.168.9.10", svc.device_registry.devices,
                         "IP 兜底条目必须撤销，同一台设备不能拆成两台")

    def test_stop_is_prompt(self):
        """stop 后线程应很快退出（不得挂 30s 拖住进程退出）"""
        svc = self._service(30)
        svc.start_device_refresh()
        t = svc._device_refresh_thread
        self.assertTrue(t.is_alive())
        t0 = time.time()
        svc.stop_device_refresh()
        self.assertLess(time.time() - t0, 2)
        self.assertFalse(t.is_alive())


class LockedReadPathRaceTest(unittest.TestCase):
    """S1-4 竞态修复回归（2026-10-20）：读路径持锁，并发读写零异常。

    背景（真实缺陷，Vic 在纯净 HEAD 上实测复现，与 S1-4 功能无关）：
    1. ``get_blind_spots()``（main.py:849）要遍历设备台账
       （``device_registry.blind_spots()`` 扫 ``devices`` dict），采集线程
       ``process_flow`` 每见到一个新 src_ip 就往台账插一台设备 —— 无锁遍历
       撞上并发插入即抛
       ``RuntimeError: dictionary changed size during iteration``。
       修复：方法体整体包进 ``with self._state_lock:``。
    2. ``describe_domain()``（main.py:726）同样包上主锁：``attribution`` 无
       自有锁，``resolve()`` 写 ``_cache``、满 4096 时整体 ``clear()``，与
       持锁读方（``get_destinations`` 的 ``resolved_view``、
       ``attribution_coverage`` 的 ``cached_domains`` 等）的迭代相撞，
       同样抛 RuntimeError。

    **防回归目标与检出力边界（重要，改这条测试前务必读完）**：
    · ``test_blind_spots_under_load``：移除 main.py:849 的锁**必红** ——
      该路径是 Python 级列表推导遍历设备台账，字节码边界全是 GIL 切换点，
      拆锁后稳定复现 ``RuntimeError``（实测 3/3，见测试报告负向验证一节）。
    · ``test_describe_domain_new_domains_under_load``：**在标准 GIL 构建上
      没有崩溃检出力** —— 生产读方遍历 ``_cache`` 用的都是
      ``sorted()`` / ``set()`` / ``list()`` 单个 C 调用，C 循环内不释放
      GIL，拆掉 describe_domain 的锁也插不进去（队长侧实测无锁路径 0 错误）。
      本条只做正向断言（并发零异常 + 返回结构不变）；迁 free-threaded
      构建（PEP 703）后才具备崩溃检出力。describe_domain 的锁纪律由
      get_blind_spots 路径的负向验证兜底。

    并发骨架的两个工程细节（缺一个竞态就复现不出来，详见各用例注释）：
    · **预置台账**：``blind_spots()`` 的遍历是纯 Python 循环，时长正比于
      设备数；CPython 的 GIL 默认 5ms 才切换一次线程，台账太小则遍历窗口
      来不及被打断。预置 2 万台后单次盲区遍历 ~4ms。
    · **临时调低 GIL 切换间隔**（``SWITCH_INTERVAL``，跑完还原）：把切换
      间隔压到 1ms，遍历窗口内才必然发生线程切换，写线程的插入才撞得进来。
    """

    DURATION = 1.2              # 与既有用例时长风格一致；单用例含启动 < 2s
    PREPOPULATE_DEVICES = 20000  # 预置台账规模（10.98.x.x 示例段）
    SWITCH_INTERVAL = 0.001     # 临时 GIL 切换间隔（默认 5ms，还原见 _run）

    def _service(self):
        return HomewardService(config={"load_system_devices": False,
                                       "actions_db_path": None})

    @staticmethod
    def _prepopulate_devices(svc, n):
        """预置 n 台 IP 兜底设备（10.98.x.x 示例段，与写线程的 10.99.x.x
        不重叠，保证写线程每条流仍然是「新设备 → 插入新键」）。

        为什么预置：见类 docstring。没有足够多的存量设备，盲区遍历窗口
        远小于 GIL 切换间隔，锁移除也撞不出 RuntimeError。
        """
        reg = svc.device_registry
        for i in range(n):
            reg.observe_ip(f"10.98.{(i // 250) % 256}.{i % 250 + 1}")

    def _run(self, readers, duration=DURATION, with_writer=True,
             prepopulate=0, warm=None):
        """并发骨架：写线程狂喂 + 各读线程按 ``readers`` 规格狂取。

        ``readers``: ``[(线程数, fn), ...]``，``fn(svc, idx)`` 在各自线程里
        循环调用。所有线程的异常都收进 ``errors`` 再统一断言 —— 不让任何
        线程的异常静默丢失。GIL 切换间隔在并发段临时调低、``finally`` 还原。
        """
        svc = self._service()
        if prepopulate:
            self._prepopulate_devices(svc, prepopulate)
        if warm is not None:
            warm(svc)
        stop = threading.Event()
        errors = []

        def writer():
            i = 0
            try:
                while not stop.is_set():
                    svc.process_flow(_flow_new_ip(i))
                    i += 1
            except Exception as exc:          # 写线程自身异常也要被看见
                errors.append(f"writer: {exc!r}")

        def loop(fn, idx):
            try:
                while not stop.is_set():
                    fn(svc, idx)
            except Exception as exc:
                errors.append(f"reader{idx}: {exc!r}")

        threads = []
        if with_writer:
            threads.append(threading.Thread(target=writer, daemon=True))
        idx = 0
        for count, fn in readers:
            for _ in range(count):
                threads.append(
                    threading.Thread(target=loop, args=(fn, idx), daemon=True))
                idx += 1

        old_switch = sys.getswitchinterval()
        sys.setswitchinterval(self.SWITCH_INTERVAL)
        try:
            for t in threads:
                t.start()
            time.sleep(duration)
            stop.set()
            for t in threads:
                t.join(timeout=5)
        finally:
            sys.setswitchinterval(old_switch)

        self.assertEqual(errors, [], f"并发访问出现异常: {errors}")
        return svc

    @staticmethod
    def _check_describe_domain(info, expect_domain):
        """describe_domain 返回值结构：dict + 七个键齐全 + 回显域名正确"""
        if not isinstance(info, dict):
            raise AssertionError(
                f"describe_domain 应返回 dict，得到 {type(info).__name__}")
        for key in ("domain", "organization", "category", "confidence",
                    "known", "side_effects", "explain"):
            if key not in info:
                raise AssertionError(f"describe_domain 返回值缺少键 {key!r}")
        if info["domain"] != expect_domain:
            raise AssertionError(
                f"回显域名应为 {expect_domain!r}，得到 {info['domain']!r}")

    @staticmethod
    def _check_blind_spots(spots):
        """get_blind_spots 返回值结构：list[str]"""
        if not isinstance(spots, list):
            raise AssertionError(
                f"get_blind_spots 应返回 list，得到 {type(spots).__name__}")
        for s in spots:
            if not isinstance(s, str):
                raise AssertionError(
                    f"盲区条目应为 str，得到 {type(s).__name__}")

    @staticmethod
    def _warm_example_domains(svc):
        """预热归属缓存：把 ``_flow_new_ip`` 会用到的 50 个 dns 域名与
        example.com 先解析一遍。

        为什么预热：``attribution_coverage()`` 收尾的
        ``self.attribution.coverage(observed)`` 已在锁内执行（main.py:885），
        首见域名的 ``_cache`` 写入已被主锁序列化，不会与读方相撞。预热仍有意义：
        让运行期 ``_cache`` 基本只读不写，把并发面收敛到「设备台账 + 盲区」这条
        本用例要盯的锁路径上，减少无关抖动、让竞态更容易稳定复现。
        """
        for i in range(50):
            svc.describe_domain(f"d{i}.example.com")
        svc.describe_domain("example.com")

    def test_blind_spots_under_load(self):
        """盯 main.py:849：写线程狂插新设备，读线程狂取盲区 + 域名视图。

        写线程每条流一个新 src_ip（10.99.x.x 轮换）→ 设备台账 dict 持续
        增大；读线程交替调 ``get_blind_spots()``（遍历台账）与
        ``describe_domain("example.com")``（压归属锁 + 校验返回结构）。

        读方结构与规格的出入及原因：规格写「3-5 个读线程都持续调
        get_blind_spots + describe_domain」。实测（见测试报告）：读线程
        全都调 get_blind_spots 时，各自的 ``attribution_coverage`` 段会把
        ``_state_lock`` 占满，写线程被饿死（1.2s 只跑出 ~1.4k 条流），且
        单次盲区遍历窗口远小于 GIL 切换间隔 —— 竞态根本复现不了，那样的
        测试是橡皮图章。故改为 2 个「盲区读线程」+ 2 个「域名读线程」：
        读方合计 4 线程（规格 3-5）、两类调用都在持续发生，同时写线程在
        盲区遍历窗口内拿得到锁、插得了设备。
        """

        def blind_spot_reader(svc, idx):
            self._check_blind_spots(svc.get_blind_spots())
            # example.com 不在归属知识库 → 未知域名 organization=None
            self._check_describe_domain(svc.describe_domain("example.com"),
                                        "example.com")

        def domain_reader(svc, idx):
            self._check_describe_domain(svc.describe_domain("example.com"),
                                        "example.com")

        # 预热归属缓存（见 _warm_example_domains 注释）：把 _cache 的并发写
        # 面从本用例中拿掉，只留设备台账这条要被盯的锁
        svc = self._run([(2, blind_spot_reader), (2, domain_reader)],
                        prepopulate=self.PREPOPULATE_DEVICES,
                        warm=self._warm_example_domains)
        self.assertGreater(svc.stats["flows_processed"], 0,
                           "写线程没有真正产生数据")
        # 结构收尾断言（线程已 join，单线程上下文，确定性强）
        self._check_blind_spots(svc.get_blind_spots())
        info = svc.describe_domain("example.com")
        self._check_describe_domain(info, "example.com")
        self.assertIsNone(info["organization"], "example.com 应查不到归属")

    def test_describe_domain_new_domains_under_load(self):
        """盯 main.py:726（正向）：读线程狂解析**新域名**（写 attribution._cache、
        周期性撞满 4096 触发 clear()），与生产读方全程并发 —— 零异常、结构不变。

        并发双方：
        · 3 个「解析方」：循环 ``describe_domain(<没解析过的新域名>)`` ——
          持续往 ``_cache`` 插新键并周期性清空，正是 describe_domain 的锁
          要序列化的写面；
        · 2 个「读方」：每轮依次调 ``attribution_coverage``（cached_domains）、
          ``get_destinations``（resolved_view）、``snapshot_observations``
          （cached_results）、``export_report``（汇总以上全部）—— 修复注释
          点名的四类持锁读方，逐个校验返回结构。

        **检出力边界（为什么本条拆锁不会红，别误会是橡皮图章）**：
        本 venv 是标准 GIL 构建（CPython 3.13），上述读方遍历 ``_cache``
        用的都是 ``sorted()`` / ``set()`` / ``list()`` 单个 C 调用，C 循环内
        不释放 GIL —— 即使拆掉 describe_domain 的锁，无锁 resolve 的插入 /
        clear() 也插不进这些 C 循环（队长侧两轮实测无锁路径 0 错误；本地对比
        探针同结论：同样的插入方，``sorted(d.items())`` 零错误，而字节码级的
        ``for k in d.keys()`` 立刻抛 RuntimeError）。因此**本条在 GIL 构建上
        没有崩溃检出力，迁 free-threaded 构建（PEP 703）后才具备**。
        describe_domain 的锁纪律由 get_blind_spots 路径
        （``test_blind_spots_under_load``，Python 级列表推导遍历，拆锁 3/3
        复现 RuntimeError）的负向验证兜底；本条作为常驻正向回归 +
        free-threaded 迁移后的预置防线。

        为什么没有 flow 写线程：这里要压的就是归属缓存这条锁，与设备台账
        （上一个用例）解耦。
        """
        seq = itertools.count()   # 全局自增：每个域名都是没解析过的新域名

        def inserter(svc, idx):
            domain = f"d{idx}-{next(seq)}.example.com"
            self._check_describe_domain(svc.describe_domain(domain), domain)

        def production_reader(svc, idx):
            cov = svc.attribution_coverage()
            if not isinstance(cov, dict):
                raise AssertionError(
                    f"attribution_coverage 应返回 dict，得到 {type(cov).__name__}")
            for key in ("total", "hit", "hit_rate", "by_parent"):
                if key not in cov:
                    raise AssertionError(
                        f"attribution_coverage 返回值缺少键 {key!r}")

            dests = svc.get_destinations()
            if not isinstance(dests, dict):
                raise AssertionError(
                    f"get_destinations 应返回 dict，得到 {type(dests).__name__}")
            for key in ("items", "total", "known", "hit_rate"):
                if key not in dests:
                    raise AssertionError(
                        f"get_destinations 返回值缺少键 {key!r}")

            snap = svc.snapshot_observations()
            if not isinstance(snap, dict):
                raise AssertionError(
                    f"snapshot_observations 应返回 dict，得到 {type(snap).__name__}")
            for key in ("version", "devices", "attribution_cache",
                        "unknown_domains", "alerts"):
                if key not in snap:
                    raise AssertionError(
                        f"snapshot_observations 返回值缺少键 {key!r}")

            rep = svc.export_report()
            if not isinstance(rep, dict):
                raise AssertionError(
                    f"export_report 应返回 dict，得到 {type(rep).__name__}")
            for key in ("report", "checkup", "stats", "coverage", "devices",
                        "destinations", "unknown_domains", "alerts",
                        "blind_spots"):
                if key not in rep:
                    raise AssertionError(
                        f"export_report 返回值缺少键 {key!r}")

        svc = self._run([(3, inserter), (2, production_reader)],
                        with_writer=False)
        self.assertGreater(svc.attribution.stats["queries"], 0,
                           "读线程没有真正产生归属查询")


if __name__ == "__main__":
    unittest.main()
