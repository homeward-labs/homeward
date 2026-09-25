"""
采集调度层（W5 主线 / 补全 W4 生产可用性）

把已存在的采集器（DnsLogCollector / ConntrackCollector）持续循环起来，
经 analysis.ingest.observation_to_flow 转成 FlowRecord，喂给 HomewardService.process_flow。

为什么单独成模块
----------------
adapters/base.py 文档里规划过「core/collector.py 采集调度层」：采集器只负责「怎么看」，
本模块负责「把看到的持续喂给决策层」。之前缺的正是这一截 —— 导致非 --demo 模式下
service 起来后没有任何数据流入，UI 全空（见 docs/STATUS.md 的 W4/W5 记录）。

能力协商
--------
· DNS（Tier1）是社区版主路径，尽力启动；
· conntrack（Tier2）best-effort：probe 通过才启动，失败则记盲区、绝不阻塞 DNS；
· 任一采集器在 records() 抛异常时捕获并记日志，单采集器炸了不能拖垮整个 UI 服务。
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from adapters.base import Collector, Observation
from analysis.ingest import observation_to_flow
from collectors.conntrack import ConntrackCollector
from collectors.dns import DnsLogCollector

logger = logging.getLogger("homeward.collector")


class CollectorRunner:
    """后台把若干采集器循环喂给 service，是「采集器 → 决策层」缺失的那截泵。"""

    def __init__(
        self,
        service,
        *,
        collectors=None,
        dns_log_path: Optional[str] = None,
        conntrack_command=None,
        poll_interval: float = 0.5,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        """
        Args:
            service: HomewardService 实例（被喂数据的决策层）
            collectors: **测试注入用**，直接给出采集器列表；留空则按能力协商自动选
            dns_log_path: 显式指定 dnsmasq 日志路径（留空按 DEFAULT_LOG_PATHS 探测）
            conntrack_command: 显式指定 conntrack 命令（argv 元组）
            poll_interval: 无新记录时的休眠间隔（秒）
            stop_event: 外部注入的停止信号（留空内部新建）
        """
        self.service = service
        self._inject = collectors
        self.dns_log_path = dns_log_path
        self.conntrack_command = conntrack_command
        self.poll_interval = poll_interval
        self._stop = stop_event or threading.Event()
        self._threads: list[threading.Thread] = []
        self._active: list[Collector] = []

    # —— 采集器选择（能力协商）——
    def _build_collectors(self) -> list[Collector]:
        if self._inject is not None:
            return list(self._inject)
        chosen: list[Collector] = []
        # Tier1 DNS：社区版主路径，尽力启动
        chosen.append(
            DnsLogCollector(log_path=self.dns_log_path, poll_interval=self.poll_interval)
        )
        # Tier2 conntrack：best-effort，构造失败不拖累 DNS
        try:
            # 注意：command 默认是元组，不要传 None 覆盖默认（否则 probe 里
            # ' '.join(None) 直接 TypeError，会让整个服务在非 demo 模式起不来）
            ct_kwargs: dict = {"poll_interval": self.poll_interval}
            if self.conntrack_command is not None:
                ct_kwargs["command"] = self.conntrack_command
            chosen.append(ConntrackCollector(**ct_kwargs))
        except Exception as exc:  # 极少数环境构造即失败
            logger.warning("conntrack 采集器构造失败，仅用 DNS：%s", exc)
        return chosen

    def start(self) -> list[dict]:
        """启动所有「probe 通过」的采集器；返回探针结果供 UI 盲区展示。"""
        status: list[dict] = []
        for collector in self._build_collectors():
            name = type(collector).__name__
            probe = collector.probe()
            if not probe.available:
                logger.warning("%s 不可用：%s（将记为盲区）", name, probe.message)
                status.append({"collector": name, "active": False, "reason": probe.message})
                continue
            status.append({"collector": name, "active": True, "reason": probe.message})
            self._active.append(collector)
            t = threading.Thread(
                target=self._pump, args=(collector,), name=f"hw-{name}", daemon=True
            )
            t.start()
            self._threads.append(t)
            logger.info("%s 已启动：%s", name, probe.message)
        # 写入 service，供 /api/overview 的盲区视图如实展示「我能看多少」
        self.service.collection_status = status
        return status

    def _pump(self, collector: Collector) -> None:
        """单采集器循环：records() → FlowRecord → service.process_flow()"""
        name = type(collector).__name__
        while not self._stop.is_set():
            try:
                for obs in collector.records():
                    if self._stop.is_set():
                        break
                    flow = observation_to_flow(obs)
                    if flow is not None:
                        self.service.process_flow(flow)
            except Exception:  # 单采集器炸了不能把 UI 服务拖垮
                logger.exception("%s 采集循环异常，10s 后重试", name)
                if self._stop.wait(timeout=10):
                    break
        logger.info("%s 采集循环结束", name)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()
        self._active.clear()
