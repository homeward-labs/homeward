"""
离线日志导入（社区版开源范围）

让社区版**无需内联部署**也能「看见」：把一段 dnsmasq 查询日志 / conntrack 快照
（或两者混合）粘贴 / 上传进来，离线回放成观测，走与实时采集完全相同的
``observation_to_flow → process_flow`` 链路。这样用户不用把家卫串进网络、也不用给
读日志权限，就能先体验「看见」能力。

安全与边界
----------
· 这里只是把**用户自己提供的日志**喂进分析层，等价于实时采集器看到的内容，
  不产生任何网络侧改动（社区版「只看见、不拦下」的边界不变）。
· **不导出、不读取知识库**：本模块只处理用户给的原始日志文本，绝不读取或输出
  归属知识库（domains.csv / behaviors.json / oui 表）的内容 —— 知识库是服务器端
  商业机密，客户端不得导出或抓取（见 open-core 边界约定）。
· 文本体量做上限保护，避免内存被打爆（默认 16MiB / 50 万行）。
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from adapters.base import Observation
from analysis.ingest import observation_to_flow
from collectors.conntrack import parse_conntrack_line
from collectors.dns import parse_dnsmasq_line

logger = logging.getLogger("homeward.import_log")

MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_LINES = 500_000


def parse_log_line(line: str) -> Optional[Observation]:
    """把一行日志解析成归一化观测；dnsmasq 与 conntrack 混合识别，都认不出返回 None。"""
    if not line:
        return None
    rec = parse_dnsmasq_line(line)
    if rec is not None:
        return Observation(
            timestamp=rec["timestamp"],
            kind="dns",
            device_id=rec["client_ip"],
            fields={
                "domain": rec["domain"],
                "client_ip": rec["client_ip"],
                "query_type": rec["query_type"],
            },
        )
    rec = parse_conntrack_line(line)
    if rec is not None:
        return Observation(
            timestamp=time.time(),
            kind="flow",
            device_id=rec["src_ip"],
            fields={
                "proto": rec["proto"],
                "src_ip": rec["src_ip"],
                "dst_ip": rec["dst_ip"],
                "src_port": rec["src_port"],
                "dst_port": rec["dst_port"],
                # 离线快照没有增量概念：用累计字节数当作本次观测到的体量（缺失则记 0，不编造）
                "bytes": rec["bytes_total"] or 0,
                "bytes_total": rec["bytes_total"],
                "packets": rec["packets"],
            },
        )
    return None


def import_log_text(text: str, service, *, max_lines: int = MAX_LINES) -> dict:
    """把一段日志文本离线回放进 ``service``。

    Args:
        text: 原始日志（dnsmasq 查询行 / conntrack 行 / 混合），按行切分。
        service: HomewardService 实例（被喂数据的决策层）。
        max_lines: 最多处理行数，超出部分丢弃并计入 ``truncated``。

    Returns:
        统计字典：lines / parsed / flows / new_devices / new_alerts / errors / truncated。
    """
    if text is None:
        text = ""
    raw_bytes = len(text.encode("utf-8", "replace"))
    if raw_bytes > MAX_TEXT_BYTES:
        raise ValueError(
            f"日志过大（{raw_bytes} 字节 > 上限 {MAX_TEXT_BYTES}），请分批导入"
        )

    devices_before = len(service.device_registry.devices)
    alerts_before = len(service.alert_center.active())

    lines = text.splitlines()
    total_lines = len(lines)
    truncated = max(0, total_lines - max_lines)
    if truncated:
        lines = lines[:max_lines]

    stats: dict = {
        "lines": total_lines,
        "truncated": truncated,
        "parsed": 0,
        "flows": 0,
        "errors": 0,
    }
    for line in lines:
        try:
            obs = parse_log_line(line)
        except Exception:  # 单行脏数据不能拖垮整次导入
            stats["errors"] += 1
            continue
        if obs is None:
            continue
        stats["parsed"] += 1
        flow = observation_to_flow(obs)
        if flow is None:
            continue
        stats["flows"] += 1
        try:
            service.process_flow(flow)
        except Exception:
            stats["errors"] += 1

    # 小批量导入也可能产生行为告警，主动跑一轮扫描确保告警生成
    try:
        service.run_behavior_scan()
    except Exception:
        logger.exception("离线导入后行为扫描异常")

    stats["devices_before"] = devices_before
    stats["devices_after"] = len(service.device_registry.devices)
    stats["new_devices"] = max(0, stats["devices_after"] - devices_before)
    stats["alerts_before"] = alerts_before
    stats["alerts_after"] = len(service.alert_center.active())
    stats["new_alerts"] = max(0, stats["alerts_after"] - alerts_before)
    return stats
