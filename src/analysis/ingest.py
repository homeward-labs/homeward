"""
采集层 → 规则层的转换。

为什么需要这一层：采集器吐出的是 ``adapters.base.Observation``（适配器层的中性
观测单元，刻意不与决策层类型耦合），而规则引擎吃的是 ``rule_engine.FlowRecord``。
两者之间原本**没有任何转换代码** —— 采集层的数据根本到不了决策层。这里补上。

方向（direction）怎么定
----------------------
``out`` 表示「家庭设备主动发出」，``in`` 表示「从外面进来的」。
判定依据：源 IP 是否落在本地网段内。

    本地 → 任意   = out    （设备外联、mDNS 组播、DNS 查询都算）
    任意 → 本地   = in     （外网主动连进来）

拿不到本地网段配置时**默认 out**：家卫观测的主体是家庭设备，采集到的绝大多数
记录本来就是设备发出的；默认成 in 会让所有出站行为规则集体失效，那是更糟的错。

丢不起的字段
-----------
DNS 观测没有字节数（dnsmasq 日志里没有），``packet_size`` 记 0 —— 这是**事实缺失**，
不填一个假数字。行为规则里凡是依赖字节数的（如 bulk_upload）天然不会只靠 DNS 命中。
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Iterable, Optional

from adapters.base import Observation
from rule_engine.engine import FlowRecord

DEFAULT_LOCAL_NETS: tuple[str, ...] = (
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
)

@lru_cache(maxsize=4096)
def _classify_local_ip(raw: str, nets: tuple[str, ...]) -> bool:
    "带 LRU 上界的 IP 归属判定；缓存键含网段配置，改配置自动失效。"
    # Stage 6 资源上限：原实现用无界 dict 缓存每个出现过的 IP 字符串，
    # 长时间运行（或日志投毒）会持续吃内存。4096 条足够覆盖家庭场景，
    # 淘汰由 functools 的 LRU 策略处理，热点 IP 不会被整表清空误伤。
    addr = ipaddress.ip_address(raw)
    return any(addr in ipaddress.ip_network(net, strict=False) for net in nets)


def is_local_ip(raw: str, local_nets: Iterable[str] = DEFAULT_LOCAL_NETS) -> Optional[bool]:
    """IP 是否属于本地网段。不是合法 IP 时返回 None（表示判断不了）。"""
    if not raw:
        return None
    try:
        return _classify_local_ip(raw, tuple(local_nets))
    except (ValueError, TypeError):
        # 非法 IP / 非法网段配置：不缓存，保持「判断不了」的既有语义
        return None


def observation_to_flow(
    obs: Observation,
    local_nets: Iterable[str] = DEFAULT_LOCAL_NETS,
) -> Optional[FlowRecord]:
    """把一条观测转成 FlowRecord；无法转换（缺关键字段 / 未知类型）返回 None。"""
    fields = obs.fields or {}
    ts = float(obs.timestamp or 0)

    if obs.kind == "dns":
        domain = (fields.get("domain") or "").strip().rstrip(".") or None
        client_ip = fields.get("client_ip") or obs.device_id or ""
        if not domain or not client_ip:
            return None
        # 反向解析噪声：*.in-addr.arpa / *.ip6.arpa 是 PTR 查询，不是「设备主动访问了谁」。
        # 它们来自路由器/系统自己做的连接反查（DDNS、日志回放等），混进画像会被当成
        # 陌生外联域名刷屏（实机复测出现过 7 个 .arpa）。.arpa 是 RFC 3172 保留的
        # 基础设施 TLD，不存在正常服务域名，整类丢弃安全。collector 层仍按原始观测记录
        # （见 test_collectors），此处只在「画像/未知外联」边界剔除。
        if domain.lower().endswith(".arpa"):
            return None
        return FlowRecord(
            timestamp=ts,
            src_ip=client_ip,
            dst_ip="",
            dst_port=53,
            protocol="udp",
            dns_query=domain,
            sni=None,
            packet_size=0,  # DNS 日志里没有字节数，不编造
            direction="out",
        )

    if obs.kind == "flow":
        src_ip = fields.get("src_ip") or obs.device_id or ""
        dst_ip = fields.get("dst_ip") or ""
        if not src_ip or not dst_ip:
            return None
        src_local = is_local_ip(src_ip, local_nets)
        dst_local = is_local_ip(dst_ip, local_nets)
        if src_local is True and dst_local is False:
            direction = "out"
        elif src_local is False and dst_local is True:
            direction = "in"
        elif src_local is None and dst_local is None:
            direction = "out"  # 判断不了时按设备出站处理，见模块文档
        else:
            # 局域网内部互访：以源端为观测主体，仍记 out（如 mDNS 扫描）
            direction = "out"
        return FlowRecord(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=int(fields.get("dst_port") or 0),
            protocol=(fields.get("proto") or "").lower() or "tcp",
            sni=fields.get("sni") or None,
            dns_query=fields.get("domain") or None,
            packet_size=int(fields.get("bytes") or 0),
            direction=direction,
        )

    return None


def observations_to_flows(
    observations: Iterable[Observation],
    local_nets: Iterable[str] = DEFAULT_LOCAL_NETS,
) -> list[FlowRecord]:
    """批量转换，自动丢掉转不出来的记录"""
    out = []
    for obs in observations:
        flow = observation_to_flow(obs, local_nets)
        if flow is not None:
            out.append(flow)
    return out
