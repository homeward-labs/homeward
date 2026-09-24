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
from typing import Iterable, Optional

from adapters.base import Observation
from rule_engine.engine import FlowRecord

DEFAULT_LOCAL_NETS: tuple[str, ...] = (
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
)

_PRIVATE_CACHE: dict[str, bool] = {}


def is_local_ip(raw: str, local_nets: Iterable[str] = DEFAULT_LOCAL_NETS) -> Optional[bool]:
    """IP 是否属于本地网段。不是合法 IP 时返回 None（表示判断不了）。"""
    if not raw:
        return None
    cached = _PRIVATE_CACHE.get(raw)
    if cached is not None:
        return cached
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return None
    result = any(addr in ipaddress.ip_network(net, strict=False) for net in local_nets)
    _PRIVATE_CACHE[raw] = result
    return result


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
