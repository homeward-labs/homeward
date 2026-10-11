"""
地址分类：区分「真实局域网设备」与「噪声地址」。

采集层（dnsmasq 日志 / conntrack）会把**一切**出现在报文里的 IP 交给设备发现层，
包括回环、链路本地、组播、广播、未指定地址，甚至解析失败的脏串。这些不是
「局域网里的一台可追踪设备」：硬建档会污染设备列表，还会触发荒谬告警
（如把 SSDP 组播 239.255.255.250 当成「数据外泄目的地」）。

本模块用标准库 ``ipaddress`` 做唯一权威判定；解析失败的串一律按噪声处理
（不建档、不评分），安全第一。

只做纯函数，便于单测（Windows 开发机也能离线跑）。
"""

from __future__ import annotations

import ipaddress

# 受限广播地址（dhcpd / 某些协议会把 255.255.255.255 当成「本网段所有主机」）
_BROADCAST_V4 = ipaddress.IPv4Address("255.255.255.255")


def _ip_or_none(ip) -> "ipaddress.IPv4Address | ipaddress.IPv6Address | None":
    """尝试把串解析成 IP 对象；任何无法解析的（空串 / 主机名 / 压缩异常的 IPv6）返回 None。"""
    if not ip or not isinstance(ip, str):
        return None
    try:
        return ipaddress.ip_address(ip.strip())
    except ValueError:
        return None


def is_address_like(s: str) -> bool:
    """看起来是 IP 地址（v4/v6）而非域名？用于覆盖率分母剔除直连 IP。"""
    return _ip_or_none(s) is not None


def is_loopback(ip: str) -> bool:
    a = _ip_or_none(ip)
    return bool(a and a.is_loopback)


def is_link_local(ip: str) -> bool:
    a = _ip_or_none(ip)
    return bool(a and a.is_link_local)


def is_multicast(ip: str) -> bool:
    a = _ip_or_none(ip)
    return bool(a and a.is_multicast)


def is_unspecified(ip: str) -> bool:
    a = _ip_or_none(ip)
    return bool(a and a.is_unspecified)


def is_private(ip: str) -> bool:
    """RFC1918 私网（含 CGNAT 100.64/10 等）。这是真实局域网设备，不算噪声。"""
    a = _ip_or_none(ip)
    return bool(a and a.is_private)


def is_global(ip: str) -> bool:
    a = _ip_or_none(ip)
    return bool(a and a.is_global)


def is_noise_address(ip: str) -> bool:
    """是否应被设备发现层直接丢弃的噪声地址（不建档、不评分）。

    包括：回环 / 链路本地 / 组播 / 广播 / 未指定，以及**任何无法解析成 IP 的串**
    （脏数据、压缩异常的 IPv6、主机名残留等）—— 这些都不是可追踪的局域网设备，
    建档只会污染设备列表，故一律按噪声处理。

    ⚠️ 不含 RFC1918 私网地址：那是真实设备，必须正常建档。
    """
    a = _ip_or_none(ip)
    if a is None:
        return True
    return (
        a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_unspecified
        or a == _BROADCAST_V4
    )


def is_internal(ip: str) -> bool:
    """是否为「内网 / 非公网可达」地址：私网 + 回环 + 链路本地 + 未指定。

    用于把「不需要归属」的地址（如 192.168.1.1、127.0.0.1、fe80::、.lan 主机名）
    从覆盖率统计里剔除，避免分母被灌水、虚假拉低覆盖率。
    """
    a = _ip_or_none(ip)
    if a is None:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified
