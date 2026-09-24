"""
演示数据：把一段「编造但可信」的家庭网络观测喂进服务（社区版开源范围）

为什么单独成文件
----------------
· Web UI 需要一个能立刻看到东西的入口（`--demo`），否则空面板无法判断渲染是否正常；
· 行为识别必须看「一段时间里的若干次观测」，单条记录判不出任何行为，
  所以演示数据是**按行为特征构造的序列**，不是随机流量；
· 主服务演示（`python -m src.core.main`）与 Web UI 共用同一份，
  避免两处各写一套、日后各自漂移。

两条硬规则
----------
1. **不编造事实数据**。演示设备的 MAC 前缀从真实 OUI 表（`knowledge_base/oui_prefixes.csv`）
   里按厂商名反查得到；表里查不到该厂商时，设备就没有 MAC，宁可显示为裸 IP，
   也不手写一个"看起来对"的前缀 —— 手写错前缀等于给设备贴错标签。
2. **只在演示路径调用**。`seed_demo*` 绝不在生产路径里被调用，
   UI 也不得在真实数据为空时悄悄灌入演示数据 —— 那是造假，不是降级。
"""

import time
from typing import Optional

from rule_engine.engine import FlowRecord

# 演示剧本里的设备：主机名 → (IP, OUI 厂商关键字, 品类关键字)
# 厂商关键字用于在真实 OUI 表里反查前缀，查不到就退化成裸 IP（规则 1）。
DEMO_DEVICES = (
    # hostname,          ip,             vendor keyword,  备注
    ("Bedroom-Cam",     "192.168.1.50", "xiaomi",        "卧室摄像头"),
    ("Livingroom-TV",   "192.168.1.77", "tcl",           "客厅电视"),
    ("Study-Phone",     "192.168.1.100", "huawei",       "书房手机"),
)

# 剧本一：三条互不相关的单条观测（用于演示「单次判定」链路）
INTRO_FLOWS = (
    # ip,              domain,                          size,  说明
    ("192.168.1.100", "api.ad.tuya.com",                1500, "涂鸦广告归因 SDK"),
    ("192.168.1.101", "ot.io.mi.com",                    200, "小米 IoT 核心通道"),
    ("192.168.1.102", "unknown-tracking-domain.xyz",      64, "完全未知域名"),
)

# 剧本二：一台卧室摄像头的一小时 —— 同时干着三件事
CAMERA_IP = "192.168.1.50"
CAMERA_HEARTBEAT = ("track.tuya.com", 60, 30.0, 12)        # 域名, 包大小, 间隔秒, 次数
CAMERA_BULK = ("storage.ml-ops.samsung.com", 300_000, 60.0, 14)
CAMERA_NORMAL = ("ot.io.mi.com", 200, 300.0, 6)            # 应当不产生告警

# 剧本三：客厅电视的 DNS 隧道特征（超长随机子域 + 高频）
TV_IP = "192.168.1.77"
TV_TUNNEL_LABEL = "a" * 58
TV_TUNNEL_TIMES = 8


def _mac_for_vendor(service, keyword: str, suffix: str = "11:22:33") -> str:
    """在真实 OUI 表里按厂商名反查一个前缀，查不到返回空串（宁缺勿编）"""
    table = getattr(service.device_registry, "oui_table", None) or {}
    kw = keyword.lower()
    for (oui, _hint), (vendor, vendor_cn) in sorted(table.items()):
        hay = f"{vendor} {vendor_cn or ''}".lower()
        if kw in hay:
            return f"{oui}:{suffix}"
    return ""


def seed_demo_devices(service, lease_ttl: int = 86400) -> dict:
    """写入演示用的 DHCP 租约，让设备有 MAC / 厂商 / 主机名

    返回 ``{"leases": 导入条数, "devices": [(主机名, IP, MAC 或空)]}``。
    """
    now = int(time.time())
    lines = []
    devices = []
    for hostname, ip, vendor_kw, note in DEMO_DEVICES:
        mac = _mac_for_vendor(service, vendor_kw)
        if not mac:
            # OUI 表里没有这家厂商 —— 就让它当裸 IP 设备，不编前缀
            devices.append((hostname, ip, ""))
            continue
        lines.append(f"{now + lease_ttl} {mac} {ip} {hostname} *")
        devices.append((hostname, ip, mac))

    imported = 0
    if lines:
        imported = service.device_registry.load_leases("\n".join(lines) + "\n")
    return {"leases": imported, "devices": devices}


def seed_demo_flows(service, base: Optional[float] = None) -> dict:
    """喂入演示流量并执行一轮行为识别

    返回统计与「剧本一」的逐条决策，供命令行演示直接打印。
    """
    if base is None:
        base = time.time()

    intro = []
    for i, (ip, domain, size, _note) in enumerate(INTRO_FLOWS):
        flow = FlowRecord(
            timestamp=base + i,
            src_ip=ip, dst_ip=f"203.0.113.{i + 1}",
            dst_port=443, protocol="tcp",
            sni=domain, dns_query=domain,
            packet_size=size, direction="out",
        )
        decision = service.process_flow(flow)
        intro.append({
            "flow": flow,
            "decision": decision,
            "device": service.get_device(ip),
            "attribution": service.describe_domain(domain),
        })

    fed = len(INTRO_FLOWS)

    def burst(domain: str, size: int, step: float, count: int, src: str, dst: str,
              port: int = 443, proto: str = "tcp", offset: float = 0.0) -> int:
        for i in range(count):
            service.process_flow(FlowRecord(
                timestamp=base + offset + i * step,
                src_ip=src, dst_ip=dst, dst_port=port, protocol=proto,
                sni=domain, dns_query=domain, packet_size=size, direction="out",
            ))
        return count

    # 摄像头：正常心跳 / 突发上传 / 正常核心服务（后者应当不告警）
    fed += burst(CAMERA_HEARTBEAT[0], CAMERA_HEARTBEAT[1], CAMERA_HEARTBEAT[2],
                 CAMERA_HEARTBEAT[3], CAMERA_IP, "203.0.113.9")
    fed += burst(CAMERA_BULK[0], CAMERA_BULK[1], CAMERA_BULK[2], CAMERA_BULK[3],
                 CAMERA_IP, "203.0.113.7", offset=100)
    fed += burst(CAMERA_NORMAL[0], CAMERA_NORMAL[1], CAMERA_NORMAL[2],
                 CAMERA_NORMAL[3], CAMERA_IP, "203.0.113.8")

    # 电视：DNS 隧道特征
    for i in range(TV_TUNNEL_TIMES):
        service.process_flow(FlowRecord(
            timestamp=base + 850 + i * 0.2,
            src_ip=TV_IP, dst_ip="",
            dst_port=53, protocol="udp",
            dns_query=f"{TV_TUNNEL_LABEL}.exfil.example.net",
            packet_size=0, direction="out",
        ))
    fed += TV_TUNNEL_TIMES

    new_alerts = service.run_behavior_scan(now=base + 900)

    return {
        "flows": fed,
        "intro": intro,
        "new_alerts": new_alerts,
        "alerts": service.get_alerts(),
    }


def seed_demo(service, base: Optional[float] = None) -> dict:
    """一次性灌入整套演示数据（设备 + 流量 + 行为扫描）"""
    out = {"devices": seed_demo_devices(service)}
    out.update(seed_demo_flows(service, base=base))
    return out
