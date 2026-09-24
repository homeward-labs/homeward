"""
W2 —— 设备发现：把 IP 变成「这是谁」（社区版开源范围）

为什么需要这一层
----------------
采集层（`src/collectors/`）只知道「哪个 IP 问了哪个域名」。
但人看得懂的是「客厅摄像头」，不是 192.168.1.23。
设备发现做的事：**IP → MAC → 厂商 / 主机名 → 推断品类**，
让后面的告警能说人话、让 UI 能画出「谁在给谁打电话」。

数据来源（**全部本地文件，不联网**）
-----------------------------------
· DHCP 租约：dnsmasq 的 leases 文件（OpenWrt / 家用路由器 / 软路由最常见格式），
  一次拿到 MAC + IP + 主机名三件套，性价比最高。
· ARP 表：`/proc/net/arp`（内核邻居表），补上没有 DHCP 租约的静态 IP 设备。
· OUI 表：`knowledge_base/oui_prefixes.csv`（**可选数据资产**，需另行生成）。

三条硬规则
----------
1. **不猜**。查不到厂商就是 `None`，绝不编一个"看起来合理"的名字 ——
   看不到的地方必须写出来，这是家卫「盲区明示」的一部分。
2. **可解释**。设备类型的推断结果带 `type_source`，UI 要能说明「是根据主机名推断的」，
   而不是摆一个不知从哪来的结论。
3. **可离线测**。解析逻辑抽成纯函数 + fixture，在 Windows 开发机上也能全量单测
   （真机才有的 /proc/net/arp 由 `DeviceRegistry` 负责，逻辑本身不依赖）。
"""

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

# dnsmasq 租约文件的常见位置，按命中概率排序
DEFAULT_LEASES_PATHS = (
    "/tmp/dhcp.leases",                 # OpenWrt / iStoreOS 默认
    "/var/lib/misc/dnsmasq.leases",     # Debian / Ubuntu 常见
    "/var/lib/dnsmasq/dnsmasq.leases",  # 部分发行版
    "/var/db/dnsmasq.leases",           # BSD / macOS 侧载
)
ARP_PATH = "/proc/net/arp"

OUI_CSV = Path(__file__).resolve().parent.parent / "knowledge_base" / "oui_prefixes.csv"

_UNKNOWN_TYPE = "unknown"

# 单台设备最多记多少个去向。家庭场景一台设备通常几十个域名足够，
# 但 DNS 隧道 / 域名生成算法会瞬间刷出海量子域 —— 没有上限的话内存会被打爆。
MAX_DOMAINS_PER_DEVICE = 200


# ---------------------------------------------------------------- 数据结构

@dataclass
class Lease:
    """一条 DHCP 租约"""
    mac: str
    ip: str
    hostname: str = ""
    expires_at: Optional[float] = None  # None 表示静态 / 永不过期

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and self.expires_at < time.time()


@dataclass
class Device:
    """设备台账里的一台设备"""
    key: str                            # 主键：有 MAC 用 MAC，否则退化为 IP
    mac: Optional[str] = None
    ips: set[str] = field(default_factory=set)
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    vendor_cn: Optional[str] = None
    device_type: str = _UNKNOWN_TYPE
    type_source: str = "unknown"        # hostname / vendor / none
    first_seen: float = 0.0
    last_seen: float = 0.0
    # 域名 → 观测次数。UI 的「去向地图」画的就是「这台设备在跟谁说话」，
    # 所以台账必须记住去向；上限见 MAX_DOMAINS_PER_DEVICE（低配设备内存要有界）。
    domains: dict[str, int] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        """给人看的名字：主机名 → 厂商 → IP，都没有就退回 IP"""
        if self.hostname:
            return self.hostname
        if self.vendor_cn or self.vendor:
            return self.vendor_cn or self.vendor
        ip = next(iter(sorted(self.ips)), None)
        return ip or self.key

    def observe_domain(self, domain: str, count: int = 1) -> None:
        """记一次去向。空域名（比如纯 IP 直连）直接跳过 —— 不编造域名。"""
        if not domain:
            return
        self.domains[domain] = self.domains.get(domain, 0) + count
        overflow = len(self.domains) - MAX_DOMAINS_PER_DEVICE
        if overflow > 0:
            # 超出上限就淘汰最早记录的几个。家庭场景几乎碰不到，
            # 但常驻服务的内存必须有界 —— 宁可少记，不能无限涨。
            for k in list(self.domains)[:overflow]:
                self.domains.pop(k, None)

    def top_domains(self, limit: int = 10) -> list[tuple[str, int]]:
        """观测次数最多的若干去向（同次数按域名排序，保证输出稳定）"""
        items = sorted(self.domains.items(), key=lambda kv: (-kv[1], kv[0]))
        return items[:limit]

    def to_dict(self, domain_limit: int = 10) -> dict:
        """给 UI / API 用的视图"""
        return {
            "key": self.key,
            "name": self.display_name,
            "mac": self.mac,
            "ips": sorted(self.ips),
            "hostname": self.hostname,
            "vendor": self.vendor_cn or self.vendor,
            "device_type": self.device_type,
            "type_source": self.type_source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "domain_count": len(self.domains),
            "top_domains": [
                {"domain": d, "count": c} for d, c in self.top_domains(domain_limit)
            ],
        }


# ---------------------------------------------------------------- 纯函数：MAC

def normalize_mac(raw: str) -> str:
    """
    归一化 MAC / MAC 前缀为小写冒号分隔形式。

    同时支持两类输入：
    · 完整 MAC（6 字节）：`AABBCCDDEEFF` / `aa-bb-cc-dd-ee-ff` / `aabb.ccdd.eeff`
    · 厂商前缀（3 字节起）：OUI 表里的 `aa:bb:cc`，以及 manuf 那种带掩码的
      `aa:bb:cc/24`（掩码先剥离，否则 24 会被当成一字节）

    返回实际存在的字节（最多取前 6 个）；不足 3 字节视为非法，返回空串。
    """
    if not raw:
        return ""
    s = re.sub(r"[^0-9a-fA-F]", "", raw.split("/")[0])
    if len(s) < 6 or len(s) % 2:
        return ""
    parts = [s[i:i + 2].lower() for i in range(0, len(s), 2)]
    return ":".join(parts[:6])


def oui_of(mac: str) -> str:
    """取 MAC 的厂商前缀（前三字节）。非法输入返回空串。"""
    n = normalize_mac(mac)
    return n[:8] if n else ""


# ---------------------------------------------------------------- 纯函数：租约 / ARP

def parse_dhcp_leases(text: str) -> list[Lease]:
    """
    解析 dnsmasq 租约文件。

    每行格式（空格分隔）：
        <expiry> <mac> <ip> <hostname> <clientid>
    · expiry 为 Unix 秒；静态（永不过期）租约常见写法是 `*`
      或 dnsmasq 里的一个极大值，统一处理成 None。
    · hostname 缺失时 dnsmasq 写 `*`。
    · 遇到缺字段 / MAC 非法的行，跳过并记日志，不让一条脏数据搞挂整条链路。
    """
    leases: list[Lease] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            logger.warning("租约第 %d 行字段不足，已跳过：%s", lineno, line)
            continue
        mac = normalize_mac(parts[1])
        if not mac:
            logger.warning("租约第 %d 行 MAC 非法，已跳过：%s", lineno, line)
            continue

        expiry_raw, ip = parts[0], parts[2]
        expires_at: Optional[float] = None
        if expiry_raw.isdigit():
            ts = int(expiry_raw)
            # dnsmasq 对静态租约可能写一个很大的值，按 2100 年兜底判为永久
            expires_at = None if ts > 4102444800 else float(ts)

        hostname = parts[3] if len(parts) > 3 and parts[3] != "*" else ""
        leases.append(Lease(mac=mac, ip=ip, hostname=hostname, expires_at=expires_at))
    return leases


def parse_arp_table(text: str) -> dict[str, str]:
    """
    解析 /proc/net/arp，返回 {ip: mac}。

    Flags 为 0x0 表示条目未完成（邻居不可达），这类映射不可信，跳过。
    MAC 全零同样丢弃。
    """
    out: dict[str, str] = {}
    for line in text.splitlines()[1:]:  # 首行是表头
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, flags, mac_raw = parts[0], parts[2], parts[3]
        if flags == "0x0":
            continue
        mac = normalize_mac(mac_raw)
        if not mac or mac == "00:00:00:00:00:00":
            continue
        out[ip] = mac
    return out


# ---------------------------------------------------------------- 纯函数：OUI 表

def parse_oui_table(text: str) -> dict[tuple[str, str], tuple[str, str]]:
    """
    解析 oui_prefixes.csv。

    返回 {(oui, device_hint): (vendor, vendor_cn)} —— 同一前缀可能对应多个 hint，
    查表时按「先精确再前缀」的策略命中（见 lookup_vendor）。
    空表 / 只有表头时返回空 dict，不抛错（识别降级而不是崩掉）。
    """
    rows: list[tuple[str, str, str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = [p.strip() for p in s.split(",")]
        if len(parts) < 4 or parts[0].lower() == "prefix":
            continue  # 表头
        pfx, vendor, vendor_cn, hint = parts[0], parts[1], parts[2], parts[3]
        oui = oui_of(pfx)
        if oui:
            rows.append((oui, vendor, vendor_cn, hint))
    return {(o, h): (v, vc) for o, v, vc, h in rows}


def lookup_vendor(mac: str, table: dict) -> tuple[Optional[str], Optional[str], str]:
    """
    查 MAC 的厂商。

    返回 (vendor, vendor_cn, device_hint)：
    · 优先命中带 device_hint 的条目（说明该厂商专注某品类，信息更具体）；
    · 未命中返回 (None, None, "")，**绝不猜**。
    """
    oui = oui_of(mac)
    if not oui or not table:
        return (None, None, "")
    for o, hint in table:
        if o == oui and hint:
            v, vc = table[(o, hint)]
            return (v, vc, hint)
    for o, hint in table:
        if o == oui:
            v, vc = table[(o, hint)]
            return (v, vc, hint)
    return (None, None, "")


# ---------------------------------------------------------------- 纯函数：品类推断

# 主机名关键词 → 品类。命中才给结论，没命中一律 unknown —— 不做概率性猜测。
_HOSTNAME_TYPE_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("camera", ("cam", "ipc", "ezviz", "hik", "dvr", "nvr", "doorbell", "bell", "萤石", "摄像")),
    ("tv", ("tv", "bravia", "appletv", "mi-tv", "shield", "mediabox", "盒子")),
    ("speaker", ("speaker", "xiaoai", "echo", "homepod", "sonos", "soundbox", "音箱")),
    ("vacuum", ("vacuum", "roborock", "dreame", "sweeper", "扫地")),
    ("bulb", ("bulb", "yeelight", "hue-", "light-", "灯")),
    ("router", ("router", "gateway", "miwifi", "gw-", "ap-")),
    ("phone", ("iphone", "redmi", "pixel", "oneplus", "android")),
    ("pc", ("macbook", "imac", "desktop", "laptop", "pc-")),
)

_VENDOR_TYPE_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("camera", ("hikvision", "ezviz", "dahua", "uniview", "reolink", "imou")),
    ("vacuum", ("roborock", "dreame", "ecovacs")),
    ("tv", ("skyworth", "hisense", "changhong", "konka")),
    ("bulb", ("yeelight", "signify")),
    ("speaker", ("philips",)),
)


def infer_device_type(hostname: Optional[str] = None,
                      vendor: Optional[str] = None,
                      vendor_hint: str = "") -> tuple[str, str]:
    """
    推断设备品类，返回 (device_type, source)。

    优先级：OUI 表自带的 hint > 主机名关键词 > 厂商名关键词 > unknown。
    source 用于 UI 解释「这个结论是怎么来的」—— 家卫要求判定可解释。
    """
    if vendor_hint:
        return (vendor_hint, "vendor_hint")

    host = (hostname or "").lower()
    for dtype, keys in _HOSTNAME_TYPE_PATTERNS:
        if any(k in host for k in keys):
            return (dtype, "hostname")

    ven = (vendor or "").lower()
    for dtype, keys in _VENDOR_TYPE_PATTERNS:
        if any(k in ven for k in keys):
            return (dtype, "vendor")

    return (_UNKNOWN_TYPE, "none")


# ---------------------------------------------------------------- 设备台账

class DeviceRegistry:
    """
    设备台账：合并多处来源，回答「这个 IP / 这条流量属于哪台设备」。

    合并键的选择很关键：**有 MAC 就用 MAC**（换 IP 仍是同一台设备）；
    没有 MAC 时退化为 IP，并在注释里承认这是一种降级。
    """

    def __init__(self,
                 oui_table: Optional[dict] = None,
                 leases_paths: Iterable[str] = DEFAULT_LEASES_PATHS,
                 arp_path: str = ARP_PATH,
                 oui_csv_path: Optional[Path] = None):
        self.oui_table = oui_table if oui_table is not None else self._load_oui(oui_csv_path)
        self.vendor_lookup_enabled = bool(self.oui_table)
        self.leases_paths = list(leases_paths)
        self.arp_path = arp_path
        self.devices: dict[str, Device] = {}
        self._ip_index: dict[str, str] = {}  # ip -> device key

    # ---------- 数据加载 ----------

    @staticmethod
    def _load_oui(csv_path: Optional[Path] = None) -> dict:
        p = Path(csv_path) if csv_path else OUI_CSV
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            logger.warning("未找到厂商表 %s —— 设备识别降级为「只有 IP / 主机名」，"
                           "盲区需在 UI 明示。生成方式见 tools/build_oui_table.py", p)
            return {}
        except OSError as e:
            logger.warning("读取厂商表失败（%s）：%s", p, e)
            return {}
        table = parse_oui_table(text)
        if not table:
            logger.warning("厂商表 %s 为空 —— 未生成真实数据。识别降级，不猜厂商。", p)
        return table

    def load_leases(self, text: str) -> int:
        """导入 DHCP 租约，返回新增/更新的设备数"""
        leases = parse_dhcp_leases(text)
        now = time.time()
        n = 0
        for lh in leases:
            if lh.expired:
                continue  # 过期租约不作为设备身份依据，但仍可能已被 observe_flow 记录为 IP
            dev = self.devices.get(lh.mac)
            if dev is None:
                dev = Device(key=lh.mac, mac=lh.mac, first_seen=now, last_seen=now)
                self.devices[lh.mac] = dev
            if lh.hostname:
                dev.hostname = lh.hostname
            dev.ips.add(lh.ip)
            self._ip_index[lh.ip] = lh.mac
            self._resolve_identity(dev)
            n += 1
        return n

    def load_arp(self, text: str) -> int:
        """导入 ARP 表，给尚无 MAC 的 IP 补上身份"""
        mapping = parse_arp_table(text)
        now = time.time()
        n = 0
        for ip, mac in mapping.items():
            if mac in self.devices:
                self.devices[mac].ips.add(ip)
                self._ip_index[ip] = mac
                continue
            # ARP 里出现的设备未必有租约（静态 IP / 未走 DHCP），也建台账
            dev = Device(key=mac, mac=mac, first_seen=now, last_seen=now)
            self.devices[mac] = dev
            dev.ips.add(ip)
            self._ip_index[ip] = mac
            self._resolve_identity(dev)
            n += 1
        return n

    def load_from_system(self) -> dict[str, int]:
        """
        从本机真实文件加载（Linux 才有，Windows / macOS 会全部落空 —— 这是预期的，
        调用方应按 empty 结果走盲区明示）。返回各来源的条目数便于诊断。
        """
        stat = {"leases": 0, "arp": 0}
        for p in self.leases_paths:
            try:
                text = Path(p).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            stat["leases"] += self.load_leases(text)
            if stat["leases"]:
                break
        try:
            self.load_arp(Path(self.arp_path).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
        return stat

    # ---------- 运行时观察 ----------

    def observe_ip(self, ip: str, ts: Optional[float] = None) -> Device:
        """观察到某个 IP 在活动：更新 last_seen，没有 MAC 身份时先用 IP 兜底"""
        now = ts if ts is not None else time.time()
        key = self._ip_index.get(ip)
        if key and key in self.devices:
            dev = self.devices[key]
            dev.last_seen = now
            return dev
        # 没有任何身份信息的 IP —— 仍然要显示（用户得看到「有个 IP 在说话」），
        # 但明确标记为 unknown，UI 上应当提示「未识别到 MAC / 主机名」。
        dev = self.devices.get(ip)
        if dev is None:
            dev = Device(key=ip, first_seen=now, last_seen=now)
            self.devices[ip] = dev
        dev.ips.add(ip)
        dev.last_seen = now
        return dev

    def observe_flow(self, flow) -> Device:
        """从一条 FlowRecord 更新台账：身份（src_ip）+ 去向（sni / dns_query）"""
        dev = self.observe_ip(flow.src_ip, getattr(flow, "timestamp", None))
        domain = getattr(flow, "sni", None) or getattr(flow, "dns_query", None)
        dev.observe_domain(domain)
        return dev

    def get_by_ip(self, ip: str) -> Optional[Device]:
        key = self._ip_index.get(ip)
        if key:
            return self.devices.get(key)
        return self.devices.get(ip)

    def list_devices(self) -> list[Device]:
        return sorted(self.devices.values(), key=lambda d: d.last_seen, reverse=True)

    def blind_spots(self) -> list[str]:
        """
        当前识别能力的盲区清单 —— 直接给 UI 用。

        家卫的承诺是「看不到的地方要写出来」，设备发现同样适用。
        """
        spots: list[str] = []
        if not self.vendor_lookup_enabled:
            spots.append("未加载 MAC 厂商库：只能靠主机名与 IP 识别设备，"
                         "厂商字段为空。生成方式见 tools/build_oui_table.py。")
        ip_only = [d for d in self.devices.values() if not d.mac]
        if ip_only:
            spots.append(f"{len(ip_only)} 台设备未拿到 MAC（静态 IP / 未走 DHCP / 未同二层），"
                         "只能按 IP 识别，换 IP 会被视为新设备。")
        no_name = [d for d in self.devices.values() if not d.hostname and not d.vendor]
        if no_name:
            spots.append(f"{len(no_name)} 台设备既无主机名也无厂商信息，UI 上只能显示 IP。")
        return spots

    # ---------- 内部 ----------

    def _resolve_identity(self, dev: Device) -> None:
        """按「厂商 → 主机名」补全设备的厂商与品类，互不覆盖已有值"""
        if self.vendor_lookup_enabled and dev.mac and not dev.vendor:
            v, vc, hint = lookup_vendor(dev.mac, self.oui_table)
            dev.vendor, dev.vendor_cn = v, vc
            dtype, source = infer_device_type(dev.hostname, v, hint)
        else:
            dtype, source = infer_device_type(dev.hostname, dev.vendor, "")
        if dev.device_type == _UNKNOWN_TYPE or source in ("vendor_hint", "hostname", "vendor"):
            dev.device_type, dev.type_source = dtype, source
