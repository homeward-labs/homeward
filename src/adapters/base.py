"""
适配器抽象层 —— 采集 / 执行正交抽象

设计核心
--------
「采集（怎么看）」与「执行（怎么拦）」是**两个正交的维度**，二者组合成一张 2×4 的格子：

  · 采集侧维度：dns_query / flow_bytes / sni / timing 四个能力位
  · 执行侧维度：enforce_soft / enforce_medium / enforce_hard 三个能力位

一个部署形态 = （一种采集器 Collector）+（一种执行器 Enforcer），二者通过
``Capabilities`` 协商层各自声明自己能做什么。平台（dnsmasq / nftables / OpenWrt …）
只决定「装哪两个实现」，不决定「能力套餐」——前端 / 决策层永远只问 Capabilities，
不绑定平台。这就避免了一条「档位 A/B」的轴把「一个平台绑死一种能力套餐」的退化设计。

关键不变量
----------
**硬阻断（VLAN 隔离）依赖交换机 / OpenWrt 的配置权，与采集方式无关。**
即便某个 Collector 拿到了完整抓包能力（sni=True, flow_bytes=True, timing=True），
也不自动等于它拥有 enforce_hard 的能力位。因此执行侧三态与采集侧四态在 ``Capabilities``
中**完全分离**，禁止互相推导。

撤销契约（本轮补齐）
--------------------
产品对外承诺「每一个拦截动作，30 分钟内可一键撤销」。这句话在代码里由**三件事共同
承载**，缺一件它就会退回空头支票：

  1. ``RevertPayload`` —— apply 时必须留下**结构化、可执行**的回滚信息（配置路径 /
     写入条目 / 备份 / nftables handle / VLAN 迁移前快照），而不是一个 ``dict`` 逃生舱。
     ``apply()`` 返回 ok=True 却没留下完整 payload，属于**实现 bug**，不是正常分支
     （见 ``validate_applied`` / ``assert_revert_contract``）。
  2. ``EnforceAction.redeemable_until`` 与 ``auto_release_at`` —— 两个时间字段**语义
     分离**：前者是「撤销按钮还在不在」，后者是「规则还生不生效」。混用这两个语义
     会让用户以为"30 分钟后摄像头自动恢复"而放心出门，实际结果是设备被永久隔离。
  3. ``Enforcer.verify_revert`` 与 ``Enforcer.force_revert`` —— 撤销指令执行成功 ≠
     设备真的恢复联网（规则删了句柄没删、配置回滚了进程没重载、设备挪回去了交换机
     端口没恢复）。所以撤销后**必须核验**；窗口过期后**必须还有人工恢复通道**，
     产品里不允许存在「解不开」的死角。

本文件只定义接口骨架与数据模型，**不实现任何具体 Collector / Enforcer**。
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, fields, replace
from typing import ClassVar, Iterator, Optional


# ==================== 能力协商层 ====================

@dataclass(frozen=True)
class Capabilities:
    """适配器能力声明（协商层的核心数据结构）

    采集侧与执行侧的能力位**完全分离**，互不可推导。上层（前端 / 决策引擎）只读这个
    对象，永远不直接问「你是什么平台」，而是问「你能不能 show sni / enforce hard」。

    Attributes:
        # —— 采集侧（决定「看得清不清」）——
        dns_query: 能否观测 DNS 查询域名（决定域名级判定能否成立）
        flow_bytes: 能否观测 flow 级字节数（决定 bulk_upload 行为判定能否成立）
        sni: 能否观测 TLS SNI（决定加密域名的上联目标能否判定）
        timing: 能否观测包间时序 / 频率（决定心跳信标等行为层判定能否成立）

        # —— 执行侧（决定「拦得住不住」）——
        enforce_soft: 能否做 DNS 级软阻断（NXDOMAIN）
        enforce_medium: 能否做网段 / ASN 级中阻断
        enforce_hard: 能否做 VLAN 隔离硬阻断（**需交换机 / OpenWrt 配置权**）

        # —— 位置属性（与「部署形态」有关，与「能力」正交）——
        in_forwarding_path: 是否位于转发路径内（nftables/NFLOG），否则为旁路 / 镜像
        is_lan_dns: 是否是局域网 DNS 解析器（dnsmasq / unbound）
        externally_reachable: 管理面是否可从外部触达（FN Connect 位）
    """

    # 采集侧
    dns_query: bool = False
    flow_bytes: bool = False
    sni: bool = False
    timing: bool = False

    # 执行侧
    enforce_soft: bool = False
    enforce_medium: bool = False
    enforce_hard: bool = False

    # 位置属性
    in_forwarding_path: bool = False
    is_lan_dns: bool = False
    externally_reachable: bool = False


@dataclass
class ProbeResult:
    """启动自检结果"""
    available: bool
    message: str = ""
    capabilities: Optional[Capabilities] = None


@dataclass
class Observation:
    """采集器吐出的归一化观测记录

    刻意与 ``rule_engine.FlowRecord`` / ``DnsRecord`` **解耦**：本类型是「适配器层能
    给出的最小观测单元」，规则引擎自行决定如何把它归并成上层结构。``kind`` 取值建议为
    ``"dns"`` / ``"flow"`` / ``"sni"`` / ``"timing"``，``fields`` 为对应原始字段字典。

    解耦原因：``FlowRecord`` 已在 ``rule_engine/engine.py`` 中定义，适配器层不应
    反向依赖决策层；此处用中性的 ``Observation`` 避免命名 / 依赖冲突。
    """

    timestamp: float
    kind: str
    device_id: Optional[str] = None
    fields: dict = field(default_factory=dict)


# ==================== 撤销契约：常量 ====================

REDEEM_WINDOW_SECONDS: float = 1800.0
"""「30 分钟内可一键撤销」的官方窗口长度（秒）。

它只约束 **UI / API 上那个撤销按钮还在不在**（``redeemable_until``），
**与规则本身什么时候失效毫无关系**（``auto_release_at``）。窗口过期后规则
照旧生效，只是不能再「一键」，必须走 ``force_revert`` 人工恢复通道。
"""


def _now(now: Optional[float] = None) -> float:
    """取当前时间戳；允许调用方注入 now 以便测试与批量判定"""
    return time.time() if now is None else now


# ==================== 撤销契约：结构化回滚载荷 ====================

@dataclass
class RevertPayload(ABC):
    """回滚载荷抽象基类 —— 「撤销」这件事到底需要哪些信息

    设计取舍：**不做**一个大杂烩 dict，也**不做**一堆 Optional 字段的万能类。
    DNS 黑洞、nftables 规则、VLAN 迁移三类阻断需要的回滚信息几乎没有交集，塞进
    同一个结构只会让每个实现各写各的、互不兼容，最后退化成 ``details: dict``。
    所以按**阻断手法**拆成三个子类，每个子类的字段都具体到「照着它就能回滚」。

    子类必须给出：
      · ``kind``（ClassVar）—— 判别字段，序列化 / 反序列化时据此还原类型
      · ``is_complete()`` —— 字段是否齐全到「足够执行一次回滚」
      · ``describe()`` —— 给用户看的人话（"即将删除 dnsmasq 配置中的 X 条目"）
    """

    kind: ClassVar[str] = ""

    @abstractmethod
    def is_complete(self) -> bool:
        """字段是否齐全到可以真正执行一次回滚

        「有 payload」不等于「能回滚」。少一个备份路径、少一个 nftables handle，
        回滚就会变成"看起来成功了实际上没恢复"，所以这个判断是契约的一部分。
        """
        ...

    @abstractmethod
    def describe(self) -> str:
        """人话描述本次回滚要做的事（给用户确认 / 审计日志用）"""
        ...

    def to_dict(self) -> dict:
        """序列化为字典（含 ``kind`` 判别字段），供注册表持久化使用"""
        data: dict = {"kind": self.kind}
        for f in fields(self):
            data[f.name] = getattr(self, f.name)
        return data

    # 子类注册表：kind -> 具体类，供 from_dict 反序列化时还原类型。
    # 阻断实现（dnsmasq / nftables / OpenWrt 等）在标准版独立仓库，各自用
    # @RevertPayload.register 装饰自己即可被本仓库的持久化层识别。
    _registry: ClassVar[dict] = {}

    @classmethod
    def register(cls, subcls: "type[RevertPayload]") -> "type[RevertPayload]":
        """子类装饰器：注册后 from_dict 才能把它还原出来"""
        if subcls.kind:
            cls._registry[subcls.kind] = subcls
        return subcls

    @classmethod
    def from_dict(cls, data: dict) -> "RevertPayload":
        """从 to_dict() 产出的字典还原具体子类实例

        未知 / 未注册的 ``kind`` 抛 ValueError —— 由持久化层决定是兜底丢弃还是
        用未知载荷载体保留原始信息，不直接崩。
        """
        if not isinstance(data, dict):
            raise ValueError(f"revert_payload 数据不是 dict：{type(data).__name__}")
        kind = data.get("kind")
        sub = cls._registry.get(kind)
        if sub is None:
            raise ValueError(
                f"未知 / 未注册的 revert_payload kind：{kind!r}（需对应 Enforcer 模块注册）"
            )
        # 只取该子类声明的字段，忽略遗留 / 无关键
        field_names = {f.name for f in fields(sub)}
        kwargs = {k: v for k, v in data.items() if k in field_names and k != "kind"}
        return sub(**kwargs)


@dataclass
class DnsBlackholePayload(RevertPayload):
    """DNS 级软阻断（dnsmasq / unbound 黑洞）的回滚载荷

    典型场景：往 ``/etc/dnsmasq.d/iot-block.conf`` 追加一行
    ``address=/api.ad.tuya.com/0.0.0.0``，让该域名解析不出 IP。
    """

    kind: ClassVar[str] = "dns_blackhole"

    config_path: str = ""
    """被写入的配置文件绝对路径（如 /etc/dnsmasq.d/iot-block.conf）"""

    entry: str = ""
    """本次写入的那一行原文（如 address=/api.ad.tuya.com/0.0.0.0），回滚时按此精确删除"""

    backup_path: Optional[str] = None
    """写入**前**的配置备份文件路径；``created_file=True`` 时可以为空（回滚即删文件）"""

    created_file: bool = False
    """本次是否新建了配置文件：True 表示回滚时删除整个文件，而不是还原备份"""

    reload_required: bool = True
    """改完配置后是否需要重载进程（dnsmasq 不 reload，规则在进程内存里仍然生效）"""

    reload_command: Optional[tuple[str, ...]] = None
    """重载命令（argv 形式，不经过 shell），``reload_required=True`` 时必填"""

    resolver_process: Optional[str] = None
    """受影响的解析器进程名 / unit 名（dnsmasq / unbound），核验时用于确认进程活着"""

    def is_complete(self) -> bool:
        if not self.config_path or not self.entry:
            return False
        if self.reload_required and not self.reload_command:
            return False
        # 要么有备份可还原，要么本次是新建文件（直接删掉即可）
        return self.created_file or bool(self.backup_path)

    def describe(self) -> str:
        action = "删除配置文件" if self.created_file else f"从 {self.config_path} 中移除条目"
        tail = f"，并重载 {self.resolver_process or '解析器进程'}" if self.reload_required else ""
        return f"{action}「{self.entry}」{tail}"


@dataclass
class NftRulePayload(RevertPayload):
    """nftables 级中阻断（网段 / ASN drop）的回滚载荷

    典型场景：``nft add rule ip filter FORWARD ip daddr 1.2.3.0/24 drop``，
    按 handle 精确删除；handle 拿不到时退化为按规则文本匹配删除。
    """

    kind: ClassVar[str] = "nft_rule"

    family: str = ""
    """nftables family：ip / ip6 / inet / arp / bridge / netdev"""

    table: str = ""
    """表名（如 filter / nat）"""

    chain: str = ""
    """链名（如 FORWARD / PREROUTING）"""

    handle: Optional[int] = None
    """规则句柄，``nft delete rule <family> <table> <chain> handle <handle>`` 用"""

    rule_text: str = ""
    """原始规则文本（``nft add rule`` 之后的完整规则串），handle 缺失时靠它匹配删除"""

    ruleset_backup_path: Optional[str] = None
    """下发前的 ``nft list ruleset`` 快照文件路径，兜底回滚用"""

    def is_complete(self) -> bool:
        if not self.table or not self.chain or not self.rule_text:
            return False
        if self.family not in ("ip", "ip6", "inet", "arp", "bridge", "netdev"):
            return False
        # handle 与 rule_text 至少要有一个能定位规则（rule_text 已强制要求）
        return True

    def describe(self) -> str:
        where = f"{self.family} {self.table} {self.chain}"
        if self.handle is not None:
            return f"删除 {where} 中 handle={self.handle} 的规则：{self.rule_text}"
        return f"删除 {where} 中匹配「{self.rule_text}」的规则"


@dataclass
class VlanMovePayload(RevertPayload):
    """VLAN 隔离硬阻断（设备迁移到隔离 VLAN）的回滚载荷

    典型场景：把设备 MAC 从家庭主网 VLAN 挪到 IoT 隔离 VLAN，涉及交换机端口 /
    Linux 网桥端口 / DHCP 固定分配三处状态，回滚必须三处一起还原，漏一处就是
    "挪回去了但没网"。
    """

    kind: ClassVar[str] = "vlan_move"

    device_mac: str = ""
    """被迁移设备的 MAC（回滚的目标主体）"""

    src_vlan: int = 0
    """迁移**前**所在 VLAN ID（回滚的目标位置）"""

    dst_vlan: int = 0
    """迁移**后**所在 VLAN ID（隔离 VLAN）"""

    switch_port: Optional[str] = None
    """交换机端口标识（如 port3 / eth1），走交换机配置权时必填"""

    bridge_port: Optional[str] = None
    """Linux 网桥端口名（如 br-iot / br-lan），纯软网桥方案时填写"""

    pre_move_snapshot: str = ""
    """迁移前该端口 / VLAN 的配置原文快照（或快照文件路径），回滚按此还原"""

    dhcp_binding: Optional[str] = None
    """为隔离 VLAN 额外下发的 DHCP 固定分配条目，回滚时需一并撤销"""

    def is_complete(self) -> bool:
        if not self.device_mac or not self.pre_move_snapshot:
            return False
        if not (0 < self.src_vlan < 4095) or not (0 < self.dst_vlan < 4095):
            return False
        if self.src_vlan == self.dst_vlan:
            return False
        # 至少要有一个落地点：交换机端口或网桥端口
        return bool(self.switch_port or self.bridge_port)

    def describe(self) -> str:
        port = self.switch_port or self.bridge_port or "未知端口"
        return (
            f"将 {self.device_mac} 从 VLAN {self.dst_vlan} 迁回 VLAN {self.src_vlan}"
            f"（端口 {port}），并还原迁移前配置快照"
        )


# ==================== 撤销契约：动作与结果 ====================

@dataclass
class EnforceAction:
    """一次执行动作请求

    ``revert_payload`` 是**硬性要求**：第一幕把 auto-rollback 砍掉后改承诺
    「30 分钟内可一键撤销」，但工程上此前没有任何字段承载这个承诺。没有
    ``revert_payload``，UI 上「可撤销」写在按钮下面就是空头支票。它由 Enforcer.apply
    时填写、由 Enforcer.revert 时消费——这是「可撤销」承诺唯一的工程载体。

    两个时间字段（**本轮从单个 ``expires_at`` 拆分而来，切勿再合并**）
    --------------------------------------------------------------
    旧版只有一个 ``expires_at``，它到底表示「规则到点自动解除」还是「撤销按钮到点
    消失」完全读不出来。用户按前者理解会以为"30 分钟后摄像头自动恢复"从而放心出门，
    实际产品想表达的是后者——结果是设备被**永久隔离**且用户不在场。故拆成：

      · ``redeemable_until``：**「一键撤销」按钮 / API 的截止时间**。到期**只影响
        操作便捷性，一丝一毫都不解除规则**。窗口过后仍可走 ``force_revert`` 人工恢复。
      · ``auto_release_at``：**规则自动解除时间**。``None`` 表示**持久生效，
        直到显式撤销**——这是默认值，也是绝大多数阻断该有的语义。

    一句话记法：**redeemable_until 管「按钮还在不在」，auto_release_at 管
    「规则还生不生效」**。两者互不推导。

    另注：``redeemable_until=None`` 表示**没有一键通道**（不是「不限期」），
    UI 不得显示撤销按钮，只能走人工通道。未知语义一律按更保守的方向解释。
    """

    action_id: str
    scope: str                      # "domain" | "asn" | "device" | "vlan"
    target: str                     # 具体值：域名 / ASN / 设备 MAC / VLAN ID
    device_id: Optional[str] = None
    applied_at: float = 0.0
    redeemable_until: Optional[float] = None
    auto_release_at: Optional[float] = None
    revert_payload: Optional[RevertPayload] = None

    def __post_init__(self) -> None:
        """拒绝语义自相矛盾 / 易被误读的组合，越早炸越好"""
        if self.revert_payload is not None and not isinstance(self.revert_payload, RevertPayload):
            raise TypeError(
                f"revert_payload 必须是 RevertPayload 子类，收到 {type(self.revert_payload).__name__}"
            )
        if self.applied_at and self.applied_at < 0:
            raise ValueError("applied_at 不能为负")
        if self.redeemable_until is not None and self.applied_at > 0:
            if self.redeemable_until <= self.applied_at:
                raise ValueError("redeemable_until 必须晚于 applied_at")
        if self.auto_release_at is not None:
            if self.applied_at > 0 and self.auto_release_at <= self.applied_at:
                raise ValueError("auto_release_at 必须晚于 applied_at")
            if (
                self.redeemable_until is not None
                and self.redeemable_until > self.auto_release_at
            ):
                # 规则都自动解除了，撤销按钮还亮着 —— 必然是有人把两个语义读混了
                raise ValueError(
                    "redeemable_until 不得晚于 auto_release_at：规则自动解除后已无东西可撤销，"
                    "该组合说明调用方把「按钮有效期」与「规则有效期」读混了"
                )

    # —— 时间语义查询（一律显式传 now 便于测试）——

    def is_persistent(self) -> bool:
        """规则是否持久生效（auto_release_at is None = 永不自动解除，只能显式撤销）"""
        return self.auto_release_at is None

    def is_released(self, now: Optional[float] = None) -> bool:
        """规则是否已因 auto_release_at 到期而自动解除"""
        if self.auto_release_at is None:
            return False
        return _now(now) >= self.auto_release_at

    def is_in_effect(self, now: Optional[float] = None) -> bool:
        """规则当前是否仍在生效（不含「已被手工撤销」的状态，那由注册表维护）"""
        return not self.is_released(now)

    def is_redeemable(self, now: Optional[float] = None) -> bool:
        """「一键撤销」窗口是否仍开放

        未声明 ``redeemable_until`` 视为**没有一键通道**（而非无限期），
        规则已自动解除时也没有撤销的必要。
        """
        if self.redeemable_until is None:
            return False
        t = _now(now)
        if self.is_released(t):
            return False
        return t < self.redeemable_until

    def revert_mode(self, now: Optional[float] = None) -> str:
        """本次撤销该走哪条通道：``"one_click"`` / ``"manual"`` / ``"released"``"""
        t = _now(now)
        if self.is_released(t):
            return "released"
        return "one_click" if self.is_redeemable(t) else "manual"

    def seconds_to_redeem_deadline(self, now: Optional[float] = None) -> float:
        """距一键窗口关闭还剩多少秒（无窗口时返回 0.0）"""
        if self.redeemable_until is None:
            return 0.0
        return max(0.0, self.redeemable_until - _now(now))

    @classmethod
    def create(
        cls,
        action_id: str,
        scope: str,
        target: str,
        *,
        device_id: Optional[str] = None,
        now: Optional[float] = None,
        redeem_window: Optional[float] = REDEEM_WINDOW_SECONDS,
        auto_release_after: Optional[float] = None,
    ) -> "EnforceAction":
        """按产品默认语义构造动作：30 分钟一键窗口 + 规则持久生效

        ``auto_release_after=None`` 是刻意的默认：阻断就该等到用户显式撤销，
        不能偷偷到点放行，否则「30 分钟后自动恢复」的误读会变成真的误放行。
        """
        t = _now(now)
        return cls(
            action_id=action_id,
            scope=scope,
            target=target,
            device_id=device_id,
            applied_at=t,
            redeemable_until=None if redeem_window is None else t + redeem_window,
            auto_release_at=None if auto_release_after is None else t + auto_release_after,
        )


@dataclass
class EnforceResult:
    """执行动作结果

    配合 ``validate_applied`` 使用：``ok=True`` 的动作**必须**已经在
    ``action.revert_payload`` 里留下完整的回滚信息，否则是 Enforcer 的实现 bug。
    """
    ok: bool
    action_id: str
    message: str = ""


class RevertContractError(RuntimeError):
    """「apply 成功却没留下可回滚信息」——这是实现 bug，不是正常分支

    抛这个异常是为了让 bug 在 apply 阶段就暴露，而不是等到用户点「撤销」
    时才发现根本撤不回来。
    """


def validate_applied(action: EnforceAction, result: EnforceResult) -> bool:
    """apply 之后的必检项：生效了的动作必须留下**完整**的回滚载荷

    判定口径：
      · 未生效（ok=False）的动作不承担回滚义务，直接判合格；
      · 生效了却没 payload，或 payload 字段不全（``is_complete()`` 为 False），判失败。

    返回 bool 而非抛异常，便于上层做告警 / 降级；要强制失败请用
    ``assert_revert_contract``。
    """
    if not result.ok:
        return True
    if result.action_id and result.action_id != action.action_id:
        return False
    payload = action.revert_payload
    if payload is None:
        return False
    return bool(payload.is_complete())


def assert_revert_contract(action: EnforceAction, result: EnforceResult) -> None:
    """同 ``validate_applied``，但违反契约时抛 ``RevertContractError``（apply 后必检）"""
    if not validate_applied(action, result):
        payload = action.revert_payload
        if payload is None:
            detail = "revert_payload 为空"
        else:
            detail = f"revert_payload({type(payload).__name__}) 字段不完整，无法执行回滚"
        raise RevertContractError(
            f"action {action.action_id} apply 成功但撤销契约未满足：{detail}。"
            f"「30 分钟内可一键撤销」承诺在此动作上不成立。"
        )


@dataclass
class RevertResult:
    """撤销（及撤销后核验）的结果

    **绝不把 ``ok=True`` 当成 ``verified=True``**：

      · ``ok`` —— 撤销指令本身是否被底层接受（文件改了 / 命令返回 0）；
      · ``verified`` —— 核验是否确认目标真的恢复了（条目确实没了、进程确实重载了、
        端口确实回原 VLAN 了）。

    前者成功而后者失败是最危险的状态：用户以为恢复了，实际上设备还在黑洞里。
    因此 ``verified`` 只在真正核验通过后才允许为 True，且 ``ok=False`` 时禁止置 True。
    """

    ok: bool
    action_id: str = ""
    verified: bool = False
    requires_manual: bool = False
    message: str = ""
    evidence: str = ""
    checked_at: float = 0.0

    def __post_init__(self) -> None:
        if self.verified and not self.ok:
            raise ValueError("verified=True 但 ok=False 自相矛盾：撤销都没成功，不可能核验通过")

    @property
    def fully_reverted(self) -> bool:
        """是否「撤销成功 + 核验通过」——只有这个状态才能告诉用户「已恢复」"""
        return self.ok and self.verified

    @classmethod
    def missing_payload(cls, action_id: str) -> "RevertResult":
        """缺回滚载荷时的标准返回（apply 阶段就漏了，属于实现 bug）"""
        return cls(
            ok=False,
            action_id=action_id,
            message=(
                f"{action_id} 缺少 revert_payload：apply 时未留下回滚信息，无法安全撤销。"
                f"这是 Enforcer 实现 bug，请查看服务端日志。"
            ),
        )

    @classmethod
    def window_expired(cls, action_id: str, redeemable_until: Optional[float]) -> "RevertResult":
        """一键窗口已过时的标准返回：规则**仍在生效**，只是不能「一键」了"""
        return cls(
            ok=False,
            action_id=action_id,
            requires_manual=True,
            message=(
                f"{action_id} 的一键撤销窗口已结束"
                f"（redeemable_until={redeemable_until}）。阻断规则仍在生效，"
                f"请走人工恢复通道 force_revert() 显式解封。"
            ),
        )


# ==================== 采集侧抽象 ====================

class Collector(ABC):
    """采集器抽象基类（正交维度的「采集」侧）

    一个 Collector 实现只负责「怎么看」，不负责「怎么拦」。它与 Enforcer 通过
    ``Capabilities`` 协商，而非通过继承耦合。

    注意：规划中的 ``core/collector.py``（采集调度层）会以本抽象为契约，在多种
    Collector 实现之间做选择与降级，二者分属不同模块、命名不冲突。
    """

    @abstractmethod
    def probe(self) -> ProbeResult:
        """启动自检：环境是否具备采集条件"""
        ...

    @abstractmethod
    def capabilities(self) -> Capabilities:
        """声明本采集器的采集侧能力位"""
        ...

    @abstractmethod
    def records(self) -> Iterator[Observation]:
        """产出归一化观测记录流"""
        ...

    @abstractmethod
    def degrade_to(self) -> Optional["Collector"]:
        """返回降级路径上的下一个 Collector（无则 None）

        例如：完整抓包能力不可用时，降级到仅 DNS 观测的 Collector。
        降级只改变「采集侧能看多少」，不改变「执行侧能拦多少」。
        """
        ...


# ==================== 执行侧抽象 ====================

class Enforcer(ABC):
    """执行器抽象基类（正交维度的「执行」侧）

    一个 Enforcer 实现只负责「怎么拦」，不负责「怎么看」。是否拥有 ``enforce_hard``
    取决于是否拿到交换机 / OpenWrt 配置权，与任何 Collector 的能力**无关**。

    撤销相关的四个方法分工
    ----------------------
      · ``revert(action)``            —— 原子回滚动作，**不判断时间窗口**；
      · ``verify_revert(action)``     —— 回滚后核验「目标真的恢复了」；
      · ``force_revert(action)``      —— 窗口过期后的人工恢复通道（基类已给默认实现）；
      · ``revert_and_verify(...)``    —— **对外唯一入口**：窗口判定 → 回滚 → 核验 →
        合并结果。UI / API 层只应调它，直接调 ``revert()`` 会绕过窗口与核验。
    """

    @abstractmethod
    def probe(self) -> ProbeResult:
        """启动自检：环境是否具备下发条件"""
        ...

    @abstractmethod
    def capabilities(self) -> Capabilities:
        """声明本执行器的执行侧能力位"""
        ...

    @abstractmethod
    def apply(self, action: EnforceAction) -> EnforceResult:
        """下发一次执行动作

        实现**必须**在返回前把撤销所需信息写入 ``action.revert_payload``，
        否则「30 分钟内可一键撤销」承诺将无法兑现。写入后由调用方用
        ``assert_revert_contract`` 做 apply 后必检。
        """
        ...

    @abstractmethod
    def revert(self, action: EnforceAction) -> RevertResult:
        """执行一次回滚（消费 ``action.revert_payload``）

        该方法**只负责回滚动作本身，不做时间窗口判断**——窗口判定统一由
        ``revert_and_verify`` 负责，避免每个实现各判各的、判出不同结果。

        实现要求：
          · **幂等**：同一 action 重复调用不得抛异常，规则已不存在时应返回 ok=True；
          · ``ok`` 只表示「回滚指令被底层接受」，不代表设备已恢复（那是 verify 的事）。
        """
        ...

    @abstractmethod
    def verify_revert(self, action: EnforceAction) -> RevertResult:
        """核验撤销是否**真的生效**（不是"命令返回 0"就算数）

        三类 Enforcer 各自该怎么核验：

        · **DNS 黑洞**：重新读取配置文件，确认那一行的确不在了；若
          ``payload.reload_required`` 为真，还要确认解析器进程已重载（进程启动时间
          晚于回滚、或用 ``dig @127.0.0.1 <domain>`` 实测不再返回 0.0.0.0）。
          只删文件行而没 reload 是最典型的假恢复。
        · **nftables**：执行 ``nft list chain <family> <table> <chain>``，确认目标
          handle / 规则文本已消失，且 ``nft list ruleset`` 里没有等价规则残留
          （同名表被重建过时会残留）。
        · **VLAN 迁移**：确认设备 MAC 已回到 ``src_vlan``（查交换机 / 网桥的 MAC 表、
          或 DHCP 租约落在原网段），并且端口配置与 ``pre_move_snapshot`` 一致——
          只把设备挪回去而交换机端口还留在隔离 VLAN，设备就是"回去了但没网"。

        约定：返回的 ``ok`` 表示「核验动作本身执行成功」，``verified`` 表示
        「核验结论是通过」；核验不通过时把证据写进 ``evidence``，**不允许静默**。
        """
        ...

    def force_revert(self, action: EnforceAction) -> RevertResult:
        """超出一键窗口后的**显式恢复通道**

        语义是"窗口过期了，但我仍然要把这个设备解封"。产品不允许存在「解不开」的
        死角：一键按钮可以消失，恢复能力不能消失。默认实现等价于 ``revert``，
        但强制标记 ``requires_manual=True`` 以便审计与 UI 提示。

        需要额外确认（如 VLAN 迁移要重跑交换机配置）的实现可覆盖本方法。
        """
        result = self.revert(action)
        message = f"{result.message}（经人工恢复通道执行）" if result.message else "经人工恢复通道执行"
        return replace(result, requires_manual=True, message=message)

    def revert_and_verify(
        self,
        action: EnforceAction,
        *,
        now: Optional[float] = None,
        force: bool = False,
    ) -> RevertResult:
        """「一键撤销」的唯一对外入口：窗口判定 → 回滚 → 核验 → 合并结果

        契约：
          · 缺 ``revert_payload`` → 直接失败并说明是实现 bug，不做任何底层改动；
          · 窗口过期且未 ``force`` → 返回 ``requires_manual=True`` 且**不解除规则**
            （保持阻断现状比半吊子回滚安全），由用户决定是否走 force 通道；
          · 规则已按 ``auto_release_at`` 自动解除 → 撤销退化为幂等空操作，但仍然
            **跑一遍核验**确认放行属实（不去吓唬用户走人工通道）；
          · 回滚成功但核验失败 → ``ok=True, verified=False``，message 必须显式告知
            用户"尚未确认恢复"，**绝不静默吞掉**。
        """
        t = _now(now)
        if action.revert_payload is None:
            return RevertResult.missing_payload(action.action_id)

        released = action.is_released(t)       # 规则已按 auto_release_at 自动解除
        expired = not action.is_redeemable(t)  # 一键窗口已过（released 时同样为 False）

        if expired and not released and not force:
            return RevertResult.window_expired(action.action_id, action.redeemable_until)

        manual = force and not released        # released 后的幂等核验不算「人工通道」
        result = self.force_revert(action) if manual else self.revert(action)
        if not result.ok:
            # 底层回滚就失败了，直接原样暴露，不做任何"也许成了"的美化
            return replace(result, checked_at=t)

        note = f"规则已于 auto_release_at={action.auto_release_at} 自动解除；" if released else ""
        verification = self.verify_revert(action)
        if not verification.verified:
            return RevertResult(
                ok=True,
                action_id=action.action_id,
                verified=False,
                requires_manual=result.requires_manual or manual,
                message=(
                    f"{note}撤销指令已执行，但核验未通过：{verification.message}"
                    f"——设备可能仍未恢复，请勿视为已放行。"
                ),
                evidence=verification.evidence,
                checked_at=t,
            )
        return RevertResult(
            ok=True,
            action_id=action.action_id,
            verified=True,
            requires_manual=result.requires_manual or manual,
            message=f"{note}{verification.message or result.message or '已撤销并核验通过'}",
            evidence=verification.evidence,
            checked_at=t,
        )


# ==================== 动作注册表 ====================

class ActionRegistry:
    """``action_id -> EnforceAction`` 的注册表（内存实现）

    存在理由：``Enforcer.revert`` 需要完整的 ``EnforceAction``（否则拿不到 apply 时
    保存的 ``revert_payload``），但 UI 层往往只持有一个 ``action_id``。注册表就是
    这两者之间的桥——UI 只管传 id，由注册表还原出完整 action 再交给 Enforcer。

    没有它，「一键撤销」在接口层面就落不了地（这是本次修复的第 2 个问题）。

    持久化：本实现是纯内存的，进程重启即丢——**那会让已生效的阻断变成孤儿规则**。
    子类覆盖 ``_persist`` / ``_evict`` / ``_load_all`` 三个钩子即可换成 JSON /
    SQLite 后端，上层调用代码一行都不用改。
    """

    def __init__(self) -> None:
        self._actions: dict[str, EnforceAction] = {}

    # —— 基础读写 ——

    def save(self, action: EnforceAction) -> None:
        """登记 / 更新一个动作（覆盖式）"""
        self._actions[action.action_id] = action
        self._persist(action)

    def get(self, action_id: str) -> Optional[EnforceAction]:
        return self._actions.get(action_id)

    def require(self, action_id: str) -> EnforceAction:
        """取动作，不存在则抛 KeyError（调用方确信它应该存在时用）"""
        try:
            return self._actions[action_id]
        except KeyError:
            raise KeyError(f"action_id 未登记：{action_id}") from None

    def remove(self, action_id: str) -> None:
        self._actions.pop(action_id, None)
        self._evict(action_id)

    def all(self) -> list[EnforceAction]:
        return list(self._actions.values())

    def __len__(self) -> int:
        return len(self._actions)

    def __contains__(self, action_id: str) -> bool:
        return action_id in self._actions

    # —— 时间语义查询 ——

    def redeemable(self, now: Optional[float] = None) -> list[EnforceAction]:
        """当前仍处在一键撤销窗口内的动作（UI 据此决定按钮亮不亮）"""
        t = _now(now)
        return [a for a in self._actions.values() if a.is_redeemable(t)]

    def due_for_auto_release(self, now: Optional[float] = None) -> list[EnforceAction]:
        """已到 auto_release_at、应被自动解除的动作（供调度器消费）"""
        t = _now(now)
        return [a for a in self._actions.values() if a.is_released(t)]

    # —— 撤销入口 ——

    def revert_with(
        self,
        enforcer: Enforcer,
        action_id: str,
        *,
        now: Optional[float] = None,
        force: bool = False,
    ) -> RevertResult:
        """只凭 action_id 完成一次撤销（含窗口判定与核验）

        查不到 id 时返回 ``ok=False`` 而不是抛异常：注册表里没有这条记录通常意味着
        它已被清理或从未持久化，属于要告知用户的状态，不该让 UI 崩掉。
        """
        action = self._actions.get(action_id)
        if action is None:
            return RevertResult(
                ok=False,
                action_id=action_id,
                message=f"未找到 action_id={action_id} 的动作记录，无法撤销（可能已被清理或未持久化）",
            )
        return enforcer.revert_and_verify(action, now=now, force=force)

    # —— 持久化钩子（默认 no-op，子类覆盖）——

    def _persist(self, action: EnforceAction) -> None:
        """写入后端（默认内存实现什么都不做）"""

    def _evict(self, action_id: str) -> None:
        """从后端删除（默认内存实现什么都不做）"""

    def _load_all(self) -> list[EnforceAction]:
        """从后端加载全部动作（默认返回空）"""
        return []

    def restore_all(self) -> list[EnforceAction]:
        """启动时从持久化后端恢复全部动作，返回恢复的条目"""
        restored = self._load_all()
        for action in restored:
            self._actions[action.action_id] = action
        return restored
