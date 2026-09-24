# 项目目录结构

```
homeward/
├── README.md
├── docs/
│   ├── README.md                    # 项目总览
│   ├── STRUCTURE.md                 # 本文档
│   ├── ARCHITECTURE.md              # 架构设计
│   ├── BLOCKING.md                  # 阻断策略设计
│   └── COMPETITORS.md               # 竞品分析
│
├── src/
│   ├── core/                       # 核心服务
│   │   ├── main.py                  # 入口
│   │   ├── api.py                   # Web API (FastAPI)
│   │   ├── collector.py             # 采集调度
│   │   ├── analyzer.py              # 分析引擎
│   │   └── config.py                # 配置管理
│   │
│   ├── adapters/                   # 采集 / 执行 正交抽象层
│   │   ├── base.py                  # 接口骨架：Collector / Enforcer / Capabilities / EnforceAction
│   │   ├── capability.py            # 协商助手：CapabilitySet（can_show / can_enforce / blind_spots）
│   │   └── （具体平台实现 nftables/dnsmasq/pcap/ebpf/openwrt 本期未实现，见正文）
│   │
│   ├── rule-engine/                # 规则匹配引擎
│   │   ├── engine.py               # 核心判定逻辑
│   │   ├── domain_rule.py          # 域名规则
│   │   ├── behavior_rule.py        # 行为特征规则
│   │   ├── cve_rule.py             # 固件漏洞规则
│   │   └── decision.py             # 阻断/放通/告警决策
│   │
│   ├── knowledge-base/             # 知识库
│   │   ├── domains.csv             # 域名→组织归属
│   │   ├── asn.csv                 # ASN→组织
│   │   ├── behaviors.json          # 行为模式库
│   │   ├── cve.json                # 固件漏洞
│   │   └── updater.py              # 知识库在线更新
│   │
│   ├── ui/                         # 前端
│   │   ├── dashboard.html          # 主仪表盘
│   │   ├── device.html             # 设备详情
│   │   └── assets/
│   │
│   └── ai/                         # AI 辅助层
│       ├── analyzer.py             # LLM 分析接口
│       ├── explainer.py            # 人话翻译
│       └── feedback.py             # 用户确认→回灌规则
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yaml
│
├── tests/                         # 契约测试（标准库 unittest，无需装 pytest）
│   └── test_revert_contract.py    # 撤销契约端到端往返
│
└── fnpk/                          # 飞牛应用包
    ├── package.toml
    └── icon.png
```


## 适配器设计：采集 / 执行正交抽象（adapters/）

> 重构结论（本轮落地）：采集（怎么看）与执行（怎么拦）是**两个正交维度**，是一张
> 2×4 的格子，不是一条「档位 A/B」的轴。特别地，**硬阻断（VLAN 隔离）依赖交换机 /
> OpenWrt 的配置权，与采集方式无关**——即便将来拿到完整抓包能力，也不自动等于拿到
> VLAN 配置权。旧版把 `flow_stream()` 与 `apply_block_rule()` 塞进同一个
> `CollectorAdapter` 基类，会导致「一个平台绑死一种能力套餐」，故废弃。

`src/adapters/` 的构成：

| 文件 | 角色 | 状态 |
|---|---|---|
| `base.py` | `Capabilities`(frozen dataclass) + `Collector` / `Enforcer` 两个抽象基类 + `EnforceAction` / `EnforceResult` / `Observation` / `ProbeResult` 数据模型 + **撤销契约**（`RevertPayload` 三子类 / `RevertResult` / `ActionRegistry`） | 接口骨架（本期） |
| `capability.py` | `CapabilitySet`：`can_show()` / `can_enforce()` / `blind_spots()`，直接生成 D22「首页明示盲区」文案 | 协商助手（本期） |
| `nftables.py` / `dnsmasq.py` / `pcap.py` / `ebpf.py` / `openwrt.py` | 具体平台实现（**标准版闭源**） | **本期未实现**（先做架构） |

### 能力协商层（Capabilities）

采集侧四态与执行侧三态在 `Capabilities` 中**完全分离、互不可推导**：

- 采集侧：`dns_query` / `flow_bytes`(决定 bulk_upload) / `sni` / `timing`(决定行为层)
- 执行侧：`enforce_soft` / `enforce_medium` / `enforce_hard`
- 位置属性：`in_forwarding_path` / `is_lan_dns` / `externally_reachable`(FN Connect 位)

### 接口骨架（adapters/base.py）

```python
from dataclasses import dataclass, field
from typing import Iterator, Optional
from abc import ABC, abstractmethod

# 「30 分钟内可一键撤销」的两个时间字段，语义**互不推导**：
#   redeemable_until —— 撤销按钮/API 的截止时间（到期不解除规则）
#   auto_release_at  —— 规则自动解除时间（None = 持久生效，直到显式撤销）
# （旧字段 expires_at 已废弃并移除，见 docs/BLOCKING.md 第四节）

@dataclass(frozen=True)
class Capabilities:
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

class RevertPayload(ABC):           # 回滚载荷：按阻断手法拆子类，不用 dict
    kind: ClassVar[str]             # 判别字段：dns_blackhole / nft_rule / vlan_move
    # 子类：DnsBlackholePayload(配置路径/写入条目/备份路径/是否需重载)
    #      NftRulePayload(family/table/chain/handle/规则文本)
    #      VlanMovePayload(MAC/源VLAN/目标VLAN/端口/迁移前配置快照)

@dataclass
class EnforceAction:
    action_id: str
    scope: str                      # "domain" | "asn" | "device" | "vlan"
    target: str
    device_id: Optional[str] = None
    applied_at: float = 0.0
    redeemable_until: Optional[float] = None   # 一键撤销窗口（到期不解除规则）
    auto_release_at: Optional[float] = None    # 规则自动解除时间（None = 持久生效）
    revert_payload: Optional[RevertPayload] = None  # 「可撤销」承诺的工程载体

class Collector(ABC):               # 只管「怎么看」
    @abstractmethod
    def probe(self) -> ProbeResult: ...
    @abstractmethod
    def capabilities(self) -> Capabilities: ...
    @abstractmethod
    def records(self) -> Iterator[Observation]: ...
    @abstractmethod
    def degrade_to(self) -> Optional["Collector"]: ...

class Enforcer(ABC):                # 只管「怎么拦」
    @abstractmethod
    def probe(self) -> ProbeResult: ...
    @abstractmethod
    def capabilities(self) -> Capabilities: ...
    @abstractmethod
    def apply(self, action: EnforceAction) -> EnforceResult: ...
    @abstractmethod
    def revert(self, action: EnforceAction) -> RevertResult: ...        # 只做回滚，不判窗口
    @abstractmethod
    def verify_revert(self, action: EnforceAction) -> RevertResult: ... # 核验是否真恢复
    def force_revert(self, action: EnforceAction) -> RevertResult: ...  # 窗口过期后的人工通道
    def revert_and_verify(self, action, *, now=None, force=False) -> RevertResult: ...
    #   ↑ 对外唯一入口：窗口判定 → 回滚 → 核验 → 合并结果

class ActionRegistry:               # action_id -> EnforceAction（UI 只持有 id 也能撤销）
    def revert_with(self, enforcer, action_id, *, now=None, force=False) -> RevertResult: ...
```

> 完整定义见 `src/adapters/base.py`。`Observation` 刻意与 `rule_engine.FlowRecord`
> 解耦，避免适配器层反向依赖决策层；`EnforceAction.revert_payload` 是「可撤销」承诺
> 的唯一下发字段，`RevertResult.verified` 是「撤销是否真的生效」的唯一判据
> （**禁止把 `ok=True` 当成 `verified=True`**）。
> `capability.CapabilitySet.blind_spots()` 直接产出 D22 首页盲区文案。
> 撤销契约的端到端测试见 `tests/test_revert_contract.py`。
