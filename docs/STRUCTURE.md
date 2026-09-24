# 项目目录结构

> 以仓库实际内容为准。标注「规划」的条目**当前不存在**，是后续工作包的位置，
> 不要照着它去找文件（早期版本这份树图里混进了十几个从未创建的文件，已清理）。

```
homeward/
├── README.md                        # 项目门面
├── LICENSE                          # MIT（仅覆盖代码）
├── requirements.txt                 # 当前零第三方依赖；Dockerfile 依赖它存在
├── docs/
│   ├── README.md                    # 项目总览
│   ├── STRUCTURE.md                 # 本文档
│   ├── ARCHITECTURE.md              # 架构设计
│   ├── BLOCKING.md                  # 阻断策略（标准版）+ 撤销契约语义
│   ├── COMPETITORS.md               # 竞品分析
│   ├── DEPLOYMENT.md                # 部署形态与安装方式（接入方式/平台/装法 三维度）
│   ├── EDITIONS.md                  # 版本矩阵与开源边界（唯一权威）
│   └── ROADMAP.md                   # 路线图与社区版 MVP 计划
│
├── src/
│   ├── core/                        # 核心服务
│   │   └── main.py                  # 入口 HomewardService：编排采集/决策/建议队列
│   ├── adapters/                    # 采集 / 执行 正交抽象层（本期只有接口）
│   │   ├── base.py                  # Capabilities + Collector/Enforcer + 撤销契约
│   │   └── capability.py            # CapabilitySet：can_show / can_enforce / blind_spots
│   ├── collectors/                  # 采集器实现（社区版开源）
│   │   ├── dns.py                   # Tier 1：dnsmasq 查询日志
│   │   └── conntrack.py             # Tier 2：连接元数据（字节数 / 直连 IP）
│   ├── enforcers/                   # 执行器实现（标准版闭源，gitignore + pre-commit 拦截）
│   ├── inventory/                   # W2：设备台账 + 域名归属
│   │   ├── device.py                # IP → MAC → 厂商 / 品类；MAC 变 IP 仍是同一台
│   │   └── attribution.py           # 域名 → 组织：精确 + 逐级向上，认输不猜
│   ├── analysis/                    # W3：行为识别 + 中文告警
│   │   ├── ingest.py                # Observation → FlowRecord（补上 W1→W2 断掉的一截）
│   │   ├── behavior.py              # 时间窗 + 设备级/目的地级粒度 → BehaviorFinding（带证据）
│   │   └── alerting.py              # 中文模板渲染 + 去重冷却收敛 → Alert
│   ├── rule_engine/                 # 规则匹配引擎
│   │   └── engine.py                # 知识库加载 + 行为匹配 + 决策（产出建议，不产出动作）
│   ├── knowledge_base/              # 知识库（数据 CC BY 4.0，使用须署名）
│   │   ├── domains.csv              # 域名 → 组织归属
│   │   ├── behaviors.json           # 行为模式库（8 个行为）
│   │   ├── oui_prefixes.csv         # MAC 前缀 → 厂商（脚本生成，见 tools/build_oui_table.py）
│   │   ├── updater.py               # 在线更新（默认关闭；无遥测回传）
│   │   └── LICENSE                  # CC BY 4.0 许可与署名要求
│   └── ai/                          # AI 辅助层（默认关闭，手动触发）
│       └── analyzer.py              # LLM 分析接口（ollama / openai 兼容）
│
├── tests/                           # 标准库 unittest，无需装 pytest
│   ├── test_collectors.py           # 采集层：解析 / 增量 / 能力位 / 降级链
│   ├── test_behavior_matching.py    # 行为判定语义（duration 按秒 / interval 真算间隔）
│   ├── test_behavior_rules.py       # W3：失败关闭 / 关键词边界 / 8 条规则各自能命中
│   └── test_analysis.py             # W3：观测转换 / 窗口与粒度 / 告警渲染与收敛
│   ├── test_inventory.py            # W2：设备识别 + 域名归属（含「不猜」红线断言）
│   └── test_revert_contract.py      # 撤销契约端到端往返
│
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yaml          # 社区版形态：只读挂 dnsmasq 日志，非 privileged
│
├── fnpk/                            # 飞牛应用包（草稿，未上架）
│   └── package.toml                 # 素材 icon.png / screenshot*.png 待补
│
├── hooks/
│   ├── pre-commit                   # 闭源防误传（提交前：暂存 diff）
│   └── pre-push                     # 闭源防误传（推送前：整棵提交树 + 历史）
│
├── .github/
│   ├── CONTRIBUTING.md
│   └── workflows/
│       └── open-boundary.yml        # CI 兜底：重扫全历史 + 跑社区版单测
│
├── reports/                         # 阶段性报告
│   └── 03-revert-contract-2026-09-24.md
│
├── tools/
│   ├── asn_hit_test.py              # ASN 命中率测试脚本
│   ├── build_oui_table.py           # 生成 oui_prefixes.csv（默认拉 Wireshark 官方 manuf）
│   ├── check_open_boundary.sh       # 开源边界自检（Linux / Git Bash）
│   ├── check_open_boundary.py       # 同上（装了 Python 的环境）
│   └── check_open_boundary.ps1      # 同上（PowerShell，无依赖）
│
└── .github/
    └── CONTRIBUTING.md              # 开源边界红线与贡献流程
```

**规划中、尚未创建的目录**：`src/ui/`（W4 Web UI）、`src/editions/`（标准版/专业版，闭源）。

---

## 适配器设计：采集 / 执行正交抽象（adapters/）

> 重构结论：采集（怎么看）与执行（怎么拦）是**两个正交维度**，是一张 2×4 的格子，
> 不是一条「档位 A/B」的轴。特别地，**硬阻断（VLAN 隔离）依赖交换机 / OpenWrt 的配置权，
> 与采集方式无关** —— 即便将来拿到完整抓包能力，也不自动等于拿到 VLAN 配置权。
> 旧版把 `flow_stream()` 与 `apply_block_rule()` 塞进同一个 `CollectorAdapter` 基类，
> 会导致「一个平台绑死一种能力套餐」，故废弃。

`src/adapters/` 的构成：

| 文件 | 角色 | 状态 |
|---|---|---|
| `base.py` | `Capabilities`(frozen dataclass) + `Collector` / `Enforcer` 两个抽象基类 + `EnforceAction` / `EnforceResult` / `Observation` / `ProbeResult` 数据模型 + **撤销契约**（`RevertPayload` 三子类 / `RevertResult` / `ActionRegistry`） | 接口骨架 |
| `capability.py` | `CapabilitySet`：`can_show()` / `can_enforce()` / `blind_spots()`，直接生成首页「明示盲区」文案 | 协商助手 |
| `src/collectors/dns.py`、`src/collectors/conntrack.py` | **采集器实现（社区版开源）**：Tier 1 DNS / Tier 2 conntrack | 已实现（W1，含单测） |
| `src/enforcers/*`（nftables / dnsmasq 黑洞 / VLAN）、深度抓包 DPI | **执行器与 Tier 3 实现（标准版闭源）**，不进公开仓库 | 未实现 |

> **开源边界**：采集与执行的开源属性**并不相同** —— 采集器属于社区版开源，落在
> `src/collectors/`；执行器与 Tier 3 深度抓包属于标准版闭源，落在 `src/enforcers/`（已 gitignore）。
> 依据见 `docs/EDITIONS.md` 与 `docs/ROADMAP.md`「采集分层」。

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
> `capability.CapabilitySet.blind_spots()` 直接产出首页盲区文案。
> 撤销契约的端到端测试见 `tests/test_revert_contract.py`。

---

## 模块导入约定

`src/core/main.py` 会把 `src/` 加入 `sys.path`，模块之间用**扁平导入**
（`from adapters.base import ...`、`from rule_engine.engine import ...`），
因此单个模块可以直接 `python -m src.xxx` 跑起来，无需安装包。
