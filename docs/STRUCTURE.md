# 项目目录结构

> 以仓库**实际内容**为准（核对方式：`git ls-files`）。
> 本仓库只承载 open-core 的**公开部分**：标准版/专业版执行器、知识库数据本体、KB 内容源与
> Cloudflare Worker 模板都**不随本仓库发布**，其判定依据是**单一清单** `tools/closed_assets.txt`
> （历史上「四处各写一份 CLOSED_DIRS」导致口径漂移，现已收敛为一份）。
> 该清单被四道防线共同引用：`tools/check_open_boundary.{py,sh,ps1}`（手动自查）、`hooks/pre-commit`
> （提交前）、`hooks/pre-push`（推送前，含整棵提交树 + 历史）、`.github/workflows/open-boundary.yml`
> （CI 兜底）。清单同时声明活源地址/机密标记正则，命中即失败；⚠️ 清单文件自身含 pattern 明文，
> 所有内容扫描都必须排除它（脚本已用 `:(exclude)tools/closed_assets.txt` 处理）。

```
homeward/
├── README.md                        # 项目门面
├── LICENSE                          # BSL 1.1（仅覆盖代码；该版本 4 年后转 MPL-2.0）
├── LICENSE-NOTES.md                 # 各来源许可证与署名说明
├── SECURITY.md                      # 安全披露渠道与红线
├── requirements.txt                 # 社区版：零第三方依赖（Dockerfile 依赖它存在）
├── requirements-dev.txt             # 仅开发/测试（pytest / segno / numpy / opencv-python-headless），绝不进运行时镜像
├── .dockerignore / .gitattributes / .gitignore
│
├── docs/
│   ├── README.md                    # 项目总览
│   ├── STRUCTURE.md                 # 本文档
│   ├── ARCHITECTURE.md              # 架构设计
│   ├── DEPLOYMENT.md                # 部署形态与安装方式（接入方式 / 平台 / 装法 三维度）
│   ├── USER-MANUAL.md               # 用户手册
│   ├── CHANGELOG.md                 # 变更日志
│   └── ROADMAP.md                   # 路线图
│   （商业/策略文档：版本矩阵、竞品分析、阻断策略、进度、同步约定
│     已迁出本公开仓库，存于维护者私有目录，不随仓库发布）
│
├── src/
│   ├── core/                        # 核心服务
│   │   ├── main.py                  # 入口 HomewardService：编排采集/决策/建议队列
│   │   ├── demo.py                  # 演示剧本（命令行演示与 UI --demo 共用，不在生产路径调用）
│   │   ├── collector.py             # 采集编排与去重
│   │   ├── import_log.py            # 历史日志导入
│   │   └── netclass.py              # 本网 / 外网 / 保留网段判定
│   ├── adapters/                    # 采集 / 执行 正交抽象层（详见本文下半篇）
│   │   ├── base.py                  # Capabilities + Collector/Enforcer + 撤销契约
│   │   ├── capability.py            # CapabilitySet：can_show / can_enforce / blind_spots
│   │   ├── sqlite_registry.py       # 建议与动作的持久化登记
│   │   └── trend_store.py           # 趋势数据存储
│   ├── collectors/                  # 采集器实现（社区版开源）
│   │   ├── dns.py                   # Tier 1：dnsmasq 查询日志
│   │   ├── conntrack.py             # Tier 2：连接元数据（字节数 / 直连 IP）
│   │   └── syslog_dns.py            # 远程 syslog 的 DNS 日志采集
│   ├── inventory/                   # W2：设备台账 + 域名归属
│   │   ├── device.py                # IP → MAC → 厂商 / 品类；MAC 变 IP 仍是同一台
│   │   └── attribution.py           # 域名 → 组织：精确 + 逐级向上，认输不猜
│   ├── analysis/                    # W3：行为识别 + 中文告警
│   │   ├── ingest.py                # Observation → FlowRecord（补上 W1→W2 断掉的一截）
│   │   ├── behavior.py              # 时间窗 + 设备级/目的地级粒度 → BehaviorFinding（带证据）
│   │   ├── alerting.py              # 中文模板渲染 + 去重冷却收敛 → Alert
│   │   └── profiler.py              # 设备画像（行为基线）
│   ├── rule_engine/                 # 规则匹配引擎
│   │   └── engine.py                # 知识库加载 + 行为匹配 + 决策（产出建议，不产出动作）
│   ├── knowledge_base/              # 知识库 **loader 层**；数据本体闭源，不随本仓库发布
│   │   ├── .gitignore               # 第一道防线：拦截 9 个数据文件（清单 kbignore 行校验其完整性）
│   │   ├── LICENSE                  # 分来源：上游公开源 MIT / 家卫策展 CC BY 4.0，均须署名
│   │   ├── VERSION                  # 本地知识库版本
│   │   ├── constants.py             # 默认源地址**置空**，运行时由闭源构建经环境变量注入
│   │   ├── updater.py               # 在线更新（默认关闭；无遥测回传）
│   │   └── seeds/README.md          # 数据文件落位与生成方式说明
│   ├── license/                     # 许可与签名校验（公钥随源码分发）
│   │   ├── ed25519.py               # 纯 stdlib Ed25519 验签
│   │   ├── kb_pubkey.txt            # 知识库分发包验签公钥
│   │   ├── verify.py                # 许可文件校验
│   │   └── store.py                 # 许可本地存储
│   ├── ui/                          # Web UI（端口 9595，社区版只读）
│   │   ├── server.py                # 标准库 http.server + JSON 接口 + 静态文件
│   │   ├── auth.py                  # 访问令牌鉴权
│   │   ├── qr.py                    # 二维码生成
│   │   ├── DESIGN.md                # 前端设计系统：:root 令牌冻结为唯一取色源 + 硬编码债登记
│   │   └── static/                  # 页面本体：零外部资源，图标为内联 SVG（禁用 emoji）
│   │       ├── index.html
│   │       ├── app.css              # `:root` 令牌（唯一取色来源）
│   │       ├── app.js
│   │       ├── charts.js
│   │       └── login.css            # 登录页独立深色主题
│   └── ai/                          # AI 辅助层（默认关闭，手动触发）
│       └── analyzer.py              # LLM 分析接口（ollama / openai 兼容）
│
├── tests/                           # 标准库 unittest，无需装 pytest
│   ├── test_collector.py            # 采集层：解析 / 增量 / 能力位 / 降级链
│   ├── test_collector_dns_source.py # DNS 日志来源切换
│   ├── test_collectors.py
│   ├── test_concurrency.py
│   ├── test_ui.py                   # W4：真起 HTTP 服务打请求（路由/头/CSP/穿越/动词约束）
│   ├── test_ui_auth.py
│   ├── test_behavior_matching.py    # 行为判定语义（duration 按秒 / interval 真算间隔）
│   ├── test_behavior_rules.py       # W3：失败关闭 / 关键词边界 / 8 条规则各自能命中
│   ├── test_analysis.py             # W3：观测转换 / 窗口与粒度 / 告警渲染与收敛
│   ├── test_inventory.py            # W2：设备识别 + 域名归属（含「不猜」红线断言）
│   ├── test_revert_contract.py      # 撤销契约端到端往返
│   ├── test_license.py / test_license_api.py
│   ├── test_kb_source.py / test_qr.py
│   ├── test_sqlite_registry.py / test_suggestion_persistence.py / test_import_log.py
│   ├── test_bulk_upload_fp.py / test_bulk_upload_grade.py / test_crypto_mining_category.py
│   ├── test_feature_evolution_f6.py / test_feature_evolution_f6_profile.py
│   ├── test_feature_evolution_f7.py / test_feature_evolution_phase_a.py
│   ├── test_visibility_coverage.py
│   └── __init__.py
│
├── docker/
│   ├── Dockerfile
│   ├── .env.example
│   ├── docker-compose.yaml          # 社区版形态：只读挂 dnsmasq 日志，非 privileged
│   ├── docker-compose.full.yml      # 全量形态
│   ├── docker-compose.pull.yml      # 拉取官方镜像
│   ├── docker-compose.istoreos.yml  # iStoreOS 形态
│   └── dnsmasq/                     # 自带 dnsmasq 容器
│       ├── Dockerfile
│       └── dnsmasq.homeward.conf
│
├── scripts/                         # 部署与运维脚本
│   ├── install.sh                   # 通用安装
│   ├── install-istoreos.sh / boot-istoreos.sh / setup-istoreos.sh
│   ├── homeward-sync.sh             # 镜像同步
│   ├── git-mirror-pull.sh
│   └── smoke.py                     # 冒烟脚本
│
├── fnpk/                            # 飞牛应用包（草稿，未上架）
│   └── package.toml                 # 素材 icon.png / screenshot*.png 待补
│
├── hooks/
│   ├── pre-commit                   # 闭源防误传（提交前：暂存 diff）
│   └── pre-push                     # 闭源防误传（推送前：整棵提交树 + 历史）
│
├── tools/
│   ├── closed_assets.txt            # ⭐ 闭源资产单一清单（四道防线的唯一判定依据）
│   ├── check_open_boundary.py       # 开源边界自检（Python，最全）
│   ├── check_open_boundary.sh       # 同上（Linux / Git Bash）
│   ├── check_open_boundary.ps1      # 同上（PowerShell，无依赖）
│   ├── asn_hit_test.py              # ASN 命中率测试脚本
│   └── build_oui_table.py           # 生成 oui_prefixes.csv（默认拉 Wireshark 官方 manuf）
│
└── .github/
    ├── CONTRIBUTING.md              # 开源边界红线与贡献流程
    ├── PULL_REQUEST_TEMPLATE.md
    ├── ISSUE_TEMPLATE/              # bug_report / feature_request / domain-attribution / config
    └── workflows/
        ├── tests.yml                # 社区版单测
        ├── open-boundary.yml        # 闭源边界 CI 兜底（重扫全历史 + 全量 pytest）
        ├── publish.yml              # 发布（含公钥前置断言，fail-closed）
        └── build-smoke.yml          # 构建冒烟
```

**不随本仓库发布（闭源）**：`src/enforcers/`（执行器与 Tier 3 深度抓包）、`src/editions/`
（标准版/专业版）、知识库**数据本体**（`domains.csv` / `behaviors.json` / `oui_prefixes.csv` /
`domains_homeward.csv` / `domains_public.csv` / `seeds/cloud_cdn.csv` / `seeds/privacy_trackers.csv` /
`SIGNATURE` / `CHECKSUM`）、KB 内容源与发布链路、Cloudflare Worker 模板。这些条目**统一由
`tools/closed_assets.txt` 声明**，不出现在上面的目录树中。

> ✅ **2026-10-30 闭源整改已完成**：越界文件（`workers/` 整包、`docs/CONTENT-SOURCE.md`、
> `src/knowledge_base/SOURCES.md`、`tests/test_merge_domains.py` 及 KB 生成/发布脚本若干）
> 已从**当前树与全部历史提交**中移除（`git filter-repo` 全仓重写，旧对象已 `gc` 清除）。
> 上面的树图即**当前实态**；「某文件是否该进公开仓」的唯一判准是 `tools/closed_assets.txt`。

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
> 依据见 私有《版本与能力归属》《路线图》文档的「采集分层」章节。

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
# （旧字段 expires_at 已废弃并移除，见私有《阻断与撤销》文档第四节）

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
