# 贡献指南 · CONTRIBUTING

感谢你关注 **家卫 / Homeward**（家庭联网设备隐私守护）。本仓库采用 **open-core（开放核心）** 模式，请先读完下面的开源边界再动手。

## 一、版本与开源边界（必读）

| 版本 | 是否开源 | 范围 |
|------|----------|------|
| 社区版 Community | ✅ 源码开放（BSL 1.1） | 仅"看见"：设备发现、流量可视化、行为识别、建议阻断展示、抽象契约层 |
| 标准版 Standard | ❌ 闭源付费 | 含"拦下"：真实阻断执行（DNS 黑名单 / nft drop / VLAN 隔离） |
| 专业版 Pro | ❌ 闭源（规划中） | 高级治理能力 |

**本公开仓库只承载社区版（可见 / 分析 / 抽象契约）。**

### 绝不上传本仓库的资产（红线）
- 目录：**整个** `src/enforcers/`、`src/editions/` 与 `workers/`（含其下所有子路径）
- 知识库**数据本体**：`src/knowledge_base/` 下的 `domains*.csv` / `behaviors.json` / `oui_prefixes.csv` / `SIGNATURE` / `CHECKSUM` 及 `seeds/*.csv`；内容源发布链路脚本（`scripts/` 下 `merge_domains.py` / `make_kb_source.py` / `publish_kb_source.py` / `feed_pipeline.py` / `feed_registry.json` 等）、`docs/CONTENT-SOURCE.md`、`src/knowledge_base/SOURCES.md`
- 文件哨兵注释（任一即视为闭源）：`# @closed-source` / `@standard-only` / `@pro-only`

> 上述范围由仓库根**单一清单** `tools/closed_assets.txt` 声明，并被四道防线共享；新增 / 调整闭源路径只改这一处。

仓库已内置四层自动防护，请勿尝试绕过：
1. `.gitignore` 忽略上述闭源目录；
2. `hooks/pre-commit` 在提交前拦截闭源目录与哨兵注释（拦截即终止提交）；
3. `hooks/pre-push` 在推送前扫描「整棵提交树 + 待推送提交的完整历史」，能拦住 `git add -f` 与 `--no-verify`；
4. `.github/workflows/open-boundary.yml` 在 CI 侧重扫全历史，本地钩子失效时仍能报警。

> 标准版 / 专业版的闭源实现在独立的私有仓库维护，不接受在本公开仓库提交。

## 二、如何贡献社区版
1. Fork 本仓库，从 `main` 切出特性分支（`feat/xxx` 或 `fix/xxx`）。
2. 仅在社区版范围内开发（可见性、分析、抽象契约 `Enforcer` / `RevertContract`）。
3. **clone 后第一件事**：`git config core.hooksPath hooks` —— 否则两道本地钩子都不会生效。
4. 提交信息清晰，PR 描述说明动机与验收方式。
5. 向 `homeward-labs/homeward` 的 `main` 发起 PR。

### 推送前自查（维护者必做）

```bash
powershell -ExecutionPolicy Bypass -File tools\check_open_boundary.ps1   # Windows（无依赖）
python tools\check_open_boundary.py                                      # Windows（装了 Python）
sh tools/check_open_boundary.sh                                          # Linux / macOS / Git Bash
```

脚本会检查钩子是否启用、`.gitignore` 规则是否还在、忽略规则是否真的生效、
已跟踪文件与**全部提交历史**中有无闭源路径、`src/` 下有无闭源标记。
推送时 `pre-push` 还会再查一遍；CI 是最后一道。防误传机制的完整说明见私有《版本与能力归属》文档。

### 日常推送流程

上游跟踪分支建好之后（`git push -u origin main` 只需在**第一次**跑），日常就是三步：

```bash
git add -A
git commit -m "一句话说明这次改动"   # pre-commit 自动运行，命中闭源即终止提交
git push                            # pre-push 自动运行，命中闭源即终止推送
```

> 注意 `-m` 后面要换成**你自己的提交说明**，不要照抄引号里的内容。
> 显示 "nothing to commit" 说明没有新改动，直接 `git push` 即可。

- `-u origin main` 只在两种情况下需要：`main` 分支首次推送；换机器 / 重新 clone 后。
  之后再带不会多一层保护 —— **它设置的是上游跟踪，与安全无关**。
- 推送某个新分支时才需要显式指定：`git push -u origin feat/xxx`。
- 不确定时（比如刚动过 `src/enforcers/` 或 `src/editions/` 附近的文件）先跑一遍
  自检脚本（见上节，PowerShell 用 ps1 版），全 PASS 再 push。

## 三、许可与商标

- 社区版代码以 **BSL 1.1**（Business Source License 1.1）发布，见仓库根 `LICENSE`；
  人话解释见 `LICENSE-NOTES.md`。要点：
  - **源码始终可读可审计**
  - 家庭 / 个人非商业使用（含在自家路由器上长期运行）**永久免费**
  - **未经授权不得**将家卫作为商业产品 / 服务提供给第三方
  - 4 年后自动转为 **MPL-2.0**
- 你提交的代码贡献默认以相同许可（BSL 1.1）并入。
- 商标「家卫 / Homeward」归项目所有；BSL 1.1 不授予商标使用权，商用请先联系维护者。
- 知识库**数据本体属闭源核心资产、不随本仓库发布**，也不适用代码许可；其来源署名要求随闭源分发说明。

## 四、知识库数据（闭源，不向本仓库提交）

知识库（域名归属 / 行为模式）是家卫的核心差异化资产：**数据本体属闭源核心资产、不随本仓库发布** ——
公开仓只保留加载器（`src/knowledge_base/updater.py` 等）与常量，因此**不接受向本仓库提交 CSV / JSON 数据**
（历史上的 `domains_homeward.csv` 直改 PR 流程已废止）。

- 若你发现某个域名被误标或未收录，请用 [域名归属反馈](ISSUE_TEMPLATE/domain-attribution.yml)
  提交**线索**（域名 + 归属 + 依据），由维护者核实后补录到闭源知识库；
- 与知识库相关的社区版**代码**（加载器 / 更新器 / 判定引擎）欢迎改进，走正常 PR 流程；
- 提交线索即表示你同意家卫将其用于加工知识库，并对外商业授权**加工后的产物**。

### 判定类改动要带证据

修改行为判定阈值（心跳间隔、突发上传字节数等）属于**判定逻辑变更**，
PR 里请说明：改前阈值、改后阈值、依据的观测样本。没有依据的调参一律不合并 ——
对一个隐私工具，误报对信任的伤害远大于漏报。

## 五、行为准则
参与本社区即视为同意友好、尊重、就事论事的协作氛围；违规可联系维护者处理。
