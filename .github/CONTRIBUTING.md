# 贡献指南 · CONTRIBUTING

感谢你关注 **家卫 / Homeward**（家庭联网设备隐私守护）。本仓库采用 **open-core（开放核心）** 模式，请先读完下面的开源边界再动手。

## 一、版本与开源边界（必读）

| 版本 | 是否开源 | 范围 |
|------|----------|------|
| 社区版 Community | ✅ MIT 开源 | 仅"看见"：设备发现、流量可视化、行为识别、建议阻断展示、抽象契约层 |
| 标准版 Standard | ❌ 闭源付费 | 含"拦下"：真实阻断执行（DNS 黑名单 / nft drop / VLAN 隔离） |
| 专业版 Pro | ❌ 闭源（规划中） | 高级治理能力 |

**本公开仓库只承载社区版（可见 / 分析 / 抽象契约）。**

### 绝不上传本仓库的代码（红线）
- 目录：**整个** `src/enforcers/` 与 `src/editions/`（含其下 `standard/`、`pro/` 等所有子路径）
- 文件哨兵注释（任一即视为闭源）：`# @closed-source` / `@standard-only` / `@pro-only`

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
sh tools/check_open_boundary.sh   # 全部 PASS 才推；退出码非 0 就别推
```

脚本会检查钩子是否启用、`.gitignore` 规则是否还在、忽略规则是否真的生效、
已跟踪文件与**全部提交历史**中有无闭源路径、`src/` 下有无闭源标记。
推送时 `pre-push` 还会再查一遍；CI 是最后一道。详见 `docs/EDITIONS.md` 的「防误传机制」。

## 三、许可与商标
- 社区版代码以 **MIT** 许可发布；你提交的贡献默认以相同许可并入。
- 商标「家卫 / Homeward」归项目所有；MIT 不授予商标使用权，商用请先联系维护者。
- 知识库数据（`src/knowledge_base/`）以 **CC BY 4.0** 发布，使用请署名。

## 四、贡献知识库数据（domains.csv / behaviors.json）

知识库是本项目的核心差异化资产，欢迎贡献 —— 但它是**数据**，许可与代码不同：

- 数据以 **CC BY 4.0** 发布（见 `src/knowledge_base/LICENSE`），你的贡献默认以相同许可并入；
- 请提交真实观测到的设备域名归属，**不要**提交来自闭源数据库或带 license 限制的数据；
- 署名通过 git 历史体现，使用方在产品中须按 CC BY 4.0 要求署名。

### 提交前自检（数据质量）

| 检查项 | 要求 |
|---|---|
| domain | 小写、去尾点、不含协议与路径；**不得与已有条目重复**（重复会被静默覆盖） |
| organization | 写单一主体的规范名，不要混写两家厂商（如不要写 `Hisense/Haier`） |
| category | 取自既有枚举：IoT_core / cloud_storage / analytics / advertising_sdk / telemetry / machine_learning / cdn / unknown |
| confidence | high 需可验证依据（官方文档 / 实测）；拿不准就填 low，**不要虚高** |
| action | 只是**建议动作**，是否真的拦截永远由用户决定 |
| side_effects | 中文分号分隔，写清「拦了会怎样」；不知道就留空，不要编 |

### 判定类改动要带证据

修改 `behaviors.json` 的阈值（心跳间隔、突发上传字节数等）属于**判定逻辑变更**，
PR 里请说明：改前阈值、改后阈值、依据的观测样本。没有依据的调参一律不合并 ——
对一个隐私工具，误报对信任的伤害远大于漏报。

## 五、行为准则
参与本社区即视为同意友好、尊重、就事论事的协作氛围；违规可联系维护者处理。
