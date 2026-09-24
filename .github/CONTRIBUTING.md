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
- 目录：`src/enforcers/`、`src/editions/standard/`、`src/editions/pro/`
- 文件哨兵注释（任一即视为闭源）：`# @closed-source` / `@standard-only` / `@pro-only`

仓库已内置两层自动防护，请勿尝试绕过：
1. `.gitignore` 忽略上述闭源目录；
2. `hooks/pre-commit` 在提交前拦截闭源目录与哨兵注释（拦截即终止提交）。

> 标准版 / 专业版的闭源实现在独立的私有仓库维护，不接受在本公开仓库提交。

## 二、如何贡献社区版
1. Fork 本仓库，从 `main` 切出特性分支（`feat/xxx` 或 `fix/xxx`）。
2. 仅在社区版范围内开发（可见性、分析、抽象契约 `Enforcer` / `RevertContract`）。
3. 首次请启用钩子：`git config core.hooksPath hooks`，保证 `pre-commit` 通过。
4. 提交信息清晰，PR 描述说明动机与验收方式。
5. 向 `homeward-labs/homeward` 的 `main` 发起 PR。

## 三、许可与商标
- 社区版代码以 **MIT** 许可发布；你提交的贡献默认以相同许可并入。
- 商标「家卫 / Homeward」归项目所有；MIT 不授予商标使用权，商用请先联系维护者。
- 知识库数据（`src/knowledge_base/`）以 **CC BY 4.0** 发布，使用请署名。

## 四、行为准则
参与本社区即视为同意友好、尊重、就事论事的协作氛围；违规可联系维护者处理。
