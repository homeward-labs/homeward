## 改了什么

<!-- 一句话说清目的；顺带说明为什么这么改（特别是取舍）。 -->

## 类型

- [ ] 缺陷修复
- [ ] 新功能
- [ ] 知识库相关代码（加载器 / 更新器 / 判定引擎）
- [ ] 文档
- [ ] 部署 / CI

## 开源边界自检（必须全勾）

家卫是 **open-core**：社区版开源（只看见、不拦截），标准版 / 专业版闭源付费。
提交前请确认：

- [ ] 本 PR **不含**任何闭源资产：`src/enforcers/`、`src/editions/`、`workers/` 下无新文件，也未提交知识库数据本体（`domains*.csv` / `behaviors.json` / `oui_prefixes.csv` / `SIGNATURE` / `CHECKSUM` 等）
- [ ] 没有引入 `@closed-source` / `@standard-only` / `@pro-only` 标记
- [ ] 没有夹带敏感资料：竞品分析、定价、合同条款、路线图、客户数据 —— 这些存维护者私有目录，**不进本仓库**
- [ ] 没有夹带真实环境的隐私数据（设备 MAC、公网 IP、家庭内网拓扑）
- [ ] 未向本仓库提交知识库数据本体（数据属闭源资产，只走 Issue 线索；见 CONTRIBUTING 第四节）

> `hooks/pre-commit` 与 `hooks/pre-push` 会自动拦截前两项；
> `tools/check_open_boundary.py` 可本地自检：`python tools/check_open_boundary.py`

## 测试

- [ ] 新增 / 修改了测试
- [ ] `python -m pytest tests -q` 通过
- [ ] `python -m unittest discover -s tests` 通过（验证零第三方依赖环境仍可跑）

## 影响面

<!-- 是否改变默认行为 / 配置 / 部署要求？若是，已在 docs/DEPLOYMENT.md 同步更新。 -->
