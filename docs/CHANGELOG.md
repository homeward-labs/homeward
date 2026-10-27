# 家卫 Homeward — 变更日志

> 版本号格式：`YYYY-MM-DD.N`（当日第 N 次迭代）；社区版遵循 open-core 边界，闭源标准版/专业版的改动不纳入本文件。

所有时间均为本地提交时间（UTC+8）。

---

## 2026-10-27.13 — P1-5 设备视图打磨

> ROADMAP Phase 2 任务"设备分组/搜索/筛选"——设备台账里经常有几十台设备平铺，用户需要快速定位某台或某类设备。纯前端就能做，不碰后端接口。

### `f783a2f` — feat(ui): 设备视图搜索 / 筛选 / 分组

- `src/ui/static/app.js`（+151 -16，单文件纯前端）
  - `state` 加三字段：`deviceSearch`（搜索框值）/ `deviceRiskFilter`（风险等级）/ `deviceGroupBy`（分组模式）
  - `renderDevices()` 重写：搜索框（name/vendor/mac/ips 子串模糊匹配，实时 input 触发）+ 风险筛选下拉（all/high/medium/low，每档带数量标签）+ 分组下拉（按厂商 / 平铺切换，未知厂商放最后）+ 清除筛选链接
  - 空结果友好提示：有设备但全被筛掉 → "筛选后无匹配设备 + 清除筛选"，而非空板
  - 各分组标题带厂商名 + 设备数 + 高风险台数（如有）
  - 事件绑定：`document.addEventListener("input")` 处理搜索实时过滤；`document.addEventListener("change")` 处理筛选/分组；click 里加清除筛选
- 回归：408 passed

---

## 2026-10-27.12 — P0 首屏加载态修复

> TASKS-2026-10-27 确认"首屏加载态修复"当年说"随下一批交付"但**从未进代码**——真机 254/252 冷启动后 UI 全是 `?? 0` 零值，用户体验极差。单文件 10 行修完。

### `2b385b3` — fix(ui): 首屏加载态骨架

- `src/ui/static/app.js`（+9 -1）
  - `state` 加 `loaded: false` 标记
  - `loadAll()` 开头 `state.loaded = false` + 结尾 `state.loaded = true`
  - `render()` 加 `(!state.loaded && !state.error)` 判断 → 显示"加载中… 正在拉取设备清单、观测记录与告警。服务首次启动约 5–15 秒完成采集器协商。"
  - 三态互斥：error（接口挂了）→ loading（还在拉）→ body（数据回来了）
- 回归：408 passed

---

## 2026-10-27.11 — Phase 2 Tier 2 接入

> Tier 2（连接元数据 / conntrack）此前已实现但与 Tier 1（DNS）各自独立，产出的 flow 没合并。本批次三件事让"社区版两 Tier 真合并叙事"成立：DNS↔IP 关联缓存、国产知识库扩量、前端采集器状态条。飞牛 / OpenWrt 应用商店打包排后续。

### `16157d8` — feat(tier2): Phase 2 Tier 2 接入

- **A. DNS→IP 双向关联缓存**（`src/core/main.py`，Tier 1+2 合并核心）
  - `HomewardService.__init__` 加 `_dns_ip_cache`（dst_ip → {domain, ts}）+ `_dns_domain_cache`（domain → {dst_ip, ts}）
  - `_process_flow_locked` 开头：Tier 1 flow（有 dns_query + dst_ip）→ 写双向缓存；Tier 2 flow（没 dns_query）→ 从 `_dns_ip_cache` 反查域名回填 `flow.dns_query`
  - `_purge_dns_cache()` helper：攒够 128 条批量清（避免每条 flow 全表扫描），TTL 30 分钟
  - **零侵入**：不改 `observation_to_flow()` / `Collector` 接口，关联逻辑完全在 service 层完成
- **B. 国产知识库扩量**（`src/knowledge_base/domains.csv`，+33 条）
  - 小米 IoT 全家桶（api.io.mi.com / ruxit / beacon warn）
  - 涂鸦智能（tuya.com / api.tuya.com / openapi.tuya.com）
  - 华为 HiLink + IoT 云 + 荣耀
  - 腾讯 IoT / 微信 IoT 设备接入
  - 百度 IoT / 小度设备
  - 阿里云 IoT / 天猫精灵
  - 海康萤石 + 大华
  - BroadLink / Aqara / Yeelight / ORVIBO（智能家居生态链）
  - TP-Link / 腾讯 / 字节 / 快手 tracker warn 条目
  - 去重后全部追加（现有 5078 条 → 5111 条）
- **C. UI 采集器状态条**（`/api/overview` + `renderOverview`）
  - server.py：`/api/overview` 响应加 `collection_status`（来自 `service.collection_status`，即 CollectorRunner.start() 返回的探针结果）
  - app.js：`renderOverview` 在统计卡前加采集器状态条，按 DnsLogCollector / SyslogDnsCollector / ConntrackCollector 映射 Tier 1 / Tier 2 标签，活跃绿 / 不可用红
  - 附带说明文字：Tier 1 看不见直连 IP，Tier 2 补字节数但也看不见加密域名（Tier 3 标准版）
- 回归：408 passed

---

## 2026-10-27.10 — Phase 1.1 成长期四连发

> 主线已闭环（Phase 1 MVP 五工作包），本批次四个 commit 是 Phase 1.1 成长期的首批交付：行为识别增强 + 数据持久化 + 导出报告扩展 + AI 辅助分析接入。

### `727c625` — feat(ai): P1-2 AI 辅助分析接入

- **server.py**（3 个新路由 + 启动时 config.json 合并）
  - `POST /api/ai/analyze` — 手动触发 AI 分析未知域名；后端未起/超时 → 422 降级；结果落 pending 目录（用户确认后才进知识库）
  - `GET /api/config` — 读 `data/config.json`，脱敏（api_key 不回传原值，只标记是否已配置）
  - `POST /api/config` — 白名单写入（只接受 ai_backend/ai_api_key/ai_base_url/ai_model + kb_source 相关键），保存后**立即刷新 service.ai** 让新后端生效（不重启）
  - 启动时自动读 `data/config.json` 合进 `HomewardService` config（演示模式跳过）
- **前端**（设置 tab + unknown tab AI 按钮）
  - 新增"设置"tab + 齿轮 SVG icon（`index.html`）
  - `renderSettings()` — 后端类型下拉（关闭/Ollama/OpenAI 兼容）+ API Key 密码框 + Base URL + 模型名；保存按钮调 POST /api/config
  - `renderUnknown()` — AI 按钮按 `state.data.config.ai_backend` 状态动态启用/禁用
  - 事件绑定：`data-ai-analyze` + `data-save-ai-cfg`
  - `loadAll()` 容错拉 `/api/config`（没配置时返回空对象，不阻塞界面）
- **安全边界**：AI 默认关闭；只分析域名/行为元数据，不上传原始流量；API Key 只写本地 config.json，脱敏回显；结果须用户确认才进知识库
- 回归：408 passed

### `b92c13f` — feat(behavior): P1-3 行为识别增强

- **新增两条行为规则**（`src/knowledge_base/behaviors.json`）
  - `sleep_rhythm` 作息节律推断：scope=device，窗口 48h，活跃小时集中度 ≥ 60% 时告警；证据字段含 top_active_hour / active_hours / concentration_pct
  - `cross_device_tracking` 跨设备身份追踪：scope=cross，窗口 1h，≥ 2 台设备碰过同一目的地时告警；证据字段含 devices_hit / device_list
- **BehaviorDetector 扩展**（`src/analysis/behavior.py`）
  - `scan()` 新增 cross scope 分支：按 destination 聚合所有 device_flows 的 src_ip 集合
  - `_scan_cross_device()` / `_scan_sleep_rhythm()` / `_hour_distribution()` 三个 helper
  - retention 计算排除大窗口特殊规则，不污染全局 FIFO 裁剪阈值（保持 6h 基线）
- **rule_engine 新增 evidence 键**（`src/rule_engine/engine.py`）
  - `min_devices` — cross_device_tracking 跨设备聚合阈值
  - `active_hour_concentration_min` — sleep_rhythm 活跃小时集中度阈值
- **alerting 扩展模板占位符**（`src/analysis/alerting.py`）
  - TEMPLATE_KEYS 新增 5 个：devices_hit / device_list / top_active_hour / active_hours / concentration_pct
  - build_context 暴露 evidence 里的对应字段，无值时返回 0 / 空字符串
- **单测更新**（`tests/test_behavior_rules.py`）
  - 规则数 8 → 10；scope 白名单加 cross
- 回归：408 passed, 0 failed

### `e841bd2` — feat(report): P1-5 导出报告纳入趋势数据

- `/api/report?format=json` 追加 `"trend": {"days": 7, "points": [...]}` 段（从 TrendStore 取 7 天小时统计点）
- `/api/report?format=markdown` 末尾新增"活跃趋势"段：汇总指标（窗口/设备峰值/告警峰值/隐私分趋势）+ 每 6 小时采样表格（`[::6][-24:]`，最多 24 行）
- 实现路径：handler 层追加，不改 HomewardService 签名；trend_store 未启用时自动跳过
- 回归：408 passed, 0 failed

### `bd87ebb` — feat(trend): P1-4 数据持久化与趋势面板

- **TrendStore**（`src/adapters/trend_store.py`，新增）
  - 独立 SQLite（`data/trends.db`），与 ObservationStore（`data/observations.db`）完全解耦
  - 整点采样：每 3600 秒一条，叠加在现有 60s 持久化线程里，零额外线程
  - 只存统计数字：devices_total / alerts_active / privacy_score / unknown_domains — 不碰 MAC / 域名 / 流量内容
  - 30 天滚动清理
- **后端路由**（`src/ui/server.py`）
  - `GET /api/trends?days=7|14|30`
- **前端**（`src/ui/static/app.js` / `app.css` / `index.html`）
  - 新增"趋势"tab，设备数 / 活跃告警 / 隐私分三组 div-bar 图
  - 纯 HTML/CSS div 实现，不引 D3 / Chart.js，符合项目 CSP 策略
  - 演示模式自动关闭趋势面板（mock 数据不进 trends.db）
- 回归：41 passed（test_ui.py 首次验证）

---

## Phase 1 MVP 完成（历史快照）

MVP 五工作包，全部提交于 2026-H1。详细交付见 ROADMAP.md Phase 1 行。

| Commit | 工作包 | 说明 |
|---|---|---|
| `ed7aadf` | FEAT-01 KB 备源 | KB_SOURCE_BACKUP_URLS + 多源降级 |
| `8662c35` | S1-4 盲区覆盖率 | 指标 + 并发锁修复 |
| … | S0-3 验收 | 部署/真机打磨收尾 |
| … | S1-1 签发 | 闭源防误传机制 |
| … | S1-2 试用 | 离线日志导入体验链路 |
