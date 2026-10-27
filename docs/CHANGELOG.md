# 家卫 Homeward — 变更日志

> 版本号格式：`YYYY-MM-DD.N`（当日第 N 次迭代）；社区版遵循 open-core 边界，闭源标准版/专业版的改动不纳入本文件。

所有时间均为本地提交时间（UTC+8）。

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
