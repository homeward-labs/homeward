"""家卫 · 分析层

把一个持续到达的观测流，变成「人看得懂、且知道后果」的中文告警。

    ingest    : 采集层 Observation → 规则层 FlowRecord（补上 W1 到 W2 之间断掉的一截）
    behavior  : 按设备/目的地维护时间窗，跑行为规则，产出 BehaviorFinding
    alerting  : 把 finding 渲染成人话告警（Alert），并做去重 / 冷却 / 排序

本层**不产生任何阻断动作**：最重的输出也只是「建议」。
"""
