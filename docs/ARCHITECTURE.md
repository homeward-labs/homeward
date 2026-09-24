# 架构设计

## 一、设计哲学

### 1.1 不解密 TLS

加密内容的保护靠法律（TLS 本身就是设计来防止中间人），我们不做 MITM。但 TLS 藏不住的是：

- **SNI**（Server Name Indication）：明文的，告诉所有人你要连谁
- **目的地 IP + ASN**：路由信息
- **包大小、频率、时序**：元数据

这些信号足够做 90% 的判断。剩下的 10%（payload 内容）我们明确不做。

### 1.2 AI 的角色边界

```
AI 负责                           AI 不负责
─────────                         ─────────
· 翻译人话（已知域名→中文解释）     · 实时拦截判定
· 分析未知域名归属                  · 规则库维护
· 生成告警文案                     · 阻断动作执行
· 回灌规则（用户确认后）            · 任何需要确定性的判断
```

**为什么 AI 不做拦截**：安全产品必须可审计。规则库里写了就是写了，模型输出的归因说不清楚。

### 1.3 默认关闭 AI

- AI 功能默认关闭
- 用户主动点击「帮我分析」才触发
- LLM 调用可选择：本地 Ollama / 用户自备 API Key
- **路由器不依赖任何外部服务即可正常工作**

---

## 二、数据流

```
采集层 → 标准化 → 规则匹配 → 决策引擎 → 动作执行
   │         │         │          │          │
   ▼         ▼         ▼          ▼          ▼
原始数据    FlowRecord  命中规则   告警/阻断    iptables/nftables
DNS日志     DnsRecord   未命中     建议文案     规则下发
```

### 2.1 采集层

不同适配器采集不同粒度的数据：

| 适配器 | 数据粒度 | 平台 |
|---|---|---|
| nftables/NFLOG | flow 级（五元组+字节数） | OpenWrt / 原生 Linux |
| dnsmasq/unbound | DNS 全量日志 | 全平台 |
| libpcap | 包级元数据（不含 payload） | Docker 特权模式 |
| eBPF | 内核级流表 | 高版本内核 |

### 2.2 标准化层

所有适配器输出统一的 `FlowRecord` / `DnsRecord`，上层不关心数据来源。

### 2.3 规则匹配层

三层规则，按顺序匹配，命中即停：

```
第1层：域名精确匹配        api.ad.tuya.com → 广告SDK → 建议阻断
第2层：域名模式匹配        *.ad.*.com      → 疑似广告
第3层：行为特征匹配        心跳信标/突发上传/周期性外联
```

未命中 → 进入 AI 分析队列（手动触发）。

### 2.4 决策引擎

```python
def decide(record, rule_hits) -> Decision:
    # 1. 白名单优先
    if record.domain in whitelist:
        return Decision.ALLOW

    # 2. 精确命中已知规则
    for hit in rule_hits:
        if hit.confidence == "high":
            return Decision.BLOCK_SOFT  # 或 BLOCK_MEDIUM / BLOCK_HARD

    # 3. 模式匹配（低置信度）
    if any(hit.confidence == "medium" for hit in rule_hits):
        return Decision.WARN  # 告警但不阻断

    # 4. 完全未知 → 等待用户手动触发 AI 分析
    return Decision.UNKNOWN
```

### 2.5 动作执行层

- **ALLOW**：不做任何事
- **WARN**：记录日志 + Web UI 展示
- **BLOCK_SOFT**：nftables 阻断该域名（DNS 返回 NXDOMAIN）
- **BLOCK_MEDIUM**：阻断整个第三方 ASN
- **BLOCK_HARD**：将设备移入 IoT VLAN（默认禁止外网）
- **UNKNOWN**：展示在「未知域名」列表，等待用户操作

---

## 三、知识库设计

### 3.1 域名归属库（domains.csv）

```csv
domain,organization,category,confidence,description,action
api.ad.tuya.com,Tuya Smart,advertising_sdk,high,涂鸦广告归因SDK,block_soft
ot.io.mi.com,Xiaomi,IoT_core,high,小米IoT设备指令通道,allow
storage.ml-ops.samsung.com,Samsung,machine_learning,medium,三星ML运维平台,block_medium
```

字段说明：
- `category`：advertising_sdk / IoT_core / analytics / cdn / unknown
- `action`：allow / block_soft / block_medium / block_hard / warn

### 3.2 行为模式库（behaviors.json）

```json
{
  "heartbeat_beacon": {
    "name": "心跳信标",
    "pattern": {
      "interval": { "min": 30, "max": 60 },
      "packet_size": { "min": 40, "max": 100 },
      "direction": "out"
    },
    "description": "设备每隔固定时间发送小包，疑似心跳信标，可能用于在线状态追踪",
    "severity": "low"
  },
  "bulk_upload": {
    "name": "突发大流量上传",
    "pattern": {
      "duration_min": 60,
      "total_bytes_min": 1048576,
      "direction": "out"
    },
    "description": "短时间内持续上传大量数据，疑似视频/音频外传",
    "severity": "high"
  }
}
```

### 3.3 在线更新

知识库定期从社区仓库拉取更新（默认每周），用户可关闭。更新方式：

- 启动时检查版本
- 后台静默下载
- 原子替换（不中断服务）

---

## 四、Web UI 设计原则

### 4.1 首页：一屏看懂

```
┌─────────────────────────────────────────────────────┐
│  🏠 你的家 · 24 台设备在线                           │
├─────────────────────────────────────────────────────┤
│                                                     │
│  🔴 3 个告警需要关注                                 │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ 📷 卧室摄像头 (Xiaomi Cam v2)                  │  │
│  │ 02:03–02:17 向 storage.ml-ops.samsung.com      │  │
│  │ 上传了 4.2MB 数据                               │  │
│  │ ⚠️ 该域名属于三星 ML 平台，与"云录像已关闭"不符  │  │
│  │ [一键软隔离] [查看详情] [帮我分析]              │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ 💡 客厅灯泡 (Philips Hue)                      │  │
│  │ 已连续 14 天每天向 api.ad.tuya.com 发送数据     │  │
│  │ 该域名属于涂鸦广告归因 SDK                      │  │
│  │ [一键阻断] [查看详情]                          │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ ❓ 未知域名 2 个                                │  │
│  │ cdn-edge-7f3a.unknowndomain.net (客厅电视)     │  │
│  │ [帮我分析]                                     │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
├─────────────────────────────────────────────────────┤
│ 📊 设备列表 | 🔒 阻断规则 | 🌐 网络拓扑 | ⚙️ 设置  │
└─────────────────────────────────────────────────────┘
```

### 4.2 关键交互细节

- **未识别域名天然浮顶**：首页只列「未识别」，已命中的折叠
- **一键操作**：阻断/放通/隔离，点一下就生效
- **阻断后果预览**：弹窗告知影响范围
- **AI 触发入口醒目**：「帮我分析」按钮直接出现在未知域名卡片上
