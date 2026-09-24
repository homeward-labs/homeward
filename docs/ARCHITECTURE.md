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

> **决策引擎产出的是「建议」，不是「动作」。** 早期版本这里直接 `return Decision.BLOCK_SOFT`，
> 读起来像是引擎会自己去拦 —— 与产品承诺「不默认自动阻断，一切以你确认为准」直接冲突，
> 而且 `src/core/main.py` 当初就是照这段伪代码实现了自动下发。已统一为建议语义。

```python
def decide(record, rule_hits) -> Decision:
    """产出建议，不产出动作

    社区版到此为止：返回的是「我们建议怎么处理」，不是「已经这么处理了」。
    真实下发属于标准版（闭源），走 Enforcer.apply() + ActionRegistry，
    且必须经用户确认后才发生。
    """
    # 1. 白名单优先
    if record.domain in whitelist:
        return Decision.ALLOW

    # 2. 精确命中已知规则 → 建议对应级别的阻断，**等待用户确认**
    for hit in rule_hits:
        if hit.confidence == "high":
            return Decision.SUGGEST_BLOCK(level=hit.action)  # soft / medium / hard

    # 3. 模式匹配（低置信度）→ 只告警，不建议阻断
    if any(hit.confidence == "medium" for hit in rule_hits):
        return Decision.WARN

    # 4. 完全未知 → 等待用户手动触发 AI 分析
    return Decision.UNKNOWN
```

### 2.5 动作执行层

| 决策 | 社区版做什么 | 标准版多做什么 |
|---|---|---|
| **ALLOW** | 不做任何事 | 同左 |
| **WARN** | 记录日志 + Web UI 展示 | 同左 |
| **SUGGEST_BLOCK_SOFT** | 建议 DNS 级黑洞（dnsmasq `address=/域名/0.0.0.0` → NXDOMAIN），写入建议队列 + 后果预览 | 用户确认后由 Enforcer 真正下发 |
| **SUGGEST_BLOCK_MEDIUM** | 建议网段 / ASN 级 drop，同上 | 同上 |
| **SUGGEST_BLOCK_HARD** | 建议移入 IoT VLAN（默认禁止外网），并说明需交换机 / OpenWrt 配置权 | 同上 |
| **UNKNOWN** | 展示在「未知域名」列表，等待用户操作 | 同左 |

> 三级阻断的实现细节见 [BLOCKING.md](./BLOCKING.md)；撤销语义（30 分钟一键撤销、
> `redeemable_until` / `auto_release_at`）与工程载体 `revert_payload` 同样在该文第四节。

---

## 三、知识库设计

### 3.1 域名归属库（domains.csv）

```csv
domain,organization,category,confidence,description,action,side_effects
ot.io.mi.com,Xiaomi,cloud_storage,high,小米IoT设备指令与状态通道,allow,
api.ad.tuya.com,Tuya Smart,advertising_sdk,high,涂鸦广告归因,block_soft,广告推送停止
xiaomi.speech.ai,Xiaomi,machine_learning,medium,小米语音AI处理,block_medium,语音助手可能受限
collector.pending.example,Unknown,unknown,low,待判定域名,warn,需进一步确认
```

字段说明（以 `src/knowledge_base/domains.csv` 实际表头为准）：
- `category`：IoT_core / cloud_storage / analytics / advertising_sdk / telemetry /
  machine_learning / cdn / unknown
- `action`：**建议动作**，不是系统会自动做的事 —— allow / warn / block_soft /
  block_medium / block_hard（阻断类一律需用户确认，实际下发属标准版）
- `side_effects`：中文分号分隔的后果说明，供「阻断后果预览」使用；allow 类留空

数据以 **CC BY 4.0** 发布，使用须署名，见 `src/knowledge_base/LICENSE`。

### 3.2 行为模式库（behaviors.json）

当前内置 8 个行为：心跳信标、突发大流量上传、周期性外联、疑似 DNS 隧道、
局域网 mDNS 扫描、疑似挖矿、疑似 C2 通信、疑似固件后门。

```json
{
  "heartbeat_beacon": {
    "name": "心跳信标",
    "description": "设备每隔固定时间发送小包，疑似心跳信标，可能用于在线状态追踪或跨设备关联",
    "severity": "low",
    "category": "telemetry",
    "pattern": {
      "interval": { "min": 30, "max": 60 },
      "packet_size": { "min": 40, "max": 100 },
      "direction": "out",
      "min_occurrences": 10
    },
    "action": "warn",
    "explanation": "设备 {device_name} 每约 {interval} 秒发送一次小数据包到 {destination}。…",
    "side_effects": "阻断可能导致设备离线状态，但本地控制不受影响"
  }
}
```

`pattern` 字段语义（判定实现见 `src/rule_engine/engine.py::BehaviorMatcher._matches`，
两条最易踩错的写在那里）：
- `interval`：相邻观测的**时间间隔**（秒），必须真的去算时间差，不能只看包大小
- `duration_min`：观测窗口长度（**秒**），不是记录条数
- `total_bytes_min`：窗口内累计字节数下限
- `packet_size`：窗口内**平均**包大小范围
- `min_occurrences`：最少出现次数，样本不够不下结论

`explanation` 是中文模板，`{device_name}` / `{destination}` 等占位由告警层填充。

### 3.3 在线更新

知识库定期从社区仓库拉取更新（默认每周），用户可关闭。更新方式：

- 启动时检查版本
- 后台静默下载
- 原子替换（不中断服务）

---

## 四、Web UI 设计原则

### 4.1 首页：一屏看懂

> **图标约定**：下图里 `〔xxx〕` 是图标占位，实现时一律取项目锁定的 SVG 图标库
> （16 / 20 / 24px 三档，统一描边）。**禁止用 emoji 当功能图标** —— emoji 在各平台
> 字形不一致、无法统一描边与缩放，混进 UI 会立刻显得廉价且不可控。

```
┌─────────────────────────────────────────────────────┐
│  〔home〕 你的家 · 24 台设备在线                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  〔alert〕 3 个告警需要关注                          │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ 〔camera〕 卧室摄像头 (Xiaomi Cam v2)          │  │
│  │ 02:03–02:17 向 storage.ml-ops.samsung.com      │  │
│  │ 上传了 4.2MB 数据                              │  │
│  │ 〔warn〕 该域名属于三星 ML 平台，               │  │
│  │         与「云录像已关闭」不符                  │  │
│  │ [预览阻断后果] [查看详情] [帮我分析]            │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ 〔bulb〕 客厅灯泡 (Philips Hue)                │  │
│  │ 已连续 14 天每天向 api.ad.tuya.com 发送数据     │  │
│  │ 该域名属于涂鸦广告归因 SDK                      │  │
│  │ [预览阻断后果] [查看详情]                      │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ 〔help〕 未知域名 2 个                         │  │
│  │ cdn-edge-7f3a.unknowndomain.net (客厅电视)     │  │
│  │ [帮我分析]                                     │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
├─────────────────────────────────────────────────────┤
│ 〔list〕 设备列表 │ 〔shield〕 阻断建议 │             │
│ 〔network〕 网络拓扑 │ 〔settings〕 设置             │
└─────────────────────────────────────────────────────┘
```

### 4.2 关键交互细节

- **未识别域名天然浮顶**：首页只列「未识别」，已命中的折叠
- **一键操作**：社区版点一下出「建议 + 后果预览」并明确标注「需你确认」；
  标准版在用户确认后才真正下发（社区版按钮不得写成「一键阻断」）
- **阻断后果预览**：弹窗告知影响范围，数据来自知识库 `side_effects` 字段
- **AI 触发入口醒目**：「帮我分析」按钮直接出现在未知域名卡片上
