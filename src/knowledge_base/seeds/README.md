# 域名库种子源（可再分发）

本目录下的 CSV 是家卫域名库的**离线种子源**，由 `scripts/merge_domains.py`
在合并时自动读取（schema 与 `../domains.csv` 完全一致：7 列）。

这些种子由家卫维护、采用 **MIT / CC0** 许可，可安全再分发进公开仓，
不依赖网络即可保证每次合并都有真实增量。

## 文件

| 文件 | 内容 | 类别覆盖 | 许可 |
|------|------|----------|------|
| `privacy_trackers.csv` | 主流广告/追踪/分析/归因厂商域名（通配） | advertising_sdk / analytics / tracker / telemetry | MIT（家卫整理） |
| `cloud_cdn.csv` | 主流云/对象存储/边缘 CDN 厂商通配 | cdn / cloud_storage / cloud | MIT（家卫整理） |

## 在线源（运行时抓取，见 `scripts/merge_domains.py::ONLINE_SOURCES`）

| 源 | URL | 许可 | 入库存否 | 类别 |
|----|-----|------|----------|------|
| StevenBlack/hosts | raw.githubusercontent.com/StevenBlack/hosts/master/hosts | MIT | 是（可再分发） | tracker |
| abuse.ch URLhaus | urlhaus.abuse.ch/downloads/csv/ | free (attribution) | 是（标注归属） | malware |
| Feodo Tracker 域名块 | feodotracker.abuse.ch/downloads/domainblocklist.txt | free (attribution) | 是（标注归属） | c2 |

> 在线源在合并时**超时/404/解析失败一律跳过**，并在报告里列明原因，
> 不影响离线种子与既有库。abuse.ch 要求署名，归属已记录于此文档。

## 同步纪律

- 种子为手工策展、稳定可再分发；新增请保持 7 列 schema 并补本表说明。
- 在线源如需扩充，在 `ONLINE_SOURCES` 追加条目（含 `license` 与
  `redistributable` 字段）；非可再分发源（如 GPL 滤表）**只抓不入库**，
  或仅作运行期 KB_SOURCE 拉取，不得打包进公开仓。
- 每次 `merge_domains.py --apply` 后 `VERSION` 自动 +1、`CHECKSUM` 由
  `make_kb_source.py` 重生；部署签名用私有 `kb_sign_seed.bin`。
