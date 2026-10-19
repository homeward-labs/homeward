# 域名库来源与许可（合规必读）

`domains.csv` 是**合并产物**，由不同来源的数据合成。

> ⚠️ **不同来源受不同许可约束，不能用一个许可整体覆盖。**
> 其中 MIT 公开源部分允许商用与再分发、**且不得附加额外限制** ——
> 因此把整库标成 CC BY-NC 或自定义禁商用许可，既违反上游许可，
> 又只是锁住了一批人人可得的零差异化数据。

## 三个再分发单元

| 文件 | 条数 | 来源构成 | 适用许可 | 商用 | 署名 |
|---|---|---|---|---|---|
| `domains_public.csv` | 2959 | StevenBlack/hosts 2653 + NoCoin 306 | **MIT**（沿用上游） | ✅ | **必须** |
| `domains_homeward.csv` | 2119 | 家卫策展（离线种子 + 手工补录 + v1.1.0 精选扩库 1044 条 + 2026-10-19 零命中域补录 8 条） | **CC BY 4.0**（见 `LICENSE`） | ✅ | 必须 |
| `domains.csv` | 5078 | 上面两者合并（**加载与更新单元**） | 混合，**按条目分别适用** | 按条目 | 按条目 |

### 设计约束（不要改）

**`domains.csv` 仍是唯一的加载入口与更新单元**（见 `constants.py` 的
`REQUIRED_DATA_FILES`）。两个拆分文件是**来源归档 / 再分发单元**，
**不加入更新清单** —— 否则线上内容源（只发 `domains.csv`）会因必需文件缺失
导致客户端更新整体失败。

## 署名要求

再分发 `domains_public.csv` 或合并产物时，**必须保留以下署名**：

```
本产品包含来自 StevenBlack/hosts (https://github.com/StevenBlack/hosts) 的
域名数据，以 MIT 许可发布。
本产品包含来自 NoCoin (https://github.com/hoshsadiq/adblock-nocoin-list) 的
域名数据，以 MIT 许可发布。
```

家卫策展部分的署名格式见 `LICENSE`。

## 红线

- **不得引入 GPL / AGPL 许可的源**（`scripts/merge_domains.py` 用 `redistributable`
  标记控制；非可再分发源只抓不入库）。
- 新增公开源必须**三处同步登记**：
  1. `seeds/README.md` 的在线源表
  2. 本文件的来源构成表
  3. `scripts/split_domains_by_source.py` 的 `PUBLIC_ORGS`（决定拆分归属）

## 拆分与同步

```bash
python scripts/split_domains_by_source.py            # 只统计
python scripts/split_domains_by_source.py --apply    # 写出两个拆分文件
```

母本与仓库版本尚未同步时，用 `--source <母本.csv>` 指定源文件
（母本路径属私有信息，**只作运行时参数传入，绝不写进脚本**）。

## 自动 Feed 管道（feed_pipeline.py）

手工精选只能一次性补充；要让库**随时间自然增长**到 5000+，靠自动 feed 管道。

- 源清单：`scripts/feed_registry.json`（**公开可审计**，每个源标注 `url` / `format` / `license` / `mit_compatible` / 默认 `action`）。
- 运行：
  ```bash
  python scripts/feed_pipeline.py            # 联网拉取 + 合并 + 重签
  python scripts/feed_pipeline.py --offline  # 只用本地缓存（无网 / 沙箱）
  python scripts/feed_pipeline.py --dry      # 只统计不写文件
  ```
- 合规分流（不得越过）：
  - `mit_compatible=true`（MIT / CC0 / 公域）→ 进 **public 层**（`organization=源 id`），沿用上游许可，**不附加限制**。
  - 其余（自定义但允许署名）→ 进 **homeward 层**（CC BY 4.0 策展），署名归档。
  - 新增 `mit_compatible` 源由管道**自动同步** `scripts/split_domains_by_source.py` 的 `PUBLIC_ORGS`，无需手改三处。
  - **严禁**引入 oisd / hagezi 等 GPLv3 / 非商用源（见项目 MEMORY 红线）。
- 调度（定期增长）：Linux/macOS cron 每日
  `17 3 * * * cd /path/homeward && /usr/bin/python3 scripts/feed_pipeline.py >> /var/log/homeward-feed.log 2>&1`；
  Windows 任务计划程序设「每日」触发器启 python 跑本脚本。
- 缓存目录 `scripts/.feed_cache/`（已 gitignore），保存最近拉取的原始源，断网可回退。

当前登记源（feed 管道就绪，首次真实运行将 bump VERSION）：

| feed id | license | 层 | 备注 |
|---|---|---|---|
| `stevenblack/hosts` | MIT | public | 主力源，定期刷新去重 |
| `nocoin` | MIT | public | 反挖矿 |
| `anudeep/adservers` | MIT | public | 广告服务器清单 |
| `perflyst/smarttv` | MIT | public | 智能电视 / IoT 遥测（贴合护城河） |
| `sinfonietta/social` | 未声明（保留版权） | homeward | 社交平台追踪 |
| `blocklistproject/ads` | 自定义（需署名） | homeward | 广告 |
| `blocklistproject/malware` | 自定义（需署名） | homeward | 恶意通信 |

## 发布到内容源（publish_kb_source.py）

feed 管道 / 手工改完 `domains_homeward.csv` 后，必须把最新、已签名的 bundle 推到内容源，
客户端（默认源 `homeward-kb.782238788.workers.dev`）才能拉到。

- 脚本：`scripts/publish_kb_source.py`
- 本地先预览会发哪些文件（不联网）：
  ```bash
  python scripts/publish_kb_source.py --dry
  ```
- 真实发布到 Cloudflare KV（推荐）：
  ```bash
  export CF_ACCOUNT_ID=<你的账户ID>
  export CF_API_TOKEN=<具有 KV 编辑权限的 Token>
  export HOMEWARD_KB_SIGN_SEED=<kb_sign_seed.bin 的 hex>
  python scripts/publish_kb_source.py --target kv --namespace-id <KV命名空间ID> --bump patch
  # 发完回源验证
  python scripts/publish_kb_source.py --verify-url https://homeward-kb.782238788.workers.dev
  ```
- 备选 R2：`--target r2 --bucket <桶名>`（走本机 `wrangler r2 object put`）。
- Worker 模板：`workers/kb-source.js` + `workers/wrangler.toml`（`wrangler deploy` 即用）。
- **密钥只走环境变量 / 参数**（CF_API_TOKEN、HOMEWARD_KB_SIGN_SEED），脚本内不写任何密钥。
- 被发布的 bundle 白名单：`VERSION` / `domains.csv` / `behaviors.json` / `oui_prefixes.csv` /
  `CHECKSUM` / `SIGNATURE` / `LICENSE`（与 `updater.py` 的 REQUIRED/OPTIONAL 清单一致）。
