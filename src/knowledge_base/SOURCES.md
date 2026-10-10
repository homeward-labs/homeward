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
| `domains_homeward.csv` | 1569 | 家卫策展（离线种子 + 手工补录 + v1.1.0 精选扩库 1044 条） | **CC BY 4.0**（见 `LICENSE`） | ✅ | 必须 |
| `domains.csv` | 4528 | 上面两者合并（**加载与更新单元**） | 混合，**按条目分别适用** | 按条目 | 按条目 |

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
