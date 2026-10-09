#!/usr/bin/env python3
"""按来源拆分域名库 —— 合规刚需，不是可选的整理。

背景
----
``src/knowledge_base/domains.csv`` 是**合并产物**，其中大部分条目来自 MIT 许可的
公开源（StevenBlack/hosts、NoCoin）。MIT 允许商用与再分发、**不得附加额外限制**，
因此绝不能把整库用一个许可（如 CC BY-NC 或自定义禁商用许可）整体覆盖 ——
那样既违反上游许可，又锁了一堆人人可得的零差异化数据。

本脚本把合并产物按来源拆成两个**再分发单元**：

* ``domains_public.csv``    —— 来源为公开源，沿用上游许可（MIT / free-attribution），必须署名
* ``domains_homeward.csv``  —— 家卫策展（种子与手工补录），**CC BY 4.0**（公开换众包）

设计约束（不要改）
------------------
**``domains.csv`` 仍是唯一的加载入口与更新单元**（见 ``constants.py`` 的
``REQUIRED_DATA_FILES``）。拆分出的两个文件是**来源归档 / 再分发单元**，
**不加入更新清单** —— 否则线上内容源（只发 domains.csv）会因必需文件缺失
导致客户端更新整体失败。

用法
----
::

    python scripts/split_domains_by_source.py            # 只统计，不写文件
    python scripts/split_domains_by_source.py --apply    # 实际写出两个文件
    python scripts/split_domains_by_source.py --source <母本.csv> --apply

``--source`` 用于母本与仓库版本尚未同步时（母本在私有目录，**路径只作运行时参数传入，
绝不写进本脚本**，遵守公开仓不泄露私有目录结构的红线）。
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KB_DIR = REPO_ROOT / "src" / "knowledge_base"

SRC = KB_DIR / "domains.csv"
PUBLIC_OUT = KB_DIR / "domains_public.csv"
HOMEWARD_OUT = KB_DIR / "domains_homeward.csv"

# 公开源判别依据：organization 列（小写比较、去首尾空格）。
# 新增公开源时在这里登记，并同步更新 src/knowledge_base/SOURCES.md。
PUBLIC_ORGS = {"stevenblack/hosts", "nocoin"}

FALLBACK_FIELDS = [
    "domain",
    "organization",
    "category",
    "confidence",
    "description",
    "action",
    "side_effects",
]


def classify(organization: str) -> str:
    """把一条记录归到 public（公开源）或 homeward（家卫策展）。"""
    return "public" if organization.strip().lower() in PUBLIC_ORGS else "homeward"


def main() -> int:
    parser = argparse.ArgumentParser(description="按来源拆分域名库（合规刚需）")
    parser.add_argument("--apply", action="store_true", help="实际写出拆分文件（默认只统计）")
    parser.add_argument("--source", default=None, help="指定源 CSV（默认仓库内 src/knowledge_base/domains.csv）")
    args = parser.parse_args()

    src = Path(args.source).resolve() if args.source else SRC

    if not src.exists():
        print(f"找不到源文件：{src}")
        return 1

    with src.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames or FALLBACK_FIELDS
        rows = list(reader)

    buckets: dict[str, list[dict]] = {"public": [], "homeward": []}
    for row in rows:
        buckets[classify(row.get("organization", ""))].append(row)

    total = len(rows)
    try:
        src_label = src.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        src_label = "（外部母本，路径不回显）"
    print(f"源文件：{src_label}  共 {total} 条")
    print()
    for name, out in (("public", PUBLIC_OUT), ("homeward", HOMEWARD_OUT)):
        count = len(buckets[name])
        pct = (count / total * 100) if total else 0.0
        print(f"  {name:<9} {count:>5} 条 ({pct:5.1f}%)  ->  {out.name}")
    print()

    if not args.apply:
        print("（dry-run，未写文件）加 --apply 实际写出。")
        return 0

    for name, out in (("public", PUBLIC_OUT), ("homeward", HOMEWARD_OUT)):
        with out.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(buckets[name])
        print(f"已写入 {out.relative_to(REPO_ROOT).as_posix()}  ({len(buckets[name])} 条)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
