#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""多源域名库合并 / 去重 / 升级工具（家卫知识库）。

把多个「域名 -> 归属/类别」来源规整成家卫统一的 ``domains.csv`` 格式，
按域名去重、按类别优先级与置信度合并冲突，产出升级后的知识库并自动
重写 ``VERSION`` 与 ``CHECKSUM``。

统一 schema（与 ``src/knowledge_base/domains.csv`` 一致，7 列）：
    domain,organization,category,confidence,description,action,side_effects

数据源分两类：
  1) 离线种子（仓库内 ``src/knowledge_base/seeds/*.csv``，MIT/CC0，可再分发）
     —— 不依赖网络，保证每次合并都有真实增量。
  2) 在线源（``ONLINE_SOURCES`` 注册表，含 URL / license / 解析器）
     —— 联网时抓取并合并；超时/不可达/解析失败一律跳过并在报告中列出，
        不影响其余源与离线种子。

设计要点：
  - 域名归一化：小写、去前导 ``*.`` / ``www.``、去末尾 ``.``；去重键 = 归一化域名。
  - 冲突合并优先级：负向类别(tracker/ads/malware/c2/phishing…) > 中性 > 正向
    (cloud/cdn/os_update/iot…)；同档内高置信度优先；再平手则保留已有(baseline)
    以减少知识库抖动。
  - 失败/不可达的源被跳过，不阻塞流程。
  - 不触碰私钥 / 签名：本工具只产出 CSV，CHECKSUM 由 ``make_kb_source.py`` 重生。

用法：
    python scripts/merge_domains.py            # 干跑：打印来源统计与冲突，不写盘
    python scripts/merge_domains.py --apply    # 写回 domains.csv + 自动 bump VERSION/CHECKSUM
    python scripts/merge_domains.py --apply --no-online   # 仅离线种子，不抓真源
    python scripts/merge_domains.py --apply --max-rows 2000 --timeout 15
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KB = REPO / "src" / "knowledge_base"
SEEDS = KB / "seeds"
DOMAINS = KB / "domains.csv"
VERSION = KB / "VERSION"
MAKE_KB = REPO / "scripts" / "make_kb_source.py"

FIELDS = ["domain", "organization", "category", "confidence", "description", "action", "side_effects"]

# 负向类别：隐私/安全工具最该拦的（tracker/ads/analytics/telemetry 偏隐私，
# malware/c2/phishing 偏安全）。冲突时负向优先于正向。
NEGATIVE = frozenset({
    "tracker", "ads", "advertising_sdk", "analytics", "telemetry",
    "malware", "c2", "phishing",
})
# 正向类别：合法云/系统/设备流量，冲突时应让位于负向。
BENIGN = frozenset({
    "cloud_storage", "cloud_backup", "os_update", "app_update",
    "cdn", "system_update", "backup", "iot_core", "developer_service",
    "machine_learning", "cloud",
})


@dataclass
class Row:
    domain: str
    organization: str
    category: str
    confidence: str
    description: str
    action: str
    side_effects: str
    source: str = ""

    def norm(self) -> str:
        d = self.domain.strip().lower()
        is_wild = d.startswith("*.")
        if is_wild:
            d = d[2:]
        if d.startswith("www."):
            d = d[4:]
        d = d.rstrip(".")
        # 保留通配前缀：*.x.com 与 x.com 视为不同键，二者共存（通配比精确更有覆盖价值）
        return ("*." + d) if is_wild else d

    def to_list(self) -> list[str]:
        return [self.domain, self.organization, self.category,
                self.confidence, self.description, self.action, self.side_effects]


# --------------------------------------------------------------------------
# 解析器
# --------------------------------------------------------------------------
def parse_csv_seed(text: str, source: str) -> list[Row]:
    """种子/通用 CSV：首行表头须含 FIELDS。防御性去 BOM。"""
    text = text.lstrip("\ufeff")
    rows: list[Row] = []
    reader = csv.DictReader(text.splitlines())
    for d in reader:
        if not d.get("domain"):
            continue
        rows.append(Row(
            d["domain"].strip(), d.get("organization", ""), d.get("category", ""),
            d.get("confidence", "medium"), d.get("description", ""),
            d.get("action", ""), d.get("side_effects", ""), source=source,
        ))
    return rows


def parse_hosts(text: str, category: str, action: str, org: str, source: str,
                max_rows: int) -> list[Row]:
    """StevenBlack 风格 hosts：每行 ``0.0.0.0  domain`` 或 ``127.0.0.1 domain``。"""
    rows: list[Row] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        host = parts[1]
        if host in ("0.0.0.0", "127.0.0.1", "localhost", "localhost.localdomain"):
            continue
        if not host.replace(".", "").isalnum() and "-" not in host:
            continue
        rows.append(Row(
            host, org, category, "high",
            f"{source} 聚合拦截域名", action,
            "广告/追踪或恶意通信被拦截；正常站点功能通常不受影响", source=source,
        ))
        if len(rows) >= max_rows:
            break
    return rows


def parse_urlhaus_csv(text: str, source: str, max_rows: int) -> list[Row]:
    """abuse.ch URLhaus：CSV（含表头），取 url 列的 host 作为域名，类别 malware。"""
    rows: list[Row] = []
    reader = csv.DictReader(text.splitlines())
    seen = set()
    for d in reader:
        url = d.get("url", "")
        if not url:
            continue
        host = url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0].strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)
        rows.append(Row(
            host, "unknown", "malware", "high",
            "URLhaus 恶意载荷域名", "block_medium",
            "恶意下载/载荷通信被拦截", source=source,
        ))
        if len(rows) >= max_rows:
            break
    return rows


# --------------------------------------------------------------------------
# 在线源注册表（URL / license / 解析器 / 是否可再分发入库）
# --------------------------------------------------------------------------
ONLINE_SOURCES: list[dict] = [
    {
        "id": "stevenblack",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "license": "MIT",
        "redistributable": True,
        "category": "tracker",   # 聚合广告/恶意域名，隐私工具统一拦截
        "action": "block_soft",
        "org": "StevenBlack/hosts",
        "parser": "hosts",
    },
    {
        "id": "urlhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv/",
        "license": "free (attribution, abuse.ch)",
        "redistributable": True,
        "parser": "urlhaus",
    },
    {
        "id": "feodo_domains",
        "url": "https://feodotracker.abuse.ch/downloads/domainblocklist.txt",
        "license": "free (attribution, abuse.ch)",
        "redistributable": True,
        "category": "c2",
        "action": "block_medium",
        "org": "Feodo Tracker",
        "parser": "hosts",  # 该列表为纯域名每行一个（无 IP 前缀）
    },
]


# --------------------------------------------------------------------------
# 合并逻辑
# --------------------------------------------------------------------------
def cat_tier(c: str) -> int:
    if c in NEGATIVE:
        return 2
    if c in BENIGN:
        return 0
    return 1


def conf_rank(c: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get((c or "").lower(), 1)


def resolve(a: Row, b: Row) -> Row:
    """冲突合并：负向 > 中性 > 正向；同档高置信优先；再平手保留已有(baseline)。"""
    ta, tb = cat_tier(a.category), cat_tier(b.category)
    if ta != tb:
        return a if ta > tb else b
    ca, cb = conf_rank(a.confidence), conf_rank(b.confidence)
    if ca != cb:
        return a if ca > cb else b
    if a.source == "baseline":
        return a
    if b.source == "baseline":
        return b
    return a


def load_baseline() -> list[Row]:
    if not DOMAINS.exists():
        return []
    with DOMAINS.open(encoding="utf-8") as f:
        return parse_csv_seed(f.read(), "baseline")


def fetch_online(src: dict, timeout: int, max_rows: int) -> tuple[list[Row], str]:
    try:
        req = urllib.request.Request(src["url"], headers={"User-Agent": "homeward-kb-merge/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
    except Exception as e:  # 网络/超时/404 等一律跳过
        return [], f"跳过({src['id']}): {type(e).__name__}: {e}"

    if src["parser"] == "hosts":
        rows = parse_hosts(text, src.get("category", "tracker"),
                           src.get("action", "block_soft"), src.get("org", ""),
                           src["id"], max_rows)
    elif src["parser"] == "urlhaus":
        rows = parse_urlhaus_csv(text, src["id"], max_rows)
    else:
        return [], f"跳过({src['id']}): 未知解析器"
    return rows, f"已合并({src['id']}): {len(rows)} 行 (license={src['license']})"


def merge_all(use_online: bool, timeout: int, max_rows: int):
    sources: dict[str, list[Row]] = {}
    notes: list[str] = []

    baseline = load_baseline()
    sources["baseline"] = baseline
    notes.append(f"baseline: {len(baseline)} 行（既有知识库）")

    if SEEDS.is_dir():
        for p in sorted(SEEDS.glob("*.csv")):
            rows = parse_csv_seed(p.read_text(encoding="utf-8"), f"seed:{p.stem}")
            sources[p.stem] = rows
            notes.append(f"seed:{p.stem}: {len(rows)} 行")

    if use_online:
        for src in ONLINE_SOURCES:
            rows, msg = fetch_online(src, timeout, max_rows)
            notes.append(msg)
            if rows:
                sources[src["id"]] = rows
    else:
        notes.append("在线源：已禁用(--no-online)")

    # 合并：按 norm 域名去重，冲突按 resolve 规则裁决
    merged: dict[str, Row] = {}
    order: list[str] = []
    conflicts = 0
    for sname, rows in sources.items():
        for r in rows:
            key = r.norm()
            if not key:
                continue
            if key in merged:
                old = merged[key]
                if (old.category != r.category) or (old.source != r.source):
                    conflicts += 1
                merged[key] = resolve(old, r)
            else:
                merged[key] = r
                order.append(key)

    out_rows: list[Row] = [merged[k] for k in order]
    return out_rows, notes, conflicts, len(baseline)


def bump_version() -> str:
    if not VERSION.exists():
        VERSION.write_text("1.0.4\n", encoding="utf-8")
        return "1.0.4"
    v = VERSION.read_text(encoding="utf-8").strip() or "1.0.3"
    parts = v.split(".")
    try:
        parts[-1] = str(int(parts[-1]) + 1)
    except ValueError:
        parts.append("4")
    nv = ".".join(parts)
    VERSION.write_text(nv + "\n", encoding="utf-8")
    return nv


def write_domains(rows: list[Row]) -> None:
    with DOMAINS.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(FIELDS)
        for r in rows:
            w.writerow(r.to_list())


def regen_checksum() -> str:
    try:
        out = subprocess.run(
            [sys.executable, str(MAKE_KB)], capture_output=True, text=True, timeout=60,
        )
        return out.stdout.strip().splitlines()[-1] if out.stdout.strip() else out.stderr.strip()
    except Exception as e:  # pragma: no cover
        return f"CHECKSUM 重生失败：{e}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="家卫域名库多源合并/去重/升级")
    ap.add_argument("--apply", action="store_true", help="写回 domains.csv 并 bump VERSION/CHECKSUM")
    ap.add_argument("--no-online", action="store_true", help="不抓取在线源，仅离线种子")
    ap.add_argument("--timeout", type=int, default=15, help="在线源超时(秒)")
    ap.add_argument("--max-rows", type=int, default=3000, help="单在线源最大行数")
    args = ap.parse_args(argv)

    out_rows, notes, conflicts, base_n = merge_all(
        use_online=not args.no_online, timeout=args.timeout, max_rows=args.max_rows,
    )

    print("==== 来源统计 ====")
    for n in notes:
        print("  " + n)
    print(f"==== 合并结果：{len(out_rows)} 行（原 baseline {base_n}），冲突裁决 {conflicts} 次 ====")

    if not args.apply:
        print("\n[干跑] 未写盘。加 --apply 执行。")
        return 0

    write_domains(out_rows)
    nv = bump_version()
    chk = regen_checksum()
    print(f"\n[已写盘] domains.csv -> {len(out_rows)} 行；VERSION -> {nv}；CHECKSUM 已重生：{chk}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
