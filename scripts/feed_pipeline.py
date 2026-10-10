#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""家卫知识库 feed 管道 —— 自动拉取/归并真实公开源，让库随时间自然增长。

设计目标
--------
把"手工精选 + 自动 feed"结合：feed 管道定期从 ``feed_registry.json`` 中登记的
真实公开源拉取域名，与现有库（public + homeward 策展）三重去重，按源许可分流到
public(MIT 沿用) / homeward(CC BY 4.0 策展) 层，重建 ``domains.csv`` 并重签。

合规约束（不要越过）
--------------------
1. 只收录 MIT / CC0 / 公域 或「自定义但允许署名」的源；oisd、hagezi 等
   GPLv3 / 非商用源**禁止**进入公开层（见项目 MEMORY 红线）。
2. ``mit_compatible=true`` 的源才进 public 层（沿用上游许可，不得附加限制）；
   其余进 homeward 层（CC BY 4.0，要求署名）。
3. 分流靠 ``domains.csv`` 的 ``organization`` 列；新增 mit_compatible 源会
   自动同步 ``scripts/split_domains_by_source.py`` 的 ``PUBLIC_ORGS``，保证拆分正确。
4. 本脚本**不硬编码签名私钥**；通过 ``--seed`` 或环境变量 ``HOMEWARD_KB_SIGN_SEED``
   注入（私钥在 家卫私有/license/，绝不入公开仓）。

用法
----
    python scripts/feed_pipeline.py                 # 联网拉取 + 合并 + 重签
    python scripts/feed_pipeline.py --offline       # 只用本地 cache（沙箱/无网）
    python scripts/feed_pipeline.py --dry           # 只统计不写文件
    python scripts/feed_pipeline.py --no-sign       # 算 CHECKSUM 但不重签
    python scripts/feed_pipeline.py --seed <hex>    # 临时注入签名种子

测试（不污染真实库）
--------------------
    python scripts/feed_pipeline.py --kb-dir /tmp/kbtest --no-sync-orgs --offline --seed <hex>

调度（定期增长）
----------------
cron 每日 03:17（Linux/macOS）：
    17 3 * * * cd /path/homeward && /usr/bin/python3 scripts/feed_pipeline.py >> /var/log/homeward-feed.log 2>&1
Windows 任务计划程序：触发器「每日」，操作启动 python.exe 跑本脚本。
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY = REPO_ROOT / "scripts" / "feed_registry.json"
SPLIT_SCRIPT = REPO_ROOT / "scripts" / "split_domains_by_source.py"

FIELDS = ["domain", "organization", "category", "confidence",
          "description", "action", "side_effects"]

LOCALHOST_LIKE = {"localhost", "localhost.localdomain", "broadcasthost",
                  "local", "ip6-localhost", "ip6-loopback"}


def log(msg: str) -> None:
    print(f"[feed] {msg}")


# ---------- registry ----------
def load_registry() -> dict:
    if not REGISTRY.exists():
        raise SystemExit(f"[feed] 找不到 feed 清单：{REGISTRY}")
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


# ---------- fetch + cache ----------
def cache_path(reg: dict, feed: dict) -> Path:
    cache_dir = REPO_ROOT / "scripts" / reg.get("cache_dir", ".feed_cache")
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / (feed["id"].replace("/", "_") + ".txt")


def fetch_feed(reg: dict, feed: dict, offline: bool) -> str | None:
    cp = cache_path(reg, feed)
    if offline:
        if cp.exists():
            log(f"(offline) 用缓存 {cp.name}")
            return cp.read_text(encoding="utf-8", errors="replace")
        log(f"(offline) 缓存缺失 {cp.name}，跳过 {feed['id']}")
        return None
    try:
        req = urllib.request.Request(
            feed["url"],
            headers={"User-Agent": reg.get("user_agent", "homeward-feed/1.0")},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        cp.write_text(text, encoding="utf-8")
        log(f"拉取 {feed['id']} 成功（{len(text)} 字节，已缓存）")
        return text
    except Exception as e:  # noqa: BLE001
        if cp.exists():
            log(f"拉取 {feed['id']} 失败（{e}），回退缓存")
            return cp.read_text(encoding="utf-8", errors="replace")
        log(f"拉取 {feed['id']} 失败且无缓存（{e}），跳过")
        return None


# ---------- parse ----------
def normalize_domain(raw: str) -> str | None:
    d = raw.strip().lower()
    if not d or d.startswith("#") or d.startswith("!"):
        return None
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.strip(".")
    if not d or "." not in d:
        return None
    if d in LOCALHOST_LIKE:
        return None
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", d):
        return None
    if d.startswith("::") or ":" in d:
        return None
    return d


def parse_hosts(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            cand = parts[-1].split("#")[0].strip()
            dom = normalize_domain(cand)
            if dom:
                out.add(dom)
        elif parts:
            dom = normalize_domain(parts[0])
            if dom:
                out.add(dom)
    return out


def parse_adblock(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("!"):
            continue
        m = re.match(r"^\|\|([^/\^\s]+)\^?", line)
        if m:
            dom = normalize_domain(m.group(1))
            if dom:
                out.add(dom)
            continue
        if line.startswith("|") or line.startswith("@"):
            continue
        dom = normalize_domain(line)
        if dom:
            out.add(dom)
    return out


def parse_plain(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        dom = normalize_domain(line)
        if dom:
            out.add(dom)
    return out


def parse_feed(feed: dict, text: str) -> set[str]:
    fmt = feed.get("format", "hosts")
    if fmt == "hosts":
        return parse_hosts(text)
    if fmt == "adblock":
        return parse_adblock(text)
    return parse_plain(text)


# ---------- merge ----------
def load_domains(kb_dir: Path) -> list[dict]:
    src = kb_dir / "domains.csv"
    with src.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def bump_version(kb_dir: Path) -> str:
    vfile = kb_dir / "VERSION"
    v = vfile.read_text(encoding="utf-8").strip()
    try:
        maj, minor, patch = v.split(".")
        nv = f"{maj}.{minor}.{int(patch) + 1}"
    except ValueError:
        nv = f"{v}.1"
    vfile.write_text(nv + "\n", encoding="utf-8")
    return nv


def sync_public_orgs(reg: dict, mit_ids: set[str]) -> None:
    """把 mit_compatible feed id 同步进 split 脚本的 PUBLIC_ORGS。"""
    if not SPLIT_SCRIPT.exists():
        log("警告：找不到 split 脚本，跳过 PUBLIC_ORGS 同步")
        return
    content = SPLIT_SCRIPT.read_text(encoding="utf-8")
    base = {"stevenblack/hosts", "nocoin"} | mit_ids
    ordered = sorted(base)
    new_line = "PUBLIC_ORGS = {" + ", ".join(f'"{x}"' for x in ordered) + "}"
    if re.search(r"^PUBLIC_ORGS\s*=", content, re.M):
        content = re.sub(r"^PUBLIC_ORGS\s*=\s*\{[^}]*\}", new_line, content, flags=re.M)
        SPLIT_SCRIPT.write_text(content, encoding="utf-8")
        log(f"同步 PUBLIC_ORGS -> {ordered}")
    else:
        log("警告：split 脚本无 PUBLIC_ORGS 行，跳过")


def main() -> int:
    ap = argparse.ArgumentParser(description="家卫知识库 feed 管道")
    ap.add_argument("--offline", action="store_true", help="只用本地 cache，不联网")
    ap.add_argument("--dry", action="store_true", help="只统计不写文件")
    ap.add_argument("--no-sign", action="store_true", help="算 CHECKSUM 但不重签")
    ap.add_argument("--no-sync-orgs", action="store_true", help="跳过同步 split 脚本 PUBLIC_ORGS")
    ap.add_argument("--kb-dir", default=None, help="指定知识库目录（默认仓库内 src/knowledge_base；测试用）")
    ap.add_argument("--seed", default=None, help="Ed25519 签名种子(hex)，或用 HOMEWARD_KB_SIGN_SEED")
    args = ap.parse_args()

    kb_dir = Path(args.kb_dir).resolve() if args.kb_dir else (REPO_ROOT / "src" / "knowledge_base")
    src_csv = kb_dir / "domains.csv"

    reg = load_registry()
    rows = load_domains(kb_dir)
    known = {r["domain"].strip().lower() for r in rows if r.get("domain")}
    log(f"现有 domains.csv：{len(rows)} 条，已知 domain：{len(known)}")

    new_public: list[dict] = []
    new_homeward: list[dict] = []
    report: list[tuple] = []
    mit_ids: set[str] = set()
    seen_new: set[str] = set()

    for feed in reg["feeds"]:
        if not feed.get("enabled", True):
            continue
        text = fetch_feed(reg, feed, args.offline)
        if text is None:
            continue
        domains = parse_feed(feed, text)
        fresh = [d for d in domains if d not in known and d not in seen_new]
        seen_new.update(fresh)
        known.update(fresh)
        if feed.get("mit_compatible"):
            mit_ids.add(feed["id"])
            layer = new_public
        else:
            layer = new_homeward
        for d in fresh:
            layer.append({
                "domain": d,
                "organization": feed["id"],
                "category": feed.get("default_category", "tracker"),
                "confidence": "medium",
                "description": f"{feed['id']} 聚合拦截域名",
                "action": feed.get("default_action", "block_soft"),
                "side_effects": feed.get("default_side_effects", ""),
            })
        report.append((feed["id"], len(domains), len(fresh),
                       "public" if feed.get("mit_compatible") else "homeward",
                       feed.get("license", "?")))

    log("=== feed 报告 ===")
    for fid, total, fresh, layer, lic in report:
        log(f"  {fid:<28} 拉取 {total:>6}  新增 {fresh:>5}  -> {layer}  ({lic})")
    log(f"新增 public：{len(new_public)}  新增 homeward：{len(new_homeward)}")

    if args.dry:
        log("（dry-run，未写文件）")
        return 0

    if not new_public and not new_homeward:
        log("无新增条目，跳过写盘")
        return 0

    # 写回 domains.csv（保留原行 + 追加新增）
    all_rows = rows + new_public + new_homeward
    with src_csv.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(all_rows)
    nv = bump_version(kb_dir)
    log(f"已写入 domains.csv（{len(all_rows)} 条）；VERSION -> {nv}")

    if not args.no_sync_orgs:
        sync_public_orgs(reg, mit_ids)

    # 重算 CHECKSUM（+ 重签）
    seed = args.seed or os.environ.get("HOMEWARD_KB_SIGN_SEED", "")
    if args.no_sign:
        log("跳过签名（--no-sign）")
        sign_arg: list[str] = []
    elif not seed:
        log("警告：未提供签名种子（--seed / HOMEWARD_KB_SIGN_SEED），只算 CHECKSUM 不重签")
        sign_arg = []
    else:
        sign_arg = ["--sign", "--seed", seed]

    cmd = [sys.executable, str(REPO_ROOT / "scripts" / "make_kb_source.py"),
           "--src", str(kb_dir)] + sign_arg
    subprocess.run(cmd, cwd=str(REPO_ROOT), check=True)
    log("feed 管道完成")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
