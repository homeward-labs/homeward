#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把家卫知识库「内容源」发布到 Cloudflare（KV 或 R2），让客户端能拉到更新。

家卫是薄客户端：域名归属库、行为库只从内容源下载（见 ``docs/CONTENT-SOURCE.md``）。
本脚本把 ``src/knowledge_base`` 里最新的、已签名的 bundle 推到 Cloudflare——
客户端 ``updater.py`` 默认源 ``homeward-kb.782238788.workers.dev`` 即由这里喂数据。

分发 bundle（被发布的文件）固定为：
    VERSION  domains.csv  behaviors.json  oui_prefixes.csv  CHECKSUM  SIGNATURE  LICENSE
（asn.csv 当前仓库无，缺省跳过，客户端按「可选文件缺失即跳过」处理。）

用法：
    # 本地先组装并校验，不真正上传（看清楚会发哪些文件）
    python scripts/publish_kb_source.py --dry

    # 真实发布到 KV（推荐）：签名 + 上传
    # 凭据走环境变量，绝不硬编码进脚本
    export CF_ACCOUNT_ID=xxxx
    export CF_API_TOKEN=xxxx          # 需 KV 编辑权限（或 R2 读写）
    export HOMEWARD_KB_SIGN_SEED=<kb_sign_seed.bin 的 hex>
    python scripts/publish_kb_source.py --target kv --namespace-id <KV_NS_ID>

    # 顺带 bump 一个小版本号再发
    python scripts/publish_kb_source.py --target kv --namespace-id <KV_NS_ID> --bump patch

    # 发完验证（回源拉一个文件确认 Worker 已生效）
    python scripts/publish_kb_source.py --verify-url https://homeward-kb.782238788.workers.dev

注意：
    - 签名种子只经 ``--seed`` 或环境变量 ``HOMEWARD_KB_SIGN_SEED`` 传入；脚本里**不写**任何密钥。
    - Cloudflare API Token 只经 ``--api-token`` 或环境变量 ``CF_API_TOKEN`` 传入。
    - R2 备选：``--target r2 --bucket <bucket>``，走 ``wrangler r2 object put``（需本机装 wrangler）。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# 复用仓内既有逻辑：校验和、签名、文件名清单（与客户端 updater 共用常量）
from knowledge_base.constants import (  # noqa: E402
    REQUIRED_DATA_FILES as REQUIRED,
    OPTIONAL_DATA_FILES as OPTIONAL,
)
from make_kb_source import build_checksum, sha256_of  # noqa: E402


# 真正被发布出去的文件（白名单，避免把 .py / seeds / 内部文件误传上公网）
DIST_FILES = ["VERSION", "domains.csv", "behaviors.json", "oui_prefixes.csv",
              "CHECKSUM", "SIGNATURE", "LICENSE"]


def bump_version(version: str, part: str) -> str:
    nums = [int(x) for x in version.strip().split(".")]
    while len(nums) < 3:
        nums.append(0)
    if part == "major":
        nums = [nums[0] + 1, 0, 0]
    elif part == "minor":
        nums = [nums[0], nums[1] + 1, 0]
    else:  # patch
        nums = [nums[0], nums[1], nums[2] + 1]
    return ".".join(str(n) for n in nums)


def build_bundle(src: Path, out: Path, seed_hex: str | None, bump: str | None) -> tuple[str, str]:
    """组装分发 bundle 到 out/，返回 (version, signature_hex_or_empty)。"""
    out.mkdir(parents=True, exist_ok=True)

    version = (src / "VERSION").read_text(encoding="utf-8").strip() if (src / "VERSION").exists() else "0.0.0"
    if bump:
        version = bump_version(version, bump)
        (src / "VERSION").write_text(version + "\n", encoding="utf-8")
        print(f"[publish] VERSION bump -> {version}")
    else:
        (out / "VERSION").write_text(version + "\n", encoding="utf-8")

    checksum = build_checksum(src)
    (out / "CHECKSUM").write_text(checksum, encoding="utf-8", newline="")

    signature_hex = ""
    if seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise SystemExit("[publish] --seed 不是合法 hex")
        from license.ed25519 import sign_message  # noqa: E402
        sig = sign_message(checksum.encode("utf-8"), seed)
        signature_hex = sig.hex()
        (out / "SIGNATURE").write_text(signature_hex + "\n", encoding="utf-8", newline="")
        print("[publish] 已用 Ed25519 重签 SIGNATURE")
    else:
        # 清掉可能残留的旧 SIGNATURE，避免发布未签名状态误导
        (out / "SIGNATURE").unlink(missing_ok=True)

    # 复制白名单内的数据/署名文件
    copied = []
    for fname in ["domains.csv", "behaviors.json", "oui_prefixes.csv", "LICENSE"]:
        f = src / fname
        if f.exists():
            out.joinpath(fname).write_bytes(f.read_bytes())
            copied.append(fname)
    return version, signature_hex, copied


def _cf_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}


def upload_kv(account_id: str, ns_id: str, token: str, out: Path, files: list[str]) -> None:
    base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{ns_id}/values"
    for fname in files:
        data = (out / fname).read_bytes()
        req = urllib.request.Request(f"{base}/{fname}", data=data, method="PUT",
                                     headers=_cf_headers(token))
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                print(f"[publish] KV 上传 {fname} ({len(data)} B) -> {resp.status}")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            raise SystemExit(f"[publish] KV 上传 {fname} 失败 HTTP {e.code}: {body}")


def upload_r2(bucket: str, out: Path, files: list[str]) -> None:
    """R2 备选：用本机 wrangler 上传（避免脚本内实现 S3 SigV4）。"""
    import shutil
    import subprocess
    wrangler = shutil.which("wrangler") or "wrangler"
    for fname in files:
        cmd = [wrangler, "r2", "object", "put", f"{bucket}/{fname}",
               "--file", str(out / fname)]
        print(f"[publish] R2 上传 {fname}: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            raise SystemExit(f"[publish] R2 上传 {fname} 失败: {e}")


def verify_worker(url: str, files: list[str]) -> None:
    for fname in files:
        try:
            with urllib.request.urlopen(f"{url.rstrip('/')}/{fname}", timeout=20) as resp:
                ok = resp.status == 200 and len(resp.read()) > 0
                print(f"[publish] 验证 {fname}: {'OK' if ok else '空响应'}")
        except Exception as e:
            print(f"[publish] 验证 {fname} 异常：{e}")


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    ap = argparse.ArgumentParser(description="发布家卫知识库内容源到 Cloudflare")
    ap.add_argument("--src", default=str(repo_root / "src" / "knowledge_base"),
                    help="源知识库目录（默认 src/knowledge_base）")
    ap.add_argument("--out", default=str(here / ".kb_dist"),
                    help="本地 bundle 暂存目录（默认 scripts/.kb_dist）")
    ap.add_argument("--target", choices=["kv", "r2"], default="kv", help="上传目标（默认 kv）")
    ap.add_argument("--account-id", default=os.environ.get("CF_ACCOUNT_ID", ""),
                    help="Cloudflare 账户 ID（或 env CF_ACCOUNT_ID）")
    ap.add_argument("--namespace-id", default=os.environ.get("CF_KV_NAMESPACE_ID", ""),
                    help="KV 命名空间 ID（或 env CF_KV_NAMESPACE_ID）")
    ap.add_argument("--bucket", default=os.environ.get("CF_R2_BUCKET", ""),
                    help="R2 桶名（--target r2 时；或 env CF_R2_BUCKET）")
    ap.add_argument("--api-token", default=os.environ.get("CF_API_TOKEN", ""),
                    help="Cloudflare API Token（或 env CF_API_TOKEN）；绝不硬编码")
    ap.add_argument("--seed", default=None, help="Ed25519 签名种子 hex；不传读 HOMEWARD_KB_SIGN_SEED")
    ap.add_argument("--bump", choices=["major", "minor", "patch"], default=None,
                    help="发布前 bump 一个小版本号")
    ap.add_argument("--dry", action="store_true", help="只组装本地 bundle，不上传、不 bump")
    ap.add_argument("--verify-url", default=None, help="发布后回源验证的 Worker 基址")
    args = ap.parse_args(argv)

    src = Path(args.src).resolve()
    out = Path(args.out).resolve()
    seed_hex = args.seed or os.environ.get("HOMEWARD_KB_SIGN_SEED", "").strip()

    if not src.is_dir():
        print(f"[publish] 源目录不存在：{src}", file=sys.stderr)
        return 2
    if not seed_hex and not args.dry:
        print("[publish] 警告：未提供签名种子，将发布「未签名」bundle；"
              "客户端在强制验签模式下会拒绝。建议传 --seed 或设 HOMEWARD_KB_SIGN_SEED", file=sys.stderr)

    version, _sig, copied = build_bundle(src, out, seed_hex if not args.dry else None,
                                         args.bump if not args.dry else None)

    # 计算实际会发布出去的文件（白名单 ∩ 存在于 out 的）
    files = [f for f in DIST_FILES if (out / f).exists()]
    print(f"[publish] 本地 bundle 已组装：{out}  (VERSION {version})")
    for f in files:
        print(f"   - {f}  sha256={sha256_of(out / f)[:16]}…")

    if args.dry:
        print("[publish] --dry：未上传。确认无误后去掉 --dry 再跑。")
        return 0

    if args.target == "kv":
        if not (args.account_id and args.namespace_id and args.api_token):
            print("[publish] KV 上传需要 --account-id / --namespace-id / --api-token"
                  "（或对应环境变量）。", file=sys.stderr)
            return 3
        upload_kv(args.account_id, args.namespace_id, args.api_token, out, files)
    else:
        if not args.bucket:
            print("[publish] R2 上传需要 --bucket（或 env CF_R2_BUCKET）。", file=sys.stderr)
            return 3
        upload_r2(args.bucket, out, files)

    print(f"[publish] ✅ 已发布 v{version} 到 Cloudflare（{args.target}），共 {len(files)} 个文件")
    if args.verify_url:
        verify_worker(args.verify_url, files)
    else:
        print("[publish] 提示：用 --verify-url https://homeward-kb.782238788.workers.dev 回源验证。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
