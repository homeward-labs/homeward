#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键构造家卫「内容源」并算 CHECKSUM。

家卫的内容源本质只是一组静态文件：

    VERSION + domains.csv + behaviors.json (+ 可选 asn.csv) + CHECKSUM

它**不需要任何公网服务器**：在飞牛、公司 2G 小主机、或任意一台内网机器上
放一份，起个 ``python -m http.server``，家卫把 ``HOMEWARD_KB_SOURCE``
指向它即可。本脚本把「摆文件 + 算校验和」固化下来，避免手动算 sha256 出错。

用法：
    # 基于内置知识库造源（默认），并写入 CHECKSUM
    python scripts/make_kb_source.py

    # 指定源目录 + 输出到可发布的目录
    python scripts/make_kb_source.py --src /path/kb --out /srv/homeward/kb

    # 造完直接打印一条可复制的起服务命令
    python scripts/make_kb_source.py --out /srv/homeward/kb --serve 8080

注意：
    - CHECKSUM 格式为 ``<sha256>  <filename>``（两空格，与 updater 解析一致）。
    - 真实 Ed25519 签名（C2）将在此处「算完 CHECKSUM 后、写盘前」插入，
      由独立私钥对 CHECKSUM 签名，公钥随家卫分发；当前版本仅算校验和。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
from pathlib import Path

# 让脚本能直接 import 仓内模块（src/license/ed25519.py 等）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# 与 KnowledgeBaseUpdater 保持一致：必需文件缺失则家卫拒绝替换
REQUIRED = ("domains.csv", "behaviors.json")
OPTIONAL = ("asn.csv",)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def build_checksum(src: Path) -> str:
    """给源目录里所有必需/可选文件算 sha256，返回 CHECKSUM 文本。"""
    lines: list[str] = []
    missing_required = []
    for fname in REQUIRED + OPTIONAL:
        f = src / fname
        if not f.exists():
            if fname in REQUIRED:
                missing_required.append(fname)
            continue
        lines.append(f"{sha256_of(f)}  {fname}")
    if missing_required:
        raise SystemExit(
            f"[make_kb_source] 必需文件缺失：{', '.join(missing_required)}"
            f"（位于 {src}），无法构造可信内容源。"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    repo_root = here.parent

    ap = argparse.ArgumentParser(description="构造家卫内容源 + 算 CHECKSUM")
    ap.add_argument(
        "--src",
        default=str(repo_root / "src" / "knowledge_base"),
        help="源知识库目录（默认：仓库内 src/knowledge_base）",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="可发布的输出目录；给出时把源文件 + CHECKSUM 复制过去",
    )
    ap.add_argument(
        "--serve",
        type=int,
        default=None,
        metavar="PORT",
        help="打印一条以该端口起 http.server 的命令（不实际启动）",
    )
    ap.add_argument(
        "--sign",
        action="store_true",
        help="对 CHECKSUM 用 Ed25519 私钥签名，产出 SIGNATURE 文件（需 --seed 或 HOMEWARD_KB_SIGN_SEED）",
    )
    ap.add_argument(
        "--seed",
        default=None,
        help="签名私钥种子（hex，32 字节）。不传则读环境变量 HOMEWARD_KB_SIGN_SEED",
    )
    args = ap.parse_args(argv)

    src = Path(args.src).resolve()
    if not src.is_dir():
        print(f"[make_kb_source] 源目录不存在：{src}", file=sys.stderr)
        return 2

    version_file = src / "VERSION"
    if not version_file.exists():
        print(
            f"[make_kb_source] 警告：{src} 下没有 VERSION 文件，"
            f"家卫会把它当 0.0.0（见 C1）。建议先补一个。",
            file=sys.stderr,
        )

    checksum = build_checksum(src)

    signature_hex = None
    if args.sign:
        seed_hex = args.seed or os.environ.get("HOMEWARD_KB_SIGN_SEED", "").strip()
        if not seed_hex:
            print(
                "[make_kb_source] --sign 需要种子：传 --seed <hex> 或设环境变量 HOMEWARD_KB_SIGN_SEED",
                file=sys.stderr,
            )
            return 3
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            print("[make_kb_source] 种子不是合法 hex", file=sys.stderr)
            return 3
        try:
            from license.ed25519 import sign_message
        except Exception as e:  # pragma: no cover
            print(f"[make_kb_source] 无法加载签名模块：{e}", file=sys.stderr)
            return 3
        sig = sign_message(checksum.encode("utf-8"), seed)
        signature_hex = sig.hex()

    if args.out:
        out = Path(args.out).resolve()
        out.mkdir(parents=True, exist_ok=True)
        # 复制全部源文件（含 VERSION / LICENSE / 必需 / 可选）
        for f in src.iterdir():
            if f.is_file():
                shutil.copy2(f, out / f.name)
        (out / "CHECKSUM").write_text(checksum, encoding="utf-8", newline="")
        if signature_hex is not None:
            (out / "SIGNATURE").write_text(signature_hex + "\n", encoding="utf-8", newline="")
        print(f"[make_kb_source] 已发布到 {out}")
        print(f"  含 {len([l for l in checksum.strip().splitlines()])} 个校验项")
        if signature_hex is not None:
            print("  已写入 SIGNATURE（Ed25519 签名）")
        if args.serve:
            print(
                f"\n  起服务命令：\n    cd {out} && python -m http.server {args.serve}\n"
                f"  家卫指向：HOMEWARD_KB_SOURCE=http://<本机IP>:{args.serve}/"
            )
    else:
        # 仅写回源目录的 CHECKSUM（就地更新校验和）
        (src / "CHECKSUM").write_text(checksum, encoding="utf-8", newline="")
        if signature_hex is not None:
            (src / "SIGNATURE").write_text(signature_hex + "\n", encoding="utf-8", newline="")
        print(f"[make_kb_source] 已写入 CHECKSUM：{src / 'CHECKSUM'}")
        print(f"  含 {len([l for l in checksum.strip().splitlines()])} 个校验项")
        if signature_hex is not None:
            print(f"[make_kb_source] 已写入 SIGNATURE：{src / 'SIGNATURE'}")
        if args.serve:
            print(
                f"\n  起服务命令：\n    cd {src} && python -m http.server {args.serve}\n"
                f"  家卫指向：HOMEWARD_KB_SOURCE=http://<本机IP>:{args.serve}/"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
