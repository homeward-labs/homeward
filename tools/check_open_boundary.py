#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
家卫 · 开源边界自检（Python 版，与 check_open_boundary.sh 等价）

为什么有这份：Windows PowerShell 没有 `sh`，而项目是 Python、零第三方依赖，
所以提供等价的 .py 版本，PowerShell / cmd / 任意终端都能原生运行：

    python tools/check_open_boundary.py

退出码：0 = 全部通过；1 = 发现越界，必须处理后再推送。
只用标准库，兼容 Python 3.8+。
"""

import re
import subprocess
import sys
from pathlib import Path

CLOSED_DIRS = ["src/enforcers", "src/editions"]
SENTINEL_RE = r"@closed-source|@standard-only|@pro-only"

fail = 0
warn = 0


def run(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    """跑一条 git 命令，返回 CompletedProcess（不抛异常，除非 check=True）。"""
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=check,
    )


def pass_(msg: str) -> None:
    print(f"  [PASS] {msg}")


def bad(msg: str) -> None:
    global fail
    fail += 1
    print(f"  [FAIL] {msg}")


def warn_(msg: str) -> None:
    global warn
    warn += 1
    print(f"  [WARN] {msg}")


def main() -> int:
    # Windows 控制台默认 GBK，强制 UTF-8 避免中文输出乱码
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print()
    print("=" * 46)
    print(" 家卫 · 开源边界自检")
    print(f" 闭源目录：{' '.join(CLOSED_DIRS)}")
    print(f" 闭源标记：{SENTINEL_RE}")
    print("=" * 46)

    # ---------- 0. 前提：在 git 仓库里，且定位到仓库根 ----------
    top = run(["git", "rev-parse", "--show-toplevel"])
    if top.returncode != 0:
        print("  [FAIL] 当前目录不在 git 仓库中，无法自检。")
        return 1
    root = Path(top.stdout.strip())
    import os
    os.chdir(root)

    # ---------- 1. 钩子是否启用 ----------
    print()
    print("1) 钩子防线")
    hp = run(["git", "config", "core.hooksPath"])
    if hp.stdout.strip() == "hooks":
        pass_("core.hooksPath = hooks（已指向仓库内钩子目录）")
    else:
        cur = hp.stdout.strip() or "<空>"
        bad(f"core.hooksPath 未设置为 hooks（当前：'{cur}'）。请执行：git config core.hooksPath hooks")

    for h in ("pre-commit", "pre-push"):
        if (root / "hooks" / h).is_file():
            pass_(f"hooks/{h} 存在")
        else:
            bad(f"hooks/{h} 缺失 —— 少了一道拦截闸")

    # ---------- 2. .gitignore 规则 ----------
    print()
    print("2) .gitignore 规则")
    gitignore = root / ".gitignore"
    gi_text = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.is_file() else ""
    for d in CLOSED_DIRS:
        if re.search(rf"^{re.escape(d)}/?$", gi_text, flags=re.M):
            pass_(f".gitignore 含规则 '{d}'（目录本体，覆盖其下所有子路径）")
        else:
            bad(f".gitignore 缺少规则 '{d}'（注意：目录规则不要带行尾斜杠+行内中文注释，那样会失效）")

    # ---------- 3. 忽略规则是否真的生效 ----------
    print()
    print("3) 忽略规则实效（对尚不存在的路径做探测）")
    for d in CLOSED_DIRS:
        r = run(["git", "check-ignore", "-q", "--no-index", f"{d}/probe.py"])
        if r.returncode == 0:
            pass_(f"'{d}/probe.py' 会被 git 忽略")
        else:
            bad(f"'{d}/probe.py' 未被忽略 —— 该目录下的文件可被 git add 收录")

    # ---------- 4. 索引中是否有闭源路径 ----------
    print()
    print("4) 已跟踪文件（git ls-files）")
    tracked = run(["git", "ls-files"]).stdout.splitlines()
    hits = [f for f in tracked if any(f == d or f.startswith(d + "/") for d in CLOSED_DIRS)]
    if hits:
        bad("已跟踪文件中存在闭源路径：")
        for f in hits:
            print(f"         {f}")
    else:
        pass_("已跟踪文件中无任何闭源路径")

    # ---------- 5. 全历史扫描（含已删除的文件） ----------
    print()
    print("5) 全部提交历史（git log --all，含已删除文件）")
    hist = run(["git", "log", "--all", "--pretty=format:", "--name-only"]).stdout.splitlines()
    hist = {f.strip() for f in hist if f.strip()}
    hits = sorted(f for f in hist if any(f == d or f.startswith(d + "/") for d in CLOSED_DIRS))
    if hits:
        bad("提交历史中出现过闭源路径（文件已删除也会留在历史里）：")
        for f in hits:
            print(f"         {f}")
    else:
        pass_("全部历史中无闭源路径")

    # ---------- 6. 哨兵标记扫描（HEAD 的 src/ 下） ----------
    # 只扫 src/：docs/ 与 hooks/ 需要合法地「提及」这些标记词（规则说明本身就是文档），
    # 扫全树会把文档与钩子自身报成违规 —— 与 pre-commit / pre-push 的策略保持一致。
    print()
    print("6) 闭源标记哨兵（HEAD 的 src/ 下）")
    if run(["git", "rev-parse", "--verify", "HEAD"]).returncode == 0:
        r = run(["git", "grep", "-l", "-E", SENTINEL_RE, "HEAD", "--", "src/"])
        if r.returncode == 0 and r.stdout.strip():
            bad("以下文件含闭源标记：")
            for f in r.stdout.splitlines():
                print(f"         {f}")
        else:
            pass_("HEAD 的 src/ 下无闭源标记")
    else:
        warn_("仓库尚无提交，跳过哨兵扫描")

    # ---------- 7. 本地闭源目录（应只存在于本地，且被忽略） ----------
    print()
    print("7) 本地闭源目录（存在但被忽略 = 正常）")
    for d in CLOSED_DIRS:
        p = root / d
        if not p.exists():
            pass_(f"'{d}' 本地不存在（闭源码在仓库外 —— 最安全的形态）")
            continue
        r = run(["git", "check-ignore", "-q", "--no-index", d])
        if r.returncode == 0:
            pass_(f"'{d}' 存在于本地且被忽略（不会被推送）")
        else:
            warn_(f"'{d}' 存在于本地但**未被忽略**，git add -A 会把它收进去")

    # ---------- 结论 ----------
    print()
    print("=" * 46)
    if fail:
        print(f" 结果：{fail} 项失败，{warn} 项警告 —— 请勿推送。")
        print(" 修复后重跑本脚本；确认无误再执行 git push。")
        print("=" * 46)
        print()
        return 1
    print(f" 结果：全部通过（{warn} 项警告）—— 可以推送。")
    print(" 记住：pre-push 钩子还会再查一遍，双保险。")
    print("=" * 46)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
