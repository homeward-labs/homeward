#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
家卫 · 开源边界自检（Python 版，与 check_open_boundary.sh / .ps1 等价）

判定依据**全部**来自单一清单 tools/closed_assets.txt（dir / file / kbignore / pattern 四类）。
为什么单一清单：历史上四处防线各写一份 CLOSED_DIRS，改一处漏三处 → 口径漂移。
本脚本只负责「按清单检查」，清单内容变了即自动生效，无需改本文件。

为什么有这份：Windows PowerShell 没有 `sh`，而项目是 Python、零第三方依赖，
所以提供等价的 .py 版本，PowerShell / cmd / 任意终端都能原生运行：

    python tools/check_open_boundary.py

退出码：0 = 全部通过；1 = 发现越界，必须处理后再推送。
只用标准库，兼容 Python 3.8+。
"""

import os
import re
import subprocess
import sys
from pathlib import Path

LIST_REL = "tools/closed_assets.txt"
SENTINEL_RE = r"@closed-source|@standard-only|@pro-only"

fail = 0
warn = 0


def run(args, check=False):
    """跑一条 git 命令，返回 CompletedProcess（不抛异常，除非 check=True）。"""
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8",
        errors="replace", check=check,
    )


def pass_(msg):
    print(f"  [PASS] {msg}")


def bad(msg):
    global fail
    fail += 1
    print(f"  [FAIL] {msg}")


def warn_(msg):
    global warn
    warn += 1
    print(f"  [WARN] {msg}")


def load_list(root):
    """解析单一清单 → (dirs, files, kbignores, patterns)；文件缺失返回 None。"""
    p = root / LIST_REL
    if not p.is_file():
        return None
    dirs, files, kbignores, patterns = [], [], [], []
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("dir:"):
            dirs.append(line[4:].strip())
        elif line.startswith("file:"):
            files.append(line[5:].strip())
        elif line.startswith("kbignore:"):
            kbignores.append(line[9:].strip())
        elif line.startswith("pattern:"):
            patterns.append(line[8:].strip())
    return dirs, files, kbignores, patterns


def is_closed(path, dirs, files):
    """目录前缀匹配 + 精确文件名匹配。"""
    for d in dirs:
        if path == d or path.startswith(d + "/"):
            return True
    return path in files


def main() -> int:
    # Windows 控制台默认 GBK，强制 UTF-8 避免中文输出乱码
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    # ---------- 0. 前提：在 git 仓库里，且定位到仓库根 ----------
    top = run(["git", "rev-parse", "--show-toplevel"])
    if top.returncode != 0:
        print("  [FAIL] 当前目录不在 git 仓库中，无法自检。")
        return 1
    root = Path(top.stdout.strip())
    os.chdir(root)

    loaded = load_list(root)
    if loaded is None:
        print()
        print("=" * 58)
        print(" 家卫 · 开源边界自检")
        print(f"  [FAIL] 单一清单 {LIST_REL} 缺失 —— 四道防线失去判定依据！")
        print("=" * 58)
        print()
        return 1
    dirs, files, kbignores, patterns = loaded

    print()
    print("=" * 58)
    print(" 家卫 · 开源边界自检")
    print(f" 单一清单：{LIST_REL}（改此文件即四道防线同时生效）")
    print(f" 闭源目录 {len(dirs)} 个 / 闭源文件 {len(files)} 个 / "
          f".gitignore 必备项 {len(kbignores)} 条 / 活源规则 {len(patterns)} 条")
    print(f" 闭源目录：{' '.join(dirs)}")
    print(f" 闭源标记：{SENTINEL_RE}")
    print("=" * 58)

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

    # ---------- 2. .gitignore 规则（目录级） ----------
    print()
    print("2) .gitignore 规则（闭源目录）")
    gitignore = root / ".gitignore"
    gi_text = gitignore.read_text(encoding="utf-8", errors="replace") if gitignore.is_file() else ""
    for d in dirs:
        if re.search(rf"^{re.escape(d)}/?$", gi_text, flags=re.M):
            pass_(f".gitignore 含规则 '{d}'（目录本体，覆盖其下所有子路径）")
        else:
            bad(f".gitignore 缺少规则 '{d}'（注意：目录规则不要带行尾斜杠+行内中文注释，那样会失效）")

    # ---------- 2b. KB 子 .gitignore 完好性（第一道防线的防线） ----------
    print()
    print("2b) src/knowledge_base/.gitignore 完好性")
    kb_gi = root / "src" / "knowledge_base" / ".gitignore"
    if not kb_gi.is_file():
        bad("src/knowledge_base/.gitignore 缺失 —— KB 数据文件的 .gitignore 防线已失效")
    else:
        kb_text = kb_gi.read_text(encoding="utf-8", errors="replace")
        kb_lines = {ln.strip() for ln in kb_text.splitlines()}
        miss = [x for x in kbignores if x not in kb_lines]
        if miss:
            bad("src/knowledge_base/.gitignore 缺失必备规则（删掉即防线失效）：")
            for x in miss:
                print(f"         {x}")
        else:
            pass_(f"src/knowledge_base/.gitignore 完好（{len(kbignores)} 条必备规则齐全）")

    # ---------- 3. 忽略规则是否真的生效 ----------
    print()
    print("3) 忽略规则实效（对尚不存在的路径做探测）")
    for d in dirs:
        r = run(["git", "check-ignore", "-q", "--no-index", f"{d}/probe.py"])
        if r.returncode == 0:
            pass_(f"'{d}/probe.py' 会被 git 忽略")
        else:
            bad(f"'{d}/probe.py' 未被忽略 —— 该目录下的文件可被 git add 收录")

    # ---------- 4. 索引中是否有闭源路径 ----------
    print()
    print("4) 已跟踪文件（git ls-files）")
    tracked = run(["git", "ls-files"]).stdout.splitlines()
    hits = [f for f in tracked if is_closed(f, dirs, files)]
    if hits:
        bad("已跟踪文件中存在闭源路径：")
        for f in hits:
            print(f"         {f}")
    else:
        pass_("已跟踪文件中无任何闭源路径")

    # ---------- 5. 全历史文件名扫描（含已删除的文件） ----------
    print()
    print("5) 全部提交历史文件名（git log --all，含已删除文件）")
    hist = run(["git", "log", "--all", "--pretty=format:", "--name-only"]).stdout.splitlines()
    hist = {f.strip() for f in hist if f.strip()}
    hits = sorted(f for f in hist if is_closed(f, dirs, files))
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
    have_head = run(["git", "rev-parse", "--verify", "HEAD"]).returncode == 0
    if have_head:
        r = run(["git", "grep", "-l", "-E", SENTINEL_RE, "HEAD", "--", "src/"])
        if r.returncode == 0 and r.stdout.strip():
            bad("以下文件含闭源标记：")
            for f in r.stdout.splitlines():
                print(f"         {f}")
        else:
            pass_("HEAD 的 src/ 下无闭源标记")
    else:
        warn_("仓库尚无提交，跳过哨兵扫描")

    # ---------- 6b. 活源地址 / 机密标记 —— HEAD 全树内容扫描 ----------
    print()
    print("6b) 活源地址 / 机密标记（HEAD 全树内容扫描）")
    if not patterns:
        warn_("清单未定义 pattern 规则，跳过")
    elif not have_head:
        warn_("仓库尚无提交，跳过")
    else:
        args = ["git", "grep", "-l"]
        for p in patterns:
            args += ["-e", p]
        args += ["HEAD", "--", ".", f":(exclude){LIST_REL}"]
        r = run(args)
        if r.returncode not in (0, 1):
            bad(f"git grep 异常（rc={r.returncode}），按 fail-closed 处理：{r.stderr.strip()}")
        elif r.stdout.strip():
            bad("HEAD 全树命中活源地址 / 机密标记（文件）：")
            for f in r.stdout.splitlines():
                print(f"         {f}")
        else:
            pass_("HEAD 全树无活源地址 / 机密标记")

    # ---------- 6c. 活源地址 / 机密标记 —— 全历史内容扫描 ----------
    # 用 git log -G（pickaxe）高效定位「引入过该字符串」的提交，避免逐提交 grep。
    # 排除本清单文件自身（它必然含有 pattern 明文）。
    print()
    print("6c) 活源地址 / 机密标记（全历史内容扫描，git log -G）")
    if not patterns:
        warn_("清单未定义 pattern 规则，跳过")
    else:
        combined = "|".join(f"({p})" for p in patterns)
        r = run(["git", "log", "--all", "--pretty=format:%h", "-G", combined,
                 "--", ".", f":(exclude){LIST_REL}"])
        if r.returncode != 0:
            bad(f"git log -G 异常（rc={r.returncode}），按 fail-closed 处理：{r.stderr.strip()}")
        elif r.stdout.strip():
            commits = [c for c in r.stdout.split() if c]
            bad(f"全部历史中 {len(commits)} 个提交曾引入活源地址 / 机密标记：")
            print(f"         {' '.join(commits[:20])}{' …' if len(commits) > 20 else ''}")
        else:
            pass_("全部历史中无活源地址 / 机密标记")

    # ---------- 7. 本地闭源目录（应只存在于本地，且被忽略） ----------
    print()
    print("7) 本地闭源目录（存在但被忽略 = 正常）")
    for d in dirs:
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
    print("=" * 58)
    if fail:
        print(f" 结果：{fail} 项失败，{warn} 项警告 —— 请勿推送。")
        print(" 修复后重跑本脚本；确认无误再执行 git push。")
        print("=" * 58)
        print()
        return 1
    print(f" 结果：全部通过（{warn} 项警告）—— 可以推送。")
    print(" 记住：pre-push 钩子还会再查一遍，双保险。")
    print("=" * 58)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())