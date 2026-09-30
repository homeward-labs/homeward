#!/usr/bin/env bash
# git-mirror-pull.sh
# ---------------------------------------------------------------------------
# 用途：把「纯拉取 / 构建」用途的机器（如家里电脑）的本地仓库强制对齐到
#       origin/main，并清掉「上游已删除、但本地还残留」的未跟踪文件。
#
# 解决的问题：普通 `git pull` 只动已跟踪文件，绝不删除未跟踪文件。
#   家里电脑上那些从没 commit 过（或后来被加进 .gitignore）的滞留文件，
#   pull 不会删它们；一旦在 home 上 `git add -A` 顺手提交，就会跟着被推上服务器。
#   本脚本用 `reset --hard` + `clean -fd` 把本地变成远程的「镜像」，从根上消除滞留。
#
# ⚠️ 警告：本脚本会丢弃本地【未推送的 tracked 改动】并删除【未跟踪文件】。
#   只用于「纯拉取机」（家里电脑 / 构建机）。编辑中的工作请在公司电脑提交，
#   或先用 `git stash` 暂存，跑完本脚本再 `git stash pop`。
#
# 用法：
#   scripts/git-mirror-pull.sh          正常执行（先预览将删除的未跟踪文件）
#   scripts/git-mirror-pull.sh --dry    只预览，不执行任何删除/重置
# ---------------------------------------------------------------------------
set -euo pipefail

DRY=0
[ "${1:-}" = "--dry" ] && DRY=1

# 切到仓库根（兼容 Git Bash / 任意子目录调用）
cd "$(git rev-parse --show-toplevel)"

echo "==> [1/4] 抓取远程最新（含清理失效的远端引用）"
git fetch origin --prune

echo "==> [2/4] 检查未提交的 tracked 改动（reset --hard 会丢，必须先行处理）"
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "  ! 发现未提交的 tracked 改动，先自行 git stash / commit 再跑本脚本："
  git status --porcelain | sed 's/^/    /'
  exit 1
fi
echo "    无未提交 tracked 改动，安全继续。"

echo "==> [3/4] 预览将被删除的未跟踪文件（git clean -fd，不含 .gitignore 项）"
git clean -fdn | sed 's/^/    /' || true
if [ "$DRY" = "1" ]; then
  echo "==> [dry] 仅预览，未执行。去掉 --dry 再跑即真正对齐。"
  exit 0
fi

echo "==> [4/4] 强制对齐 origin/main（上游删除的 tracked 文件会被删除）"
git reset --hard origin/main
echo "    删除未跟踪滞留文件（git clean -fd）"
git clean -fd

echo "==> 完成。当前 HEAD: $(git rev-parse --short HEAD)"
git status -sb | head -3
