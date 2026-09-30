#!/usr/bin/env bash
# git-mirror-pull.sh
# ---------------------------------------------------------------------------
# 用途：把「纯拉取 / 构建」用途的机器（如家里电脑）的本地仓库强制对齐到
#       origin/main，并把「上游已删、但本地还残留」的未跟踪文件**隔离**到
#       .homeward-trash/（不直接删除，防误删有用文件）。
#
# 解决的问题：普通 `git pull` 只动已跟踪文件，绝不删除未跟踪文件。
#   家里电脑上那些从没 commit 过（或后来被加进 .gitignore）的滞留文件，
#   pull 不会删它们；一旦在 home 上 `git add -A` 顺手提交，就会跟着被推上服务器。
#   本脚本用 `reset --hard` 对齐已跟踪文件，未跟踪残留则 mv 到隔离区，从根上消除滞留。
#
# 安全设计（不直接删）：未跟踪文件先 mv 到仓库内 .homeward-trash/<时间戳>/，
#   该目录自带 .gitignore（忽略全部），**绝不参与 git 上传**；并写入 manifest 记录。
#   保留期默认 30 天，到期用 `homeward-sync.sh purge` 再确认删除。
#
# ⚠️ 警告：本脚本会丢弃本地【未推送的 tracked 改动】（reset --hard）。
#   只用于「纯拉取机」（家里电脑 / 构建机）。编辑中的工作请在公司电脑提交，
#   或先用 `git stash` 暂存，跑完本脚本再 `git stash pop`。
#   未跟踪文件**不会丢**，只是被隔离到 .homeward-trash/ 便于找回。
#
# 用法：
#   scripts/git-mirror-pull.sh          正常执行（隔离未跟踪残留 + 对齐已跟踪）
#   scripts/git-mirror-pull.sh --dry    只预览，不执行任何隔离/重置
# ---------------------------------------------------------------------------
set -euo pipefail

DRY=0
[ "${1:-}" = "--dry" ] && DRY=1

# 切到仓库根（兼容 Git Bash / 任意子目录调用）
cd "$(git rev-parse --show-toplevel)"

TRASH_DIR=".homeward-trash"
TRASH_DAYS="${HOMEWARD_TRASH_DAYS:-30}"

echo "==> [1/4] 抓取远程最新（含清理失效的远端引用）"
git fetch origin --prune

echo "==> [2/4] 检查未提交的 tracked 改动（reset --hard 会丢，必须先行处理）"
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "  ! 发现未提交的 tracked 改动，先自行 git stash / commit 再跑本脚本："
  git status --porcelain | sed 's/^/    /'
  exit 1
fi
echo "    无未提交 tracked 改动，安全继续。"

echo "==> [3/4] 预览将被隔离的未跟踪文件（mv 到 $TRASH_DIR/，不直接删除）"
FILES="$(git ls-files --others --exclude-standard)"
if [ -z "$FILES" ]; then
  echo "    无未跟踪残留文件。"
else
  echo "$FILES" | sed 's/^/    /'
fi
if [ "$DRY" = "1" ]; then
  echo "==> [dry] 仅预览，未执行。去掉 --dry 再跑即真正对齐。"
  exit 0
fi

echo "==> [4/4] 隔离未跟踪残留 + 强制对齐 origin/main"
if [ -n "$FILES" ]; then
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  DEST="$TRASH_DIR/$TS"
  mkdir -p "$DEST"
  printf '*' > "$TRASH_DIR/.gitignore"
  [ -f "$TRASH_DIR/manifest.txt" ] || : > "$TRASH_DIR/manifest.txt"
  CNT=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    TGT="$DEST/$f"
    mkdir -p "$(dirname "$TGT")"
    if mv "$f" "$TGT" 2>/dev/null; then
      printf '%s|%s\n' "$f" "$TS" >> "$TRASH_DIR/manifest.txt"
      CNT=$((CNT+1))
    fi
  done <<< "$FILES"
  echo "    已隔离 $CNT 个未跟踪残留到 $DEST（保留 ${TRASH_DAYS} 天，到期 purge 清理）"
fi
git reset --hard origin/main
echo "    已跟踪文件已对齐 origin/main（当前 HEAD: $(git rev-parse --short HEAD)）"
git status -sb | head -3
