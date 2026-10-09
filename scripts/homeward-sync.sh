#!/usr/bin/env bash
# homeward-sync.sh —— 家卫跨机一键同步脚本（傻瓜版）
# ---------------------------------------------------------------------------
# 不管在公司还是家里，跑一次就自动处理「跨机同步卫生」：
#   1) 把本地仓库强制对齐成远程镜像（上游已删的 tracked 文件会被删；
#      **未跟踪的残留文件不直接删除，而是隔离到 .homeward-trash/ 防误推**）
#   2) 校验私有目录完整性（verify.py）
#   3) 识别当前机器 / 站点，并报告两个目录的当前状态
#   4) 可选「受保护推送」：先隔离未跟踪残留 -> 只 add 具体文件（绝不 git add -A）
#      -> 跑开源边界自检 -> 确认后 commit -> push
#
# 安全设计（针对「直接 git clean -fd 会误删有用文件」的反馈）：
#   * 任何「未跟踪残留文件」都先 mv 到仓库内的 `.homeward-trash/<时间戳>/` 目录，
#     该目录自带 .gitignore（忽略全部），**绝不参与 git 上传**，也不会被脚本自己重复搬运。
#   * 隔离时写入 `.homeward-trash/manifest.txt`（原路径|隔离UTC时间），便于找回与审计。
#   * 设定保留期（默认 30 天，可用 HOMEWARD_TRASH_DAYS 覆盖），到期用 `purge` 子命令
#     再确认删除，避免「一拉取就把本地有用文件永久删掉」。
#
# 本脚本是公开的（进 git 仓库），不含任何敏感信息；敏感资料只在脱 git 的私有目录。
#
# 用法：
#   ./homeward-sync.sh              # 默认 = 镜像拉取(隔离残留) + 私有校验 + 状态报告（推荐每次跑）
#   ./homeward-sync.sh pull         # 等同默认
#   ./homeward-sync.sh push         # 受保护推送（交互确认，绝不盲加）
#   ./homeward-sync.sh push --yes   # 跳过交互确认（仅在你清楚在做什么时用）
#   ./homeward-sync.sh status       # 只报告两个目录状态
#   ./homeward-sync.sh trash        # 查看当前隔离区里有哪些被隔离的文件
#   ./homeward-sync.sh purge        # 删除隔离区中超过保留期的文件（默认 30 天）
#   ./homeward-sync.sh doctor       # 诊断当前机器 / 代理 / 路径
#
# 环境变量（可选）：
#   HOMEWARD_PRIVATE_DIR   私有目录路径（探测不到时指定）
#   HOMEWARD_REMOTE        远程名（默认 origin）
#   HOMEWARD_BRANCH        分支名（默认 main）
#   HOMEWARD_TRASH_DAYS    隔离文件保留天数（默认 30；到期 purge 才删）
# ---------------------------------------------------------------------------
set -uo pipefail

# ---------- 颜色（非终端时不加色） ----------
if [ -t 1 ]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_C=$'\033[36m'; C_0=$'\033[0m'
else
  C_R=""; C_G=""; C_Y=""; C_C=""; C_0=""
fi
info(){ printf "${C_C}==>${C_0} %s\n" "$*"; }
ok(){   printf "${C_G}[OK]${C_0} %s\n" "$*"; }
warn(){ printf "${C_Y}[!] ${C_0}%s\n" "$*"; }
err(){  printf "${C_R}[X] ${C_0}%s\n" "$*" >&2; }

# ---------- 隔离区配置 ----------
TRASH_DIR=".homeward-trash"
TRASH_DAYS="${HOMEWARD_TRASH_DAYS:-30}"

# ---------- 定位仓库（自动，不硬编码路径） ----------
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO_ROOT" ]; then
  err "当前目录不在 git 仓库内。请先 cd 到家卫代码仓库再运行本脚本。"
  exit 1
fi
cd "$REPO_ROOT" || exit 1

REMOTE="${HOMEWARD_REMOTE:-origin}"
BRANCH="${HOMEWARD_BRANCH:-main}"

# ---------- 探测私有目录（不硬编码绝对敏感路径） ----------
detect_private(){
  local d
  if [ -n "${HOMEWARD_PRIVATE_DIR:-}" ] && [ -d "$HOMEWARD_PRIVATE_DIR" ]; then
    echo "$HOMEWARD_PRIVATE_DIR"; return 0
  fi
  for d in "${HOMEWARD_PRIVATE_DIR:-}"; do
    if [ -d "$d" ] && [ -f "$d/verify.py" ]; then echo "$d"; return 0; fi
  done
  return 1
}
PRIVATE_DIR="$(detect_private || true)"

# ---------- 识别当前机器（粗判 + 对照 MACHINE.md） ----------
detect_machine(){
  local h; h="$(hostname 2>/dev/null || echo unknown)"
  if [ -n "$PRIVATE_DIR" ] && [ -f "$PRIVATE_DIR/MACHINE.md" ]; then
    if grep -qi "1KI5RG6" "$PRIVATE_DIR/MACHINE.md" 2>/dev/null && echo "$h" | grep -qi "1KI5RG6"; then
      echo "公司电脑 (DESKTOP-1KI5RG6)"
      return
    fi
  fi
  echo "$h（若与私有目录/MACHINE.md 记录不符，请核对是否换机/换站）"
}
MACHINE="$(detect_machine)"

# ---------- 隔离未跟踪残留（核心：不直接删，先隔离） ----------
move_to_trash(){
  # 列出未跟踪且未被 ignore 的文件（locale 安全，不解析 clean 输出）
  local files; files="$(git ls-files --others --exclude-standard)"
  if [ -z "$files" ]; then return 0; fi

  local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local dest="$TRASH_DIR/$ts"
  mkdir -p "$dest"
  # 隔离目录自带 .gitignore，确保自身不参与上传、也不会被脚本重复搬运
  printf '*' > "$TRASH_DIR/.gitignore"
  [ -f "$TRASH_DIR/manifest.txt" ] || : > "$TRASH_DIR/manifest.txt"

  local n=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    local tgt="$dest/$f"
    mkdir -p "$(dirname "$tgt")"
    if mv "$f" "$tgt" 2>/dev/null; then
      printf '%s|%s\n' "$f" "$ts" >> "$TRASH_DIR/manifest.txt"
      n=$((n+1))
    fi
  done <<< "$files"

  if [ "$n" -gt 0 ]; then
    warn "已将 $n 个未跟踪残留文件隔离到 $dest"
    warn "（该目录被 git 忽略、不参与上传；保留 ${TRASH_DAYS} 天，到期用 './homeward-sync.sh purge' 清理）"
  fi
}

# ---------- 镜像拉取（隔离残留 + 对齐已跟踪） ----------
run_mirror_pull(){
  info "镜像拉取：把已跟踪文件对齐到 $REMOTE/$BRANCH，未跟踪残留隔离到 .homeward-trash/"
  git fetch "$REMOTE" --prune
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "发现未提交的 tracked 改动，reset --hard 会丢。请先 git stash / commit："
    git status --porcelain | sed 's/^/    /'
    return 1
  fi
  move_to_trash                       # 先把未跟踪残留隔离，不直接删
  git reset --hard "$REMOTE/$BRANCH"  # 已跟踪文件对齐远程（上游删的 tracked 会删，但可从远程恢复）
  ok "拉取完成，当前 HEAD: $(git rev-parse --short HEAD)"
}

# ---------- 校验私有目录 ----------
run_verify(){
  if [ -z "$PRIVATE_DIR" ]; then
    warn "未探测到私有目录（可设 HOMEWARD_PRIVATE_DIR 环境变量）。跳过 verify.py。"
    return 0
  fi
  info "校验私有目录：$PRIVATE_DIR"
  if command -v python >/dev/null 2>&1; then
    ( cd "$PRIVATE_DIR" && python verify.py 2>&1 | tail -6 )
  elif command -v python3 >/dev/null 2>&1; then
    ( cd "$PRIVATE_DIR" && python3 verify.py 2>&1 | tail -6 )
  else
    warn "本机无 python，跳过 verify.py（请手动在私有目录跑 python verify.py）。"
  fi
}

# ---------- 报告两个目录状态 ----------
do_status(){
  echo
  info "仓库根：$REPO_ROOT"
  info "当前机器：$MACHINE"
  echo "--- homeward 代码仓 ---"
  echo "  HEAD : $(git rev-parse --short HEAD 2>/dev/null)  (总提交 $(git rev-list --count HEAD 2>/dev/null))"
  echo "  远程 : $(git rev-parse --short "$REMOTE/$BRANCH" 2>/dev/null || echo '?')"
  local wt; wt="$(git status --porcelain 2>/dev/null)"
  if [ -z "$wt" ]; then echo "  工作树: 干净"; else echo "  工作树: 有改动（$(echo "$wt" | wc -l | tr -d ' ') 项）"; fi
  # 隔离区提示
  if [ -f "$TRASH_DIR/manifest.txt" ]; then
    local cnt; cnt="$(wc -l < "$TRASH_DIR/manifest.txt" | tr -d ' ')"
    warn "  隔离区 .homeward-trash/ 有 $cnt 个被隔离文件（保留 ${TRASH_DAYS} 天；purge 清理）"
  fi
  echo "--- 私有目录 ---"
  if [ -n "$PRIVATE_DIR" ]; then
    echo "  路径 : $PRIVATE_DIR"
  else
    warn "  未探测到（可设 HOMEWARD_PRIVATE_DIR）"
  fi
  echo "  （公司基线请对照私有目录/CODELINE.md；家里仓库 HEAD 须独立核验，勿套用公司基线）"
}

# ---------- 受保护推送 ----------
do_push(){
  local yes=0
  [ "${1:-}" = "--yes" ] && yes=1
  info "受保护推送（绝不 git add -A）"

  # 1) 先把未跟踪残留隔离，防误推
  move_to_trash

  # 2) 列出将提交的文件
  local changes; changes="$(git status --porcelain)"
  if [ -z "$changes" ]; then ok "没有可提交的改动，无需推送。"; return 0; fi
  echo "将提交的文件："
  echo "$changes" | sed 's/^/    /'

  # 3) 开源边界自检
  if [ -x tools/check_open_boundary.sh ]; then
    info "运行开源边界自检（tools/check_open_boundary.sh）..."
    if ! bash tools/check_open_boundary.sh >/tmp/hw_boundary.log 2>&1; then
      err "边界自检未通过，停止推送。常见原因：闭源标记/@closed-source 被加进暂存。"
      tail -20 /tmp/hw_boundary.log
      return 1
    fi
    ok "边界自检通过"
  fi

  # 4) 确认
  if [ "$yes" != 1 ]; then
    read -r -p "确认提交并推送以上文件？(y/N) " a
    case "$a" in y|Y) ;; *) warn "已取消。"; return 0 ;; esac
  fi

  # 5) 只 add 具体文件（绝不 git add -A）
  echo "$changes" | awk '{print $2}' | while read -r f; do [ -n "$f" ] && git add "$f"; done

  # 6) 提交 + 推送
  local msg
  if [ "$yes" = 1 ] && [ -n "${2:-}" ]; then msg="$2"; else read -r -p "提交说明: " msg; fi
  [ -z "$msg" ] && msg="chore: 通过 homeward-sync.sh 同步"
  git commit -m "$msg"
  git push "$REMOTE" "$BRANCH"
  ok "推送完成，当前 HEAD: $(git rev-parse --short HEAD)"
}

# ---------- 查看隔离区 ----------
do_trash(){
  if [ ! -f "$TRASH_DIR/manifest.txt" ]; then ok "隔离区为空。"; return 0; fi
  info "隔离区内容（.homeward-trash/，不参与上传，保留 ${TRASH_DAYS} 天）："
  local now; now=$(date -u +%s)
  while IFS='|' read -r f ts; do
    [ -z "$f" ] && continue
    local e; e=$(date -u -d "$ts" +%s 2>/dev/null || echo 0)
    local age=$(( (now - e) / 86400 ))
    printf "  %-50s 隔离于 %s (%d 天前)\n" "$f" "$ts" "$age"
  done < "$TRASH_DIR/manifest.txt"
}

# ---------- 清理过期隔离文件 ----------
do_purge(){
  if [ ! -f "$TRASH_DIR/manifest.txt" ]; then ok "隔离区为空，无需清理。"; return 0; fi
  local now; now=$(date -u +%s)
  local removed=0 kept=0
  local tmp; tmp="$(mktemp)"
  while IFS='|' read -r f ts; do
    [ -z "$f" ] && continue
    local e; e=$(date -u -d "$ts" +%s 2>/dev/null || echo 0)
    local age=$(( (now - e) / 86400 ))
    if [ "$age" -ge "$TRASH_DAYS" ]; then
      local p="$TRASH_DIR/$ts/$f"
      if [ -e "$p" ]; then rm -rf "$p"; removed=$((removed+1)); fi
    else
      printf '%s|%s\n' "$f" "$ts" >> "$tmp"; kept=$((kept+1))
    fi
  done < "$TRASH_DIR/manifest.txt"
  mv "$tmp" "$TRASH_DIR/manifest.txt"
  ok "清理完成：移除 $removed 个超期隔离项，保留 $kept 个未到期项（保留期 ${TRASH_DAYS} 天）。"
}

# ---------- 诊断 ----------
do_doctor(){
  info "诊断当前环境"
  echo "hostname : $(hostname 2>/dev/null)"
  echo "仓库根   : $REPO_ROOT"
  echo "远程分支 : $REMOTE/$BRANCH"
  echo "私有目录 : ${PRIVATE_DIR:-未找到}"
  echo "代理变量 : $(env | grep -i proxy || echo '  (无，符合软路由透明代理「直连即可」的设定)')"
  info "直连 GitHub 测试："
  if git ls-remote --heads "$REMOTE" >/dev/null 2>&1; then ok "可达（软路由透明代理已生效，无需代理参数）"; else warn "不可达，请检查网络 / 软路由"; fi
}

# ---------- 入口 ----------
CMD="${1:-sync}"
case "$CMD" in
  sync|pull)
    run_mirror_pull
    run_verify
    do_status
    ;;
  push)  do_push "${2:-}" "${3:-}" ;;
  status) do_status ;;
  trash)  do_trash ;;
  purge)  do_purge ;;
  doctor) do_doctor ;;
  *) err "未知子命令: $CMD （可用 sync|pull|push|status|trash|purge|doctor）"; exit 1 ;;
esac
