#!/usr/bin/env bash
# homeward-sync.sh —— 家卫跨机一键同步脚本（傻瓜版）
# ---------------------------------------------------------------------------
# 不管在公司还是家里，跑一次就自动处理「跨机同步卫生」：
#   1) 把本地仓库强制对齐成远程镜像（清掉上游已删的残留文件，
#      从根上防止 `git add -A` 把这些残留误推上服务器）
#   2) 校验私有目录目录完整性（verify.py）
#   3) 识别当前机器 / 站点，并报告两个目录的当前状态
#   4) 可选「受保护推送」：绝不 git add -A；只 add 具体文件；跑开源边界自检
#
# 本脚本是公开的（进 git 仓库），不含任何敏感信息；敏感资料只在「私有目录」目录。
#
# 用法：
#   ./homeward-sync.sh              # 默认 = 镜像拉取 + 私有校验 + 状态报告（最安全，推荐每次跑）
#   ./homeward-sync.sh pull         # 等同默认
#   ./homeward-sync.sh push         # 受保护推送（交互确认，绝不盲加）
#   ./homeward-sync.sh push --yes   # 跳过交互确认（仅在你清楚在做什么时用）
#   ./homeward-sync.sh status       # 只报告两个目录状态
#   ./homeward-sync.sh doctor       # 诊断当前机器 / 代理 / 路径
#
# 环境变量（可选）：
#   HOMEWARD_PRIVATE_DIR   私有目录目录路径（探测不到时指定）
#   HOMEWARD_REMOTE        远程名（默认 origin）
#   HOMEWARD_BRANCH        分支名（默认 main）
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

# ---------- 定位仓库（自动，不硬编码路径） ----------
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO_ROOT" ]; then
  err "当前目录不在 git 仓库内。请先 cd 到家卫代码仓库再运行本脚本。"
  exit 1
fi
cd "$REPO_ROOT" || exit 1

REMOTE="${HOMEWARD_REMOTE:-origin}"
BRANCH="${HOMEWARD_BRANCH:-main}"

# ---------- 探测私有目录目录（不硬编码绝对敏感路径） ----------
detect_private(){
  local d
  if [ -n "${HOMEWARD_PRIVATE_DIR:-}" ] && [ -d "$HOMEWARD_PRIVATE_DIR" ]; then
    echo "$HOMEWARD_PRIVATE_DIR"; return 0
  fi
  for d in "$HOME/私有目录" "$HOME/Documents/私有目录" "$HOME/私有目录目录"; do
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

# ---------- 镜像拉取（清残留，防误推） ----------
run_mirror_pull(){
  info "镜像拉取：把本地强制对齐成 $REMOTE/$BRANCH，并清掉上游已删的残留文件"
  if [ -f "$REPO_ROOT/scripts/git-mirror-pull.sh" ]; then
    bash "$REPO_ROOT/scripts/git-mirror-pull.sh"
    return $?
  fi
  # 兜底内联（极少数没带 git-mirror-pull.sh 的情况）
  git fetch "$REMOTE" --prune
  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "发现未提交 tracked 改动，reset --hard 会丢。请先 git stash / commit："
    git status --porcelain | sed 's/^/    /'
    return 1
  fi
  git reset --hard "$REMOTE/$BRANCH"
  git clean -fd
  ok "拉取完成，当前 HEAD: $(git rev-parse --short HEAD)"
}

# ---------- 校验私有目录目录 ----------
run_verify(){
  if [ -z "$PRIVATE_DIR" ]; then
    warn "未探测到私有目录目录（可设 HOMEWARD_PRIVATE_DIR 环境变量）。跳过 verify.py。"
    return 0
  fi
  info "校验私有目录目录：$PRIVATE_DIR"
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
  echo "--- 私有目录目录 ---"
  if [ -n "$PRIVATE_DIR" ]; then
    echo "  路径 : $PRIVATE_DIR"
  else
    warn "  未探测到（可设 HOMEWARD_PRIVATE_DIR）"
  fi
  echo "  （公司基线请对照 私有目录/CODELINE.md；家里仓库 HEAD 须独立核验，勿套用公司基线）"
}

# ---------- 受保护推送 ----------
do_push(){
  local yes=0
  [ "${1:-}" = "--yes" ] && yes=1
  info "受保护推送（绝不 git add -A）"

  # 1) 先清未跟踪残留，防误推
  local dirty; dirty="$(git clean -fdn 2>/dev/null)"
  if [ -n "$dirty" ]; then
    warn "存在未跟踪文件（正是要防误推的残留），先清理："
    echo "$dirty" | sed 's/^/    /'
    if [ "$yes" = 1 ]; then
      git clean -fd
    else
      read -r -p "删除这些未跟踪文件？(y/N) " a
      case "$a" in y|Y) git clean -fd ;; *) warn "未清理，推送中止。"; return 1 ;; esac
    fi
  fi

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
  doctor) do_doctor ;;
  *) err "未知子命令: $CMD （可用 sync|pull|push|status|doctor）"; exit 1 ;;
esac
