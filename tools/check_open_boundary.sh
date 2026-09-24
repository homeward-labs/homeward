#!/bin/sh
# homeward 开源边界自检脚本
#
# 用途：在任何时候（尤其是 git push 之前）手动跑一遍，验证闭源代码不可能进入公开仓库。
# 用法：sh tools/check_open_boundary.sh        （Windows / Git Bash）
#       bash tools/check_open_boundary.sh      （Linux / macOS）
#
# 退出码：0 = 全部通过；1 = 发现越界，必须处理后再推送。
#
# 兼容 Windows git bash：不使用 mktemp/touch/rm。

# 闭源区是「整个目录」，不只是其下的 standard/ pro/ 子目录 ——
# 否则直接放在 src/editions/ 下的文件会绕过第一道防线。
CLOSED_DIRS="src/enforcers src/editions"
SENTINEL_RE="@closed-source|@standard-only|@pro-only"

fail=0
warn=0

pass() { echo "  [PASS] $1"; }
bad()  { echo "  [FAIL] $1"; fail=$((fail + 1)); }
warn_() { echo "  [WARN] $1"; warn=$((warn + 1)); }

echo ""
echo "=============================================="
echo " 家卫 · 开源边界自检"
echo " 闭源目录：$CLOSED_DIRS"
echo " 闭源标记：$SENTINEL_RE"
echo "=============================================="

# ---------- 0. 前提：在 git 仓库里 ----------
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "  [FAIL] 当前目录不是 git 仓库，无法自检。"
  exit 1
fi

# ---------- 1. 钩子是否启用 ----------
echo ""
echo "1) 钩子防线"
hook_path=$(git config core.hooksPath </dev/null 2>/dev/null)
if [ "$hook_path" = "hooks" ]; then
  pass "core.hooksPath = hooks（已指向仓库内钩子目录）"
else
  bad "core.hooksPath 未设置为 hooks（当前：'${hook_path:-<空>}'）。请执行：git config core.hooksPath hooks"
fi

for h in pre-commit pre-push; do
  if [ -f "hooks/$h" ]; then
    pass "hooks/$h 存在"
  else
    bad "hooks/$h 缺失 —— 少了一道拦截闸"
  fi
done

# ---------- 2. .gitignore 规则 ----------
echo ""
echo "2) .gitignore 规则"
for d in $CLOSED_DIRS; do
  # 同时接受 'src/editions' 与 'src/editions/' 两种写法
  if grep -qE "^$d/?\$" .gitignore </dev/null 2>/dev/null; then
    pass ".gitignore 含规则 '$d'（目录本体，覆盖其下所有子路径）"
  else
    bad ".gitignore 缺少规则 '$d'（注意：目录规则不要带行尾斜杠+行内中文注释，那样会失效）"
  fi
done

# ---------- 3. 忽略规则是否真的生效 ----------
echo ""
echo "3) 忽略规则实效（对尚不存在的路径做探测）"
for d in $CLOSED_DIRS; do
  if git check-ignore -q --no-index "$d/probe.py" </dev/null 2>/dev/null; then
    pass "'$d/probe.py' 会被 git 忽略"
  else
    bad "'$d/probe.py' 未被忽略 —— 该目录下的文件可被 git add 收录"
  fi
done

# ---------- 4. 索引中是否有闭源路径 ----------
echo ""
echo "4) 已跟踪文件（git ls-files）"
tracked=$(git ls-files </dev/null 2>/dev/null)
hit=0
for d in $CLOSED_DIRS; do
  if printf '%s\n' "$tracked" | grep -q "^$d/"; then
    bad "已跟踪文件中存在闭源路径 '$d/'："
    printf '%s\n' "$tracked" | grep "^$d/" | sed 's/^/         /'
    hit=1
  fi
done
[ "$hit" -eq 0 ] && pass "已跟踪文件中无任何闭源路径"

# ---------- 5. 全历史扫描（含已删除的文件） ----------
echo ""
echo "5) 全部提交历史（git log --all，含已删除文件）"
hist=$(git log --all --pretty=format: --name-only </dev/null 2>/dev/null | sort -u)
hit=0
for d in $CLOSED_DIRS; do
  if printf '%s\n' "$hist" | grep -q "^$d/"; then
    bad "提交历史中出现过闭源路径 '$d/'："
    printf '%s\n' "$hist" | grep "^$d/" | sed 's/^/         /'
    hit=1
  fi
done
[ "$hit" -eq 0 ] && pass "全部历史中无闭源路径"

# ---------- 6. 哨兵标记扫描（当前 HEAD 全树） ----------
echo ""
echo "6) 闭源标记哨兵（HEAD 的 src/ 下）"
# 只扫 src/：docs/ 与 hooks/ 需要合法地「提及」这些标记词（规则说明本身就是文档），
# 扫全树会把文档与钩子自身报成违规 —— 与 pre-commit / pre-push 的策略保持一致。
if git rev-parse --verify HEAD >/dev/null 2>&1; then
  bad_files=$(git grep -l -E "$SENTINEL_RE" HEAD -- src/ </dev/null 2>/dev/null)
  if [ -n "$bad_files" ]; then
    bad "以下文件含闭源标记："
    printf '%s\n' "$bad_files" | sed 's/^/         /'
  else
    pass "HEAD 全树无闭源标记"
  fi
else
  warn_ "仓库尚无提交，跳过哨兵扫描"
fi

# ---------- 7. 本地闭源目录残留（应只存在于本地，且不被跟踪） ----------
echo ""
echo "7) 本地闭源目录（存在但被忽略 = 正常）"
for d in $CLOSED_DIRS; do
  if [ -d "$d" ]; then
    n=$(git status --porcelain --ignored "$d" </dev/null 2>/dev/null | wc -l)
    if git check-ignore -q "$d" </dev/null 2>/dev/null; then
      pass "'$d' 存在于本地且被忽略（不会被推送）"
    else
      warn_ "'$d' 存在于本地但**未被忽略**，git add -A 会把它收进去"
    fi
  else
    pass "'$d' 本地不存在（闭源码在仓库外 —— 最安全的形态）"
  fi
done

# ---------- 结论 ----------
echo ""
echo "=============================================="
if [ "$fail" -ne 0 ]; then
  echo " 结果：$fail 项失败，$warn 项警告 —— 请勿推送。"
  echo " 修复后重跑本脚本；确认无误再执行 git push。"
  echo "=============================================="
  echo ""
  exit 1
fi
echo " 结果：全部通过（$warn 项警告）—— 可以推送。"
echo " 记住：pre-push 钩子还会再查一遍，双保险。"
echo "=============================================="
echo ""
exit 0
