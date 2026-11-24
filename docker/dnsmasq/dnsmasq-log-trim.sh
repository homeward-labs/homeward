#!/bin/sh
# 家卫 · dnsmasq 日志精简档（小存储设备专用）
# 设计依据：docs/03-服务端部署/小存储设备档位方案-2026-11-24.md
#
# 硬规则（改脚本前先读）：
#   1. 零放大 —— 只做原地 `: >` 截断，绝不复制日志本体；可选尾片上限 2 MB。
#   2. 按大小触发，不按时间 —— 阈值 min(HOMEWARD_LOG_MAX_MB, tmpfs 可用 * PCT%)。
#   3. 失败不截断 —— 尾片写入失败就退出，宁可涨、不可丢。
#   4. 保 inode —— 只用 `: >`；禁 mv，禁新建同名文件替换（bind 挂载会失明）。
#
# 用法：
#   dnsmasq-log-trim.sh check     # 打印档位/阈值/当前占用，不修改任何东西（安装自检用）
#   dnsmasq-log-trim.sh trim      # 超阈值就截断（cron 每 5 分钟）
#   dnsmasq-log-trim.sh           # 等价于 trim
#
# 环境变量（都可不设）：
#   HOMEWARD_DNS_LOG       日志路径，默认 /tmp/dnsmasq.log
#   HOMEWARD_LOG_MAX_MB    上限 MB，默认 16
#   HOMEWARD_LOG_TMPFS_PCT 可用空间百分比上限，默认 8
#   HOMEWARD_LOG_TAIL_DIR  可选尾片目录（必须与日志不同文件系统才会启用）
#   HOMEWARD_LOG_TAIL_BYTES 尾片字节数，默认 2097152（2 MB）
#   HOMEWARD_LOG_TRIM_DRY  非空则只打印将要做什么
#
# 退出码：0 正常（截断/无需动作/检查）｜1 参数或环境错误｜3 尾片失败已放弃（未截断）

set -u

LOG=${HOMEWARD_DNS_LOG:-/tmp/dnsmasq.log}
MAX_MB=${HOMEWARD_LOG_MAX_MB:-16}
PCT=${HOMEWARD_LOG_TMPFS_PCT:-8}
TAIL_DIR=${HOMEWARD_LOG_TAIL_DIR:-}
TAIL_BYTES=${HOMEWARD_LOG_TAIL_BYTES:-2097152}
DRY=${HOMEWARD_LOG_TRIM_DRY:-}

log_msg() {
    if command -v logger >/dev/null 2>&1; then
        logger -t homeward-log-trim "$*" 2>/dev/null || true
    fi
    echo "[homeward-log-trim] $*"
}

usage() {
    echo "usage: $0 [check|trim]" >&2
    exit 1
}

[ -n "$LOG" ] || { echo "HOMEWARD_DNS_LOG 不能为空" >&2; exit 1; }
case "$MAX_MB" in ''|*[!0-9]*) echo "HOMEWARD_LOG_MAX_MB 必须是整数" >&2; exit 1;; esac
case "$PCT" in ''|*[!0-9]*) echo "HOMEWARD_LOG_TMPFS_PCT 必须是整数" >&2; exit 1;; esac

LOG_DIR=$(dirname "$LOG")
[ -d "$LOG_DIR" ] || { log_msg "目录不存在：$LOG_DIR（无 DNS 观测，退出）"; exit 1; }

# 日志所在文件系统的可用 KB（POSIX df -Pk，busybox 也支持）
AVAIL_KB=$(df -Pk "$LOG_DIR" 2>/dev/null | awk 'NR==2 {print $4}')
[ -n "${AVAIL_KB:-}" ] || AVAIL_KB=0

# 阈值 = min(MAX_MB * 1MB, 可用 * PCT%)
LIMIT_MB_BYTES=$((MAX_MB * 1048576))
LIMIT_PCT_BYTES=$((AVAIL_KB * 1024 * PCT / 100))
LIMIT_BYTES=$LIMIT_MB_BYTES
[ "$LIMIT_PCT_BYTES" -lt "$LIMIT_BYTES" ] && LIMIT_BYTES=$LIMIT_PCT_BYTES
[ "$LIMIT_BYTES" -lt 1048576 ] && LIMIT_BYTES=1048576   # 下限 1 MB，避免阈值塌成 0 而反复截断

SIZE=0
[ -f "$LOG" ] && SIZE=$(wc -c < "$LOG" 2>/dev/null | tr -d ' ')
[ -n "${SIZE:-}" ] || SIZE=0

mode=${1:-trim}
case "$mode" in
check)
    TIER=精简档
    [ -n "$TAIL_DIR" ] && [ -d "$TAIL_DIR" ] && TIER=精简档+尾片
    printf '档位=%s\n' "$TIER"
    printf '日志=%s\n' "$LOG"
    printf '当前=%s B（%.1f MB）\n' "$SIZE" "$((SIZE))"
    printf '阈值=%s B（%.1f MB，= min(%s MB, 可用 %s KB * %s%%）)\n' \
        "$LIMIT_BYTES" "$LIMIT_BYTES" "$MAX_MB" "$AVAIL_KB" "$PCT"
    printf '超限=%s\n' "$([ "$SIZE" -ge "$LIMIT_BYTES" ] && echo yes || echo no)"
    exit 0
;;
trim) ;;
*) usage ;;
esac

if [ "$SIZE" -lt "$LIMIT_BYTES" ]; then
    [ -n "$DRY" ] && log_msg "dry: 未超阈值（$SIZE < $LIMIT_BYTES），无需动作"
    exit 0
fi

# 可选尾片：仅当目标目录存在、且与日志不在同一文件系统时才做（零放大规则的延伸）
if [ -n "$TAIL_DIR" ] && [ -d "$TAIL_DIR" ]; then
    if [ "$(stat -c %d "$LOG_DIR" 2>/dev/null)" = "$(stat -c %d "$TAIL_DIR" 2>/dev/null)" ]; then
        log_msg "尾片跳过：目标与日志同一文件系统（零放大规则），只截断"
    else
        TAIL_TMP="$TAIL_DIR/.dnsmasq-tail.tmp"
        TAIL_OUT="$TAIL_DIR/dnsmasq-tail.log"
        if [ -n "$DRY" ]; then
            log_msg "dry: 将写尾片 $TAIL_BYTES B 到 $TAIL_OUT 后截断"
        else
            if tail -c "$TAIL_BYTES" "$LOG" > "$TAIL_TMP" 2>/dev/null && [ -s "$TAIL_TMP" ]; then
                mv -f "$TAIL_TMP" "$TAIL_OUT" 2>/dev/null || {
                    log_msg "尾片改名失败，放弃截断（失败不截断）"; rm -f "$TAIL_TMP"; exit 3; }
                log_msg "尾片已存 $TAIL_OUT（$TAIL_BYTES B 上限）"
            else
                log_msg "尾片写入失败，放弃截断（失败不截断）"
                rm -f "$TAIL_TMP"
                exit 3
            fi
        fi
    fi
fi

if [ -n "$DRY" ]; then
    log_msg "dry: 将截断 $LOG（当前 $SIZE B，阈值 $LIMIT_BYTES B）"
    exit 0
fi

# 原地截断：保 inode（只此一种写法，禁 mv）
: > "$LOG" 2>/dev/null || { log_msg "截断失败：$LOG"; exit 1; }
log_msg "已截断 $LOG（原 $SIZE B，阈值 $LIMIT_BYTES B，档位=精简）"
exit 0
