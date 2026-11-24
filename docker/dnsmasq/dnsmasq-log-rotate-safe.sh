#!/bin/sh
# 家卫 · dnsmasq 日志归档档（有独立磁盘时使用，252 现行方案的加固版）
#
# 与 252 上现役 `dnsmasq-log-rotate.sh` 的差别只有两条硬约束（其余行为保持一致）：
#   1. 日志 > HOMEWARD_ARCHIVE_FULL_MAX_MB（默认 32 MB）时，**禁止整份 cp**，
#      只存尾部 HOMEWARD_ARCHIVE_TAIL_BYTES（默认 8 MB）为 `<stamp>.tail.log.truncated`。
#      起因：2026-11-23 252 首次归档把上线前 594.9 MB 历史整份留成"最老小时档"，
#      单文件吃掉 650 MB 目录的 91%。
#   2. 归档目标与日志必须**不同文件系统**；同盘同分区时直接拒绝归档（退化为精简档行为）。
#
# 用法：dnsmasq-log-rotate-safe.sh [--dry]
# 环境变量：HOMEWARD_DNS_LOG / HOMEWARD_ARCHIVE_DIR / HOMEWARD_ARCHIVE_FULL_MAX_MB
#           HOMEWARD_ARCHIVE_TAIL_BYTES / HOMEWARD_DNSMASQ_RESTART_CMD（默认不重启）
#
# 退出码：0 正常（归档+截断 或 无需动作）｜2 拒绝归档（同文件系统/目录不可写）｜3 归档失败（未截断）｜4 参数错误

set -u

LOG=${HOMEWARD_DNS_LOG:-/tmp/dnsmasq.log}
ARCH=${HOMEWARD_ARCHIVE_DIR:-/mnt/mydisk/dnsmasq}
FULL_MAX_MB=${HOMEWARD_ARCHIVE_FULL_MAX_MB:-32}
TAIL_BYTES=${HOMEWARD_ARCHIVE_TAIL_BYTES:-8388608}
DRY=
[ "${1:-}" = "--dry" ] && DRY=1

log_msg() {
    command -v logger >/dev/null 2>&1 && logger -t homeward-log-archive "$*" 2>/dev/null || true
    echo "[homeward-log-archive] $*"
}

case "$FULL_MAX_MB" in ''|*[!0-9]*) echo "HOMEWARD_ARCHIVE_FULL_MAX_MB 必须是整数" >&2; exit 4;; esac

[ -f "$LOG" ] || { log_msg "日志不存在：$LOG"; exit 0; }
mkdir -p "$ARCH" 2>/dev/null || { log_msg "归档目录不可写：$ARCH"; exit 2; }

# 硬约束 2：同文件系统拒绝归档
if [ "$(stat -c %d "$(dirname "$LOG")" 2>/dev/null)" = "$(stat -c %d "$ARCH" 2>/dev/null)" ]; then
    log_msg "拒绝归档：$ARCH 与日志同一文件系统（零放大）。请改用精简档 dnsmasq-log-trim.sh"
    exit 2
fi

SIZE=$(wc -c < "$LOG" 2>/dev/null | tr -d ' ')
[ -n "${SIZE:-}" ] || SIZE=0
STAMP=$(date +%Y%m%d-%H)
FULL_MAX_BYTES=$((FULL_MAX_MB * 1048576))

if [ "$SIZE" -gt "$FULL_MAX_BYTES" ]; then
    OUT="$ARCH/dnsmasq-$STAMP.tail.log.truncated"
    [ -n "$DRY" ] && { log_msg "dry: 大文件 $SIZE B，只存尾片 $TAIL_BYTES B → $OUT"; exit 0; }
    if tail -c "$TAIL_BYTES" "$LOG" > "$OUT.tmp" 2>/dev/null && [ -s "$OUT.tmp" ]; then
        mv -f "$OUT.tmp" "$OUT" 2>/dev/null || { log_msg "尾片改名失败，放弃截断"; rm -f "$OUT.tmp"; exit 3; }
        log_msg "大文件仅存尾片：$OUT（源 $SIZE B，禁整份 cp）"
    else
        log_msg "尾片写入失败，放弃截断（失败不截断）"
        rm -f "$OUT.tmp"
        exit 3
    fi
else
    OUT="$ARCH/dnsmasq-$STAMP.log"
    [ -n "$DRY" ] && { log_msg "dry: 整份归档 $SIZE B → $OUT"; exit 0; }
    cp -f "$LOG" "$OUT" 2>/dev/null || { log_msg "整份归档失败，放弃截断"; exit 3; }
    log_msg "整份归档：$OUT（$SIZE B）"
fi

if [ -n "$DRY" ]; then exit 0; fi

# 保 inode 原地截断
: > "$LOG" 2>/dev/null || { log_msg "截断失败：$LOG"; exit 1; }
log_msg "已截断 $LOG（归档档）"

# 保留策略：小时档 24 份、日档 7 份（与 252 现役一致）
if [ "$STAMP" ]; then
    ls -1t "$ARCH"/dnsmasq-??????-??.log 2>/dev/null | tail -n +25 | while read -r f; do rm -f "$f"; done
fi
if [ "$(date +%H)" = "04" ]; then
    DAY=$(date +%Y%m%d)
    cp -f "$ARCH/dnsmasq-$STAMP.log" "$ARCH/dnsmasq-$DAY.log" 2>/dev/null || true
    ls -1t "$ARCH"/dnsmasq-????????.log 2>/dev/null | tail -n +8 | while read -r f; do rm -f "$f"; done
fi

exit 0
