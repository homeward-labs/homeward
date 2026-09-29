#!/bin/sh
# 家卫（Homeward）· iStoreOS 分步安装脚本
#
# 设计原则：一步步来，每步做完立刻检查并打 ✓；失败就停在那一步，
# 明确说清是哪一步、为什么、下一步怎么办。绝不把所有事情混在一起跑。
#
# 用法（二选一）：
#   A. 按用户手册粘贴生成 /tmp/hw-install.sh 后执行：sh /tmp/hw-install.sh
#   B. 已有源码目录时，直接：sh scripts/install-istoreos.sh
set -u

TARBALL="/tmp/hw.tar.gz"
SRC_URL="https://github.com/homeward-labs/homeward/archive/refs/heads/main.tar.gz"
MIRRORS="https://ghfast.top/ https://gh-proxy.com/"

# 安装位置：遵循 iStoreOS 规范，Docker 应用统一放在 /userdata/apps/<应用名>/ 下
# （/userdata 是 iStoreOS 的持久分区，重启/重装都不丢；/tmp 是 tmpfs，重启即清空，绝不能用）。
# 源码目录每次重装会被 rm -rf 重建；数据目录独立到同级的 homeward-data，重装/重启都不丢。
BASE=""
for _c in /userdata/apps /userdata /root; do
  if mkdir -p "$_c/.hw_probe" 2>/dev/null; then
    rmdir "$_c/.hw_probe" 2>/dev/null
    BASE="$_c"
    break
  fi
done
if [ -z "$BASE" ]; then
  echo "  ！ 未找到可用的持久目录（/userdata/apps、/userdata、/root 均不可写），将退回 /tmp（重启/重装数据会丢失）"
  BASE="/tmp"
  mkdir -p "$BASE"
fi
DIR="$BASE/homeward"                   # 源码目录（iStore 标准应用位）：每次重装 rm -rf 重建
DATA_DIR="$BASE/homeward-data"         # 数据目录：独立于源码，重装/重启都不丢
BACKUP_FILE="$BASE/homeward-data-backup.tar.gz"
LOG_FILE="/tmp/dnsmasq.log"
COMPOSE_FILE="docker/docker-compose.istoreos.yml"

step() { echo ""; echo "===== $1 ====="; }
ok()   { echo "  ✓ $1"; }
no()   { echo "  ✗ $1"; }

echo ""
echo "======================================"
echo " 家卫 Homeward · iStoreOS 分步安装"
echo "======================================"

# ---------- 第 1 步：检查网络 ----------
step "第 1 步 / 共 5 步：检查路由器网络"
NET_OK=0
if ping -c 1 -W 3 223.5.5.5 >/dev/null 2>&1; then
    NET_OK=1
    ok "外网连通（ping 223.5.5.5 正常）"
else
    no "ping 不通外网 —— 路由器现在没联上网"
    echo "    处理：先确认路由器 WAN 口联网正常（管理页首页能看到公网 IP），"
    echo "          修好后重新运行：sh /tmp/hw-install.sh"
    exit 1
fi
if nslookup github.com >/dev/null 2>&1; then
    ok "DNS 解析正常"
else
    echo "  ！ DNS 解析 github.com 失败（不影响下一步：会优先走国内镜像）"
fi

# ---------- 第 2 步：下载源码包 ----------
step "第 2 步 / 共 5 步：下载家卫源码包"
if [ -s "$TARBALL" ] && tar -tzf "$TARBALL" >/dev/null 2>&1; then
    ok "发现已下载好的压缩包 $TARBALL，跳过下载（想重新下载请先删掉它）"
else
    DL_OK=0
    for URL in $MIRRORS"$SRC_URL" "$SRC_URL"; do
        echo "  尝试下载源：$URL"
        if command -v curl >/dev/null 2>&1; then
            curl -fL --connect-timeout 10 --max-time 300 --progress-bar -o "$TARBALL" "$URL" && DL_OK=1
        else
            wget -O "$TARBALL" "$URL" && DL_OK=1
        fi
        if [ "$DL_OK" = "1" ] && [ -s "$TARBALL" ]; then
            break
        fi
        echo "  （这个源下不动，自动换下一个…）"
    done
    if [ "$DL_OK" = "1" ] && [ -s "$TARBALL" ]; then
        ok "下载完成：$TARBALL"
    else
        no "三个下载源都失败了"
        echo "    处理（三选一）："
        echo "    ① 稍等几分钟再重跑本脚本（可能是网络临时抖动）；"
        echo "    ② 用手机热点给路由器联网后重跑；"
        echo "    ③ 电脑浏览器打开 $SRC_URL"
        echo "       手动下载后把文件拷到路由器 /tmp/ 目录，命名 hw.tar.gz，再重跑本脚本（会自动跳过下载）。"
        exit 1
    fi
fi

# ---------- 第 3 步：校验、备份既有数据并解压 ----------
step "第 3 步 / 共 5 步：校验、备份既有数据并解压"
if ! tar -tzf "$TARBALL" >/dev/null 2>&1; then
    no "压缩包损坏（下载不完整）"
    echo "    处理：rm -f $TARBALL 后重新运行本脚本。"
    exit 1
fi
ok "压缩包完好"

# —— 重装前：先保住既有数据 ——
# 数据目录 $DATA_DIR 独立于源码目录，下面的 rm -rf "$DIR" 不会动它；这里再打一份备份到
# 持久位置，并兼容旧版（旧安装把数据放在 /tmp/homeward-main），若还在就先迁过来。
BACKUP_FILE="$BASE/homeward-data-backup.tar.gz"
LEGACY="/tmp/homeward-main"
if [ ! -d "$DATA_DIR" ] && [ -d "$LEGACY" ]; then
    for _ld in "$LEGACY/data" "$LEGACY/docker/data"; do
        if [ -d "$_ld" ]; then
            mkdir -p "$DATA_DIR"
            cp -a "$_ld/." "$DATA_DIR/" 2>/dev/null && ok "已从旧位置迁移历史数据：$_ld"
            break
        fi
    done
fi
if [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
    tar czf "$BACKUP_FILE" -C "$BASE" "$(basename "$DATA_DIR")" 2>/dev/null \
        && ok "已备份既有数据到 $BACKUP_FILE" \
        || echo "  ！ 备份失败（不影响安装，数据仍在 $DATA_DIR）"
else
    echo "  · 没有既有数据需要备份（首次安装或数据目录为空）"
fi

rm -rf "$DIR"
if tar xzf "$TARBALL" -C "$BASE"; then
    # GitHub 归档顶层目录通常为 homeward-main，重命名为标准应用名 homeward
    _src=$(tar tzf "$TARBALL" | head -1 | cut -d/ -f1)
    if [ -n "$_src" ] && [ "$_src" != "$(basename "$DIR")" ] && [ -d "$BASE/$_src" ]; then
        mv "$BASE/$_src" "$DIR"
    fi
    if [ -f "$DIR/scripts/install-istoreos.sh" ]; then
        ok "解压完成：$DIR"
    else
        no "解压失败（未找到安装脚本）"
        exit 1
    fi
else
    no "解压失败"
    exit 1
fi

# ---------- 第 4 步：配置 DNS 查询日志 ----------
step "第 4 步 / 共 5 步：让路由器开始记录 DNS 查询"
if command -v uci >/dev/null 2>&1; then
    if uci set dhcp.@dnsmasq[0].logqueries='1' \
       && uci set dhcp.@dnsmasq[0].logfacility="$LOG_FILE" \
       && uci commit dhcp \
       && /etc/init.d/dnsmasq restart; then
        ok "dnsmasq 已配置并重启（日志写入 $LOG_FILE）"
    else
        no "uci 配置失败 —— 可改用手动方式：管理页 → 网络 → DHCP/DNS → 日志标签页"
        echo "    （勾选「记录 DNS 查询」；日志设施输入 /tmp/dnsmasq.log 回车添加）"
        exit 1
    fi
    i=0
    while [ ! -f "$LOG_FILE" ] && [ "$i" -lt 10 ]; do
        sleep 1
        i=$((i+1))
    done
    if [ -f "$LOG_FILE" ]; then
        ok "日志文件已生成"
    else
        echo "  ！ 日志文件还没出现——配置已生效，设备开始上网后文件会自动出现，不影响安装"
    fi
else
    echo "  ！ 当前系统没有 uci（不是 iStoreOS/OpenWrt？），跳过 DNS 配置"
fi

# ---------- 第 5 步：拉起家卫容器 ----------
step "第 5 步 / 共 5 步：拉起家卫容器"
cd "$DIR" || { no "找不到源码目录 $DIR"; exit 1; }
if [ ! -f "$COMPOSE_FILE" ]; then
    no "找不到 $COMPOSE_FILE"
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    no "未检测到 Docker —— iStoreOS 管理页 → Docker 插件，先启用再重跑本脚本"
    exit 1
fi
echo "  （首次构建镜像约 3~10 分钟，输出滚动属正常，请不要关闭窗口）"
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
else
    no "未检测到 Docker Compose —— iStoreOS 请在 Docker 插件里启用 Compose"
    exit 1
fi
mkdir -p "$DATA_DIR"
# 把持久化数据目录传给 compose（docker/docker-compose.istoreos.yml 用它做 bind 挂载源）
export HOMEWARD_DATA_HOST="$DATA_DIR"
export HOMEWARD_LOGS_HOST="$DATA_DIR/logs"
if $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d --build; then
    ok "家卫容器已启动"
    # 重装后若数据目录为空但有备份，则自动恢复（兜底：极少触发，因 $DATA_DIR 本身持久）
    _empty=1
    [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ] && _empty=0
    if [ "$_empty" = "1" ] && [ -f "$BACKUP_FILE" ]; then
        tar xzf "$BACKUP_FILE" -C "$BASE" 2>/dev/null && ok "已从备份自动恢复历史数据"
    fi
else
    no "容器启动失败 —— 把上面最后几行报错发给维护者排查"
    exit 1
fi

# ---------- 完成 ----------
echo ""
echo "======================================"
echo " ✓ 全部 5 步完成！"
LAN_IP=$(uci -q get network.lan.ipaddr 2>/dev/null | sed 's|/.*||')
if [ -n "$LAN_IP" ]; then
    echo "   浏览器打开：  http://$LAN_IP:9595"
else
    echo "   浏览器打开：  http://<路由器IP>:9595"
fi
echo "======================================"
echo ""
echo "  数据持久化：观测记录与许可指纹保存在 $DATA_DIR（独立于源码，重装/重启不丢）。"
echo "  若之前装过旧版，历史数据会在重装时自动迁移/恢复。"
echo ""
echo "  下一步（重要）：若面板是空的，是因为还没有设备把查询发到这台路由器。"
echo "  ▸ 这台软路由若带无线网卡，可以开一个 WiFi 让设备连进来："
echo "    - 当主路由用：设备直接连它的 WiFi 上网；"
echo "    - 当旁路由用：主路由不动，只把部分设备的网关/DNS 指向它。"
echo "    建议 WiFi 名与主路由不同，把智能设备和手机电脑分成两个网络："
echo "    好管理、更安全；这台设备万一出问题也不影响主网络（旁路由的好处）。"
echo "    （透明网桥等其他模式将在后续版本支持）"
echo "  ▸ 个别智能设备不会自动走新路由，需要手动把它的 DNS 改成本路由 IP；"
echo "    想主动盯住某个设备的方法，将在后续版本提供。"
echo ""
echo "  安全提示：默认只建议在内网访问。确需暴露公网，请先在 docker/.env"
echo "  设置 HOMEWARD_AUTH_TOKEN（访问口令），再重启容器。"
echo ""
