#!/bin/sh
# 家卫（Homeward）· iStoreOS 一键安装脚本
#
# 作用：① 让路由器开始记录 DNS 查询日志 ② 拉起家卫 Docker 容器
# 用法：在 iStoreOS 终端（SSH）进入本仓库目录后执行：
#       sh scripts/setup-istoreos.sh
# 说明：默认无鉴权（仅局域网可访问）。要暴露到公网，请先在 docker/.env
#       填好 HOMEWARD_AUTH_TOKEN，再运行本脚本。

set -u

LOG_FILE="/tmp/dnsmasq.log"
COMPOSE_FILE="docker/docker-compose.istoreos.yml"

echo ""
echo "======================================"
echo " 家卫 Homeward · iStoreOS 一键安装"
echo "======================================"

# ---------- 1/4 配置 DNS 查询日志 ----------
echo ""
echo "[1/4] 配置 dnsmasq 查询日志 ..."
if command -v uci >/dev/null 2>&1; then
    uci set dhcp.@dnsmasq[0].logqueries='1' || { echo "错误：无法写入 uci 配置"; exit 1; }
    uci set dhcp.@dnsmasq[0].logfacility="$LOG_FILE" || { echo "错误：无法写入 uci 配置"; exit 1; }
    uci commit dhcp
    /etc/init.d/dnsmasq restart
    echo "      OK：dnsmasq 已配置并重启（日志写入 $LOG_FILE）"
else
    echo "      警告：当前系统没有 uci 命令（这不是 iStoreOS/OpenWrt？）。"
    echo "      跳过 DNS 日志配置，请手动确认 dnsmasq 日志路径后再继续。"
fi

# ---------- 2/4 等待日志文件生成 ----------
echo ""
echo "[2/4] 等待日志文件生成 ..."
i=0
while [ ! -f "$LOG_FILE" ] && [ "$i" -lt 10 ]; do
    sleep 1
    i=$((i+1))
done
if [ -f "$LOG_FILE" ]; then
    echo "      OK：日志文件已生成 $LOG_FILE"
else
    echo "      提示：日志文件还没出现。别担心——配置已生效，"
    echo "            等家里设备开始上网产生 DNS 查询后，文件会自动出现。"
fi

# ---------- 3/4 拉起家卫容器 ----------
echo ""
echo "[3/4] 拉起家卫容器 ..."
if [ ! -f "$COMPOSE_FILE" ]; then
    echo "错误：找不到 $COMPOSE_FILE"
    echo "      本脚本需要在家卫源码目录下运行。请先用下面的方式获取完整源码"
    echo "      （iStoreOS 默认没装 git，用压缩包方式，不需要 git；下载带进度条，"
    echo "       GitHub 直连太慢会自动换镜像加速）："
    echo "        sh -c 'cd /tmp && U=https://github.com/homeward-labs/homeward/archive/refs/heads/main.tar.gz && echo \"[1/3] 下载家卫源码包（进度条会动）\" && { curl -fL --connect-timeout 15 --progress-bar -o hw.tar.gz \"\$U\" || curl -fL --connect-timeout 15 --progress-bar -o hw.tar.gz \"https://ghfast.top/\$U\" || wget -O hw.tar.gz \"https://ghfast.top/\$U\"; } && echo \"[2/3] 解压\" && tar xzf hw.tar.gz && cd homeward-main && echo \"[3/3] 运行安装脚本\" && sh scripts/setup-istoreos.sh'"
    exit 1
fi
if command -v docker >/dev/null 2>&1; then
    echo "      （首次安装需要构建镜像，可能要 3~10 分钟，取决于路由器性能，请耐心等待）"
    if docker compose version >/dev/null 2>&1; then
        docker compose -f "$COMPOSE_FILE" up -d
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose -f "$COMPOSE_FILE" up -d
    else
        echo "错误：未检测到 Docker Compose（iStoreOS 请在「Docker」插件里启用）。"
        exit 1
    fi
else
    echo "错误：未检测到 Docker。iStoreOS 请先在管理页启用 Docker。"
    exit 1
fi

# ---------- 4/4 完成 ----------
echo ""
echo "[4/4] 完成！"
LAN_IP=$(uci -q get network.lan.ipaddr 2>/dev/null | sed 's|/.*||')
if [ -n "$LAN_IP" ]; then
    echo ""
    echo "  请在浏览器打开：  http://$LAN_IP:9595"
else
    echo ""
    echo "  请在浏览器打开：  http://<你的路由器IP>:9595"
fi
echo ""
echo "  第一次面板可能是空的——等几分钟设备上网后就有数据了。"
echo "  想把端口暴露到公网？先在 docker/.env 里设置 HOMEWARD_AUTH_TOKEN 再运行本脚本。"
echo ""
