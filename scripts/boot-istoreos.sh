#!/bin/sh
# 家卫 Homeward · iStoreOS 一键引导
# 用户只需执行一条命令（无任何引号，粘贴不会出错）：
#   wget -qO- https://ghfast.top/https://raw.githubusercontent.com/homeward-labs/homeward/main/scripts/boot-istoreos.sh | sh
set -u
TARBALL="/tmp/hw.tar.gz"
SRC_URL="https://github.com/homeward-labs/homeward/archive/refs/heads/main.tar.gz"
DIR="/tmp/homeward-main"

# 包必须是「完好的压缩包 + 里面有安装脚本」才算合格
# （防两类坑：下载到一半的坏包；镜像缓存的旧版包——里面还没有安装脚本）
tarball_ok() {
    tar -tzf "$TARBALL" 2>/dev/null | grep -q "install-istoreos.sh"
}

echo ""
echo "======================================"
echo " 家卫 Homeward · iStoreOS 一键安装"
echo "======================================"
echo "① 下载家卫源码包（进度条会动；直连慢自动换镜像）..."

if [ -s "$TARBALL" ] && tarball_ok; then
    echo "   ✓ 发现已下载好的合格包，跳过下载（想重新下载请先删 /tmp/hw.tar.gz）"
else
    if [ -s "$TARBALL" ]; then
        echo "   ！发现旧包/坏包（缺少安装脚本或已损坏），自动删除重新下载…"
        rm -f "$TARBALL"
    fi
    GOT=0
    for U in "https://ghfast.top/$SRC_URL" "https://gh-proxy.com/$SRC_URL" "$SRC_URL"; do
        echo "   尝试下载源：$U"
        if command -v curl >/dev/null 2>&1; then
            curl -fL --connect-timeout 10 --max-time 300 --progress-bar -o "$TARBALL" "$U" && GOT=1
        else
            wget -O "$TARBALL" "$U" && GOT=1
        fi
        if [ "$GOT" = "1" ] && tarball_ok; then
            break
        fi
        GOT=0
        rm -f "$TARBALL"
        echo "   （这个源的包不合格，自动换下一个…）"
    done
    if [ "$GOT" != "1" ]; then
        echo "   ✗ 所有下载源都失败了"
        echo "     出路：电脑浏览器打开 $SRC_URL 下载，"
        echo "     拷到路由器 /tmp/ 并命名 hw.tar.gz，再重新执行本命令（会自动跳过下载）。"
        exit 1
    fi
fi
echo "   ✓ 下载完成（已确认包内有安装脚本）"

echo "② 解压..."
rm -rf "$DIR"
tar xzf "$TARBALL" -C /tmp || { echo "   ✗ 解压失败，请删 /tmp/hw.tar.gz 后重试"; exit 1; }
[ -f "$DIR/scripts/install-istoreos.sh" ] || { echo "   ✗ 包内容异常（缺少安装脚本），请重跑本命令自动重新下载"; exit 1; }
echo "   ✓ 解压完成"

echo "③ 启动安装（内部自动分 5 步执行，每步打完 ✓ 再进下一步）..."
echo ""
sh "$DIR/scripts/install-istoreos.sh"
