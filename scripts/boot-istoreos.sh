#!/bin/sh
# 家卫 Homeward · iStoreOS 一键引导
# 安全用法（先落盘、再看、再执行；禁止 wget|sh 直执行未校验的远程脚本）：
#   wget -qO /tmp/hw-boot.sh https://ghfast.top/https://raw.githubusercontent.com/homeward-labs/homeward/main/scripts/boot-istoreos.sh \
#     && sh /tmp/hw-boot.sh
# 可选硬校验：执行前 export EXPECTED_SHA256=<可信渠道拿到的源码包 sha256>
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

# 注意：每次都重新下载，确保拿到的永远是最新代码（旧包合格也会导致装到旧版本）
if [ -s "$TARBALL" ]; then
    echo "   清理旧包，重新下载最新版…"
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
    if [ -n "${EXPECTED_SHA256:-}" ]; then
        _ACTUAL=$(sha256sum "$TARBALL" 2>/dev/null | awk '{print $1}')
        if [ -z "$_ACTUAL" ] || [ "$_ACTUAL" != "$EXPECTED_SHA256" ]; then
            echo "   ✗ 源码包 sha256 校验失败（期望 ${EXPECTED_SHA256}；实得 ${_ACTUAL:-无法计算}）"
            echo "     拒绝解压执行。请确认 EXPECTED_SHA256 来自可信渠道，或清空该变量后重试。"
            exit 1
        fi
        echo "   ✓ 源码包 sha256 校验通过"
    fi
        break
    fi
    GOT=0
    rm -f "$TARBALL"
    echo "   （这个源的包不合格，自动换下一个…）"
done
if [ "$GOT" != "1" ]; then
    echo "   ✗ 所有下载源都失败了"
    echo "     出路：电脑浏览器打开 $SRC_URL 下载，"
    echo "     拷到路由器 /tmp/ 并命名 hw.tar.gz，然后手动执行："
    echo "       tar xzf /tmp/hw.tar.gz -C /tmp && sh /tmp/homeward-main/scripts/install-istoreos.sh"
    exit 1
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
