#!/bin/sh
# 家卫（Homeward）· iStoreOS 安装入口
#
# 真正的分步安装逻辑在 install-istoreos.sh（共 5 步，每步打完 ✓ 再进下一步）。
# 本文件只是个轻量入口：在源码目录里直接跑 `sh scripts/setup-istoreos.sh` 时，
# 自动转交给 install-istoreos.sh，避免两份逻辑分叉。
#
# 注意：一键安装命令里已经从压缩包解压并 `sh scripts/install-istoreos.sh`，
#       所以通常不需要单独跑本文件。

HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
TARGET="$HERE/install-istoreos.sh"

if [ -f "$TARGET" ]; then
    echo "→ 转交分步安装脚本：$TARGET"
    echo ""
    exec sh "$TARGET"
else
    echo "错误：找不到同目录下的 install-istoreos.sh"
    echo "      请确认你在完整的家卫源码目录（homeward-main/scripts/）里运行。"
    exit 1
fi
