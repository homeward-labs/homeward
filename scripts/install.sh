#!/usr/bin/env bash
#
# 家卫 Homeward —— 一键安装脚本（飞牛 / 任意 Debian 系 Linux + Docker 环境）
#
# 用法（在飞牛终端执行）：
#   bash scripts/install.sh
#
# 脚本自动完成：
#   1. 准备代码 —— 当前已在仓库内则 git pull；否则从 GitHub 克隆到 ./homeward
#   2. 构建并后台启动容器（docker compose up -d --build）
#   3. 等待容器健康检查通过
#   4. 自动探测飞牛局域网 IP（无需手填）
#   5. 打印浏览器访问地址
#
# 说明：本脚本采用「零配置」部署，默认无鉴权、浏览器直开。
#       仅当你在 docker/.env 设置了 HOMEWARD_AUTH_TOKEN 时才会启用口令，
#       那种情况下脚本会自动从日志抓取随机口令并打印，无需手动翻日志。
#
set -euo pipefail

REPO_URL="https://github.com/homeward-labs/homeward"
COMPOSE_FILE="docker/docker-compose.yaml"
CONTAINER="homeward"
PORT=9595

info() { echo -e "\033[32m[家卫]\033[0m $*"; }
warn() { echo -e "\033[33m[家卫]\033[0m $*"; }
die()  { echo -e "\033[31m[家卫 ERROR]\033[0m $*" >&2; exit 1; }

# 0) 依赖检查
command -v git    >/dev/null 2>&1 || die "未找到 git，请先安装"
command -v docker >/dev/null 2>&1 || die "未找到 docker，请先在飞牛/系统中安装 Docker"

# 1) 准备代码
if [ -f "$COMPOSE_FILE" ]; then
  info "已在仓库目录，拉取最新代码"
  git pull --ff-only 2>/dev/null || warn "git pull 失败（可能本地有未提交改动），继续使用当前代码"
elif [ -d homeward/.git ]; then
  info "发现 homeward/，拉取最新代码"
  git -C homeward pull --ff-only 2>/dev/null || true
  cd homeward
else
  info "从 GitHub 克隆 $REPO_URL"
  git clone "$REPO_URL" homeward
  cd homeward
fi

# 2) 构建并启动容器
info "构建并启动容器（首次会拉取镜像，请稍候）"
if docker compose version >/dev/null 2>&1; then
  docker compose -f "$COMPOSE_FILE" up -d --build
else
  docker-compose -f "$COMPOSE_FILE" up -d --build
fi

# 3) 等待容器健康
info "等待容器就绪"
for i in $(seq 1 30); do
  st=$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "starting")
  [ "$st" = "healthy" ] && break
  sleep 2
done

# 4) 自动探测飞牛局域网 IP（无需手动填写）
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$IP" ] || [ "$IP" = "127.0.0.1" ]; then
  IP=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[\d.]+' | grep -v '^127\.' | head -1)
fi

# 5) 完成
echo
info "===================================================="
info " 家卫 Homeward 已启动"
info " 浏览器打开:  http://${IP:-localhost}:${PORT}"
info "===================================================="

# 6) 若部署启用了口令鉴权，自动抓取随机口令提示（零配置版不会走到这里）
if docker logs "$CONTAINER" 2>/dev/null | grep -q "登录口令"; then
  TOKEN=$(docker logs "$CONTAINER" 2>/dev/null | grep "登录口令" | tail -1 | sed -E 's/.*[：:][[:space:]]*(.*)/\1/')
  warn "当前部署启用了口令鉴权，登录口令为: $TOKEN"
fi
