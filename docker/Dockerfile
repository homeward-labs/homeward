FROM python:3.12-slim

LABEL maintainer="Homeward"
LABEL description="家庭联网设备隐私守护（社区版：只看见，不拦截）"

WORKDIR /app

# 社区版不装 tcpdump / libpcap / iptables / nftables：
#   抓包与防火墙下发都属于标准版（闭源付费），社区版镜像不该预装这些工具 ——
#   既缩小镜像体积、降低攻击面，也避免给人「社区版也能拦」的错误暗示。
# 社区版只读 dnsmasq 查询日志，Python 标准库足够，无系统级依赖。

# Python 依赖（当前零第三方依赖，见 requirements.txt 说明；文件必须存在）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制代码
COPY src/ ./src/

# 默认配置
ENV HOST=0.0.0.0
ENV PORT=9595
ENV LOG_LEVEL=info

# 暴露 Web UI 端口
EXPOSE 9595

# 启动命令（根据实际适配器选择）
CMD ["python", "-m", "src.core.main"]
