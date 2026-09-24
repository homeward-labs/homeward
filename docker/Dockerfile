FROM python:3.12-slim

LABEL maintainer="Homeward"
LABEL description="家庭 IoT 隐私守护"

WORKDIR /app

# 系统依赖
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    iptables \
    nftables \
    dnsmasq \
    && rm -rf /var/lib/apt/lists/*

# Python 依赖
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
