# 双容器形态用的 dnsmasq 镜像（仅用于宿主机本身没有 dnsmasq 的环境：裸 Linux / 云主机 / 某些 NAS）
# iStoreOS / OpenWrt / 飞牛 等已有系统 dnsmasq 的环境不要用它，请改用单容器 compose 直接挂系统日志。
#
# 基于 alpine 自建，不依赖任何第三方 dnsmasq 镜像 —— 体积最小、供应链可信、多架构（匹配宿主机）。
# 配置通过 docker-compose.full.yml 把 ./dnsmasq/dnsmasq.homeward.conf 挂到 /etc/dnsmasq.conf 注入。

FROM alpine:3.20

RUN apk add --no-cache dnsmasq

# 日志落 /var/log/dnsmasq.log，由 compose 的命名卷共享给 homeward 容器只读。
# -k 前台运行；--log-queries=extra 记每一条查询（含客户端 IP，家卫唯一设备识别源）；
# --log-facility 指定文件而非 syslog（OpenWrt 习惯走 syslog，这里是给裸机用的文件形态）。
CMD ["dnsmasq", "-k", "--log-queries=extra", "--log-facility=/var/log/dnsmasq.log"]
