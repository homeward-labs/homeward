# 部署形态与安装方式

> **一句话立场**：家卫是**一个轻量自建服务，不是一个绑定平台的 App**。
> 它跑在你自己掌控的那台设备上 —— 软路由、NAS、旧电脑、云主机、任意 Linux 都行。
> Docker 是其中一种安装方式，飞牛是其中一个目标平台，**两者都不是定义**。

---

## 一、为什么会有"形态"这个概念

家卫的能力**不是固定的**，它由两件事共同决定：

1. **这台设备在网络里的位置**（流量是否必经它）→ 决定能"看见"多少；
2. **装的是社区版还是标准版** → 决定能不能"拦下"。

第 2 点（社区版 / 标准版能力差异）见私有《版本与能力归属》文档（不随本仓库发布）。**本文件只讲第 1 点。**

一个诚实的工具必须承认：装在单网口 NAS 的 Docker 里，和装在软路由主路由位上，看到的东西根本不是一回事。家卫不掩饰这个差异 —— 它把差异写成 `Capabilities`，并在首页直接列出当前形态的盲区（见 [capability.py](../src/adapters/capability.py) 的「首页明示盲区」）。

---

## 二、三个正交的维度

别把这三件事混为一谈：

| 维度 | 回答什么 | 例子 |
|---|---|---|
| **接入方式** | 流量怎么到它手上 | 网关位 / 网桥串联 / 单臂旁听 / 只读日志 |
| **运行平台** | 跑在什么硬件与系统上 | 软路由 / NAS / x86 主机 / 云主机 |
| **安装方式** | 怎么把它装上去 | Docker Compose / 原生 systemd / 固件包（`.fpk`、`.ipk`） |

同一台设备可以换安装方式，同一种安装方式可以落在不同平台上。**真正决定能力上限的是「接入方式」。**

---

## 二-B、目录组织原则与平台速查表

### 1) 为什么**不**按品牌建目录（飞牛/群晖/威联通/iStoreOS/爱快/RouterOS/Ubuntu 各一个）

家卫的部署差异本质只有「**数据源类型**」，不是品牌。所有平台收敛为 3 类接入形态：

1. 系统**已有 dnsmasq**，日志在 `/var/log/dnsmasq.log`（Debian 系 NAS / 主机）
2. 系统**已有 dnsmasq**，日志在 `/tmp/dnsmasq.log`（OpenWrt / iStoreOS）
3. 系统**没有 dnsmasq**（裸 Linux / 云主机）→ 用自带 dnsmasq 容器的双容器形态

品牌差异只是「**日志路径 / 如何把日志开到文件**」，沉淀到本文档各平台章节（§五-B 飞牛、§五-C iStoreOS），**不另开目录**。这是 GitHub 上 Docker 项目的正规做法：

- 单一 `docker/` 目录，按「接入形态」命名多个 compose 变体（`docker-compose.yaml` / `docker-compose.istoreos.yml` / `docker-compose.full.yml`）；
- 某形态专属的构建资源就近放进子目录（如 `docker/dnsmasq/` 放双容器用的 dnsmasq 镜像与配置）；
- 品牌/固件的开启步骤写在文档章节，而非代码目录。

> 另：iStoreOS 商店 ipk、飞牛 `.fpk`、群晖 `.spk` 这类**原生商店包**属于独立维度（打包形态，非 Docker 形态），应放 `packages/` 或独立仓库，不混进 `docker/`。

### 2) 平台 → 形态速查表

| 平台 | dnsmasq 日志落点 | 选用 compose | 文档章节 |
|---|---|---|---|
| 飞牛 FNOS | 自装 dnsmasq，默认 `/var/log/dnsmasq.log` | `docker-compose.yaml` | §五-B |
| 群晖 Synology | `/var/log/dnsmasq.log`（需先装 dnsmasq） | `docker-compose.yaml` | （同 Debian 系） |
| 威联通 QNAP | 视容器 / DNS 配置 | `docker-compose.yaml` 或 `.full.yml` | — |
| iStoreOS / OpenWrt | `/tmp/dnsmasq.log` | `docker-compose.istoreos.yml` | §五-C |
| 爱快 iKuai | 无 dnsmasq，走自身 DNS + syslog 导出 | 社区版暂不支持（待标准版 syslog 接入） | — |
| RouterOS (MikroTik) | 无 dnsmasq，用 container + 自身 DNS | 社区版暂不支持 | — |
| 裸 Linux / 云主机 | 无 | `docker-compose.full.yml` | §2.5 |

> 社区版的核心约束：**只认 dnsmasq 查询日志这一种数据源**。凡系统不以 dnsmasq 为解析点（爱快 / RouterOS / 某些 NAS）或无 dnsmasq 日志可挂的，社区版先不覆盖；这些走标准版的 syslog / 流量接入。

## 三、接入方式对照表（决定能看到多少）

| 接入方式 | 典型拓扑 | 能看见 | 看不见（盲区） | 适用设备 |
|---|---|---|---|---|
| **网关位**（推荐） | 家卫就是主路由，或作为旁路由承载全部出网流量 | 全量：DNS 查询 + 连接五元组 + 流量大小与时序 | 加密 DNS（DoH/DoT）内容、TLS 内层 payload | 软路由（**iStoreOS** / OpenWrt）、x86 主机 |
| **网桥串联** | 双网口设备串在光猫与内网之间 | 全量（libpcap 旁路抓包） | 同上 | 双网口 NAS、双网口 x86、旧电脑加网卡 |
| **单臂旁听** | 单网口设备挂在局域网里，只收 DNS 日志 / DNS 镜像 | **仅 DNS 层**：哪个设备问了哪个域名 | 不走本地 DNS 的连接、硬编码 DoH 的设备、**流量大小与时序全盲** | 单网口 NAS（飞牛 / 群晖 / 威联通）、普通 Linux 主机 |
| **只读日志** | 喂现有日志文件，不接入网络 | 取决于喂进去什么 | 大 | 开发机、快速试用 |

**选型建议**：

- 想"看全" → 上网关位（主力：**iStoreOS** 软路由）或网桥串联。iStoreOS 自带商店+Docker，一台 x86 小主机刷 iStoreOS 是最省事的答案；今天即可用 Docker 形态坐网关位拿全量视野。
- 只想"先看看谁在给谁打电话" → 单臂 Docker 起步，几分钟就能跑，**但必须接受它只有 DNS 层视野**。
- 单臂形态下家卫会明确告诉你"我只看到了 DNS 层"，不会假装看见了流量。

---

## 三-B、代理软件（Clash / Mihomo 等）与家卫的可见性矩阵

家卫看不看得见，**只取决于它是否处在 DNS / 网关 / 旁路抓包路径上**，与代理用哪种模式无关。下面按代理常见的 4 种模式逐一说明（以 Clash / Mihomo 为例）。

| 代理模式 | 客户端是否发出真实域名查询 | 家卫能否看到（家卫在 DNS 解析路径 / 网关位） | 家卫能否看到（代理独立设备、家卫不在路径上） |
|---|---|---|---|
| ① fake-ip | 是（明文真实域名；被伪造的是「回答里的 IP」`198.18.0.0/16`，**不是问题里的域名**） | ✅ DNS 层可见（Tier1） | ❌ 全盲 |
| ② redir-host（真解析） | 是 | ✅ DNS 层可见，且最干净（代理不伪造、直接外发真实查询） | ❌ 全盲 |
| ③ TUN（虚拟网卡接管） | 是（仍发真实查询） | ⚠️ 仅当家卫在 TUN 出口的网关 / 旁路抓包路径上可见；否则 ❌ | ❌ 全盲（查询被 TUN 在**内核层** `tun.dns-hijack: any:53` 劫持进代理自身 DNS 引擎，不经过系统 dnsmasq、也不产生 dnsmasq 日志） |
| ④ 系统代理 / 应用层 HTTP+SOCKS | 否（客户端不本地解析，由远端代理解析） | ❌ DNS 层全盲 | ❌ 全盲 |

**关键结论（部署定位铁律）**：

- 家卫必须处在 DNS / 网关 / 旁路抓包路径上才看得见。代理的 fake-ip / TUN 只是改变了「查询在哪被解析」，不改变这条铁律。
- 模式 ① ② 下，只要家卫是 DNS 解析器（网关位 / 旁路由 / DNS 转发器），客户端发出的真实域名查询就会落到 dnsmasq 查询日志里，**家卫照常看见**。代理作为「独立设备」、但客户端 DNS 仍指向家卫时同理。
- 模式 ③ ④ 下，查询根本不经过家卫一侧的 dnsmasq：TUN 在内核层劫持、系统代理在远端解析。此时 DNS 层（Tier1）必然全盲，必须靠 **标准版的 pcap 采集器（SNI / SOCKS5 明文域名 / HTTP CONNECT host，抓包层兜底）** 才能恢复可见性——该能力属**标准版（闭源付费）**，社区版仅留接口、不含实现。

### dns_source：无代理 / 代理两套数据源可切换

社区版提供 `dns_source` 开关，让「换数据源、架构不变」成为配置项：

| `dns_source` | 读什么 | 适用 |
|---|---|---|
| `dnsmasq`（默认） | dnsmasq 专属查询日志文件 | 无代理；或代理 ①/② 模式下家卫即 DNS 解析器 |
| `syslog` | 系统 syslog 里的 dnsmasq 查询行 | 代理接管 DNS、但家卫仍在解析路径上；或 OpenWrt / iStoreOS 把查询发到系统 syslog（不写专属文件） |

两种都是 Tier1、共用同一套解析（`parse_dnsmasq_line`），切换只换「从哪读」，不碰架构。conntrack（Tier2）在两种模式下都照常启动。

> ⚠️ `dns_source=syslog` 解决的是「数据源换了个地方」，**解决不了** TUN / 系统代理的 DNS 层全盲——那需要家卫站在抓包路径上 + 标准版 pcap。别把「切到 syslog」当成「开了代理也能全看见」的万金油。

配置方式见 §六-B（环境变量 `DNS_SOURCE` / `SYSLOG_PATH`）与启动参数 `--dns-source` / `--syslog-path`。

---

## 四、安装方式对照表

| 安装方式 | 适用平台 | 状态 | 说明 |
|---|---|---|---|
| **预构建镜像（GHCR · 多架构）** | amd64 / arm64 / armv7 的软路由与 NAS | 🔜 **工作流已就位，首个 `v*` tag 发布后可用** | `ghcr.io/homeward-labs/homeward`，一次构建出 `linux/amd64` + `linux/arm64` + `linux/arm/v7`。**不用本地 build**，低配软路由 / ARM NAS 尤其省事；发布流程见 `.github/workflows/publish.yml`。在此之前请用下面的源码 build |
| **Docker Compose（本地 build）** | 任何能跑 Docker 的 Linux / NAS | ✅ 骨架可用 | `docker compose up -d`，端口 `9595`。首个 tag 发布前，这是最通用的路径 |
| **源码直跑** | 开发机、Linux 主机 | ✅ 可用（开发用） | `python -m src.core.main`，零第三方依赖，用于开发与验证 |
| **原生 Linux（systemd）** | Debian / Ubuntu / 任意 Linux 主机、旧电脑、物理机 | ⬜ **计划中** | 目标形态之一：一台旧电脑或迷你主机常驻，不走容器 |
| **iStoreOS 包（主力）** | 软路由 | 🔜 **最高优先级** | 最有价值的形态：坐网关位 = 全量视野（DNS + 五元组 + 流量大小/时序）。iStoreOS 自带商店与 Docker，今天即可用 Docker 形态跑，原生商店一键包为最高优先级待办 |
| **飞牛 OS `.fpk`** | 飞牛 NAS 应用中心 | ⬜ **计划中，未实现** | `fnpk/` 仅含打包配置草稿，未提交审核、未上架。但**飞牛的 Docker 形态已可用**（见下节） |
| **群晖 / 威联通 / 其他 NAS** | 走容器 | ⬜ **计划中** | 优先复用 Docker 形态，暂不做原生套件 |

> ⚠️ 上表中标注「计划中」的原生套件（飞牛 `.fpk`、群晖/威联通套件、系统原生包）**当前都没有可用产物**。但 **iStoreOS / 任意能跑 Docker 的软路由，今天即可用 Docker 形态坐网关位拿全量视野**（见 §五-C）；飞牛也能直接跑 Docker（见 §五-B）。在原生包落地前，请使用 Docker Compose 或源码直跑。
> 不要用 README 里任何一句话推断出"飞牛一键装"已经可用 —— 它还没有。
> 但飞牛能直接跑 Docker，所以**社区版的 Docker Compose 部署路径在飞牛上已可用**（见 §五-B）。

---

## 五、快速开始

### 方式 A：直接用预构建镜像（最省事，Release 发布后可用）

不用 clone、不用本地 build —— 对算力有限的软路由 / ARM NAS 尤其合适。

```bash
mkdir -p ~/homeward-data
docker run -d --name homeward --restart unless-stopped \
  -p 9595:9595 \
  -v "$HOME/homeward-data:/app/data" \
  -v /var/log/dnsmasq.log:/var/log/dnsmasq.log:ro \
  -e HOMEWARD_DATA_DIR=/app/data/homeward \
  ghcr.io/homeward-labs/homeward:latest
# 打开 http://<设备IP>:9595
```

> `-v` 第二段是 DNS 日志：Debian 系 / 飞牛 / 群晖一般 `/var/log/dnsmasq.log`，
> **iStoreOS / OpenWrt 改成 `/tmp/dnsmasq.log`**。
> `~/homeward-data` 必须持久化：许可令牌与设备标识存在里面，丢了会导致已激活的许可
> 因指纹漂移显示「设备不符」。
> 架构会自动匹配（amd64 / arm64 / armv7 三档）。

### 方式 B：从源码构建（当前最通用）

```bash
git clone https://github.com/homeward-labs/homeward
cd homeward
docker compose up -d
# 打开 http://<设备IP>:9595
```

开发模式（不进容器，直接看日志输出）：

```bash
python -m src.core.main
```

> 单臂 Docker 形态下只能看到 DNS 层面（设备往哪个域名打电话）；
> 要看全量流量，请部署为网关位（软路由主路由 / 旁路由）或双网口网桥。

不想手敲命令？直接用一键脚本（见 §五-B-5），自动克隆/更新 + 启动 + 探测 IP 并打印访问地址，全程不用手填 IP。

---

## 五-B、飞牛 OS（FnOS）部署与冒烟验收

飞牛是 Debian 系的 NAS，自带 Docker，**社区版可直接以 Docker Compose 跑起来**。
在飞牛上的形态是「单臂 Docker / 只读日志」——即**只看到 DNS 层**（哪台设备问了哪个域名），
看不到流量大小与时序。这是诚实的视野上限，不是 bug。

> ### 稳妥优先原则（务必先读）
> 家卫的价值**绝不建立在任何"改动家庭网络"的操作上**。下面所有方案都**不碰光猫、不动路由器、
> 不改动任何其它设备的网络设置**。若你家里跑着生产环境（NAS、监控、智能家居、远程办公、HomeLab），
> 请只走 **A 档（只看飞牛本机）**——它连飞牛自身的改动都收敛到"可一键还原"，绝不会让全家断网。
> B / C 档只能是你**自己自愿、明知风险**时的可选操作，本工具默认不推荐，文档都会明确警告。

### 1) 部署步骤（零配置，开箱即用）

```bash
cd homeward
docker compose -f docker/docker-compose.yaml up -d --build
# 浏览器开 http://<飞牛IP>:9595 即可，无需任何口令
```

就这么两步把容器跑起来。默认即「无鉴权」模式：浏览器直接打开就能进界面，
不用填 token、不用翻日志。**仅在你要把它暴露到不可信网络时，才需要设口令**（见下）。

> 注意：容器刚起时面板可能为空——因为社区版数据来自 DNS 查询日志，而飞牛默认还没产生它。
> 接数据源请严格按 §3 的 **A 档**走：只让家卫看**飞牛自己**，不碰任何其它设备。

compose 已按「常年常驻在低配 NAS」做了加固：`read_only` 根文件系统、`cap_drop ALL`、
内存上限 128M / 0.5 核、健康检查探 `/api/health`。改动镜像内容或提权都做不到。

### 2) 进阶：暴露公网时启用口令鉴权（可选）

```bash
cp docker/.env.example docker/.env
# 编辑 docker/.env，把 HOMEWARD_AUTH_TOKEN= 填上：openssl rand -hex 16
docker compose -f docker/docker-compose.yaml up -d
# 之后浏览器打开会要求输入该口令
```

### 3) 让面板有数据：三档方案（从稳妥到激进）

社区版唯一数据源是 **DNS 查询日志**。要让面板有东西，飞牛必须把 DNS 查询记到
`/var/log/dnsmasq.log`（容器只读挂它）。下面三档按"风险从低到高"排列，**默认推荐 A 档**。

#### A 档 · 零侵入：只看飞牛本机（默认推荐，今天就能用，不碰任何其它设备）

目标：只让家卫看到**飞牛这台 NAS 自己**的外联域名。完全不碰光猫、路由器、手机、TV、摄像头。

为什么稳：飞牛是你自己掌控的设备；这里唯一的改动是飞牛**本机**的 DNS 解析回路，可一键还原，
崩了你自己登后台就能救——**绝不会连累家里的生产环境或其它设备**。

**步骤**：
```bash
# ① 飞牛装 dnsmasq（Debian 系）
apt-get install -y dnsmasq

# ② 配置：仅监听本机回环 + 转发真实解析 + 记日志
cat > /etc/dnsmasq.d/homeward.conf <<'EOF'
listen-address=127.0.0.1          # 只听本机，绝不对外服务（不影响局域网任何设备）
server=223.5.5.5                  # 上游真实解析（阿里公共 DNS，保证飞牛上网正常）
log-queries=extra
log-facility=/var/log/dnsmasq.log
EOF

# ③ 关键：先建日志文件，避免 Docker 把挂载点建成空目录占住
touch /var/log/dnsmasq.log
systemctl restart dnsmasq

# ④ 让飞牛自己的解析走本机 dnsmasq（带公共 DNS 兜底，dnsmasq 挂了也不至于本机断网）
cat > /etc/resolv.conf <<'EOF'
nameserver 127.0.0.1
nameserver 119.29.29.29
EOF

# ⑤ 重启容器，挂上真实日志
cd ~/homeward/homeward
docker compose -f docker/docker-compose.yaml up -d --build
```

起好后，飞牛自身发起的 DNS 查询（系统更新、App 商店、下载 / 影视 / 相册同步向厂商云回传等）
都会出现在面板里。**NAS 是家庭数据中枢，它本身的外联画像恰好是隐私审计最有价值的部分**——
你看清了它，工具就值回票价。界面「盲区」视图会显示 DNS 采集器变「可用」。

> 还原（如要回退）：把 `/etc/resolv.conf` 改回原来的（通常是光猫给的）、`systemctl stop dnsmasq`、
> 删 `/etc/dnsmasq.d/homeward.conf`，飞牛立刻恢复用原来的 DNS，全网无感。

#### B 档 · 自愿观测单台设备（可选，低风险）

你**自己**愿意把某台主力设备（比如手机或电脑）的 DNS 手动指到飞牛 IP —— **只改那一台**，
不动全家、不动路由器。飞牛需把 `listen-address` 从 `127.0.0.1` 改为 `0.0.0.0`（监听所有网卡），
并在该设备的 Wi-Fi / 以太网设置里把 DNS 填成飞牛局域网 IP 即可。代价：摄像头、智能音箱等
没法改 DNS 的 IoT 小设备抓不到，但那些本无多少隐私价值。

#### C 档 · 全屋覆盖（高风险，生产环境用户请勿使用，仅作知识列出）

- **改光猫 LAN / DHCP 下发的 DNS = 飞牛 IP**：会让飞牛成为**全屋 DNS 单点**——飞牛 / 容器一挂，全家断网。
  且电信光猫常锁 DNS、1 拖 N 分光拓扑桥接会废分猫，折腾大、收益小。
- **桥接光猫 + 自备路由器**：需把光猫改桥接，会使依赖光猫做路由的分猫失效，全家覆盖重组。

这两类是为"让家卫坐网关位、覆盖全屋"准备的，属于**标准版全量抓包（流量大小 / 时序）**的前置工程，
**社区版纯 DNS 层根本不需要为此大动干戈**。家里有生产环境，请直接放弃 C 档，用 A 档即可。

### 4) 可选验证（平时不用，想确认没问题再做）

```bash
docker compose -f docker/docker-compose.yaml config >/dev/null && echo "compose OK"
python scripts/smoke.py --base http://<飞牛IP>:9595          # 自动适配：无鉴权直探 / 有鉴权提示传 token
docker stats homeward                                       # 看真实内存占用（应 < 100MB）
```

冒烟脚本（`scripts/smoke.py`，纯标准库、跨平台）会输出：服务是否存活、各只读接口是否可读、
以及 `采集激活` 字段（DNS / conntrack 哪个在干活、哪个记为盲区）。

> 本仓库的 Windows 开发机**装不了 Docker**，故镜像构建与 `docker stats` 实测必须在飞牛执行；
> 但冒烟脚本本身已在本地用真实服务跑通（RC=0），逻辑正确性已验证。

### 5) 一键安装脚本（最省事，推荐）

仓库自带 `scripts/install.sh`，在飞牛终端跑一条命令即可完成「克隆/更新代码 → 构建启动 → 自动探测飞牛 IP → 打印访问地址」，**全程不用手填 IP、不用翻日志**：

```bash
git clone https://github.com/homeward-labs/homeward
cd homeward
bash scripts/install.sh
# 脚本结束会直接打印类似：浏览器打开: http://<设备IP>:9595
```

脚本行为：
- 当前已在 `homeward/` 仓库内 → 自动 `git pull` 更新到最新（含零配置版）；
- 不在仓库内 → 自动从 GitHub 克隆；
- 启动后自动 `hostname -I` 探测飞牛局域网 IP 并打印，省去手动查 IP；
- 默认零配置无鉴权，浏览器直开；若你在 `docker/.env` 设了 `HOMEWARD_AUTH_TOKEN`，界面会要求口令，
  用你设的值登录即可。

---

### 6) 飞牛 Docker 拉不到基础镜像（401 / docker.fnnas.com）

若 `docker compose up --build` 报 `failed to resolve source metadata for docker.io/library/python:3.12-slim ... 401 Unauthorized`（请求被打到 `docker.fnnas.com`），说明飞牛 Docker 的镜像源不能代理 Docker Hub 官方镜像。解决：给飞牛 Docker 配置一个能访问 Docker Hub 的镜像加速器（中科大 / DaoCloud 等），再重启 docker：

```bash
cat > /etc/docker/daemon.json <<'EOF'
{ "registry-mirrors": ["https://docker.m.daocloud.io", "https://hub-mirror.c.163.com"] }
EOF
systemctl restart docker
```

重启后回到仓库目录重新 `bash scripts/install.sh` 即可。`scripts/install.sh` 在构建失败且日志含 401/Unauthorized 时会自动打印上面这段指引。

---

## 五-C、iStoreOS 软路由（主力推荐形态）

> **定位**：软路由是家卫"看全"的最省事答案；而在软路由系统里，**iStoreOS 是本项目的主力推荐平台** ——
> 它基于 OpenWrt、自带应用商店与 Docker 管理器。一台 x86 小主机（或友善/倍控等软路由硬件）刷上 iStoreOS，
> 既能今天就用 Docker 形态把家卫跑成**网关位**（全量视野），又是最容易做成"商店一键安装"的形态。
> 坐网关位时能力上限等同 §三「网关位」行：DNS 查询 + 连接五元组 + 流量大小与时序，全量可见。

### 1) 两种拓扑（按需二选一）

- **主路由（全屋覆盖）**：光猫改桥接，iStoreOS 拨号 / 做主路由，全家出网必经它。视野最全，
  但要动光猫桥接 —— **家里有生产环境、不想动网络的，请勿用此档**（同 §五-B 的稳妥原则）。
- **旁路由（推荐给大多数人）**：iStoreOS 作为局域网里独立的一台设备，自己开一个 WiFi，或仅作 DNS + 网关服务器；
  **让 IoT、摄像头、智能音箱等"其他设备"的网关 / DNS 指到 iStoreOS**，而你自己的手机、电脑继续连光猫 WiFi。
  这样全家重要设备不受影响，只有"其他设备"的流量经家卫 —— 既拿到这些设备最值得看的画像，又不碰全家网络。
  （这是本项目推荐的家庭默认姿势：重要设备零风险，IoT 设备高可见。）

### 2) 今天就能用：iStoreOS 上的 Docker 形态（网关位）

iStoreOS 自带 Docker 管理器，部署步骤与飞牛一致，只是你是网关位而非单臂：

```bash
# 在 iStoreOS 的终端里（iStoreOS 默认未安装 git，用源码压缩包方式，不依赖 git）
cd /tmp
U=https://github.com/homeward-labs/homeward/archive/refs/heads/main.tar.gz
# 直连带进度条；GitHub 直连失败自动换镜像加速（ghfast.top 可按当地可用性替换）
curl -fL --connect-timeout 15 --progress-bar -o homeward.tar.gz "$U" \
  || curl -fL --connect-timeout 15 --progress-bar -o homeward.tar.gz "https://ghfast.top/$U" \
  || wget -O homeward.tar.gz "https://ghfast.top/$U"
tar xzf homeward.tar.gz
cd homeward-main
docker compose -f docker/docker-compose.yaml up -d --build
# 浏览器开 http://<iStoreOS IP>:9595
```

让面板有全量数据：iStoreOS 已是网关位，重点是把它经手的流量记给家卫 ——
dnsmasq 开 `log-queries=extra` + `log-facility=/var/log/dnsmasq.log`（容器只读挂它）拿 DNS 层；
若要做网关位抓包（连接五元组 / 字节数），用 nftables / NFLOG 适配器（见 §三 网关位行）。
社区版只"看见"，不拦截；拦截是标准版能力。

### 2.5) 一条命令两种形态（现在就能用）

家卫在 iStoreOS 上的"一条命令"分两种，**区别在于宿主机有没有现成的 dnsmasq**：

| 形态 | 适用 | 命令 | 说明 |
|---|---|---|---|
| **单容器·iStoreOS 专属** | iStoreOS / OpenWrt（系统已有 dnsmasq，占着 53 端口） | `docker compose -f docker/docker-compose.istoreos.yml up -d` | 只起家卫，只读挂载系统 `/tmp/dnsmasq.log`。**iStoreOS 用这个** |
| **双容器·通用** | 裸 Linux / 云主机 / 某些 NAS（宿主机没有 dnsmasq） | `docker compose -f docker/docker-compose.full.yml up -d --build` | 同一条命令把 `dnsmasq` + `homeward` 两个容器一起拉起并配好，日志经命名卷共享给家卫只读 |

> ⚠️ **为什么 iStoreOS 不能"把 dnsmasq 也加进容器"**：iStoreOS 本身就是路由器，系统 dnsmasq 已经占着 53 端口。
> 再起一个 dnsmasq 容器必抢端口冲突。所以 iStoreOS 用单容器读系统日志；双容器版只给"宿主机没 dnsmasq"的场景。

**iStoreOS 前置（一次性，开启系统 dnsmasq 日志到文件）**：
- 图形：iStoreOS 管理页 → 网络 → DHCP/DNS → 常规设置 →「日志设施」填 `/tmp/dnsmasq.log` → 保存应用；
- 或终端：`uci set dhcp.@dnsmasq[0].logfacility='/tmp/dnsmasq.log' && uci commit dhcp && /etc/init.d/dnsmasq restart`；
- 验证：`cat /tmp/dnsmasq.log` 能看到 `query[A] ... from <IP>` 行即成功。
- 若你的 iStoreOS 把日志写到别处，把 `docker-compose.istoreos.yml` 里 volumes 的源路径与 `DNS_LOG_PATH` 一起改成实际位置。
  （即便不改，家卫代码也已把 `/tmp/dnsmasq.log` 纳入默认探测路径，自动兜底。）

**双容器 dnsmasq 的安全提醒**：它把 53 端口暴露到宿主机，等于这台机器成了局域网 DNS 服务器。
仅限可信内网；暴露公网务必用防火墙限制来源，避免成为开放解析器被滥用。

### 3) 路线：iStoreOS 商店一键包（最高优先级）

相比 NAS 原生包，iStoreOS 商店包是**最高优先级**的待办：做成商店里一键安装的应用，
免去命令行、自动处理网关位接入与日志外发。在它落地前，请用上面的 Docker 形态。

---

## 六、资源占用

家卫的设计约束是「能常年常驻在最低配的那台设备上」：

- 内存目标 < 100 MB（社区版纯 Python、无第三方依赖、无数据库）；
- CPU 近乎为零（日志/连接表增量读取，不做 DPI、不解 TLS）；
- 磁盘：知识库约数百 KB，日志按轮转保留。

这也是它选择「DNS 为主 + 元数据判断」而非全流量 DPI 的根本原因 —— 见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

---

## 六-B、运行期环境变量与安全部署红线

### 1) 环境变量一览

| 变量 | 作用 | 默认 |
|---|---|---|
| `HOST` / `PORT` | 监听地址 / 端口 | `127.0.0.1` / `9595` |
| `DNS_LOG_PATH` | dnsmasq 查询日志路径（不给则按内置路径探测） | 探测 |
| `DNS_SOURCE` | Tier1 DNS 数据源：`dnsmasq`（默认）/ `syslog`（见 §三-B，代理/系统 syslog 场景） | `dnsmasq` |
| `SYSLOG_PATH` | `DNS_SOURCE=syslog` 时指定 syslog 文件路径（不给则按内置路径探测） | 探测 |
| `HOMEWARD_AUTH_TOKEN` | Web UI 登录口令；**设了才启用鉴权** | 空（无鉴权） |
| `HOMEWARD_DATA_DIR` | 许可令牌 / CRL / 设备标识的落盘目录 | `~/.homeward` |
| `HOMEWARD_LICENSE_PUBLIC_KEY_B64` | **构建期注入正式许可公钥**（32 字节 Ed25519 Raw 的 base64） | 空（退回开发公钥） |
| `HOMEWARD_REQUIRE_PROD_KEY=1` | 发布门禁：仍在使用开发公钥时**拒绝启动** | 关闭（仅告警） |

### 2) 三条安全红线

**① 绑非回环地址必须设口令或加防火墙。**
`HOST=0.0.0.0`（容器内必需）时，同一局域网任何人都能打开面板，看到家里的
设备 MAC / IP / 外联域名，还能调用 `/api/import`、`/api/activate` 写入数据。
服务启动时会自己告警，但告警不能替代处置：要么设 `HOMEWARD_AUTH_TOKEN`，
要么用防火墙把 9595 端口限制在可信来源 IP。

**② 对外发布的构件必须注入正式许可公钥。**
仓库内嵌的是**开发公钥**，配套开发私钥存在本地联调环境 —— 用它发布等于任何人
都能签出「验签通过」的许可。构建时通过 `HOMEWARD_LICENSE_PUBLIC_KEY_B64`
注入正式公钥，并在 CI 里设 `HOMEWARD_REQUIRE_PROD_KEY=1` 让漏注入直接构建失败。

**③ `HOMEWARD_DATA_DIR` 要挂到持久卷。**
该目录存放已激活的许可令牌与设备稳定标识。容器重建时若目录不持久，
`/etc/machine-id` 与设备标识都会重新生成 → 指纹漂移 → 已激活的许可显示
「设备不符」，用户被迫重新激活。Docker 部署请把它挂到具名卷 / 宿主机目录。

---

## 七、相关文档

- 版本与能力归属：见私有《版本与能力归属》文档（不随本仓库发布）
- 采集与执行的正交抽象：[README.md](./README.md) 架构章节 / [ARCHITECTURE.md](./ARCHITECTURE.md)
- 阻断与撤销语义：见私有《阻断与撤销》文档（不随本仓库发布）
