# 部署形态与安装方式

> **一句话立场**：家卫是**一个轻量自建服务，不是一个绑定平台的 App**。
> 它跑在你自己掌控的那台设备上 —— 软路由、NAS、旧电脑、云主机、任意 Linux 都行。
> Docker 是其中一种安装方式，飞牛是其中一个目标平台，**两者都不是定义**。

---

## 一、为什么会有"形态"这个概念

家卫的能力**不是固定的**，它由两件事共同决定：

1. **这台设备在网络里的位置**（流量是否必经它）→ 决定能"看见"多少；
2. **装的是社区版还是标准版** → 决定能不能"拦下"。

第 2 点见 [EDITIONS.md](./EDITIONS.md)。**本文件只讲第 1 点。**

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

## 三、接入方式对照表（决定能看到多少）

| 接入方式 | 典型拓扑 | 能看见 | 看不见（盲区） | 适用设备 |
|---|---|---|---|---|
| **网关位**（推荐） | 家卫就是主路由，或作为旁路由承载全部出网流量 | 全量：DNS 查询 + 连接五元组 + 流量大小与时序 | 加密 DNS（DoH/DoT）内容、TLS 内层 payload | 软路由（OpenWrt / iStoreOS）、x86 主机 |
| **网桥串联** | 双网口设备串在光猫与内网之间 | 全量（libpcap 旁路抓包） | 同上 | 双网口 NAS、双网口 x86、旧电脑加网卡 |
| **单臂旁听** | 单网口设备挂在局域网里，只收 DNS 日志 / DNS 镜像 | **仅 DNS 层**：哪个设备问了哪个域名 | 不走本地 DNS 的连接、硬编码 DoH 的设备、**流量大小与时序全盲** | 单网口 NAS（飞牛 / 群晖 / 威联通）、普通 Linux 主机 |
| **只读日志** | 喂现有日志文件，不接入网络 | 取决于喂进去什么 | 大 | 开发机、快速试用 |

**选型建议**：

- 想"看全" → 上网关位或网桥串联。软路由是最省事的答案（一台 x86 小主机 + OpenWrt）。
- 只想"先看看谁在给谁打电话" → 单臂 Docker 起步，几分钟就能跑，**但必须接受它只有 DNS 层视野**。
- 单臂形态下家卫会明确告诉你"我只看到了 DNS 层"，不会假装看见了流量。

---

## 四、安装方式对照表

| 安装方式 | 适用平台 | 状态 | 说明 |
|---|---|---|---|
| **Docker Compose** | 任何能跑 Docker 的 Linux / NAS | ✅ 骨架可用 | `docker compose up -d`，端口 `9595`。当前唯一可实际跑起来的方式 |
| **源码直跑** | 开发机、Linux 主机 | ✅ 可用（开发用） | `python -m src.core.main`，零第三方依赖，用于开发与验证 |
| **原生 Linux（systemd）** | Debian / Ubuntu / 任意 Linux 主机、旧电脑、物理机 | ⬜ **计划中** | 目标形态之一：一台旧电脑或迷你主机常驻，不走容器 |
| **OpenWrt / iStoreOS 包** | 软路由 | ⬜ **计划中** | 最有价值的形态（网关位 = 全量视野），优先级高于 NAS 原生包 |
| **飞牛 OS `.fpk`** | 飞牛 NAS 应用中心 | ⬜ **计划中，未实现** | `fnpk/` 仅含打包配置草稿，未提交审核、未上架。但**飞牛的 Docker 形态已可用**（见下节） |
| **群晖 / 威联通 / 其他 NAS** | 走容器 | ⬜ **计划中** | 优先复用 Docker 形态，暂不做原生套件 |

> ⚠️ 上表中「计划中」的三项**当前都不存在可用产物**。在它们落地前，请使用 Docker Compose 或源码直跑。
> 不要用 README 里任何一句话推断出"飞牛一键装"已经可用 —— 它还没有。
> 但飞牛能直接跑 Docker，所以**社区版的 Docker Compose 部署路径在飞牛上已可用**（见 §五-B）。

---

## 五、快速开始（当前唯一可跑的路径）

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

---

## 五-B、飞牛 OS（FnOS）部署与冒烟验收

飞牛是 Debian 系的 NAS，自带 Docker，**社区版可直接以 Docker Compose 跑起来**。
在飞牛上的形态是「单臂 Docker / 只读日志」——即**只看到 DNS 层**（哪台设备问了哪个域名），
看不到流量大小与时序。这是诚实的视野上限，不是 bug。

### 1) 部署步骤（零配置，开箱即用）

```bash
cd homeward
docker compose -f docker/docker-compose.yaml up -d --build
# 浏览器开 http://<飞牛IP>:9595 即可，无需任何口令
```

就这么两步。默认即「无鉴权」模式：浏览器直接打开就能看家庭设备外联情况，
不用填 token、不用翻日志。**仅在你要把它暴露到不可信网络时，才需要设口令**（见下）。

compose 已按「常年常驻在低配 NAS」做了加固：`read_only` 根文件系统、`cap_drop ALL`、
内存上限 128M / 0.5 核、健康检查探 `/api/health`。改动镜像内容或提权都做不到。

### 2) 进阶：暴露公网时启用口令鉴权（可选）

```bash
cp docker/.env.example docker/.env
# 编辑 docker/.env，把 HOMEWARD_AUTH_TOKEN= 填上：openssl rand -hex 16
docker compose -f docker/docker-compose.yaml up -d
# 之后浏览器打开会要求输入该口令
```

### 3) 飞牛的 DNS 日志在哪

飞牛自带 DNS 不一定走 dnsmasq，所以「面板为空」在刚部署时是**预期**的。让它真正看到数据有两种办法：

- 让飞牛的 DNS 走 dnsmasq，并配置 `log-queries=extra` + `log-facility=/var/log/dnsmasq.log`
  （最常见的家庭 DNS 方案）；compose 已默认只读挂载该路径。
- 或在 `docker/.env` 设 `DNS_LOG_PATH=/实际/路径`，它会自动传给服务的 `--dns-log`。

若暂时没有 DNS 日志，面板为空、并在「盲区」视图提示「DNS 采集器不可用」——属预期，
不是故障。界面「采集激活」一栏会如实显示当前到底哪个采集器在干活。

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

---

## 六、资源占用

家卫的设计约束是「能常年常驻在最低配的那台设备上」：

- 内存目标 < 100 MB（社区版纯 Python、无第三方依赖、无数据库）；
- CPU 近乎为零（日志/连接表增量读取，不做 DPI、不解 TLS）；
- 磁盘：知识库约数百 KB，日志按轮转保留。

这也是它选择「DNS 为主 + 元数据判断」而非全流量 DPI 的根本原因 —— 见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

---

## 七、相关文档

- 版本与能力归属：[EDITIONS.md](./EDITIONS.md)
- 采集与执行的正交抽象：[README.md](./README.md) 架构章节 / [ARCHITECTURE.md](./ARCHITECTURE.md)
- 阻断与撤销语义：[BLOCKING.md](./BLOCKING.md)
