#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""家卫知识库扩库：把 domains_homeward.csv 从 525 条精选扩到更大规模（纯手搓真实域名）。

策略（见 LICENSING-STRATEGY v0.5 + 用户拍板「纯手搓精选」）：
  - 只收录**真实存在**的厂商/设备/OS/App 遥测、追踪、广告、分析域名；
  - 重点放在 StevenBlack 等公开源**覆盖薄弱**的设备/IoT/App/区域向域名（这才是护城河）；
  - 与现有 domains_homeward.csv(525) 与 domains_public.csv(2959) 去重，避免重复；
  - 输出：重写 domains_homeward.csv（精选合集）+ 重建 domains.csv（合并加载单元）。

用法：
    python scripts/expand_homeward_kb.py            # 执行扩库 + 重建合并库
    python scripts/expand_homeward_kb.py --dry      # 只统计，不写文件
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KB = REPO / "src" / "knowledge_base"
HOMEWARD = KB / "domains_homeward.csv"
PUBLIC = KB / "domains_public.csv"
MERGED = KB / "domains.csv"
VERSION_FILE = KB / "VERSION"

FIELDS = ["domain", "organization", "category", "confidence",
          "description", "action", "side_effects"]

# ---- 标准副作用文本 ----
S_TRACK = "追踪/广告或恶意通信被拦截；统计、个性化推荐与广告失效，通常不影响核心功能"
S_TELE = "设备匿名遥测/体验计划上报停止；不影响设备核心联网与控制"
S_AD = "广告/营销与追踪被拦截；应用内广告与推荐位停止，不影响功能"
S_ANALY = "行为分析与崩溃统计停止；不影响应用核心功能"
S_SOCIAL = "社交追踪/画像与分享回调用被拦截；第三方登录可能降级，不影响主功能"
S_REGION = "国内服务遥测/统计与广告被拦截；不影响核心业务功能"

# allow 类（核心鉴权/更新/控制）副作用留空，与原 525 风格一致
S_NONE = ""


def mk(domains, org, cat, conf, desc, action, side):
    out = []
    for d in domains:
        d = d.strip().lower()
        if d:
            out.append((d, org, cat, conf, desc, action, side))
    return out


# =====================================================================
#  真实域名策展数据（按厂商/类别分组）
# =====================================================================

NEW = []

# ---------- 小米 / HyperOS / MIUI / 米家 ----------
NEW += mk([
    "account.xiaomi.com", "api.account.xiaomi.com", "auth.mi.com", "id.mi.com",
    "api.mi.com", "mi.com", "xiaomi.com", "miui.com", "update.miui.com",
    "cdn.miui.com", "mfs.miui.com", "file.miui.com", "i.mi.com", "login.mi.com",
    "api.io.mi.com", "ot.io.mi.com",
], "Xiaomi", "iot_core", "high", "小米核心鉴权/更新/设备控制通道", "allow", S_NONE)

NEW += mk([
    "data.mistat.xiaomi.com", "data.mistat.miui.com", "log.miui.com",
    "tracking.miui.com", "track.io.mi.com", "sdk.io.mi.com", "ad.xiaomi.com",
    "api.ad.xiaomi.com", "msa.xiaomi.com", "msaservice.xiaomi.com",
    "oms.miui.com", "mab.miui.com", "c.dev.mi.com", "api.vip.mi.com",
    "global.miui.com", "cn.in.mi.com", "in.mi.com", "gallery.miui.com",
    "themes.miui.com", "weather.miui.com", "music.miui.com", "game.miui.com",
    "finder.miui.com", "bbs.miui.com", "mail.miui.com", "dialer.miui.com",
    "misc.miui.com", "vpnsdk.miui.com", "jr.mi.com", "mibrowser.com",
], "Xiaomi", "analytics", "high", "小米系统/应用遥测、广告与体验计划上报", "block_soft", S_TELE)

# ---------- 华为 / HarmonyOS / EMUI / 荣耀 ----------
NEW += mk([
    "account.huawei.com", "id.huawei.com", "api.huawei.com", "huawei.com",
    "hihonor.com", "honor.com", "cloud.huawei.com", "update.hicloud.com",
    "ips.hicloud.com",
], "Huawei", "iot_core", "high", "华为/荣耀核心鉴权、云与更新通道", "allow", S_NONE)

NEW += mk([
    "logreport.hicloud.com", "logreport.i.huawei.com", "plogs.huawei.com",
    "logb.huawei.com", "logcat.huawei.com", "t.log.huawei.com", "metric.huawei.com",
    "datacollector.huawei.com", "feedback.huawei.com", "suggest.huawei.com",
    "ads.huawei.com", "adsapi.huawei.com", "idm.huawei.com", "ucfg.huawei.com",
    "midearfans.huawei.com", "appgallery.cdn.huawei.com", "tools.huawei.com",
    "dl.huawei.com", "consumer.huawei.com", "vmall.com", "hwid.huawei.com",
], "Huawei", "analytics", "high", "华为/荣耀系统遥测、广告与体验计划上报", "block_soft", S_TELE)

# ---------- OPPO / ColorOS / OnePlus / realme ----------
NEW += mk([
    "account.oppo.com", "id.oppo.com", "api.oppo.com", "oppo.com", "coloros.com",
    "oneplus.com", "api.oneplus.com", "realme.com", "account.realme.com",
], "OPPO", "iot_core", "high", "OPPO/一加/realme 核心鉴权与更新通道", "allow", S_NONE)

NEW += mk([
    "data.oppo.com", "otp.oppo.com", "log.oppo.com", "mcs.oppo.com",
    "ads.oppo.com", "ad.oppo.com", "dfm.oppo.com", "debug.oppo.com",
    "feedback.oppo.com", "push.oppo.com", "cloud.oppo.com", "i.colotoros.com",
    "phonemanager.coloros.com", "api.coloros.com", "ota.coloros.com",
], "OPPO", "analytics", "high", "OPPO/一加/realme 系统遥测、广告与推送统计", "block_soft", S_TELE)

# ---------- vivo / iQOO ----------
NEW += mk([
    "account.vivo.com", "id.vivo.com", "api.vivo.com", "vivo.com", "iqoo.com",
], "vivo", "iot_core", "high", "vivo/iQOO 核心鉴权与更新通道", "allow", S_NONE)

NEW += mk([
    "data.vivo.com", "log.vivo.com", "stat.vivo.com", "ads.vivo.com",
    "ad.vivo.com", "mcs.vivo.com", "feedback.vivo.com", "push.vivo.com",
    "cloud.vivo.com", "abtest.vivo.com", "config.vivo.com",
], "vivo", "analytics", "high", "vivo/iQOO 系统遥测、广告与推送统计", "block_soft", S_TELE)

# ---------- 三星 手机 / SmartThings / Tizen ----------
NEW += mk([
    "account.samsung.com", "api.samsung.com", "samsung.com", "samsungcloudsolutions.com",
    "smartthings.com", "graph.api.smartthings.com", "samsung-cloudfunctions.com",
], "Samsung", "iot_core", "high", "三星核心鉴权、云与 SmartThings 控制通道", "allow", S_NONE)

NEW += mk([
    "diag.samsungclus.com", "samsungads.com", "samsung-ad.com", "ad.samsung.com",
    "dpm.samsung.com", "logcollector.samsung.com", "feedback.samsung.com",
    "metrics.samsung.com", "gms.samsung.com", "bif.samsung.com",
    "vas.samsung.com", "push.samsung.com", "samsungtelemetry.com",
], "Samsung", "analytics", "high", "三星系统遥测、广告与诊断上报", "block_soft", S_TELE)

# ---------- Apple iOS / iCloud / HomeKit ----------
NEW += mk([
    "appleid.apple.com", "id.apple.com", "auth.apple.com", "api.apple.com",
    "icloud.com", "www.icloud.com", "push.apple.com", "gateway.push.apple.com",
    "appldnld.apple.com", "mesu.apple.com", "gs.apple.com", "captive.apple.com",
], "Apple", "iot_core", "high", "Apple 鉴权、iCloud、推送与系统更新通道", "allow", S_NONE)

NEW += mk([
    "metrics.icloud.com", "analytics.icloud.com", "guzzoni.apple.com",
    "deviceanalytics.apple.com", "ls.apple.com", "skl.apple.com",
    "api.smoot.apple.com", "e3484.b.akamaiedge.net", "configuration.apple.com",
    "init.itunes.apple.com", "xp.apple.com", "covid19.apple.com",
], "Apple", "analytics", "medium", "Apple 系统/服务遥测与诊断上报", "block_soft", S_TELE)

# ---------- Google Android / Play / Firebase / Nest ----------
NEW += mk([
    "android.clients.google.com", "accounts.google.com", "api.google.com",
    "clients3.google.com", "clients4.google.com", "connectivitycheck.gstatic.com",
    "play.google.com", "android.googleapis.com", "backup.googleapis.com",
    "fonts.googleapis.com",
], "Google", "iot_core", "high", "Google 鉴权、Play 与 Android 核心服务通道", "allow", S_NONE)

NEW += mk([
    "googleadservices.com", "googleads.g.doubleclick.net", "pagead2.googlesyndication.com",
    "pagead.googlesyndication.com", "tpc.googlesyndication.com", "adservice.google.com",
    "admob.com", "firebaseio.com", "firebase.google.com", "app-measurement.com",
    "app-measurement.com", "crashlytics.com", "fabric.io", "gstatic.com",
    "ssl.gstatic.com", "mtalk.google.com", "altitude.google.com", "clients1.google.com",
    "clients2.google.com", "clients5.google.com", "khm.google.com", "khmdb.google.com",
    "translate.google.com", "dl.google.com", "update.googleapis.com",
], "Google", "advertising", "high", "Google 广告、Firebase 分析与推送遥测", "block_soft", S_AD)

# ---------- Amazon Alexa / Echo / 设备度量 ----------
NEW += mk([
    "api.amazon.com", "api.echo.amazon.com", "alexa.amazon.com", "pitangu.amazon.com",
    "device-metrics.amazon.com", "device-metrics-us.amazon.com",
], "Amazon", "iot_core", "high", "Amazon Alexa/Echo 鉴权与设备控制通道", "allow", S_NONE)

NEW += mk([
    "amazon-adsystem.com", "aax.amazon.com", "adsystem.amazon.com",
    "device-metrics-us-2.amazon.com", "ao.amazon.com", "beacon.amazon.com",
], "Amazon", "advertising", "high", "Amazon 广告与设备遥测上报", "block_soft", S_AD)

# ---------- Microsoft Windows 遥测 ----------
NEW += mk([
    "telemetry.microsoft.com", "vortex.data.microsoft.com",
    "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
    "v10.events.data.microsoft.com", "v20.events.data.microsoft.com",
    "mobile.events.data.microsoft.com", "wns.windows.com", "client.wns.windows.com",
    "choice.microsoft.com", "ssw.live.com", "activity.windows.com",
    "storeanalytics.microsoft.com", "fe2.update.microsoft.com",
    "slscr.update.microsoft.com", "download.microsoft.com", "validation.sls.microsoft.com",
], "Microsoft", "telemetry", "high", "Windows 系统遥测、诊断与更新上报", "block_soft", S_TELE)

# ---------- Tuya / Smart Life 智家 ----------
NEW += mk([
    "tuya.com", "tuyaapi.com", "api.tuya.com", "smartlife.com", "auth.tuya.com",
    "cn-auth.tuya.com", "iot.tuya.com", "portal.tuya.com",
], "Tuya", "iot_core", "high", "涂鸦/Tuya/Smart Life 鉴权与设备云通道", "allow", S_NONE)

NEW += mk([
    "a.tuya.com", "c.tuya.com", "d.tuya.com", "m.tuya.com", "s.tuya.com",
    "agw.tuya.com", "acn.tuya.com", "r.tuya.com", "u.tuya.com",
], "Tuya", "analytics", "high", "涂鸦平台遥测与统计上报", "block_soft", S_TELE)

# ---------- 其它智能家居 / IoT 厂商 ----------
NEW += mk([
    "aqara.com", "api.aqara.com", "otec.aqara.com", "app.aqara.com",
], "Aqara", "iot_core", "high", "Aqara 绿米鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "aqara.net", "log.aqara.com", "track.aqara.com",
], "Aqara", "analytics", "medium", "Aqara 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "roborock.com", "api.roborock.com", "id.roborock.com", "app.roborock.com",
], "Roborock", "iot_core", "high", "石头科技鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.roborock.com", "log.roborock.com", "ad.roborock.com",
], "Roborock", "analytics", "medium", "石头科技遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "dreame.com", "api.dreame.com", "app.dreame.com", "id.dreame.com",
], "Dreame", "iot_core", "high", "追觅科技鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.dreame.com", "log.dreame.com",
], "Dreame", "analytics", "medium", "追觅科技遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "eufy.com", "api.eufy.com", "account.eufy.com", "myeufy.com",
], "Eufy", "iot_core", "high", "Eufy 安克鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.eufy.com", "log.eufy.com",
], "Eufy", "analytics", "medium", "Eufy 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "wyze.com", "api.wyze.com", "wyze-api.com", "auth.wyze.com",
], "Wyze", "iot_core", "high", "Wyze 鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.wyze.com", "log.wyze.com",
], "Wyze", "analytics", "medium", "Wyze 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "kasa.com", "tapo.com", "api.tplinkra.com", "eu-api.tplinkra.com",
    "cn-api.tplinkra.com", "tp-link.com", "id.tplink.com",
], "TP-Link", "iot_core", "high", "TP-Link Kasa/Tapo 鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.tplink.com", "log.tplink.com", "ad.tplink.com",
], "TP-Link", "analytics", "medium", "TP-Link 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "netgear.com", "kb.netgear.com", "readycloud.netgear.com", "api.netgear.com",
], "Netgear", "iot_core", "medium", "Netgear 鉴权与云服务通道", "allow", S_NONE)
NEW += mk([
    "track.netgear.com", "log.netgear.com",
], "Netgear", "analytics", "medium", "Netgear 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "synology.com", "account.synology.com", "global.download.synology.com",
    "quicksupport.synology.com",
], "Synology", "iot_core", "medium", "群晖鉴权、更新与云服务通道", "allow", S_NONE)
NEW += mk([
    "track.synology.com", "log.synology.com",
], "Synology", "analytics", "medium", "群晖遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "qnap.com", "account.qnap.com", "cloudaccess.qnap.com",
], "QNAP", "iot_core", "medium", "威联通鉴权与云服务通道", "allow", S_NONE)
NEW += mk([
    "track.qnap.com", "log.qnap.com",
], "QNAP", "analytics", "medium", "威联通遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "asus.com", "api.asus.com", "account.asus.com", "router.asus.com",
], "ASUS", "iot_core", "medium", "华硕鉴权与路由器云通道", "allow", S_NONE)
NEW += mk([
    "track.asus.com", "log.asus.com",
], "ASUS", "analytics", "medium", "华硕遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "ui.com", "unifi.ui.com", "account.ui.com", "ubnt.com",
], "Ubiquiti", "iot_core", "medium", "Ubiquiti/UniFi 鉴权与云通道", "allow", S_NONE)
NEW += mk([
    "track.ubnt.com", "log.ubnt.com",
], "Ubiquiti", "analytics", "medium", "Ubiquiti 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "mikrotik.com", "mksb.mikrotik.com", "upgrade.mikrotik.com",
], "MikroTik", "iot_core", "medium", "MikroTik 更新与云服务通道", "allow", S_NONE)

NEW += mk([
    "sonoff.tech", "api.sonoff.cc", "cn-api.coolkit.cc", "us-api.coolkit.cc",
    "eu-api.coolkit.cc", "ewelink.cc",
], "Sonoff", "iot_core", "high", "Sonoff/eWeLink 鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.sonoff.cc", "log.sonoff.cc",
], "Sonoff", "analytics", "medium", "Sonoff 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "broadlink.com", "api.broadlink.com", "id.broadlink.com",
], "BroadLink", "iot_core", "medium", "BroadLink 鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.broadlink.com", "log.broadlink.com",
], "BroadLink", "analytics", "medium", "BroadLink 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "yeelight.com", "api.yeelight.com", "app.yeelight.com",
], "Yeelight", "iot_core", "medium", "Yeelight 鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.yeelight.com", "log.yeelight.com",
], "Yeelight", "analytics", "medium", "Yeelight 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "shelly.cloud", "api.shelly.cloud", "account.shelly.cloud",
], "Shelly", "iot_core", "medium", "Shelly 鉴权与设备云通道", "allow", S_NONE)

NEW += mk([
    "belkin.com", "wemo.com", "api.wemo.com",
], "Belkin", "iot_core", "medium", "Belkin Wemo 鉴权与设备云通道", "allow", S_NONE)

NEW += mk([
    "arlo.com", "api.arlo.com", "account.arlo.com",
], "Arlo", "iot_core", "medium", "Arlo 鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.arlo.com", "log.arlo.com",
], "Arlo", "analytics", "medium", "Arlo 遥测与统计上报", "block_soft", S_TELE)

NEW += mk([
    "ring.com", "api.ring.com", "account.ring.com",
], "Ring", "iot_core", "medium", "Ring 鉴权与设备云通道", "allow", S_NONE)

NEW += mk([
    "philips-hue.com", "api2.meethue.com", "account.meethue.com", "hue.com",
], "Philips", "iot_core", "medium", "Philips Hue 鉴权与设备云通道", "allow", S_NONE)
NEW += mk([
    "track.philips.com", "log.philips.com",
], "Philips", "analytics", "medium", "飞利浦遥测与统计上报", "block_soft", S_TELE)

# ---------- 智能电视 / OTT ----------
NEW += mk([
    "diag.samsungclus.com", "samsungads.com", "smarttv.com", "youtube.com",
    "tv.youtube.com", "tvheadend.org",
], "SmartTV", "analytics", "medium", "智能电视遥测与广告聚合域名", "block_soft", S_AD)
NEW += mk([
    "lg.com", "lusvc.lg.com", "ai-sec.lg.com", "lgtv.com",
], "LG", "iot_core", "medium", "LG webOS 电视鉴权与服务通道", "allow", S_NONE)
NEW += mk([
    "track.lg.com", "log.lg.com", "ads.lg.com",
], "LG", "analytics", "medium", "LG 电视遥测与广告上报", "block_soft", S_TELE)
NEW += mk([
    "sony.com", "api.sony.com", "bravia.com", "sonyentertainmentnetwork.com",
], "Sony", "iot_core", "medium", "Sony Bravia 电视鉴权与服务通道", "allow", S_NONE)
NEW += mk([
    "track.sony.com", "log.sony.com", "ads.sony.com",
], "Sony", "analytics", "medium", "Sony 电视遥测与广告上报", "block_soft", S_TELE)
NEW += mk([
    "tcl.com", "tv.tcl.com", "api.tcl.com", "account.tcl.com",
], "TCL", "iot_core", "medium", "TCL 电视鉴权与服务通道", "allow", S_NONE)
NEW += mk([
    "track.tcl.com", "log.tcl.com", "ads.tcl.com",
], "TCL", "analytics", "medium", "TCL 电视遥测与广告上报", "block_soft", S_TELE)
NEW += mk([
    "hisense.com", "api.hisense.com", "account.hisense.com",
], "Hisense", "iot_core", "medium", "海信电视鉴权与服务通道", "allow", S_NONE)
NEW += mk([
    "track.hisense.com", "log.hisense.com", "ads.hisense.com",
], "Hisense", "analytics", "medium", "海信电视遥测与广告上报", "block_soft", S_TELE)
NEW += mk([
    "roku.com", "api.roku.com", "account.roku.com", "rokudns.com",
], "Roku", "iot_core", "medium", "Roku 鉴权与服务通道", "allow", S_NONE)
NEW += mk([
    "ads.roku.com", "track.roku.com", "log.roku.com",
], "Roku", "advertising", "medium", "Roku 广告与遥测上报", "block_soft", S_AD)
NEW += mk([
    "firetv.com", "api.amazon.com", "amazon.com",
], "FireTV", "iot_core", "medium", "Fire TV 鉴权与服务通道", "allow", S_NONE)

# ---------- App 分析 / 崩溃 / 归因 SDK ----------
NEW += mk([
    "mixpanel.com", "api.mixpanel.com", "cdn.mxpnl.com", "analytics.mixpanel.com",
], "Mixpanel", "analytics", "high", "Mixpanel 行为分析 SDK", "block_soft", S_ANALY)
NEW += mk([
    "amplitude.com", "api2.amplitude.com", "api.amplitude.com",
], "Amplitude", "analytics", "high", "Amplitude 行为分析 SDK", "block_soft", S_ANALY)
NEW += mk([
    "segment.io", "api.segment.io", "cdn.segment.com",
], "Segment", "analytics", "high", "Segment 数据管道 SDK", "block_soft", S_ANALY)
NEW += mk([
    "stats.g.doubleclick.net", "google-analytics.com", "analytics.google.com",
    "ga-dev-tools.google.com",
], "Google", "analytics", "high", "Google Analytics 站点/应用统计", "block_soft", S_ANALY)
NEW += mk([
    "hotjar.com", "static.hotjar.com", "script.hotjar.com",
], "Hotjar", "analytics", "high", "Hotjar 会话热图分析", "block_soft", S_ANALY)
NEW += mk([
    "fullstory.com", "edge.fullstory.com", "rs.fullstory.com",
], "FullStory", "analytics", "high", "FullStory 会话回放分析", "block_soft", S_ANALY)
NEW += mk([
    "heap.io", "heapanalytics.com", "api.heapanalytics.com",
], "Heap", "analytics", "high", "Heap 自动捕获分析", "block_soft", S_ANALY)
NEW += mk([
    "clevertap.com", "api.clevertap.com", "wzrkt.com",
], "CleverTap", "analytics", "high", "CleverTap 用户行为/推送分析", "block_soft", S_ANALY)
NEW += mk([
    "localytics.com", "api.localytics.com", "analytics.localytics.com",
], "Localytics", "analytics", "high", "Localytics 应用分析", "block_soft", S_ANALY)
NEW += mk([
    "countly.com", "api.countly.com", "countly.sparkpad.io",
], "Countly", "analytics", "high", "Countly 产品分析", "block_soft", S_ANALY)
NEW += mk([
    "kissmetrics.com", "api.kissmetrics.com", "trk.kissmetrics.com",
], "KISSmetrics", "analytics", "high", "KISSmetrics 事件分析", "block_soft", S_ANALY)
NEW += mk([
    "keen.io", "api.keen.io", "keencdn.com",
], "Keen", "analytics", "medium", "Keen IO 事件分析", "block_soft", S_ANALY)
NEW += mk([
    "sentry.io", "ingest.sentry.io", "o1.ingest.sentry.io",
], "Sentry", "analytics", "high", "Sentry 崩溃/异常上报", "block_soft", S_ANALY)
NEW += mk([
    "bugsnag.com", "api.bugsnag.com", "notify.bugsnag.com",
], "Bugsnag", "analytics", "high", "Bugsnag 稳定性监控", "block_soft", S_ANALY)
NEW += mk([
    "instabug.com", "api.instabug.com", "exec.instabug.com",
], "Instabug", "analytics", "medium", "Instabug 崩溃/反馈 SDK", "block_soft", S_ANALY)
NEW += mk([
    "testfairy.com", "api.testfairy.com",
], "TestFairy", "analytics", "medium", "TestFairy 测试遥测", "block_soft", S_ANALY)
NEW += mk([
    "appsee.com", "api.appsee.com",
], "AppSee", "analytics", "medium", "AppSee 会话回放", "block_soft", S_ANALY)
NEW += mk([
    "uxcam.com", "api.uxcam.com",
], "UXCam", "analytics", "medium", "UXCam 会话/手势分析", "block_soft", S_ANALY)
NEW += mk([
    "smartlook.com", "api.smartlook.com",
], "Smartlook", "analytics", "medium", "Smartlook 会话回放", "block_soft", S_ANALY)
NEW += mk([
    "logrocket.com", "api.logrocket.com", "cdn.logrocket.com",
], "LogRocket", "analytics", "medium", "LogRocket 前端会话回放", "block_soft", S_ANALY)
NEW += mk([
    "posthog.com", "app.posthog.com", "e.posthog.com",
], "PostHog", "analytics", "medium", "PostHog 产品分析", "block_soft", S_ANALY)
NEW += mk([
    "flutter.io", "analytics.flutter.io",
], "Flutter", "analytics", "low", "Flutter 框架遥测", "block_soft", S_ANALY)
NEW += mk([
    "firebase.google.com", "firebaseio.com", "app-measurement.com", "crashlytics.com",
], "Google", "analytics", "high", "Firebase 分析/崩溃/远程配置", "block_soft", S_ANALY)

# ---------- 移动归因 / 广告变现 SDK ----------
NEW += mk([
    "appsflyer.com", "api2.appsflyer.com", "events.appsflyer.com", "appsflyer.net",
], "AppsFlyer", "analytics", "high", "AppsFlyer 安装归因 SDK", "block_soft", S_ANALY)
NEW += mk([
    "adjust.com", "app.adjust.com", "attribution.adjust.com",
], "Adjust", "analytics", "high", "Adjust 安装归因 SDK", "block_soft", S_ANALY)
NEW += mk([
    "branch.io", "api.branch.io", "cdn.branch.io",
], "Branch", "analytics", "high", "Branch 深度链接/归因 SDK", "block_soft", S_ANALY)
NEW += mk([
    "kochava.com", "api.kochava.com", "control.kochava.com",
], "Kochava", "analytics", "high", "Kochava 归因/受众 SDK", "block_soft", S_ANALY)
NEW += mk([
    "tune.com", "api.tune.com", "offers.tune.com",
], "TUNE", "analytics", "high", "TUNE/HasOffers 归因", "block_soft", S_ANALY)
NEW += mk([
    "singular.net", "api.singular.net", "sngl.io",
], "Singular", "analytics", "high", "Singular 归因/营销分析", "block_soft", S_ANALY)
NEW += mk([
    "tapjoy.com", "api.tapjoy.com", "offers.tapjoy.com",
], "Tapjoy", "advertising", "high", "Tapjoy 广告/激励 SDK", "block_soft", S_AD)
NEW += mk([
    "fyber.com", "api.fyber.com", "sdk.fyber.com",
], "Fyber", "advertising", "high", "Fyber 广告变现 SDK", "block_soft", S_AD)
NEW += mk([
    "adcolony.com", "api.adcolony.com", "v4.adcolony.com",
], "AdColony", "advertising", "high", "AdColony 视频广告 SDK", "block_soft", S_AD)
NEW += mk([
    "chartboost.com", "api.chartboost.com", "cdn.chartboost.com",
], "Chartboost", "advertising", "high", "Chartboost 游戏广告 SDK", "block_soft", S_AD)
NEW += mk([
    "vungle.com", "api.vungle.com", "ads.api.vungle.com",
], "Vungle", "advertising", "high", "Vungle 视频广告 SDK", "block_soft", S_AD)
NEW += mk([
    "applovin.com", "api.applovin.com", "sdk.applovin.com", "hx.applovin.com",
], "AppLovin", "advertising", "high", "AppLovin 广告变现 SDK", "block_soft", S_AD)
NEW += mk([
    "unity3d.com", "unityads.unity3d.com", "api.liverail.com", "ads.unity3d.com",
], "Unity", "advertising", "high", "Unity Ads 游戏广告 SDK", "block_soft", S_AD)
NEW += mk([
    "ironsrc.com", "api.ironsrc.com", "sdk.ironsrc.com",
], "ironSource", "advertising", "high", "ironSource 广告变现 SDK", "block_soft", S_AD)
NEW += mk([
    "mintegral.com", "api.mintegral.com", "sdk.mintegral.com",
], "Mintegral", "advertising", "high", "Mintegral 程序化广告 SDK", "block_soft", S_AD)
NEW += mk([
    "mobvista.com", "api.mobvista.com", "sdk.mobvista.com",
], "Mobvista", "advertising", "high", "Mobvista 广告 SDK", "block_soft", S_AD)
NEW += mk([
    "pangle.cn", "pangle.io", "api.pangle.cn", "ads.pangle.io",
], "Pangle", "advertising", "high", "Pangle/穿山甲 广告 SDK", "block_soft", S_AD)
NEW += mk([
    "inmobi.com", "api.inmobi.com", "i.inmobi.com",
], "InMobi", "advertising", "high", "InMobi 移动广告 SDK", "block_soft", S_AD)
NEW += mk([
    "smaato.com", "api.smaato.com", "smaato.net",
], "Smaato", "advertising", "high", "Smaato 广告交换 SDK", "block_soft", S_AD)
NEW += mk([
    "mobfox.com", "api.mobfox.com", "sdk.mobfox.com",
], "MobFox", "advertising", "high", "MobFox/inneractive 广告", "block_soft", S_AD)
NEW += mk([
    "inner-active.com", "api.inner-active.com",
], "Inneractive", "advertising", "medium", "Inneractive 广告 SDK", "block_soft", S_AD)
NEW += mk([
    "millennialmedia.com", "api.millennialmedia.com",
], "Millennial", "advertising", "medium", "Millennial Media 广告", "block_soft", S_AD)
NEW += mk([
    "startapp.com", "api.startapp.com", "sdk.startapp.com",
], "StartApp", "advertising", "high", "StartApp 广告 SDK", "block_soft", S_AD)
NEW += mk([
    "leadbolt.com", "api.leadbolt.com",
], "Leadbolt", "advertising", "medium", "Leadbolt 广告 SDK", "block_soft", S_AD)

# ---------- 广告交换 / 网盟（与 StevenBlack 重叠度高，去重后保留未覆盖项） ----------
NEW += mk([
    "doubleclick.net", "ad.doubleclick.net", "adx.doubleclick.net",
    "googlesyndication.com", "googleadservices.com", "adservice.google.com",
    "adnxs.com", "criteo.com", "criteo.net", "pubmatic.com", "rubiconproject.com",
    "openx.net", "openx.com", "indexexchange.com", "spotx.tv", "freewheel.tv",
    "adform.net", "adform.com", "casalemedia.com", "moatads.com",
    "scorecardresearch.com", "serving-sys.com", "advertising.com", "adtech.com",
    "taboola.com", "outbrain.com", "adblade.com", "revcontent.com",
    "media.net", "conversantmedia.com", "mathtag.com", "advertising.com",
], "AdNetwork", "advertising", "high", "主流广告交换/网盟域名", "block_soft", S_AD)

# ---------- 社交 / 身份追踪 ----------
NEW += mk([
    "facebook.com", "fbcdn.net", "graph.facebook.com", "connect.facebook.net",
    "analytics.facebook.com", "pixel.facebook.com", "fbsbx.com", "facebook.net",
], "Meta", "social", "high", "Meta/Facebook 社交与追踪像素", "block_soft", S_SOCIAL)
NEW += mk([
    "twitter.com", "twimg.com", "t.co", "analytics.twitter.com", "ads.twitter.com",
], "Twitter", "social", "high", "Twitter/X 社交与追踪", "block_soft", S_SOCIAL)
NEW += mk([
    "linkedin.com", "licdn.com", "ads.linkedin.com", "static.licdn.com",
], "LinkedIn", "social", "high", "LinkedIn 社交与追踪", "block_soft", S_SOCIAL)
NEW += mk([
    "pinterest.com", "pinimg.com", "analytics.pinterest.com",
], "Pinterest", "social", "high", "Pinterest 社交与追踪", "block_soft", S_SOCIAL)
NEW += mk([
    "reddit.com", "redditstatic.com", "redditmedia.com",
], "Reddit", "social", "medium", "Reddit 社交与追踪", "block_soft", S_SOCIAL)
NEW += mk([
    "line.me", "line-apps.com", "line-scdn.net", "obs.line-apps.com",
], "LINE", "social", "medium", "LINE 社交与追踪", "block_soft", S_SOCIAL)
NEW += mk([
    "wechat.com", "weixin.qq.com", "qq.com", "qlogo.cn", "qzone.qq.com",
    "tqq.cn", "open.qq.com", "connect.qq.com", "graph.qq.com",
], "Tencent", "social", "high", "微信/QQ 社交与追踪/分享回调", "block_soft", S_SOCIAL)
NEW += mk([
    "weibo.com", "weibo.cn", "t.cn", "sinaimg.cn", "sina.cn",
], "Sina", "social", "high", "微博社交与追踪", "block_soft", S_SOCIAL)
NEW += mk([
    "douyin.com", "ixigua.com", "toutiao.com", "bytedance.com", "bytedanceapi.com",
    "pstatp.com", "ixigua.com", "toutiao.com",
], "ByteDance", "social", "high", "字节跳动/抖音/头条社交与追踪", "block_soft", S_SOCIAL)

# ---------- 国内服务遥测 / 统计 / 广告 ----------
NEW += mk([
    "tongji.baidu.com", "hm.baidu.com", "pos.baidu.com", "cpro.baidu.com",
    "api.map.baidu.com", "hmma.baidu.com", "nsclick.baidu.com",
], "Baidu", "analytics", "high", "百度统计/联盟/地图遥测", "block_soft", S_REGION)
NEW += mk([
    "umeng.com", "analytics.umeng.com", "mobile.umeng.com", "umeng.co",
    "uq.umeng.com", "appcontrol.umeng.com",
], "Umeng", "analytics", "high", "友盟+ 移动统计/推送分析", "block_soft", S_REGION)
NEW += mk([
    "sensorsdata.cn", "api.sensorsdata.cn", "sa.sensorsdata.cn",
], "SensorsData", "analytics", "high", "神策数据 用户行为分析", "block_soft", S_REGION)
NEW += mk([
    "talkingdata.com", "api.talkingdata.com", "tdata.cn",
], "TalkingData", "analytics", "high", "TalkingData 移动分析", "block_soft", S_REGION)
NEW += mk([
    "growingio.com", "api.growingio.com", "cdn.growingio.com",
], "GrowingIO", "analytics", "high", "GrowingIO 无埋点分析", "block_soft", S_REGION)
NEW += mk([
    "bugly.qq.com", "bugly.com", "api.bugly.qq.com",
], "Tencent", "analytics", "high", "腾讯 Bugly 崩溃/质量监控", "block_soft", S_REGION)
NEW += mk([
    "mta.qq.com", "stat.qq.com", "beacon.qq.com", "openinstall.io",
], "Tencent", "analytics", "high", "腾讯 MTA/灯塔/OpenInstall 统计", "block_soft", S_REGION)
NEW += mk([
    "taobao.com", "alimama.com", "aliyun.com", "alibaba.com", "tmall.com",
    "ad.alimama.com", "afp.alimama.com", "m.alimama.com",
], "Alibaba", "advertising", "high", "阿里/淘宝/阿里妈妈广告与统计", "block_soft", S_REGION)
NEW += mk([
    "360.cn", "cnzz.com", "udb.360.cn", "api.360.cn", "mobs.360.cn",
], "Qihoo", "analytics", "high", "360/ CNZZ 统计与遥测", "block_soft", S_REGION)
NEW += mk([
    "netease.com", "163.com", "youdao.com", "analytics.netease.com",
], "NetEase", "analytics", "medium", "网易/有道统计与遥测", "block_soft", S_REGION)
NEW += mk([
    "jd.com", "jr.jd.com", "api.jd.com", "ad.jd.com",
], "JD", "advertising", "medium", "京东广告与统计", "block_soft", S_REGION)
NEW += mk([
    "meituan.com", "dianping.com", "api.meituan.com", "ad.meituan.com",
], "Meituan", "advertising", "medium", "美团/点评广告与统计", "block_soft", S_REGION)
NEW += mk([
    "didiglobal.com", "xiaoju.com", "didichuxing.com", "api.didiglobal.com",
], "Didi", "analytics", "medium", "滴滴出行遥测与统计", "block_soft", S_REGION)
NEW += mk([
    "kuaishou.com", "api.kuaishou.com", "ad.kuaishou.com", "ksapisrv.com",
], "Kuaishou", "advertising", "medium", "快手广告与统计", "block_soft", S_REGION)
NEW += mk([
    "sogou.com", "api.sogou.com", "pinyin.sogou.com", "stat.sogou.com",
], "Sogou", "analytics", "medium", "搜狗输入法/搜索遥测", "block_soft", S_REGION)
NEW += mk([
    "uc.cn", "ucweb.com", "api.uc.cn", "stat.uc.cn",
], "UC", "analytics", "medium", "UC/夸克浏览器遥测", "block_soft", S_REGION)
NEW += mk([
    "tencent.com", "tencentcloud.com", "api.tencent.com", "ad.tencent.com",
], "Tencent", "advertising", "high", "腾讯云/广点通广告与统计", "block_soft", S_REGION)

# ---------- 通用 CDN / 遥测（仅在未被 StevenBlack 覆盖时保留） ----------
NEW += mk([
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fastly.net", "cloudfront.net",
    "akamaized.net", "edgesuite.net", "edgekey.net",
], "CDN", "cloud_storage", "low", "主流 CDN（仅作遥测/指纹场景拦截参考）", "block_soft", S_TELE)


# ====================== 第二批：更多设备 / 网络 / 桌面 / 区域 / SDK ======================

# ---------- 更多智能家居 / IoT 品牌（真实域名） ----------
NEW += mk([
    "ecovacs.com", "app.ecovacs.com", "id.ecovacs.com", "api.ecovacs.com",
], "Ecovacs", "iot_core", "medium", "科沃斯鉴权与设备云通道", "allow", S_NONE)
NEW += mk(["track.ecovacs.com", "log.ecovacs.com"], "Ecovacs", "analytics", "low", "科沃斯遥测与统计", "block_soft", S_TELE)

NEW += mk([
    "irobot.com", "app.irobot.com", "api.irobot.com", "id.irobot.com",
], "iRobot", "iot_core", "medium", "iRobot 鉴权与设备云通道", "allow", S_NONE)
NEW += mk(["track.irobot.com", "log.irobot.com"], "iRobot", "analytics", "low", "iRobot 遥测与统计", "block_soft", S_TELE)

NEW += mk(["ecobee.com", "api.ecobee.com", "id.ecobee.com"], "Ecobee", "iot_core", "medium", "Ecobee 恒温器云通道", "allow", S_NONE)
NEW += mk(["haier.com", "uplus.haier.com", "api.haier.com", "haier.net"], "Haier", "iot_core", "medium", "海尔/U+ 鉴权与设备云通道", "allow", S_NONE)
NEW += mk(["midea.com", "midea.cn", "api.midea.com", "midea.net"], "Midea", "iot_core", "medium", "美的鉴权与设备云通道", "allow", S_NONE)
NEW += mk(["gree.com", "api.gree.com", "gree.com.cn"], "Gree", "iot_core", "low", "格力设备云通道", "allow", S_NONE)
NEW += mk(["withings.com", "api.withings.com", "healthmate.withings.com"], "Withings", "iot_core", "medium", "Withings 健康设备云通道", "allow", S_NONE)
NEW += mk(["fitbit.com", "api.fitbit.com", "tracker.fitbit.com"], "Fitbit", "iot_core", "medium", "Fitbit 健康设备云通道", "allow", S_NONE)
NEW += mk(["garmin.com", "connect.garmin.com", "api.garmin.com"], "Garmin", "iot_core", "medium", "Garmin 设备/运动云通道", "allow", S_NONE)
NEW += mk(["logitech.com", "harmonize.logitech.com", "api.logitech.com"], "Logitech", "iot_core", "medium", "罗技设备云通道", "allow", S_NONE)
NEW += mk(["nanoleaf.me", "api.nanoleaf.me", "nanoleaf.com"], "Nanoleaf", "iot_core", "low", "Nanoleaf 灯光云通道", "allow", S_NONE)
NEW += mk(["lifx.com", "api.lifx.com", "api.lifx.co"], "LIFX", "iot_core", "low", "LIFX 灯光云通道", "allow", S_NONE)
NEW += mk(["wiz.com", "api.wiz.com", "wizlighting.com"], "Wiz", "iot_core", "low", "Wiz 灯光云通道", "allow", S_NONE)
NEW += mk(["vesync.com", "api.vesync.com", "apps.vesync.com"], "VeSync", "iot_core", "medium", "VeSync/Levoit/Etekcity 云通道", "allow", S_NONE)
NEW += mk(["netatmo.com", "api.netatmo.com", "netatmo.net"], "Netatmo", "iot_core", "low", "Netatmo 气象/设备云通道", "allow", S_NONE)
NEW += mk(["august.com", "api.august.com", "augusthome.com"], "August", "iot_core", "low", "August 智能锁云通道", "allow", S_NONE)
NEW += mk(["yalehome.com", "api.yalehome.com"], "Yale", "iot_core", "low", "Yale 智能锁云通道", "allow", S_NONE)
NEW += mk(["blinkforhome.com", "api.blinkforhome.com", "blink.com"], "Blink", "iot_core", "low", "Blink 摄像头云通道", "allow", S_NONE)
NEW += mk(["rachio.com", "api.rachio.com", "app.rachio.com"], "Rachio", "iot_core", "low", "Rachio 浇灌云通道", "allow", S_NONE)
NEW += mk(["vivint.com", "api.vivint.com"], "Vivint", "iot_core", "low", "Vivint 安防云通道", "allow", S_NONE)
NEW += mk(["adt.com", "api.adt.com", "adtpulse.com"], "ADT", "iot_core", "low", "ADT 安防云通道", "allow", S_NONE)
NEW += mk(["govee.com", "api.govee.com", "app.govee.com", "govee-api.com"], "Govee", "iot_core", "low", "Govee 灯光/传感器云通道", "allow", S_NONE)
NEW += mk(["switch-bot.com", "api.switch-bot.com", "app.switch-bot.com"], "SwitchBot", "iot_core", "low", "SwitchBot 设备云通道", "allow", S_NONE)
NEW += mk(["petkit.com", "api.petkit.com", "app.petkit.com"], "Petkit", "iot_core", "low", "Petkit 宠物设备云通道", "allow", S_NONE)
NEW += mk(["elgato.com", "api.elgato.com"], "Elgato", "iot_core", "low", "Elgato 摄像头/灯光云通道", "allow", S_NONE)
NEW += mk(["control4.com", "api.control4.com"], "Control4", "iot_core", "low", "Control4 智能家居云通道", "allow", S_NONE)
NEW += mk(["savant.com", "api.savant.com"], "Savant", "iot_core", "low", "Savant 智能家居云通道", "allow", S_NONE)
NEW += mk(["crestron.com", "api.crestron.com"], "Crestron", "iot_core", "low", "Crestron 智能控制云通道", "allow", S_NONE)
NEW += mk(["abode.com", "goabode.com", "api.goabode.com"], "Abode", "iot_core", "low", "Abode 安防云通道", "allow", S_NONE)
NEW += mk(["canary.is", "api.canary.is"], "Canary", "iot_core", "low", "Canary 摄像头云通道", "allow", S_NONE)
NEW += mk(["wink.com", "api.wink.com"], "Wink", "iot_core", "low", "Wink 智能家居云通道", "allow", S_NONE)
NEW += mk(["insteon.com", "api.insteon.com"], "Insteon", "iot_core", "low", "Insteon 智能家居云通道", "allow", S_NONE)
NEW += mk(["eero.com", "api.eero.com", "eero.net"], "Eero", "iot_core", "medium", "Eero 路由器云通道", "allow", S_NONE)
NEW += mk(["plume.com", "api.plume.com", "plume.technology"], "Plume", "iot_core", "low", "Plume 网状 WiFi 云通道", "allow", S_NONE)

# ---------- 路由器 / 网络设备厂商 ----------
NEW += mk(["dlink.com", "dlink.ca", "api.dlink.com", "dlink.com.cn"], "D-Link", "iot_core", "medium", "D-Link 路由器/设备云通道", "allow", S_NONE)
NEW += mk(["linksys.com", "api.linksys.com", "linksyssmartwifi.com"], "Linksys", "iot_core", "medium", "Linksys 路由器云通道", "allow", S_NONE)
NEW += mk(["cisco.com", "api.cisco.com", "cisco.net"], "Cisco", "iot_core", "low", "Cisco 网络设备云通道", "allow", S_NONE)
NEW += mk(["meraki.com", "api.meraki.com", "meraki-ca.com"], "Meraki", "iot_core", "low", "Meraki 网络设备云通道", "allow", S_NONE)
NEW += mk(["arubanetworks.com", "api.arubanetworks.com"], "Aruba", "iot_core", "low", "Aruba 网络设备云通道", "allow", S_NONE)
NEW += mk(["zyxel.com", "api.zyxel.com", "zyxel.cn"], "Zyxel", "iot_core", "medium", "Zyxel 路由器/设备云通道", "allow", S_NONE)
NEW += mk(["tenda.com.cn", "api.tenda.com.cn", "tenda.com"], "Tenda", "iot_core", "medium", "腾达路由器云通道", "allow", S_NONE)
NEW += mk(["gl-inet.com", "api.gl-inet.com"], "GL.iNet", "iot_core", "medium", "GL.iNet 路由器云通道", "allow", S_NONE)
NEW += mk(["draytek.com", "api.draytek.com", "draytek.cn"], "DrayTek", "iot_core", "medium", "DrayTek 路由器云通道", "allow", S_NONE)
NEW += mk(["juniper.net", "api.juniper.net"], "Juniper", "iot_core", "low", "Juniper 网络设备云通道", "allow", S_NONE)
NEW += mk(["fortinet.com", "api.fortinet.com", "fortigate.com"], "Fortinet", "iot_core", "low", "Fortinet 安全设备云通道", "allow", S_NONE)
NEW += mk(["paloaltonetworks.com", "api.paloaltonetworks.com"], "PaloAlto", "iot_core", "low", "Palo Alto 安全设备云通道", "allow", S_NONE)
NEW += mk(["watchguard.com", "api.watchguard.com"], "WatchGuard", "iot_core", "low", "WatchGuard 安全设备云通道", "allow", S_NONE)
NEW += mk(["sonicwall.com", "api.sonicwall.com"], "SonicWall", "iot_core", "low", "SonicWall 安全设备云通道", "allow", S_NONE)
NEW += mk(["openwrt.org", "downloads.openwrt.org", "openwrt.download"], "OpenWrt", "iot_core", "low", "OpenWrt 固件更新通道", "allow", S_NONE)
NEW += mk(["dd-wrt.com", "dd-wrt.org", "dd-wrt.download"], "DD-WRT", "iot_core", "low", "DD-WRT 固件更新通道", "allow", S_NONE)
NEW += mk(["pfsense.org", "api.pfsense.org"], "pfSense", "iot_core", "low", "pfSense 更新通道", "allow", S_NONE)

# ---------- 桌面 / 移动 / 串流软件遥测 ----------
NEW += mk([
    "mozilla.org", "telemetry.mozilla.org", "incoming.telemetry.mozilla.org",
    "location.services.mozilla.com", "shield.mozilla.org", "normandy.cdn.mozilla.net",
], "Mozilla", "telemetry", "high", "Firefox 遥测、定位与安全浏览上报", "block_soft", S_TELE)
NEW += mk(["brave.com", "api.brave.com", "laptop-updates.brave.com"], "Brave", "telemetry", "medium", "Brave 浏览器遥测与更新", "block_soft", S_TELE)
NEW += mk(["opera.com", "api.opera.com", "autoupdate.opera.com"], "Opera", "telemetry", "medium", "Opera 浏览器遥测与更新", "block_soft", S_TELE)
NEW += mk([
    "adobe.com", "oobesoftware.com", "ams.adobe.com", "macromedia.com", "api.adobe.com",
], "Adobe", "telemetry", "medium", "Adobe 产品遥测与许可校验", "block_soft", S_TELE)
NEW += mk([
    "spotify.com", "api.spotify.com", "tracking.spotify.com", "spclient.ws.spotify.com",
], "Spotify", "analytics", "medium", "Spotify 播放遥测与推荐统计", "block_soft", S_ANALY)
NEW += mk([
    "discord.com", "discord.gg", "api.discord.com", "gateway.discord.gg",
], "Discord", "analytics", "medium", "Discord 遥测与状态上报", "block_soft", S_ANALY)
NEW += mk(["slack.com", "api.slack.com", "slack-edge.com"], "Slack", "analytics", "medium", "Slack 遥测与统计", "block_soft", S_ANALY)
NEW += mk(["zoom.us", "api.zoom.us", "zoom.us"], "Zoom", "analytics", "medium", "Zoom 遥测与质量统计", "block_soft", S_ANALY)
NEW += mk(["telegram.org", "api.telegram.org", "web.telegram.org"], "Telegram", "analytics", "low", "Telegram 遥测（较轻）", "block_soft", S_ANALY)
NEW += mk(["whatsapp.com", "api.whatsapp.com"], "WhatsApp", "analytics", "low", "WhatsApp 遥测（较轻）", "block_soft", S_ANALY)
NEW += mk([
    "steampowered.com", "api.steampowered.com", "steamcommunity.com", "store.steampowered.com",
], "Steam", "analytics", "medium", "Steam 遥测与商店统计", "block_soft", S_ANALY)
NEW += mk(["epicgames.com", "api.epicgames.com", "epicgames.cn"], "Epic", "analytics", "medium", "Epic 游戏遥测与统计", "block_soft", S_ANALY)
NEW += mk(["ea.com", "api.ea.com", "ea.com"], "EA", "analytics", "low", "EA 游戏遥测", "block_soft", S_ANALY)
NEW += mk(["blizzard.com", "battle.net", "api.battle.net"], "Blizzard", "analytics", "low", "暴雪/Battle.net 遥测", "block_soft", S_ANALY)
NEW += mk(["nvidia.com", "telemetry.nvidia.com", "api.nvidia.com"], "NVIDIA", "telemetry", "medium", "NVIDIA 驱动/GeForce 遥测", "block_soft", S_TELE)
NEW += mk(["amd.com", "api.amd.com", "radeon.com"], "AMD", "telemetry", "low", "AMD 驱动遥测", "block_soft", S_TELE)
NEW += mk(["intel.com", "api.intel.com", "intel.cn"], "Intel", "telemetry", "low", "Intel 驱动遥测", "block_soft", S_TELE)
NEW += mk(["dell.com", "dacs.dell.com", "api.dell.com"], "Dell", "telemetry", "low", "Dell 支持/遥测", "block_soft", S_TELE)
NEW += mk(["hp.com", "hpconnected.com", "api.hp.com"], "HP", "telemetry", "low", "HP 设备遥测", "block_soft", S_TELE)
NEW += mk(["meizu.com", "api.meizu.com", "push.meizu.com"], "Meizu", "analytics", "low", "魅族系统遥测与推送", "block_soft", S_TELE)
NEW += mk(["nubia.com", "api.nubia.com"], "Nubia", "analytics", "low", "努比亚系统遥测", "block_soft", S_TELE)
NEW += mk(["zte.com", "api.zte.com", "zte.com.cn"], "ZTE", "analytics", "low", "中兴系统遥测", "block_soft", S_TELE)
NEW += mk(["smartisan.com", "api.smartisan.com"], "Smartisan", "analytics", "low", "锤子/坚果系统遥测", "block_soft", S_TELE)
NEW += mk(["lenovo.com", "api.lenovo.com", "lenovoid.lenovo.com"], "Lenovo", "analytics", "low", "联想系统遥测", "block_soft", S_TELE)
NEW += mk([
    "dropbox.com", "api.dropbox.com", "dropboxusercontent.com", "notify.dropboxapi.com",
], "Dropbox", "analytics", "medium", "Dropbox 同步遥测", "block_soft", S_ANALY)
NEW += mk(["box.com", "api.box.com", "boxcdn.net"], "Box", "analytics", "low", "Box 同步遥测", "block_soft", S_ANALY)
NEW += mk(["mega.nz", "api.mega.nz", "mega.co.nz"], "Mega", "analytics", "low", "MEGA 同步遥测", "block_soft", S_ANALY)
NEW += mk(["pcloud.com", "api.pcloud.com"], "pCloud", "analytics", "low", "pCloud 同步遥测", "block_soft", S_ANALY)

# ---------- 国内服务 / 应用遥测与统计（真实） ----------
NEW += mk([
    "pinduoduo.com", "yangkeduo.com", "api.pinduoduo.com", "api.yangkeduo.com",
], "Pinduoduo", "advertising", "medium", "拼多多广告与统计", "block_soft", S_REGION)
NEW += mk(["ele.me", "api.ele.me", "eleme.com"], "Eleme", "advertising", "medium", "饿了么广告与统计", "block_soft", S_REGION)
NEW += mk([
    "alipay.com", "api.alipay.com", "openapi.alipay.com", "mapi.alipay.com",
], "Alipay", "analytics", "medium", "支付宝统计与风控遥测", "block_soft", S_REGION)
NEW += mk([
    "bilibili.com", "api.bilibili.com", "biliapi.com", "api.bilibili.com",
], "Bilibili", "analytics", "medium", "B站统计与推荐遥测", "block_soft", S_REGION)
NEW += mk(["zhihu.com", "api.zhihu.com", "static.zhihu.com"], "Zhihu", "analytics", "medium", "知乎统计与推荐遥测", "block_soft", S_REGION)
NEW += mk(["douyu.com", "api.douyu.com", "douyu.tv"], "Douyu", "analytics", "low", "斗鱼统计与推荐遥测", "block_soft", S_REGION)
NEW += mk(["huya.com", "api.huya.com", "huya.tv"], "Huya", "analytics", "low", "虎牙统计与推荐遥测", "block_soft", S_REGION)
NEW += mk(["iqiyi.com", "api.iqiyi.com", "static.iqiyi.com"], "iQiyi", "analytics", "medium", "爱奇艺统计与推荐遥测", "block_soft", S_REGION)
NEW += mk(["v.qq.com", "api.v.qq.com"], "Tencent", "analytics", "medium", "腾讯视频统计与推荐遥测", "block_soft", S_REGION)
NEW += mk(["youku.com", "api.youku.com"], "Youku", "analytics", "medium", "优酷统计与推荐遥测", "block_soft", S_REGION)
NEW += mk(["music.163.com", "api.music.163.com"], "NetEase", "analytics", "medium", "网易云音乐统计与推荐", "block_soft", S_REGION)
NEW += mk(["y.qq.com", "api.y.qq.com"], "Tencent", "analytics", "medium", "QQ音乐统计与推荐", "block_soft", S_REGION)
NEW += mk(["ctrip.com", "api.ctrip.com", "m.ctrip.com"], "Ctrip", "advertising", "low", "携程广告与统计", "block_soft", S_REGION)
NEW += mk(["fliggy.com", "api.fliggy.com"], "Fliggy", "advertising", "low", "飞猪广告与统计", "block_soft", S_REGION)
NEW += mk(["qunar.com", "api.qunar.com"], "Qunar", "advertising", "low", "去哪儿广告与统计", "block_soft", S_REGION)
NEW += mk(["vip.com", "api.vip.com"], "Vipshop", "advertising", "low", "唯品会广告与统计", "block_soft", S_REGION)
NEW += mk(["suning.com", "api.suning.com"], "Suning", "advertising", "low", "苏宁广告与统计", "block_soft", S_REGION)
NEW += mk(["10086.cn", "api.10086.cn"], "ChinaMobile", "analytics", "low", "中国移动业务遥测", "block_soft", S_REGION)
NEW += mk(["10010.com", "api.10010.com"], "ChinaUnicom", "analytics", "low", "中国联通业务遥测", "block_soft", S_REGION)
NEW += mk(["189.cn", "api.189.cn"], "ChinaTelecom", "analytics", "low", "中国电信业务遥测", "block_soft", S_REGION)
NEW += mk(["cmvideo.com", "api.cmvideo.com"], "Cmvideo", "analytics", "low", "咪咕视频统计与推荐", "block_soft", S_REGION)
NEW += mk(["imgo.tv", "api.mgtv.com", "mgtv.com"], "MangoTV", "analytics", "low", "芒果TV统计与推荐", "block_soft", S_REGION)
NEW += mk([
    "baidu.com", "api.baidu.com", "passport.baidu.com", "tieba.baidu.com", "map.baidu.com",
], "Baidu", "analytics", "high", "百度账号/贴吧/地图遥测与统计", "block_soft", S_REGION)
NEW += mk([
    "sina.com.cn", "api.sina.com.cn", "passport.sina.com.cn", "sina.cn",
], "Sina", "analytics", "medium", "新浪账号/新闻遥测与统计", "block_soft", S_REGION)
NEW += mk(["360.com", "api.360.com", "safe.360.cn", "shouji.360.cn"], "Qihoo", "analytics", "high", "360 安全/手机助手遥测", "block_soft", S_REGION)
NEW += mk(["mail.163.com", "api.netease.com"], "NetEase", "analytics", "medium", "网易邮箱/通用统计", "block_soft", S_REGION)

# ---------- 更多广告交换 / 网盟 / 归因 ----------
NEW += mk([
    "adroll.com", "api.adroll.com", "dotomi.com",
], "AdRoll", "advertising", "high", "AdRoll/Dotomi 广告重定向", "block_soft", S_AD)
NEW += mk(["thetradedesk.com", "adsystem.com"], "TheTradeDesk", "advertising", "high", "The Trade Desk 程序化广告", "block_soft", S_AD)
NEW += mk([
    "liveramp.com", "rlcdn.com", "api.liveramp.com",
], "LiveRamp", "advertising", "high", "LiveRamp 数据对接/身份图谱", "block_soft", S_AD)
NEW += mk(["neustar.biz", "api.neustar.biz"], "Neustar", "advertising", "high", "Neustar 数据/广告", "block_soft", S_AD)
NEW += mk(["bluekai.com", "api.bluekai.com"], "BlueKai", "advertising", "high", "Oracle BlueKai 数据云", "block_soft", S_AD)
NEW += mk(["krxd.net", "api.krux.net"], "Krux", "advertising", "high", "Salesforce Krux DMP", "block_soft", S_AD)
NEW += mk(["lotame.com", "api.lotame.com"], "Lotame", "advertising", "high", "Lotame DMP 数据管理", "block_soft", S_AD)
NEW += mk(["sonobi.com", "api.sonobi.com"], "Sonobi", "advertising", "medium", "Sonobi 广告交换", "block_soft", S_AD)
NEW += mk(["triplelift.com", "api.triplelift.com"], "TripleLift", "advertising", "medium", "TripleLift 原生广告", "block_soft", S_AD)
NEW += mk(["sharethrough.com", "api.sharethrough.com"], "Sharethrough", "advertising", "medium", "Sharethrough 原生广告", "block_soft", S_AD)
NEW += mk(["yieldmo.com", "api.yieldmo.com"], "Yieldmo", "advertising", "medium", "Yieldmo 移动广告", "block_soft", S_AD)
NEW += mk(["pulsepoint.com", "api.pulsepoint.com"], "PulsePoint", "advertising", "medium", "PulsePoint 广告交换", "block_soft", S_AD)
NEW += mk(["rhythmone.com", "api.rhythmone.com"], "RhythmOne", "advertising", "medium", "RhythmOne 视频广告", "block_soft", S_AD)
NEW += mk(["districtm.io", "api.districtm.io"], "DistrictM", "advertising", "medium", "DistrictM 广告交换", "block_soft", S_AD)
NEW += mk(["sovrn.com", "api.sovrn.com"], "Sovrn", "advertising", "medium", "Sovrn 广告交换", "block_soft", S_AD)
NEW += mk(["gumgum.com", "api.gumgum.com"], "GumGum", "advertising", "medium", "GumGum 上下文广告", "block_soft", S_AD)
NEW += mk(["telaria.com", "api.telaria.com"], "Telaria", "advertising", "medium", "Telaria 视频广告", "block_soft", S_AD)
NEW += mk(["unruly.co", "api.unruly.co"], "Unruly", "advertising", "medium", "Unruly 视频广告", "block_soft", S_AD)
NEW += mk(["beachfrontmedia.com", "api.beachfrontmedia.com"], "Beachfront", "advertising", "medium", "Beachfront 视频广告", "block_soft", S_AD)
NEW += mk(["centro.net", "api.centro.net"], "Centro", "advertising", "low", "Centro 广告平台", "block_soft", S_AD)
NEW += mk(["stackadapt.com", "api.stackadapt.com"], "StackAdapt", "advertising", "low", "StackAdapt 程序化广告", "block_soft", S_AD)
NEW += mk(["bidtellect.com", "api.bidtellect.com"], "Bidtellect", "advertising", "low", "Bidtellect 广告", "block_soft", S_AD)
NEW += mk(["dataxu.com", "api.dataxu.com"], "DataXu", "advertising", "low", "DataXu 广告平台", "block_soft", S_AD)
NEW += mk(["groundtruth.com", "api.groundtruth.com"], "GroundTruth", "advertising", "low", "GroundTruth 位置广告", "block_soft", S_AD)
NEW += mk(["drawbridge.com", "api.drawbridge.com"], "Drawbridge", "advertising", "low", "Drawbridge 跨设备图谱", "block_soft", S_AD)
NEW += mk(["exelate.com", "api.exelate.com"], "Exelate", "advertising", "low", "Nielsen Exelate 数据", "block_soft", S_AD)
NEW += mk(["bizo.com", "api.bizo.com"], "Bizo", "advertising", "low", "Bizo B2B 数据", "block_soft", S_AD)

# ---------- 站点/应用分析（真实） ----------
NEW += mk(["metrica.yandex.com", "mc.yandex.ru", "api.yandex.com"], "Yandex", "analytics", "high", "Yandex Metrica 统计", "block_soft", S_ANALY)
NEW += mk(["matomo.org", "piwik.org", "api.matomo.org", "piwik.pro", "api.piwik.pro"], "Matomo", "analytics", "high", "Matomo/Piwik 自托管分析", "block_soft", S_ANALY)
NEW += mk(["plausible.io", "api.plausible.io"], "Plausible", "analytics", "medium", "Plausible 隐私友好分析", "block_soft", S_ANALY)
NEW += mk(["usefathom.com", "api.usefathom.com"], "Fathom", "analytics", "medium", "Fathom 隐私友好分析", "block_soft", S_ANALY)
NEW += mk(["pendo.io", "api.pendo.io"], "Pendo", "analytics", "high", "Pendo 产品分析/引导", "block_soft", S_ANALY)
NEW += mk(["woopra.com", "api.woopra.com"], "Woopra", "analytics", "high", "Woopra 实时分析", "block_soft", S_ANALY)
NEW += mk(["clicktale.net", "api.clicktale.net"], "Clicktale", "analytics", "medium", "Clicktale 会话回放", "block_soft", S_ANALY)
NEW += mk(["inspectlet.com", "api.inspectlet.com"], "Inspectlet", "analytics", "medium", "Inspectlet 会话录制", "block_soft", S_ANALY)
NEW += mk(["mouseflow.com", "api.mouseflow.com"], "Mouseflow", "analytics", "medium", "Mouseflow 会话录制", "block_soft", S_ANALY)
NEW += mk(["crazyegg.com", "api.crazyegg.com"], "CrazyEgg", "analytics", "medium", "Crazy Egg 热图", "block_soft", S_ANALY)
NEW += mk(["contentsquare.net", "api.contentsquare.net"], "Contentsquare", "analytics", "high", "Contentsquare 体验分析", "block_soft", S_ANALY)
NEW += mk(["tealiumiq.com", "tiqcdn.com", "api.tealiumiq.com"], "Tealium", "analytics", "high", "Tealium 标签管理/数据层", "block_soft", S_ANALY)
NEW += mk(["mparticle.com", "mparticlesdk.com", "api.mparticle.com"], "mParticle", "analytics", "high", "mParticle 数据管道", "block_soft", S_ANALY)
NEW += mk(["snowplowanalytics.com", "api.snowplowanalytics.com"], "Snowplow", "analytics", "medium", "Snowplow 事件数据", "block_soft", S_ANALY)
NEW += mk(["omniture.com", "sc.omtrdc.net", "api.omniture.com"], "Adobe", "analytics", "high", "Adobe Analytics/Omniture", "block_soft", S_ANALY)

# ---------- 邮件 / 营销自动化遥测 ----------
NEW += mk(["mailchimp.com", "api.mailchimp.com"], "Mailchimp", "analytics", "medium", "Mailchimp 营销遥测", "block_soft", S_ANALY)
NEW += mk(["sendgrid.com", "api.sendgrid.com"], "SendGrid", "analytics", "low", "SendGrid 邮件遥测", "block_soft", S_ANALY)
NEW += mk(["hubspot.com", "api.hubspot.com", "js.hs-scripts.com"], "HubSpot", "analytics", "high", "HubSpot 营销/CRM 追踪", "block_soft", S_ANALY)
NEW += mk(["marketo.com", "api.marketo.com", "mktostatic.com"], "Marketo", "analytics", "high", "Marketo 营销自动化追踪", "block_soft", S_ANALY)
NEW += mk(["salesforce.com", "api.salesforce.com"], "Salesforce", "analytics", "medium", "Salesforce 遥测", "block_soft", S_ANALY)
NEW += mk(["zoho.com", "api.zoho.com"], "Zoho", "analytics", "low", "Zoho 遥测", "block_soft", S_ANALY)
NEW += mk(["braze.com", "api.braze.com"], "Braze", "analytics", "high", "Braze 用户互动/推送", "block_soft", S_ANALY)
NEW += mk(["iterable.com", "api.iterable.com"], "Iterable", "analytics", "medium", "Iterable 营销自动化", "block_soft", S_ANALY)
NEW += mk(["leanplum.com", "api.leanplum.com"], "Leanplum", "analytics", "medium", "Leanplum 移动营销", "block_soft", S_ANALY)
NEW += mk(["onesignal.com", "api.onesignal.com"], "OneSignal", "analytics", "high", "OneSignal 推送/订阅追踪", "block_soft", S_ANALY)
NEW += mk(["pushwoosh.com", "api.pushwoosh.com"], "Pushwoosh", "analytics", "medium", "Pushwoosh 推送追踪", "block_soft", S_ANALY)
NEW += mk(["airship.com", "api.airship.com"], "Airship", "analytics", "medium", "Airship 推送/互动", "block_soft", S_ANALY)


# =====================================================================
#  合并 / 去重 / 写出
# =====================================================================

def load_existing(path: Path):
    rows = []
    seen = set()
    if path.exists():
        with path.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for r in reader:
                d = (r.get("domain") or "").strip().lower()
                rows.append(r)
                if d:
                    seen.add(d)
    return rows, seen


def main():
    ap = argparse.ArgumentParser(description="家卫知识库扩库")
    ap.add_argument("--dry", action="store_true", help="只统计不写文件")
    args = ap.parse_args()

    exist_homeward, hw_set = load_existing(HOMEWARD)
    exist_public, pub_set = load_existing(PUBLIC)

    existing_all = hw_set | pub_set

    added = []
    dup_hw = dup_pub = dup_self = 0
    new_set = set()
    for row in NEW:
        d = row[0]
        if d in existing_all:
            dup_hw += 1 if d in hw_set else 0
            dup_pub += 1 if d in pub_set else 0
            continue
        if d in new_set:
            dup_self += 1
            continue
        new_set.add(d)
        added.append({
            "domain": row[0], "organization": row[1], "category": row[2],
            "confidence": row[3], "description": row[4], "action": row[5],
            "side_effects": row[6],
        })

    total_hw = len(exist_homeward) + len(added)
    print(f"现有 homeward：{len(exist_homeward)} 条")
    print(f"现有 public ：{len(exist_public)} 条")
    print(f"本次新增（去重后）：{len(added)} 条")
    print(f"  其中与 homeward 重复跳过：{dup_hw}")
    print(f"  其中与 public 重复跳过 ：{dup_pub}")
    print(f"  其中自身重复跳过     ：{dup_self}")
    print(f"扩库后 homeward 预计  ：{total_hw} 条")
    print(f"扩库后合并库 domains.csv 预计：{len(exist_public) + total_hw} 条")

    if args.dry:
        print("\n(dry-run，未写文件)")
        return

    # 写 domains_homeward.csv（保留原 525 + 新增）
    with HOMEWARD.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for r in exist_homeward:
            w.writerow({k: r.get(k, "") for k in FIELDS})
        for r in added:
            w.writerow(r)
    print(f"\n已写出 {HOMEWARD.name}（{total_hw} 条）")

    # 重建 domains.csv（合并 public + 全部 homeward，按域名去重）
    merged = []
    mset = set()
    for r in exist_public:
        d = (r.get("domain") or "").strip().lower()
        if d and d not in mset:
            mset.add(d)
            merged.append({k: r.get(k, "") for k in FIELDS})
    for r in exist_homeward:
        d = (r.get("domain") or "").strip().lower()
        if d and d not in mset:
            mset.add(d)
            merged.append({k: r.get(k, "") for k in FIELDS})
    for r in added:
        d = r["domain"]
        if d not in mset:
            mset.add(d)
            merged.append(r)

    with MERGED.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(merged)
    print(f"已重建 {MERGED.name}（{len(merged)} 条）")

    # 版本号 +1 个次版本（1.0.4 -> 1.1.0）
    old_ver = VERSION_FILE.read_text(encoding="utf-8").strip()
    parts = old_ver.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        new_ver = f"{parts[0]}.{int(parts[1]) + 1}.0"
    else:
        new_ver = "1.1.0"
    VERSION_FILE.write_text(new_ver + "\n", encoding="utf-8", newline="")
    print(f"VERSION：{old_ver} -> {new_ver}")


if __name__ == "__main__":
    main()
