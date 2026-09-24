#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成家卫的精简 MAC 厂商（OUI）表 —— src/knowledge_base/oui_prefixes.csv

为什么要这个脚本
----------------
MAC 地址前 3 字节（OUI / MA-L）是 IEEE 分配给厂商的**事实数据**，不是代码。
把它手写进仓库有两个风险：一是凭记忆写极易出错（一条错前缀就等于给设备贴错标签），
二是来源不清。所以家卫的做法是：**仓库里不放原始数据，改用脚本按需生成精简表**，
并在产物头部写死来源与生成日期，可复现、可审计。

用法
----
    python tools/build_oui_table.py                    # 默认拉 Wireshark 官方 manuf 并过滤
    python tools/build_oui_table.py --from ieee        # 改用 IEEE registry（常有反爬，可能 418）
    python tools/build_oui_table.py --source oui.csv   # 用已下载好的本地文件
    python tools/build_oui_table.py --all              # 不做白名单过滤，导出全量

产物
----
    src/knowledge_base/oui_prefixes.csv
    字段：prefix,vendor,vendor_cn,device_hint
    · prefix    归一化为小写 xx:xx:xx（只取前三字节）
    · vendor    厂商英文名（来自源数据，未做改写）
    · vendor_cn 中文名（来自本脚本的白名单配置，便于中文 UI 展示）
    · device_hint 白名单标注的品类倾向（可能留空 —— 不猜）

数据来源与许可
--------------
· **默认来源：Wireshark 官方 manuf**（https://www.wireshark.org/download/automated/data/manuf）
  这是 Wireshark 自动化构建发布的数据目录，可直接下载（约 3 MB / 5.8 万行）。
  注意：manuf 文件本身是 GPL-2.0；本脚本**不复制其任何代码**，只读取其中的
  「前缀 → 厂商名」**事实**（事实数据不受版权保护）。若你的法务口径更严，
  请改用 --from ieee。
· **备选来源：IEEE MA-L registry**（https://standards-oui.ieee.org/oui/oui.csv）
  URL 有效，但 IEEE 站点对脚本 UA 有反爬（可能返回 418），建议在浏览器下载后用
  --source 导入。
· 本项目红线：**不引入任何 GPL / AGPL 代码**。本脚本为标准库实现，无第三方依赖。

过滤策略
--------
家庭场景用不上 3 万多条 IEEE 全量数据。脚本按下面的白名单做子串匹配，
优先保留国产设备厂商与常见家庭网络设备厂商，产物约几百行（对应产品的轻量定位）。
"""

import argparse
import csv
import gzip
import re
import ssl
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "src" / "knowledge_base" / "oui_prefixes.csv"

# 下载源。Wireshark 官方 automated 数据目录可直接下载，作为默认源。
WIRESHARK_MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"
DOWNLOAD_SOURCES = {
    # name: (url, 解析器名)
    "wireshark": (WIRESHARK_MANUF_URL, "manuf"),
    "ieee": (IEEE_URL, "ieee"),
}
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# 白名单：厂商名子串（小写匹配） -> (中文名, 品类倾向)
# device_hint 只在「该厂商几乎只做这一类设备」时才填，否则留空 —— 不猜。
WANTED: dict[str, tuple[str, str]] = {
    # 智能家居生态
    "xiaomi": ("小米", ""),
    "lumiunited": ("Aqara / 绿米", ""),
    "aqara": ("Aqara / 绿米", ""),
    "tuya": ("涂鸦智能", ""),
    "hangzhou tuya": ("涂鸦智能", ""),
    "yeelight": ("Yeelight / 易来", "bulb"),
    "sonoff": ("Sonoff", ""),
    "itead": ("ITEAD / Sonoff", ""),
    "espressif": ("Espressif / 乐鑫", ""),
    "qingping": ("青萍", ""),
    "roborock": ("石头科技", "vacuum"),
    "dreame": ("追觅", "vacuum"),
    "ecovacs": ("科沃斯", "vacuum"),
    "cloudminds": ("CloudMinds", ""),
    # 视频监控
    "hikvision": ("海康威视", "camera"),
    "ezviz": ("萤石", "camera"),
    "dahua": ("大华股份", "camera"),
    "uniview": ("宇视科技", "camera"),
    "reolink": ("Reolink", "camera"),
    "imou": ("乐橙", "camera"),
    # 手机 / 消费电子
    "huawei": ("华为", ""),
    "honor": ("荣耀", ""),
    "oppo": ("OPPO", ""),
    "vivo": ("vivo", ""),
    "oneplus": ("一加", ""),
    "realme": ("realme", ""),
    "meizu": ("魅族", ""),
    "zte": ("中兴", ""),
    "apple": ("Apple", ""),
    "samsung": ("Samsung / 三星", ""),
    "sony": ("Sony / 索尼", ""),
    "lg elect": ("LG", ""),
    "xiaomi commun": ("小米", ""),
    # 电视 / 影音
    "skyworth": ("创维", "tv"),
    "hisense": ("海信", "tv"),
    "tcl": ("TCL", "tv"),
    "changhong": ("长虹", "tv"),
    "konka": ("康佳", "tv"),
    "haier": ("海尔", ""),
    # 路由 / 网络
    "tp-link": ("TP-Link", "router"),
    "tplink": ("TP-Link", "router"),
    "netgear": ("NETGEAR", "router"),
    "asustek": ("华硕", "router"),
    "d-link": ("D-Link", "router"),
    "xiaomi electric": ("小米", ""),
    "gl-inet": ("GL-iNet", "router"),
    "cudy": ("Cudy", "router"),
    "mikrotik": ("MikroTik", "router"),
    "ubiquiti": ("Ubiquiti", "router"),
    "phicomm": ("斐讯", "router"),
    "mercury": ("水星 / Mercury", "router"),
    "fast": ("迅捷 / FAST", "router"),
    "raspberry": ("Raspberry Pi", ""),
    # 云服务盒子 / 智能音箱
    "amazon tech": ("Amazon", "speaker"),
    "google": ("Google", "speaker"),
    "philips": ("Signify / 飞利浦", "bulb"),
    "signify": ("Signify / 飞利浦", "bulb"),
}

MAC_RE = re.compile(r"^[0-9a-f]{2}[:-]?[0-9a-f]{2}[:-]?[0-9a-f]{2}")


def normalize_prefix(raw: str) -> str:
    """把各种写法的 MAC 前缀归一化成 xx:xx:xx（只取前三字节）。"""
    s = raw.strip().lower().replace("-", ":")
    # IEEE oui.csv 的 Assignment 字段是 6 个连续 hex：AABBCC
    if ":" not in s and re.fullmatch(r"[0-9a-f]{6}", s):
        return f"{s[0:2]}:{s[2:4]}:{s[4:6]}"
    # manuf 可能是 XX:XX:XX 甚至更长（含 /xx 掩码）
    m = MAC_RE.match(s)
    if not m:
        return ""
    head = re.findall(r"[0-9a-f]{2}", s[:8])
    if len(head) < 3:
        return ""
    return ":".join(head[:3])


# 短关键字（≤4 字符）容易误伤：如 "fast" 会命中任何含 fast 的厂商名。
# 这类 key 要求「全词匹配」，不得作为子串。
_SHORT_KEY_RE_CACHE: dict[str, re.Pattern] = {}


def match_wanted(vendor: str, include_chip: bool = False) -> tuple[str, str] | None:
    v = vendor.lower().strip()
    table = dict(WANTED)
    if include_chip:
        table.update(CHIP_VENDORS)
    for key, val in table.items():
        if len(key) <= 4 and "-" not in key:
            pat = _SHORT_KEY_RE_CACHE.get(key)
            if pat is None:
                pat = re.compile(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])")
                _SHORT_KEY_RE_CACHE[key] = pat
            if pat.search(v):
                return val
        elif key in v:
            return val
    return None


def read_ieee_csv(text: str) -> dict[str, str]:
    """解析 IEEE oui.csv：Registry,Assignment,Organization Name,Organization Address"""
    out: dict[str, str] = {}
    reader = csv.reader(text.splitlines())
    for row in reader:
        if len(row) < 3:
            continue
        assignment, org = row[1].strip(), row[2].strip()
        prefix = normalize_prefix(assignment)
        if prefix and org and prefix not in out:
            out[prefix] = org
    return out


def read_manuf(text: str) -> dict[str, str]:
    """解析 Wireshark manuf：prefix<TAB>vendor<TAB># comment"""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        prefix = normalize_prefix(parts[0])
        vendor = parts[1].strip().lstrip("#").strip()
        if prefix and vendor and prefix not in out:
            out[prefix] = vendor
    return out


def download(url: str) -> tuple[str, str]:
    """下载源数据，返回 (文本, 解析器名)。自动处理 gzip。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=180, context=ctx) as resp:
        raw = resp.read()
    if raw[:2] == b"\x1f\x8b":  # gzip magic
        raw = gzip.decompress(raw)
    text = raw.decode("utf-8", errors="replace")
    first = text.splitlines()[0].lower() if text.splitlines() else ""
    # 自动判别格式：IEEE oui.csv 首行含 assignment；manuf 是注释块
    return (text, "ieee" if "assignment" in first else "manuf")


def main() -> int:
    ap = argparse.ArgumentParser(description="生成家卫精简 OUI 厂商表")
    ap.add_argument("--source", help="本地源数据路径（IEEE oui.csv 或 Wireshark manuf）")
    ap.add_argument("--from", dest="origin", default="wireshark",
                    choices=sorted(DOWNLOAD_SOURCES),
                    help="在线来源：wireshark（默认，可直接下载）/ ieee（可能 418 反爬）")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="输出 CSV 路径")
    ap.add_argument("--all", action="store_true", help="不做白名单过滤（导出全量，体积大）")
    ap.add_argument("--include-chip-vendors", action="store_true",
                    help="额外收录芯片方案商（Realtek/MediaTek 等），会显著增大表体")
    args = ap.parse_args()

    if args.source:
        p = Path(args.source)
        if not p.is_file():
            print(f"源文件不存在：{p}", file=sys.stderr)
            return 1
        text = p.read_text(encoding="utf-8", errors="replace")
        first = text.splitlines()[0].lower() if text.splitlines() else ""
        raw = read_ieee_csv(text) if "assignment" in first else read_manuf(text)
        used = args.source
    else:
        url, _parser = DOWNLOAD_SOURCES[args.origin]
        print(f"下载 {url} ...")
        try:
            text, parser = download(url)
        except Exception as e:
            print(f"下载失败：{type(e).__name__} {e}", file=sys.stderr)
            if args.origin == "ieee":
                print("IEEE 站点常有反爬（418）。请浏览器下载后改用 --source 导入，"
                      "或换默认源 wireshark。", file=sys.stderr)
            return 1
        raw = read_ieee_csv(text) if parser == "ieee" else read_manuf(text)
        used = url

    print(f"源数据条目：{len(raw)}")

    rows = []
    for prefix, vendor in raw.items():
        hit = match_wanted(vendor, include_chip=args.include_chip_vendors)
        if args.all:
            cn, hint = "", ""
            rows.append((prefix, vendor, cn, hint))
        elif hit:
            cn, hint = hit
            rows.append((prefix, vendor, cn, hint))

    rows.sort(key=lambda r: r[0])
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        f.write("# 家卫 · MAC 厂商（OUI）精简表\n")
        f.write(f"# 生成方式: python tools/build_oui_table.py"
                f" {'--source ' + used if args.source else '--from ' + args.origin}"
                f"{' --all' if args.all else ''}\n")
        f.write(f"# 数据来源: {used}\n")
        f.write(f"# 过滤策略: {'全量导出' if args.all else '家庭 / 国产设备厂商白名单'}\n")
        f.write("# 字段: prefix,vendor,vendor_cn,device_hint\n")
        f.write("# 说明: device_hint 只在厂商几乎只做该品类时才填，其余留空 —— 不猜。\n")
        w = csv.writer(f)
        w.writerow(["prefix", "vendor", "vendor_cn", "device_hint"])
        w.writerows(rows)

    print(f"已写出 {len(rows)} 条 → {out_path}")
    print("提示：把产物 commit 进仓库后，设备识别才能显示厂商名。"
          "未加载该表时家卫会在盲区里明示「厂商未知」，不会瞎猜。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
