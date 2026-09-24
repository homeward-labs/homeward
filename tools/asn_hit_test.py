#!/usr/bin/env python3
"""
ASN Lite 命中率测试 harness
==========================

目的：回答「DB-IP ASN Lite 能否承担国产 IoT 域名的归属层」，
      从而决定是否需要立项自建国产归属库。

决策阈值（先定死，避免事后解释）：
    语义准确率 >= 70%  -> ASN 可作兜底展示
    语义准确率 50~70%  -> 仅在「未知域名」卡片作次要信息
    语义准确率 <  50%  -> 不展示；立项自建国产归属库

⚠️ POPULATION CAVEAT（人口口径，最容易出假数字的地方）
--------------------------------------
ASN 在生产上只有一个用途：**域名查不到时兜底**。
domains.csv 里的 104 条我们【已有自己的归属标注】，永远轮不到 ASN 出场。
所以拿 domains.csv 当测试集只能验证管道连通，
**测出来的准确率不代表真实场景** —— 真实人口是「不在 domains.csv 里的未知域名」。
正确用法：竞析提供未知域名清单 + 人工标注 ground truth，再用本脚本测。

⚠️ 执行前必读：三个会产生假数字的陷阱
--------------------------------------
1. ASN Lite 是 IP -> ASN，不是 domain -> ASN。必须先解析域名拿 IP，再查 ASN。
2. 【致命】CDN/GSLB 按来源地域返回不同 IP。
   **必须在中国大陆境内网络执行**，否则国产域名会解析到境外节点，
   得到错误的 ASN，整套数字作废。脚本会要求你声明 --vantage。
3. 技术命中率 != 语义准确率，必须分开测：
   - 技术命中率：能否查到 ASN 记录
   - 语义准确率：ASN 组织名是否 == 域名真实的业务运营方  <- 这个才决定 UX
   例：ot.io.mi.com 若托管在阿里云，ASN 会说 "Alibaba Cloud" 而非 "Xiaomi"
   -> 技术命中但语义错误。

用法：
    # 1) 下载 DB-IP ASN Lite（CC BY 4.0，免费，月更）
    #    https://db-ip.com/db/download/ip-to-asn-lite
    # 2) 在【中国大陆境内】执行：
    python tools/asn_hit_test.py \
        --domains src/knowledge_base/domains.csv \
        --asn-db dbip-asn-lite-2026-08.mmdb \
        --vantage "中国大陆/家宽" \
        --out asn_hit_result.json

    # 仅做管道自检（不用于决策）：
    python tools/asn_hit_test.py --domains src/knowledge_base/domains.csv \
        --asn-db <path> --vantage "境外/仅自检" --self-test-only

依赖：
    MMDB: pip install maxminddb     （可选，推荐）
    CSV : 无依赖
"""

import argparse
import csv
import ipaddress
import json
import socket
import sys
from bisect import bisect_right
from pathlib import Path


# ---------------------------------------------------------------- 组织名归一化

ALIAS = {
    "alibaba": {"alibaba", "alibaba cloud", "alibaba.com", "aliyun",
                "alibaba us technology", "alibaba cloud computing"},
    "tencent": {"tencent", "tencent cloud", "tencent technology",
                "shenzhen tencent", "qcloud"},
    "huawei": {"huawei", "huawei cloud", "huawei technologies",
               "huawei cloud computing"},
    "baidu": {"baidu", "baidu cloud", "beijing baidu"},
    "xiaomi": {"xiaomi", "beijing xiaomi", "xiaomi technology"},
    "tuya": {"tuya", "tuya smart", "hangzhou tuya"},
    "tp-link": {"tp-link", "tplink", "tp-link technologies"},
    "hikvision": {"hikvision", "ezviz", "hangzhou hikvision"},
    "dahua": {"dahua", "zhejiang dahua"},
    "360": {"qihoo 360", "qihoo", "360", "beijing qihoo"},
}

CANON = {}
for canon, variants in ALIAS.items():
    for v in variants:
        CANON[v] = canon


def norm_org(s: str) -> str:
    """归一化组织名，便于比较"""
    s = (s or "").strip().lower()
    for junk in (" co., ltd.", " ltd.", " inc.", " llc.", " limited",
                 " technology", " technologies", " (beijing)", " beijing",
                 " shenzhen", " hangzhou", " zhejiang"):
        s = s.replace(junk, "")
    s = " ".join(s.split())
    return CANON.get(s, s)


def org_match(expected: str, got: str) -> str:
    """返回 exact / alias / partial / miss —— 保守判定，宁可判 miss"""
    e, g = norm_org(expected), norm_org(got)
    if not e or not g:
        return "miss"
    if e == g:
        return "exact"
    if e in g or g in e:
        return "partial"
    return "miss"


# ---------------------------------------------------------------- ASN 库加载

class ASNIndex:
    def __init__(self, path: str):
        self.path = Path(path)
        self.kind = "mmdb" if self.path.suffix == ".mmdb" else "csv"
        if self.kind == "mmdb":
            import maxminddb  # noqa
            self.reader = maxminddb.open_database(str(self.path))
            self.starts = None
        else:
            self.reader = None
            self.starts, self.rows = [], []
            with open(self.path, encoding="utf-8") as f:
                for row in csv.reader(f):
                    if len(row) < 4:
                        continue
                    self.starts.append(int(row[0]))
                    self.rows.append((int(row[1]), f"AS{row[2]}", row[3]))

    def lookup(self, ip: str):
        """返回 (asn, org) 或 None"""
        try:
            ip_int = int(ipaddress.ip_address(ip))
        except ValueError:
            return None
        if self.kind == "mmdb":
            rec = self.reader.get(ip)
            if not rec:
                return None
            org = rec.get("organization") or rec.get("as_organization") or ""
            asn = rec.get("autonomous_system_number")
            return (f"AS{asn}" if asn else "", org) if org else None
        i = bisect_right(self.starts, ip_int) - 1
        if i < 0:
            return None
        ip_to, asn, org = self.rows[i]
        return (asn, org) if ip_int <= ip_to else None

    def close(self):
        if self.reader:
            self.reader.close()


# ---------------------------------------------------------------- 主流程

# 三组划分（竞析提出，组 3 为我最初遗漏）
#   组 1 大厂自有 ASN   —— 检验 ASN 库上限
#   组 2 上云设备厂商   —— 预判「技术命中但语义错误」
#   组 3 CDN/OTA/公共基础设施 —— 预判「答成 CDN」，且它是行为层主场
# 先验权重（竞析按典型中国家庭 20 台设备估算）——【先验，非实测，待验证】
PRIOR_WEIGHTS = {"g1": 0.25, "g2": 0.50, "g3": 0.25}

_G3_ORG = {"jsdelivr", "cloudflare", "pool project", "tsinghua university"}
_G3_KW = ("cdn", "ota", "upgrade", "firmware", "ntp", "unpkg", "jsdelivr")
_G1_ORG = {"xiaomi", "huawei", "tencent cloud", "alibaba cloud", "baidu",
           "tencent", "qihoo 360"}


def classify_group(domain: str, org: str, category: str) -> str:
    """启发式分组（粗略）。精确分组请用 --groups 覆盖文件。
    覆盖文件格式：每行 `domain,group`，group ∈ g1|g2|g3"""
    o = norm_org(org)
    d = domain.lower()
    if category in ("cdn", "telemetry") or o in _G3_ORG or any(k in d for k in _G3_KW):
        return "g3"
    return "g1" if o in _G1_ORG else "g2"


def load_domains(path: str, override: str = None):
    """从 domains.csv 读取 (domain, expected_org, category, group)
    —— 该文件自带 organization 标注，可直接作为 ground truth

    ⚠️ 重要的人口口径警告（见文件头 POPULATION CAVEAT）：
    domains.csv 里的域名我们【已有自己的语义标注】，生产环境根本不会用 ASN 去归因。
    用它做种子集只能验证管道可用，不能代表真实使用场景。
    真实人口应为「不在 domains.csv 里的未知域名」，需由竞析补清单并人工标注。
    """
    over = {}
    if override:
        with open(override, encoding="utf-8") as f:
            for line in f:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 2 and parts[0]:
                    over[parts[0]] = parts[1]
    out = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(l for l in f if not l.strip().startswith("#")):
            d = (row.get("domain") or "").strip()
            if not d or "*" in d:
                continue
            org = row.get("organization", "").strip()
            cat = row.get("category", "").strip()
            out.append((d, org, cat, over.get(d) or classify_group(d, org, cat)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domains", default="src/knowledge_base/domains.csv")
    ap.add_argument("--asn-db", required=True, help="dbip-asn-lite .mmdb 或 .csv")
    ap.add_argument("--vantage", required=True,
                    help="执行网络视角，例如 '中国大陆/家宽'。境外结果不可用于决策。")
    ap.add_argument("--groups", default=None,
                    help="分组覆盖文件：每行 `domain,g1|g2|g3`（启发式分组不准时用）")
    ap.add_argument("--out", default="asn_hit_result.json")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--self-test-only", action="store_true",
                    help="仅验证管道可用，明确标注不可用于决策")
    args = ap.parse_args()

    mainland = ("中国" in args.vantage) and ("境外" not in args.vantage)
    if not mainland and not args.self_test_only:
        print("❌ 拒绝执行：--vantage 未声明中国大陆境内。\n"
              "   CDN/GSLB 会按来源地域返回不同 IP，境外解析会得到错误 ASN，\n"
              "   整套数字作废。请在中国大陆境内网络执行，\n"
              "   或显式加 --self-test-only 声明仅做管道自检。", file=sys.stderr)
        sys.exit(2)

    domains = load_domains(args.domains, args.groups)
    if args.limit:
        domains = domains[: args.limit]

    idx = ASNIndex(args.asn_db)
    results = []
    for domain, expected_org, category, group in domains:
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None)})
        except Exception:
            ips = []
        hits = []
        for ip in ips:
            r = idx.lookup(ip)
            hits.append({"ip": ip, "asn": r[0] if r else None,
                         "org": r[1] if r else None})
        resolved = [h for h in hits if h["org"]]
        verdict = "unresolved"
        if resolved:
            verdicts = [org_match(expected_org, h["org"]) for h in resolved]
            for v in ("exact", "partial", "miss"):
                if v in verdicts:
                    verdict = v
                    break
        results.append({
            "domain": domain, "expected_org": expected_org, "category": category,
            "group": group, "resolved_ips": hits, "verdict": verdict,
        })

    n = len(results)
    resolved_n = sum(1 for r in results if r["resolved_ips"])

    # ---- 分组统计（主口径），聚合值按先验权重加权后才对阈值 ----
    def rate(rows, pred):
        return round(sum(1 for r in rows if pred(r)) / len(rows), 4) if rows else None

    by_group, weighted = {}, 0.0
    for g in ("g1", "g2", "g3"):
        rows = [r for r in results if r["group"] == g]
        tech = rate(rows, lambda r: r["verdict"] != "unresolved")
        sem = rate(rows, lambda r: r["verdict"] in ("exact", "partial"))
        by_group[g] = {
            "n": len(rows),
            "prior_weight": PRIOR_WEIGHTS[g],
            "tech_hit_rate": tech,
            "semantic_accuracy": sem,
            "miss": sum(1 for r in rows if r["verdict"] == "miss"),
            "unresolved": sum(1 for r in rows if r["verdict"] == "unresolved"),
        }
        if sem is not None:
            weighted += sem * PRIOR_WEIGHTS[g]

    # 未加权聚合仅作参考；判阈值用 weighted
    exact = sum(1 for r in results if r["verdict"] == "exact")
    partial = sum(1 for r in results if r["verdict"] == "partial")
    tech_rate = rate(results, lambda r: r["verdict"] != "unresolved")
    sem_rate = (exact + partial) / n if n else 0

    summary = {
        "vantage": args.vantage,
        "usable_for_decision": mainland and not args.self_test_only,
        "sample_size": n,
        "resolve_success": resolved_n,
        "tech_hit_rate": tech_rate,
        "semantic_accuracy_unweighted": round(sem_rate, 4),
        "semantic_accuracy_weighted": round(weighted, 4),
        "by_group": by_group,
        "prior_weights_are_estimate": True,
        "counting_basis": "distinct-domain（query 频次口径需真实 DNS 日志，本 harness 无法产出）",
        "population_caveat": (
            "domains.csv 内的域名我们已有自有的语义标注，生产上不会用 ASN 归因；"
            "本结果仅验证管道可用。真实人口应为未知域名，需人工标注清单。"),
        "exact": exact, "partial": partial,
        "miss": sum(1 for r in results if r["verdict"] == "miss"),
        "unresolved": sum(1 for r in results if r["verdict"] == "unresolved"),
        # 注意：<50% 分支的补救措施不是「自建 ASN 库」。
        # 若失败模式是「ASN 说 Alibaba Cloud 而实际服务方是涂鸦」，
        # 那 ASN 回答的是【谁的网络】，它没答错，是答了另一个问题。
        # 自建一张 ASN 表复制 DB-IP 的工作修不了它——那个 IP 确实属于阿里云。
        # 正确补救是自建【IP → 业务归属】库，且必须靠域名-IP 关联观测得到
        # （观察到 api.ad.tuya.com 解析到 1.2.3.4，即知该 IP 服务于涂鸦），
        # 而不是去抄 ASN 注册数据。
        # 判阈值用【加权】语义准确率，不是未加权聚合值
        "verdict_for_asn": (
            "兜底展示" if weighted >= 0.70 else
            "仅作未知域名卡片次要信息" if weighted >= 0.50 else
            "不展示；转投 domain 语义层（domains.csv），"
            "必要时自建 IP->业务归属 库（基于域名-IP 关联观测）"),
    }

    Path(args.out).write_text(
        json.dumps({"summary": summary, "details": results},
                   ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\n明细已写入 {args.out}")
    if not summary["usable_for_decision"]:
        print("⚠️ 本次结果【不可用于决策】（境外视角或自检模式）")
    idx.close()


if __name__ == "__main__":
    main()
