"""
W2 —— 域名归属：回答「这条外联是发给谁的」（社区版开源范围）

为什么单独一层
--------------
`src/knowledge_base/domains.csv` 是一张人工维护的知识表，
「怎么查」这件事本身值得封装：清洗、缓存、向上匹配、覆盖率统计都在这一层，
上层（规则引擎 / UI / 告警文案）只需要问一句 `resolve()`。

匹配策略
--------
1. **精确匹配**：`ot.io.mi.com` 直接命中表里同名条目，置信度不加不减。
2. **逐级向上**：`x.y.ot.io.mi.com` → `y.ot.io.mi.com` → `ot.io.mi.com`。
   向上最多走到「可注册域名」（eTLD+1），**绝不继续匹配到 `com` 这种纯后缀** ——
   否则任何未知域名都会被归给某条恰好是短域名的规则，那是在制造假信息。
3. **认输**：全都匹配不上就返回 unknown，不猜、不模糊匹配相似域名。

为什么要缓存
------------
家庭网络里同一个域名每分钟被问几十次；Tier 1 采集量大，
重复解析（含字符串切分与字典查找）会成为热点。加一层带上限的缓存。

> 未知不是失败，是**待补的知识**。resolve() 返回 unknown 时，
> 上层应把它交给「未知域名」列表，等待用户手动触发 AI 分析（默认关闭）。
"""

import csv
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

DEFAULT_DOMAINS_CSV = Path(__file__).resolve().parent.parent / "knowledge_base" / "domains.csv"

# 多级后缀（写全才会把 registrable 算成三段，如 example.com.cn）
MULTI_SUFFIXES = frozenset({
    "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw",
    "co.jp", "ne.jp", "or.jp", "co.kr", "com.au", "com.br", "co.in", "com.mx",
    "co.nz", "com.sg", "com.tr",
})
# 常见单级后缀；这里只用来判断「再往上一级就是纯后缀了，停」
GENERIC_SUFFIXES = frozenset({
    "com", "net", "org", "cn", "io", "cc", "xyz", "info", "dev", "app",
    "cloud", "top", "tv", "me", "gov", "edu", "biz", "link", "online",
    "site", "store", "tech", "ai", "co", "so", "sh", "pro", "one", "ltd",
})

_UNKNOWN_CATEGORY = "unknown"
_NO_CONFIDENCE = "none"


@dataclass
class AttributionResult:
    """一次归属查询的结果"""
    domain: str                       # 规范化后的查询域名
    organization: Optional[str]       # 归属组织，未知为 None
    category: str                     # IoT_core / analytics / advertising_sdk ...
    confidence: str                   # high / medium / low / none
    description: str = ""
    action: str = "allow"             # **建议**动作；是否真的拦截永远由用户决定
    side_effects: list[str] = field(default_factory=list)
    matched_domain: Optional[str] = None   # 实际命中的那条规则（可能是父域名）
    matched_by: str = "none"               # exact / parent / none

    @property
    def known(self) -> bool:
        return self.matched_domain is not None

    @property
    def is_infrastructure(self) -> bool:
        """CDN / 云存储这类基础设施：归属仍然成立，但不应据此判定设备行为异常"""
        return self.category in ("cdn", "cloud_storage")

    def explain(self) -> str:
        """给 UI 用的一句话解释 —— 家卫要求判定可解释"""
        if not self.known:
            return f"{self.domain}：知识库中没有归属记录（未知域名）"
        tail = ""
        if self.side_effects:
            tail = f"；拦下的话：{'、'.join(self.side_effects)}"
        return (f"{self.domain} 属于 {self.organization}"
                f"（{self.category}，置信度 {self.confidence}）{tail}")


@dataclass
class CoverageReport:
    """一批域名的归属覆盖率 —— 衡量知识库够不够用"""
    total: int = 0
    hit: int = 0
    by_parent: int = 0
    unknown: list[str] = field(default_factory=list)

    @property
    def rate(self) -> float:
        return 0.0 if not self.total else round(self.hit / self.total, 4)

    def summary(self) -> str:
        return (f"归属覆盖率 {self.hit}/{self.total} = {self.rate:.1%}"
                f"（其中 {self.by_parent} 条靠父域名兜上）")


def normalize_domain(raw: str) -> str:
    """小写、去尾点、去空格与协议/端口残留。空或非法返回空串。"""
    if not raw:
        return ""
    d = raw.strip().lower().rstrip(".")
    # 极端情况下数据源会给带端口或协议的串，做保守清理
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split(":")[0]
    return d


def registrable_domain(domain: str) -> str:
    """
    求可注册域名（eTLD+1），作为向上匹配的**下限**。

    这里用一张有限后缀表而非引入 PSL —— 引入完整 Public Suffix List
    会显著增加体积与维护成本，与「低配设备常驻」的定位冲突。
    遇到表里没有的多级后缀会退化为二维�断，最坏情况是少匹配一级，不会误报。
    """
    labels = [l for l in domain.split(".") if l]
    if len(labels) < 2:
        return domain
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _parent_candidates(domain: str) -> list[str]:
    """
    生成从完整域名到可注册域名的所有候选，**不含纯后缀**。

    例：`abc.track.io.mi.com` → [abc.track.io.mi.com, track.io.mi.com, io.mi.com, mi.com]
    停在 mi.com：再往上一级是 `com`，拿纯后缀去匹配规则等于制造假归属，禁止。
    """
    labels = [l for l in domain.split(".") if l]
    if len(labels) < 2:
        return [domain] if domain == registrable_domain(domain) else []
    floor = registrable_domain(domain)
    cands: list[str] = []
    for i in range(len(labels) - 1):  # 最多剥到剩两个标签，永远碰不到单标签后缀
        cand = ".".join(labels[i:])
        if len(cand.split(".")) < 2:
            break
        cands.append(cand)
        if cand == floor:
            break
    return cands


class DomainAttribution:
    """域名归属查询器"""

    def __init__(self, csv_path: Optional[Path] = None, cache_size: int = 4096):
        self.csv_path = Path(csv_path) if csv_path else DEFAULT_DOMAINS_CSV
        self.cache_size = cache_size
        self._rules: dict[str, dict] = {}
        self._cache: dict[str, AttributionResult] = {}
        self.stats = {"queries": 0, "cache_hits": 0, "exact": 0, "parent": 0, "miss": 0}
        self.load()

    # ---------- 加载 ----------

    def load(self) -> int:
        """
        加载知识库。**表里没有数据就抛错** ——
        静默加载成空表会让所有域名都变成 unknown 而不报错，是很难排查的假故障。
        """
        if not self.csv_path.is_file():
            raise FileNotFoundError(f"归属知识库不存在：{self.csv_path}")
        rules: dict[str, dict] = {}
        with open(self.csv_path, encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                d = normalize_domain(row.get("domain", ""))
                if not d:
                    continue
                if d in rules:
                    logger.warning("知识库重复条目 %s，保留后出现的一条", d)
                rules[d] = {
                    "organization": (row.get("organization") or "").strip() or None,
                    "category": (row.get("category") or _UNKNOWN_CATEGORY).strip(),
                    "confidence": (row.get("confidence") or _NO_CONFIDENCE).strip(),
                    "description": (row.get("description") or "").strip(),
                    "action": (row.get("action") or "allow").strip(),
                    "side_effects": _split_side_effects(row.get("side_effects") or ""),
                }
        if not rules:
            raise ValueError(f"归属知识库为空：{self.csv_path}（加载到 0 条规则）")
        self._rules = rules
        self._cache.clear()
        return len(rules)

    # ---------- 查询 ----------

    def resolve(self, domain: str) -> AttributionResult:
        self.stats["queries"] += 1
        norm = normalize_domain(domain)
        if not norm:
            return self._unknown("")
        if norm in self._cache:
            self.stats["cache_hits"] += 1
            return self._cache[norm]

        result = self._lookup(norm)
        if len(self._cache) >= self.cache_size:
            self._cache.clear()  # 简单换页：家庭场景域名基数有限，全清代价可接受
        self._cache[norm] = result
        return result

    def resolve_many(self, domains: Iterable[str]) -> dict[str, AttributionResult]:
        return {d: self.resolve(d) for d in domains}

    def resolved_view(self) -> list[dict]:
        """已解析过的域名快照（缓存内容），给 UI 的「去向」视图用

        注意这是**查过的**域名，不是全部见过的域名：缓存有上限且满了会整体清空，
        所以它只能用来展示「当前已知去向」，不能当作统计口径。
        """
        out = []
        for domain, r in sorted(self._cache.items()):
            out.append({
                "domain": r.domain,
                "organization": r.organization,
                "category": r.category,
                "confidence": r.confidence,
                "known": r.known,
                "matched_by": r.matched_by,
                "side_effects": r.side_effects,
                "explain": r.explain(),
            })
        return out

    def coverage(self, domains: Iterable[str]) -> CoverageReport:
        rep = CoverageReport()
        for d in domains:
            r = self.resolve(d)
            rep.total += 1
            if r.known:
                rep.hit += 1
                if r.matched_by == "parent":
                    rep.by_parent += 1
            else:
                rep.unknown.append(r.domain)
        return rep

    # ---------- 内部 ----------

    def _lookup(self, domain: str) -> AttributionResult:
        hit = self._rules.get(domain)
        if hit:
            self.stats["exact"] += 1
            return self._build(domain, hit, domain, "exact")

        for cand in _parent_candidates(domain)[1:]:
            hit = self._rules.get(cand)
            if hit:
                self.stats["parent"] += 1
                return self._build(domain, hit, cand, "parent")

        self.stats["miss"] += 1
        return self._unknown(domain)

    def _build(self, domain: str, rule: dict, matched: str, by: str) -> AttributionResult:
        return AttributionResult(
            domain=domain,
            organization=rule["organization"],
            category=rule["category"],
            confidence=rule["confidence"],
            description=rule["description"],
            action=rule["action"],
            side_effects=list(rule["side_effects"]),
            matched_domain=matched,
            matched_by=by,
        )

    @staticmethod
    def _unknown(domain: str) -> AttributionResult:
        return AttributionResult(
            domain=domain,
            organization=None,
            category=_UNKNOWN_CATEGORY,
            confidence=_NO_CONFIDENCE,
            action="allow",
            matched_by="none",
        )


def _split_side_effects(raw: str) -> list[str]:
    """side_effects 用中文分号分隔；空单元格返回空列表"""
    parts = re.split(r"[;；]", raw)
    return [p.strip() for p in parts if p.strip()]
