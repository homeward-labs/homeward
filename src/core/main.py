"""
家卫 — 核心服务入口

架构:
  collectors (采集层) → analyzer (分析层) → engine (决策层) → actions (动作层)
"""

import asyncio
import json
import logging
import signal
from dataclasses import asdict
from pathlib import Path
from typing import Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("homeward")

# 项目根目录
SRC_DIR = Path(__file__).resolve().parent.parent  # src/ 目录（main.py 在 src/core/ 下，parent.parent = src/）
KB_DIR = SRC_DIR / "knowledge_base"
ROOT = SRC_DIR.parent

# 导入各模块
import sys
sys.path.insert(0, str(SRC_DIR))

from rule_engine.engine import (
    KnowledgeBase,
    BehaviorMatcher,
    DecisionEngine,
    FlowRecord,
    Decision,
)
from ai.analyzer import AIAnalyzer, AnalysisRequest, AnalysisResult
from knowledge_base.updater import KnowledgeBaseUpdater


class IoTSentinel:
    """家卫 主服务"""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.kb = KnowledgeBase(str(KB_DIR))
        self.behavior_matcher = BehaviorMatcher(str(KB_DIR / "behaviors.json"))
        self.engine = DecisionEngine(self.kb, self.behavior_matcher)

        # AI 分析器（默认关闭）
        self.ai = AIAnalyzer(
            backend=self.config.get("ai_backend", "none"),
            api_key=self.config.get("ai_api_key"),
            base_url=self.config.get("ai_base_url"),
        )

        # 知识库更新器
        self.kb_updater = KnowledgeBaseUpdater(
            kb_dir=str(KB_DIR),
            auto_update=self.config.get("kb_auto_update", True),
            interval=self.config.get("kb_update_interval", 604800),
        )

        # 阻断规则存储
        self.block_rules: list[dict] = []

        # 统计
        self.stats = {
            "flows_processed": 0,
            "decisions_made": 0,
            "blocks_active": 0,
            "unknown_domains": set(),
        }

        logger.info(f"家卫 initialized with {len(self.kb.domains)} domain rules")

    async def start(self):
        """启动服务"""
        logger.info("Starting 家卫...")

        # 启动知识库更新
        self.kb_updater.start()

        # 加载已有阻断规则
        self._load_block_rules()

        # 注册信号处理
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        logger.info("家卫 started successfully")

    async def stop(self):
        """停止服务"""
        logger.info("Stopping 家卫...")
        self.kb_updater.stop()
        self._save_block_rules()
        logger.info("家卫 stopped")

    def process_flow(self, flow: FlowRecord) -> Decision:
        """
        处理一条流量记录
        这是核心入口，被采集层调用
        """
        self.stats["flows_processed"] += 1

        decision = self.engine.evaluate(flow)
        self.stats["decisions_made"] += 1

        if decision.action == "unknown" and flow.sni:
            self.stats["unknown_domains"].add(flow.sni)

        # 执行决策
        if decision.action.startswith("block"):
            self._apply_block(flow, decision)

        return decision

    def _apply_block(self, flow: FlowRecord, decision: Decision):
        """执行阻断"""
        # 实际实现中这里调用 nftables / iptables
        # 这里只记录日志
        hit = decision.rule_hits[0] if decision.rule_hits else None
        rule = {
            "domain": flow.sni or flow.dns_query,
            "device": flow.src_ip,
            "level": decision.action,
            "reason": decision.reason,
            "source": hit.rule_type if hit else "manual",
        }
        self.block_rules.append(rule)
        self.stats["blocks_active"] += 1
        logger.info(f"[BLOCK] {rule['domain']} → {decision.reason}")

    def request_ai_analysis(self, domain: str, behavior: dict) -> Optional[AnalysisResult]:
        """
        用户手动触发的 AI 分析
        """
        if not self.ai.is_enabled():
            logger.warning("AI analyzer is not enabled. Please configure backend first.")
            return None

        request = AnalysisRequest(
            domain=domain,
            total_connections=behavior.get("total_connections", 0),
            total_bytes=behavior.get("total_bytes", 0),
            time_span_hours=behavior.get("time_span_hours", 0),
            avg_interval_seconds=behavior.get("avg_interval_seconds", 0),
            destination_asn=behavior.get("asn"),
            destination_country=behavior.get("country"),
        )

        result = self.ai.analyze(request)
        if result:
            logger.info(f"[AI] {domain} → {result.predicted_organization} ({result.category}, {result.confidence})")
        return result

    def confirm_ai_result(self, result: AnalysisResult) -> bool:
        """
        用户确认 AI 分析结果后，回灌到知识库
        生成一条可审核的规则草稿
        """
        # 写入待审核目录（人工 review 后合入主库）
        pending_dir = KB_DIR / "pending"
        pending_dir.mkdir(exist_ok=True)

        rule = {
            "domain": result.domain,
            "organization": result.predicted_organization,
            "category": result.category,
            "confidence": result.confidence,
            "description": result.explanation,
            "action": result.suggested_action,
            "side_effects": result.side_effects,
        }

        fname = pending_dir / f"{result.domain}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(rule, f, ensure_ascii=False, indent=2)

        logger.info(f"[AI] Result saved to pending: {fname}")
        return True

    def get_unknown_domains(self) -> list[str]:
        """获取所有未识别域名"""
        return sorted(self.stats["unknown_domains"])

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            **self.stats,
            "unknown_domains_count": len(self.stats["unknown_domains"]),
            "unknown_domains": sorted(self.stats["unknown_domains"]),
        }

    def _load_block_rules(self):
        """加载已有阻断规则"""
        rules_file = ROOT / "data" / "block_rules.json"
        if rules_file.exists():
            with open(rules_file, encoding="utf-8") as f:
                self.block_rules = json.load(f)
            self.stats["blocks_active"] = len(self.block_rules)

    def _save_block_rules(self):
        """保存阻断规则"""
        rules_file = ROOT / "data" / "block_rules.json"
        rules_file.parent.mkdir(exist_ok=True)
        with open(rules_file, "w", encoding="utf-8") as f:
            json.dump(self.block_rules, f, ensure_ascii=False, indent=2)

    def _signal_handler(self, signum, frame):
        """信号处理器"""
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(self.stop())


# ==================== 演示 ====================

if __name__ == "__main__":
    sentinel = IoTSentinel()

    # 模拟流量
    test_flows = [
        FlowRecord(
            timestamp=1705316400, src_ip="192.168.1.100", dst_ip="203.0.113.1",
            dst_port=443, protocol="tcp", sni="api.ad.tuya.com",
            dns_query="api.ad.tuya.com", packet_size=1500, direction="out",
        ),
        FlowRecord(
            timestamp=1705316401, src_ip="192.168.1.101", dst_ip="203.0.113.2",
            dst_port=443, protocol="tcp", sni="ot.io.mi.com",
            dns_query="ot.io.mi.com", packet_size=200, direction="out",
        ),
        FlowRecord(
            timestamp=1705316402, src_ip="192.168.1.102", dst_ip="203.0.113.3",
            dst_port=443, protocol="tcp", sni="unknown-tracking-domain.xyz",
            dns_query="unknown-tracking-domain.xyz", packet_size=64, direction="out",
        ),
    ]

    print("=" * 70)
    print("家卫 — 核心服务演示")
    print("=" * 70)

    for flow in test_flows:
        decision = sentinel.process_flow(flow)
        print(f"\n📡 {flow.sni}")
        print(f"   决策: [{decision.action}] {decision.reason}")
        if decision.requires_user_input:
            print(f"   💡 可点击「帮我分析」进行 AI 辅助分析")

    print(f"\n{'=' * 70}")
    print(f"📊 统计: {json.dumps(sentinel.get_stats(), ensure_ascii=False, indent=2)}")

    # AI 分析演示（模拟）
    print(f"\n{'=' * 70}")
    print("AI 分析演示（需配置 backend）")
    print("=" * 70)

    result = sentinel.request_ai_analysis(
        "unknown-tracking-domain.xyz",
        {
            "total_connections": 1440,
            "total_bytes": 50000,
            "time_span_hours": 24,
            "avg_interval_seconds": 60,
            "asn": "AS13335",
            "country": "US",
        },
    )

    if result:
        print(f"  域名: {result.domain}")
        print(f"  归属: {result.predicted_organization}")
        print(f"  类型: {result.category}")
        print(f"  置信度: {result.confidence}")
        print(f"  解释: {result.explanation}")
        print(f"  建议: {result.suggested_action}")
        if result.side_effects:
            print(f"  影响: {result.side_effects}")
    else:
        print("  AI 未启用（默认关闭）。需在配置中设置 ai_backend 和 api_key。")
        print("  支持后端: ollama (本地) / openai (自备 API Key)")
