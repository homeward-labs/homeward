"""
AI 辅助层
默认关闭，用户手动触发
只分析域名和行为元数据，不上传任何 payload
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class AnalysisRequest:
    """AI 分析请求"""
    domain: str
    organization_hint: Optional[str] = None
    # 行为摘要（不上传原始流量）
    total_connections: int = 0
    total_bytes: int = 0
    time_span_hours: float = 0
    avg_interval_seconds: float = 0
    destination_asn: Optional[str] = None
    destination_country: Optional[str] = None


@dataclass
class AnalysisResult:
    """AI 分析结果"""
    domain: str
    predicted_organization: str
    category: str  # advertising_sdk / analytics / IoT_core / unknown / etc
    confidence: str  # high / medium / low
    explanation: str  # 人话解释
    suggested_action: str  # allow / block_soft / block_medium / block_hard / warn
    side_effects: str = ""  # 阻断后的影响预估


class AIAnalyzer:
    """
    AI 分析器（接口抽象）

    支持两种后端：
    1. 本地 Ollama（用户自己部署）
    2. 用户自备 API Key（OpenAI 兼容接口）
    """

    def __init__(self, backend: str = "none", api_key: str = None, base_url: str = None):
        """
        backend: none | ollama | openai
        api_key: 用户自备 API Key
        base_url: 自定义 API 端点（支持国内中转）
        """
        self.backend = backend
        self.api_key = api_key
        self.base_url = base_url

    def is_enabled(self) -> bool:
        """AI 是否可用"""
        return self.backend != "none"

    def analyze(self, request: AnalysisRequest) -> Optional[AnalysisResult]:
        """
        分析未知域名
        默认不执行，需用户手动调用
        """
        if not self.is_enabled():
            return None

        if self.backend == "ollama":
            return self._analyze_ollama(request)
        elif self.backend == "openai":
            return self._analyze_openai(request)

        return None

    def _build_prompt(self, request: AnalysisRequest) -> str:
        """构建分析提示词（结构化、确定性输出）"""
        return f"""你是一个联网设备流量分析专家。请分析以下域名，判断它属于什么类型的服务。

域名: {request.domain}
ASN: {request.destination_asn or "未知"}
国家: {request.destination_country or "未知"}
连接次数: {request.total_connections}
总流量: {request.total_bytes} bytes
时间跨度: {request.time_span_hours} 小时
平均间隔: {request.avg_interval_seconds} 秒

请严格按以下 JSON 格式输出，不要输出其他内容:
{{
  "predicted_organization": "预测归属组织",
  "category": "服务类型(advertising_sdk/analytics/IoT_core/cdn/telemetry/cloud_storage/machine_learning/unknown)",
  "confidence": "high/medium/low",
  "explanation": "用中文解释这个域名可能是什么服务，为什么",
  "suggested_action": "allow/block_soft/block_medium/block_hard/warn",
  "side_effects": "如果阻断，可能影响什么功能"
}}"""

    def _analyze_ollama(self, request: AnalysisRequest) -> AnalysisResult:
        """调用本地 Ollama"""
        import urllib.request
        import json

        prompt = self._build_prompt(request)
        data = json.dumps({
            "model": "qwen2.5:7b",
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url or 'http://localhost:11434'}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            output = json.loads(result.get("response", "{}"))

        return AnalysisResult(
            domain=request.domain,
            predicted_organization=output.get("predicted_organization", "未知"),
            category=output.get("category", "unknown"),
            confidence=output.get("confidence", "low"),
            explanation=output.get("explanation", ""),
            suggested_action=output.get("suggested_action", "warn"),
            side_effects=output.get("side_effects", ""),
        )

    def _analyze_openai(self, request: AnalysisRequest) -> AnalysisResult:
        """调用 OpenAI 兼容 API"""
        import urllib.request
        import json

        prompt = self._build_prompt(request)
        data = json.dumps({
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "你是联网设备流量分析专家，只输出严格 JSON。"},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
        }).encode()

        req = urllib.request.Request(
            f"{self.base_url or 'https://api.openai.com/v1/chat/completions'}",
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            output = json.loads(result["choices"][0]["message"]["content"])

        return AnalysisResult(
            domain=request.domain,
            predicted_organization=output.get("predicted_organization", "未知"),
            category=output.get("category", "unknown"),
            confidence=output.get("confidence", "low"),
            explanation=output.get("explanation", ""),
            suggested_action=output.get("suggested_action", "warn"),
            side_effects=output.get("side_effects", ""),
        )
