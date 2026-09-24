"""
能力协商助手 —— CapabilitySet

把 ``Capabilities`` 的能力位翻译成：
  · can_show(field)     首页「能不能展示某采集字段」
  · can_enforce(level)  决策层「能不能做某级阻断」
  · blind_spots()       直接生成 D22「首页明示盲区」文案

本文件属于「Capabilities 协商层」，是 ``base.py`` 之上的薄封装；**不实现任何具体
Collector / Enforcer**，也不依赖任何平台代码。导入风格与项目既有约定保持一致
（顶层包目录在 sys.path 上，使用 ``from adapters.base import ...`` 的扁平导入）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from adapters.base import Capabilities


@dataclass
class CapabilitySet:
    """围绕某个适配器（或整套部署形态）能力的查询助手"""

    caps: Capabilities

    # 采集侧字段名 → Capabilities 对应能力位
    _SHOW_FIELDS = {
        "dns_query": "dns_query",
        "flow_bytes": "flow_bytes",
        "sni": "sni",
        "timing": "timing",
    }

    # 执行侧级别名 → Capabilities 对应能力位
    _ENFORCE_LEVELS = {
        "soft": "enforce_soft",
        "medium": "enforce_medium",
        "hard": "enforce_hard",
    }

    def can_show(self, field: str) -> bool:
        """首页能否展示该采集字段（field ∈ dns_query / flow_bytes / sni / timing）"""
        attr = self._SHOW_FIELDS.get(field)
        if attr is None:
            raise ValueError(f"未知采集字段: {field}")
        return getattr(self.caps, attr)

    def can_enforce(self, level: str) -> bool:
        """能否执行该级别阻断（level ∈ soft / medium / hard）"""
        attr = self._ENFORCE_LEVELS.get(level)
        if attr is None:
            raise ValueError(f"未知阻断级别: {level}")
        return getattr(self.caps, attr)

    def blind_spots(self) -> list[str]:
        """生成 D22「首页明示盲区」文案：逐条列出当前部署形态看不到 / 拦不住的地方"""
        spots: list[str] = []
        if not self.caps.dns_query:
            spots.append("无法观测 DNS 查询：仅凭 IP / ASN 判断，域名级归因会漏判。")
        if not self.caps.sni:
            spots.append("无法观测 TLS SNI：加密域名的上联目标不可见，可能漏判。")
        if not self.caps.flow_bytes:
            spots.append("无法观测 flow 字节数：突发大流量上传（bulk_upload）类行为无法判定。")
        if not self.caps.timing:
            spots.append("无法观测包间时序：心跳信标等周期性行为层特征无法判定。")
        if not self.caps.enforce_soft:
            spots.append("无法做 DNS 级软阻断：广告 / 统计类域名只能告警，不能拦截。")
        if not self.caps.enforce_medium:
            spots.append("无法做网段 / ASN 级中阻断：无法整片隔离某厂商辅助服务。")
        if not self.caps.enforce_hard:
            spots.append("无法做 VLAN 隔离硬阻断：需交换机 / OpenWrt 配置权，当前部署形态不具备。")
        return spots
