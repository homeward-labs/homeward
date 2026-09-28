"""
verify.py —— 家卫社区版 许可令牌验证（零第三方依赖，仅内嵌公钥）

职责（只读、纯本地、可离线）：
  1. 用内嵌公钥验证许可令牌的 Ed25519 签名（挡住随意伪造 / keygen）。
  2. 校验订阅有效期 valid_until。
  3. 校验设备指纹绑定 device_fp（可选，由调用方传入本机指纹）。
  4. 提供 CRL 吊销名单的本地查询钩子（名单由服务端签发、客户端联网机会性拉取）。

安全约束：
  - 本文件**只含公钥**，绝不含私钥、绝不含任何网络/文件写入。
  - 任何异常一律返回 None（验签失败 = 视为无效），不抛出。
  - 规范化（canonical）必须与签发端完全一致，否则验签必失败。

令牌格式：`base64(json_payload) + "." + base64(ed25519_signature)`
其中 ed25519_signature 是对 `canonical(json_payload)`（密钥排序紧凑 JSON）的签名。
"""

import base64
import json
import os
import time

# 兼容两种运行方式：作为包导入（from license.verify ...）或直接运行。
try:  # 包内导入（src/ 已在 sys.path，server.py 已注入）
    from license.ed25519 import verify_signature
except ImportError:  # 直接运行 / 测试时按文件路径加载
    import importlib.util as _ilu

    _here = os.path.dirname(os.path.abspath(__file__))
    _spec = _ilu.spec_from_file_location("ed25519", os.path.join(_here, "ed25519.py"))
    _mod = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    verify_signature = _mod.verify_signature


# ── 内嵌公钥（Raw 32 字节，Base64）──
# 生产构建时，由闭源构建流程把这里替换成正式公钥（对应 ~/家卫私有/license/ 下的私钥）。
# 当前为**开发用**公钥，仅用于本地联调；上线前必须替换，否则任何人可用开发私钥签发许可。
_DEV_PUBLIC_KEY_B64 = "/ADxAT6LVmMl2ytd8HURTl+1B2S6py7MFUBBKs5uRL8="
PUBLIC_KEY = base64.b64decode(_DEV_PUBLIC_KEY_B64)


def canonical(payload: dict) -> bytes:
    """规范化：按键排序的紧凑 JSON（UTF-8）。必须与签发端逐字节一致。"""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def parse_token(token: str):
    """拆分令牌为 (payload_dict, signature_bytes)，失败返回 (None, None)。"""
    try:
        b64_payload, b64_sig = token.split(".", 1)
        payload = json.loads(base64.b64decode(b64_payload))
        sig = base64.b64decode(b64_sig)
        return payload, sig
    except Exception:
        return None, None


def is_revoked(payload: dict, revoked_order_ids: set) -> bool:
    """CRL 钩子：检查该令牌的 order_id 是否在吊销名单内。"""
    if not revoked_order_ids:
        return False
    return payload.get("order_id") in revoked_order_ids


def verify_token(
    token: str,
    expected_device_fp: str = None,
    public_key: bytes = PUBLIC_KEY,
    revoked_order_ids: set = None,
) -> dict | None:
    """验证升级许可令牌。

    返回：dict（有效 payload）或 None（无效 / 过期 / 被篡改 / 设备不符 / 已吊销）。
    """
    try:
        payload, sig = parse_token(token)
        if payload is None or sig is None:
            return None
        # 1) 签名
        if not verify_signature(sig, canonical(payload), public_key):
            return None
        # 2) 吊销名单
        if is_revoked(payload, revoked_order_ids or set()):
            return None
        # 3) 有效期
        if int(payload.get("valid_until", 0)) < int(time.time()):
            return None
        # 4) 设备指纹绑定（调用方提供本机指纹才校验）
        if expected_device_fp is not None and payload.get("device_fp") != expected_device_fp:
            return None
        return payload
    except Exception:
        return None


def days_remaining(payload: dict) -> int:
    """距离订阅到期的天数（<=0 表示已过期或无效）。"""
    try:
        return max(0, (int(payload["valid_until"]) - int(time.time())) // 86400)
    except Exception:
        return 0


def status_summary(token: str, expected_device_fp: str = None) -> dict:
    """给 UI 用的摘要：是否有效、版本、剩余天数、吊销/过期原因。"""
    payload = verify_token(token, expected_device_fp=expected_device_fp)
    if payload is None:
        # 进一步区分原因（便于 UI 提示），失败一律归为 invalid
        p, _ = parse_token(token)
        reason = "invalid"
        if p is not None:
            if int(p.get("valid_until", 0)) < int(time.time()):
                reason = "expired"
        return {"valid": False, "reason": reason, "edition": None, "days_remaining": 0}
    return {
        "valid": True,
        "reason": "ok",
        "edition": payload.get("edition"),
        "features": payload.get("features", []),
        "order_id": payload.get("order_id"),
        "days_remaining": days_remaining(payload),
        "valid_until": payload.get("valid_until"),
    }
