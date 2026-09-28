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
import logging
import os
import time

logger = logging.getLogger("homeward.license")

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


# ── 公钥（Ed25519 Raw 32 字节，Base64）──
# 优先级：环境变量 HOMEWARD_LICENSE_PUBLIC_KEY_B64（构建期 / 部署期注入正式公钥）
#         > 仓库内嵌的**开发公钥**（仅本地联调，绝不进对外构件）。
#
# 为什么必须有这一步：开发公钥对应的开发私钥存在于本地联调环境，
# 任何人拿到它都能签出「验签通过」的令牌，付费升级形同虚设。
# 因此对外发布的构件必须在构建时注入正式公钥（见 assert_production_key）。
_DEV_PUBLIC_KEY_B64 = "/ADxAT6LVmMl2ytd8HURTl+1B2S6py7MFUBBKs5uRL8="
_DEV_PUBLIC_KEY = base64.b64decode(_DEV_PUBLIC_KEY_B64)


def _load_public_key() -> bytes:
    """按优先级解析公钥：环境变量注入的正式公钥优先，否则退回开发公钥。

    环境变量供 CI / 闭源构建流程使用，使公开仓库里的源码**无需改动源码**
    即可产出「只认正式签发令牌」的构件（对应 私有目录 下的私钥）。
    值不合法（非 base64 / 长度不是 32 字节）时记 error 并忽略——
    绝不静默吞掉，否则会误以为注入成功、实则仍停在可伪造状态。
    """
    raw = os.environ.get("HOMEWARD_LICENSE_PUBLIC_KEY_B64")
    if raw:
        try:
            key = base64.b64decode(raw, validate=True)
        except Exception:
            key = b""
        if len(key) == 32:
            return key
        logger.error("HOMEWARD_LICENSE_PUBLIC_KEY_B64 不是合法的 32 字节 "
                     "Ed25519 公钥（base64 解码后长度 %d），已忽略", len(key))
    return _DEV_PUBLIC_KEY


PUBLIC_KEY = _load_public_key()

#: True 表示当前用的仍是仓库内嵌的开发公钥 —— 对外发布前必须替换。
IS_DEV_PUBLIC_KEY = (PUBLIC_KEY == _DEV_PUBLIC_KEY)


def assert_production_key(force: "bool | None" = None) -> None:
    """发布门禁：仍在用开发公钥时明确告警 / 报错。

    默认**只告警不阻断**：社区版没有许可也应能正常「看见」（许可只是升级闸门），
    不能因为忘了注入公钥就让整个服务起不来。
    发布流程（CI / 打包脚本）设 ``HOMEWARD_REQUIRE_PROD_KEY=1`` 则直接抛错，
    把「忘了注入正式公钥」挡在发布之前，而不是等上线后被伪造许可打脸。
    """
    if not IS_DEV_PUBLIC_KEY:
        return
    if force is None:
        force = os.environ.get("HOMEWARD_REQUIRE_PROD_KEY", "").strip() in (
            "1", "true", "True", "yes")
    msg = ("当前使用的是仓库内嵌的**开发公钥**：任何人拿到配套开发私钥都能签出"
           "「验签通过」的许可，付费升级形同虚设。对外发布前请通过环境变量 "
           "HOMEWARD_LICENSE_PUBLIC_KEY_B64 注入正式公钥并重新构建。")
    if force:
        raise RuntimeError(msg)
    logger.warning(msg)


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
        # 4) 设备指纹绑定：只有**令牌自身声明了 device_fp** 才做绑定校验。
        #    发行端可以签发「通用令牌」（不绑定设备，例如多设备家庭套餐）；
        #    这类令牌若因为调用方总是传入本机指纹就被一律拒绝，等于把通用令牌
        #    变成了废纸。因此：令牌没声明 → 不校验；声明了 → 必须一致。
        bound_fp = payload.get("device_fp")
        if (bound_fp is not None and expected_device_fp is not None
                and bound_fp != expected_device_fp):
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
