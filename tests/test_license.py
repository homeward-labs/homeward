"""tests/test_license.py —— 零依赖：Ed25519 验签 + 许可令牌格式端到端验证。

不依赖 cryptography / 网络 / 私有密钥：用 ed25519.py 自身签名，verify.py 验签，
覆盖 正常、篡改、过期、设备不符、吊销 五类场景。
运行：python -m pytest tests/test_license.py -q
      或：python tests/test_license.py
"""
import base64
import json
import os
import sys
import time

# 把 src/ 加入路径，使 `license` 成为可导入的顶层包
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from license.ed25519 import sign_message, derive_public, verify_signature  # noqa: E402
from license.verify import canonical, verify_token, is_revoked, days_remaining  # noqa: E402


def _sign_token(seed: bytes, payload: dict) -> str:
    sig = sign_message(canonical(payload), seed)
    head = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode()
    tail = base64.b64encode(sig).decode()
    return f"{head}.{tail}"


def _make_payload(valid_days=365, device_fp="fp-abc", order_id="WX-1"):
    now = int(time.time())
    return {
        "kid": "2026-09",
        "edition": "standard",
        "device_fp": device_fp,
        "features": ["dns_block"],
        "issued_at": now,
        "valid_until": now + valid_days * 86400,
        "order_id": order_id,
        "nonce": os.urandom(8).hex(),
    }


def test_ed25519_basic():
    seed = os.urandom(32)
    pub = derive_public(seed)
    for msg in (b"", b"homeward", os.urandom(50)):
        sig = sign_message(msg, seed)
        assert verify_signature(sig, msg, pub)
        bad = bytearray(sig); bad[0] ^= 0xFF
        assert not verify_signature(bytes(bad), msg, pub)


def test_token_roundtrip():
    seed = os.urandom(32)
    pub = derive_public(seed)
    token = _sign_token(seed, _make_payload())
    out = verify_token(token, expected_device_fp="fp-abc", public_key=pub)
    assert out is not None
    assert out["edition"] == "standard"
    assert out["order_id"] == "WX-1"
    assert days_remaining(out) >= 364


def test_token_tampered():
    seed = os.urandom(32)
    pub = derive_public(seed)
    token = _sign_token(seed, _make_payload())
    head, tail = token.split(".", 1)
    # 改 payload 不改签名 → 验签失败
    bad_payload = json.loads(base64.b64decode(head))
    bad_payload["edition"] = "pro"
    bad_head = base64.b64encode(json.dumps(bad_payload, ensure_ascii=False).encode()).decode()
    assert verify_token(f"{bad_head}.{tail}", public_key=pub) is None


def test_token_expired():
    seed = os.urandom(32)
    pub = derive_public(seed)
    token = _sign_token(seed, _make_payload(valid_days=-1))
    assert verify_token(token, public_key=pub) is None


def test_token_device_mismatch():
    seed = os.urandom(32)
    pub = derive_public(seed)
    token = _sign_token(seed, _make_payload(device_fp="fp-abc"))
    # 本机指纹不符 → 拒绝
    assert verify_token(token, expected_device_fp="fp-other", public_key=pub) is None
    # 不传指纹 → 不校验绑定（仅验签+有效期）
    assert verify_token(token, public_key=pub) is not None


def test_token_revoked():
    seed = os.urandom(32)
    pub = derive_public(seed)
    token = _sign_token(seed, _make_payload(order_id="WX-REVOKED"))
    assert verify_token(token, public_key=pub, revoked_order_ids={"WX-REVOKED"}) is None
    assert verify_token(token, public_key=pub, revoked_order_ids=set()) is not None


if __name__ == "__main__":
    test_ed25519_basic()
    test_token_roundtrip()
    test_token_tampered()
    test_token_expired()
    test_token_device_mismatch()
    test_token_revoked()
    print("ALL LICENSE TESTS PASSED")
