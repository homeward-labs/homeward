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


def test_universal_token_has_no_device_binding():
    """发行端签发「通用令牌」（不带 device_fp）时，不应因为调用方总是传本机
    指纹而被拒绝 —— 否则家庭多设备套餐这类令牌等于废纸。"""
    seed = os.urandom(32)
    pub = derive_public(seed)
    payload = _make_payload()
    payload.pop("device_fp")            # 通用令牌：不绑定设备
    token = _sign_token(seed, payload)
    assert verify_token(token, expected_device_fp="fp-any-xyz",
                        public_key=pub) is not None


def test_bound_token_still_enforced():
    """反过来：令牌声明了 device_fp 就必须严格一致，不能被上面这条放宽掉。"""
    seed = os.urandom(32)
    pub = derive_public(seed)
    token = _sign_token(seed, _make_payload(device_fp="fp-abc"))
    assert verify_token(token, expected_device_fp="fp-abc", public_key=pub) is not None
    assert verify_token(token, expected_device_fp="fp-other", public_key=pub) is None


# ── 发布门禁：开发公钥绝不能进对外构件 ──

def test_dev_public_key_is_flagged_by_default():
    """默认（未注入正式公钥）必须被标记为开发公钥，门禁才会告警。"""
    import importlib

    import license.verify as verify
    importlib.reload(verify)
    assert verify.IS_DEV_PUBLIC_KEY is True


def test_assert_production_key_raises_when_forced():
    """发布流程设 force / HOMEWARD_REQUIRE_PROD_KEY=1 时必须是硬失败。"""
    import importlib

    import license.verify as verify
    importlib.reload(verify)
    try:
        verify.assert_production_key(force=True)
    except RuntimeError as exc:
        assert "开发公钥" in str(exc)
    else:
        raise AssertionError("使用开发公钥时 assert_production_key 必须抛错")


def test_env_injected_public_key_replaces_dev_key():
    """构建期注入正式公钥后，必须真的生效（IS_DEV_PUBLIC_KEY 变 False）。"""
    import base64 as _b64
    import importlib
    import os as _os

    seed = os.urandom(32)
    pub = derive_public(seed)
    old = _os.environ.get("HOMEWARD_LICENSE_PUBLIC_KEY_B64")
    _os.environ["HOMEWARD_LICENSE_PUBLIC_KEY_B64"] = _b64.b64encode(pub).decode()
    try:
        import license.verify as verify
        importlib.reload(verify)
        assert verify.IS_DEV_PUBLIC_KEY is False
        assert verify.PUBLIC_KEY == pub
        # 注入后：正式私钥签的令牌通过，开发公钥签的不通过
        token = _sign_token(seed, _make_payload())
        assert verify.verify_token(token) is not None
        other = os.urandom(32)
        bad = _sign_token(other, _make_payload())
        assert verify.verify_token(bad) is None
        # 门禁此时应安静通过（不抛错）
        verify.assert_production_key(force=True)
    finally:
        if old is None:
            _os.environ.pop("HOMEWARD_LICENSE_PUBLIC_KEY_B64", None)
        else:
            _os.environ["HOMEWARD_LICENSE_PUBLIC_KEY_B64"] = old
        import license.verify as verify  # noqa: F811
        importlib.reload(verify)


def test_invalid_env_key_is_ignored_not_silently_used():
    """非法公钥必须被忽略并回退，不能被当作有效公钥静默使用。"""
    import importlib
    import os as _os

    old = _os.environ.get("HOMEWARD_LICENSE_PUBLIC_KEY_B64")
    _os.environ["HOMEWARD_LICENSE_PUBLIC_KEY_B64"] = "not-a-valid-base64-@@@"
    try:
        import license.verify as verify
        importlib.reload(verify)
        assert verify.IS_DEV_PUBLIC_KEY is True, "非法公钥应被忽略，退回开发公钥"
    finally:
        if old is None:
            _os.environ.pop("HOMEWARD_LICENSE_PUBLIC_KEY_B64", None)
        else:
            _os.environ["HOMEWARD_LICENSE_PUBLIC_KEY_B64"] = old
        import license.verify as verify  # noqa: F811
        importlib.reload(verify)


if __name__ == "__main__":
    test_ed25519_basic()
    test_token_roundtrip()
    test_token_tampered()
    test_token_expired()
    test_token_device_mismatch()
    test_token_revoked()
    test_universal_token_has_no_device_binding()
    test_bound_token_still_enforced()
    test_dev_public_key_is_flagged_by_default()
    test_assert_production_key_raises_when_forced()
    test_env_injected_public_key_replaces_dev_key()
    test_invalid_env_key_is_ignored_not_silently_used()
    print("ALL LICENSE TESTS PASSED")
