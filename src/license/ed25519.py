"""
ed25519.py —— 零依赖的 Ed25519 实现（验证 + 开发用签名）

用途
----
家卫社区版的许可**验证**必须能在没有任何第三方依赖的情况下跑在家庭网关上
（见 src/ui/server.py 顶部「零外部依赖」原则）。本文件是 Ed25519 的一个
纯标准库实现，专门用来在客户端验证许可令牌的签名。

安全说明（重要）
----------------
- 这里**只放公开算法**，私钥（签名用的种子）永远不在本文件、不在公开仓库。
- `sign_message` / `generate_seed` 仅供**开发期与测试**使用（生成测试令牌、
  本地最小签发器）；生产环境的签名由私密目录 `~/家卫私有/license/` 下的
  闭源签发器完成，私钥永不进公开仓库。
- 采用 RFC 8032 的**扩展 Edwards 坐标**加法公式（X,Y,Z,T），这是业界
  经广泛验证的实现，避免手工推导仿射公式出错。与 `cryptography` 的 Ed25519
  Raw 编码**二进制兼容**（公私钥、签名均为 32/64 字节原始字节），因此客户
  端纯 Python 验签可验证服务端 `cryptography` 签出的令牌。
"""

import hashlib
import os

# ---- 域参数 ----
b = 256
q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(base: int, e: int, m: int) -> int:
    if e == 0:
        return 1
    t = _expmod(base, e // 2, m) ** 2 % m
    if e & 1:
        t = (t * base) % m
    return t


def _inv(x: int) -> int:
    return _expmod(x % q, q - 2, q)


_d = -121665 * _inv(121666) % q
_I = _expmod(2, (q - 1) // 4, q)

# 标准 Ed25519 基点（RFC 8032 给出的 y；x 由其正(偶数)平方根确定，避免硬编码写错）。
_B_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
# B_EXT 在 _xrecover 定义之后计算（见文件末尾）


# ---- 编解码（仿射 x,y）----

def _encode_int(y: int) -> bytes:
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _encode_point(P) -> bytes:
    x, y = P
    return _encode_int(y | ((x & 1) << 255))


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _decode_int(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(b))


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1) % q
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


def _decode_point(s: bytes):
    # 最高位（bit 255）是符号位（x 的奇偶），必须清掉后才能取纯 y 来反解 x。
    y = _decode_int(s[: b // 8]) & ((1 << (b - 1)) - 1)
    x = _xrecover(y)
    if x & 1 != _bit(s, b - 1):
        x = q - x
    return [x % q, y % q]


# ---- 扩展 Edwards 坐标运算 ----

def _affine_to_ext(P):
    x, y = P
    return (x % q, y % q, 1, (x * y) % q)


def _ext_to_affine(P):
    X, Y, Z, _T = P
    z = _inv(Z)
    return (X * z % q, Y * z % q)


def _edwards_add(P, Q):
    # RFC 8032 扩展坐标加法（a = -1，故 H = B + A）
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (X1 * X2) % q
    B = (Y1 * Y2) % q
    C = (T1 * _d * T2) % q
    D = (Z1 * Z2) % q
    E = ((X1 + Y1) * (X2 + Y2) - A - B) % q
    F = (D - C) % q
    G = (D + C) % q
    H = (B + A) % q
    X3 = (E * F) % q
    Y3 = (G * H) % q
    Z3 = (F * G) % q
    T3 = (E * H) % q
    return (X3, Y3, Z3, T3)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _hint(m: bytes) -> int:
    # 必须把**完整 64 字节** SHA-512 摘要当作小端整数（随后在 S/H 处 mod L）。
    # 注意：不能用 _decode_int()——它只读取前 256 位，会把 512 位摘要截断，
    # 导致 r / 挑战量 h 与标准（RFC 8032）实现不一致（尽管自洽）。
    return int.from_bytes(_H(m), "little")


# ---- 对外便捷 API ----

def generate_seed() -> bytes:
    """生成 32 字节私钥种子（开发/测试用；生产私钥由闭源签发器保管）。"""
    return os.urandom(32)


def _clamp_scalar(h: bytes) -> int:
    return 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))


def derive_public(seed: bytes) -> bytes:
    """由种子推导 32 字节原始公钥。"""
    a = _clamp_scalar(_H(seed))
    A_ext = _scalarmult(B_EXT, a)
    return _encode_point(_ext_to_affine(A_ext))


def sign_message(message: bytes, seed: bytes) -> bytes:
    """用种子对消息签名，返回 64 字节原始签名（开发/测试用）。"""
    h = _H(seed)
    a = _clamp_scalar(h)
    r = _hint(h[b // 8 : b // 4] + message)
    R_ext = _scalarmult(B_EXT, r)
    R_aff = _ext_to_affine(R_ext)
    pk = derive_public(seed)
    S = (r + _hint(_encode_point(R_aff) + pk + message) * a) % L
    return _encode_point(R_aff) + _encode_int(S)


def verify_signature(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """验证签名。任何异常都视为失败（不抛出）。"""
    try:
        if len(signature) != b // 4 or len(public_key) != b // 8:
            return False
        R_aff = _decode_point(signature[: b // 8])
        A_aff = _decode_point(public_key)
        S = _decode_int(signature[b // 8 : b // 4])
        h = _hint(_encode_point(R_aff) + public_key + message)
        R_ext = _affine_to_ext(R_aff)
        A_ext = _affine_to_ext(A_aff)
        v1 = _ext_to_affine(_scalarmult(B_EXT, S))
        v2 = _ext_to_affine(_edwards_add(R_ext, _scalarmult(A_ext, h)))
        return v1 == v2
    except Exception:
        return False


# ---- 标准基点 B 的扩展坐标（必须在 _xrecover 定义之后计算）----
# RFC 8032 §5.1：基点 B 的 y 坐标为 4/5，x 取**正（偶数）平方根**，
# 即 _xrecover(_B_Y) 直接给出的偶数根，无需翻转。
# 已用 cryptography 交叉验证：使用偶数根时，本实现的 derive_public / 验签
# 与 cryptography(Ed25519 Raw) 产生的公私钥、签名二进制完全兼容。
_B_X = _xrecover(_B_Y)  # 已是偶数根，正平方根，直接使用
B_EXT = (_B_X % q, _B_Y % q, 1, (_B_X * _B_Y) % q)
