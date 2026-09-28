"""
tests/test_qr.py — 零依赖 QR 生成器（src/ui/qr.py）正确性校验

校验策略（两层）：
  1. 矩阵级比对（权威）：与第三方库 segno 逐单元格比对，要求 bit 完全一致。
     segno 为成熟实现，仅作开发期校验基准，不进运行时依赖。
  2. 解码级校验（健全性）：用 opencv 渲染 PNG 并反解，确认可扫描、内容一致。
     渲染分辨率取 scale≥24，规避 opencv 对特定密集图案的伪阴性。

segno / cv2 均为开发期可选依赖：未在环境中安装时对应用例自动 skip，
不影响 qr.py 本身的 stdlib 运行能力。

覆盖：版本 1–10 × EC(L/M) × 掩码 0–7 共 152 例（容量不足的组合自然跳过）。
"""
import os
import sys

import pytest

# 让测试能直接 import 位于 src/ui 的 qr.py（纯标准库模块）
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "src", "ui"))

import qr as qr  # noqa: E402

segno = pytest.importorskip("segno")
cv2 = pytest.importorskip("cv2")
np = pytest.importorskip("numpy")


# ───────────────────────── 版本信息 BCH 权威值 ─────────────────────────
# 取自 QR 规范附录（BCH(18,6)，生成多项式 G18=0x1F25）。
# 仅覆盖本模块支持的版本范围（v7–v10；v1–6 无版本信息）。
VERSION_INFO_CANON = {
    7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3,
}


def test_version_info_canonical():
    for v, expected in VERSION_INFO_CANON.items():
        assert qr._version_info(v) == expected, f"版本信息 v{v} 错误"


# ───────────────────────── 矩阵级比对（核心） ─────────────────────────
def _segno_matrix(text, ec, version, mask):
    qr_seg = segno.make(text, error=ec, version=version, mask=mask, boost_error=False)
    m = qr_seg.matrix
    return [[int(m[r][c]) for c in range(len(m))] for r in range(len(m))]


def test_matrix_matches_segno_bit_exact():
    """逐单元格比对：qr_matrix 输出必须与 segno 完全一致（0 差异）。"""
    text = "https://h.dev/a"
    total = 0
    for version in range(1, 11):
        for ec in ("L", "M"):
            for mask in range(8):
                try:
                    sm = _segno_matrix(text, ec, version, mask)
                except Exception:
                    # 容量不足等：segno 无法构造，说明该 (版本,EC) 不适用，跳过
                    continue
                mm = qr.qr_matrix(text, ec_level=ec, version=version, mask=mask)
                n = len(mm)
                assert len(mm) == len(sm), f"v{version} {ec} mask{mask} 尺寸不符"
                fn_diff = data_diff = 0
                for r in range(n):
                    for c in range(n):
                        if sm[r][c] != mm[r][c]:
                            if qr._is_function(r, c, version):
                                fn_diff += 1
                            else:
                                data_diff += 1
                assert fn_diff == 0 and data_diff == 0, (
                    f"v{version} {ec} mask{mask}: FN={fn_diff} DATA={data_diff}"
                )
                total += 1
    # 152 例全部通过方为预期
    assert total == 152, f"实际比对用例数异常: {total}"


# ───────────────────────── 解码级校验（健全性） ─────────────────────────
def _render_png(mat, scale=24, border=6):
    n = len(mat)
    sz = (n + 2 * border) * scale
    img = np.full((sz, sz), 255, np.uint8)
    for r in range(n):
        for c in range(n):
            if mat[r][c]:
                y0 = (r + border) * scale
                x0 = (c + border) * scale
                img[y0:y0 + scale, x0:x0 + scale] = 0
    return img


def test_decode_roundtrip_auto_version():
    """自动选型 + 自动掩码：渲染后必须可被 opencv 反解为原文。"""
    det = cv2.QRCodeDetector()
    urls = [
        "https://h.dev/a",
        "https://pay.homeward.dev/order?o=WX20260928",
        "https://homeward.dev/license/activate?k=ED25519-DEMO-9F2A",
        "HELLO WORLD 123",
    ]
    for u in urls:
        mat = qr.qr_matrix(u)  # 自动版本 + 自动掩码
        img = _render_png(mat)
        res, _, _ = det.detectAndDecode(img)
        assert res == u, f"解码失败: 期望 {u!r} 实得 {res!r}"


def test_decode_roundtrip_forced_version_mask():
    """强制版本/掩码（含 v10-L 奇数前置填充字节的边界）：必须可解。"""
    det = cv2.QRCodeDetector()
    u = "https://h.dev/a"
    for version in (1, 3, 5, 7, 10):
        for ec in ("L", "M"):
            try:
                mat = qr.qr_matrix(u, ec_level=ec, version=version, mask=3)
            except ValueError:
                continue  # 容量不足，跳过
            img = _render_png(mat)
            res, _, _ = det.detectAndDecode(img)
            assert res == u, f"v{version} {ec} mask3 解码失败: {res!r}"


def test_module_is_stdlib_only():
    """qr.py 必须仅依赖标准库（无第三方 import）。"""
    import ast
    src = open(os.path.join(_HERE, "..", "src", "ui", "qr.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    third_party = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                third_party.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                third_party.add(node.module.split(".")[0])
    # 允许的标准库白名单
    allowed = {"__future__"}
    assert third_party <= allowed, f"发现非标准库依赖: {third_party - allowed}"
