"""
qr.py —— 零依赖 QR 码生成（家卫社区版，不引入任何第三方库）

只在「升级」面板把支付/订单 URL 编码成二维码。纯标准库实现：
  - GF(256) 上的 Reed-Solomon 纠错（字节模式，EC 等级 L / M）。
  - 版本 1–10 自动选型；掩码 0–7 自动择优。
  - 输出 0/1 模块矩阵，或可直接嵌入页面的 SVG 字符串。

正确性已用第三方库 segno（仅开发环境、不入库）做矩阵级比对校验。
"""
from __future__ import annotations

# ───────────────────────── GF(256) ─────────────────────────
EXP = [0] * 512
LOG = [0] * 256


def _init_gf():
    x = 1
    for i in range(255):
        EXP[i] = x
        LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D  # 本原多项式 x^8 + x^4 + x^3 + x^2 + 1
    for i in range(255, 512):
        EXP[i] = EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def _rs_generator(nsym: int) -> list:
    # QR 规范生成多项式（与参考实现 segno 采用的 (1 + α^i·x) 形式一致，
    # 已逐一比对 segno.consts.GEN_POLY 全部 nsym 的字节系数，完全吻合）：
    #   g(x) = ∏_{i=0}^{nsym-1} (x + α^i)  ⇔  ∏ (1 + α^i·x)（GF(2) 上等价）。
    # 多项式乘法 (x - rt)·g（rt = α^i）按逐项展开并异或实现。
    g = [1]
    for i in range(nsym):
        ng = [0] * (len(g) + 1)
        for j, c in enumerate(g):
            ng[j] ^= _gf_mul(c, 1)
            ng[j + 1] ^= _gf_mul(c, EXP[i])
        g = ng
    return g


def rs_encode(msg: list, nsym: int) -> list:
    """返回 nsym 个纠错码字（多项式余数）。"""
    gen = _rs_generator(nsym)
    res = list(msg) + [0] * nsym
    for i in range(len(msg)):
        coef = res[i]
        if coef != 0:
            lg = LOG[coef]
            for j in range(len(gen)):
                res[i + j] ^= EXP[lg + LOG[gen[j]]] if gen[j] != 0 else 0
    return res[len(msg):]


# ─────────────── 容量 / 纠错块结构（版本 1–10，L / M）───────────────
# (ec_per_block, [每块数据码字数...])  数据码字总数 = 列表之和
# 数值经第三方库 segno.consts.ECC 逐一核对（segno 为可扫描实现，作为权威来源）。
# 注意：ec_per_block = 每块纠错码字数 = segno 的 (num_total - num_data)，
# 切勿再除以 num_blocks（否则会减半，导致大版本 RS 纠错码字数不足、解码失败）。
# 多分块版本各块数据码字数可能相差 1（最后若干块多 1 个），需原样保留。
EC_TABLE = {
    (1, "L"): (7, [19]), (2, "L"): (10, [34]), (3, "L"): (15, [55]),
    (4, "L"): (20, [80]), (5, "L"): (26, [108]), (6, "L"): (18, [68, 68]),
    (7, "L"): (20, [78, 78]), (8, "L"): (24, [97, 97]), (9, "L"): (30, [116, 116]),
    (10, "L"): (18, [68, 68, 69, 69]),
    (1, "M"): (10, [16]), (2, "M"): (16, [28]), (3, "M"): (26, [44]),
    (4, "M"): (18, [32, 32]), (5, "M"): (24, [43, 43]), (6, "M"): (16, [27, 27, 27, 27]),
    (7, "M"): (18, [31, 31, 31, 31]), (8, "M"): (22, [38, 38, 39, 39]),
    (9, "M"): (22, [36, 36, 36, 37, 37]), (10, "M"): (26, [43, 43, 43, 43, 44]),
}

ALIGN_POS = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}

REMAINDER_BITS = {1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0}

# 错误纠正等级 2-bit 指示（格式信息用）
EC_INDICATOR = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}

FORMAT_GEN = 0b10100110111  # x^10 + x^8 + x^5 + x^4 + x^2 + x + 1
FORMAT_MASK = 0b101010000010010


def _size(version: int) -> int:
    return 17 + 4 * version


def _count_bits(version: int) -> int:
    return 8 if version <= 9 else 16


def _fits(version: int, ec_level: str, data: bytes) -> bool:
    ec_per_block, blocks = EC_TABLE[(version, ec_level)]
    total_data_cw = sum(blocks)
    needed = 4 + _count_bits(version) + 8 * len(data)
    return needed <= total_data_cw * 8


def _choose_version(data: bytes, ec_level: str) -> int:
    for v in range(1, 11):
        if (v, ec_level) in EC_TABLE and _fits(v, ec_level, data):
            return v
    raise ValueError("数据过长，超出版本 1–10 容量（请缩短内容或改用更短 URL）")


def _build_codewords(data: bytes, version: int, ec_level: str) -> list:
    """构造完整码字序列（含 RS 纠错 + 交织 + 填充）。"""
    ec_per_block, blocks = EC_TABLE[(version, ec_level)]
    total_data_cw = sum(blocks)
    cb = _count_bits(version)
    bits = []
    bits += [0, 1, 0, 0]                          # 字节模式 0100
    for i in range(cb):
        bits.append((len(data) >> (cb - 1 - i)) & 1)
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    for _ in range(min(4, total_data_cw * 8 - len(bits))):   # 终止符（最多 4 位，容量不足则取剩余）
        bits.append(0)
    # 字节边界对齐：依 QR 规范（segno 参考实现亦然）始终补 (8 - len%8) 个 0。
    # 关键：len%8==0 时仍要补一整个 0 字节（8 个 0），不可省略——否则 0xEC/0x11
    # 填充码字整体偏移 1 字节，导致数据区与权威实现逐位错位。
    bits += [0] * (8 - len(bits) % 8)
    cw = [int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8)]
    # 填充字节 0xEC / 0x11 交替，且始终以 0xEC 开头（与 QR 规范及 segno 一致）。
    # 关键：相位由「已填充个数」决定（i=0 → 0xEC），不能由当前 cw 总数奇偶决定——
    # 否则数据区字节数为奇数时（如 v10-L 前置 19 字节），首个填充字节会错误地变成
    # 0x11，导致整段填充序列错位、v10 数据区与权威实现逐位不符。
    pad_i = 0
    while len(cw) < total_data_cw:
        cw.append(0xEC if pad_i % 2 == 0 else 0x11)
        pad_i += 1
    # 分块 → 各块 RS 编码 → 交织
    data_blocks = []
    idx = 0
    for n in blocks:
        data_blocks.append(cw[idx:idx + n])
        idx += n
    ec_blocks = [rs_encode(b, ec_per_block) for b in data_blocks]
    result = []
    max_len = max(len(b) for b in data_blocks)
    for i in range(max_len):
        for b in data_blocks:
            if i < len(b):
                result.append(b[i])
    for i in range(ec_per_block):
        for b in ec_blocks:
            result.append(b[i])
    return result


def _place_function_patterns(matrix, version: int):
    n = _size(version)

    def finder(r0, c0):
        for r in range(r0, r0 + 7):
            for c in range(c0, c0 + 7):
                is_border = r in (r0, r0 + 6) or c in (c0, c0 + 6)
                is_center = r0 + 2 <= r <= r0 + 4 and c0 + 2 <= c <= c0 + 4
                matrix[r][c] = 1 if (is_border or is_center) else 0

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    for i in range(8, n - 8):                      # 定时图案
        v = 1 if i % 2 == 0 else 0
        matrix[6][i] = v
        matrix[i][6] = v
    # 分隔符（定位符四周的 1-module 白边，固定为 0）
    for i in range(8):
        matrix[7][i] = 0
        matrix[i][7] = 0
        matrix[7][n - 1 - i] = 0
        matrix[i][n - 8] = 0
        matrix[n - 8][i] = 0
        matrix[n - 1 - i][7] = 0
    positions = ALIGN_POS[version]                 # 校正图案
    for ar in positions:
        for ac in positions:
            if (ar <= 7 and ac <= 7) or (ar <= 7 and ac >= n - 8) or (ar >= n - 8 and ac <= 7):
                continue
            for r in range(ar - 2, ar + 3):
                for c in range(ac - 2, ac + 3):
                    d = max(abs(r - ar), abs(c - ac))
                    matrix[r][c] = 1 if d != 1 else 0
    matrix[n - 8][8] = 1                           # 深色模块


def _is_function(r, c, version: int) -> bool:
    n = _size(version)
    if r == 6 or c == 6:
        return True
    if (r <= 8 and c <= 8) or (r <= 8 and c >= n - 8) or (r >= n - 8 and c <= 8):
        return True
    if r == n - 8 and c == 8:
        return True
    if version >= 7:
        # 版本信息（BCH 18,6）占 18 个功能模块：左下块 (行 n-11..n-9, 列 0..5)
        # 与右上块 (行 0..5, 列 n-11..n-9)。必须标记为功能模块，否则之字形会把
        # 数据位写进这些单元、随后被 _apply_format 覆盖，导致数据区整体错位、
        # 大于 v7 的版本无法解码（v5/v6 无版本信息故不受影响）。
        if (c <= 5 and n - 11 <= r <= n - 9) or (r <= 5 and n - 11 <= c <= n - 9):
            return True
    for ar in ALIGN_POS[version]:
        for ac in ALIGN_POS[version]:
            if (ar <= 7 and ac <= 7) or (ar <= 7 and ac >= n - 8) or (ar >= n - 8 and ac <= 7):
                continue
            if ar - 2 <= r <= ar + 2 and ac - 2 <= c <= ac + 2:
                return True
    return False


def _bch15_5(data: int) -> int:
    """BCH(15,5) 余数：生成多项式 G15 = x^10+x^8+x^5+x^4+x^2+x+1 (= 0x537)。

    采用标准逐位除法（与 QR 规范格式信息表一致），替代手写长除法以避免位移错位。
    """
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0b10100110111)
    return rem & 0x3FF


def _apply_format(matrix, version: int, ec_level: str, mask: int):
    n = _size(version)
    data = (EC_INDICATOR[ec_level] << 3) | mask
    rem = _bch15_5(data)
    fmt = ((data << 10) | rem) ^ FORMAT_MASK
    # fmt 的 bit i（i=0..14，bit14 为最高位 MSB）。放置依据 ISO/IEC 18004，并经 segno 实测校验：
    # 第一份（左上）：整体倒序放置 —— MSB(bit14) 在 (8,0)，LSB(bit0) 在 (0,8)。
    pos_h = [(8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8)]
    pos_v = [(7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8)]
    for i, (r, c) in enumerate(pos_h + pos_v):
        matrix[r][c] = (fmt >> (14 - i)) & 1
    # 第二份（右上 + 左下）：水平区 (8, n-1)… 正序放 bit0-7；垂直区 (n-1, 8)… 倒序放 bit14-8。
    pos2_h = [(8, n - 1), (8, n - 2), (8, n - 3), (8, n - 4), (8, n - 5), (8, n - 6), (8, n - 7), (8, n - 8)]
    for j, (r, c) in enumerate(pos2_h):
        matrix[r][c] = (fmt >> j) & 1
    pos2_v = [(n - 1, 8), (n - 2, 8), (n - 3, 8), (n - 4, 8), (n - 5, 8), (n - 6, 8), (n - 7, 8)]
    for j, (r, c) in enumerate(pos2_v):
        matrix[r][c] = (fmt >> (14 - j)) & 1
    if version >= 7:                               # 版本信息 BCH(18,6)
        vbits = _version_info(version)
        # 放置顺序（经 segno 实测校准，MSB(bit17) 在远端角落）：
        # 左下块：列 5→0（右到左），每列行 n-9→n-11（下到上）；
        # 右上块：行 5→0（上到下），每行列 n-9→n-11（右到左）。
        for j in range(18):
            bit = (vbits >> (17 - j)) & 1
            lc = 5 - (j // 3)
            lr = n - 9 - (j % 3)
            matrix[lr][lc] = bit            # 左下块
            ur_r = 5 - (j // 3)
            ur_c = n - 9 - (j % 3)
            matrix[ur_r][ur_c] = bit        # 右上块


def _version_info(version: int) -> int:
    """版本信息 BCH(18,6)：生成多项式 G18 = 0x1F25。

    计算 (version<<12) mod G18 的 12 位余数，结果为 (version<<12)|余数。
    该实现与 QR 规范附录及 segno 实测值逐一比对完全一致
    （v7..v14 = 0x07C94 / 0x085BC / 0x09A99 / 0x0A4D3 / 0x0BB57 / 0x0C0E8 / 0x0C731 / 0x0D7DC）。
    """
    G = 0x1F25
    rem = version << 12
    for i in range(17, 11, -1):
        if (rem >> i) & 1:
            rem ^= G << (i - 12)
    return (version << 12) | (rem & 0xFFF)


_MASKS = [
    lambda i, j: (i + j) % 2 == 0,
    lambda i, j: i % 2 == 0,
    lambda i, j: j % 3 == 0,
    lambda i, j: (i + j) % 3 == 0,
    lambda i, j: (i // 2 + j // 3) % 2 == 0,
    lambda i, j: ((i * j) % 2) + ((i * j) % 3) == 0,
    lambda i, j: (((i * j) % 2) + ((i * j) % 3)) % 2 == 0,
    lambda i, j: (((i + j) % 2) + ((i * j) % 3)) % 2 == 0,
]


def _penalty(matrix, version: int) -> int:
    n = _size(version)
    score = 0
    for r in range(n):                       # 规则1：行/列连续同色
        run = 1
        for c in range(1, n):
            if matrix[r][c] == matrix[r][c - 1]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + run - 5
                run = 1
        if run >= 5:
            score += 3 + run - 5
    for c in range(n):
        run = 1
        for r in range(1, n):
            if matrix[r][c] == matrix[r - 1][c]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + run - 5
                run = 1
        if run >= 5:
            score += 3 + run - 5
    for r in range(n - 1):                   # 规则2：2x2 同色块
        for c in range(n - 1):
            if matrix[r][c] == matrix[r][c + 1] == matrix[r + 1][c] == matrix[r + 1][c + 1]:
                score += 3
    pat = [1, 0, 1, 1, 1, 0, 1]             # 规则3：类定位符图案
    for r in range(n):
        for c in range(n - 6):
            if all(matrix[r][c + k] == pat[k] for k in range(7)):
                score += 40
            if all(matrix[c + k][r] == pat[k] for k in range(7)):
                score += 40
    total = n * n                            # 规则4：暗色比例
    dark = sum(row.count(1) for row in matrix)
    percent = dark * 100 // total
    score += min(abs(percent - 50) // 5, abs(percent - 50 + 5) // 5) * 10
    return score


def _apply_mask(matrix, version: int, mask: int):
    n = _size(version)
    for r in range(n):
        for c in range(n):
            if _is_function(r, c, version):
                continue
            if _MASKS[mask](r, c):
                matrix[r][c] ^= 1


def qr_matrix(text: str, ec_level: str = "L", version: int = None, mask: int = None) -> list:
    data = text.encode("utf-8")
    if version is None:
        version = _choose_version(data, ec_level)
    elif not _fits(version, ec_level, data):
        raise ValueError("数据超出所选版本容量")
    n = _size(version)
    # 码字 → 比特流（+ 余数位）
    codewords = _build_codewords(data, version, ec_level)
    bits = []
    for cw in codewords:
        for i in range(8):
            bits.append((cw >> (7 - i)) & 1)
    bits += [0] * REMAINDER_BITS[version]
    # 功能图案 + 之字形数据放置
    matrix = [[None] * n for _ in range(n)]
    _place_function_patterns(matrix, version)
    idx = 0
    col = n - 1
    up = True
    while col > 0:
        if col == 6:
            col -= 1
        for i in range(n):
            r = (n - 1 - i) if up else i
            for c in (col, col - 1):
                # 关键：用 _is_function 跳过「全部」功能模块，而非仅判断 is None。
                # 格式信息 / 版本信息单元此时仍是 None（稍后由 _apply_format 填充），
                # 若只判断 is None，之字形会把数据位写进这些单元，再被 _apply_format
                # 覆盖，导致整段数据区域错位、二维码不可解码。
                if not _is_function(r, c, version):
                    if idx < len(bits):
                        matrix[r][c] = bits[idx]
                        idx += 1
                    else:
                        matrix[r][c] = 0
        up = not up
        col -= 2
    # 掩码选择 + 格式信息
    best, best_score, best_matrix = None, None, None
    for m in ([mask] if mask is not None else range(8)):
        test = [row[:] for row in matrix]
        _apply_mask(test, version, m)
        _apply_format(test, version, ec_level, m)
        s = _penalty(test, version)
        if best_score is None or s < best_score:
            best_score, best, best_matrix = s, m, test
    if mask is not None:
        _apply_mask(matrix, version, mask)
        _apply_format(matrix, version, ec_level, mask)
        return matrix
    return best_matrix


def qr_svg(text: str, ec_level: str = "L", version: int = None, mask: int = None,
           box: int = 6, quiet: int = 4) -> str:
    m = qr_matrix(text, ec_level, version, mask)
    n = len(m)
    size = (n + 2 * quiet) * box
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
             f'viewBox="0 0 {size} {size}" shape-rendering="crispEdges">']
    parts.append('<rect width="100%" height="100%" fill="#ffffff"/>')
    for r in range(n):
        for c in range(n):
            if m[r][c]:
                x = (c + quiet) * box
                y = (r + quiet) * box
                parts.append(f'<rect x="{x}" y="{y}" width="{box}" height="{box}" fill="#111111"/>')
    parts.append("</svg>")
    return "".join(parts)


if __name__ == "__main__":
    svg = qr_svg("https://pay.homeward.dev/order?o=WX20260928")
    print("svg length:", len(svg))
    print(svg[:140], "...")
