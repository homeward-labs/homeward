"""SSRF 出网守卫（M1-4 / 待办-122 · 2026-11-17 第 577 批）

根因（评审 P0-3）：`_ALLOW` 只是**键名**白名单，`ai_base_url` 可被改写，
而 `analyzer.py` 无条件给该 URL 附加 `Authorization: Bearer {api_key}`
——凭据与用户可控 URL 落在同一请求路径上，等于把 Key 送到任意地址。

本模块按五要素收口，写入层（`server.py` `/api/config`）与出网层
（`analyzer.py`）两层都走它：

1. **URL 白名单**：scheme 仅 `http`/`https`；带用户名口令的 URL 一律拒绝。
2. **私网 / 保留段拒绝**：DNS 解析出的**每一个** A/AAAA 都不得落在
   private / loopback / link_local / reserved / multicast / unspecified
   （`169.254.169.254` 云元数据属 link_local，一并覆盖）。
3. **重定向逐跳校验**：禁用 urllib 的自动跟随，本模块自己跟，每跳重新校验；
   **跨主机跳转丢弃 `Authorization`**。
4. **响应体上限**：分块读，超限立即中止（默认 2 MiB）。
5. **非白名单目标零凭据头**：仅当 host ∈ 官方端点 ∪ 用户显式信任主机，
   才允许携带 `Authorization`。

回环（`localhost`/`127.0.0.1`/`::1`）只在 `allow_loopback=True` 时放行，
且**仅供 ollama 本地后端**使用——绝不与携带凭据的 openai 路径共用。

失败的 host 解析按 fail-closed 处理：解析不出来就不发请求。
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

OFFICIAL_HOSTS = frozenset({"api.openai.com"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})
MAX_BODY_BYTES = 2 * 1024 * 1024
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


class SsrfError(ValueError):
    """出网目标被拒（原因放在 str(e) 里，便于测试与日志取证）。"""


def _addr_allowed(ip_str: str) -> bool:
    """单个解析结果是否落在可出网的公网段。"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def normalize_host(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def is_loopback_host(host: str) -> bool:
    return normalize_host(host) in LOOPBACK_HOSTS


def may_carry_credentials(host: str, trusted_hosts=()) -> bool:
    """只有官方端点与用户显式信任主机才允许带凭据头。"""
    h = normalize_host(host)
    return h in OFFICIAL_HOSTS or h in {normalize_host(t) for t in trusted_hosts}


def check_url(url: str, *, allow_loopback: bool = False, trusted_hosts=()) -> str:
    """校验目标 URL，通过则返回规范化 host，否则抛 SsrfError。"""
    if not isinstance(url, str) or not url.strip():
        raise SsrfError("empty_url")
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise SsrfError(f"scheme_not_allowed:{parts.scheme or '(none)'}")
    if parts.username or parts.password:
        raise SsrfError("url_has_credentials")
    host = normalize_host(parts.hostname or "")
    if not host:
        raise SsrfError("missing_host")

    if is_loopback_host(host):
        if not allow_loopback:
            raise SsrfError("loopback_not_allowed")
        return host

    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise SsrfError(f"dns_failed:{type(e).__name__}") from e
    addrs = {info[4][0] for info in infos}
    if not addrs:
        raise SsrfError("dns_empty")
    for addr in sorted(addrs):
        if not _addr_allowed(addr):
            raise SsrfError(f"private_or_reserved:{addr}")
    return host


def _origin(url: str) -> tuple:
    """(scheme, host, port) —— 跨 origin 才算换了目标；换端口同样算换。"""
    p = urlsplit(url)
    default = 443 if p.scheme == "https" else 80
    return (p.scheme, normalize_host(p.hostname or ""), p.port or default)


def guarded_open(
    url: str,
    data: bytes | None = None,
    headers: dict | None = None,
    *,
    allow_loopback: bool = False,
    trusted_hosts=(),
    max_bytes: int = MAX_BODY_BYTES,
    timeout: float = 30.0,
    max_redirects: int = 3,
    method: str | None = None,
) -> bytes:
    """带五要素校验的取数；返回响应体原始字节。"""
    hdrs = {k: v for k, v in (headers or {}).items()}
    current = url
    for _hop in range(max_redirects + 1):
        host = check_url(current, allow_loopback=allow_loopback, trusted_hosts=trusted_hosts)
        parts = urlsplit(current)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        conn = cls(host, port, timeout=timeout)
        try:
            verb = method or ("GET" if data is None else "POST")
            conn.request(verb, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            if resp.status in _REDIRECT_CODES:
                loc = resp.getheader("Location")
                if not loc:
                    raise SsrfError("redirect_without_location")
                nxt = urljoin(current, loc)
                if _origin(nxt) != _origin(current):
                    hdrs.pop("Authorization", None)   # 跨 origin 跳转丢凭据（换端口也算）
                try:
                    resp.read(0)
                except Exception:  # noqa: BLE001
                    pass
                current = nxt
                continue
            buf: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise SsrfError(f"body_too_large:{total}>{max_bytes}")
                buf.append(chunk)
            return b"".join(buf)
        finally:
            conn.close()
    raise SsrfError("too_many_redirects")
