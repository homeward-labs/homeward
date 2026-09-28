#!/usr/bin/env python3
"""家卫部署冒烟测试（社区版）

在飞牛 / 任意 Linux 上 `docker compose up -d` 之后跑本脚本，验证整条链路是否真的活了：

  · 服务存活        —— /api/health（免鉴权）
  · 自动适配鉴权模式 —— 不带 --token 时：无鉴权则直接探全部只读接口；
                       有鉴权则提示传入 --token
  · 带口令可读全部接口 —— overview / devices / destinations / alerts / unknown-domains /
                        suggestions / blind-spots / license/status / report(json·markdown) /
                        qr / domain（以上全为 GET，无副作用）
  · 采集激活情况与盲区 —— 来自 /api/overview 的 collection 字段（哪个采集器在干活）

加 `--write` 会额外验证写操作链路（**会改动服务状态**，别对生产实例跑）：

  · 离线日志导入     —— POST /api/import 灌入样例 dnsmasq 行，应解析出流
  · 无效许可容错     —— POST /api/activate 塞一个假令牌，服务必须平静拒绝且不崩
  · 撤销并自清       —— POST /api/license/deactivate 清回社区版，再确认服务仍存活

CI 里对一次性容器跑 `--write` 正合适；对你正在用的实例，请只用默认的只读检查。

并提示用 `docker stats homeward` 看真实资源占用（设计目标 < 100 MB / 近零 CPU）。

用法：
  python scripts/smoke.py --base http://<设备IP>:9595
  python scripts/smoke.py --base http://<设备IP>:9595 --token <HOMEWARD_AUTH_TOKEN>   # 仅当启用了口令鉴权
  python scripts/smoke.py --base http://127.0.0.1:9595 --write                        # CI / 一次性容器

默认「零配置即无鉴权」：不带 --token 时脚本会自动探测——若服务无鉴权则直接验证全部
只读接口；若服务启用了鉴权则提示传入 --token。纯标准库，Windows / Linux / macOS 都能跑。
"""
import argparse
import http.client
import json
import sys
import urllib.parse

# 只读接口：全部是 GET，跑冒烟不会改动服务状态，对生产实例也安全。
PROTECTED = [
    "/api/overview",
    "/api/devices",
    "/api/destinations",
    "/api/alerts",
    "/api/unknown-domains",
    "/api/suggestions",
    "/api/blind-spots",
    # —— 社区版 P0 三件套 + 付费升级链路（新增）——
    "/api/license/status",
    "/api/report?format=json",
    "/api/report?format=markdown",
    "/api/qr?text=homeward-smoke-test",
    "/api/domain?q=example.com",
]

# 写操作检查用的样例日志：真实 dnsmasq 查询行格式（见 src/collectors/dns.py）
SAMPLE_LOG = "\n".join([
    "Feb 11 12:34:56 dnsmasq[1234]: query[A] www.example.com from 192.168.1.50",
    "Feb 11 12:34:57 dnsmasq[1234]: query[A] api.io.mi.com from 192.168.1.51",
    "Feb 11 12:34:58 dnsmasq[1234]: query[AAAA] www.example.com from 192.168.1.50",
])


def _conn(base: str, timeout: float):
    p = urllib.parse.urlparse(base)
    return http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)


def _get(base: str, path: str, cookie: str = None, timeout: float = 10):
    # http.client 不跟随重定向：受保护接口返回 200/401 都不会被悄悄改写。
    try:
        conn = _conn(base, timeout)
        headers = {"Cookie": cookie} if cookie else {}
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")
        status = resp.status
        conn.close()
        return status, data
    except Exception as e:  # 连接失败等
        return -1, str(e)


def _post(base: str, path: str, body: bytes, content_type: str,
          cookie: str = None, timeout: float = 10):
    try:
        conn = _conn(base, timeout)
        headers = {"Content-Type": content_type}
        if cookie:
            headers["Cookie"] = cookie
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")
        status = resp.status
        conn.close()
        return status, data
    except Exception as e:  # 连接失败等
        return -1, str(e)


def _login(base: str, token: str, timeout: float = 10):
    # 登录返回 302 + Set-Cookie；http.client 不跟随重定向，正好原样拿到会话 cookie。
    try:
        conn = _conn(base, timeout)
        body = urllib.parse.urlencode({"token": token}).encode("utf-8")
        conn.request("POST", "/api/login", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        sc = resp.getheader("Set-Cookie") or ""
        conn.close()
        for part in sc.split(";"):
            part = part.strip()
            if part.startswith("homeward_session="):
                # 返回完整的 name=value，直接作为后续请求的 Cookie 头
                return resp.status, part
        return resp.status, None
    except Exception:
        return -1, None


def _ok(status: int) -> str:
    return "OK " if 200 <= status < 300 else "FAIL"


def probe_protected(base: str, cookie: str = None, timeout: float = 10) -> int:
    """遍历全部只读接口，返回异常数（0 = 全绿）"""
    failures = 0
    for path in PROTECTED:
        st, body = _get(base, path, cookie=cookie, timeout=timeout)
        mark = _ok(st)
        if 200 <= st < 300:
            extra = ""
            try:
                j = json.loads(body)
                if path == "/api/overview":
                    coll = j.get("stats", {}).get("collection") or []
                    active = [c["collector"] for c in coll if c.get("active")]
                    blind = j.get("blind_spots") or []
                    extra = f" | 采集激活：{active or '无'} | 盲区 {len(blind)} 条"
                elif path == "/api/devices":
                    extra = f" | 设备 {len(j.get('items', []))} 台"
                elif path == "/api/alerts":
                    extra = f" | 告警 {len(j.get('items', []))} 条"
                elif path.startswith("/api/license/status"):
                    lic = j.get("license") or {}
                    extra = (f" | 版次 {j.get('edition', {}).get('label')}"
                             f" / 许可有效 {bool(lic.get('valid'))}")
                elif path.startswith("/api/report"):
                    extra = f" | 设备 {len((j.get('devices') or {}))} 台"
                elif path.startswith("/api/domain"):
                    extra = f" | 归属 {j.get('organization') or '未知'}"
            except json.JSONDecodeError:
                pass
            # Markdown 报告不是 JSON：按字节数确认非空即可
            if not extra and path.startswith("/api/report"):
                extra = f" | {len(body)} 字节"
            if not extra and path.startswith("/api/qr"):
                extra = f" | SVG {len(body)} 字节"
            print(f"[{mark}] {path} -> {st}{extra}")
        else:
            print(f"[{mark}] {path} -> {st}")
            failures += 1
    return failures


def probe_write(base: str, cookie: str = None, timeout: float = 10) -> int:
    """写操作检查（仅 --write 时跑）。

    会改动服务状态：灌入样例观测、写入一个无效许可令牌再清掉。
    **不要对你正在用的生产实例跑**；CI / 一次性容器才是它的使用场景。
    """
    failures = 0

    # 1) 离线日志导入：必须解析出流，而不是静默返回 0
    st, body = _post(base, "/api/import", SAMPLE_LOG.encode("utf-8"),
                     "text/plain", cookie, timeout)
    extra = ""
    if 200 <= st < 300:
        try:
            s = (json.loads(body).get("stats") or {})
            extra = (f" | 解析 {s.get('parsed')} 行 / 流 {s.get('flows')} 条"
                     f" / 错误 {s.get('errors')}")
            if not s.get("flows"):
                extra += "  ← 一行都没解析出来，检查日志格式"
                failures += 1
        except json.JSONDecodeError:
            pass
        print(f"[{_ok(st)}] POST /api/import -> {st}{extra}")
    else:
        print(f"[{_ok(st)}] POST /api/import -> {st} {body[:120]}")
        failures += 1

    # 2) 无效许可令牌：必须「平静拒绝」—— 不能 500 崩、不能把服务搞死
    st, _ = _post(base, "/api/activate",
                  urllib.parse.urlencode({"token": "not-a-valid-license"}).encode("utf-8"),
                  "application/x-www-form-urlencoded", cookie, timeout)
    ok = st in (200, 400, 401, 403)
    if not ok:
        failures += 1
    print(f"[{'OK ' if ok else 'FAIL'}] POST /api/activate(无效令牌) -> {st}"
          f"（期望 200/4xx，不应 5xx）")

    # 3) 自清：撤销上面写入的令牌，回到社区版
    st, _ = _post(base, "/api/license/deactivate", b"",
                  "application/x-www-form-urlencoded", cookie, timeout)
    print(f"[{_ok(st)}] POST /api/license/deactivate -> {st}")
    if not (200 <= st < 300):
        failures += 1

    # 4) 兜底：一轮写操作之后服务必须还活着
    st, _ = _get(base, "/api/health", cookie=cookie, timeout=timeout)
    print(f"[{_ok(st)}] /api/health（写操作后） -> {st}")
    if not (200 <= st < 300):
        failures += 1
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description="家卫部署冒烟测试")
    ap.add_argument("--base", default="http://127.0.0.1:9595",
                    help="服务地址（默认 http://127.0.0.1:9595）")
    ap.add_argument("--token", default=None,
                    help="HOMEWARD_AUTH_TOKEN；默认不填，脚本自动适配（无鉴权直探 / 有鉴权提示传 token）")
    ap.add_argument("--timeout", type=float, default=10,
                    help="单请求超时（秒，默认 10）")
    ap.add_argument("--write", action="store_true",
                    help="额外验证写操作（离线导入 / 无效许可容错 / 撤销自清）。"
                         "会改动服务状态，仅用于 CI 或一次性容器")
    args = ap.parse_args()

    base = args.base
    print(f"== 家卫冒烟测试：{base} ==")
    print()

    # 1) 健康（免鉴权）
    h_status, h_body = _get(base, "/api/health", timeout=args.timeout)
    print(f"[{_ok(h_status)}] /api/health  -> {h_status}")
    if h_status == 200:
        try:
            h = json.loads(h_body)
            print(f"      版本 {h.get('version')} / 版次 {h.get('edition', {}).get('label')} "
                  f"/ 知识库域名 {h.get('kb_domains')} 个")
        except json.JSONDecodeError:
            pass
    else:
        print("      ✗ 服务未存活，停止。请先 `docker compose logs homeward` 排查。")
        return 1

    # 2) 不带 token：自动探测鉴权模式
    if not args.token:
        ov_status, _ = _get(base, "/api/overview", timeout=args.timeout)
        if ov_status == 200:
            print()
            print("[] 服务为「无鉴权」模式（开箱即用）；直接验证全部只读接口：")
            failures = probe_protected(base, cookie=None, timeout=args.timeout)
            if args.write:
                print()
                print("[] 写操作检查（--write）：")
                failures += probe_write(base, cookie=None, timeout=args.timeout)
        elif ov_status == 401:
            lg_status, _ = _get(base, "/login", timeout=args.timeout)
            login_ok = lg_status == 200
            print(f"[{'OK ' if login_ok else 'FAIL'}] /login -> {lg_status}（登录页应可达）")
            print()
            print("提示：服务启用了鉴权，传入 --token <口令> 可继续验证全部受保护接口。")
            if args.write:
                print("      --write 同样需要 --token（写接口受鉴权保护）。")
            print("\n资源占用（设计目标 < 100 MB）请另开终端执行：\n    docker stats homeward")
            return 0 if login_ok else 1
        else:
            print(f"FAIL /api/overview -> {ov_status}（非预期状态码）")
            return 1
        print()
        if failures == 0:
            print("✓ 全部只读接口可读。")
        else:
            print(f"✗ {failures} 个接口异常，请查上面明细。")
        print("\n资源占用（设计目标 < 100 MB / 近零 CPU）请另开终端执行：\n    docker stats homeward")
        print("飞牛里若 dnsmasq 日志路径不同，在 .env 设 DNS_LOG_PATH 并重新 up。")
        return 0 if failures == 0 else 1

    # 3) 带 token：登录拿会话 cookie 后探
    print()
    lg_status, cookie = _login(base, args.token, timeout=args.timeout)
    lg_ok = lg_status in (200, 302) and bool(cookie)
    print(f"[{'OK ' if lg_ok else 'FAIL'}] /api/login -> {lg_status}")
    if not cookie:
        print("      ✗ 登录失败（口令错误？）。请确认与 HOMEWARD_AUTH_TOKEN 一致。")
        return 1
    failures = probe_protected(base, cookie=cookie, timeout=args.timeout)
    if args.write:
        print()
        print("[] 写操作检查（--write）：")
        failures += probe_write(base, cookie=cookie, timeout=args.timeout)
    print()
    if failures == 0:
        print("✓ 全部受保护接口可读。")
    else:
        print(f"✗ {failures} 个接口异常，请查上面明细。")
    print("\n资源占用（设计目标 < 100 MB / 近零 CPU）请另开终端执行：\n    docker stats homeward")
    print("飞牛里若 dnsmasq 日志路径不同，在 .env 设 DNS_LOG_PATH 并重新 up。")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
