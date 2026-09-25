#!/usr/bin/env python3
"""家卫部署冒烟测试（社区版）

在飞牛 / 任意 Linux 上 `docker compose up -d` 之后跑本脚本，验证整条链路是否真的活了：

  · 服务存活        —— /api/health（免鉴权）
  · 鉴权门禁生效     —— 不带口令访问 /api/overview 必须 401
  · 带口令可读全部接口 —— overview / devices / destinations / alerts /
                        unknown-domains / suggestions / blind-spots
  · 采集激活情况与盲区 —— 来自 /api/overview 的 collection 字段（哪个采集器在干活）

并提示用 `docker stats homeward` 看真实资源占用（设计目标 < 100 MB / 近零 CPU）。

用法：
  python scripts/smoke.py --base http://<设备IP>:9595 --token <HOMEWARD_AUTH_TOKEN>
  python scripts/smoke.py                 # 默认 http://127.0.0.1:9595，无口令（只验健康 + 登录页 + 门禁）

纯标准库，无需安装任何依赖；Windows / Linux / macOS 都能跑。
"""
import argparse
import http.client
import json
import sys
import urllib.parse

PROTECTED = [
    "/api/overview",
    "/api/devices",
    "/api/destinations",
    "/api/alerts",
    "/api/unknown-domains",
    "/api/suggestions",
    "/api/blind-spots",
]


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


def main() -> int:
    ap = argparse.ArgumentParser(description="家卫部署冒烟测试")
    ap.add_argument("--base", default="http://127.0.0.1:9595",
                    help="服务地址（默认 http://127.0.0.1:9595）")
    ap.add_argument("--token", default=None,
                    help="HOMEWARD_AUTH_TOKEN；不填则只验健康/登录页/门禁")
    ap.add_argument("--timeout", type=float, default=10,
                    help="单请求超时（秒，默认 10）")
    args = ap.parse_args()

    base = args.base
    print(f"== 家卫冒烟测试：{base} ==")
    print()

    # 1) 健康
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

    if not args.token:
        # 2) 无口令：门禁应拦 + 登录页应可达
        print()
        ov_status, _ = _get(base, "/api/overview", timeout=args.timeout)
        gate_ok = ov_status == 401
        print(f"[{'OK ' if gate_ok else 'FAIL'}] 未带口令 /api/overview -> {ov_status} "
              f"（期望 401 = 鉴权门禁生效）")
        lg_status, _ = _get(base, "/login", timeout=args.timeout)
        login_ok = lg_status == 200
        print(f"[{'OK ' if login_ok else 'FAIL'}] /login -> {lg_status}（登录页应可达）")
        print()
        print("提示：传入 --token 可继续验证全部受保护接口与采集激活情况。")
        return 0 if gate_ok and login_ok else 1

    # 2) 登录拿会话 cookie
    print()
    lg_status, cookie = _login(base, args.token, timeout=args.timeout)
    lg_ok = lg_status in (200, 302) and bool(cookie)
    print(f"[{'OK ' if lg_ok else 'FAIL'}] /api/login -> {lg_status}")
    if not cookie:
        print("      ✗ 登录失败（口令错误？）。请确认与 HOMEWARD_AUTH_TOKEN 一致。")
        return 1

    # 3) 各受保护接口
    failures = 0
    for path in PROTECTED:
        st, body = _get(base, path, cookie=cookie, timeout=args.timeout)
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
            except json.JSONDecodeError:
                pass
            print(f"[{mark}] {path} -> {st}{extra}")
        else:
            print(f"[{mark}] {path} -> {st}")
            failures += 1

    print()
    if failures == 0:
        print("✓ 全部受保护接口可读。")
    else:
        print(f"✗ {failures} 个接口异常，请查上面明细。")

    print()
    print("资源占用（设计目标 < 100 MB / 近零 CPU）请另开终端执行：")
    print("    docker stats homeward")
    print("飞牛里若 dnsmasq 日志路径不同，在 .env 设 DNS_LOG_PATH 并重新 up。")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
