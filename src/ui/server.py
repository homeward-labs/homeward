"""
W4 —— Web UI 服务端（社区版开源范围）

为什么用标准库 http.server
-------------------------
社区版刻意做到**零第三方依赖**（见 requirements.txt）。一个跑在家庭网关上的常驻
服务，依赖越少越好：镜像小、启动快、供应链攻击面小。代价是没有模板引擎与路由框架，
所以这里手写了一个几十行的路由表 —— 对本项目的十个接口来说，这比拖进一个框架划算。

四条硬规则
----------
1. **零外部资源**。页面不引任何 CDN / 字体 / 统计脚本，CSP 锁死 `default-src 'self'`。
   一个隐私工具自己的界面去请求第三方，是说不过去的。
2. **只读**。社区版界面**没有任何会改动网络配置的写操作**：唯一可写接口是
   「忽略一条告警」（只动界面状态）。阻断按钮一律禁用并注明属标准版能力，
   不做"点了假装生效"的假按钮。
3. **不缓存**。`no-store` —— 家庭网络观测数据不该留在浏览器缓存里。
4. **盲区要显示**。`blind_spots` / 覆盖率是接口的一等公民，不是调试信息。

鉴权状态：**当前无鉴权**。绑定到非回环地址时启动日志会明确告警，
这是一条已知缺口，不掩饰（见 docs/ROADMAP.md 的 P1 项）。
"""

import argparse
import json
import logging
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

SRC_DIR = Path(__file__).resolve().parent.parent  # src/
sys.path.insert(0, str(SRC_DIR))

from core.demo import seed_demo                    # noqa: E402
from core.main import HomewardService              # noqa: E402

logger = logging.getLogger("homeward.ui")

DEFAULT_PORT = 9595
DEFAULT_HOST = "127.0.0.1"
VERSION = "0.1.0"
EDITION = "community"

STATIC_DIR = Path(__file__).resolve().parent / "static"

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}

# 一个隐私工具的界面：不引外部资源、不允许被嵌套、不留缓存
SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy",
     "default-src 'self'; "
     "script-src 'self'; "
     "style-src 'self'; "
     "img-src 'self' data:; "
     "connect-src 'self'; "
     "frame-ancestors 'none'; "
     "base-uri 'none'; "
     "form-action 'none'"),
]

# 社区版能力边界 —— 前端据此把不可用的操作显示为禁用态，而不是灰掉不给理由
EDITION_INFO = {
    "edition": EDITION,
    "label": "社区版",
    "can_see": True,
    "can_enforce": False,
    "enforce_note": "实际拦截（DNS 黑名单 / nftables / VLAN 隔离）属标准版能力，"
                    "本仓库不含其实现。社区版只告诉你「拦下会怎样」。",
}


# ---------------------------------------------------------------- 请求处理

class HomewardHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器

    ``service`` 与 ``start_time`` 由 :func:`make_server` 通过子类注入 —— 不用
    全局变量，这样单测可以并行起多个互不干扰的实例。
    """

    server_version = "homeward/" + VERSION
    service: HomewardService = None
    start_time: float = 0.0

    # ---- 基础 ----

    def log_message(self, fmt, *args):
        """默认实现写 stderr；统一收到 logger，便于容器收集"""
        logger.info("%s %s", self.address_string(), fmt % args)

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if path.startswith("/api/"):
                self._api(method, path, parse_qs(parsed.query))
            elif method in ("GET", "HEAD"):
                self._static(method, path)
            else:
                self._json(405, {"error": "method_not_allowed", "path": path})
        except Exception as exc:  # 单条请求的异常不能把整个服务带下线
            logger.exception("处理 %s %s 时出错", method, path)
            self._json(500, {"error": "internal_error", "detail": str(exc)})

    # ---- 输出 ----

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _static(self, method: str, path: str):
        # 静态文件直接放在 static/ 下，URL 上的 /static/ 前缀只是命名空间
        if path in ("/", ""):
            rel = "index.html"
        elif path.startswith("/static/"):
            rel = path[len("/static/"):]
        else:
            rel = path.lstrip("/")
        # 目录穿越防护：解析后的真实路径必须仍在 static/ 内
        try:
            target = (STATIC_DIR / rel).resolve()
        except (OSError, ValueError):
            self._json(400, {"error": "bad_path"})
            return
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            self._json(404, {"error": "not_found", "path": path})
            return
        ctype = MIME_TYPES.get(target.suffix.lower(), "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # ---- API ----

    def _api(self, method: str, path: str, query: dict):
        svc = self.service
        if svc is None:
            self._json(503, {"error": "service_not_ready"})
            return

        # 只读接口的动词约束：写方法一律 405。社区版界面没有任何"改网络"的动作，
        # 这里把只读性做成接口契约，而不是靠前端自觉。
        if path in ("/api/health", "/api/overview", "/api/devices", "/api/destinations",
                    "/api/alerts", "/api/suggestions", "/api/unknown-domains",
                    "/api/blind-spots", "/api/domain") and method not in ("GET", "HEAD"):
            self._json(405, {"error": "method_not_allowed", "need": "GET"})
            return

        if path == "/api/health":
            self._json(200, {
                "ok": True,
                "version": VERSION,
                "edition": EDITION_INFO,
                "uptime_seconds": round(time.time() - self.start_time, 1),
                "kb_domains": len(svc.kb.domains),
                "behaviors_supported": len(svc.behavior_matcher.supported_rules),
                "behaviors_unsupported": svc.behavior_matcher.unsupported(),
                "vendor_lookup_enabled": svc.device_registry.vendor_lookup_enabled,
            })
            return

        if path == "/api/overview":
            stats = svc.get_stats()
            self._json(200, {
                "version": VERSION,
                "edition": EDITION_INFO,
                "uptime_seconds": round(time.time() - self.start_time, 1),
                "stats": stats,
                "alerts": svc.get_alert_stats(),
                "coverage": svc.attribution_coverage(),
                "blind_spots": svc.get_blind_spots(),
            })
            return

        if path == "/api/devices":
            self._json(200, {"items": svc.get_devices()})
            return

        if path == "/api/destinations":
            self._json(200, svc.get_destinations())
            return

        if path == "/api/alerts":
            include = query.get("include_dismissed", ["0"])[0] in ("1", "true")
            self._json(200, {"items": svc.get_alerts(include_dismissed=include)})
            return

        m = re.fullmatch(r"/api/alerts/([^/]+)/dismiss", path)
        if m:
            if method != "POST":
                self._json(405, {"error": "method_not_allowed", "need": "POST"})
                return
            alert_id = unquote(m.group(1))
            ok = svc.dismiss_alert(alert_id)
            self._json(200 if ok else 404,
                       {"dismissed": ok, "id": alert_id})
            return

        if path == "/api/suggestions":
            self._json(200, {
                "items": list(svc.suggested_rules),
                "note": EDITION_INFO["enforce_note"],
            })
            return

        if path == "/api/unknown-domains":
            self._json(200, {"items": svc.get_unknown_domains()})
            return

        if path == "/api/blind-spots":
            self._json(200, {"items": svc.get_blind_spots()})
            return

        if path == "/api/domain":
            q = (query.get("q") or [""])[0].strip().lower()
            if not q:
                self._json(400, {"error": "missing_query"})
                return
            self._json(200, svc.describe_domain(q))
            return

        if path == "/api/scan":
            # 手动跑一轮行为识别。只读：不产生任何网络侧改动。
            if method != "POST":
                self._json(405, {"error": "method_not_allowed", "need": "POST"})
                return
            new = svc.run_behavior_scan()
            self._json(200, {"new_alerts": len(new), "alerts": svc.get_alerts()})
            return

        self._json(404, {"error": "not_found", "path": path})


# ---------------------------------------------------------------- 启动

def make_server(service: HomewardService, host: str = DEFAULT_HOST,
                port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    """创建一个绑定好的服务实例（未启动 serve_forever）

    用子类注入 service，避免全局变量 —— 单测里可以起多个互不干扰的实例。
    """
    handler_cls = type(
        "HomewardHandler",
        (HomewardHandler,),
        {"service": service, "start_time": time.time()},
    )
    ThreadingHTTPServer.allow_reuse_address = True
    return ThreadingHTTPServer((host, port), handler_cls)


def run_server(service: HomewardService, host: str = DEFAULT_HOST,
               port: int = DEFAULT_PORT) -> None:
    """阻塞运行直到 Ctrl-C"""
    httpd = make_server(service, host=host, port=port)
    _warn_if_exposed(host)
    logger.info("家卫 Web UI：http://%s:%d", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("收到中断，正在关闭 Web UI")
    finally:
        httpd.server_close()


def _warn_if_exposed(host: str) -> None:
    """绑定到非回环地址时明确告警：当前版本**没有鉴权**"""
    if host in ("127.0.0.1", "localhost", "::1"):
        return
    msg = (f"Web UI 绑定到 {host}：当前版本没有鉴权，"
           "同一网络内任何人都能看到家里的设备与外联情况。请确认你信任该网络，"
           "或用防火墙限制来源。")
    logger.warning(msg)
    print("[警告] " + msg)


def main(argv=None) -> int:
    # 环境变量兜底：容器里用 HOST / PORT 配（docker-compose 与 Dockerfile 都这么设），
    # 命令行参数优先。这样 CMD 可以保持 exec 形式，不必为了展开变量退化成 shell 形式。
    env_host = os.environ.get("HOST") or DEFAULT_HOST
    try:
        env_port = int(os.environ.get("PORT") or DEFAULT_PORT)
    except ValueError:
        env_port = DEFAULT_PORT

    ap = argparse.ArgumentParser(description="家卫 Web UI（社区版：只读）")
    ap.add_argument("--host", default=env_host,
                    help=f"监听地址（默认 {DEFAULT_HOST}；容器内需要 0.0.0.0）")
    ap.add_argument("--port", type=int, default=env_port,
                    help=f"监听端口（默认 {DEFAULT_PORT}）")
    ap.add_argument("--demo", action="store_true",
                    help="灌入演示数据（用于界面自测，生产路径请勿使用）")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    service = HomewardService(config={"load_system_devices": not args.demo})
    if args.demo:
        out = seed_demo(service)
        print(f"[演示数据] 设备 {len(out['devices']['devices'])} 台、"
              f"观测 {out['flows']} 条、告警 {len(out['alerts'])} 条")

    run_server(service, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
