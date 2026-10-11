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

鉴权状态：**默认零配置即无鉴权（开箱即用，浏览器直开）**；仅当显式提供口令
（``HOMEWARD_AUTH_TOKEN`` / ``--auth-token``）时才启用单用户口令鉴权，登录后以
``HttpOnly`` + ``SameSite=Strict`` 的会话 cookie 维持（见 ``src/ui/auth.py``）。
``--no-auth`` 可强制关闭鉴权。暴露到不可信网络时务必设口令，并用防火墙限制来源 IP。
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

SRC_DIR = Path(__file__).resolve().parent.parent  # src/
sys.path.insert(0, str(SRC_DIR))

from core.demo import seed_demo                    # noqa: E402
from core.import_log import import_log_text        # noqa: E402
from core.main import HomewardService, ROOT        # noqa: E402
from ui.auth import SESSION_COOKIE, WebAuth        # noqa: E402
from ui.qr import qr_svg, max_capacity_bytes      # noqa: E402
from adapters.sqlite_registry import SqliteObservationStore  # noqa: E402
from license.store import (                        # noqa: E402
    device_fingerprint,
    status as license_status,
    save_token,
    clear_token,
)
from license.verify import assert_production_key   # noqa: E402

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
     "form-action 'self'"),
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


# ---------------------------------------------------------------- 报告渲染

def _report_markdown(payload: dict) -> str:
    """把观测报告结构化数据渲染成给人看的 Markdown（只含用户自己的遥测）

    注意：这是下载文件，不进浏览器渲染管线，无需 esc()。知识库仍是服务器端商业机密，
    此处**不**输出知识库全表，只呈现用户自己观测到的域名及其本地查询结论。
    """
    rep = payload.get("report", {})
    stats = payload.get("stats", {}) or {}
    cov = payload.get("coverage", {}) or {}
    devices = payload.get("devices", []) or []
    dests = payload.get("destinations", {}) or {}
    unknowns = payload.get("unknown_domains", []) or []
    alerts = payload.get("alerts", []) or []
    spots = payload.get("blind_spots", []) or []

    gen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rep.get("generated_at", 0) or 0))
    rate = cov.get("hit_rate", 0.0)
    rate_pct = f"{rate * 100:.1f}%" if isinstance(rate, (int, float)) else str(rate)

    L = []
    L.append("# 家卫 Homeward · 观测报告")
    L.append("")
    L.append(f"- 生成时间：{gen}")
    L.append(f"- 版本：{stats.get('version', '?')}（社区版）")
    L.append(f"- 范围：{rep.get('scope', '用户自己的观测遥测（不含知识库）')}")
    L.append("")
    L.append("> 本报告仅包含你自己的观测数据（设备、去向、未知域名、告警、盲区）。"
             "知识库在服务器端，不会经此导出。")
    L.append("")
    L.append("## 概览")
    L.append("")
    L.append(f"- 设备总数：{stats.get('devices_total', 0)}（其中 {stats.get('vendors_resolved', 0)} 台识别出厂商）")
    L.append(f"- 观测记录：{stats.get('flows_processed', 0)} 条，决策 {stats.get('decisions_made', 0)} 条")
    L.append(f"- 活跃告警：{stats.get('alerts_active', 0)} 条")
    L.append(f"- 域名归属覆盖率：{cov.get('hit', 0)} / {cov.get('total', 0)}（{rate_pct}）")
    L.append("")
    L.append("## 设备台账")
    L.append("")
    if devices:
        L.append("| 名称 | IP | MAC | 厂商 | 品类 | 主要去向 |")
        L.append("| --- | --- | --- | --- | --- | --- |")
        for d in devices:
            name = d.get("name") or "-"
            ips = "、".join(d.get("ips") or []) or "-"
            mac = d.get("mac") or "-"
            vendor = d.get("vendor") or "-"
            dtype = d.get("device_type") or "unknown"
            top = "、".join(
                f"{t.get('domain')}({t.get('count')})" for t in (d.get("top_domains") or [])[:5]
            )
            L.append(f"| {name} | {ips} | {mac} | {vendor} | {dtype} | {top} |")
    else:
        L.append("（无）")
    L.append("")
    L.append("## 去向地图")
    L.append("")
    items = dests.get("items", []) if isinstance(dests, dict) else dests
    if items:
        known = dests.get("known", 0) if isinstance(dests, dict) else 0
        L.append(f"共 {len(items)} 个域名，认出 {known} 个。")
        L.append("")
        for x in items[:200]:
            org = x.get("organization") or "未识别"
            tail = f"；涉及 {len(x.get('devices', []))} 台设备" if x.get("devices") else ""
            L.append(f"- `{x.get('domain')}` — {org}"
                     f"（{x.get('category','?')}，置信度 {x.get('confidence','?')}）{tail}")
    else:
        L.append("（无）")
    L.append("")
    L.append("## 未知域名")
    L.append("")
    if unknowns:
        for u in unknowns:
            L.append(f"- {u}")
    else:
        L.append("（所有观测域名都能在知识库查到归属）")
    L.append("")
    L.append("## 告警")
    L.append("")
    if alerts:
        for a in alerts:
            dom = a.get("domain") or a.get("destination")
            L.append(f"- **[{a.get('severity_label','?')}] {a.get('title','')}**"
                     f" · {a.get('device_name','?')} → {dom}（归属：{a.get('organization') or '未识别'}）")
            L.append(f"  - 说明：{a.get('summary','')}")
            L.append(f"  - 建议：{a.get('action_label','')}；后果：{a.get('side_effects','')}")
    else:
        L.append("（无活跃告警）")
    L.append("")
    L.append("## 盲区")
    L.append("")
    if spots:
        for s in spots:
            L.append(f"- {s}")
    else:
        L.append("（无）")
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- 请求处理


class HomewardHandler(BaseHTTPRequestHandler):
    """HTTP 请求处理器

    ``service`` 与 ``start_time`` 由 :func:`make_server` 通过子类注入 —— 不用
    全局变量，这样单测可以并行起多个互不干扰的实例。
    """

    server_version = "homeward/" + VERSION
    service: HomewardService = None
    start_time: float = 0.0
    auth: "WebAuth | None" = None
    observation_store: "SqliteObservationStore | None" = None

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
        query = parse_qs(parsed.query)
        try:
            # —— 鉴权门禁 ——
            # 白名单（免登录）：登录页 / 登录登出接口 / 健康检查 / 登录页样式
            if path in ("/login", "/api/login", "/api/logout", "/api/health",
                        "/static/login.css"):
                self._public(method, path, query)
                return
            if self.auth is not None and not self.auth.is_authenticated(self):
                if path.startswith("/api/"):
                    self._json(401, {"error": "unauthorized", "login": "/login"})
                else:
                    self._send_redirect("/login")
                return
            # —— 已登录：正常路由 ——
            if path.startswith("/api/"):
                self._api(method, path, query)
            elif method in ("GET", "HEAD"):
                self._static(method, path)
            else:
                self._json(405, {"error": "method_not_allowed", "path": path})
        except Exception as exc:  # 单条请求的异常不能把整个服务带下线
            logger.exception("处理 %s %s 时出错", method, path)
            self._json(500, {"error": "internal_error", "detail": str(exc)})

    # ---- 免鉴权路由（登录页 / 登录登出 / 健康 / 登录样式）----

    def _public(self, method: str, path: str, query: dict):
        if path == "/api/health":
            self._api(method, path, query)
        elif path == "/login":
            self._serve_login()
        elif path == "/api/login":
            self._login(method)
        elif path == "/api/logout":
            self._logout(method)
        elif path == "/static/login.css":
            self._static(method, path)
        else:
            self._json(404, {"error": "not_found", "path": path})

    def _serve_login(self):
        if self.auth is None:
            html = ("<html lang='zh-CN'><body style='font-family:sans-serif'>"
                    "<h1>家卫</h1><p>当前以 <code>--no-auth</code> 启动，未启用鉴权。"
                    "直接访问 <a href='/'>首页</a> 即可。</p></body></html>")
        else:
            html = self.auth.login_page_html()
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _login(self, method: str):
        if method != "POST":
            self._json(405, {"error": "method_not_allowed", "need": "POST"})
            return
        form = self._read_form()
        token = (form.get("token") or [""])[0]
        if self.auth is None or not self.auth.verify(token):
            self._json(401, {"error": "invalid_token"})
            return
        # 种会话 cookie 并跳回首页
        self._send_redirect("/",
                            extra_headers=[("Set-Cookie", self.auth.session_cookie())])

    def _logout(self, method: str):
        if method != "POST":
            self._json(405, {"error": "method_not_allowed", "need": "POST"})
            return
        cookie = self.auth.logout_cookie() if self.auth else f"{SESSION_COOKIE}=; Max-Age=0; Path=/"
        self._send_json_with_headers(200, {"ok": True},
                                     extra_headers=[("Set-Cookie", cookie)])

    # ---- 输出辅助 ----

    def _send_redirect(self, location: str, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", location)
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()

    def _send_json_with_headers(self, status: int, payload: dict, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra_headers)

    def _read_form(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b""
        return parse_qs(raw.decode("utf-8", "replace"))

    def _read_text_body(self) -> str:
        """读取请求体原文（用于离线日志导入等非表单输入）"""
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b""
        return raw.decode("utf-8", "replace")

    def _parse_import_payload(self, text: str) -> str:
        """从请求体里取出日志文本：支持 JSON / form / 裸文本三种入参"""
        text = text or ""
        # 1) JSON：{"log": "..."} 或 {"text": "..."}
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                log = obj.get("log") or obj.get("text") or ""
                if log:
                    return log
        except (ValueError, TypeError):
            pass
        # 2) form-urlencoded：log=...
        form = parse_qs(text)
        log = (form.get("log") or [""])[0]
        if log:
            return log
        # 3) 裸日志文本
        return text

    # ---- 输出 ----

    def _send(self, status: int, body: bytes, content_type: str, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS:
            self.send_header(k, v)
        for k, v in (extra_headers or []):
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
                    "/api/blind-spots", "/api/domain", "/api/license/status", "/api/qr",
                    "/api/report"
                    ) and method not in ("GET", "HEAD"):
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

        if path == "/api/observations/clear":
            # 一键清除全部观测记录（设备/域名/告警），让用户能重新开始分析：
            # 把"修复前的旧证据"和"重新采集到的新数据"彻底分开。
            # 只清观测态 + 落盘快照（observations.db），绝不碰 actions.db（许可指纹）。
            if method != "POST":
                self._json(405, {"error": "method_not_allowed", "need": "POST"})
                return
            result = svc.reset_observations()
            if self.observation_store is not None:
                try:
                    self.observation_store.clear()
                except Exception as exc:  # 内存态已清，落盘失败不致命
                    logger.warning("清除落盘观测快照失败（内存态已清空）：%s", exc)
            self._json(200, {"ok": True, **result})
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

        # —— 升级 / 许可（Task #12）——
        # 社区版只做"看见 + 升级闸门骨架"：展示状态、出付款二维码、导入并本地校验许可。
        # 真正的签名私钥在服务端（闭源），客户端仅用内嵌公钥验签（纯标准库）。
        if path == "/api/license/status":
            fp = device_fingerprint()
            self._json(200, {
                "edition": EDITION_INFO,
                "license": license_status(expected_device_fp=fp),
                # 付款/订单页 URL 由服务端下发（可经 HOMEWARD_ORDER_URL 配置），
                # 前端不硬编码任何外部 URL，便于私有化部署改写。
                "order_url": os.environ.get(
                    "HOMEWARD_ORDER_URL", "https://pay.homeward.dev/order"),
            })
            return

        if path == "/api/qr":
            text = (query.get("text") or [""])[0]
            if not text:
                self._json(400, {"error": "missing_text"})
                return
            # 容量随纠错等级变化（v10：L=271 字节 / M=213 字节）。预检必须按**实际
            # 使用的等级**算，否则长 URL 会通过检查却在编码时抛 ValueError → 500。
            ec_level = (query.get("ec") or ["M"])[0].upper()
            if ec_level not in ("L", "M"):
                ec_level = "M"
            limit = max_capacity_bytes(ec_level)
            if len(text.encode("utf-8")) > limit:
                self._json(400, {"error": "too_long", "max_bytes": limit,
                                 "ec_level": ec_level})
                return
            try:
                svg = qr_svg(text, ec_level=ec_level)
            except Exception as exc:
                self._json(400, {"error": "qr_encode_failed", "detail": str(exc)})
                return
            self._send(200, svg.encode("utf-8"), "image/svg+xml")
            return

        if path == "/api/activate":
            # 导入许可令牌：本地验签 + 持久化。是社区版唯一允许的"写"动作之一
            # （另一个是忽略告警），不触碰任何网络配置。
            if method != "POST":
                self._json(405, {"error": "method_not_allowed", "need": "POST"})
                return
            form = self._read_form()
            token = (form.get("token") or [""])[0].strip()
            if not token:
                self._json(400, {"error": "missing_token"})
                return
            if not save_token(token):
                self._json(500, {"error": "save_failed"})
                return
            fp = device_fingerprint()
            self._json(200, {"saved": True,
                             "status": license_status(expected_device_fp=fp)})
            return

        if path == "/api/license/deactivate":
            # 移除本地许可令牌（清回社区版）。仅删本地文件，不联网。
            if method != "POST":
                self._json(405, {"error": "method_not_allowed", "need": "POST"})
                return
            self._json(200, {"cleared": clear_token()})
            return

        # —— 离线日志导入（Task #15）——
        # 把用户粘贴 / 上传的一段 dnsmasq 日志或 conntrack 快照离线回放成观测。
        # 等价于实时采集器看到的内容，不产生任何网络侧改动（社区版「只看见」边界不变）。
        # 知识库是服务器端商业机密，此处**绝不读取或导出**知识库。
        if path == "/api/import":
            if method != "POST":
                self._json(405, {"error": "method_not_allowed", "need": "POST"})
                return
            try:
                log = self._parse_import_payload(self._read_text_body())
                stats = import_log_text(log, svc)
            except ValueError as exc:   # 日志过大等上限保护
                self._json(413, {"error": "payload_too_large", "detail": str(exc)})
                return
            except Exception as exc:     # 单行脏数据已在内部吞掉，这里兜底其他异常
                self._json(500, {"error": "import_failed", "detail": str(exc)})
                return
            # 导入后顺手持久化一次，避免还没等到周期保存就重启丢失
            if self.observation_store is not None:
                try:
                    self.observation_store.save(svc.snapshot_observations())
                except Exception:
                    logger.exception("导入后持久化观测快照失败")
            self._json(200, {"ok": True, "stats": stats})
            return

        # —— 观测报告导出（Task #17）——
        # 只导用户自己的观测遥测（设备 / 去向 / 未知域名 / 告警 / 盲区）；
        # **绝不 Dump 知识库**，也不提供「浏览全部已知域名」接口。
        if path == "/api/report":
            payload = svc.export_report()
            fmt = (query.get("format") or ["markdown"])[0].lower()
            if fmt == "json":
                self._json(200, payload)
                return
            md = _report_markdown(payload)
            self._send(200, md.encode("utf-8"), "text/markdown; charset=utf-8")
            return

        self._json(404, {"error": "not_found", "path": path})


# ---------------------------------------------------------------- 启动

def make_server(service: HomewardService, host: str = DEFAULT_HOST,
                port: int = DEFAULT_PORT, auth: "WebAuth | None" = None,
                observation_store: "SqliteObservationStore | None" = None
                ) -> ThreadingHTTPServer:
    """创建一个绑定好的服务实例（未启动 serve_forever）

    用子类注入 service / auth / observation_store，避免全局变量 —— 单测里可以起多个
    互不干扰的实例。
    """
    handler_cls = type(
        "HomewardHandler",
        (HomewardHandler,),
        {"service": service, "start_time": time.time(),
         "auth": auth, "observation_store": observation_store},
    )
    #启动时恢复上次未确认的「建议阻断」队列。
    # service.start() 是 async 且从未被 run_server 调用（信号注册也在那里），
    # 故这里显式加载一次；幂等，重复调用无副作用。
    service._load_suggestions()
    ThreadingHTTPServer.allow_reuse_address = True
    return ThreadingHTTPServer((host, port), handler_cls)


def run_server(service: HomewardService, host: str = DEFAULT_HOST,
               port: int = DEFAULT_PORT, auth: "WebAuth | None" = None,
               observation_store: "SqliteObservationStore | None" = None) -> None:
    """阻塞运行直到 Ctrl-C"""
    httpd = make_server(service, host=host, port=port, auth=auth,
                        observation_store=observation_store)
    _warn_if_exposed(host, auth)
    logger.info("家卫 Web UI：http://%s:%d", host, port)
    saver = _ObservationSaver(observation_store, service)
    saver.start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("收到中断，正在关闭 Web UI")
    finally:
        saver.stop()
        httpd.server_close()
        # 🔴 关闭路径必须显式落盘「建议阻断」队列。
        # 起因（2026-10-11 真机实测）：本函数原先只停 saver/httpd，从不调
        # service.stop()，而 _save_suggestions() 只挂在 stop() 上
        # → suggested_rules.json 从未生成，重启即清零。
        # 这里不 await（stop() 是 async 但内部无 await点），直接跑协程保证一定执行。
        try:
            asyncio.run(service.stop())
        except Exception as e:  # 落盘失败不该影响退出
            logger.warning("关闭时保存建议队列失败: %s", e)


def _warn_if_exposed(host: str, auth: "WebAuth | None" = None) -> None:
    """绑定到非回环地址时明确告警"""
    if host in ("127.0.0.1", "localhost", "::1"):
        return
    if auth is None:
        msg = (f"Web UI 绑定到 {host} 且**未启用鉴权**（--no-auth）："
               "同一网络内任何人都能看到家里的设备与外联情况。仅限可信局域网使用。")
    else:
        msg = (f"Web UI 绑定到 {host}：已启用口令鉴权，但仍请确保你信任该网络，"
               "或用防火墙限制来源 IP。")
    logger.warning(msg)
    print("[警告] " + msg)


class _ObservationSaver:
    """后台周期把观测状态快照落盘（SQLite），关闭时再落一次。

    只在 ``observation_store`` 非空时工作；演示模式（会灌入演示数据）默认不启用，
    避免把演示数据持久化进真实数据库。
    """

    def __init__(self, store: "SqliteObservationStore", service: HomewardService,
                 interval: float = 60.0) -> None:
        self.store = store
        self.service = service
        self.interval = interval
        self._stop = threading.Event()
        self._thread: "threading.Thread | None" = None

    def start(self) -> None:
        if self.store is None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.store.save(self.service.snapshot_observations())
            except Exception:
                logger.exception("周期持久化观测快照失败")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self.store is not None:
            try:
                self.store.save(self.service.snapshot_observations())
            except Exception:
                logger.exception("关闭前持久化观测快照失败")


def main(argv=None) -> int:
    # 环境变量兜底：容器里用 HOST / PORT / DNS_LOG_PATH 配（docker-compose 与
    # Dockerfile 都这么设），命令行参数优先。这样 CMD 可以保持 exec 形式，
    # 不必为了展开变量退化成 shell 形式（shell 形式会让信号传不到进程、优雅退出失效）。
    env_host = os.environ.get("HOST") or DEFAULT_HOST
    try:
        env_port = int(os.environ.get("PORT") or DEFAULT_PORT)
    except ValueError:
        env_port = DEFAULT_PORT
    env_dns_log = os.environ.get("DNS_LOG_PATH") or None
    env_dns_source = os.environ.get("DNS_SOURCE") or "dnsmasq"
    env_syslog_path = os.environ.get("SYSLOG_PATH") or None

    ap = argparse.ArgumentParser(description="家卫 Web UI（社区版：只读）")
    ap.add_argument("--host", default=env_host,
                    help=f"监听地址（默认 {DEFAULT_HOST}；容器内需要 0.0.0.0）")
    ap.add_argument("--port", type=int, default=env_port,
                    help=f"监听端口（默认 {DEFAULT_PORT}）")
    ap.add_argument("--demo", action="store_true",
                    help="灌入演示数据（用于界面自测，生产路径请勿使用）")
    ap.add_argument("--dns-log", default=env_dns_log,
                    help="dnsmasq 查询日志路径（默认按 /var/log/dnsmasq.log 等探测，"
                         "或由环境变量 DNS_LOG_PATH 指定）")
    ap.add_argument("--dns-source", default=env_dns_source,
                    choices=("dnsmasq", "syslog"),
                    help="Tier1 DNS 数据源：dnsmasq=读 dnsmasq 专属日志（默认，无代理/家卫即"
                         "解析器）；syslog=读系统 syslog 里的 dnsmasq 查询行（代理接管 DNS 但家卫"
                         "仍在解析路径上、或 OpenWrt/iStoreOS 把查询发到系统 syslog 时使用）")
    ap.add_argument("--syslog-path", default=env_syslog_path,
                    help="dns_source=syslog 时指定 syslog 文件路径（默认按 /var/log/messages 等探测，"
                         "或由环境变量 SYSLOG_PATH 指定）")
    ap.add_argument("--auth-token", default=None,
                    help="Web UI 登录口令；不填则默认无鉴权（浏览器直开）。"
                         "也可由环境变量 HOMEWARD_AUTH_TOKEN 提供")
    ap.add_argument("--no-auth", action="store_true",
                    help="强制关闭鉴权（默认即无鉴权；此开关用于有口令时仍要关）")
    ap.add_argument("--no-persist", action="store_true",
                    help="关闭观测状态持久化（默认生产模式开启：重启后保留设备/告警；"
                         "演示模式 --demo 默认关闭）")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # 许可公钥门禁：仍在使用开发公钥时告警（设 HOMEWARD_REQUIRE_PROD_KEY=1 则拒绝启动）。
    # 放在鉴权判断之前——这是「付费墙有没有用」的问题，与界面鉴权无关。
    try:
        assert_production_key()
    except RuntimeError as exc:
        logger.error("%s", exc)
        print("[错误] " + str(exc))
        return 2

    # 鉴权：默认「零配置即无鉴权」，浏览器直开（开箱即用）。
    # 仅当显式提供了口令（--auth-token 或 HOMEWARD_AUTH_TOKEN）才启用单用户鉴权；
    # 暴露到不可信网络时务必设口令，并用防火墙限制来源 IP。--no-auth 可强制关闭。
    auth = None
    if not args.no_auth:
        tok = args.auth_token or os.environ.get("HOMEWARD_AUTH_TOKEN")
        if tok:
            auth = WebAuth(token=tok)

    # 演示模式：不加载系统设备，也不落盘（actions.db 同样不写，避免污染生产数据）
    service = HomewardService(config={
        "load_system_devices": not args.demo,
        "actions_db_path": None if args.demo else (ROOT / "data" / "actions.db"),
    })

    # 观测状态持久化：生产模式默认开启（重启不丢设备/告警），演示模式默认关闭
    # （避免把演示数据落进真实数据库）。--no-persist 可强制关闭。
    observation_store = None
    if (not args.demo) and (not args.no_persist):
        observation_store = SqliteObservationStore(ROOT / "data" / "observations.db")
        snapshot = observation_store.load()
        if snapshot:
            n = service.restore_observations(snapshot)
            logger.info("已从 SQLite 恢复观测快照（%d 条）", n)
        else:
            logger.info("暂无历史观测快照，本次从零开始累计")

    runner = None
    if args.demo:
        out = seed_demo(service)
        print(f"[演示数据] 设备 {len(out['devices']['devices'])} 台、"
              f"观测 {out['flows']} 条、告警 {len(out['alerts'])} 条")
    else:
        # 生产模式：启动采集泵，把真实 DNS / conntrack 数据持续喂给 service
        from core.collector import CollectorRunner
        runner = CollectorRunner(
            service,
            dns_log_path=args.dns_log,
            dns_source=args.dns_source,
            syslog_path=args.syslog_path,
            poll_interval=0.5,
        )
        status = runner.start()
        active = [s["collector"] for s in status if s["active"]]
        note = "、".join(active) if active else "无（请确认 DNS 数据源配置，详见界面「盲区」视图）"
        print(f"[采集] 已启动（dns_source={args.dns_source}）：{note}")

    try:
        run_server(service, host=args.host, port=args.port, auth=auth,
                   observation_store=observation_store)
    finally:
        if runner is not None:
            runner.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
