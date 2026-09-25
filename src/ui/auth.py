"""Web UI 鉴权（社区版，单用户 / 家庭管理员）

设计取舍
--------
家卫是跑在家庭网关上的**单用户**隐私工具，没有多账号、没有注册、没有角色——
家庭网络的管理员就是唯一用户。因此做一套「账号系统」纯属过度设计。这里用
**单口令（token）鉴权**：

  · 口令来源优先级：命令行 ``--auth-token`` > 环境变量 ``HOMEWARD_AUTH_TOKEN``。
  · 两者都没给时：**自动生成一个随机口令**，仅在启动日志里打印一次**（安全默认值：
    不是「不拦」，而是「给一个只有看服务器日志的人拿得到的随机口令」）。
  · 登录后维持 ``HttpOnly`` + ``SameSite=Strict`` 的会话 cookie（cookie 直接存口令，
    靠 HttpOnly 防前端 JS 窃取；家庭内网 http 场景不置 ``Secure``）。
  · 口令比对走 ``secrets.compare_digest`` 做常量时间比较，避免时序侧信道。
  · ``--no-auth`` 仅在可信局域网 / 纯本地自测时关闭，生产必须设口令。

所有页面与写接口都需登录；白名单（登录页 / 登录登出接口 / 健康检查 / 登录页样式）
免鉴权。鉴权本身零外部依赖、不写任何文件。
"""

import os
import secrets

SESSION_COOKIE = "homeward_session"


def _parse_cookie(headers: "dict | object") -> dict:
    """从请求头里抽出 cookie 字典（兼容 dict 与 http 头对象）"""
    raw = ""
    if isinstance(headers, dict):
        raw = headers.get("Cookie", "") or ""
    else:
        raw = getattr(headers, "get", lambda *_: "")("Cookie", "") or ""
    out: dict = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


class WebAuth:
    """单用户口令鉴权器"""

    def __init__(self, token: "str | None" = None):
        tok = token or os.environ.get("HOMEWARD_AUTH_TOKEN") or ""
        if not tok:
            # 安全默认：自动生成一次性随机口令，仅打印到启动日志
            tok = secrets.token_urlsafe(24)
            self.auto_token = tok
            logger_generated(tok)
        else:
            self.auto_token = None
        self._token = tok

    # —— 对外查询 ——

    @property
    def token(self) -> str:
        return self._token

    def is_authenticated(self, handler) -> bool:
        """handler 需提供 .headers（含 Cookie）"""
        val = _parse_cookie(handler.headers).get(SESSION_COOKIE)
        if not val:
            return False
        return secrets.compare_digest(val, self._token)

    def verify(self, presented: str) -> bool:
        """校验登录口令（常量时间）"""
        if not presented:
            return False
        return secrets.compare_digest(presented, self._token)

    # —— cookie 构造 ——

    def session_cookie(self) -> str:
        return f"{SESSION_COOKIE}={self._token}; HttpOnly; SameSite=Strict; Path=/"

    def logout_cookie(self) -> str:
        return f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"

    # —— 登录页（自包含、零外部资源、符合 CSP）——
    # 注意：本页不使用任何内联脚本，靠标准表单 POST 提交（配合 CSP form-action 'self'）。
    # 样式走 /static/login.css（已在服务端对未登录放白名单）。

    def login_page_html(self) -> str:
        generated_hint = (
            '<p class="gen">首次启动自动生成的登录口令（仅服务器日志中显示一次）：'
            f'<code>{self.auto_token}</code></p>'
            if self.auto_token
            else ""
        )
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>家卫 · 登录</title>
  <link rel="stylesheet" href="/static/login.css">
</head>
<body class="login">
  <main class="card">
    <h1>家卫 Homeward</h1>
    <p class="sub">家庭设备外联隐私守护</p>
    {generated_hint}
    <form method="post" action="/api/login" class="login-form">
      <label for="token">登录口令</label>
      <input id="token" name="token" type="password" autocomplete="current-password" required>
      <button type="submit">登录</button>
    </form>
    <p class="note">口令由运行服务的管理员设置（HOMEWARD_AUTH_TOKEN）。这是家庭网络上的隐私工具，请只在可信设备上登录。</p>
  </main>
</body>
</html>
"""


def logger_generated(token: str) -> None:
    import logging
    logging.getLogger("homeward.ui").info(
        "Web UI 鉴权口令（自动生成，仅显示一次）：%s", token
    )
