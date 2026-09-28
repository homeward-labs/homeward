"""
store.py —— 社区版许可本地存储（零依赖，纯本地文件）

职责：
  - 持久化已导入的许可令牌（data/license.token）。
  - 缓存服务端签发的吊销名单 CRL（data/crl.json，联网机会性拉取）。
  - 对外暴露 status()（封装 verify.status_summary）。

安全：
  - 只读写本地文件，不发起任何网络请求、不写任何家庭网络数据。
  - 令牌文件权限受限（仅当前用户可读），内容即签名令牌本身，不含密钥。
"""
import hashlib
import json
import os
import platform
import time
import uuid
from pathlib import Path

from license.verify import status_summary, verify_token, PUBLIC_KEY


def _stable_id() -> "str | None":
    """持久化的本机稳定标识，用于对抗「机器标识漂移」。

    为什么需要：Docker 镜像更新 / 容器重建后 ``/etc/machine-id`` 可能重新生成，
    指纹随之漂移 → 已激活的许可突然变成「设备不符」，用户被迫重新激活。
    这里在数据目录（可用 ``HOMEWARD_DATA_DIR`` 指定，生产部署应挂到持久卷）
    落一个随机标识并复用，使指纹跨重建保持稳定。

    只在**确实能写入**数据目录时启用：写不了（只读根文件系统 / tmpfs）就返回 None，
    退回原有逻辑 —— 否则每次启动都换新 ID，反而让指纹更不稳定。
    """
    try:
        p = _data_dir() / "device.id"
        if p.is_file():
            v = p.read_text(encoding="utf-8").strip()
            if v:
                return v
        v = uuid.uuid4().hex
        p.write_text(v, encoding="utf-8")
        return v
    except Exception:
        return None


def device_fingerprint() -> str:
    """本机稳定指纹（sha256，仅本地使用，绝不离开本机）。

    用于许可的设备绑定校验（verify.verify_token 的 expected_device_fp）。
    生产级实现取「磁盘序列号 + 主板 + 系统 UUID」组合；此处用各平台稳定的机器标识
    做等价绑定（Linux /etc/machine-id、Windows MachineGuid），均不含敏感原始硬件信息。
    原始标识只参与本地哈希，从不外发；哈希本身也只在本地做一致性比较。
    """
    parts = []
    # Linux：系统 machine-id（稳定、非硬件序列号）
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            parts.append(Path(p).read_text(encoding="utf-8").strip())
        except Exception:
            pass
    # Windows：注册表 MachineGuid
    if not parts:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"SOFTWARE\Microsoft\Cryptography") as k:
                parts.append(str(winreg.QueryValueEx(k, "MachineGuid")[0]))
        except Exception:
            pass
    # 兜底：MAC + 平台串（隐私友好度较低，仅在前两者都拿不到时用）
    if not parts:
        try:
            parts.append(hex(uuid.getnode()))
            parts.append(platform.platform())
        except Exception:
            parts.append("fallback-unknown")
    # 持久化稳定标识（能写数据目录时才有）：对抗容器重建 / machine-id 漂移
    sid = _stable_id()
    if sid:
        parts.append(sid)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _data_dir() -> Path:
    env = os.environ.get("HOMEWARD_DATA_DIR")
    base = Path(env) if env else (Path.home() / ".homeward")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _token_path() -> Path:
    return _data_dir() / "license.token"


def _crl_path() -> Path:
    return _data_dir() / "crl.json"


def load_token() -> str | None:
    p = _token_path()
    if not p.is_file():
        return None
    try:
        return p.read_text(encoding="utf-8").strip()
    except Exception:
        return None


def save_token(token: str) -> bool:
    """保存令牌到本地。成功返回 True。会先用内嵌公钥做一次有效性预检，但不阻塞保存
    （离线/过期也允许保存，status() 会如实反映）。"""
    try:
        p = _token_path()
        # 限制文件权限（类 Unix）；Windows 下 mkdir 已限制父目录，这里尽力而为
        p.write_text(token.strip(), encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return True
    except Exception:
        return False


def clear_token() -> bool:
    p = _token_path()
    if p.is_file():
        try:
            p.unlink()
            return True
        except Exception:
            return False
    return True


def status(expected_device_fp: str = None) -> dict:
    """返回当前许可状态摘要（active / none / expired / invalid / revoked）。"""
    token = load_token()
    if not token:
        return {"valid": False, "reason": "none", "edition": None,
                "days_remaining": 0, "device_bound": expected_device_fp is not None}
    revoked = set(load_crl().get("revoked_order_ids", []))
    summary = status_summary(token, expected_device_fp=expected_device_fp)
    if summary["valid"] and token and revoked:
        # status_summary 已含 CRL 判断；这里对离线缓存再确认一次
        payload = verify_token(token, expected_device_fp=expected_device_fp,
                               revoked_order_ids=revoked)
        if payload is None:
            summary = {**summary, "valid": False, "reason": "revoked"}
    return summary


# ── CRL 缓存（联网机会性拉取后写入；本文件不负责下载，由调用方写入）──

def load_crl() -> dict:
    p = _crl_path()
    if not p.is_file():
        return {"revoked_order_ids": [], "fetched_at": 0}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"revoked_order_ids": [], "fetched_at": 0}


def save_crl(crl: dict) -> bool:
    """crl: {"revoked_order_ids": [...], "fetched_at": <ts>, "valid_until": <ts>}"""
    try:
        _crl_path().write_text(json.dumps(crl, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception:
        return False


def crl_stale(tolerance_seconds: int = 7 * 86400) -> bool:
    """离线容忍窗口：超过则下次需联网刷新（设计文档 §4.5 已确认 = 7 天）。"""
    crl = load_crl()
    fetched = crl.get("fetched_at", 0)
    if not fetched:
        return True
    return (time.time() - fetched) > tolerance_seconds
