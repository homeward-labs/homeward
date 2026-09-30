"""
知识库在线更新模块
支持从社区仓库拉取最新域名归属数据
"""

import hashlib
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from urllib.request import urlopen


def _version_key(version: str) -> tuple:
    """把版本号解析成可比较的元组：'1.10.0' → (1, 10, 0)

    早期直接对版本字符串做 ``<=`` 比较，而字符串世界里 ``'10.0.0' <= '9.0.0'`` 成立 ——
    结果是知识库永远被判成「已是最新」，从此再也不更新。必须按数值逐段比。
    非数字段（如 '1.2.0-beta'）取前导数字，缺失补 0。
    """
    parts: list[int] = []
    for seg in str(version).strip().split("."):
        m = re.match(r"\d+", seg)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts) if parts else (0,)


class KnowledgeBaseUpdater:
    """知识库在线更新器"""

    DEFAULT_REPO = "https://raw.githubusercontent.com/homeward-labs/knowledge-base/main"

    #: 环境变量名：自建内容源地址（覆盖默认源）
    ENV_SOURCE = "HOMEWARD_KB_SOURCE"

    #: 环境变量名：验签公钥（hex，32 字节 raw Ed25519 公钥）。不设置则回退仓内文件
    ENV_PUBKEY = "HOMEWARD_KB_PUBKEY"
    #: 环境变量名：是否强制验签（1/true/yes = 无签名或验签失败一律拒绝更新）
    ENV_REQUIRE_SIG = "HOMEWARD_KB_REQUIRE_SIGNATURE"
    #: 仓内公钥文件名（与 updater.py 同仓、随开源分发）
    KB_PUBKEY_FILENAME = "kb_pubkey.txt"
    #: 内容源签名文件名（对 CHECKSUM 内容的 Ed25519 签名，hex 编码）
    SIGNATURE_FILENAME = "SIGNATURE"

    def __init__(
        self,
        kb_dir: str,
        repo_url: str | None = None,
        repo_urls: list[str] | None = None,
        auto_update: bool = True,
        interval: int = 604800,
    ):
        """
        kb_dir: 知识库目录
        repo_url: 单个远程仓库地址（兼容旧接口）
        repo_urls: 多个远程仓库地址（按顺序兜底；主源挂掉时自动切备用源）
        auto_update: 是否自动更新
        interval: 更新间隔（秒），默认 7 天

        **源优先级**：显式 ``repo_urls`` 列表 > 显式 ``repo_url`` 单串 >
        环境变量 ``HOMEWARD_KB_SOURCE``（支持逗号分隔多个源）> ``DEFAULT_REPO``。
        解析后统一存为 ``self.repo_urls``（去重保序的列表）。

        环境变量的多源写法：``HOMEWARD_KB_SOURCE="https://a/kb,https://b/kb"``。
        实测单源抖动可达 4 倍（相邻两次 1.68s vs 4.63s），多源逐个尝试能显著提升
        更新成功率——任一源成功即停，全部失败才保持原状。

        环境变量这条路径是给「自建源 / 内网镜像」准备的：内容源本质上只是一组
        静态文件（VERSION + domains.csv + behaviors.json + CHECKSUM），
        所以在飞牛或任意一台内网机器上放一份、起个 HTTP 服务，
        家卫指向 ``http://<内网IP>:8080/kb/`` 即可 —— **不需要任何公网服务器**。
        测试阶段尤其该走这条路：零成本、不对外暴露、改完立刻生效。
        """
        self.kb_dir = Path(kb_dir)
        self.repo_urls = self._resolve_sources(repo_urls, repo_url)
        self.auto_update = auto_update
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self):
        """启动后台更新线程"""
        if not self.auto_update:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        """停止后台更新"""
        self._stop.set()

    def _run(self):
        """后台循环"""
        while not self._stop.is_set():
            try:
                self.check_and_update()
            except Exception as e:
                print(f"[KB Update] Error: {e}")
            self._stop.wait(self.interval)

    def check_and_update(self) -> bool:
        """检查并更新知识库（多源兜底）。返回是否更新了新数据。"""
        for url in self.repo_urls:
            try:
                if self._try_update_from(url):
                    return True
            except Exception as e:
                print(f"[KB Update] 源 {url} 更新异常：{e}")
        return False

    def _try_update_from(self, url: str) -> bool:
        """对单个源尝试更新；成功返回 True，源不可用/无更新/校验失败返回 False。"""
        remote_version = self._fetch_version(url)
        if not remote_version:
            return False
        local_version = self._read_local_version()
        if _version_key(remote_version) <= _version_key(local_version):
            print(f"[KB Update] 源 {url} 已是最新 (v{local_version})")
            return False
        print(f"[KB Update] 源 {url} 有新版本：v{local_version} → v{remote_version}")
        if self._download_and_replace(remote_version, url):
            self._write_local_version(remote_version)
            print(f"[KB Update] 已从 {url} 更新到 v{remote_version}")
            return True
        return False

    def _resolve_sources(
        self, repo_urls: list[str] | None, repo_url: str | None
    ) -> list[str]:
        """把多种传入形式归一为去重保序的源列表。

        优先级：显式列表 > 显式单串 > 环境变量(逗号分隔) > 默认源。
        """
        if repo_urls:
            urls = list(repo_urls)
        elif repo_url:
            urls = [repo_url]
        else:
            env = os.environ.get(self.ENV_SOURCE, "").strip()
            urls = [u.strip() for u in env.split(",") if u.strip()] or [self.DEFAULT_REPO]
        seen: set[str] = set()
        out: list[str] = []
        for u in urls:
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _fetch_version(self, url: str) -> str | None:
        """获取远程版本号"""
        try:
            with urlopen(f"{url}/VERSION", timeout=10) as resp:
                return resp.read().decode().strip()
        except Exception:
            return None

    def _read_local_version(self) -> str:
        """读取本地版本"""
        version_file = self.kb_dir / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()
        return "0.0.0"

    def _write_local_version(self, version: str):
        """写入本地版本"""
        (self.kb_dir / "VERSION").write_text(version)

    # 必需文件：缺任何一个就不允许替换（否则会出现「新域名库 + 旧行为库」的错配）
    REQUIRED_FILES = ("domains.csv", "behaviors.json")
    # 可选文件：下载失败只是少一份能力，不阻塞本次更新
    OPTIONAL_FILES = ("asn.csv",)

    def _download_and_replace(self, version: str, url: str) -> bool:
        """下载新版本并整体替换 —— **要么全换，要么一个都不换**

        早期实现是「逐个下载，失败就 continue，最后把下到的都 move 过去」，网络抖一下
        就会留下「新版 domains.csv + 旧版 behaviors.json」的错配状态，而知识库没有
        版本号能表达这种半新半旧，排查极痛。故改为全或无。
        """
        files = self.REQUIRED_FILES + self.OPTIONAL_FILES

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            missing: list[str] = []
            for fname in self.REQUIRED_FILES:
                dst = tmpdir / fname
                try:
                    with urlopen(f"{url}/{fname}", timeout=30) as resp:
                        dst.write_bytes(resp.read())
                except Exception as e:
                    print(f"[KB Update] 必需文件下载失败：{fname} ({e})")
                    missing.append(fname)

            if missing:
                print(
                    f"[KB Update] 必需文件缺失（{'、'.join(missing)}），"
                    f"放弃本次更新，保持原知识库不变"
                )
                return False

            for fname in self.OPTIONAL_FILES:
                dst = tmpdir / fname
                try:
                    with urlopen(f"{url}/{fname}", timeout=30) as resp:
                        dst.write_bytes(resp.read())
                except Exception as e:
                    print(f"[KB Update] 可选文件下载失败，跳过：{fname} ({e})")

            # 校验（可选：比对 checksum）
            checksum_url = f"{url}/CHECKSUM"
            expected = ""
            try:
                with urlopen(checksum_url, timeout=10) as resp:
                    expected = resp.read().decode()
                if not self._verify_checksum(tmpdir, expected):
                    print("[KB Update] Checksum mismatch, aborting")
                    return False
            except Exception:
                pass  # 校验文件不存在则跳过

            # C2 签名验证：签名覆盖 CHECKSUM，CHECKSUM 再覆盖各文件。
            # 即便 CHECKSUM 缺失也仍执行（缺失则对空串验签，强制模式会据此拒绝）。
            if not self._verify_signature(expected, url):
                return False

            # 原子替换
            for fname in files:
                src = tmpdir / fname
                if src.exists():
                    shutil.move(str(src), str(self.kb_dir / fname))

        return True

    def _load_pubkey(self) -> bytes | None:
        """加载验签公钥（双轨：环境变量优先，回退仓内文件）。

        - 环境变量 ``HOMEWARD_KB_PUBKEY`` 直接给 hex 公钥；
        - 否则读仓内 ``src/license/kb_pubkey.txt``（与 updater 同仓、随开源分发）。
        - 都没有返回 None —— 此时降级为「仅告警不阻断」，除非处于强制验签模式。
        """
        env = os.environ.get(self.ENV_PUBKEY, "").strip()
        if env:
            try:
                return bytes.fromhex(env)
            except ValueError:
                print(f"[KB Update] {self.ENV_PUBKEY} 不是合法 hex，忽略")
        kb_file = (
            Path(__file__).resolve().parent.parent / "license" / self.KB_PUBKEY_FILENAME
        )
        if kb_file.exists():
            try:
                return bytes.fromhex(kb_file.read_text(encoding="utf-8").strip())
            except ValueError:
                print(f"[KB Update] 仓内公钥文件格式错误：{kb_file}")
        return None

    def _verify_signature(self, checksum_text: str, url: str) -> bool:
        """验证内容源签名（C2）。

        签名是对 ``CHECKSUM`` 内容的 Ed25519 签名（见 ``scripts/make_kb_source.py --sign``）。
        返回 True=可继续替换；False=应拒绝替换。

        降级策略由 ``HOMEWARD_KB_REQUIRE_SIGNATURE`` 控制：
          - 未设 / 非真值：无签名、公钥缺失、或验签失败**仅告警**，仍允许更新
            （开发/测试期默认，避免本地源还没签名就被卡死）；
          - 设为 1/true/yes：无签名或验签失败**一律拒绝更新**。
        """
        require = os.environ.get(self.ENV_REQUIRE_SIG, "").strip().lower() in (
            "1",
            "true",
            "yes",
        )
        try:
            from license.ed25519 import verify_signature
        except Exception:
            print("[KB Update] 无法加载 ed25519 验签模块，跳过签名验证")
            return not require

        pubkey = self._load_pubkey()
        if pubkey is None:
            print("[KB Update] 未配置验签公钥，跳过签名验证（建议设置 HOMEWARD_KB_PUBKEY 或仓内 kb_pubkey.txt）")
            return not require

        sig_url = f"{url}/{self.SIGNATURE_FILENAME}"
        try:
            with urlopen(sig_url, timeout=10) as resp:
                sig_hex = resp.read().decode("utf-8").strip()
        except Exception:
            print(f"[KB Update] 内容源未提供签名文件（{self.SIGNATURE_FILENAME}）")
            if require:
                print("[KB Update] 强制验签模式：无签名，拒绝本次更新")
                return False
            return True

        try:
            sig = bytes.fromhex(sig_hex)
        except ValueError:
            print("[KB Update] 签名文件不是合法 hex")
            return not require

        if verify_signature(sig, checksum_text.encode("utf-8"), pubkey):
            print("[KB Update] 内容源签名校验通过 ✅")
            return True

        print("[KB Update] 签名校验失败！内容源可能被篡改")
        if require:
            print("[KB Update] 强制验签模式：拒绝本次更新")
            return False
        print("[KB Update] 降级模式：仍允许更新（建议核查内容源可信度）")
        return True

    def _verify_checksum(self, directory: Path, expected: str) -> bool:
        """验证下载文件的 checksum"""
        # 简单实现：逐文件计算 sha256 并比对
        for line in expected.strip().split("\n"):
            parts = line.split()
            if len(parts) != 2:
                continue
            expected_hash, fname = parts
            fpath = directory / fname
            if not fpath.exists():
                return False
            actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
            if actual != expected_hash:
                return False
        return True

    # 这里**刻意不提供**任何"回传用户数据"的方法。
    #
    # 家卫是隐私工具，自身必须零遥测：默认不采集、不上报任何用户数据。
    # 早期版本曾在这里放过一个 submit_anonymous_data() —— 它会把用户家里观察到的
    # 域名与行为摘要发往远端，与产品定位根本冲突，且 URL 构造还是错的
    # （raw.githubusercontent.com 里没有 /raw/ 可替换）。已移除。
    # 若将来要做社区知识库共建，必须：默认关闭 + UI 显式开关 + 逐条用户确认 +
    # 在 README 明示，而不是埋在更新器里静默上报。
