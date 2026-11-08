"""
知识库在线更新模块
支持从配置的内容源拉取最新域名归属数据（源地址由闭源构建注入）
"""

import hashlib
import os
import re
import shutil
import tempfile
import threading
import uuid
from pathlib import Path
from urllib.request import Request, urlopen

#: 客户端 UA。Cloudflare 边缘默认拦截 ``Python-urllib`` UA（403），
#: 必须用可识别的产品 UA 访问自建内容源（Cloudflare Worker 等）。
#: 知识库内容源配置：地址 / 文件名 / 路径等所有「可能变动」的项，全部集中在
#: ``constants.py``，此处只负责取到它们。
#:
#: 导入策略（与项目对 ``license`` 模块的处理**保持一致**）：
#: 优先走包导入；但当 ``src`` 不在 sys.path 顶层时（生产以 ``python -m src.ui.server``
#: 启动即如此），绝对导入 ``knowledge_base`` 会解析不到 —— 这正是历史上
#: 「``license`` 撞标准库同名模块 → 验签被静默跳过」的同一处坑。
#: 故退化为按文件路径加载同目录的 ``constants.py``，保证任何加载方式下配置都取得到。
try:
    from knowledge_base.constants import (
        KB_SOURCE_DEFAULT_URL,
        KB_SOURCE_BACKUP_URLS,
        VERSION_FILE,
        CHECKSUM_FILE,
        SIGNATURE_FILE,
        KB_LICENSE_DIRNAME,
        KB_PUBKEY_FILENAME,
        ED25519_MODULE_BASENAME,
        USER_AGENT_HOMEPAGE,
        REQUIRED_DATA_FILES,
        OPTIONAL_DATA_FILES,
    )
except Exception:
    import importlib.util as _ilu

    _c_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "constants.py")
    _c_spec = _ilu.spec_from_file_location("homeward_kb_constants", _c_path)
    _c_mod = _ilu.module_from_spec(_c_spec)
    _c_spec.loader.exec_module(_c_mod)
    KB_SOURCE_DEFAULT_URL = _c_mod.KB_SOURCE_DEFAULT_URL
    KB_SOURCE_BACKUP_URLS = _c_mod.KB_SOURCE_BACKUP_URLS
    VERSION_FILE = _c_mod.VERSION_FILE
    CHECKSUM_FILE = _c_mod.CHECKSUM_FILE
    SIGNATURE_FILE = _c_mod.SIGNATURE_FILE
    KB_LICENSE_DIRNAME = _c_mod.KB_LICENSE_DIRNAME
    KB_PUBKEY_FILENAME = _c_mod.KB_PUBKEY_FILENAME
    ED25519_MODULE_BASENAME = _c_mod.ED25519_MODULE_BASENAME
    USER_AGENT_HOMEPAGE = _c_mod.USER_AGENT_HOMEPAGE
    REQUIRED_DATA_FILES = _c_mod.REQUIRED_DATA_FILES
    OPTIONAL_DATA_FILES = _c_mod.OPTIONAL_DATA_FILES

USER_AGENT = f"Homeward-KB/1.0 (+{USER_AGENT_HOMEPAGE})"

#: 知识库替换互斥：避免两个更新线程同时换入同一份 KB 造成半新半旧。
_KB_REPLACE_LOCK = threading.Lock()

#: Stage 6 崩溃恢复标记：进入「逐个 os.replace」的半写窗口前写下，正常/异常/回滚
#: 三条路径都在 finally 删除。进程被强杀或断电时 except 不会执行，标记会残留，
#: 下次启动由 recover_if_interrupted() 检出。内容只含随机 id，绝不含密钥或凭据。
UPDATE_MARKER_FILENAME = ".update_in_progress"

#: 只匹配 _replace_all_atomic() 自己生成的暂存文件：
#: `.{fname}.hwswap-{8 位小写 hex}`。宽匹配（如 *hwswap-*）会误删
#: kb_dir 内同名的手工备份或说明文件。
_SWAP_RESIDUE_RE = re.compile(r"\..+\.hwswap-[0-9a-f]{8}\Z")


def _http_get(url: str, timeout: int) -> bytes:
    """带产品 UA 的 GET。Cloudflare（及部分 CDN）会 403 掉默认 ``Python-urllib`` UA。"""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


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

    DEFAULT_REPO = KB_SOURCE_DEFAULT_URL

    #: 环境变量名：自建内容源地址（覆盖默认源）
    ENV_SOURCE = "HOMEWARD_KB_SOURCE"

    #: 环境变量名：验签公钥（hex，32 字节 raw Ed25519 公钥）。不设置则回退仓内文件
    ENV_PUBKEY = "HOMEWARD_KB_PUBKEY"
    #: 环境变量名：是否强制验签（1/true/yes = 无签名或验签失败一律拒绝更新）
    ENV_REQUIRE_SIG = "HOMEWARD_KB_REQUIRE_SIGNATURE"
    #: 环境变量名：解密主密钥 KEK（hex，32 字节）。仅闭源私有构建经此注入；
    #: 开源/社区构建不配置 → 客户端只尝试明文源（且默认源为空，不连公网）。
    ENV_DECRYPT_KEY = "HOMEWARD_KB_DECRYPT_KEY"
    #: 仓内公钥文件名（与 updater.py 同仓、随开源分发）
    KB_PUBKEY_FILENAME = "kb_pubkey.txt"
    #: 内容源签名文件名（对 CHECKSUM 内容的 Ed25519 签名，hex 编码）
    SIGNATURE_FILENAME = SIGNATURE_FILE

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

    def _default_sources(self) -> list[str]:
        """默认源清单 = 主源（Cloudflare Worker）+ 内置国内备源（constants.KB_SOURCE_BACKUP_URLS）。

        主源 workers.dev 在国内部分地区被干扰，客户端几乎全在国内 —— 故默认清单在
        主源之后带上国内可达备源，主源取不到时按序自动降级（机制见 check_and_update）。
        备源清单默认空 tuple：不擅自改变开箱联网目标，由维护者 Provision 好国内镜像
        （Gitee raw / OSS / COS / 自建内网镜像，选型见服务端架构文档 §四）后填入。
        隐私：备源同属家卫第一方，只分发公开知识库静态文件、零遥测；且 kb_auto_update
        默认关闭，用户显式开启前客户端不向任何源发起连接。
        """
        out = [self.DEFAULT_REPO]
        for u in KB_SOURCE_BACKUP_URLS:
            u = (u or "").strip()
            if u and u not in out:
                out.append(u)
        return out

    def _resolve_sources(
        self, repo_urls: list[str] | None, repo_url: str | None
    ) -> list[str]:
        """把多种传入形式归一为去重保序的源列表。

        优先级：显式列表 > 显式单串 > 环境变量(逗号分隔) > 默认源。
        默认源 = 主源 + 内置国内备源（见 _default_sources）；环境变量 / 显式传入视为
        用户自定义清单，整体替换默认（不再附加内置备源）。
        """
        if repo_urls:
            urls = list(repo_urls)
        elif repo_url:
            urls = [repo_url]
        else:
            env = os.environ.get(self.ENV_SOURCE, "").strip()
            urls = [u.strip() for u in env.split(",") if u.strip()] or self._default_sources()
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
            return _http_get(f"{url}/{VERSION_FILE}", 10).decode().strip()
        except Exception as e:
            print(f"[KB Update] 获取 VERSION 失败（{url}）：{e}")
            return None

    def _read_local_version(self) -> str:
        """读取本地版本"""
        version_file = self.kb_dir / VERSION_FILE
        if version_file.exists():
            return version_file.read_text().strip()
        return "0.0.0"

    def _write_local_version(self, version: str):
        """写入本地版本"""
        (self.kb_dir / VERSION_FILE).write_text(version)

    # 必需文件：缺任何一个就不允许替换（否则会出现「新域名库 + 旧行为库」的错配）
    # 可选文件：下载失败只是少一份能力，不阻塞本次更新
    # 清单来自 constants.py（单一真相源），此处不再硬编码文件名。
    REQUIRED_FILES = REQUIRED_DATA_FILES
    OPTIONAL_FILES = OPTIONAL_DATA_FILES

    def _download_and_replace(self, version: str, url: str) -> bool:
        """下载新版本并整体替换 —— **要么全换，要么一个都不换**

        早期实现是「逐个下载，失败就 continue，最后把下到的都 move 过去」，网络抖一下
        就会留下「新版 domains.csv + 旧版 behaviors.json」的错配状态，而知识库没有
        版本号能表达这种半新半旧，排查极痛。故改为全或无。
        """
        files = self.REQUIRED_FILES + self.OPTIONAL_FILES
        kek = self._load_kek()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            missing: list[str] = []
            for fname in self.REQUIRED_FILES:
                if not self._download_data_file(tmpdir, fname, url, kek):
                    missing.append(fname)

            if missing:
                print(
                    f"[KB Update] 必需文件缺失（{'、'.join(missing)}），"
                    f"放弃本次更新，保持原知识库不变"
                )
                return False

            for fname in self.OPTIONAL_FILES:
                # 可选项失败静默跳过，不影响本次更新成功
                self._download_data_file(tmpdir, fname, url, kek)

            # 校验（可选：比对 checksum）
            checksum_url = f"{url}/{CHECKSUM_FILE}"
            expected = ""
            try:
                expected = _http_get(checksum_url, 10).decode()
                if not self._verify_checksum(tmpdir, expected):
                    print("[KB Update] Checksum mismatch, aborting")
                    return False
            except Exception:
                pass  # 校验文件不存在则跳过

            # C2 签名验证：签名覆盖 CHECKSUM，CHECKSUM 再覆盖各文件。
            # 即便 CHECKSUM 缺失也仍执行（缺失则对空串验签，强制模式会据此拒绝）。
            if not self._verify_signature(expected, url):
                return False

            # 全或无替换：任一文件失败即整体回滚，保持原知识库不变
            if not self._replace_all_atomic(tmpdir, files):
                return False

        return True

    def _replace_all_atomic(self, tmpdir: Path, files) -> bool:
        """把 staging 文件整体换入 kb_dir：要么全换，要么一个都不换。

        ``tmpdir`` 常位于系统临时分区，与 ``kb_dir`` 未必同盘；直接
        ``os.replace`` 跨分区会抛 EXDEV，故先复制到 kb_dir 内的同分区
        临时文件，再逐个原子换入。任一环节失败则按备份逐文件回滚。
        """
        staged: list[tuple[Path, Path, str]] = []
        backups: dict[str, bytes | None] = {}
        try:
            with _KB_REPLACE_LOCK:
                for fname in files:
                    src = tmpdir / fname
                    if not src.is_file():
                        continue
                    dst = self.kb_dir / fname
                    swap = self.kb_dir / f".{fname}.hwswap-{uuid.uuid4().hex[:8]}"
                    shutil.copyfile(str(src), str(swap))
                    staged.append((dst, swap, fname))
                # Stage 6：进入半写窗口前留标记；写不上就拒绝替换（fail-closed），
                # 避免留下「无标记可检测」的半新半旧状态。
                marker = self.kb_dir / UPDATE_MARKER_FILENAME
                try:
                    marker.write_text(
                        "interrupted_replace %s\n" % uuid.uuid4().hex[:16],
                        encoding="utf-8")
                except OSError as me:
                    print(f"[KB Update] 无法写入更新标记，跳过本次替换：{me}")
                    return False

                # 全部备妥后才开始换入，缩短半新半旧窗口
                for dst, swap, fname in staged:
                    backups[fname] = dst.read_bytes() if dst.exists() else None
                    os.replace(str(swap), str(dst))
        except Exception as exc:
            # 只回滚已换入的文件；blob=None 表示原本不存在，回滚即删除
            for fname, blob in backups.items():
                dst = self.kb_dir / fname
                try:
                    if blob is None:
                        dst.unlink(missing_ok=True)
                    else:
                        dst.write_bytes(blob)
                except OSError as rb:
                    print(f"[KB Update] 回滚 {fname} 失败：{rb}")
            print(f"[KB Update] 替换中断，已回滚，保持原知识库不变：{exc}")
            return False
        finally:
            # 成功、异常回滚、标记写入失败三条路径都要清标记；进程被强杀时
            # 走不到这里，残留标记由 recover_if_interrupted() 在下次启动处理。
            try:
                (self.kb_dir / UPDATE_MARKER_FILENAME).unlink(missing_ok=True)
            except OSError:
                pass
            for _, swap, _ in staged:
                try:
                    swap.unlink(missing_ok=True)
                except OSError:
                    pass
        return True

    def recover_if_interrupted(self) -> bool:
        """启动时检出上次 KB 替换是否被强杀 / 断电打断。

        只做「检测 + 清理本流程生成的 .hwswap- 暂存残留 + 告警 + 删标记」四件事：
        **不联网、不重下、不自动回滚**。内存中的 backups 在进程消失时已丢失，
        半写态必须由人工核对 KB 的 VERSION / CHECKSUM 完整性后决定处置；
        默认不联网的知识库策略不因恢复流程而改变。幂等，可重复调用。

        返回是否确实检出过中断标记。
        """
        try:
            if not self.kb_dir.is_dir():
                return False
            marker = self.kb_dir / UPDATE_MARKER_FILENAME
            if not marker.exists():
                return False
            cleaned = 0
            # iterdir() 是惰性迭代，OSError 可能在迭代途中抛出；连同
            # is_dir() 与 exists() 一起包住，保证启动期的恢复检测不拖垮服务。
            for residue in self.kb_dir.iterdir():
                if not _SWAP_RESIDUE_RE.fullmatch(residue.name):
                    continue
                try:
                    residue.unlink()
                    cleaned += 1
                except OSError:
                    pass
            print("[KB Update] 检出上次更新被中断（%s）；已清理 %d 个残留临时文件。"
                  "未联网重下、未自动回滚，请人工核对 KB 的 VERSION / CHECKSUM 完整性。"
                  % (UPDATE_MARKER_FILENAME, cleaned))
            try:
                marker.unlink(missing_ok=True)
            except OSError:
                pass
            return True
        except OSError as ie:
            # 检测失败时保留标记，下次启动再试；不联网、不重下、不改 KB。
            print(f"[KB Update] 恢复检测遇到 IO 错误，已跳过（标记保留）：{ie}")
            return False

    def _load_kek(self) -> bytes | None:
        """加载解密主密钥 KEK（仅闭源私有构建经 HOMEWARD_KB_DECRYPT_KEY 注入）。

        开源/社区构建不配置此变量 → 返回 None → 客户端只尝试明文源（且默认源为空，
        不会向公网发起连接）。仅当测试者被授权拿到 KEK 时才非空，此时客户端
        才能从加密端点消费 ``.enc`` 密文。
        """
        env = os.environ.get(self.ENV_DECRYPT_KEY, "").strip()
        if not env:
            return None
        try:
            raw = bytes.fromhex(env)
        except ValueError:
            print(f"[KB Update] {self.ENV_DECRYPT_KEY} 不是合法 hex，忽略")
            return None
        if len(raw) != 32:
            print(f"[KB Update] {self.ENV_DECRYPT_KEY} 必须为 32 字节，实际 {len(raw)}，忽略")
            return None
        return raw

    def _decrypt(self, enc: bytes, kek: bytes, name: str) -> bytes:
        """AES-256-GCM 解密单个 ``.enc`` 文件（与 ``kb-private/encrypt_build.py`` 对称）。

        encrypt_build 输出 = nonce(12) || ciphertext||GCM-tag；
        密钥 = HKDF-SHA256(KEK, info=name)。第三方库 lazy import，
        仅配置了 KEK 的闭源构建才会走到这里，开源用户不受影响。
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        if len(enc) <= 12:
            raise ValueError("密文过短，缺少 nonce")
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=name.encode()).derive(kek)
        nonce, ct = enc[:12], enc[12:]
        return AESGCM(key).decrypt(nonce, ct, None)

    def _download_data_file(self, tmpdir: Path, fname: str, url: str, kek: bytes | None) -> bool:
        """下载单个数据文件到 ``tmpdir/fname``。

        闭源加密源优先：若配置了 KEK，先尝试 ``<url>/<fname>.enc``，成功则用 KEK
        解密还原为明文 ``fname``；未配置 KEK 或加密源不可达时，回退明文
        ``<url>/<fname>``。返回 True=已就位；False=未取得（调用方决定缺失/跳过）。
        """
        dst = tmpdir / fname
        if kek is not None:
            try:
                enc = _http_get(f"{url}/{fname}.enc", 30)
                dst.write_bytes(self._decrypt(enc, kek, fname))
                return True
            except Exception as e:
                print(f"[KB Update] 加密源 {fname}.enc 获取/解密失败，回退明文：{e}")
        try:
            dst.write_bytes(_http_get(f"{url}/{fname}", 30))
            return True
        except Exception as e:
            print(f"[KB Update] 文件下载失败：{fname} ({e})")
            return False

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
            Path(__file__).resolve().parent.parent / KB_LICENSE_DIRNAME / self.KB_PUBKEY_FILENAME
        )
        if kb_file.exists():
            try:
                return bytes.fromhex(kb_file.read_text(encoding="utf-8").strip())
            except ValueError:
                print(f"[KB Update] 仓内公钥文件格式错误：{kb_file}")
        return None

    def _verify_signature(self, checksum_text: str, url: str) -> bool:
        """验证内容源签名（C2）。

        签名是对 ``CHECKSUM`` 内容的 Ed25519 签名（由闭源侧的 ``make_kb_source.py --sign`` 生成）。
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
            # ``license`` 撞上 Python 标准库同名模块：当 ``src/`` 不在 sys.path 顶层
            # （或路径顺序让标准库优先）时，上面的绝对导入会解析到标准库的 ``license``，
            # 从而找不到 ``ed25519`` 属性。退路：直接按文件路径加载本项目的
            # ``src/license/ed25519.py``，彻底绕开名字冲突（与 license/verify.py 一致）。
            try:
                import importlib.util as _ilu
                _here = os.path.dirname(os.path.abspath(__file__))
                _spec = _ilu.spec_from_file_location(
                    "homeward_license_ed25519",
                    os.path.join(_here, "..", KB_LICENSE_DIRNAME, ED25519_MODULE_BASENAME),
                )
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                verify_signature = _mod.verify_signature
            except Exception:
                print("[KB Update] 无法加载 ed25519 验签模块，跳过签名验证")
                return not require

        pubkey = self._load_pubkey()
        if pubkey is None:
            print("[KB Update] 未配置验签公钥，跳过签名验证（建议设置 HOMEWARD_KB_PUBKEY 或仓内 kb_pubkey.txt）")
            return not require

        sig_url = f"{url}/{self.SIGNATURE_FILENAME}"
        try:
            sig_hex = _http_get(sig_url, 10).decode("utf-8").strip()
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

    @staticmethod
    def _safe_fname(fname: str) -> bool:
        """远端 CHECKSUM 里的文件名必须先校验，才能拼进本地路径。

        拒绝：空名、``.`` / ``..``、点开头隐藏名、目录分隔符、驱动器前缀、
        NUL 与 Windows 保留设备名。只接受单层普通文件名。
        """
        if not fname or fname in (".", "..") or fname.startswith("."):
            return False
        if "/" in fname or "\\" in fname or "\x00" in fname:
            return False
        if os.path.splitdrive(fname)[0]:
            return False
        if Path(fname).name != fname:
            return False
        stem = os.path.splitext(fname)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or (
            len(stem) == 4 and stem[:3] in {"COM", "LPT"} and stem[3] in "123456789"
        ):
            return False
        return True

    def _verify_checksum(self, directory: Path, expected: str) -> bool:
        """验证下载文件的 checksum；文件名来自远端响应，一律先过校验。"""
        try:
            base = directory.resolve()
        except OSError:
            return False
        for line in expected.strip().split("\n"):
            parts = line.split()
            if len(parts) != 2:
                continue
            expected_hash, fname = parts
            if not self._safe_fname(fname):
                print(f"[KB Update] CHECKSUM 含非法文件名，拒绝更新：{fname!r}")
                return False
            fpath = directory / fname
            if not fpath.is_file():
                return False
            # 防符号链接 / 目录穿越：解析后必须仍在 staging 目录内
            try:
                fpath.resolve().relative_to(base)
            except ValueError:
                print(f"[KB Update] CHECKSUM 文件名越出 staging 目录，拒绝：{fname!r}")
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
