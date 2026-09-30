"""tests/test_kb_source.py —— 知识库内容源：可配置性 + 消费侧闭环。

为什么单独建这个文件：
    内容源是「客户端唯一向外取的东西」，但它长期**不可配置** ——
    ``main.py`` 实例化 updater 时不传 ``repo_url``，只能用硬编码的
    ``homeward-labs/knowledge-base``（该仓库当时尚未创建 → 恒 404）。
    后果是自建源 / 内网镜像 / 本地测试源**一个都用不了**，
    测试只能在代码里硬改，测不出真实场景。这是 T0 要解决的问题。

    另一半是消费侧闭环：内容源本质是「几个静态文件 + 一个版本号」，
    所以**用本机 http.server 就能当源**，不需要任何公网服务器。
    这里把「正常更新 / 已是最新 / 源不可达 / 校验不符 / 必需文件缺失」
    五个场景钉死，防止回归。

运行：python -m pytest tests/test_kb_source.py -q
      或：python -m unittest tests.test_kb_source -v
"""
import hashlib
import os
import shutil
import sys
import tempfile
import threading
import unittest
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from knowledge_base.updater import KnowledgeBaseUpdater, _version_key  # noqa: E402

DEFAULT_REPO = KnowledgeBaseUpdater.DEFAULT_REPO
ENV = KnowledgeBaseUpdater.ENV_SOURCE

REQUIRED = ("domains.csv", "behaviors.json")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def make_source(dst: Path, version: str = "1.0.0") -> Path:
    """构造一份最小可用的内容源目录（VERSION + 必需文件 + CHECKSUM）"""
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "domains.csv").write_text(
        "domain,organization,category,confidence,description,action\n"
        "e.example.com,示例组织,analytics,high,示例,allow\n",
        encoding="utf-8",
    )
    (dst / "behaviors.json").write_text("[]", encoding="utf-8")
    (dst / "VERSION").write_text(version, encoding="utf-8")
    lines = [f"{sha(dst / f)}  {f}" for f in REQUIRED]
    (dst / "CHECKSUM").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dst


def make_kb(dst: Path, version: str = "0.0.0", marker: str = "keepme\n") -> Path:
    """构造一份「已装了旧知识库」的目录"""
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "domains.csv").write_text(marker, encoding="utf-8")
    (dst / "behaviors.json").write_text("[]", encoding="utf-8")
    (dst / "VERSION").write_text(version, encoding="utf-8")
    return dst


class _Server:
    """本机静态源：起一个只服务指定目录的 HTTP 服务"""

    def __init__(self, directory: Path):
        handler = partial(SimpleHTTPRequestHandler, directory=str(directory))
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestSourceConfig(unittest.TestCase):
    """源可配：显式传参 > 环境变量 > 默认源"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self._old = os.environ.get(ENV)
        os.environ.pop(ENV, None)

    def tearDown(self):
        os.environ.pop(ENV, None)
        if self._old is not None:
            os.environ[ENV] = self._old
        shutil.rmtree(self.root, ignore_errors=True)

    def test_default_when_nothing_set(self):
        u = KnowledgeBaseUpdater(kb_dir=str(self.root))
        self.assertEqual(u.repo_urls, [DEFAULT_REPO])

    def test_explicit_arg_wins(self):
        u = KnowledgeBaseUpdater(kb_dir=str(self.root), repo_url="http://a.invalid/kb")
        self.assertEqual(u.repo_urls, ["http://a.invalid/kb"])

    def test_env_used_when_no_arg(self):
        os.environ[ENV] = "http://nas.local:8080/kb"
        u = KnowledgeBaseUpdater(kb_dir=str(self.root))
        self.assertEqual(u.repo_urls, ["http://nas.local:8080/kb"])

    def test_explicit_arg_beats_env(self):
        os.environ[ENV] = "http://nas.local:8080/kb"
        u = KnowledgeBaseUpdater(kb_dir=str(self.root), repo_url="http://explicit.invalid/kb")
        self.assertEqual(u.repo_urls, ["http://explicit.invalid/kb"])

    def test_blank_env_falls_back_to_default(self):
        os.environ[ENV] = "   "
        u = KnowledgeBaseUpdater(kb_dir=str(self.root))
        self.assertEqual(u.repo_urls, [DEFAULT_REPO])

    def test_main_service_respects_env(self):
        """主服务实例化时也要吃到环境变量 —— 否则 T0 等于没做"""
        from core.main import HomewardService

        os.environ[ENV] = "http://nas.local:8080/kb"
        svc = HomewardService()
        self.assertEqual(svc.kb_updater.repo_urls, ["http://nas.local:8080/kb"])
        os.environ.pop(ENV, None)

    def test_main_service_default_unchanged(self):
        """不设环境变量时，默认联网目标必须与改动前完全一致"""
        from core.main import HomewardService

        svc = HomewardService()
        self.assertEqual(svc.kb_updater.repo_urls, [DEFAULT_REPO])


    def test_env_comma_separated_resolves_to_list(self):
        os.environ[ENV] = "http://a.local/kb, http://b.local/kb "
        u = KnowledgeBaseUpdater(kb_dir=str(self.root))
        self.assertEqual(u.repo_urls, ["http://a.local/kb", "http://b.local/kb"])

    def test_explicit_repo_urls_list_wins(self):
        u = KnowledgeBaseUpdater(
            kb_dir=str(self.root), repo_urls=["http://x/kb", "http://y/kb"]
        )
        self.assertEqual(u.repo_urls, ["http://x/kb", "http://y/kb"])

    def test_explicit_list_beats_env(self):
        os.environ[ENV] = "http://env.local/kb"
        u = KnowledgeBaseUpdater(kb_dir=str(self.root), repo_urls=["http://x/kb"])
        self.assertEqual(u.repo_urls, ["http://x/kb"])

    def test_dedup_sources(self):
        u = KnowledgeBaseUpdater(
            kb_dir=str(self.root),
            repo_urls=["http://x/kb", "http://x/kb", "http://y/kb"],
        )
        self.assertEqual(u.repo_urls, ["http://x/kb", "http://y/kb"])


class TestUpdateLoop(unittest.TestCase):
    """消费侧闭环：用本机静态源，不需要任何公网服务器"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.servers: list[_Server] = []

    def tearDown(self):
        for s in self.servers:
            s.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    def _serve(self, directory: Path) -> str:
        s = _Server(directory)
        self.servers.append(s)
        return s.base

    def test_normal_update(self):
        src = make_source(self.root / "src")
        kb = make_kb(self.root / "kb")
        base = self._serve(src)

        u = KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base)
        self.assertTrue(u.check_and_update())
        self.assertEqual((kb / "VERSION").read_text().strip(), "1.0.0")
        self.assertEqual(sha(kb / "domains.csv"), sha(src / "domains.csv"))

    def test_already_latest_noop(self):
        src = make_source(self.root / "src")
        kb = make_kb(self.root / "kb")
        base = self._serve(src)

        KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base).check_and_update()
        again = KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base).check_and_update()
        self.assertFalse(again)

    def test_version_compare_is_numeric(self):
        """'10.0.0' 必须大于 '9.0.0' —— 字符串比较会得出相反结论"""
        src = make_source(self.root / "src", version="9.0.0")
        kb = make_kb(self.root / "kb", version="10.0.0")
        base = self._serve(src)

        self.assertFalse(
            KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base).check_and_update()
        )

    def test_unreachable_source_keeps_local(self):
        kb = make_kb(self.root / "kb")
        u = KnowledgeBaseUpdater(kb_dir=str(kb), repo_url="http://127.0.0.1:1/nope")
        self.assertFalse(u.check_and_update())
        self.assertEqual((kb / "domains.csv").read_text(), "keepme\n")
        self.assertEqual((kb / "VERSION").read_text().strip(), "0.0.0")

    def test_checksum_mismatch_aborts(self):
        src = make_source(self.root / "src")
        (src / "CHECKSUM").write_text("0" * 64 + "  domains.csv\n", encoding="utf-8")
        kb = make_kb(self.root / "kb")
        base = self._serve(src)

        self.assertFalse(
            KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base).check_and_update()
        )
        self.assertEqual((kb / "domains.csv").read_text(), "keepme\n")

    def test_missing_required_file_aborts(self):
        """全或无：不允许留下「新版域名库 + 旧版行为库」的错配状态"""
        src = make_source(self.root / "src")
        (src / "behaviors.json").unlink()
        kb = make_kb(self.root / "kb")
        base = self._serve(src)

        self.assertFalse(
            KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base).check_and_update()
        )
        self.assertEqual((kb / "domains.csv").read_text(), "keepme\n")

    def test_zero_telemetry(self):
        """隐私红线：更新器不得存在任何回传用户数据的方法"""
        import inspect

        for name, _ in inspect.getmembers(KnowledgeBaseUpdater, inspect.isfunction):
            self.assertNotIn(
                "submit",
                name.lower(),
                f"更新器不应存在上报类方法：{name}（家卫零遥测）",
            )


    def test_multi_source_falls_through_to_working(self):
        """主源不可达时，自动切到备用源完成更新（抖动兜底）"""
        src = make_source(self.root / "src")
        kb = make_kb(self.root / "kb")
        base = self._serve(src)
        u = KnowledgeBaseUpdater(
            kb_dir=str(kb), repo_urls=["http://127.0.0.1:1/dead", base]
        )
        self.assertTrue(u.check_and_update())
        self.assertEqual((kb / "VERSION").read_text().strip(), "1.0.0")

    def test_multi_source_first_higher_wins(self):
        """多源均可用时，按顺序取第一个能更新的源"""
        src = make_source(self.root / "src", version="1.0.0")
        kb = make_kb(self.root / "kb", version="0.0.0")
        base = self._serve(src)
        u = KnowledgeBaseUpdater(
            kb_dir=str(kb), repo_urls=[base, "http://127.0.0.1:1/dead"]
        )
        self.assertTrue(u.check_and_update())
        self.assertEqual((kb / "VERSION").read_text().strip(), "1.0.0")


class TestBundledVersion(unittest.TestCase):
    """C1：内置知识库必须自带 VERSION，否则 UI 恒显示 0.0.0（P1）"""

    def test_bundled_kb_has_nonzero_version(self):
        bundled = Path(__file__).resolve().parent.parent / "src" / "knowledge_base" / "VERSION"
        self.assertTrue(bundled.exists(), "内置知识库必须带 VERSION 文件")
        v = bundled.read_text(encoding="utf-8").strip()
        self.assertNotEqual(v, "0.0.0", "内置 VERSION 不得为 0.0.0（那是『读不到』的兜底值）")
        self.assertTrue(
            _version_key(v) > (0,),
            f"内置 VERSION 必须是合法数值版本，实际：{v!r}",
        )

    def test_read_local_version_reads_file(self):
        kb = Path(tempfile.mkdtemp()) / "kb"
        kb.mkdir(parents=True)
        (kb / "VERSION").write_text("2.3.1\n", encoding="utf-8")
        (kb / "domains.csv").write_text("x\n", encoding="utf-8")
        (kb / "behaviors.json").write_text("[]", encoding="utf-8")
        u = KnowledgeBaseUpdater(kb_dir=str(kb))
        self.assertEqual(u._read_local_version(), "2.3.1")


class TestMakeKbSource(unittest.TestCase):
    """C4：一键起内容源脚本，CHECKSUM 格式须与 updater 解析一致"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _load_module(self):
        import importlib.util

        p = (
            Path(__file__).resolve().parent.parent
            / "scripts"
            / "make_kb_source.py"
        )
        spec = importlib.util.spec_from_file_location("make_kb_source", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_build_checksum_format_and_verifiable(self):
        from knowledge_base.updater import KnowledgeBaseUpdater

        src = self.root / "kb"
        src.mkdir(parents=True)
        (src / "domains.csv").write_text("x,y\n", encoding="utf-8")
        (src / "behaviors.json").write_text("[]", encoding="utf-8")
        mks = self._load_module()
        checksum = mks.build_checksum(src)
        # 格式：<sha256>  <filename>（两空格）
        for line in checksum.strip().splitlines():
            self.assertRegex(line, r"^[0-9a-f]{64}  \S+$")
        # updater 能认这个 CHECKSUM（反方向校验，防止格式漂移）
        u = KnowledgeBaseUpdater(kb_dir=str(src))
        self.assertTrue(u._verify_checksum(src, checksum))

    def test_build_checksum_missing_required_raises(self):
        src = self.root / "kb"
        src.mkdir()
        (src / "domains.csv").write_text("x\n", encoding="utf-8")
        # 故意缺 behaviors.json
        mks = self._load_module()
        with self.assertRaises(SystemExit):
            mks.build_checksum(src)


class TestSignature(unittest.TestCase):
    """C2：内容源 Ed25519 签名验证（双轨公钥 + 降级告警）

    自包含：测试内生成密钥对，不依赖真实私钥（真实种子仅在私有目录）。
    """

    ENV_PUB = "HOMEWARD_KB_PUBKEY"
    ENV_REQ = "HOMEWARD_KB_REQUIRE_SIGNATURE"

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.servers = []
        from license.ed25519 import generate_seed, derive_public

        self.seed = generate_seed()
        self.pub = derive_public(self.seed).hex()
        self._old_pub = os.environ.pop(self.ENV_PUB, None)
        self._old_req = os.environ.pop(self.ENV_REQ, None)
        os.environ[self.ENV_PUB] = self.pub  # 用环境变量注入公钥

    def tearDown(self):
        for s in getattr(self, "servers", []):
            s.stop()
        os.environ.pop(self.ENV_PUB, None)
        os.environ.pop(self.ENV_REQ, None)
        if self._old_pub is not None:
            os.environ[self.ENV_PUB] = self._old_pub
        if self._old_req is not None:
            os.environ[self.ENV_REQ] = self._old_req
        shutil.rmtree(self.root, ignore_errors=True)

    def _signed_source(self, version: str = "1.0.0", tamper: bool = False) -> tuple[Path, str]:
        """构造一份带有效 SIGNATURE 的内容源，返回 (源目录, base_url)"""
        from license.ed25519 import sign_message

        src = make_source(self.root / "src", version=version)
        checksum = (src / "CHECKSUM").read_text(encoding="utf-8")
        if tamper:
            sig = sign_message(b"tampered", self.seed)
        else:
            sig = sign_message(checksum.encode("utf-8"), self.seed)
        (src / "SIGNATURE").write_text(sig.hex() + "\n", encoding="utf-8")
        return src

    def test_valid_signature_passes(self):
        src = self._signed_source()
        kb = make_kb(self.root / "kb")
        base = self._serve(src)
        u = KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base)
        self.assertTrue(u.check_and_update())
        self.assertEqual((kb / "VERSION").read_text().strip(), "1.0.0")

    def test_invalid_signature_rejected_when_required(self):
        os.environ[self.ENV_REQ] = "1"
        src = self._signed_source(tamper=True)  # 用错消息签名 → 验签失败
        kb = make_kb(self.root / "kb")
        base = self._serve(src)
        u = KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base)
        self.assertFalse(u.check_and_update())
        self.assertEqual((kb / "domains.csv").read_text(), "keepme\n")

    def test_absent_signature_warns_when_not_required(self):
        """降级模式：无签名仅告警，仍允许更新"""
        src = make_source(self.root / "src")
        kb = make_kb(self.root / "kb")
        base = self._serve(src)
        u = KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base)
        self.assertTrue(u.check_and_update())

    def test_absent_signature_rejected_when_required(self):
        os.environ[self.ENV_REQ] = "1"
        src = make_source(self.root / "src")  # 无 SIGNATURE
        kb = make_kb(self.root / "kb")
        base = self._serve(src)
        u = KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base)
        self.assertFalse(u.check_and_update())
        self.assertEqual((kb / "domains.csv").read_text(), "keepme\n")

    def test_signed_update_works_without_src_on_syspath(self):
        """回归（生产路径）：家卫以 ``python -m src.ui.server`` 启动时 ``src/`` 不在
        sys.path 顶层，``from license.ed25519`` 会解析到 Python 标准库的 ``license``
        模块（无 ed25519 属性）→ 若没有 importlib 文件路径兜底，验签会被**静默跳过**，
        C2 安全能力在生产环境形同虚设。

        本测试复现该条件（临时把 src/ 移出 sys.path），用 importlib 从文件加载 updater，
        再跑一次带签名的内容源更新，验证签名校验**确实生效且通过**。"""
        import importlib.util as _ilu

        src_dir = Path(__file__).resolve().parent.parent / "src"
        updater_path = src_dir / "knowledge_base" / "updater.py"
        saved = list(sys.path)
        # 复现生产：src/ 不在 sys.path 顶层（标准库 license 优先）
        sys.path = [p for p in sys.path if os.path.abspath(p) != str(src_dir)]
        try:
            spec = _ilu.spec_from_file_location("kb_updater_prod", str(updater_path))
            mod = _ilu.module_from_spec(spec)
            spec.loader.exec_module(mod)
        finally:
            sys.path = saved

        os.environ[self.ENV_PUB] = self.pub
        src = self._signed_source()  # 带有效 SIGNATURE
        kb = make_kb(self.root / "kb_prod")
        base = self._serve(src)
        u = mod.KnowledgeBaseUpdater(kb_dir=str(kb), repo_url=base)
        self.assertTrue(u.check_and_update())
        self.assertEqual((kb / "VERSION").read_text().strip(), "1.0.0")
        # 验签函数确实可用（未被跳过）
        self.assertTrue(callable(u._verify_signature))

    def _serve(self, directory: Path) -> str:
        s = _Server(directory)
        self.servers.append(s)
        return s.base


if __name__ == "__main__":
    unittest.main(verbosity=2)
