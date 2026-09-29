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

from knowledge_base.updater import KnowledgeBaseUpdater  # noqa: E402

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
        self.assertEqual(u.repo_url, DEFAULT_REPO)

    def test_explicit_arg_wins(self):
        u = KnowledgeBaseUpdater(kb_dir=str(self.root), repo_url="http://a.invalid/kb")
        self.assertEqual(u.repo_url, "http://a.invalid/kb")

    def test_env_used_when_no_arg(self):
        os.environ[ENV] = "http://nas.local:8080/kb"
        u = KnowledgeBaseUpdater(kb_dir=str(self.root))
        self.assertEqual(u.repo_url, "http://nas.local:8080/kb")

    def test_explicit_arg_beats_env(self):
        os.environ[ENV] = "http://nas.local:8080/kb"
        u = KnowledgeBaseUpdater(kb_dir=str(self.root), repo_url="http://explicit.invalid/kb")
        self.assertEqual(u.repo_url, "http://explicit.invalid/kb")

    def test_blank_env_falls_back_to_default(self):
        os.environ[ENV] = "   "
        u = KnowledgeBaseUpdater(kb_dir=str(self.root))
        self.assertEqual(u.repo_url, DEFAULT_REPO)

    def test_main_service_respects_env(self):
        """主服务实例化时也要吃到环境变量 —— 否则 T0 等于没做"""
        from core.main import HomewardService

        os.environ[ENV] = "http://nas.local:8080/kb"
        svc = HomewardService()
        self.assertEqual(svc.kb_updater.repo_url, "http://nas.local:8080/kb")
        os.environ.pop(ENV, None)

    def test_main_service_default_unchanged(self):
        """不设环境变量时，默认联网目标必须与改动前完全一致"""
        from core.main import HomewardService

        svc = HomewardService()
        self.assertEqual(svc.kb_updater.repo_url, DEFAULT_REPO)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
