"""Stage 1 安全回归：CHECKSUM 远程文件名校验 + KB 替换全或无。

对应审计报告 ME-7（路径遍历 / 半写窗口）与施工单 Stage 1 的 1、4 两项。
运行：python -m pytest tests/test_kb_updater_security.py -q
"""
import hashlib
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from knowledge_base import updater as kb_updater  # noqa: E402
from knowledge_base.updater import (  # noqa: E402
    KnowledgeBaseUpdater,
    UPDATE_MARKER_FILENAME,
)


def _sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


class TestChecksumFname(unittest.TestCase):
    """CHECKSUM 内容由远端内容源提供，属不可信输入。"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.u = KnowledgeBaseUpdater(kb_dir=str(self.root))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_valid_fname_passes(self):
        (self.root / "domains.csv").write_bytes(b"ok")
        self.assertTrue(
            self.u._verify_checksum(self.root, _sha(b"ok") + "  domains.csv\n")
        )

    def test_hash_mismatch_rejected(self):
        (self.root / "domains.csv").write_bytes(b"ok")
        self.assertFalse(
            self.u._verify_checksum(self.root, "0" * 64 + "  domains.csv\n")
        )

    def test_missing_file_rejected(self):
        self.assertFalse(
            self.u._verify_checksum(self.root, "0" * 64 + "  domains.csv\n")
        )

    def test_directory_instead_of_file_rejected(self):
        (self.root / "domains.csv").mkdir()
        self.assertFalse(
            self.u._verify_checksum(self.root, "0" * 64 + "  domains.csv\n")
        )

    def test_traversal_and_illegal_fnames_rejected(self):
        bad = [
            "../evil", "..\\evil", "sub/domains.csv", "/etc/passwd",
            "C:\\Windows\\win.ini", "..", ".", ".hidden",
            "CON", "NUL", "COM1", "LPT9",
        ]
        for fname in bad:
            with self.subTest(fname=fname):
                self.assertFalse(
                    self.u._verify_checksum(self.root, "0" * 64 + "  " + fname + "\n"),
                    "应拒绝非法 fname: %r" % fname,
                )

    def test_safe_fname_accepts_known_data_files(self):
        for fname in ("domains.csv", "behaviors.json", "asn.csv", "oui_prefixes.csv"):
            with self.subTest(fname=fname):
                self.assertTrue(KnowledgeBaseUpdater._safe_fname(fname))


class TestAtomicReplace(unittest.TestCase):
    """替换过程中出错必须整体回滚，且不留 .hwswap 临时文件。"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.kb = self.root / "kb"
        self.stage = self.root / "stage"
        self.kb.mkdir()
        self.stage.mkdir()
        (self.kb / "domains.csv").write_bytes(b"OLD-DOMAINS")
        (self.kb / "behaviors.json").write_bytes(b"OLD-BEHAVIORS")
        (self.stage / "domains.csv").write_bytes(b"NEW-DOMAINS")
        (self.stage / "behaviors.json").write_bytes(b"NEW-BEHAVIORS")
        self.u = KnowledgeBaseUpdater(kb_dir=str(self.kb))
        self.files = ["domains.csv", "behaviors.json"]

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_all_replaced(self):
        self.assertTrue(self.u._replace_all_atomic(self.stage, self.files))
        self.assertEqual((self.kb / "domains.csv").read_bytes(), b"NEW-DOMAINS")
        self.assertEqual((self.kb / "behaviors.json").read_bytes(), b"NEW-BEHAVIORS")
        self.assertEqual(list(self.kb.glob("*.hwswap-*")), [])

    def test_missing_optional_source_skipped(self):
        self.assertTrue(
            self.u._replace_all_atomic(self.stage, self.files + ["asn.csv"])
        )
        self.assertEqual((self.kb / "domains.csv").read_bytes(), b"NEW-DOMAINS")

    def test_rollback_on_mid_failure(self):
        real_replace = os.replace
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("simulated disk failure")
            return real_replace(src, dst)

        with mock.patch("knowledge_base.updater.os.replace", side_effect=flaky):
            ok = self.u._replace_all_atomic(self.stage, self.files)
        self.assertFalse(ok)
        self.assertEqual((self.kb / "domains.csv").read_bytes(), b"OLD-DOMAINS")
        self.assertEqual((self.kb / "behaviors.json").read_bytes(), b"OLD-BEHAVIORS")
        self.assertEqual(list(self.kb.glob("*.hwswap-*")), [])

    def test_rollback_removes_newly_added_file(self):
        (self.stage / "asn.csv").write_bytes(b"NEW-ASN")
        real_replace = os.replace
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("simulated disk failure")
            return real_replace(src, dst)

        with mock.patch("knowledge_base.updater.os.replace", side_effect=flaky):
            ok = self.u._replace_all_atomic(
                self.stage, ["domains.csv", "asn.csv", "behaviors.json"]
            )
        self.assertFalse(ok)
        self.assertEqual((self.kb / "domains.csv").read_bytes(), b"OLD-DOMAINS")
        self.assertFalse((self.kb / "asn.csv").exists())
        self.assertEqual(list(self.kb.glob("*.hwswap-*")), [])


class TestCrashRecovery(unittest.TestCase):
    """Stage 6：崩溃恢复标记（只检测/清理/告警，绝不联网重下或自动回滚）"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.kb = self.root / "kb"
        self.stage = self.root / "stage"
        self.kb.mkdir()
        self.stage.mkdir()
        (self.kb / "domains.csv").write_bytes(b"OLD-DOMAINS")
        (self.kb / "behaviors.json").write_bytes(b"OLD-BEHAVIORS")
        (self.stage / "domains.csv").write_bytes(b"NEW-DOMAINS")
        (self.stage / "behaviors.json").write_bytes(b"NEW-BEHAVIORS")
        self.u = KnowledgeBaseUpdater(kb_dir=str(self.kb))
        self.files = ["domains.csv", "behaviors.json"]
        self.marker = self.kb / UPDATE_MARKER_FILENAME

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_success_removes_marker(self):
        self.assertTrue(self.u._replace_all_atomic(self.stage, self.files))
        self.assertFalse(self.marker.exists())

    def test_rollback_removes_marker(self):
        real_replace = os.replace
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("simulated disk failure")
            return real_replace(src, dst)

        with mock.patch("knowledge_base.updater.os.replace", side_effect=flaky):
            ok = self.u._replace_all_atomic(self.stage, self.files)
        self.assertFalse(ok)
        self.assertFalse(self.marker.exists())
        self.assertEqual((self.kb / "domains.csv").read_bytes(), b"OLD-DOMAINS")

    def test_marker_present_during_replace_window(self):
        seen = []
        real_replace = os.replace

        def probe(src, dst):
            seen.append(self.marker.exists())
            return real_replace(src, dst)

        with mock.patch("knowledge_base.updater.os.replace", side_effect=probe):
            self.assertTrue(self.u._replace_all_atomic(self.stage, self.files))
        self.assertEqual(seen, [True, True], "每次 os.replace 时标记都应存在")
        self.assertFalse(self.marker.exists())

    def test_recovery_cleans_marker_and_swap_residue_without_network(self):
        self.marker.write_text("interrupted_replace test\n", encoding="utf-8")
        residue = self.kb / ".domains.csv.hwswap-deadbeef"
        residue.write_bytes(b"PARTIAL")
        with mock.patch("knowledge_base.updater.urlopen") as net:
            self.assertTrue(self.u.recover_if_interrupted())
            net.assert_not_called()
        self.assertFalse(self.marker.exists())
        self.assertFalse(residue.exists())
        self.assertEqual((self.kb / "domains.csv").read_bytes(), b"OLD-DOMAINS",
                         "恢复不得改动既有 KB 文件（不自动回滚/重下）")
        self.assertEqual((self.kb / "behaviors.json").read_bytes(), b"OLD-BEHAVIORS")

    def test_recovery_is_idempotent_and_noop_without_marker(self):
        self.assertFalse(self.u.recover_if_interrupted())
        self.marker.write_text("x\n", encoding="utf-8")
        self.assertTrue(self.u.recover_if_interrupted())
        self.assertFalse(self.u.recover_if_interrupted())

    def test_recovery_tolerates_missing_kb_dir(self):
        u = KnowledgeBaseUpdater(kb_dir=str(self.root / "nonexistent"))
        self.assertFalse(u.recover_if_interrupted())


class TestCrashRecoveryHardening(unittest.TestCase):
    """第 400 批：残留精确匹配、迭代期 IO 容错、marker 写失败 fail-closed。"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.kb = self.root / "kb"
        self.stage = self.root / "stage"
        self.kb.mkdir()
        self.stage.mkdir()
        (self.kb / "domains.csv").write_bytes(b"OLD-DOMAINS")
        (self.kb / "behaviors.json").write_bytes(b"OLD-BEHAVIORS")
        (self.stage / "domains.csv").write_bytes(b"NEW-DOMAINS")
        (self.stage / "behaviors.json").write_bytes(b"NEW-BEHAVIORS")
        self.u = KnowledgeBaseUpdater(kb_dir=str(self.kb))
        self.files = ["domains.csv", "behaviors.json"]
        self.marker = self.kb / UPDATE_MARKER_FILENAME

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_recovery_only_removes_own_swap_residue(self):
        self.marker.write_text("interrupted_replace test\n", encoding="utf-8")
        own = self.kb / ".domains.csv.hwswap-deadbeef"
        own.write_bytes(b"PARTIAL")
        decoys = [
            "domains.csv.hwswap-backup",          # 无前导点
            ".domains.csv.hwswap-1234567",        # 7 位
            ".domains.csv.hwswap-123456789",      # 9 位
            ".domains.csv.hwswap-ghijklmn",       # 非 hex 字符
            ".domains.csv.hwswap-deadbeef.txt",   # 多余尾缀
            "notes-hwswap-todo.txt",              # 完全无关
        ]
        for name in decoys:
            (self.kb / name).write_bytes(b"KEEP")
        self.assertTrue(self.u.recover_if_interrupted())
        self.assertFalse(own.exists())
        for name in decoys:
            self.assertTrue((self.kb / name).exists(), "误删非本流程文件: " + name)
        self.assertFalse(self.marker.exists())

    def test_recovery_tolerates_iterdir_io_error(self):
        self.marker.write_text("x\n", encoding="utf-8")
        with mock.patch.object(Path, "iterdir",
                               side_effect=OSError("simulated IO failure")):
            self.assertFalse(self.u.recover_if_interrupted())
        # 检测失败时保留标记，下次启动再试
        self.assertTrue(self.marker.exists())

    def test_marker_write_failure_fails_closed(self):
        real_write_text = Path.write_text

        def deny_marker(path_obj, *a, **kw):
            if path_obj.name == UPDATE_MARKER_FILENAME:
                raise OSError("simulated read-only kb dir")
            return real_write_text(path_obj, *a, **kw)

        with mock.patch.object(Path, "write_text", deny_marker):
            ok = self.u._replace_all_atomic(self.stage, self.files)
        self.assertFalse(ok)
        self.assertEqual((self.kb / "domains.csv").read_bytes(), b"OLD-DOMAINS")
        self.assertEqual((self.kb / "behaviors.json").read_bytes(), b"OLD-BEHAVIORS")
        self.assertFalse(list(self.kb.glob(".*.hwswap-*")))
        self.assertFalse(self.marker.exists())


class TestKbTokenGate(unittest.TestCase):
    """内容源门禁（X-Homeward-KB-Token / 403）：口令必须出示，403 必须显式失败。"""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_http_get_sends_token_header_when_env_set(self):
        captured = {}

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"OK"

        def fake_urlopen(req, timeout=None):
            captured["headers"] = {str(k).lower(): str(v) for k, v in dict(req.header_items()).items()}
            return _Resp()

        with mock.patch.dict(os.environ, {"HOMEWARD_KB_TOKEN": "test-token-value"}):
            with mock.patch("knowledge_base.updater.urlopen", side_effect=fake_urlopen):
                self.assertEqual(kb_updater._http_get("http://example.invalid/v", 5), b"OK")

        self.assertEqual(captured["headers"].get("x-homeward-kb-token"), "test-token-value")
        self.assertIn("user-agent", captured["headers"])

    def test_http_get_omits_token_header_when_env_missing(self):
        captured = {}

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"OK"

        def fake_urlopen(req, timeout=None):
            captured["headers"] = {str(k).lower(): str(v) for k, v in dict(req.header_items()).items()}
            return _Resp()

        env = {k: v for k, v in os.environ.items() if k != "HOMEWARD_KB_TOKEN"}
        with mock.patch.dict(os.environ, env, clear=True):
            with mock.patch("knowledge_base.updater.urlopen", side_effect=fake_urlopen):
                kb_updater._http_get("http://example.invalid/v", 5)

        self.assertNotIn("x-homeward-kb-token", captured["headers"])

    def test_http_get_raises_kbauthdenied_on_403(self):
        err = kb_updater.HTTPError("http://example.invalid/v", 403, "Forbidden", {}, None)
        with mock.patch("knowledge_base.updater.urlopen", side_effect=err):
            with self.assertRaises(kb_updater.KBAuthDenied) as ctx:
                kb_updater._http_get("http://example.invalid/v", 5)
        self.assertIn("HOMEWARD_KB_TOKEN", str(ctx.exception))

    def test_non_403_http_error_propagates_unchanged(self):
        err = kb_updater.HTTPError("http://example.invalid/v", 404, "Not Found", {}, None)
        with mock.patch("knowledge_base.updater.urlopen", side_effect=err):
            with self.assertRaises(kb_updater.HTTPError):
                kb_updater._http_get("http://example.invalid/v", 5)

    def test_all_sources_403_raises_instead_of_silent_false(self):
        u = KnowledgeBaseUpdater(kb_dir=str(self.root), repo_urls=["http://a.invalid", "http://b.invalid"])
        with mock.patch.object(u, "_try_update_from", side_effect=kb_updater.KBAuthDenied("403")):
            with self.assertRaises(kb_updater.KBAuthDenied):
                u.check_and_update()

    def test_partial_403_still_returns_false(self):
        u = KnowledgeBaseUpdater(kb_dir=str(self.root), repo_urls=["http://a.invalid", "http://b.invalid"])

        def fake(url):
            if url.endswith("a.invalid"):
                raise kb_updater.KBAuthDenied("403")
            return False

        with mock.patch.object(u, "_try_update_from", side_effect=fake):
            self.assertFalse(u.check_and_update())


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
