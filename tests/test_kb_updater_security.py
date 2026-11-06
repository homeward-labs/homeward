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

from knowledge_base.updater import KnowledgeBaseUpdater  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
