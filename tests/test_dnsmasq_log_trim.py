"""
待办-526 / 小存储设备精简档 —— 日志脚本离线验收（方案 §7 五例中可本地复现的四例）

脚本是给 busybox（iStoreOS / OpenWrt）用的 POSIX sh，所以测试通过宿主 sh 执行，
不依赖目标设备。找不到 sh 的环境自动跳过（CI 无 shell 时不阻塞回归）。

覆盖：
  1. check 模式打印档位与阈值；
  2. 未超阈值不动文件；
  3. 超阈值原地截断，**inode 不变**（bind 挂载不失明的关键）；
  4. 尾片目录与日志同一文件系统 → 拒绝尾片，只截断（零放大）；
  5. 归档档同文件系统 → 拒绝归档（退出码 2）。
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TRIM = REPO / "docker" / "dnsmasq" / "dnsmasq-log-trim.sh"
ROTATE = REPO / "docker" / "dnsmasq" / "dnsmasq-log-rotate-safe.sh"

SH = shutil.which("sh") or shutil.which("bash") or (
    str(Path(r"C:\Users\xuekai\.workbuddy\binaries\PortableGit\versions\1.3.0\bin\bash.exe"))
    if os.name == "nt" and Path(r"C:\Users\xuekai\.workbuddy\binaries\PortableGit\versions\1.3.0\bin\bash.exe").exists()
    else None
)


@unittest.skipIf(SH is None, "宿主无 POSIX shell，脚本验收跳过")
class LogTrimScriptTest(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hw-trim-")
        self.log = Path(self.tmp) / "dnsmasq.log"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, script, args=(), env_extra=None):
        env = dict(os.environ)
        env.update({
            "HOMEWARD_DNS_LOG": str(self.log).replace("\\", "/"),
            "HOMEWARD_LOG_MAX_MB": "1",          # 1 MB，避免测试写大文件
            "HOMEWARD_LOG_TMPFS_PCT": "100",     # 让 MB 上限生效，排除 df 干扰
        })
        if env_extra:
            env.update(env_extra)
        cmd = [SH, str(script).replace("\\", "/")] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)

    def test_check_mode_reports_tier_and_limit(self):
        self.log.write_text("", encoding="utf-8")
        r = self._run(TRIM, ["check"])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("档位=", r.stdout)
        self.assertIn("阈值=", r.stdout)
        self.assertIn("超限=no", r.stdout)

    def test_below_limit_untouched(self):
        self.log.write_text("x" * 100 + "\n", encoding="utf-8")
        before = self.log.stat()
        r = self._run(TRIM, ["trim"])
        self.assertEqual(r.returncode, 0, r.stderr)
        after = self.log.stat()
        self.assertEqual(before.st_size, after.st_size)
        self.assertEqual(before.st_ino, after.st_ino)

    def test_above_limit_truncates_in_place(self):
        self.log.write_bytes(b"y" * (2 * 1024 * 1024))
        before = self.log.stat()
        r = self._run(TRIM, ["trim"])
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        after = self.log.stat()
        self.assertEqual(after.st_size, 0)
        # 保 inode：同一个文件被截短，而不是换了新文件
        self.assertEqual(before.st_ino, after.st_ino)

    def test_same_filesystem_tail_refused(self):
        self.log.write_bytes(b"z" * (2 * 1024 * 1024))
        r = self._run(TRIM, ["trim"], {"HOMEWARD_LOG_TAIL_DIR": self.tmp.replace("\\", "/")})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("同一文件系统", r.stdout + r.stderr)
        self.assertEqual(self.log.stat().st_size, 0)
        self.assertFalse((Path(self.tmp) / "dnsmasq-tail.log").exists())

    def test_archive_refuses_same_filesystem(self):
        self.log.write_bytes(b"a" * 1024)
        r = self._run(ROTATE, [], {
            "HOMEWARD_ARCHIVE_DIR": (Path(self.tmp) / "arch").as_posix(),
        })
        self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
        self.assertEqual(self.log.stat().st_size, 1024)   # 拒绝归档时不动日志


if __name__ == "__main__":
    unittest.main()
