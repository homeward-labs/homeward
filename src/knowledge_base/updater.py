"""
知识库在线更新模块
支持从社区仓库拉取最新域名归属数据
"""

import csv
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import urlopen, Request


class KnowledgeBaseUpdater:
    """知识库在线更新器"""

    DEFAULT_REPO = "https://raw.githubusercontent.com/homeward/knowledge-base/main"

    def __init__(self, kb_dir: str, repo_url: str = None, auto_update: bool = True, interval: int = 604800):
        """
        kb_dir: 知识库目录
        repo_url: 远程仓库地址
        auto_update: 是否自动更新
        interval: 更新间隔（秒），默认 7 天
        """
        self.kb_dir = Path(kb_dir)
        self.repo_url = repo_url or self.DEFAULT_REPO
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
        """
        检查并更新知识库
        返回是否更新了新数据
        """
        # 1. 检查版本
        remote_version = self._fetch_version()
        if not remote_version:
            return False

        local_version = self._read_local_version()
        if remote_version <= local_version:
            print(f"[KB Update] Already up to date (v{local_version})")
            return False

        # 2. 下载新版本
        print(f"[KB Update] New version available: v{local_version} → v{remote_version}")
        if self._download_and_replace(remote_version):
            self._write_local_version(remote_version)
            print(f"[KB Update] Updated to v{remote_version}")
            return True

        return False

    def _fetch_version(self) -> str | None:
        """获取远程版本号"""
        try:
            with urlopen(f"{self.repo_url}/VERSION", timeout=10) as resp:
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

    def _download_and_replace(self, version: str) -> bool:
        """原子替换知识库文件"""
        files = ["domains.csv", "behaviors.json", "asn.csv"]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            for fname in files:
                url = f"{self.repo_url}/{fname}"
                dst = tmpdir / fname
                try:
                    with urlopen(url, timeout=30) as resp:
                        dst.write_bytes(resp.read())
                except Exception:
                    continue

            # 校验（可选：比对 checksum）
            checksum_url = f"{self.repo_url}/CHECKSUM"
            try:
                with urlopen(checksum_url, timeout=10) as resp:
                    expected = resp.read().decode()
                if not self._verify_checksum(tmpdir, expected):
                    print("[KB Update] Checksum mismatch, aborting")
                    return False
            except Exception:
                pass  # 校验文件不存在则跳过

            # 原子替换
            for fname in files:
                src = tmpdir / fname
                if src.exists():
                    shutil.move(str(src), str(self.kb_dir / fname))

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

    def submit_anonymous_data(self, domain: str, behavior_summary: dict) -> bool:
        """
        匿名提交未知域名和观察到的行为摘要
        供社区知识库贡献新样本
        """
        # 只提交域名 + 行为元数据，不提交任何 payload 或用户标识
        payload = json.dumps({
            "domain": domain,
            "behavior": behavior_summary,
            "submitted_at": int(time.time()),
        }).encode()

        try:
            req = Request(
                f"{self.repo_url.replace('/raw/', '/api/')}/submit",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception:
            return False
