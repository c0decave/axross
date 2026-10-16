"""rsync open_read of a symlink returns the target's bytes.

open_read ran ``rsync <url> <tmpfile>`` without ``-L`` / ``-l``. For a
symlink rsync prints "skipping non-regular file", exits 0, and leaves
the temp file empty: the listing shows ``link.txt``, reading it gives
``b""``, and a copy from the pane silently produces an empty file.

Driven end to end against a real ``rsync --daemon`` on 127.0.0.1.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

RSYNC = shutil.which("rsync")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(RSYNC, "rsync binary not installed")
class RsyncSymlinkReadTest(unittest.TestCase):
    def setUp(self) -> None:
        from core.rsync_client import RsyncSession

        self.tmp = tempfile.mkdtemp(prefix="axross-rsyncd-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        data = os.path.join(self.tmp, "data")
        os.makedirs(os.path.join(data, "dir"))
        Path(data, "real.txt").write_bytes(b"payload\n")
        os.symlink("real.txt", os.path.join(data, "link.txt"))
        os.symlink("dir", os.path.join(data, "dirlink"))
        os.symlink("missing.txt", os.path.join(data, "dangling"))
        port = _free_port()
        conf = os.path.join(self.tmp, "rsyncd.conf")
        Path(conf).write_text(
            f"pid file = {self.tmp}/pid\nuse chroot = no\nmunge symlinks = no\n"
            f"address = 127.0.0.1\nport = {port}\n"
            f"[mod]\npath = {data}\nread only = no\n"
        )
        self.daemon = subprocess.Popen(
            [RSYNC, "--daemon", "--no-detach", f"--config={conf}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.daemon.wait, 5)
        self.addCleanup(self.daemon.terminate)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        self.s = RsyncSession("127.0.0.1", port=port, module="mod")

    def _read(self, path: str) -> bytes:
        with self.s.open_read(path) as fh:
            return fh.read()

    def test_happy_regular_file(self) -> None:
        self.assertEqual(self._read("/real.txt"), b"payload\n")

    def test_sad_symlink_reads_its_target(self) -> None:
        names = {i.name: i.is_link for i in self.s.list_dir("/")}
        self.assertTrue(names["link.txt"])
        self.assertEqual(self._read("/link.txt"), b"payload\n")

    def test_edge_dangling_link_and_directory_fail_loudly(self) -> None:
        with self.assertRaises(OSError):
            self._read("/dangling")
        with self.assertRaises(OSError):
            self._read("/dirlink")


if __name__ == "__main__":
    unittest.main()
