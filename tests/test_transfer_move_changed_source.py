"""A move keeps a source that changed while it was being copied.

Reported: moving a log file that was still being written from the local
disk to an SFTP server ended "done" and deleted the local file - but the
lines appended after the copy had read the last byte were in neither
place. The worker removed the source on the strength of "the copy read to
EOF". Its integrity check could not object: the SFTP server offers no
checksum, and without one the check is skipped. A local-to-local move
caught the same case only because both sides there hash the whole file.

Now a move compares the source's size before and after the copy and keeps
the source (failing the job) when it differs.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402

LATE = b"LATE LOG LINE\n"


class _WrittenAtEof(LocalFS):
    """A writer appends to the source right after the copy read its end."""

    late = LATE

    def open_read(self, path):
        handle = super().open_read(path)
        real_read = handle.read
        state = {"done": False}

        def read(n=-1):
            data = real_read(n)
            if not data and not state["done"]:
                state["done"] = True
                with open(path, "ab") as writer:
                    writer.write(self.late)
            return data

        handle.read = read
        return handle


class _NoStat(LocalFS):
    """A source backend that cannot stat a file (the protocol has no such call)."""

    def stat(self, path):
        raise OSError(95, "Operation not supported")


class MoveChangedSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.profiles import ConnectionProfile
        from core.ssh_client import SSHSession
        from core.transfer_manager import TransferManager
        from tests.sftp_testkit import SftpServer

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.server_root = self.tmp / "srv"
        self.server_root.mkdir()
        self.local = self.tmp / "local"
        self.local.mkdir()
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        patch = mock.patch("pathlib.Path.home", return_value=home)
        patch.start()
        self.addCleanup(patch.stop)
        server = SftpServer(str(self.server_root))
        self.addCleanup(server.close)
        profile = ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=server.port, username="u"
        )
        self.sftp = SSHSession(profile)
        self.sftp.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.sftp.disconnect)
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)

    def _move(self, source_backend, name: str, dest_backend=None, dest_dir="/"):
        jobs = self.mgr.transfer_files(
            source_backend, dest_backend or self.sftp, [str(self.local / name)],
            dest_dir, move=True,
        )
        deadline = time.monotonic() + 20
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            self.assertLess(time.monotonic(), deadline, "move did not finish")
            time.sleep(0.01)
        self.app.processEvents()
        [job] = jobs
        return job

    def test_happy_an_unchanged_file_is_moved(self) -> None:
        (self.local / "app.log").write_bytes(b"line\n" * 1000)
        job = self._move(LocalFS(), "app.log")
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertFalse((self.local / "app.log").exists())
        self.assertEqual((self.server_root / "app.log").read_bytes(), b"line\n" * 1000)

    def test_sad_a_file_appended_during_the_copy_keeps_its_source(self) -> None:
        (self.local / "app.log").write_bytes(b"line\n" * 1000)
        job = self._move(_WrittenAtEof(), "app.log")
        self.assertEqual(job.status, TransferStatus.ERROR)
        self.assertIn("changed while it was copied", job.error_message)
        # Nothing is lost: the source still has every line, the late one too.
        self.assertEqual((self.local / "app.log").read_bytes(), b"line\n" * 1000 + LATE)
        self.assertEqual((self.server_root / "app.log").read_bytes(), b"line\n" * 1000)

    def test_edge_a_local_move_of_a_symlink_still_completes(self) -> None:
        (self.local / "real.bin").write_bytes(b"R" * 4000)
        os.symlink(self.local / "real.bin", self.local / "link.bin")
        dest = self.tmp / "dest"
        dest.mkdir()
        job = self._move(LocalFS(), "link.bin", dest_backend=LocalFS(), dest_dir=str(dest))
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertFalse(os.path.lexists(self.local / "link.bin"))
        self.assertEqual((dest / "link.bin").read_bytes(), b"R" * 4000)
        self.assertEqual((self.local / "real.bin").read_bytes(), b"R" * 4000)

    def test_edge_a_source_without_stat_moves_as_before(self) -> None:
        (self.local / "f.bin").write_bytes(b"x" * 500)
        job = self._move(_NoStat(), "f.bin")
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertFalse((self.local / "f.bin").exists())
        self.assertEqual((self.server_root / "f.bin").read_bytes(), b"x" * 500)


if __name__ == "__main__":
    unittest.main()
