"""A copy or move keeps a file's permission bits and modification time.

Measured before: F6 of a 0600 key gave a 0644 file, a 0700 script lost
its execute bit, and every copy carried "now" as its modification time,
so Compare -> Sync never converged for a file too large to hash (same
size, mtime differs = "unknown" forever).

The copy is never WIDER than its source, nor wider than the umask allows
(cp semantics), and a 0600 source's bytes never sit in a group- or
world-readable temp file.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

OLD = 1_600_000_000


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class _WatchingFS(LocalFS):
    """Records the temp file's mode at every write of data."""

    def __init__(self) -> None:
        super().__init__()
        self.modes_at_write: list[int] = []

    def open_write(self, path, append=False):
        fh = super().open_write(path, append)
        fs = self

        class _H:
            def write(self, data):
                fh.flush()
                fs.modes_at_write.append(_mode(path))
                return fh.write(data)

            def close(self):
                fh.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                fh.close()

        return _H()


class _NoMetadataFS(LocalFS):
    """A destination that can neither chmod nor set a time (S3-like)."""

    set_modified = None

    def chmod(self, path, mode):
        raise NotImplementedError("no chmod here")


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"
        self.out.mkdir()
        old = os.umask(0o022)
        self.addCleanup(os.umask, old)

    def _file(self, name: str, mode: int, data: bytes = b"data") -> Path:
        p = self.tmp / name
        p.write_bytes(data)
        os.chmod(p, mode)
        os.utime(p, (OLD, OLD))
        return p


class WorkerTest(_Base):
    def _run(self, src: Path, *, move=False, dest_fs=None) -> TW.TransferJob:
        fs = LocalFS()
        item = fs.stat(str(src))
        job = TW.TransferJob(
            source_path=str(src), dest_path=str(self.out / src.name),
            total_bytes=item.size, filename=src.name, move=move,
            source_backend=fs, dest_backend=dest_fs or LocalFS(),
            source_mode=item.permissions, source_mtime=item.modified.timestamp(),
        )
        TW.TransferWorker()._process_job(job)
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        return job

    def test_happy_a_moved_script_keeps_its_execute_bit_and_time(self) -> None:
        src = self._file("run.sh", 0o700, b"#!/bin/sh\n")
        self._run(src, move=True)
        dst = self.out / "run.sh"
        self.assertEqual(_mode(dst), 0o700)
        self.assertEqual(os.stat(dst).st_mtime, OLD)
        self.assertFalse(src.exists())

    def test_sad_a_secret_is_never_readable_by_others_while_copied(self) -> None:
        src = self._file("id_secret", 0o600, b"k" * (3 * TW.CHUNK_SIZE))
        fs = _WatchingFS()
        self._run(src, dest_fs=fs)
        self.assertTrue(fs.modes_at_write)
        self.assertEqual({m & 0o077 for m in fs.modes_at_write}, {0})
        self.assertEqual(_mode(self.out / "id_secret"), 0o600)

    def test_edge_the_copy_is_never_wider_than_the_umask(self) -> None:
        src = self._file("shared.txt", 0o666)
        self._run(src)
        self.assertEqual(_mode(self.out / "shared.txt"), 0o644)

    def test_edge_setuid_and_sticky_bits_are_not_copied(self) -> None:
        src = self._file("tool", 0o4755)
        self._run(src)
        self.assertEqual(_mode(self.out / "tool"), 0o755)

    def test_edge_a_destination_without_chmod_or_times_still_copies(self) -> None:
        src = self._file("plain.txt", 0o640)
        self._run(src, dest_fs=_NoMetadataFS())
        self.assertEqual((self.out / "plain.txt").read_bytes(), b"data")

    def test_edge_an_unknown_source_mode_keeps_the_default(self) -> None:
        src = self._file("u.txt", 0o600)
        fs = LocalFS()
        job = TW.TransferJob(source_path=str(src), dest_path=str(self.out / "u.txt"),
                             total_bytes=4, filename="u.txt", source_backend=fs,
                             dest_backend=fs)
        TW.TransferWorker()._process_job(job)
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual(_mode(self.out / "u.txt"), 0o644)


class ManagerAndSyncTest(_Base):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def _wait(self, jobs) -> None:
        deadline = time.monotonic() + 20
        while any(j.status in (TW.TransferStatus.PENDING, TW.TransferStatus.ACTIVE)
                  for j in jobs):
            self.app.processEvents()
            if time.monotonic() > deadline:
                self.fail("transfer did not finish")
            time.sleep(0.01)

    def test_happy_a_synced_file_compares_equal_without_hashing(self) -> None:
        from core.transfer_manager import TransferManager
        from core.tree_compare import Status, compare_trees

        left, right = self.tmp / "L", self.tmp / "R"
        (left / "sub").mkdir(parents=True)
        right.mkdir()
        big = left / "sub" / "video.mp4"
        big.write_bytes(os.urandom(64 * 1024))
        os.utime(big, (OLD, OLD))
        (left / "sub" / "key").write_bytes(b"k")
        os.chmod(left / "sub" / "key", 0o600)
        mgr = TransferManager()
        self.addCleanup(mgr.shutdown)
        jobs = mgr.transfer_files(LocalFS(), LocalFS(), [str(left / "sub")], str(right))
        self._wait(jobs)
        entries = compare_trees(LocalFS(), str(left), LocalFS(), str(right), hash_limit=0)
        self.assertEqual({e.rel_path: e.status for e in entries}["sub/video.mp4"], Status.SAME)
        self.assertEqual(_mode(right / "sub" / "key"), 0o600)


if __name__ == "__main__":
    unittest.main()
