"""resumable_copy reports a copy complete only when the destination committed.

Measured before: the destination handle was closed in a ``finally`` that
swallowed every exception. Backends that buffer and upload on close (FTP,
WebDAV, S3, SCP ...) report a failed upload exactly there, so the copy
returned ``completed=True`` and deleted its resume manifest although the
destination was never written.
"""

from __future__ import annotations

import os
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import copy_resume as CR  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

SEGMENT = CR.MIN_SEGMENT_SIZE


class _CommitOnCloseFS(LocalFS):
    """Buffers writes and commits them at close; ``fail_commit`` makes the
    commit raise the way a refused upload does."""

    def __init__(self, fail_commit: bool) -> None:
        super().__init__()
        self.fail_commit = fail_commit

    def open_write(self, path, append=False):
        fs = self
        existing = Path(path).read_bytes() if append and os.path.exists(path) else b""

        class _Writer:
            def __init__(self) -> None:
                self.buf = bytearray(existing)

            def write(self, data):
                self.buf += data
                return len(data)

            def close(self):
                if fs.fail_commit:
                    raise OSError("550 upload refused")
                Path(path).write_bytes(bytes(self.buf))

        return _Writer()


class _ShortSourceFS(LocalFS):
    def open_read(self, path):
        fh = super().open_read(path)

        class _Short:
            def read(self, n=-1):
                return fh.read(n)[:10]

            def seek(self, *a):
                return fh.seek(*a)

            def close(self):
                fh.close()

        return _Short()


class CommitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.data = random.Random(5).randbytes(3 * SEGMENT + 123)
        self.src = self.tmp / "src.bin"
        self.src.write_bytes(self.data)
        self.dst = self.tmp / "dst.bin"
        self.manifest = self.tmp / "resume.json"

    def copy(self, dst_fs, src_fs=None):
        return CR.resumable_copy(
            src_fs or LocalFS(),
            str(self.src),
            dst_fs,
            str(self.dst),
            segment_size=SEGMENT,
            manifest_path=self.manifest,
        )

    def test_happy_a_committed_copy_is_complete(self) -> None:
        report = self.copy(_CommitOnCloseFS(fail_commit=False))
        self.assertTrue(report.completed)
        self.assertEqual(self.dst.read_bytes(), self.data)
        self.assertFalse(self.manifest.exists())

    def test_sad_a_refused_commit_raises_and_keeps_the_manifest(self) -> None:
        with self.assertRaises(OSError) as ctx:
            self.copy(_CommitOnCloseFS(fail_commit=True))
        self.assertIn("550 upload refused", str(ctx.exception))
        self.assertFalse(self.dst.exists())
        self.assertTrue(self.manifest.exists())

    def test_edge_a_rerun_after_a_refused_commit_copies_everything(self) -> None:
        with self.assertRaises(OSError):
            self.copy(_CommitOnCloseFS(fail_commit=True))
        report = self.copy(_CommitOnCloseFS(fail_commit=False))
        self.assertTrue(report.completed)
        self.assertEqual(self.dst.read_bytes(), self.data)

    def test_edge_a_read_error_is_not_masked_by_the_close(self) -> None:
        """On the error path the close stays best-effort: the short read is
        what the caller has to see, not the follow-up commit failure."""
        with self.assertRaises(OSError) as ctx:
            self.copy(_CommitOnCloseFS(fail_commit=True), src_fs=_ShortSourceFS())
        self.assertIn("short read", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
