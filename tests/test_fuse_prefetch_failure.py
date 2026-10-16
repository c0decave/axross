"""A failed pre-fetch never turns into an overwrite of the existing file.

Measured before: opening an existing file for writing without O_TRUNC
pre-fetched its content into the write buffer. When that read failed (a
dropped connection, a permission hiccup) the open went ahead with an EMPTY
buffer marked dirty, and close committed it -- the file was wiped even if
nothing was written. ``truncate(path, n)`` without a handle did the same
with n zero bytes ("flushing a buffer from what we could read").
"""

from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _FlakyReadFS(LocalFS):
    """open_read fails (or fails mid-stream) while ``broken`` is set."""

    def __init__(self) -> None:
        super().__init__()
        self.broken = False
        self.fail_after_first_chunk = False

    def open_read(self, path):
        if self.broken:
            raise OSError("connection reset by peer")
        fh = super().open_read(path)
        if not self.fail_after_first_chunk:
            return fh
        state = {"reads": 0}

        class _H:
            def read(self, n=-1):
                state["reads"] += 1
                if state["reads"] > 1:
                    raise OSError("connection reset by peer")
                return fh.read(n)

            def close(self):
                fh.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                fh.close()

        return _H()


class PrefetchFailureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = _FlakyReadFS()
        self.fuse = FM.BackendFuseFS(self.fs, str(self.tmp), writeable=True)
        self.file = self.tmp / "notes.txt"
        self.content = b"line\n" * 40_000  # 200 000 bytes, several chunks
        self.file.write_bytes(self.content)

    def test_happy_an_edit_keeps_the_rest_of_the_file(self) -> None:
        fh = self.fuse.open("/notes.txt", os.O_RDWR)
        self.fuse.write("/notes.txt", b"LINE", 0, fh)
        self.fuse.release("/notes.txt", fh)
        self.assertEqual(self.file.read_bytes(), b"LINE" + self.content[4:])

    def test_sad_a_failed_prefetch_refuses_the_open(self) -> None:
        self.fs.broken = True
        with self.assertRaises(FM.FuseOSError) as ctx:
            self.fuse.open("/notes.txt", os.O_RDWR)
        self.assertEqual(ctx.exception.errno, errno.EIO)
        self.assertEqual(self.file.read_bytes(), self.content)

    def test_sad_a_prefetch_cut_off_midway_refuses_the_open(self) -> None:
        self.fs.fail_after_first_chunk = True
        with self.assertRaises(FM.FuseOSError):
            self.fuse.open("/notes.txt", os.O_WRONLY)
        self.assertEqual(self.file.read_bytes(), self.content)
        self.assertEqual(self.fuse._writes, {})

    def test_sad_a_path_truncate_with_a_failed_prefetch_keeps_the_file(self) -> None:
        self.fs.broken = True
        with self.assertRaises(FM.FuseOSError):
            self.fuse.truncate("/notes.txt", 100)
        self.assertEqual(self.file.read_bytes(), self.content)

    def test_edge_a_missing_file_still_opens_empty_for_writing(self) -> None:
        fh = self.fuse.open("/new.txt", os.O_WRONLY)
        self.fuse.write("/new.txt", b"fresh", 0, fh)
        self.fuse.release("/new.txt", fh)
        self.assertEqual((self.tmp / "new.txt").read_bytes(), b"fresh")

    def test_edge_truncate_to_zero_needs_no_prefetch(self) -> None:
        self.fs.broken = True
        self.fuse.truncate("/notes.txt", 0)
        self.assertEqual(self.file.read_bytes(), b"")

    def test_edge_a_path_truncate_shortens_with_a_working_backend(self) -> None:
        self.fuse.truncate("/notes.txt", 10)
        self.assertEqual(self.file.read_bytes(), self.content[:10])


if __name__ == "__main__":
    unittest.main()
