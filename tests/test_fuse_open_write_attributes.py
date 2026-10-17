"""getattr answers from the open write session, not from the backend.

Measured before: ``getattr`` asked only the stat cache and the backend.
A file created on a buffer-mode mount exists nowhere but in its write
session until the first commit, so libfuse's fgetattr right after
create() got ENOENT and ``echo > new.txt`` failed. A file opened with
O_APPEND lost data the same way: once the kernel's attribute cache
expired, getattr reported the backend's pre-commit size, the kernel took
it as the new end of file and the next append overwrote the bytes
written before.
"""

from __future__ import annotations

import errno
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _Base(unittest.TestCase):
    write_mode = "buffer"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = LocalFS()
        # ttl_stat=0: every getattr goes past the cache, the way it does
        # once the 30 s default expired.
        self.fuse = FM.BackendFuseFS(
            self.fs,
            str(self.tmp),
            writeable=True,
            write_mode=self.write_mode,
            ttl_stat=0,
        )
        (self.tmp / "log.txt").write_bytes(b"old\n")


class BufferSessionAttributesTest(_Base):
    def test_happy_a_created_file_has_attributes_before_its_first_commit(self) -> None:
        fh = self.fuse.create("/new.txt", 0o644)
        attrs = self.fuse.getattr("/new.txt", fh)
        self.assertTrue(stat.S_ISREG(attrs["st_mode"]))
        self.assertEqual(attrs["st_size"], 0)
        self.fuse.release("/new.txt", fh)

    def test_happy_the_size_follows_the_writes_without_a_handle(self) -> None:
        fh = self.fuse.create("/new.txt", 0o644)
        self.fuse.write("/new.txt", b"hello", 0, fh)
        self.assertEqual(self.fuse.getattr("/new.txt")["st_size"], 5)
        self.fuse.release("/new.txt", fh)
        self.assertEqual(self.fuse.getattr("/new.txt")["st_size"], 5)

    def test_happy_an_append_session_reports_the_grown_size(self) -> None:
        fh = self.fuse.open("/log.txt", os.O_WRONLY | os.O_APPEND)
        self.fuse.write("/log.txt", b"AAAA", 4, fh)
        # The backend still has 4 bytes; the kernel must see 8.
        self.assertEqual((self.tmp / "log.txt").stat().st_size, 4)
        self.assertEqual(self.fuse.getattr("/log.txt")["st_size"], 8)
        self.assertEqual(self.fuse.getattr("/log.txt", fh)["st_size"], 8)
        self.fuse.write("/log.txt", b"BBBB", 8, fh)
        self.fuse.flush("/log.txt", fh)
        self.fuse.release("/log.txt", fh)
        self.assertEqual((self.tmp / "log.txt").read_bytes(), b"old\nAAAABBBB")

    def test_happy_a_read_handle_sees_the_writer_size(self) -> None:
        wfh = self.fuse.open("/log.txt", os.O_WRONLY | os.O_APPEND)
        rfh = self.fuse.open("/log.txt", os.O_RDONLY)
        self.fuse.write("/log.txt", b"AAAA", 4, wfh)
        self.assertEqual(self.fuse.getattr("/log.txt", rfh)["st_size"], 8)
        self.fuse.release("/log.txt", rfh)
        self.fuse.release("/log.txt", wfh)

    def test_sad_a_missing_file_without_a_session_is_still_enoent(self) -> None:
        with self.assertRaises(FM.FuseOSError) as ctx:
            self.fuse.getattr("/nope.txt")
        self.assertEqual(ctx.exception.errno, errno.ENOENT)

    def test_sad_a_released_uncommitted_file_is_gone_again(self) -> None:
        class _NoCommit(LocalFS):
            def rename(self, src, dst):
                raise OSError(errno.ENOSPC, "no space", dst)

            def open_write(self, path, append=False):
                raise OSError(errno.ENOSPC, "no space", path)

        fuse = FM.BackendFuseFS(_NoCommit(), str(self.tmp), writeable=True, ttl_stat=0)
        fh = fuse.create("/lost.txt", 0o644)
        fuse.write("/lost.txt", b"data", 0, fh)
        self.assertEqual(fuse.getattr("/lost.txt")["st_size"], 4)
        with self.assertRaises(FM.FuseOSError):
            fuse.flush("/lost.txt", fh)
        fuse.release("/lost.txt", fh)
        with self.assertRaises(FM.FuseOSError) as ctx:
            fuse.getattr("/lost.txt")
        self.assertEqual(ctx.exception.errno, errno.ENOENT)

    def test_edge_truncate_through_the_handle_shrinks_the_size(self) -> None:
        fh = self.fuse.open("/log.txt", os.O_RDWR)
        self.fuse.truncate("/log.txt", 1, fh)
        self.assertEqual(self.fuse.getattr("/log.txt", fh)["st_size"], 1)
        self.fuse.release("/log.txt", fh)

    def test_edge_the_handle_passed_in_wins_over_another_session(self) -> None:
        first = self.fuse.open("/log.txt", os.O_RDWR)
        second = self.fuse.open("/log.txt", os.O_RDWR)
        self.fuse.write("/log.txt", b"0123456789", 0, first)
        self.assertEqual(self.fuse.getattr("/log.txt", first)["st_size"], 10)
        self.assertEqual(self.fuse.getattr("/log.txt", second)["st_size"], 4)
        self.fuse.release("/log.txt", second)
        self.fuse.release("/log.txt", first)

    def test_edge_a_session_on_another_path_does_not_leak(self) -> None:
        fh = self.fuse.create("/other.txt", 0o644)
        self.fuse.write("/other.txt", b"x" * 100, 0, fh)
        self.assertEqual(self.fuse.getattr("/log.txt")["st_size"], 4)
        self.fuse.release("/other.txt", fh)

    def test_edge_session_answers_are_not_cached(self) -> None:
        fuse = FM.BackendFuseFS(self.fs, str(self.tmp), writeable=True)  # 30 s TTL
        fh = fuse.open("/log.txt", os.O_RDWR)
        fuse.write("/log.txt", b"0123456789", 0, fh)
        self.assertEqual(fuse.getattr("/log.txt")["st_size"], 10)
        fuse.release("/log.txt", fh)
        (self.tmp / "log.txt").write_bytes(b"xy")
        fuse._stat.invalidate_all()
        self.assertEqual(fuse.getattr("/log.txt")["st_size"], 2)


class StreamSessionAttributesTest(_Base):
    write_mode = "stream"

    def test_happy_a_streamed_file_reports_the_bytes_sent(self) -> None:
        fh = self.fuse.create("/out.bin", 0o644)
        self.fuse.write("/out.bin", b"abc", 0, fh)
        attrs = self.fuse.getattr("/out.bin", fh)
        self.assertTrue(stat.S_ISREG(attrs["st_mode"]))
        self.assertEqual(attrs["st_size"], 3)
        self.fuse.release("/out.bin", fh)

    def test_edge_the_size_survives_a_flush_between_writes(self) -> None:
        fh = self.fuse.create("/out.bin", 0o644)
        self.fuse.write("/out.bin", b"abc", 0, fh)
        self.fuse.flush("/out.bin", fh)
        self.assertEqual(self.fuse.getattr("/out.bin")["st_size"], 3)
        self.fuse.release("/out.bin", fh)


if __name__ == "__main__":
    unittest.main()
