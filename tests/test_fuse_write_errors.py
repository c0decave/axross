"""A failed commit on a writeable FUSE mount reaches the writer's close().

Measured before: the buffered content was committed to the backend only in
``release()``, whose return value the kernel discards, while ``flush()`` --
the callback that close(2) waits for -- returned 0. A full disk, a quota or
a dropped connection during the commit therefore left the writing program
with a successful close() and the old content on the backend. Stream mode
had the same gap: the backend handle was closed (= committed) in release().

Now flush() and fsync() commit and report a failure as EIO; release() only
commits what no flush saw (writes that arrive after the last close, such as
mmap write-back) and cleans up.
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


class _FullDiskFS(LocalFS):
    """Every commit fails with ENOSPC while ``full`` is set.

    The buffer-mode commit goes through ``atomic_write_stream`` (temp file
    plus rename); the stream-mode commit is the close of the open_write
    handle. Both fail here, the way a full remote disk fails them.
    """

    def __init__(self) -> None:
        super().__init__()
        self.full = False
        self.renames = 0
        self.writes_opened = 0

    def rename(self, src, dst):
        self.renames += 1
        if self.full:
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), dst)
        return super().rename(src, dst)

    def open_write(self, path, append=False):
        self.writes_opened += 1
        fh = super().open_write(path, append=append)
        owner = self

        class _Handle:
            def write(self, data):
                return fh.write(data)

            def close(self):
                fh.close()
                if owner.full:
                    raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), path)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

        return _Handle()


class _Base(unittest.TestCase):
    write_mode = "buffer"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = _FullDiskFS()
        self.fuse = FM.BackendFuseFS(
            self.fs,
            str(self.tmp),
            writeable=True,
            write_mode=self.write_mode,
        )
        self.file = self.tmp / "doc.txt"
        self.file.write_bytes(b"version 1\n")

    def _tempfiles(self) -> list[str]:
        return [
            s.tmp.name for s in self.fuse._writes.values() if s.tmp is not None
        ]


class BufferModeFlushTest(_Base):
    def test_happy_flush_commits_the_edit(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.write("/doc.txt", b"version 2\n", 0, fh)
        self.assertEqual(self.fuse.flush("/doc.txt", fh), 0)
        self.assertEqual(self.file.read_bytes(), b"version 2\n")
        self.fuse.release("/doc.txt", fh)
        self.assertEqual(self.file.read_bytes(), b"version 2\n")

    def test_happy_release_does_not_commit_a_flushed_buffer_again(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.write("/doc.txt", b"version 2\n", 0, fh)
        self.fuse.flush("/doc.txt", fh)
        renames_after_flush = self.fs.renames
        self.fuse.release("/doc.txt", fh)
        self.assertEqual(self.fs.renames, renames_after_flush)

    def test_sad_a_failed_commit_fails_flush_with_eio(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.write("/doc.txt", b"version 2\n", 0, fh)
        self.fs.full = True
        with self.assertRaises(FM.FuseOSError) as ctx:
            self.fuse.flush("/doc.txt", fh)
        self.assertEqual(ctx.exception.errno, errno.EIO)
        self.assertEqual(self.file.read_bytes(), b"version 1\n")

    def test_sad_a_failed_commit_fails_fsync_with_eio(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.write("/doc.txt", b"version 2\n", 0, fh)
        self.fs.full = True
        with self.assertRaises(FM.FuseOSError) as ctx:
            self.fuse.fsync("/doc.txt", 0, fh)
        self.assertEqual(ctx.exception.errno, errno.EIO)

    def test_happy_fsync_commits(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.write("/doc.txt", b"version 3\n", 0, fh)
        self.assertEqual(self.fuse.fsync("/doc.txt", 1, fh), 0)
        self.assertEqual(self.file.read_bytes(), b"version 3\n")

    def test_sad_release_after_a_failed_flush_cleans_up_without_raising(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.write("/doc.txt", b"version 2\n", 0, fh)
        tmp_name = self._tempfiles()[0]
        self.fs.full = True
        with self.assertRaises(FM.FuseOSError):
            self.fuse.flush("/doc.txt", fh)
        self.assertEqual(self.fuse.release("/doc.txt", fh), 0)
        self.assertFalse(os.path.exists(tmp_name))
        self.assertEqual(self.fuse._writes, {})

    def test_edge_a_retried_flush_commits_once_the_disk_has_room(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.write("/doc.txt", b"version 2\n", 0, fh)
        self.fs.full = True
        with self.assertRaises(FM.FuseOSError):
            self.fuse.flush("/doc.txt", fh)
        self.fs.full = False
        self.assertEqual(self.fuse.flush("/doc.txt", fh), 0)
        self.assertEqual(self.file.read_bytes(), b"version 2\n")
        self.fuse.release("/doc.txt", fh)

    def test_edge_writes_after_a_flush_are_committed_by_the_next_flush(self) -> None:
        # A shell's "(cmd1; cmd2) > file": cmd1 exits (flush), cmd2 writes on.
        fh = self.fuse.create("/new.txt", 0o644)
        self.fuse.write("/new.txt", b"first\n", 0, fh)
        self.fuse.flush("/new.txt", fh)
        self.assertEqual((self.tmp / "new.txt").read_bytes(), b"first\n")
        self.fuse.write("/new.txt", b"second\n", 6, fh)
        self.fuse.flush("/new.txt", fh)
        self.fuse.release("/new.txt", fh)
        self.assertEqual((self.tmp / "new.txt").read_bytes(), b"first\nsecond\n")

    def test_edge_writes_after_the_last_flush_are_committed_on_release(self) -> None:
        # mmap write-back can reach the file system after close().
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.fuse.flush("/doc.txt", fh)
        self.fuse.write("/doc.txt", b"VERSION", 0, fh)
        self.fuse.release("/doc.txt", fh)
        self.assertEqual(self.file.read_bytes(), b"VERSION 1\n")

    def test_edge_flush_of_a_clean_session_does_not_touch_the_backend(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDWR)
        self.assertEqual(self.fuse.flush("/doc.txt", fh), 0)
        self.fuse.release("/doc.txt", fh)
        self.assertEqual(self.fs.renames, 0)
        self.assertEqual(self.fs.writes_opened, 0)

    def test_edge_flush_of_a_read_handle_or_unknown_fh_is_a_no_op(self) -> None:
        fh = self.fuse.open("/doc.txt", os.O_RDONLY)
        self.fs.full = True
        self.assertEqual(self.fuse.flush("/doc.txt", fh), 0)
        self.assertEqual(self.fuse.fsync("/doc.txt", 0, fh), 0)
        self.assertEqual(self.fuse.flush("/doc.txt", 424242), 0)
        self.fuse.release("/doc.txt", fh)


class StreamModeFlushTest(_Base):
    write_mode = "stream"

    def test_happy_flush_commits_the_stream(self) -> None:
        fh = self.fuse.create("/out.bin", 0o644)
        self.fuse.write("/out.bin", b"abc", 0, fh)
        self.assertEqual(self.fuse.flush("/out.bin", fh), 0)
        self.assertEqual((self.tmp / "out.bin").read_bytes(), b"abc")
        self.assertEqual(self.fuse.release("/out.bin", fh), 0)
        self.assertEqual((self.tmp / "out.bin").read_bytes(), b"abc")

    def test_sad_a_failed_close_of_the_stream_fails_flush_with_eio(self) -> None:
        fh = self.fuse.create("/out.bin", 0o644)
        self.fuse.write("/out.bin", b"abc", 0, fh)
        self.fs.full = True
        with self.assertRaises(FM.FuseOSError) as ctx:
            self.fuse.flush("/out.bin", fh)
        self.assertEqual(ctx.exception.errno, errno.EIO)
        self.assertEqual(self.fuse.release("/out.bin", fh), 0)
        self.assertEqual(self.fuse._writes, {})

    def test_sad_an_errored_stream_fails_flush_with_eio(self) -> None:
        fh = self.fuse.create("/out.bin", 0o644)
        with self.assertRaises(FM.FuseOSError):
            self.fuse.write("/out.bin", b"abc", 10, fh)  # not sequential
        with self.assertRaises(FM.FuseOSError) as ctx:
            self.fuse.flush("/out.bin", fh)
        self.assertEqual(ctx.exception.errno, errno.EIO)
        self.fuse.release("/out.bin", fh)

    def test_edge_writes_after_a_flush_continue_the_file(self) -> None:
        # bash opens, dup2()s and closes the original fd (flush) before
        # the first write; a forked child's exit flushes between writes.
        fh = self.fuse.create("/out.bin", 0o644)
        self.fuse.flush("/out.bin", fh)
        self.fuse.write("/out.bin", b"abc", 0, fh)
        self.fuse.flush("/out.bin", fh)
        self.fuse.write("/out.bin", b"def", 3, fh)
        self.fuse.flush("/out.bin", fh)
        self.fuse.release("/out.bin", fh)
        self.assertEqual((self.tmp / "out.bin").read_bytes(), b"abcdef")

    def test_edge_a_stream_without_any_flush_is_committed_on_release(self) -> None:
        fh = self.fuse.create("/out.bin", 0o644)
        self.fuse.write("/out.bin", b"xyz", 0, fh)
        self.fuse.release("/out.bin", fh)
        self.assertEqual((self.tmp / "out.bin").read_bytes(), b"xyz")


if __name__ == "__main__":
    unittest.main()
