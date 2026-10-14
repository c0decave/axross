"""FUSE reads keep one backend handle per open file.

Measured before: every kernel read() (typically 128 KiB) opened the
file on the backend, seeked, read and closed it again. On a handle
without seek() it read and discarded everything up to the offset each
time, so ``cat`` of a 128 MiB file moved ~64 GiB. Now a read-only open
gets its own fh; sequential reads continue on the same handle, other
offsets seek, and anything unexpected falls back to the old one-open-
per-read path.
"""

from __future__ import annotations

import errno
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

KIB = 1024


class _CountingFS(LocalFS):
    def __init__(self, seekable: bool = True) -> None:
        super().__init__()
        self.opens = 0
        self.closes = 0
        self.bytes_read = 0
        self.seekable = seekable
        self.fail_reads = 0

    def open_read(self, path):
        fh = super().open_read(path)
        self.opens += 1  # successful opens only: each must be closed
        fs = self

        class _H:
            def read(self, n=-1):
                if fs.fail_reads:
                    fs.fail_reads -= 1
                    raise OSError("transient")
                data = fh.read(n)
                fs.bytes_read += len(data)
                return data

            def close(self):
                fs.closes += 1
                fh.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

        if self.seekable:
            _H.seek = lambda self, *a: fh.seek(*a)
        return _H()


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.data = random.Random(4).randbytes(1024 * KIB + 77)
        (self.tmp / "f.bin").write_bytes(self.data)

    def fs(self, backend, **kw):
        return FM.BackendFuseFS(backend, str(self.tmp), **kw)

    def read_all(self, fuse, fh, step=128 * KIB) -> bytes:
        out = bytearray()
        while True:
            chunk = fuse.read("/f.bin", step, len(out), fh)
            if not chunk:
                return bytes(out)
            out += chunk


class ReadHandleTest(_Base):
    def test_happy_sequential_read_opens_once(self) -> None:
        be = _CountingFS()
        fuse = self.fs(be)
        fh = fuse.open("/f.bin", 0)
        self.assertEqual(self.read_all(fuse, fh), self.data)
        self.assertEqual(be.opens, 1)
        fuse.release("/f.bin", fh)
        self.assertEqual(be.closes, 1)

    def test_happy_random_offsets_seek_on_the_same_handle(self) -> None:
        be = _CountingFS()
        fuse = self.fs(be)
        fh = fuse.open("/f.bin", 0)
        rng = random.Random(1)
        for _ in range(50):
            off, size = rng.randint(0, len(self.data) + 10), rng.randint(0, 200 * KIB)
            self.assertEqual(fuse.read("/f.bin", size, off, fh), self.data[off : off + size])
        self.assertEqual(be.opens, 1)
        fuse.release("/f.bin", fh)

    def test_happy_no_seek_sequential_read_discards_nothing(self) -> None:
        be = _CountingFS(seekable=False)
        fuse = self.fs(be)
        fh = fuse.open("/f.bin", 0)
        self.assertEqual(self.read_all(fuse, fh), self.data)
        self.assertEqual((be.opens, be.bytes_read), (1, len(self.data)))
        fuse.release("/f.bin", fh)

    def test_sad_no_seek_backward_read_reopens_and_is_correct(self) -> None:
        be = _CountingFS(seekable=False)
        fuse = self.fs(be)
        fh = fuse.open("/f.bin", 0)
        self.assertEqual(fuse.read("/f.bin", 100, 5000, fh), self.data[5000:5100])
        self.assertEqual(fuse.read("/f.bin", 100, 10, fh), self.data[10:110])
        self.assertEqual(be.opens, 2)
        self.assertEqual(be.closes, 1)  # the first handle was closed on reopen
        fuse.release("/f.bin", fh)
        self.assertEqual(be.closes, 2)

    def test_sad_missing_file_is_eio(self) -> None:
        fuse = self.fs(_CountingFS())
        fh = fuse.open("/nope.bin", 0)
        with self.assertRaises(FM.FuseOSError) as cm:
            fuse.read("/nope.bin", 10, 0, fh)
        self.assertEqual(cm.exception.errno, errno.EIO)
        fuse.release("/nope.bin", fh)

    def test_sad_a_failing_handle_read_falls_back_to_a_fresh_open(self) -> None:
        be = _CountingFS()
        fuse = self.fs(be)
        fh = fuse.open("/f.bin", 0)
        self.assertEqual(fuse.read("/f.bin", 10, 0, fh), self.data[:10])
        be.fail_reads = 1
        self.assertEqual(fuse.read("/f.bin", 10, 10, fh), self.data[10:20])
        self.assertEqual(fuse.read("/f.bin", 10, 20, fh), self.data[20:30])
        fuse.release("/f.bin", fh)
        self.assertEqual(be.opens, be.closes)

    def test_edge_no_seek_offset_past_the_discard_cap_is_eio(self) -> None:
        be = _CountingFS(seekable=False)
        fuse = self.fs(be)
        fh = fuse.open("/f.bin", 0)
        with mock.patch.object(FM, "MAX_FALLBACK_DISCARD", 1000):
            with self.assertRaises(FM.FuseOSError) as cm:
                fuse.read("/f.bin", 10, 2000, fh)
        self.assertEqual(cm.exception.errno, errno.EIO)
        fuse.release("/f.bin", fh)

    def test_sad_a_read_failing_after_a_good_seek_is_eio_not_wrong_bytes(self) -> None:
        # Before: the error was swallowed and the discard fallback ran on
        # the already-seeked handle, returning the bytes at 2 * offset.
        be = _CountingFS()
        be.fail_reads = 1
        fuse = self.fs(be)
        with self.assertRaises(FM.FuseOSError) as cm:
            fuse.read("/f.bin", 10, 1000, 0)
        self.assertEqual(cm.exception.errno, errno.EIO)
        self.assertEqual(be.opens, be.closes)

    def test_edge_reads_without_an_open_fh_still_work(self) -> None:
        be = _CountingFS()
        fuse = self.fs(be)
        self.assertEqual(fuse.read("/f.bin", 100, 50, 0), self.data[50:150])
        self.assertEqual(be.opens, be.closes)

    def test_edge_a_commit_through_another_fh_is_seen_by_open_readers(self) -> None:
        be = _CountingFS()
        fuse = self.fs(be, writeable=True)
        rfh = fuse.open("/f.bin", 0)
        self.assertEqual(fuse.read("/f.bin", 4, 0, rfh), self.data[:4])
        wfh = fuse.open("/f.bin", FM.os.O_WRONLY | FM.os.O_TRUNC)
        fuse.write("/f.bin", b"new content", 0, wfh)
        fuse.release("/f.bin", wfh)
        self.assertEqual(fuse.read("/f.bin", 7, 4, rfh), b"content")
        fuse.release("/f.bin", rfh)
        self.assertEqual(be.opens, be.closes)

    def test_edge_unlink_and_replace_by_rename_are_seen_like_before(self) -> None:
        be = _CountingFS()
        fuse = self.fs(be, writeable=True)
        (self.tmp / "g.bin").write_bytes(b"replacement")
        rfh = fuse.open("/f.bin", 0)
        self.assertEqual(fuse.read("/f.bin", 3, 0, rfh), self.data[:3])
        fuse.unlink("/f.bin")
        with self.assertRaises(FM.FuseOSError):
            fuse.read("/f.bin", 3, 3, rfh)
        fuse.rename("/g.bin", "/f.bin")
        self.assertEqual(fuse.read("/f.bin", 4, 3, rfh), b"lace")
        fuse.truncate("/f.bin", 2)
        self.assertEqual(fuse.read("/f.bin", 10, 0, rfh), b"re")
        fuse.release("/f.bin", rfh)
        self.assertEqual(be.opens, be.closes)

    def test_edge_read_fh_and_write_fh_never_collide(self) -> None:
        fuse = self.fs(_CountingFS(), writeable=True)
        r1 = fuse.open("/f.bin", 0)
        w1 = fuse.open("/f.bin", FM.os.O_WRONLY | FM.os.O_TRUNC)
        r2 = fuse.open("/f.bin", 0)
        self.assertEqual(len({r1, w1, r2}), 3)
        self.assertNotIn(r1, fuse._writes)
        for fh in (r2, w1, r1):
            fuse.release("/f.bin", fh)


if __name__ == "__main__":
    unittest.main()
