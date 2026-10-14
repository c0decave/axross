"""resumable_copy reads the source once, front to back.

Measured before: the source was opened again for every segment and read
up to the segment's offset (seek or drain), so a backend that downloads on
open moved a 64 MiB file 16 times (1 GiB) with 4 MiB segments.
"""

from __future__ import annotations

import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import copy_resume as CR  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _CountingFS(LocalFS):
    def __init__(self) -> None:
        super().__init__()
        self.opens = 0
        self.bytes_read = 0

    def open_read(self, path):
        self.opens += 1
        fh = super().open_read(path)
        counter = self

        class _H:
            def read(self, n=-1):
                data = fh.read(n)
                counter.bytes_read += len(data)
                return data

            def seek(self, *a):
                return fh.seek(*a)

            def close(self):
                fh.close()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                fh.close()

        return _H()


class _NoSeekFS(_CountingFS):
    """A stream that cannot seek (drain fallback)."""

    def open_read(self, path):
        h = super().open_read(path)
        del type(h).seek
        return h


class SourceReadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.payload = random.Random(3).randbytes(10 * CR.MIN_SEGMENT_SIZE + 123)
        (self.tmp / "src.bin").write_bytes(self.payload)
        self.manifest = self.tmp / "m.json"

    def copy(self, src_fs):
        return CR.resumable_copy(
            src_fs,
            str(self.tmp / "src.bin"),
            LocalFS(),
            str(self.tmp / "dst.bin"),
            segment_size=CR.MIN_SEGMENT_SIZE,
            manifest_path=self.manifest,
        )

    def test_happy_one_open_and_each_byte_read_once(self) -> None:
        fs = _CountingFS()
        rep = self.copy(fs)
        self.assertTrue(rep.completed)
        self.assertEqual((self.tmp / "dst.bin").read_bytes(), self.payload)
        self.assertEqual(fs.opens, 1)
        self.assertEqual(fs.bytes_read, len(self.payload))

    def test_sad_a_stream_without_seek_still_copies_correctly(self) -> None:
        fs = _NoSeekFS()
        rep = self.copy(fs)
        self.assertTrue(rep.completed)
        self.assertEqual((self.tmp / "dst.bin").read_bytes(), self.payload)
        self.assertEqual(fs.bytes_read, len(self.payload))

    def test_edge_an_interrupted_copy_resumes_after_its_done_prefix(self) -> None:
        seg = CR.MIN_SEGMENT_SIZE

        class _Failing(_CountingFS):
            def open_read(self, path):
                h = super().open_read(path)
                outer = self
                inner_read = h.read

                def read(n=-1):
                    if outer.bytes_read >= 3 * seg:
                        raise OSError("link dropped")
                    return inner_read(n)

                h.read = read
                return h

        with self.assertRaises(OSError):
            self.copy(_Failing())
        fs = _CountingFS()
        rep = self.copy(fs)
        self.assertTrue(rep.completed)
        self.assertEqual(rep.segments_skipped, 3)
        self.assertEqual((self.tmp / "dst.bin").read_bytes(), self.payload)


if __name__ == "__main__":
    unittest.main()
