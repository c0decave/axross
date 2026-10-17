"""The RamFS size cap bounds what open writers buffer, not only commits.

Measured before: ``_RamFsWriter.write`` checked only the growth of the
chunk at hand against the COMMITTED size. The bytes the same writer had
already buffered never counted, so a 10 MiB RamFS buffered 64 MiB in RAM
and refused only at close() -- the cap that exists to keep RAM bounded
did not bound it. Two writers could do the same together.

Now every open writer reserves its growth in the session: a write that
would take committed plus reserved bytes past ``max_bytes`` is refused,
and closing or discarding a writer releases its reservation.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ram_fs  # noqa: E402
from core.ram_fs import RamFsCapacityError, RamFsSession  # noqa: E402

CAP = 1000


def _fs() -> RamFsSession:
    return RamFsSession(label="cap", max_bytes=CAP, system_reserve_bytes=0)


class WriterCapTest(unittest.TestCase):
    def test_happy_writing_up_to_the_cap_commits(self) -> None:
        fs = _fs()
        with fs.open_write("/a.bin") as w:
            for _ in range(10):
                w.write(b"x" * 100)
        self.assertEqual(fs.size_bytes, CAP)
        self.assertEqual(fs._reserved_bytes, 0)

    def test_sad_one_writer_cannot_buffer_past_the_cap(self) -> None:
        fs = _fs()
        w = fs.open_write("/big.bin")
        for _ in range(10):
            w.write(b"x" * 100)
        with self.assertRaises(RamFsCapacityError):
            w.write(b"x")
        self.assertEqual(w._buffered_size, CAP)
        w.discard()
        self.assertEqual(fs.size_bytes, 0)
        self.assertFalse(fs.exists("/big.bin"))

    def test_sad_two_writers_together_cannot_pass_the_cap(self) -> None:
        fs = _fs()
        first = fs.open_write("/one.bin")
        second = fs.open_write("/two.bin")
        first.write(b"x" * 600)
        with self.assertRaises(RamFsCapacityError):
            second.write(b"y" * 600)
        second.write(b"y" * 400)
        first.close()
        second.close()
        self.assertEqual(fs.size_bytes, CAP)

    def test_sad_committed_bytes_count_against_a_new_writer(self) -> None:
        fs = _fs()
        with fs.open_write("/full.bin") as w:
            w.write(b"x" * 900)
        w2 = fs.open_write("/more.bin")
        with self.assertRaises(RamFsCapacityError):
            w2.write(b"y" * 101)
        w2.discard()

    def test_edge_discard_and_close_release_the_reservation(self) -> None:
        fs = _fs()
        w = fs.open_write("/tmp.bin")
        w.write(b"x" * 800)
        w.discard()
        self.assertEqual(fs._reserved_bytes, 0)
        with fs.open_write("/real.bin") as w2:
            w2.write(b"y" * 1000)
        self.assertEqual(fs._reserved_bytes, 0)

    def test_edge_a_dropped_writer_releases_the_reservation(self) -> None:
        import gc

        fs = _fs()
        w = fs.open_write("/lost.bin")
        w.write(b"x" * 700)
        self.assertEqual(fs._reserved_bytes, 700)
        del w
        gc.collect()
        self.assertEqual(fs._reserved_bytes, 0)
        self.assertFalse(fs.exists("/lost.bin"))

    def test_edge_a_failed_commit_releases_the_reservation(self) -> None:
        fs = _fs()
        w = fs.open_write("/dir/file.bin")
        w.write(b"x" * 500)
        fs.remove("/dir", recursive=True)
        with self.assertRaises(OSError):
            w.close()
        self.assertEqual(fs._reserved_bytes, 0)
        self.assertEqual(fs.size_bytes, 0)

    def test_edge_an_overwrite_within_the_old_size_needs_no_room(self) -> None:
        fs = _fs()
        with fs.open_write("/f.bin") as w:
            w.write(b"x" * 900)
        with fs.open_write("/f.bin") as w:
            w.write(b"y" * 900)
        self.assertEqual(fs.size_bytes, 900)
        with fs.open_write("/f.bin", append=True) as w:
            w.write(b"z" * 100)
            with self.assertRaises(RamFsCapacityError):
                w.write(b"z")
        self.assertEqual(fs.size_bytes, CAP)

    def test_edge_the_memory_reserve_sees_only_the_new_chunk(self) -> None:
        # Bytes already buffered are already in RAM: the free-memory
        # probe reflects them, so counting them again would refuse early.
        fs = RamFsSession(label="mem", max_bytes=CAP, system_reserve_bytes=10_000)
        with mock.patch.object(ram_fs, "_available_memory_bytes", return_value=10_150):
            with fs.open_write("/m.bin") as w:
                w.write(b"x" * 100)
                w.write(b"x" * 100)
                with self.assertRaises(RamFsCapacityError):
                    w.write(b"x" * 151)
        self.assertEqual(fs.size_bytes, 200)


if __name__ == "__main__":
    unittest.main()
