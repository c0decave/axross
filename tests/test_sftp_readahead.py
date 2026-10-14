"""SFTP reads pipeline their requests; writes do not wait for every ack.

paramiko asks for at most 32 KiB per READ and waits for each answer, so a
plain download moves 32 KiB per round trip — about 1.6 MB/s at 20 ms,
however fast the link. ``open_read`` now reads ahead in bounded windows
once it sees sequential reading (random access stays request-sized), and
``open_write`` pipelines its WRITEs; errors still surface, at ``close``.
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402
from tests.sftp_testkit import SftpServer  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "srv"
        self.root.mkdir()
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        p = mock.patch("pathlib.Path.home", return_value=home)
        p.start()
        self.addCleanup(p.stop)
        self.server = SftpServer(str(self.root))
        self.addCleanup(self.server.close)
        profile = ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=self.server.port, username="u"
        )
        self.s = SSHSession(profile)
        self.s.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.s.disconnect)
        rnd = random.Random(3)
        self.data = rnd.randbytes(3 * 1024 * 1024 + 12345)
        (self.root / "big.bin").write_bytes(self.data)


class ReadAheadTest(_Base):
    def test_happy_a_whole_file_read_is_byte_identical(self) -> None:
        with self.s.open_read("/big.bin") as fh:
            got = fh.read()
        self.assertEqual(hashlib.sha256(got).hexdigest(), hashlib.sha256(self.data).hexdigest())

    def test_happy_chunked_reads_are_byte_identical(self) -> None:
        out = bytearray()
        with self.s.open_read("/big.bin") as fh:
            while chunk := fh.read(64 * 1024):
                out += chunk
        self.assertEqual(bytes(out), self.data)

    def test_happy_sequential_reading_pipelines_requests(self) -> None:
        # The server counts READ requests; pipelining shows up as the
        # client reading far ahead of what was consumed.
        with self.s.open_read("/big.bin") as fh:
            fh.read(64 * 1024)
            fh.read(64 * 1024)
            raw = fh.raw
            self.assertGreaterEqual(raw._window, raw.MIN_WINDOW)

    def test_edge_random_access_stays_small(self) -> None:
        with self.s.open_read("/big.bin") as fh:
            for off in (len(self.data) - 100, 10, 2_000_000, 0):
                fh.seek(off)
                self.assertEqual(fh.read(50), self.data[off : off + 50])
            self.assertLessEqual(len(fh.raw._buf), fh.raw.MIN_WINDOW)

    def test_edge_seek_whence_and_tell(self) -> None:
        with self.s.open_read("/big.bin") as fh:
            fh.seek(-10, os.SEEK_END)
            self.assertEqual(fh.tell(), len(self.data) - 10)
            self.assertEqual(fh.read(), self.data[-10:])
            fh.seek(100)
            fh.read(10)
            fh.seek(5, os.SEEK_CUR)
            self.assertEqual(fh.read(4), self.data[115:119])

    def test_edge_resume_from_an_offset_then_read_sequentially(self) -> None:
        with self.s.open_read("/big.bin") as fh:
            fh.seek(1_000_001)
            self.assertEqual(fh.read(), self.data[1_000_001:])

    def test_edge_readline_and_iteration(self) -> None:
        lines = b"".join(b"line %d\n" % i for i in range(20000))
        (self.root / "t.txt").write_bytes(lines)
        with self.s.open_read("/t.txt") as fh:
            self.assertEqual(fh.readline(), b"line 0\n")
            rest = list(fh)
        self.assertEqual(len(rest), 19999)
        self.assertEqual(rest[-1], b"line 19999\n")

    def test_edge_empty_file(self) -> None:
        (self.root / "empty").write_bytes(b"")
        with self.s.open_read("/empty") as fh:
            self.assertEqual(fh.read(), b"")
            self.assertEqual(fh.read(10), b"")

    def test_edge_a_file_that_grows_while_reading_is_read_to_its_new_end(self) -> None:
        with self.s.open_read("/big.bin") as fh:
            first = fh.read(1024 * 1024)
            with open(self.root / "big.bin", "ab") as grow:
                grow.write(b"TAIL")
            rest = fh.read()
        self.assertEqual(first + rest, self.data + b"TAIL")

    def test_edge_a_file_that_shrinks_while_reading_yields_only_original_bytes(self) -> None:
        # Concurrent truncation has no defined result (any read-ahead, the
        # page cache included, may still hold bytes past the new end); what
        # must hold: only original bytes, in order, and the read ends.
        with self.s.open_read("/big.bin") as fh:
            fh.read(16)
            os.truncate(self.root / "big.bin", 100_000)
            rest = fh.read()
        self.assertGreaterEqual(len(rest), 100_000 - 16)
        self.assertEqual(rest, self.data[16 : 16 + len(rest)])

    def test_sad_a_missing_file_raises(self) -> None:
        with self.assertRaises(OSError):
            self.s.open_read("/nope.bin")

    def test_sad_a_read_error_mid_file_is_raised_not_swallowed(self) -> None:
        self.server.stats["fail_reads_at"] = 2 * 1024 * 1024
        with self.assertRaises(OSError), self.s.open_read("/big.bin") as fh:
            fh.read()

    def test_the_read_ahead_buffer_is_bounded(self) -> None:
        big = random.Random(5).randbytes(40 * 1024 * 1024)
        (self.root / "huge.bin").write_bytes(big)
        peak = 0
        h = hashlib.sha256()
        with self.s.open_read("/huge.bin") as fh:
            while chunk := fh.read(1 << 20):
                h.update(chunk)
                peak = max(peak, len(fh.raw._buf))
        self.assertEqual(h.hexdigest(), hashlib.sha256(big).hexdigest())
        self.assertLessEqual(peak, fh.raw.MAX_WINDOW)


class PipelinedWriteTest(_Base):
    def test_happy_written_bytes_arrive_intact(self) -> None:
        with self.s.open_write("/out.bin") as fh:
            for i in range(0, len(self.data), 65536):
                fh.write(self.data[i : i + 65536])
        self.assertEqual((self.root / "out.bin").read_bytes(), self.data)

    def test_happy_writes_are_pipelined(self) -> None:
        fh = self.s.open_write("/out.bin")
        try:
            fh.write(self.data[: 20 * 32 * 1024])
            self.assertGreater(fh._in_flight(), 1)  # sent without waiting
        finally:
            fh.close()
        self.assertEqual(fh._in_flight(), 0)
        self.assertEqual((self.root / "out.bin").read_bytes(), self.data[: 20 * 32 * 1024])

    def test_sad_a_failure_is_not_lost_when_another_request_reads_the_answer(self) -> None:
        # Another request on the same connection consumes pending answers
        # first; with paramiko's own pipelining that dropped the error.
        self.server.stats["fail_writes"] = True
        fh = self.s.open_write("/out.bin")
        fh.write(self.data[:65536])
        self.s.stat("/big.bin")
        with self.assertRaises(OSError):
            fh.close()

    def test_edge_in_flight_writes_are_bounded(self) -> None:
        fh = self.s.open_write("/out.bin")
        try:
            peak = 0
            for i in range(0, len(self.data), 65536):
                fh.write(self.data[i : i + 65536])
                peak = max(peak, fh._in_flight())
            self.assertLessEqual(peak, fh.MAX_IN_FLIGHT)
        finally:
            fh.close()
        self.assertEqual((self.root / "out.bin").read_bytes(), self.data)

    def test_sad_a_server_side_write_error_surfaces_at_close(self) -> None:
        self.server.stats["fail_writes"] = True
        fh = self.s.open_write("/out.bin")
        with self.assertRaises(OSError):
            try:
                fh.write(self.data[:100000])
            finally:
                fh.close()

    def test_edge_append_mode(self) -> None:
        (self.root / "a.bin").write_bytes(b"head-")
        with self.s.open_write("/a.bin", append=True) as fh:
            fh.write(b"tail")
        self.assertEqual((self.root / "a.bin").read_bytes(), b"head-tail")


if __name__ == "__main__":
    unittest.main()
