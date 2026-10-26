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


class _SyncRequests:
    """Counts the SFTP requests the client waited for one by one (a round
    trip each), per request type, while active."""

    def __init__(self) -> None:
        from paramiko import sftp_client

        self.by_type: dict[int, int] = {}
        original = sftp_client.SFTPClient._request

        def counting(client, t, *args, **kwargs):
            self.by_type[t] = self.by_type.get(t, 0) + 1
            return original(client, t, *args, **kwargs)

        self._patch = mock.patch.object(sftp_client.SFTPClient, "_request", counting)

    def __enter__(self):
        self._patch.start()
        return self

    def __exit__(self, *exc) -> None:
        self._patch.stop()

    @property
    def reads(self) -> int:
        from paramiko.sftp import CMD_READ

        return self.by_type.get(CMD_READ, 0)

    @property
    def total(self) -> int:
        return sum(self.by_type.values())


class ReadRoundTripTest(_Base):
    """Bytes the reader asked for go out as pipelined READs, not as one
    waited-for 32 KiB READ after the other: the transfer worker reads 1 MiB
    at a time, and those reads were larger than the window for the first
    three windows, so each file's first 3 MiB cost 96 round trips."""

    def test_happy_large_sequential_reads_wait_for_no_32k_read(self) -> None:
        out = bytearray()
        with _SyncRequests() as count, self.s.open_read("/big.bin") as fh:
            while chunk := fh.read(1 << 20):
                out += chunk
        self.assertEqual(bytes(out), self.data)
        # Only the end-of-file probe past the known size reads plainly.
        self.assertLessEqual(count.reads, 2, count.by_type)

    def test_happy_a_small_file_read_whole_costs_no_extra_round_trip(self) -> None:
        payload = bytes(range(256)) * 16
        (self.root / "small.bin").write_bytes(payload)
        with _SyncRequests() as count, self.s.open_read("/small.bin") as fh:
            got = fh.read(1 << 20)  # as the transfer worker reads
            self.assertEqual(fh.read(1 << 20), b"")
        self.assertEqual(got, payload)
        # OPEN, the size, the end-of-file probe, CLOSE (the data is one
        # pipelined READ).
        self.assertLessEqual(count.total, 4, count.by_type)

    def test_edge_a_large_read_after_a_seek_is_pipelined_but_reads_nothing_ahead(self) -> None:
        offset = 1_000_001
        with _SyncRequests() as count, self.s.open_read("/big.bin") as fh:
            fh.read(10)
            fh.seek(offset)
            got = fh.raw.read(1 << 20)  # one raw read: what the reader asked for
            self.assertEqual(got, self.data[offset : offset + (1 << 20)])
            self.assertLessEqual(len(fh.raw._buf), 1 << 20)
        self.assertLessEqual(count.reads, 1, count.by_type)

    def test_edge_a_large_read_crossing_the_end_of_file_stops_there(self) -> None:
        offset = len(self.data) - 5000
        with self.s.open_read("/big.bin") as fh:
            fh.seek(offset)
            self.assertEqual(fh.raw.read(1 << 20), self.data[offset:])
            self.assertEqual(fh.read(), b"")

    def test_edge_small_random_reads_cost_one_round_trip_each_and_stay_small(self) -> None:
        # The reader's 64 KiB buffer fill was two waited-for READs.
        with _SyncRequests() as count, self.s.open_read("/big.bin") as fh:
            for off in (2_000_000, 17, 3_000_000):
                fh.seek(off)
                self.assertEqual(fh.read(100), self.data[off : off + 100])
                self.assertLessEqual(len(fh.raw._buf), 64 * 1024)
        self.assertLessEqual(count.reads, 3, count.by_type)

    def test_edge_a_read_larger_than_the_window_is_whole_and_bounded_per_round_trip(self) -> None:
        big = random.Random(9).randbytes(12 * 1024 * 1024 + 7)
        (self.root / "large.bin").write_bytes(big)
        with self.s.open_read("/large.bin") as fh:
            got = fh.read(len(big) + 100)
            self.assertLessEqual(len(fh.raw._buf), fh.raw.MAX_WINDOW)
        self.assertEqual(got, big)

    def test_edge_a_read_at_the_end_after_a_short_window_is_one_plain_request(self) -> None:
        payload = b"z" * 5000
        (self.root / "small.bin").write_bytes(payload)
        with self.s.open_read("/small.bin") as fh:
            self.assertEqual(fh.raw.read(1 << 20), payload)  # the window came back short
            with _SyncRequests() as count:
                self.assertEqual(fh.raw.read(1 << 20), b"")
                self.assertEqual(fh.raw.read(1 << 20), b"")
            with open(self.root / "small.bin", "ab") as grow:
                grow.write(b"MORE")
            self.assertEqual(fh.raw.read(1 << 20), b"MORE")  # it grew: read on
        self.assertEqual(count.reads, 2, count.by_type)

    def test_sad_a_read_error_inside_a_large_read_is_raised(self) -> None:
        self.server.stats["fail_reads_at"] = 512 * 1024
        with self.assertRaises(OSError), self.s.open_read("/big.bin") as fh:
            fh.read(1 << 20)


class CloseRoundTripTest(_Base):
    """CLOSE does not cost a round trip of its own: an upload's CLOSE goes
    out behind its last WRITEs (the server handles requests on one handle
    in order) and one wait takes all their answers; a download's CLOSE is
    not waited for at all (paramiko ignores its answer anyway)."""

    def _record_close(self):
        """Patches _async_request: the WRITEs still unanswered when CLOSE
        is sent, per CLOSE."""
        from paramiko import sftp_client
        from paramiko.sftp import CMD_CLOSE, CMD_WRITE

        seen: list[int] = []
        writes: set[int] = set()
        original = sftp_client.SFTPClient._async_request

        def recording(client, owner, t, *args):
            if t == CMD_CLOSE:
                seen.append(sum(1 for n in writes if n in client._expecting))
            num = original(client, owner, t, *args)
            if t == CMD_WRITE:
                writes.add(num)
            return num

        return seen, mock.patch.object(sftp_client.SFTPClient, "_async_request", recording)

    def test_happy_an_upload_sends_close_behind_its_unanswered_writes(self) -> None:
        seen, patch = self._record_close()
        with patch, _SyncRequests() as count:
            with self.s.open_write("/out.bin") as fh:
                fh.write(self.data[: 10 * 32 * 1024])
        self.assertEqual((self.root / "out.bin").read_bytes(), self.data[: 10 * 32 * 1024])
        self.assertEqual(len(seen), 1)
        self.assertGreater(seen[0], 0)  # CLOSE went out before their answers were read
        from paramiko.sftp import CMD_CLOSE

        self.assertEqual(count.by_type.get(CMD_CLOSE, 0), 0, count.by_type)
        self.assertEqual(dict(self.s.sftp._expecting), {})

    def test_happy_a_download_does_not_wait_for_its_close(self) -> None:
        from paramiko.sftp import CMD_CLOSE

        with _SyncRequests() as count:
            with self.s.open_read("/big.bin") as fh:
                self.assertEqual(fh.read(100), self.data[:100])
        self.assertEqual(count.by_type.get(CMD_CLOSE, 0), 0, count.by_type)
        # The next request reads the CLOSE answer; the file is closed and
        # can be removed.
        self.s.remove("/big.bin")
        self.assertFalse((self.root / "big.bin").exists())
        self.assertEqual(dict(self.s.sftp._expecting), {})

    def test_sad_a_write_failure_is_still_raised_at_close_and_the_handle_closed(self) -> None:
        self.server.stats["fail_writes"] = True
        fh = self.s.open_write("/out.bin")
        fh.write(self.data[:65536])
        with self.assertRaises(OSError) as caught:
            fh.close()
        self.assertIn("write failed", str(caught.exception))
        self.assertTrue(fh.closed)
        self.assertEqual(dict(self.s.sftp._expecting), {})

    def test_sad_a_refused_close_after_good_writes_is_raised(self) -> None:
        self.server.stats["fail_close"] = True
        fh = self.s.open_write("/out.bin")
        fh.write(self.data[:65536])
        with self.assertRaises(OSError) as caught:
            fh.close()
        self.assertIn("close failed", str(caught.exception))
        self.assertEqual(dict(self.s.sftp._expecting), {})

    def test_edge_an_empty_upload_and_a_double_close(self) -> None:
        fh = self.s.open_write("/empty.bin")
        fh.close()
        fh.close()
        self.assertEqual((self.root / "empty.bin").read_bytes(), b"")
        reader = self.s.open_read("/empty.bin")
        reader.close()
        reader.close()
        self.assertTrue(self.s.exists("/empty.bin"))
        self.assertEqual(dict(self.s.sftp._expecting), {})

    def test_edge_many_uploads_and_downloads_in_a_row_leave_nothing_pending(self) -> None:
        for i in range(20):
            with self.s.open_write(f"/f{i}.bin") as fh:
                fh.write(bytes([i]) * 5000)
            with self.s.open_read(f"/f{i}.bin") as fh:
                self.assertEqual(fh.read(), bytes([i]) * 5000)
        self.assertTrue(self.s.exists("/f19.bin"))
        self.assertEqual(dict(self.s.sftp._expecting), {})


class ChannelWindowTest(_Base):
    """The SFTP channel's receive window holds a whole read-ahead window.

    paramiko opens it with 2 MiB (DEFAULT_WINDOW_SIZE): the server could
    send only that much per round trip of the 8 MiB the reader asks for,
    so a download at 20 ms ran at ~52 MB/s instead of ~90 MB/s."""

    def test_happy_the_window_is_larger_than_a_read_ahead_window(self) -> None:
        from core.sftp_io import ReadAheadRaw

        channel = self.s.sftp.get_channel()
        self.assertGreaterEqual(channel.in_window_size, 2 * ReadAheadRaw.MAX_WINDOW)

    def test_happy_every_thread_gets_the_same_window_and_the_bytes_are_intact(self) -> None:
        import threading

        from core.sftp_io import ReadAheadRaw

        seen = {}

        def work() -> None:
            with self.s.open_read("/big.bin") as fh:
                seen["data"] = fh.read()
            seen["window"] = self.s.sftp.get_channel().in_window_size

        t = threading.Thread(target=work)
        t.start()
        t.join(30)
        self.assertEqual(seen["data"], self.data)
        self.assertGreaterEqual(seen["window"], 2 * ReadAheadRaw.MAX_WINDOW)

    def test_edge_a_reopened_channel_keeps_the_window(self) -> None:
        from core.sftp_io import ReadAheadRaw

        self.s.sftp.get_channel().close()
        self.assertTrue(self.s.exists("/big.bin"))  # a new channel is opened
        self.assertGreaterEqual(self.s.sftp.get_channel().in_window_size,
                                2 * ReadAheadRaw.MAX_WINDOW)


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
