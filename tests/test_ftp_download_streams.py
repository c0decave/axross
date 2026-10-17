"""An FTP download streams on a connection of its own.

Measured before: ``FtpSession.open_read`` ran the whole RETR into a spool
inside one call while holding the session's I/O lock. The transfer
worker's cancel check and progress callback only ran after that call
returned, so Cancel did nothing until the whole file was downloaded, the
progress bar stood still, and every other call on the session (a stat
from the GUI thread) waited for the entire download.

Driven against a scripted FTP server on 127.0.0.1 whose RETR sends its
data in slow blocks.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402

BLOCK = 64 * 1024
PAYLOAD = bytes(range(256)) * (BLOCK * 20 // 256)  # 20 blocks, 1.25 MiB


class _SlowRetrServer(FakeFtpServer):
    """RETR sends ``files[path]`` in BLOCK pieces, ``delay`` apart, then
    ``final``. Connections beyond ``max_conns`` get a 421 greeting."""

    def __init__(self, files, *, delay=0.0, final=b"226 done\r\n", max_conns=None):
        size = len(files.get("/f", b""))
        super().__init__(
            replies={
                "MLST": (
                    f"250-Listing\r\n type=file;size={size};modify=20260101000000; /f\r\n"
                    "250 End\r\n"
                ).encode()
            },
            data={"MLSD": b""},
        )
        self.files = files
        self.delay = delay
        self.final = final
        self.max_conns = max_conns
        self.connections = 0

    def logins(self) -> int:
        return sum(1 for c in self.commands if c.startswith("USER"))

    def _handle(self, conn):
        with self._lock:
            self.connections += 1
            number = self.connections
        if self.max_conns is not None and number > self.max_conns:
            conn.sendall(b"421 Too many connections from your address\r\n")
            return
        super()._handle(conn)

    def _send_data(self, conn, verb, arg):
        if verb != "RETR":
            return super()._send_data(conn, verb, arg)
        ds, self._data_sock = self._data_sock, None
        if arg not in self.files:
            if ds is not None:
                ds.close()
            conn.sendall(b"550 No such file\r\n")
            return True
        conn.sendall(b"150 opening data connection\r\n")
        dconn, _ = ds.accept()
        ds.close()
        payload = self.files[arg]
        try:
            for start in range(0, len(payload), BLOCK):
                dconn.sendall(payload[start : start + BLOCK])
                if self.delay:
                    time.sleep(self.delay)
        except OSError:
            dconn.close()
            conn.sendall(b"426 transfer aborted\r\n")
            return True
        dconn.close()
        conn.sendall(self.final)
        return True


def _session(srv) -> FC.FtpSession:
    return FC.FtpSession(srv.host, srv.port, "u", "p")


# ------------------------------------------------------------- transfer engine
# The engine reads 1 MiB per chunk and checks cancel / reports progress in
# between, for every backend. 64 blocks 0.05 s apart: the whole file takes
# 3.2 s on the wire, one chunk 0.8 s.
BIG = bytes(range(256)) * (BLOCK * 64 // 256)


def _job(src, tmp_path):
    from core.local_fs import LocalFS
    from core.transfer_worker import TransferJob

    job = TransferJob(
        source_path="/f",
        dest_path=str(tmp_path / "f.bin"),
        total_bytes=len(BIG),
        filename="f.bin",
        use_temp_file=True,
    )
    job.source_backend, job.dest_backend = src, LocalFS()
    return job


def _run_job(job):
    from core.transfer_worker import TransferWorker

    thread = threading.Thread(target=TransferWorker()._process_job, args=(job,), daemon=True)
    thread.start()
    return thread


def test_happy_cancel_stops_the_download_within_a_chunk(tmp_path):
    with _SlowRetrServer({"/f": BIG}, delay=0.05) as srv:
        job = _job(_session(srv), tmp_path)
        started = time.monotonic()
        thread = _run_job(job)
        time.sleep(0.3)
        job.cancel_event.set()
        thread.join(10)
        elapsed = time.monotonic() - started
    assert job.status.value == "cancelled"
    assert elapsed < 2.0, f"cancel took effect only after {elapsed:.2f}s"


def test_happy_progress_is_reported_while_the_download_runs(tmp_path):
    with _SlowRetrServer({"/f": BIG}, delay=0.05) as srv:
        job = _job(_session(srv), tmp_path)
        started = time.monotonic()
        thread = _run_job(job)
        first_progress = None
        while thread.is_alive():
            if first_progress is None and job.transferred_bytes > 0:
                first_progress = time.monotonic() - started
            time.sleep(0.01)
        thread.join()
    assert job.status.value == "done", job.error_message
    assert (tmp_path / "f.bin").read_bytes() == BIG
    assert first_progress is not None and first_progress < 2.0, (
        f"first progress after {first_progress}s - only once the file was down"
    )


def test_happy_the_first_block_is_readable_before_the_file_is_down():
    with _SlowRetrServer({"/f": PAYLOAD}, delay=0.25) as srv:
        s = _session(srv)
        started = time.monotonic()
        with s.open_read("/f") as fh:
            assert fh.read(BLOCK) == PAYLOAD[:BLOCK]
            waited = time.monotonic() - started
    assert waited < 1.0, f"the first block took {waited:.2f}s"


def test_happy_stat_on_the_session_does_not_wait_for_a_download():
    with _SlowRetrServer({"/f": PAYLOAD}, delay=0.25) as srv:
        s = _session(srv)

        def download():
            with s.open_read("/f") as fh:
                fh.read()

        reader = threading.Thread(target=download, daemon=True)
        reader.start()
        time.sleep(0.3)
        started = time.monotonic()
        assert s.stat("/f").size == len(PAYLOAD)
        waited = time.monotonic() - started
        reader.join(10)
    assert waited < 1.0, f"stat waited {waited:.2f}s for the download"


# ------------------------------------------------------------- the handle
def test_happy_read_seek_back_and_tell():
    with _SlowRetrServer({"/f": PAYLOAD}) as srv:
        with _session(srv).open_read("/f") as fh:
            assert fh.read(10) == PAYLOAD[:10]
            assert fh.tell() == 10
            fh.seek(0)
            assert fh.read() == PAYLOAD
            fh.seek(BLOCK + 3)
            assert fh.read(5) == PAYLOAD[BLOCK + 3 : BLOCK + 8]
            assert fh.seek(0, 2) == len(PAYLOAD)
            assert fh.read(1) == b""


def test_edge_read_n_returns_n_bytes_until_the_end():
    """FUSE hands read(size) straight to the kernel, which takes a short
    read for the end of the file."""
    with _SlowRetrServer({"/f": PAYLOAD}, delay=0.01) as srv:
        with _session(srv).open_read("/f") as fh:
            fh.seek(100)
            assert len(fh.read(BLOCK * 3)) == BLOCK * 3
            fh.seek(len(PAYLOAD) - 7)
            assert fh.read(4096) == PAYLOAD[-7:]


def test_edge_seek_ahead_of_the_received_bytes_then_read():
    with _SlowRetrServer({"/f": PAYLOAD}) as srv:
        with _session(srv).open_read("/f") as fh:
            fh.seek(len(PAYLOAD) - 3)
            assert fh.read() == PAYLOAD[-3:]
            fh.seek(len(PAYLOAD) + 10)
            assert fh.read(5) == b""


def test_edge_empty_file():
    with _SlowRetrServer({"/f": b""}) as srv:
        with _session(srv).open_read("/f") as fh:
            assert fh.read() == b""


def test_sad_missing_file_fails_at_open():
    with _SlowRetrServer({"/f": PAYLOAD}) as srv:
        with pytest.raises(OSError):
            _session(srv).open_read("/missing")


def test_sad_a_failed_end_of_transfer_is_an_error_not_a_short_file():
    """The data arrives, then the server reports 451: that is not a
    complete file."""
    with _SlowRetrServer({"/f": PAYLOAD}, final=b"451 local error in processing\r\n") as srv:
        s = _session(srv)
        with pytest.raises(OSError), s.open_read("/f") as fh:
            fh.read()


def test_edge_a_failed_download_keeps_failing_and_the_next_one_works():
    with _SlowRetrServer({"/f": PAYLOAD}, final=b"451 local error in processing\r\n") as srv:
        s = _session(srv)
        try:
            fh = s.open_read("/f")
        except OSError:
            fh = None  # a download that completes inside open_read
        if fh is not None:
            with pytest.raises(OSError):
                fh.read()
            with pytest.raises(OSError):
                fh.read(1)
            fh.close()
        srv.final = b"226 done\r\n"
        with s.open_read("/f") as fh:
            assert fh.read() == PAYLOAD


def test_sad_a_server_refusing_a_second_connection_still_serves_the_file():
    with _SlowRetrServer({"/f": PAYLOAD}, max_conns=1) as srv:
        s = _session(srv)
        with s.open_read("/f") as fh:
            assert fh.read() == PAYLOAD
        with s.open_read("/f") as fh:
            assert fh.read() == PAYLOAD
        # Refused once, then not asked again.
        assert srv.connections == 2


def test_edge_sequential_downloads_reuse_one_extra_connection():
    with _SlowRetrServer({"/f": PAYLOAD}) as srv:
        s = _session(srv)
        for _ in range(3):
            with s.open_read("/f") as fh:
                assert fh.read() == PAYLOAD
        with pytest.raises(OSError):
            s.open_read("/missing")
        with s.open_read("/f") as fh:
            assert fh.read(3) == PAYLOAD[:3]
        assert srv.logins() == 2
        s.disconnect()


def test_edge_a_download_closed_early_is_not_reused():
    with _SlowRetrServer({"/f": PAYLOAD}, delay=0.01) as srv:
        s = _session(srv)
        with s.open_read("/f") as fh:
            assert fh.read(10) == PAYLOAD[:10]
        with s.open_read("/f") as fh:
            assert fh.read() == PAYLOAD
        assert srv.logins() == 3


def test_edge_fuse_reads_on_one_thread_and_releases_on_another():
    """FUSE opens, reads and releases on different libfuse threads; the
    handle must not be bound to the thread that opened it."""
    from core.fuse_mount import BackendFuseFS

    with _SlowRetrServer({"/f": PAYLOAD}) as srv:
        fs = BackendFuseFS(_session(srv), "/")
        fh = fs.open("/f", os.O_RDONLY)
        out: dict[str, object] = {}

        def read():
            out["data"] = fs.read("/f", 4096, 0, fh)

        def release():
            out["rc"] = fs.release("/f", fh)

        for target in (read, release):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            t.join(10)
            assert not t.is_alive()
        assert out == {"data": PAYLOAD[:4096], "rc": 0}
        # The session is still usable afterwards.
        assert fs.read("/f", 3, 1, None) == PAYLOAD[1:4]

