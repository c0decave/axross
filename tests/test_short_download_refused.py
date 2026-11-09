"""A download that ends early is an error, not a short file.

Measured before (review round 6, repro reconn/netloss/t_ftp.py): the
data connection of an FTP RETR ended after half of a 3 MB file, the
server answered "226 Transfer complete" all the same, and the transfer
job finished DONE with 1500000 of 3000000 bytes - the short file replaced
the destination. Only a move compared the bytes written with the source.

Now FTP compares the bytes received with the size SIZE (or the 150 reply)
gave before RETR, and the transfer engine compares every copy from a
remote source with the size known at open (one stat of the source when
the copy came out short of it) before the copy replaces the destination.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

WHOLE = bytes(range(256)) * 400  # 102400 bytes
HALF = WHOLE[: len(WHOLE) // 2]


def _server(*, sent: bytes, size_reply: bytes | None, feat: bool = True,
            opening: bytes = b"150 opening data connection\r\n"):
    replies = {}
    if feat:
        replies["FEAT"] = b"211-Features:\r\n SIZE\r\n UTF8\r\n211 End\r\n"
    if size_reply is not None:
        replies["SIZE"] = size_reply
    srv = FakeFtpServer(replies=replies, data={"RETR": sent})
    if opening != b"150 opening data connection\r\n":
        original = srv._send_data

        def send_data(conn, verb, arg):
            class _Conn:
                def sendall(self, data):
                    if data.startswith(b"150 "):
                        data = opening
                    conn.sendall(data)

            return original(_Conn(), verb, arg)

        srv._send_data = send_data
    return srv


def _read(srv, *, shared: bool = False) -> bytes:
    session = FC.FtpSession(srv.host, srv.port, "u", "p")
    try:
        if shared:
            session._separate_transfers = False
        with session.open_read("/f") as handle:
            return handle.read()
    finally:
        session.close()


# ------------------------------------------------------------------ FTP
@pytest.mark.parametrize("shared", [False, True], ids=["own-connection", "shared"])
def test_sad_ftp_download_shorter_than_size_fails(shared):
    with _server(sent=HALF, size_reply=f"213 {len(WHOLE)}\r\n".encode()) as srv:
        with pytest.raises(OSError, match=f"{len(HALF)} of {len(WHOLE)} bytes"):
            _read(srv, shared=shared)


@pytest.mark.parametrize("shared", [False, True], ids=["own-connection", "shared"])
def test_happy_ftp_download_of_the_announced_size_reads_whole(shared):
    with _server(sent=WHOLE, size_reply=f"213 {len(WHOLE)}\r\n".encode()) as srv:
        assert _read(srv, shared=shared) == WHOLE
        assert any(c == "SIZE /f" for c in srv.commands)


def test_edge_ftp_size_refused_trusts_the_150_reply():
    opening = f"150 Opening BINARY mode data connection for /f ({len(WHOLE)} bytes)\r\n"
    with _server(sent=HALF, size_reply=b"550 not a plain file\r\n",
                 opening=opening.encode()) as srv:
        with pytest.raises(OSError, match="the download ended"):
            _read(srv)


def test_edge_ftp_without_size_in_feat_is_not_asked():
    with _server(sent=HALF, size_reply=None, feat=False) as srv:
        assert _read(srv) == HALF  # nothing to compare with
        assert not any(c.startswith("SIZE") for c in srv.commands)


# ------------------------------------------------------- transfer engine
class _ShortReads(RamFsSession):
    """A remote-like source whose reads end at half the file without an
    error (the stream ended early), while stat reports the whole file."""

    def open_read(self, path, mode="rb"):
        with super().open_read(path, mode) as handle:
            data = handle.read()
        return io.BytesIO(data[: len(data) // 2])


def _source(cls=_ShortReads):
    src = cls()
    with src.open_write("/f.bin") as handle:
        handle.write(WHOLE)
    return src


def _job(src, dest_backend, dest_path, *, temp: bool, move: bool = False):
    from core.transfer_worker import TransferJob, TransferWorker

    job = TransferJob(source_path="/f.bin", dest_path=dest_path, filename="f.bin",
                      total_bytes=len(WHOLE), source_backend=src,
                      dest_backend=dest_backend, use_temp_file=temp, move=move)
    TransferWorker()._process_job(job)
    return job


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_sad_short_read_fails_the_job_and_keeps_the_local_destination(tmp_path, temp):
    from core.local_fs import LocalFS
    from core.transfer_worker import TransferStatus

    # Another name: a direct write over the source's leaf name has a
    # check of its own (the destination may be the source itself).
    dest = tmp_path / "g.bin"
    dest.write_bytes(b"the old file")
    job = _job(_source(), LocalFS(), str(dest), temp=temp)
    assert job.status is TransferStatus.ERROR, job.error_message
    assert "were read" in job.error_message
    assert dest.read_bytes() == b"the old file"


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_sad_short_read_keeps_a_remote_destination(temp):
    from core.transfer_worker import TransferStatus

    dest = RamFsSession()
    with dest.open_write("/g.bin") as handle:
        handle.write(b"the old file")
    job = _job(_source(), dest, "/g.bin", temp=temp)
    assert job.status is TransferStatus.ERROR
    assert "were read" in job.error_message
    with dest.open_read("/g.bin") as handle:
        assert handle.read() == b"the old file"


def test_edge_source_that_shrank_since_the_listing_is_copied_as_it_is(tmp_path):
    from core.local_fs import LocalFS
    from core.transfer_worker import TransferStatus

    src = _source(RamFsSession)
    with src.open_write("/f.bin") as handle:
        handle.write(HALF)  # shorter now than the job's listed size
    job = _job(src, LocalFS(), str(tmp_path / "f.bin"), temp=True)
    assert job.status is TransferStatus.DONE, job.error_message
    assert (tmp_path / "f.bin").read_bytes() == HALF


def test_happy_whole_read_is_done(tmp_path):
    from core.local_fs import LocalFS
    from core.transfer_worker import TransferStatus

    job = _job(_source(RamFsSession), LocalFS(), str(tmp_path / "f.bin"), temp=True)
    assert job.status is TransferStatus.DONE
    assert (tmp_path / "f.bin").read_bytes() == WHOLE
