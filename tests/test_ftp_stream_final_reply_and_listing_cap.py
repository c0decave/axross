"""FTP: a streamed download's failing final reply is an OSError that
stays, and a listing has a cap.

Protocol review (round 1):

* ``_StreamedDownload._receive_into`` ran ``_finish()`` (the server's
  reply after the data connection ends) outside its error handling: a
  ``426 transfer aborted`` came out of ``read()`` as ftplib's error_temp
  (no OSError - FUSE, MCP, the editor catch OSError), and the next
  ``read()`` returned b"" - a cut file that looked complete.
* A listing (MLSD, LIST, NLST) was collected without any cap: SFTP
  stops at 300 000 entries, WebDAV at 64 MiB, a hostile FTP server could
  stream until memory ran out. Past the cap the listing fails and the
  control connection, its reply unread, is closed (the next call logs in
  again).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ftp_fuzz_server import FakeFtpServer  # noqa: E402
from test_ftp_download_streams import _SlowRetrServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core.read_spool import sequential_reads  # noqa: E402

PAYLOAD = b"X" * 3000


def _session(srv) -> FC.FtpSession:
    return FC.FtpSession(srv.host, srv.port, "u", "p")


def test_sad_streamed_download_426_is_an_oserror_and_stays():
    with _SlowRetrServer({"/f": PAYLOAD}, final=b"426 Connection closed; transfer aborted\r\n") as srv:
        s = _session(srv)
        with sequential_reads():
            fh = s.open_read("/f")
        got = b""
        with pytest.raises(OSError, match="426"):
            while chunk := fh.read(65536):
                got += chunk
        with pytest.raises(OSError):
            fh.read(65536)
        fh.close()


def test_happy_streamed_download_226_reads_whole():
    with _SlowRetrServer({"/f": PAYLOAD}) as srv:
        s = _session(srv)
        with sequential_reads():
            fh = s.open_read("/f")
        assert fh.read() == PAYLOAD
        fh.close()


def test_sad_endless_listing_stops_at_the_cap(monkeypatch):
    monkeypatch.setattr(FC, "MAX_LISTING_LINES", 50)
    lines = b"".join(b"type=file;size=1; f%05d\r\n" % i for i in range(200))
    feat = b"211-Features:\r\n MLST type*;size*;modify*;\r\n211 End\r\n"
    with FakeFtpServer(replies={"FEAT": feat}, data={"MLSD": lines}) as srv:
        s = _session(srv)
        with pytest.raises(OSError, match="entries"):
            s.list_dir("/")
        # The connection whose reply was left unread is not used again.
        monkeypatch.setattr(FC, "MAX_LISTING_LINES", 10_000)
        assert len(s.list_dir("/")) == 200


def test_edge_listing_under_the_cap(monkeypatch):
    monkeypatch.setattr(FC, "MAX_LISTING_LINES", 50)
    lines = b"".join(b"type=file;size=1; f%05d\r\n" % i for i in range(40))
    feat = b"211-Features:\r\n MLST type*;size*;modify*;\r\n211 End\r\n"
    with FakeFtpServer(replies={"FEAT": feat}, data={"MLSD": lines}) as srv:
        assert len(_session(srv).list_dir("/")) == 40
