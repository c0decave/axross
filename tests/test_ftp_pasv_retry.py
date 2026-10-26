"""A 425 reply to PASV is asked again before the transfer fails.

Measured 2026-10-26 against the lab's pure-ftpd (passive ports
30000-30010): 300 uploads of 4 KiB with four jobs at a time lost a file in
2 of 10 rounds to "425 Unable to identify the local data socket: Address
already in use" - the reply to PASV, sent before STOR. 425 is a transient
reply (RFC 959 4.2.1: 4yz) and nothing has been transferred yet, so the
data connection is asked for again, a few times. Any other refusal, and a
425 to the transfer command itself, fails as before.
"""

from __future__ import annotations

import contextlib
import ftplib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402

_BUSY = b"425 Unable to identify the local data socket: Address already in use\r\n"


@pytest.fixture(autouse=True)
def _short_timeouts(monkeypatch):
    orig = ftplib.FTP.connect

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        return orig(self, host, port, 2.0, source_address)

    monkeypatch.setattr(ftplib.FTP, "connect", connect)
    monkeypatch.setattr(FC, "PASV_RETRY_DELAY", 0.0)


@contextlib.contextmanager
def _connected(pasv_replies: list, **kw):
    """A session on a server whose PASV replies, after the login, come
    from *pasv_replies* first; every PASV after them gets a real port.
    Yields the server, the session's connection and the commands sent
    after the login."""
    holder: dict = {}
    queue: list = []

    def pasv(arg):
        reply = queue.pop(0) if queue else None
        return holder["srv"]._open_pasv() if reply is None else reply

    replies = {"PASV": pasv, **kw.pop("replies", {})}
    with FakeFtpServer(replies=replies, **kw) as srv:
        holder["srv"] = srv
        ftp = FC.FtpSession(srv.host, srv.port, "u", "p")._ensure_connected()
        mark = len(srv.commands)
        queue.extend(pasv_replies)
        yield srv, ftp, lambda: [c.split(" ", 1)[0].upper() for c in srv.commands[mark:]]


# --- happy ----------------------------------------------------------------


def test_happy_a_busy_passive_port_is_asked_again_and_the_listing_arrives():
    with _connected([_BUSY], data={"NLST": b"a.txt\r\nb.txt\r\n"}) as (_srv, ftp, sent):
        assert ftp.nlst("/") == ["a.txt", "b.txt"]
        assert sent().count("PASV") == 2
        assert sent().count("NLST") == 1


def test_happy_a_download_survives_two_busy_replies():
    with _connected([_BUSY, _BUSY], data={"RETR": b"payload"}) as (_srv, ftp, sent):
        chunks: list[bytes] = []
        ftp.retrbinary("RETR /x.bin", chunks.append)
        assert b"".join(chunks) == b"payload"
        assert sent().count("PASV") == 3
        assert sent().count("RETR") == 1


# --- sad ------------------------------------------------------------------


def test_sad_a_port_that_stays_busy_fails_without_sending_the_transfer():
    with _connected([_BUSY] * 10, data={"NLST": b"a.txt\r\n"}) as (_srv, ftp, sent):
        with pytest.raises(ftplib.error_temp, match="425"):
            ftp.nlst("/")
        assert "NLST" not in sent()
        assert sent().count("PASV") == FC.PASV_ATTEMPTS == 3


@pytest.mark.parametrize(
    "reply",
    [b"421 Service not available\r\n", b"426 aborted\r\n", b"502 no passive\r\n"],
    ids=["421", "426", "502"],
)
def test_sad_other_refusals_of_pasv_are_not_asked_again(reply):
    with _connected([reply], data={"NLST": b"a.txt\r\n"}) as (_srv, ftp, sent):
        with pytest.raises(ftplib.Error, match=reply[:3].decode()):
            ftp.nlst("/")
        assert sent().count("PASV") == 1
        assert "NLST" not in sent()


# --- edge -----------------------------------------------------------------


def test_edge_a_425_to_the_transfer_command_itself_is_not_repeated():
    """425 after PASV succeeded: the server may have acted on the command."""
    with _connected([], replies={"NLST": _BUSY}) as (_srv, ftp, sent):
        with pytest.raises(ftplib.error_temp, match="425"):
            ftp.nlst("/")
        assert sent().count("NLST") == 1
        assert sent().count("PASV") == 1


def test_edge_the_proxy_and_tls_classes_ask_again_too():
    mixin = FC._ControlChannelMixin
    for cls in (FC._FTP, FC._FTP_TLS, FC._ProxyFTP, FC._ProxyFTP_TLS):
        assert cls.makepasv is mixin.makepasv, cls
