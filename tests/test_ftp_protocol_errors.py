"""FTP protocol errors reach callers as OSError.

``ftplib`` raises ``error_temp`` (4xx), ``error_reply``, ``error_proto``
and ``EOFError`` (control connection closed) — none of them an
``OSError``. ``FtpSession`` translated only ``error_perm`` and only in some
methods, so "450 file busy", "425 can't open data connection" or a server
that hung up escaped as foreign exception types: every caller that handles
``OSError`` (tree compare, the pane, transfers, recursive delete) crashed
instead of reporting the failure.

Driven end to end against a scripted control connection on a socketpair.
"""

from __future__ import annotations

import socket
import sys
import threading
from ftplib import FTP
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402
from core.tree_compare import compare_trees  # noqa: E402


class _ScriptedFtp:
    """Answers each verb from a table; ``None`` hangs up the connection."""

    def __init__(self, replies: dict[str, str | None]) -> None:
        self.replies = {"NOOP": "200 ok\r\n", "TYPE": "200 ok\r\n", **replies}
        self.client_sock, self._srv = socket.socketpair()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        for raw in self._srv.makefile("rb"):
            verb = raw.decode().rstrip("\r\n").partition(" ")[0]
            reply = self.replies.get(verb, "502 not implemented\r\n")
            if reply is None:
                self._srv.close()
                return
            self._srv.sendall(reply.encode())

    def session(self, has_mlsd: bool = True) -> FC.FtpSession:
        ftp = FTP()
        ftp.sock = self.client_sock
        ftp.file = self.client_sock.makefile("r", encoding="utf-8")
        ftp.af = socket.AF_INET
        s = FC.FtpSession.__new__(FC.FtpSession)
        s._ftp = ftp
        s._host, s._username = "h", "u"
        s._has_mlsd = has_mlsd
        return s


def test_happy_permanent_error_is_still_an_oserror():
    s = _ScriptedFtp({"MKD": "550 exists\r\n"}).session()
    with pytest.raises(OSError):
        s.mkdir("/d")


@pytest.mark.parametrize(
    "replies, op",
    [
        ({"PASV": "425 Can't open data connection\r\n"}, lambda s: s.list_dir("/")),
        ({"PASV": "421 Too many connections\r\n"}, lambda s: s.open_read("/f")),
        ({"MKD": "450 Busy\r\n"}, lambda s: s.mkdir("/d")),
        ({"RNFR": "450 Busy\r\n"}, lambda s: s.rename("/a", "/b")),
        (
            {"PWD": '257 "/"\r\n', "CWD": "550 not a dir\r\n", "DELE": "450 locked\r\n"},
            lambda s: s.remove("/f"),
        ),
        ({"MLST": "451 Local error\r\n"}, lambda s: s.stat("/f")),
        ({"PWD": "451 Local error\r\n"}, lambda s: s.home()),
        ({"SITE": "451 Local error\r\n"}, lambda s: s.chmod("/f", 0o644)),
    ],
    ids=["list_dir", "open_read", "mkdir", "rename", "remove", "stat", "home", "chmod"],
)
def test_sad_transient_errors_are_oserrors(replies, op):
    s = _ScriptedFtp(replies).session()
    with pytest.raises(OSError):
        op(s)


def test_sad_upload_refused_with_4xx_raises_oserror_on_close():
    s = _ScriptedFtp({"PASV": "452 Insufficient storage\r\n"}).session()
    w = s.open_write("/f")
    w.write(b"data")
    with pytest.raises(OSError):
        w.close()


def test_sad_compare_skips_a_directory_whose_listing_fails_transiently():
    s = _ScriptedFtp({"PASV": "425 Can't open data connection\r\n"}).session()

    class _Empty:
        def list_dir(self, path):
            return []

        def join(self, *parts):
            return "/".join(parts)

    assert compare_trees(s, "/", _Empty(), "/", hash_limit=0) == []


def test_edge_server_hangup_is_an_oserror():
    s = _ScriptedFtp({"MKD": None}).session()
    with pytest.raises(OSError):
        s.mkdir("/d")


def test_edge_recursive_delete_failure_inside_the_walk_is_an_oserror(monkeypatch):
    s = _ScriptedFtp(
        {"PWD": '257 "/"\r\n', "CWD": "250 ok\r\n", "DELE": "550 Permission denied\r\n"}
    ).session()
    monkeypatch.setattr(
        FC.FtpSession,
        "list_dir",
        lambda self, path: [FC.FileItem(name="x")] if path == "/d" else [],
    )
    with pytest.raises(OSError):
        s.remove("/d", recursive=True)
