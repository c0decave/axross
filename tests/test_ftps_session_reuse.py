"""FTPS data connections resume the control connection's TLS session.

test.rebex.net refused every listing over FTPS with "425 Cannot secure
data connection - TLS session resumption required": the data socket was
wrapped without ``session=``, so it negotiated a new TLS session. vsftpd
requires the same by default (require_ssl_reuse=YES). Both the direct and
the proxy path now pass the control socket's session.
"""

from __future__ import annotations

import sys
from ftplib import FTP
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402


class _Context:
    def __init__(self):
        self.calls = []

    def wrap_socket(self, sock, **kw):
        self.calls.append(kw)
        return ("wrapped", sock)


def _tls(cls, prot_p=True):
    ftp = cls.__new__(cls)
    ftp.context = _Context()
    ftp.host = "ftp.example.org"
    ftp._prot_p = prot_p
    ftp.sock = mock.Mock(session="CONTROL-SESSION")
    return ftp


# --- happy ----------------------------------------------------------------


def test_happy_the_data_socket_resumes_the_control_session():
    ftp = _tls(FC._FTP_TLS)
    with mock.patch.object(FTP, "ntransfercmd", return_value=("raw", 42)):
        conn, size = ftp.ntransfercmd("LIST")
    assert conn == ("wrapped", "raw") and size == 42
    assert ftp.context.calls == [
        {"server_hostname": "ftp.example.org", "session": "CONTROL-SESSION"}
    ]


def test_happy_the_proxy_path_resumes_it_too():
    ftp = _tls(FC._ProxyFTP_TLS)
    ftp.passiveserver = True
    ftp.sock.getpeername.return_value = ("192.0.2.1", 21)
    ftp.makepasv = lambda: ("192.0.2.5", 2121)
    ftp.sendcmd = lambda cmd: "150 here"
    ftp._axross_proxy = object()
    with mock.patch("core.proxy.create_proxy_socket", return_value="raw"):
        conn, _ = ftp.ntransfercmd("LIST")
    assert conn == ("wrapped", "raw")
    assert ftp.context.calls[0]["session"] == "CONTROL-SESSION"


# --- sad ------------------------------------------------------------------


def test_sad_without_prot_p_the_data_socket_stays_clear():
    ftp = _tls(FC._FTP_TLS, prot_p=False)
    with mock.patch.object(FTP, "ntransfercmd", return_value=("raw", None)):
        conn, _ = ftp.ntransfercmd("LIST")
    assert conn == "raw" and ftp.context.calls == []


# --- edge -----------------------------------------------------------------


def test_edge_no_session_yet_still_wraps():
    # Before a TLS 1.3 ticket arrives the control socket has no session:
    # the data socket then negotiates its own instead of failing.
    ftp = _tls(FC._FTP_TLS)
    ftp.sock.session = None
    with mock.patch.object(FTP, "ntransfercmd", return_value=("raw", None)):
        ftp.ntransfercmd("LIST")
    assert ftp.context.calls[0]["session"] is None
