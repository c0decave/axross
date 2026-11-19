"""How an FTP / FTPS session connects, and what a failed connect says.

* A refused login (530) was ftplib's ``error_perm`` - no OSError - and the
  dialog showed "530 Login incorrect". It is now an authentication error
  (a PermissionError whose class core.user_errors names a refused login),
  so the user reads "The server refused the login. Check the user name and
  the password ...". A 530 about too many users stays the server's text.
* FTPS against a server without TLS showed "502 TLS not configured"; now
  it says that the server does not offer FTPS.
* Implicit FTPS (port 990: TLS from the first byte, no AUTH TLS) never got
  a greeting - the client waited for "220" in clear text and timed out
  after 15 s ("did not answer in time"). An FTPS session to port 990 now
  speaks TLS first.
* The profile's IP version was ignored: ``address_family`` "ipv4" /
  "ipv6" now picks the addresses the control connection may use.

Driven against tests/ftp_fs_server.py.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fs_server import FtpFsServer, self_signed_context  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture
def root(tmp_path):
    folder = tmp_path / "root"
    folder.mkdir()
    (folder / "f.txt").write_bytes(b"data")
    return str(folder)


def test_wrong_password_is_a_refused_login(root):
    with FtpFsServer(root) as srv:
        with pytest.raises(PermissionError) as info:
            FC.FtpSession("127.0.0.1", srv.port, "u", "wrong")
    assert "530" in str(info.value)
    assert describe(info.value).startswith("The server refused the login.")


def test_too_many_users_keeps_the_server_text(root):
    import ftp_fs_server as FS

    def full(conn_self, arg):
        conn_self.send("530 Sorry, the maximum number of clients (5) for this user are already connected.")

    orig = FS._Conn.do_PASS
    FS._Conn.do_PASS = full
    try:
        with FtpFsServer(root) as srv:
            with pytest.raises(OSError) as info:
                FC.FtpSession("127.0.0.1", srv.port, "u", "p")
    finally:
        FS._Conn.do_PASS = orig
    assert "maximum number of clients" in describe(info.value)


def test_ftps_to_a_server_without_tls_says_so(root):
    with FtpFsServer(root) as srv:
        with pytest.raises(OSError) as info:
            FC.FtpSession("127.0.0.1", srv.port, "u", "p", tls=True, verify_tls=False)
    text = describe(info.value)
    assert "FTPS" in text and "502" in text


def test_implicit_ftps_on_port_990(root, tmp_path, monkeypatch):
    ctx = self_signed_context(str(tmp_path))
    with FtpFsServer(root, tls_context=ctx, implicit=True, require_reuse=True) as srv:
        # The convention is the port: 990 means implicit FTPS.
        monkeypatch.setattr(FC, "IMPLICIT_FTPS_PORTS", frozenset({srv.port}))
        sess = FC.FtpSession("127.0.0.1", srv.port, "u", "p", tls=True, verify_tls=False)
        try:
            assert [i.name for i in sess.list_dir("/")] == ["f.txt"]
            with sess.open_read("/f.txt") as fh:
                assert fh.read() == b"data"
            assert not any(c.startswith("AUTH") for c in srv.commands)
            assert "PROT P" in srv.commands
            info = sess.security_info()
            assert info is not None and "data channel protected (PROT P)" in info.details
        finally:
            sess.close()


def test_explicit_ftps_elsewhere_still_uses_auth_tls(root, tmp_path):
    ctx = self_signed_context(str(tmp_path))
    with FtpFsServer(root, tls_context=ctx) as srv:
        sess = FC.FtpSession("127.0.0.1", srv.port, "u", "p", tls=True, verify_tls=False)
        try:
            assert [i.name for i in sess.list_dir("/")] == ["f.txt"]
            assert any(c.startswith("AUTH TLS") for c in srv.commands)
        finally:
            sess.close()


def _has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def test_ipv4_only_never_dials_ipv6(root):
    with FtpFsServer(root) as srv:
        sess = FC.FtpSession("localhost", srv.port, "u", "p", address_family="ipv4")
        try:
            assert sess._ftp.sock.family == socket.AF_INET
            assert [i.name for i in sess.list_dir("/")] == ["f.txt"]
        finally:
            sess.close()


@pytest.mark.skipif(not _has_ipv6_loopback(), reason="no IPv6 loopback")
def test_ipv6_only_refuses_an_ipv4_literal(root):
    with FtpFsServer(root) as srv:
        with pytest.raises(OSError):
            FC.FtpSession("127.0.0.1", srv.port, "u", "p", address_family="ipv6")


@pytest.mark.skipif(not _has_ipv6_loopback(), reason="no IPv6 loopback")
def test_ipv6_only_connects_and_lists_over_ipv6(root):
    with FtpFsServer(root, family=socket.AF_INET6) as srv:
        sess = FC.FtpSession("::1", srv.port, "u", "p", address_family="ipv6")
        try:
            assert sess._ftp.sock.family == socket.AF_INET6
            assert [i.name for i in sess.list_dir("/")] == ["f.txt"]
        finally:
            sess.close()
