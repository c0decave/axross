"""FTP listings on servers without MLSD (vsftpd, pure-ftpd), and the
PASV address through a proxy - the final protocol review.

* vsftpd (force_dot_files=NO, its default) and pure-ftpd leave dot entries
  out of a plain NLST / LIST: list_dir took its names from ``NLST path``,
  so a folder copy silently left .htaccess / .env / .git behind and a
  recursive delete removed the rest, then failed on RMD. Now ``NLST -a``
  (and ``LIST -a``) is asked first; a server that refuses the option, or
  takes "-a" for part of the path, gets the plain command.
* NLST of a FILE answers with that file (ls of the argument): list_dir of
  a file listed the file as its own child.
* A folder's date without MLSD comes from LIST, which servers print on
  their own clock; it was read as UTC while files (MDTM) are UTC - a
  folder looked hours off its files. The offset MDTM and LIST show for
  the files of the listing is applied to the folders.
* Through a SOCKS / HTTP proxy the data connection went to whatever host
  the 227 reply named: SSRF through the proxy, and a NAT'ed server that
  announces its private address failed. The control host is used, as
  ftplib does without a proxy.
"""

from __future__ import annotations

import socket
from datetime import datetime, timedelta

import pytest

from core.ftp_client import FtpSession
from tests.test_backend_conformance import _FtpServer


@pytest.fixture
def server_tz(monkeypatch):
    """Client in Asia/Kolkata, server (LIST) in America/Los_Angeles."""
    import time

    monkeypatch.setenv("TZ", "Asia/Kolkata")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _site(tmp_path, **kw):
    root = tmp_path / "ftp"
    (root / "site" / ".git").mkdir(parents=True)
    (root / "site" / ".htaccess").write_bytes(b"Deny from all\n")
    (root / "site" / ".git" / "HEAD").write_bytes(b"ref")
    (root / "site" / "index.html").write_bytes(b"<html/>")
    (root / "g").write_bytes(b"other")
    srv = _FtpServer(root, mlsd=False, **kw)
    s = FtpSession("127.0.0.1", srv.port, "u", "p")
    return root, srv, s


def test_happy_dot_files_are_listed_without_mlsd(tmp_path):
    root, srv, s = _site(tmp_path)
    try:
        names = {i.name: i.is_dir for i in s.list_dir("/site")}
        assert names == {".htaccess": False, ".git": True, "index.html": False}
        assert any(c.startswith("NLST -a ") for c in srv.commands)
    finally:
        s.close()
        srv.close()


def test_sad_recursive_delete_removes_the_dot_files_too(tmp_path):
    root, srv, s = _site(tmp_path)
    try:
        s.remove("/site", recursive=True)
        assert not (root / "site").exists()
        assert (root / "g").read_bytes() == b"other"
    finally:
        s.close()
        srv.close()


@pytest.mark.parametrize("dash_a", ["refuse", "literal"])
def test_edge_a_server_without_the_option_gets_the_plain_listing(tmp_path, dash_a):
    """501 to "-a", or "-a /site" taken as a path (550): the plain NLST
    answers - never a listing of a path named "-a ..."."""
    root, srv, s = _site(tmp_path, dash_a=dash_a)
    try:
        names = {i.name for i in s.list_dir("/site")}
        # Without the option the server hides its dot files: only the rest.
        assert names == {"index.html"}
        assert "NLST /site" in srv.commands
    finally:
        s.close()
        srv.close()


def test_edge_a_folder_with_only_dot_files_is_not_empty(tmp_path):
    root, srv, s = _site(tmp_path)
    (root / "site" / "index.html").unlink()
    try:
        assert {i.name for i in s.list_dir("/site")} == {".htaccess", ".git"}
    finally:
        s.close()
        srv.close()


@pytest.mark.parametrize("mlsd", [True, False], ids=["mlsd", "no-mlsd"])
def test_sad_list_dir_of_a_file_is_not_a_directory(tmp_path, mlsd):
    root = tmp_path / "ftp"
    root.mkdir()
    (root / "g").write_bytes(b"other")
    (root / "a" / "a").mkdir(parents=True)  # a folder whose only child has its name
    srv = _FtpServer(root, mlsd=mlsd)
    s = FtpSession("127.0.0.1", srv.port, "u", "p")
    try:
        with pytest.raises(NotADirectoryError):
            s.list_dir("/g")
        assert [(i.name, i.is_dir) for i in s.list_dir("/a")] == [("a", True)]
        with pytest.raises(FileNotFoundError):
            s.list_dir("/nope")
        with pytest.raises(FileNotFoundError):
            s.open_read("/nope")
        with pytest.raises(NotADirectoryError):
            s.stat("/g/")
    finally:
        s.close()
        srv.close()


def test_sad_folder_dates_from_list_take_the_servers_clock_offset(tmp_path, server_tz):
    root, srv, s = _site(tmp_path)
    try:
        now = datetime.now()
        items = {i.name: i for i in s.list_dir("/")}
        for name in ("g", "site"):
            off = items[name].modified - now
            assert abs(off) < timedelta(minutes=10), f"{name} off by {off}"
    finally:
        s.close()
        srv.close()


def test_edge_without_a_file_to_compare_folder_dates_stay_as_listed(tmp_path, server_tz):
    """No MDTM answer to compare with: nothing is guessed."""
    root = tmp_path / "ftp"
    (root / "only" / "sub").mkdir(parents=True)
    srv = _FtpServer(root, mlsd=False)
    s = FtpSession("127.0.0.1", srv.port, "u", "p")
    try:
        (item,) = s.list_dir("/only")
        assert item.name == "sub" and item.is_dir
    finally:
        s.close()
        srv.close()


def test_sad_pasv_through_a_proxy_dials_the_control_host(tmp_path, monkeypatch):
    import core.proxy

    asked: list[tuple[str, int]] = []

    def fake_proxy_socket(proxy, host, port, timeout=10.0, family=socket.AF_UNSPEC):
        asked.append((host, int(port)))
        return socket.create_connection(("127.0.0.1", int(port)), timeout)

    monkeypatch.setattr(core.proxy, "create_proxy_socket", fake_proxy_socket)
    root = tmp_path / "ftp"
    root.mkdir()
    (root / "g").write_bytes(b"other")
    # What a NAT'ed or hostile server announces.
    srv = _FtpServer(root, pasv_host="169,254,169,254")
    s = FtpSession("127.0.0.1", srv.port, "u", "p", proxy_type="socks5",
                   proxy_host="proxy.example", proxy_port=1080)
    try:
        with s.open_read("/g") as fh:
            assert fh.read() == b"other"
    finally:
        s.close()
        srv.close()
    assert asked and {host for host, _port in asked} == {"127.0.0.1"}
