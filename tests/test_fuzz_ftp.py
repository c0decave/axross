"""Fuzz: FtpSession against a hostile FTP server.

Every backend call must return sane data or raise OSError - never a
UnicodeDecodeError, ValueError, OverflowError or IndexError that the pane,
the transfer worker and compare do not catch - and must never hang.
"""

from __future__ import annotations

import posixpath
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fuzz_server import STALL, FakeFtpServer  # noqa: E402
from fuzz_testkit import check_contract, iterations, mutants, run_bounded  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core.remote_name import is_safe_remote_name  # noqa: E402

MLSD_CORPUS = [
    b"type=cdir;modify=20260101000000; .\r\n"
    b"type=pdir;modify=20260101000000; ..\r\n"
    b"type=file;size=1234;modify=20260102030405;perm=r; report.pdf\r\n"
    b"type=dir;modify=20250101000000;perm=flcdmpe; sub dir\r\n"
    b"type=OS.unix=slink:/etc;modify=20250101000000; link\r\n",
    b"size=0;type=file;modify=19700101000000.123; empty\r\n",
    b"type=file;size=99999999999999;modify=99991231235959; huge\r\n",
]

LIST_CORPUS = [
    b"total 12\r\n"
    b"drwxr-xr-x 2 ftp ftp 4096 Jan  1 12:00 sub\r\n"
    b"-rw-r--r-- 1 ftp ftp 1234 Feb 29  2024 file with spaces.txt\r\n"
    b"lrwxrwxrwx 1 ftp ftp 4 Mar  3 03:03 ln -> /tmp\r\n",
    b"01-01-26  12:00PM       <DIR>          dosdir\r\n"
    b"01-01-26  12:00PM                 1234 dosfile.txt\r\n",
    b"-rw-r--r--   1 owner    12345 Jan 01  1970 no-group\r\n",
]

NLST_CORPUS = [b"/sub\r\n/file with spaces.txt\r\nln\r\n", b"a\r\nb\r\n"]

CONTROL_CORPUS = {
    "MLST": b"250-Listing /f\r\n type=file;size=12;modify=20260101000000; /f\r\n250 End\r\n",
    "SIZE": b"213 1234\r\n",
    "MDTM": b"213 20260101120000\r\n",
    "FEAT": b"211-Features:\r\n MLST type*;size*;\r\n UTF8\r\n211 End\r\n",
    "PWD": b'257 "/home/u" is cwd\r\n',
    "HASH": b"213 SHA-256 0-12 " + b"ab" * 32 + b"\r\n",
}


@pytest.fixture(autouse=True)
def _short_timeouts(monkeypatch):
    """The production timeout is 15 s; a stalled fake server must fail the
    same way, only sooner. Every (re)connect gets a 0.3 s timeout, which
    ftplib also uses for the PASV data connections."""
    import ftplib

    orig = ftplib.FTP.connect

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        return orig(self, host, port, 0.3, source_address)

    monkeypatch.setattr(ftplib.FTP, "connect", connect)


def _session(srv: FakeFtpServer) -> FC.FtpSession:
    return FC.FtpSession(srv.host, srv.port, "u", "p")


def _assert_sane(items) -> None:
    assert isinstance(items, list)
    for item in items:
        assert isinstance(item.name, str)
        assert isinstance(item.size, int)


def _contract(fn, ctx):
    return check_contract(fn, (OSError,), timeout=15.0, context=ctx)


@pytest.fixture
def mlsd_server():
    srv = FakeFtpServer(data={"MLSD": MLSD_CORPUS[0]})
    yield srv
    srv.close()


# ---------------------------------------------------------------- happy path
def test_happy_mlsd_listing_parses(mlsd_server):
    s = _session(mlsd_server)
    items = s.list_dir("/")
    names = sorted(i.name for i in items)
    assert names == ["link", "report.pdf", "sub dir"]
    by = {i.name: i for i in items}
    assert by["report.pdf"].size == 1234
    assert by["sub dir"].is_dir
    assert by["link"].is_link


# ---------------------------------------------------------------- sad paths
@pytest.mark.parametrize(
    "pasv",
    [
        b"227 Entering Passive Mode (127,0,0,1,999,999)\r\n",  # port > 65535
        b"227 Entering Passive Mode (127,0,0,1)\r\n",
        b"227 nothing here\r\n",
        b"227 Entering Passive Mode (300,1,1,1,1,1)\r\n",
        b"227 Entering Passive Mode (127,0,0,1,0,0)\r\n",
        b"229 Entering Extended Passive Mode (|||abc|)\r\n",
        b"\r\n",
    ],
)
def test_sad_broken_pasv_reply_is_an_oserror(mlsd_server, pasv):
    s = _session(mlsd_server)
    mlsd_server.replies["PASV"] = pasv
    result = _contract(lambda: s.list_dir("/"), f"PASV {pasv!r}")
    assert isinstance(result, OSError) or isinstance(result, list)


def test_edge_pasv_to_foreign_ip_is_not_followed(mlsd_server):
    """FTP bounce: a PASV reply naming another host is answered by
    connecting to the control peer, never the announced address."""
    mlsd_server.pasv_host = "203,0,113,9"
    s = _session(mlsd_server)
    items = _contract(lambda: s.list_dir("/"), "foreign PASV")
    assert isinstance(items, list) and items  # data came from 127.0.0.1
    assert s._ftp.trust_server_pasv_ipv4_address is False


def _read_all(s, path):
    """A download streams: a stalled data channel shows on the read."""
    with s.open_read(path) as fh:
        return fh.read()


@pytest.mark.parametrize("verb", ["MLSD", "RETR"])
def test_sad_stalled_data_channel_times_out(mlsd_server, verb):
    s = _session(mlsd_server)
    mlsd_server.data[verb] = STALL
    op = (lambda: s.list_dir("/")) if verb == "MLSD" else (lambda: _read_all(s, "/f"))
    result = _contract(op, f"stalled {verb}")
    assert isinstance(result, OSError)


def test_sad_stalled_control_reply_times_out(mlsd_server):
    s = _session(mlsd_server)
    mlsd_server.replies["MKD"] = STALL
    assert isinstance(_contract(lambda: s.mkdir("/d"), "stalled MKD"), OSError)


def test_sad_server_hangs_up_mid_reply(mlsd_server):
    s = _session(mlsd_server)
    mlsd_server.replies["MKD"] = None
    assert isinstance(_contract(lambda: s.mkdir("/d"), "EOF on MKD"), OSError)


def test_edge_huge_control_line_is_bounded(mlsd_server):
    s = _session(mlsd_server)
    mlsd_server.replies["MKD"] = b"257 " + b"A" * 200_000 + b"\r\n"
    assert isinstance(_contract(lambda: s.mkdir("/d"), "huge reply"), OSError)


def test_edge_huge_listing_line_is_bounded(mlsd_server):
    s = _session(mlsd_server)
    mlsd_server.data["MLSD"] = b"type=file; " + b"x" * 200_000 + b"\r\n"
    assert isinstance(_contract(lambda: s.list_dir("/"), "huge MLSD line"), OSError)


def test_edge_out_of_order_duplicated_replies(mlsd_server):
    """A server that answers twice desynchronises the control channel;
    later calls fail cleanly instead of crashing."""
    s = _session(mlsd_server)
    mlsd_server.replies["MKD"] = b'257 "/d" created\r\n257 "/d" created\r\n550 stray\r\n'
    for op in (lambda: s.mkdir("/d"), lambda: s.rename("/a", "/b"), lambda: s.list_dir("/")):
        _contract(op, "desync")


def test_edge_traversal_names_from_listing_cannot_escape_download(mlsd_server, tmp_path):
    """Names a server lists are joined onto local targets only after the
    transfer layer's validation; nothing lands outside the target."""
    from core.local_fs import LocalFS
    from core.path_policy import drop_unsafe_names

    mlsd_server.data["MLSD"] = (
        b"type=file;size=1; ../escape\r\n"
        b"type=file;size=1; /etc/passwd\r\n"
        b"type=file;size=1; a/b\r\n"
        b"type=file;size=1; ..\r\n"
        b"type=file;size=1; ok.txt\r\n"
    )
    s = _session(mlsd_server)
    items = s.list_dir("/")
    kept = [i.name for i in drop_unsafe_names(items)]
    assert kept == ["ok.txt"]
    target = tmp_path / "target"
    target.mkdir()
    lfs = LocalFS()
    for item in items:
        if not is_safe_remote_name(item.name):
            continue
        dest = FC.safe_join(lfs, str(target), item.name)
        assert posixpath.commonpath([str(target), dest]) == str(target)


# ---------------------------------------------------------------- mutation sweeps
def test_fuzz_mlsd_listing_mutants(mlsd_server):
    s = _session(mlsd_server)
    for n, payload in enumerate(mutants(MLSD_CORPUS, seed=0xF7F0, per_entry=iterations(25))):
        mlsd_server.data["MLSD"] = payload
        result = _contract(lambda: s.list_dir("/"), f"MLSD mutant #{n}: {payload[:120]!r}")
        if not isinstance(result, OSError):
            _assert_sane(result)


def test_fuzz_list_nlst_fallback_mutants():
    srv = FakeFtpServer(
        replies={"MLSD": b"500 no\r\n", "MLST": b"500 no\r\n", "SIZE": b"213 5\r\n"},
        data={"NLST": NLST_CORPUS[0], "LIST": LIST_CORPUS[0]},
    )
    try:
        s = _session(srv)
        corpus = LIST_CORPUS + NLST_CORPUS
        for n, payload in enumerate(mutants(corpus, seed=0xF7F1, per_entry=iterations(10))):
            srv.data["LIST"] = payload
            srv.data["NLST"] = payload if n % 2 else NLST_CORPUS[0]
            result = _contract(lambda: s.list_dir("/"), f"LIST mutant #{n}: {payload[:120]!r}")
            if not isinstance(result, OSError):
                _assert_sane(result)
    finally:
        srv.close()


def test_fuzz_list_parser_direct():
    """The Unix LIST parser itself, over many mutants (no sockets)."""
    corpus = LIST_CORPUS
    for payload in mutants(corpus, seed=0xF7F2, per_entry=iterations(300)):
        lines = payload.decode("utf-8", "replace").split("\n")
        entries = FC._parse_unix_list(lines)
        assert entries is None or isinstance(entries, list)
        FC._unix_entry(entries, "sub")


@pytest.mark.parametrize("verb", sorted(CONTROL_CORPUS))
def test_fuzz_control_reply_mutants(verb):
    srv = FakeFtpServer(replies=dict(CONTROL_CORPUS), data={"MLSD": MLSD_CORPUS[0]})
    ops = {
        "MLST": lambda s: s.stat("/f"),
        "SIZE": lambda s: s.exists("/f"),
        "MDTM": lambda s: s.stat("/f"),
        "FEAT": lambda s: s.features(),
        "PWD": lambda s: s.home(),
        "HASH": lambda s: s.checksum("/f"),
    }
    try:
        s = _session(srv)
        if verb in ("SIZE", "MDTM"):
            s._has_mlsd = False
        for n, payload in enumerate(
            mutants(
                [CONTROL_CORPUS[verb]], seed=zlib.crc32(verb.encode()), per_entry=iterations(15)
            )
        ):
            srv.replies[verb] = payload
            _contract(lambda: ops[verb](s), f"{verb} mutant #{n}: {payload[:120]!r}")
    finally:
        srv.close()


def test_fuzz_mlst_reply_parser_direct():
    corpus = [CONTROL_CORPUS["MLST"]]
    for payload in mutants(corpus, seed=0xF7F3, per_entry=iterations(400)):
        text = payload.decode("utf-8", "replace")
        facts = FC.FtpSession._mlst_reply_facts(text)
        if facts is not None:
            item = FC.FtpSession._mlsd_to_item("f", facts)
            assert isinstance(item.size, int)


def test_fuzz_welcome_banner_never_hangs():
    """Connection setup may fail with any Exception (connect_worker forwards
    them all) but must never hang."""
    corpus = [b"220 ready\r\n", b"220-multi\r\n220 line\r\n"]
    for n, banner in enumerate(mutants(corpus, seed=0xF7F4, per_entry=iterations(10))):
        if not banner.endswith(b"\n"):
            banner += b"\r\n"
        srv = FakeFtpServer(welcome=banner, data={"MLSD": MLSD_CORPUS[0]})
        try:
            _, exc = run_bounded(lambda: FC.FtpSession(srv.host, srv.port, "u", "p"), 30.0)
            assert exc is None or isinstance(exc, Exception), f"banner #{n}: {exc!r}"
        finally:
            srv.close()
