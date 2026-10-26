"""FTP exists() asks MLST on the control connection where the server has it.

Measured 2026-10-26 against the lab's pure-ftpd: exists() of a missing
file sent SIZE (550), PWD, CWD (550) and then an NLST of the parent over a
data connection of its own. pure-ftpd delays every failed CWD by 100 ms
times the failed CWDs so far on that connection and drops the connection
after the 50th, so an upload of 300 new files paid about 2.6 s per file and
lost every 51st file to "connection closed by server" ("Cannot safely
stream to destination without probing whether it exists").

Now a server that names MLST in FEAT (asked once per control connection)
gets one MLST: 250 is "there", 550 is "not there", no data connection and
no CWD. A server without MLST keeps the SIZE / CWD / listing chain, with
the connection in TYPE I before SIZE (vsftpd refuses SIZE in ASCII mode
with the same 550 a missing file gets). False is the go-ahead to write for
server_side_copy(overwrite=False) and the transfer engine, so anything but
a definitive answer stays an OSError or falls back to the listing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from tests.test_ftp_symlink_delete import _DirFtpServer  # noqa: E402

_DATA_VERBS = ("PASV", "EPSV", "PORT", "EPRT", "LIST", "NLST", "MLSD", "RETR", "STOR")
_FEAT_MLST = b"211-Features:\r\n SIZE\r\n MLST type*;size*;modify*;\r\n211 End\r\n"


@pytest.fixture(autouse=True)
def _short_timeouts(monkeypatch):
    import ftplib

    orig = ftplib.FTP.connect

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        return orig(self, host, port, 2.0, source_address)

    monkeypatch.setattr(ftplib.FTP, "connect", connect)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "srv"
    (root / "dir" / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("keep")
    (root / "dir" / "inner.bin").write_bytes(b"x")
    (root / "with space ü é.txt").write_text("u")
    (root / "folder with space ü").mkdir()
    os.symlink("a.txt", root / "filelink")
    os.symlink("dir", root / "dirlink")
    os.symlink("no-such-target", root / "dangling")
    locked = root / "locked.bin"
    locked.write_bytes(b"secret")
    locked.chmod(0)
    return root


@pytest.fixture
def connect(tmp_path):
    made: list[tuple[_DirFtpServer, FC.FtpSession]] = []

    def make(**server_kw):
        srv = _DirFtpServer(_tree(tmp_path), **server_kw)
        s = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
        made.append((srv, s))
        return srv, s

    yield make
    for srv, s in made:
        s.disconnect()
        srv.close()


def _verbs(commands: list[str]) -> list[str]:
    return [c.split(" ", 1)[0].upper() for c in commands]


def _after(srv, mark: int) -> list[str]:
    return _verbs(srv.commands[mark:])


def _session(srv: FakeFtpServer) -> FC.FtpSession:
    return FC.FtpSession(srv.host, srv.port, "u", "p")


# --- happy ----------------------------------------------------------------


def test_happy_absent_file_costs_no_data_connection_on_an_mlst_server(connect):
    srv, s = connect(mlsd="follow", feat=True)
    mark = len(srv.commands)
    assert s.exists("/missing.bin") is False
    assert s.exists("/dir/missing.bin") is False
    assert s.exists("/nodir/missing.bin") is False
    sent = _after(srv, mark)
    assert not set(sent) & set(_DATA_VERBS), sent
    assert "CWD" not in sent and "SIZE" not in sent, sent
    assert sent.count("MLST") == 3, sent


def test_happy_present_entries_answer_from_one_mlst_each(connect):
    srv, s = connect(mlsd="follow", feat=True)
    s.exists("/a.txt")  # FEAT goes out with the first call
    mark = len(srv.commands)
    for path in ("/a.txt", "/dir", "/dir/", "/dir/inner.bin", "/dir/sub"):
        assert s.exists(path) is True, path
    assert _after(srv, mark) == ["MLST"] * 5


def test_happy_feat_is_asked_once_per_connection(connect):
    srv, s = connect(mlsd="follow", feat=True)
    for _ in range(4):
        s.exists("/missing.bin")
        s.exists("/a.txt")
    assert _verbs(srv.commands).count("FEAT") == 1
    s.disconnect()
    assert s.exists("/a.txt") is True  # a new connection asks again
    assert _verbs(srv.commands).count("FEAT") == 2


def test_happy_a_no_clobber_copy_onto_an_existing_file_is_refused(connect, monkeypatch):
    from core.server_ops import server_side_copy

    _srv, s = connect(mlsd="follow", feat=True)
    written = []
    monkeypatch.setattr(s, "copy", lambda src, dst: written.append(dst))
    monkeypatch.setattr(s, "open_write", lambda path, append=False: written.append(path))
    with pytest.raises((FileExistsError, OSError)):
        server_side_copy(s, "/dir/inner.bin", "/a.txt", overwrite=False)
    assert written == []


# --- sad ------------------------------------------------------------------


def test_sad_without_feat_the_listing_chain_decides(connect):
    srv, s = connect()  # FEAT 502, MLST 500 (vsftpd without MLST)
    assert s.exists("/a.txt") is True
    assert s.exists("/dir") is True
    mark = len(srv.commands)
    assert s.exists("/missing.bin") is False
    sent = _after(srv, mark)
    assert "MLST" not in sent and "NLST" in sent, sent


@pytest.mark.parametrize(
    "feat",
    [b"502 not implemented\r\n", b"500 FEAT?\r\n", b"530 not now\r\n"],
    ids=["502", "500", "530"],
)
def test_sad_a_refused_feat_never_asks_mlst(feat):
    replies = {"FEAT": feat, "MLST": b"550 should not be asked\r\n", "SIZE": b"213 4\r\n"}
    with FakeFtpServer(replies=replies) as srv:
        assert _session(srv).exists("/a.txt") is True
        assert "MLST" not in _verbs(srv.commands)


@pytest.mark.parametrize(
    "refusal",
    [b"500 MLST not understood\r\n", b"502 not implemented\r\n", b"504 not for this\r\n"],
    ids=["500", "502", "504"],
)
def test_sad_mlst_named_in_feat_but_refused_falls_back_once(refusal):
    replies = {
        "FEAT": _FEAT_MLST,
        "MLST": refusal,
        "SIZE": b"550 no\r\n",
        "CWD": b"550 no\r\n",
    }
    with FakeFtpServer(replies=replies, data={"NLST": b"other.bin\r\n"}) as srv:
        s = _session(srv)
        assert s.exists("/missing.bin") is False
        assert s.exists("/missing2.bin") is False
        sent = _verbs(srv.commands)
        assert sent.count("MLST") == 1, sent  # not asked again on this connection
        assert sent.count("NLST") == 2, sent


@pytest.mark.parametrize(
    "reply",
    [
        b"530 Please login with USER and PASS\r\n",
        b"421 Timeout\r\n",
        b"534 Policy requires SSL\r\n",
        b"450 busy\r\n",
    ],
    ids=["530", "421", "534", "450"],
)
def test_sad_a_refused_mlst_is_an_oserror_not_absent(reply):
    with FakeFtpServer(replies={"FEAT": _FEAT_MLST, "MLST": reply}) as srv:
        with pytest.raises(OSError, match=reply[:3].decode()):
            _session(srv).exists("/a.txt")
        assert "NLST" not in _verbs(srv.commands)


def test_sad_a_lost_login_is_not_a_go_ahead_for_a_no_clobber_copy(monkeypatch):
    from core.server_ops import server_side_copy

    with FakeFtpServer(replies={"FEAT": _FEAT_MLST, "MLST": b"530 Not logged in\r\n"}) as srv:
        s = _session(srv)
        written = []
        monkeypatch.setattr(s, "copy", lambda src, dst: written.append(dst))
        monkeypatch.setattr(s, "open_write", lambda path, append=False: written.append(path))
        with pytest.raises(OSError):
            server_side_copy(s, "/a.txt", "/b.txt", overwrite=False)
        assert written == []


@pytest.mark.parametrize(
    ("listing", "expected"),
    [(b"locked.bin\r\n", True), (b"other.bin\r\n", False)],
    ids=["listed", "not-listed"],
)
def test_sad_a_permission_refusal_with_550_is_decided_by_the_listing(listing, expected):
    """IIS and others answer 550 "Access is denied" for an entry that is
    there: no answer about the path, so the listing chain decides."""
    replies = {
        "FEAT": _FEAT_MLST,
        "MLST": b"550 Access is denied.\r\n",
        "SIZE": b"550 Permission denied\r\n",
        "CWD": b"550 Permission denied\r\n",
    }
    with FakeFtpServer(replies=replies, data={"NLST": listing}) as srv:
        assert _session(srv).exists("/locked.bin") is expected
        assert "NLST" in _verbs(srv.commands)


@pytest.mark.parametrize(
    "reply", [b"226 odd\r\n", b"150 odd\r\n250 late\r\n"], ids=["226", "150-then-250"]
)
def test_sad_an_unexpected_mlst_reply_is_an_oserror_and_leaves_no_stale_reply(reply):
    """After a 1xx another reply follows; read by the next command, it
    would answer a question about another path."""
    with FakeFtpServer(replies={"FEAT": _FEAT_MLST, "MLST": reply}) as srv:
        s = _session(srv)
        with pytest.raises(OSError):
            s.exists("/a.txt")
        srv.replies["MLST"] = b"550 Can't check for file existence\r\n"
        assert s.exists("/missing.bin") is False


def test_sad_a_name_with_a_line_break_is_an_oserror_not_a_wire_command():
    with FakeFtpServer(replies={"FEAT": _FEAT_MLST, "MLST": b"550 no\r\n"}) as srv:
        s = _session(srv)
        for name in ("/a\r\nDELE /x", "/a\nb"):
            with pytest.raises(OSError):
                s.exists(name)
        assert "DELE" not in _verbs(srv.commands)


# --- edge -----------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/filelink", "/dirlink", "/dangling", "/locked.bin", "/with space ü é.txt",
     "/folder with space ü", "/dir/sub/"],
)
def test_edge_links_spaces_non_ascii_and_unreadable_entries_are_there(connect, path):
    """A dangling link is there (LocalFS and SFTP lstat it); a file without
    read permission is there, MLST needs no read access."""
    srv, s = connect(mlsd="follow", feat=True)
    mark = len(srv.commands)
    assert s.exists(path) is True
    assert not set(_after(srv, mark)) & set(_DATA_VERBS)


@pytest.mark.parametrize(
    "path", ["/with space ü é.txt.bak", "/folder with space ü/missing ä.txt", "/a.txt/b"]
)
def test_edge_missing_names_with_spaces_non_ascii_and_a_file_on_the_way(connect, path):
    srv, s = connect(mlsd="follow", feat=True)
    mark = len(srv.commands)
    assert s.exists(path) is False
    assert not set(_after(srv, mark)) & set(_DATA_VERBS)


def test_edge_without_mlst_an_unreadable_file_refused_by_size_is_still_there(connect):
    """550 to SIZE and CWD for an existing file the server will not size:
    the listing still finds it."""
    _srv, s = connect(size=False)
    assert s.exists("/locked.bin") is True
    assert s.exists("/dir/inner.bin") is True
    assert s.exists("/dir/missing.bin") is False


def test_edge_size_goes_out_in_binary_mode(connect):
    """vsftpd refuses SIZE in ASCII mode with the 550 of a missing file; a
    listing leaves the connection in ASCII mode. TYPE I first lets SIZE
    find the file without a listing, and is sent only when needed."""
    srv, s = connect(size="binary")
    s.list_dir("/dir")  # TYPE A
    mark = len(srv.commands)
    assert s.exists("/a.txt") is True
    assert s.exists("/dir/inner.bin") is True
    assert s.exists("/with space ü é.txt") is True
    sent = _after(srv, mark)
    assert "NLST" not in sent and "CWD" not in sent, sent
    assert sent.count("TYPE") == 1, sent
    assert s.exists("/missing.bin") is False  # a missing name still asks the listing


def test_edge_a_refused_type_i_still_lets_size_and_the_listing_decide():
    def type_(arg):
        return b"504 no binary here\r\n" if arg.upper().startswith("I") else b"200 ok\r\n"

    replies = {"TYPE": type_, "SIZE": b"550 no\r\n", "CWD": b"550 no\r\n"}
    with FakeFtpServer(replies=replies, data={"NLST": b"a.txt\r\n"}) as srv:
        s = _session(srv)
        assert s.exists("/a.txt") is True
        assert s.exists("/b.txt") is False
        assert [c for c in srv.commands if c.upper() == "TYPE I"] == ["TYPE I"]  # asked once


def test_edge_many_absent_files_survive_a_server_that_drops_after_50_failed_cwds():
    """pure-ftpd drops a control connection after 50 failed CWDs (measured
    2026-10-26); 300 checks of new names on one session must not touch it."""
    failed = {"cwd": 0}

    def cwd(arg):
        failed["cwd"] += 1
        return None if failed["cwd"] > 50 else b"550 no such directory\r\n"

    replies = {"FEAT": _FEAT_MLST, "MLST": b"550 Can't check for file existence\r\n", "CWD": cwd}
    with FakeFtpServer(replies=replies) as srv:
        s = _session(srv)
        mark = len(srv.commands)  # after the login's MLSD probe
        assert [s.exists(f"/up/f{i:05d}.bin") for i in range(300)] == [False] * 300
        assert failed["cwd"] == 0
        assert not set(_after(srv, mark)) & set(_DATA_VERBS)


def test_edge_stat_sizes_a_file_in_binary_mode(connect):
    """stat() without MLSD asks SIZE too: in ASCII mode vsftpd refused it
    and the file came back with size 0 after a parent listing."""
    srv, s = connect(size="binary")
    s.list_dir("/dir")  # TYPE A
    mark = len(srv.commands)
    item = s.stat("/a.txt")
    assert (item.size, item.is_dir) == (4, False)
    assert "NLST" not in _after(srv, mark)
