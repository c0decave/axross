"""FTP exists() and is_dir() say False only for "not found".

Both read every 5xx reply (ftplib.error_perm) to CWD as "no": 530 "not
logged in" after the server dropped the login, 500 / 502 from a server
that did not understand, 534 from a policy refusal. And a reply ftplib
could not decode (UnicodeDecodeError) was "no" as well. Only 550 is the
FTP answer "no such file or folder" ("file unavailable");
server_side_copy(overwrite=False) and the transfer worker's no-clobber
check take False from exists() as the go-ahead to write. A refused SIZE
still falls back to the CWD probe: SIZE says nothing about a folder and
is optional (RFC 3659).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from tests.test_ftp_symlink_delete import _DirFtpServer  # noqa: E402

_NO_MLSD = {"MLSD": b"500 no\r\n", "MLST": b"500 no\r\n"}


@pytest.fixture(autouse=True)
def _short_timeouts(monkeypatch):
    import ftplib

    orig = ftplib.FTP.connect

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        return orig(self, host, port, 2.0, source_address)

    monkeypatch.setattr(ftplib.FTP, "connect", connect)


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "srv"
    (root / "dir").mkdir(parents=True)
    (root / "a.txt").write_text("keep")
    srv = _DirFtpServer(root)
    s = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
    yield s
    s.disconnect()
    srv.close()


def _session(srv: FakeFtpServer) -> FC.FtpSession:
    return FC.FtpSession(srv.host, srv.port, "u", "p")


def test_happy_present_and_absent(tree):
    s = tree
    assert s.exists("/a.txt") is True
    assert s.exists("/dir") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/a.txt") is False
    assert s.exists("/missing") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize(
    "reply",
    [
        b"530 Please login with USER and PASS\r\n",
        b"500 Command not understood\r\n",
        b"534 Policy requires SSL\r\n",
        b"421 Timeout\r\n",
    ],
    ids=["530", "500", "534", "421"],
)
def test_sad_a_refused_cwd_is_an_oserror_not_absent(reply):
    replies = {**_NO_MLSD, "SIZE": b"550 not a plain file\r\n", "CWD": reply}
    with FakeFtpServer(replies=replies) as srv:
        s = _session(srv)
        with pytest.raises(OSError, match=reply[:3].decode()):
            s.exists("/dir")
    with FakeFtpServer(replies=replies) as srv:
        s = _session(srv)
        with pytest.raises(OSError, match=reply[:3].decode()):
            s.is_dir("/dir")


def test_sad_a_lost_login_is_not_a_go_ahead_for_a_no_clobber_copy(monkeypatch):
    from core.server_ops import server_side_copy

    replies = {**_NO_MLSD, "SIZE": b"530 Not logged in\r\n", "CWD": b"530 Not logged in\r\n"}
    with FakeFtpServer(replies=replies) as srv:
        s = _session(srv)
        written = []
        monkeypatch.setattr(s, "copy", lambda src, dst: written.append(dst))
        monkeypatch.setattr(s, "open_write", lambda path, append=False: written.append(path))
        with pytest.raises(OSError):
            server_side_copy(s, "/a.txt", "/b.txt", overwrite=False)
        assert written == []


def test_sad_an_undecodable_reply_is_an_oserror_not_absent(monkeypatch):
    with FakeFtpServer(replies={**_NO_MLSD, "SIZE": b"550 no\r\n"}) as srv:
        s = _session(srv)
        ftp = s._ensure_connected()

        def cwd(path):
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

        monkeypatch.setattr(ftp, "cwd", cwd)
        with pytest.raises(OSError):
            s.is_dir("/dir")
        with pytest.raises(OSError):
            s.exists("/dir")


def test_edge_a_refused_size_still_falls_back_to_cwd():
    """SIZE refused with any 5xx (unsupported, a folder): CWD decides."""
    replies = {**_NO_MLSD, "SIZE": b"502 SIZE not implemented\r\n", "CWD": b"250 ok\r\n"}
    with FakeFtpServer(replies=replies) as srv:
        assert _session(srv).exists("/dir") is True


def test_edge_550_to_both_probes_means_absent():
    replies = {**_NO_MLSD, "SIZE": b"550 no\r\n", "CWD": b"550 No such directory\r\n"}
    with FakeFtpServer(replies=replies) as srv:
        s = _session(srv)
        assert s.exists("/missing") is False
        assert s.is_dir("/missing") is False


def test_edge_a_file_on_the_way(tree):
    assert tree.exists("/a.txt/b") is False
    assert tree.is_dir("/a.txt/b") is False


# --- the same probes inside stat() and list_dir() -------------------------


def test_sad_stat_of_a_lost_login_is_not_file_not_found():
    """stat() asked the same CWD probe and the parent's NLST: a 530 to
    every probe made it raise FileNotFoundError ("no such file")."""
    replies = {
        **_NO_MLSD,
        "SIZE": b"530 Not logged in\r\n",
        "MDTM": b"530 Not logged in\r\n",
        "CWD": b"530 Not logged in\r\n",
        "NLST": b"530 Not logged in\r\n",
    }
    with FakeFtpServer(replies=replies) as srv:
        with pytest.raises(OSError, match="530") as err:
            _session(srv).stat("/a.txt")
    assert not isinstance(err.value, FileNotFoundError)


def test_edge_stat_of_a_missing_path_is_still_file_not_found(tree):
    with pytest.raises(FileNotFoundError):
        tree.stat("/missing")
    with pytest.raises(FileNotFoundError):
        tree.stat("/nodir/missing")


# --- a server that refuses SIZE for a file ---------------------------------


@pytest.fixture
def no_size_tree(tmp_path):
    """vsftpd answers SIZE in ASCII mode with "550 Could not get file
    size": the same code as "no such file"."""
    root = tmp_path / "srv"
    (root / "dir").mkdir(parents=True)
    (root / "dir" / "inner.bin").write_bytes(b"x")
    (root / "a.txt").write_text("keep")
    srv = _DirFtpServer(root, size=False)
    s = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
    yield s
    s.disconnect()
    srv.close()


def test_happy_a_file_is_present_when_size_is_refused(no_size_tree):
    """SIZE 550 and CWD 550 ("not a dir") for a FILE made exists() say
    False, and a no-clobber copy then overwrote the file."""
    assert no_size_tree.exists("/a.txt") is True
    assert no_size_tree.exists("/dir/inner.bin") is True


def test_sad_a_no_clobber_copy_onto_a_file_without_size_is_refused(no_size_tree, monkeypatch):
    from core.server_ops import server_side_copy

    s = no_size_tree
    written = []
    monkeypatch.setattr(s, "copy", lambda src, dst: written.append(dst))
    monkeypatch.setattr(s, "open_write", lambda path, append=False: written.append(path))
    with pytest.raises((FileExistsError, OSError)):
        server_side_copy(s, "/dir/inner.bin", "/a.txt", overwrite=False)
    assert written == []


def test_edge_without_size_a_missing_name_and_a_file_on_the_way_stay_absent(no_size_tree):
    s = no_size_tree
    assert s.exists("/missing") is False
    assert s.exists("/dir/missing.bin") is False
    assert s.exists("/nodir/missing") is False
    assert s.exists("/a.txt/b") is False
    assert s.exists("/dir") is True


def test_sad_without_size_a_refused_parent_listing_is_an_oserror():
    """CWD says 550 for a file; the parent listing then decides, and a
    530 to NLST is no answer, not "absent"."""
    replies = {
        **_NO_MLSD,
        "SIZE": b"550 Could not get file size.\r\n",
        "CWD": b"550 not a dir\r\n",
        "NLST": b"530 Not logged in\r\n",
    }
    with FakeFtpServer(replies=replies) as srv:
        with pytest.raises(OSError, match="530"):
            _session(srv).exists("/a.txt")
