"""FtpSession against servers that send what they should not.

Found by the FTP fuzz suite (tests/test_fuzz_ftp.py); each case here pins
one defect: the backend contract is OSError, which is all the pane, the
transfer worker and compare catch.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402


@pytest.fixture(autouse=True)
def _short_timeouts(monkeypatch):
    import ftplib

    orig = ftplib.FTP.connect

    def connect(self, host="", port=0, timeout=-999, source_address=None):
        return orig(self, host, port, 2.0, source_address)

    monkeypatch.setattr(ftplib.FTP, "connect", connect)


def _session(srv: FakeFtpServer) -> FC.FtpSession:
    return FC.FtpSession(srv.host, srv.port, "u", "p")


# --- listing bytes that are not valid in the negotiated encoding ----------
def test_happy_utf8_listing_names_decode():
    with FakeFtpServer(data={"MLSD": "type=file;size=3; café.txt\r\n".encode()}) as srv:
        assert [i.name for i in _session(srv).list_dir("/")] == ["café.txt"]


@pytest.mark.parametrize(
    "payload, expected",
    [
        (b"type=file;size=3; caf\xe9.txt\r\ntype=file;size=1; ok\r\n", ["caf�.txt", "ok"]),
        (b"type=file;size=3; \xff\xfe\r\n", ["��"]),
    ],
    ids=["latin1-name", "garbage-name"],
)
def test_sad_undecodable_mlsd_names_list_with_replacement(payload, expected):
    """A server that accepted OPTS UTF8 but lists latin-1 names: the
    listing shows (replacement characters, like the control channel),
    instead of a UnicodeDecodeError nobody catches."""
    with FakeFtpServer(data={"MLSD": payload}) as srv:
        assert [i.name for i in _session(srv).list_dir("/")] == expected


def test_sad_undecodable_nlst_and_list_fallback():
    with FakeFtpServer(
        replies={"MLSD": b"500 no\r\n", "MLST": b"500 no\r\n", "SIZE": b"213 3\r\n"},
        data={
            "NLST": b"caf\xe9\r\nok\r\n",
            "LIST": b"-rw-r--r-- 1 a b 3 Jan  1 12:00 caf\xe9\r\n"
            b"-rw-r--r-- 1 a b 3 Jan  1 12:00 ok\r\n",
        },
    ) as srv:
        s = _session(srv)
        assert not s._has_mlsd
        items = s.list_dir("/")
        assert [i.name for i in items] == ["caf�", "ok"]
        assert all(i.size == 3 for i in items)


def test_edge_truncated_multibyte_sequence_at_end_of_listing():
    with FakeFtpServer(data={"MLSD": b"type=file;size=1; ok\r\ntype=file; \xc3"}) as srv:
        names = [i.name for i in _session(srv).list_dir("/")]
    assert names == ["ok", "�"]


# --- a 213 SIZE reply whose size is not a number --------------------------
_NO_MLSD = {"MLSD": b"500 no\r\n", "MLST": b"500 no\r\n"}


def test_happy_size_reply_means_the_file_exists():
    with FakeFtpServer(replies={**_NO_MLSD, "SIZE": b"213 1234\r\n"}) as srv:
        s = _session(srv)
        assert s.exists("/f") is True
        assert s.stat("/f").size == 1234


@pytest.mark.parametrize("reply", [b"213 abc\r\n", b"213 \r\n", b"213 1e9\r\n", b"213 12 34\r\n"])
def test_sad_unparsable_213_size_still_means_exists(reply):
    """ftplib.FTP.size() does int() on the reply text and raises ValueError
    for "213 abc"; the server said 213 (the file is there)."""
    with FakeFtpServer(replies={**_NO_MLSD, "SIZE": reply}) as srv:
        s = _session(srv)
        assert s.exists("/f") is True
        assert s.stat("/f").size == 0


def test_edge_size_refused_falls_back_to_cwd_probe():
    with FakeFtpServer(replies={**_NO_MLSD, "SIZE": b"550 no\r\n", "CWD": b"550 no\r\n"}) as srv:
        assert _session(srv).exists("/missing") is False


# --- a name the session encoding cannot carry -----------------------------
_LATIN1 = {"OPTS": b"501 no utf8\r\n", "MKD": b'257 "/x" created\r\n'}


def test_happy_latin1_name_on_latin1_server():
    with FakeFtpServer(replies=_LATIN1) as srv:
        s = _session(srv)
        assert s._ftp.encoding == "latin-1"
        s.mkdir("/café")
        assert b"MKD /caf\xe9\r\n" in srv.raw_commands  # sent as latin-1


@pytest.mark.parametrize("op", ["mkdir", "list_dir", "remove", "rename", "open_read"])
def test_sad_unencodable_name_on_latin1_server_is_an_oserror(op):
    """ftplib encodes every command in the session encoding; a CJK name on
    a latin-1 server raised UnicodeEncodeError out of the backend."""
    name = "/日本"
    calls = {
        "mkdir": lambda s: s.mkdir(name),
        "list_dir": lambda s: s.list_dir(name),
        "remove": lambda s: s.remove(name),
        "rename": lambda s: s.rename(name, "/b"),
        "open_read": lambda s: s.open_read(name),
    }
    with FakeFtpServer(replies=_LATIN1) as srv:
        s = _session(srv)
        with pytest.raises(OSError, match="cannot be encoded"):
            calls[op](s)


def test_edge_lone_surrogate_name_on_utf8_server_is_an_oserror():
    with FakeFtpServer(data={"MLSD": b""}) as srv:
        s = _session(srv)
        assert s._ftp.encoding == "utf-8"
        with pytest.raises(OSError, match="cannot be encoded"):
            s.mkdir("/caf\udce9")
