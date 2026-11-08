"""FTP: the HASH reply is parsed field by field; control characters in a
path are an OSError before anything is sent.

* ``HASH`` answers ``213 <algo> <range> <hash> <name>``
  (draft-bryan-ftpext-hash). checksum() took the LAST token for the hash:
  that is the file name, and a name that happened to be hex was returned
  as the file's checksum.
* A path with CR/LF made ftplib raise ValueError (no OSError, so the pane
  and the transfer engine did not catch it); other C0 characters went to
  the server's command parser as they were. Every FTP path now goes
  through core.path_policy.refuse_control_chars: OSError (EINVAL).
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SERVER_MD5 = "a" * 32


@pytest.fixture
def ftp():
    def server(replies):
        srv = FakeFtpServer(
            replies={"FEAT": b"211-x\r\n MLST type*;size*;\r\n211 end\r\n", **replies},
            data={"MLSD": b"type=file;size=1; a\r\n"},
        )
        made.append(srv)
        return FC.FtpSession(srv.host, srv.port, "u", "p"), srv

    made: list = []
    yield server
    for srv in made:
        srv.close()


# -- happy -------------------------------------------------------------------


def test_happy_the_hash_field_of_a_hash_reply_is_returned(ftp):
    session, _ = ftp({"HASH": f"213 MD5 0-0 {SERVER_MD5} {EMPTY_MD5}\r\n".encode()})
    assert session.checksum(f"/{EMPTY_MD5}", "md5") == f"md5:{SERVER_MD5}"


def test_happy_an_xmd5_reply_still_gives_its_digest(ftp):
    session, _ = ftp({"HASH": b"502 no\r\n", "XMD5": f"250 {SERVER_MD5}\r\n".encode()})
    assert session.checksum("/x", "md5") == f"md5:{SERVER_MD5}"


# -- sad ---------------------------------------------------------------------


def test_sad_a_hash_reply_without_a_hash_field_is_no_checksum(ftp):
    # The hash field is no digest; only the name is hex - not the file's hash.
    reply = f"213 MD5 0-0 pending {EMPTY_MD5}\r\n".encode()
    session, _ = ftp({"HASH": reply, "XMD5": b"502 no\r\n"})
    assert session.checksum("/x", "md5") == ""


@pytest.mark.parametrize(
    "op",
    [
        lambda s: s.stat("/a\r\nDELE /x"),
        lambda s: s.mkdir("/a\nb"),
        lambda s: s.rename("/a", "/b\r\nDELE /etc"),
        lambda s: s.remove("/a\nb"),
        lambda s: s.list_dir("/a\nb"),
        lambda s: s.open_read("/a\nb"),
        lambda s: s.open_write("/a\nb"),
        lambda s: s.exists("/a\x00b"),
        lambda s: s.is_dir("/a\x15b"),
        lambda s: s.checksum("/a\nb", "md5"),
    ],
    ids=[
        "stat", "mkdir", "rename", "remove", "list_dir",
        "open_read", "open_write", "exists-NUL", "is_dir-NAK", "checksum",
    ],
)
def test_sad_a_control_character_path_is_an_oserror_and_sends_nothing(ftp, op):
    session, srv = ftp({"DELE": b"250 ok\r\n", "MKD": b"257 ok\r\n"})
    before = list(srv.commands)
    with pytest.raises(OSError) as info:
        op(session)
    assert info.value.errno == errno.EINVAL
    assert srv.commands == before


# -- edge --------------------------------------------------------------------


def test_edge_a_name_with_blanks_after_the_hash_field_is_ignored(ftp):
    reply = f"213 SHA-256 0-9 {'b' * 64} my {'c' * 64}.iso\r\n".encode()
    session, _ = ftp({"HASH": reply})
    assert session.checksum("/my x.iso", "sha256") == "sha256:" + "b" * 64


def test_edge_mlst_and_cwd_refuse_crlf_as_oserror():
    session = FC.FtpSession.__new__(FC.FtpSession)
    for op in (lambda: session.mlst("/x\r\nQUIT"), lambda: session.cwd("/x\nLIST")):
        with pytest.raises(OSError):
            op()
