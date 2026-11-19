"""An FTP folder holding a file name that is not UTF-8 lists, and the
entry can be read, renamed and removed.

A server that accepts ``OPTS UTF8 ON`` (vsftpd answers it on every build)
still sends names as stored: a latin-1 name on a Linux server is
ordinary. Listings were decoded with replacement characters, so the entry
showed as "lat�.txt" and every command on it asked for a name that is
not there - read, rename and delete answered 550, and a recursive delete
of its folder failed. Now names decode with ``surrogateescape`` (as SFTP
and local file names do) and every command encodes back the same way, so
the name round-trips. Driven against tests/ftp_fs_server.py, with MLSD
and without (NLST + LIST).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fs_server import FtpFsServer  # noqa: E402

from core.ftp_client import FtpSession  # noqa: E402

LATIN1 = b"lat\xe9.txt"


@pytest.fixture(params=["mlsd", "list"])
def session(request, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / os.fsdecode(LATIN1)).write_bytes(b"latin")
    features = None if request.param == "mlsd" else ()
    srv = FtpFsServer(str(root), **({} if features is None else {"features": features}))
    sess = FtpSession("127.0.0.1", srv.port, "u", "p")
    yield sess, os.fsencode(root)
    sess.close()
    srv.close()


def _the_name(sess) -> str:
    names = [item.name for item in sess.list_dir("/")]
    assert len(names) == 1
    return names[0]


def test_listed_name_keeps_its_bytes(session):
    sess, _root = session
    name = _the_name(sess)
    assert "�" not in name
    assert name.encode("utf-8", "surrogateescape") == LATIN1


def test_entry_can_be_read(session):
    sess, _root = session
    with sess.open_read("/" + _the_name(sess)) as fh:
        assert fh.read() == b"latin"


def test_entry_can_be_renamed_and_removed(session):
    sess, root = session
    name = _the_name(sess)
    sess.rename("/" + name, "/" + name + ".old")
    assert os.listdir(root) == [LATIN1 + b".old"]
    sess.remove("/" + name + ".old")
    assert os.listdir(root) == []


def test_upload_under_such_a_name(session):
    sess, root = session
    name = "new\udcff.bin"  # a byte 0xff, not UTF-8
    with sess.open_write("/" + name) as fh:
        fh.write(b"data")
    assert (root + b"/new\xff.bin") in [root + b"/" + n for n in os.listdir(root)]
