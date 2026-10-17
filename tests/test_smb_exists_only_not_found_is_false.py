"""SMB exists() and is_dir() say False only for "not found".

smbclient.path.exists() / isdir() already answer False only for ENOENT
(STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND) and re-raise
everything else - but SmbSession caught every _SMB_FAILURES around them
and answered False: STATUS_ACCESS_DENIED, a dropped or timed-out
connection, a message that did not verify. server_side_copy(overwrite=
False) and the transfer worker's no-clobber check take False as the
go-ahead to write. Only "not found" (and STATUS_NOT_A_DIRECTORY: a file
where the path needs a folder) means False now.

Driven through the real smbclient.path functions; only the stat call
under them is scripted.
"""

from __future__ import annotations

import stat as stat_module
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("smbprotocol")
from smbprotocol.exceptions import (  # noqa: E402
    NtStatus,
    SMBConnectionClosed,
    SMBException,
    SMBLinkRedirectionError,
    SMBOSError,
)

from core import smb_client as SC  # noqa: E402

PREFIX = "\\\\h\\s"


class _Share:
    """Answers smbclient's stat() for a small tree; ``fail`` answers
    every stat with that exception."""

    def __init__(self):
        self.dirs = {PREFIX, PREFIX + "\\dir"}
        self.files = {PREFIX + "\\a.txt"}
        self.fail: BaseException | None = None

    def stat(self, path, follow_symlinks=True, **kw):
        if self.fail is not None:
            raise self.fail
        if path in self.dirs:
            return SimpleNamespace(st_mode=stat_module.S_IFDIR | 0o755)
        if path in self.files:
            return SimpleNamespace(st_mode=stat_module.S_IFREG | 0o644)
        if path.startswith(PREFIX + "\\a.txt\\"):
            raise SMBOSError(NtStatus.STATUS_NOT_A_DIRECTORY, path)
        raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)


@pytest.fixture
def smb(monkeypatch):
    import smbclient.path as smb_path

    share = _Share()
    monkeypatch.setattr(smb_path, "stat", share.stat)
    s = SC.SmbSession.__new__(SC.SmbSession)
    s._host, s._share, s._port = "h", "s", 445
    s._prefix = PREFIX
    return share, s


FAILURES = [
    SMBOSError(NtStatus.STATUS_ACCESS_DENIED, PREFIX + "\\a.txt"),
    SMBOSError(NtStatus.STATUS_NETWORK_NAME_DELETED, PREFIX + "\\a.txt"),
    SMBOSError(NtStatus.STATUS_IO_TIMEOUT, PREFIX + "\\a.txt"),
    SMBConnectionClosed("SMB socket was closed"),
    SMBException("Server message signature could not be verified"),
    struct.error("unpack requires a buffer of 4 bytes"),
    ConnectionResetError("reset by peer"),
]
FAILURE_IDS = ["access-denied", "name-deleted", "io-timeout", "closed", "signature",
               "short-message", "reset"]


def test_happy_present_and_absent(smb):
    _share, s = smb
    assert s.exists("/a.txt") is True
    assert s.exists("/dir") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/a.txt") is False
    assert s.exists("/missing") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize("fail", FAILURES, ids=FAILURE_IDS)
def test_sad_a_failed_check_is_an_oserror_not_absent(smb, fail):
    share, s = smb
    share.fail = fail
    with pytest.raises(OSError, match="a.txt"):
        s.exists("/a.txt")
    with pytest.raises(OSError, match="dir"):
        s.is_dir("/dir")


def test_sad_no_clobber_copy_keeps_the_target_when_access_is_denied(smb, monkeypatch):
    from core.server_ops import server_side_copy

    share, s = smb
    share.fail = SMBOSError(NtStatus.STATUS_ACCESS_DENIED, PREFIX + "\\b.txt")
    written = []
    monkeypatch.setattr(s, "open_write", lambda path, append=False: written.append(path))
    monkeypatch.setattr(s, "copy", lambda src, dst: written.append(dst))
    with pytest.raises(OSError):
        server_side_copy(s, "/a.txt", "/b.txt", overwrite=False)
    assert written == []


def test_edge_a_file_on_the_way_means_absent(smb):
    _share, s = smb
    assert s.exists("/a.txt/b") is False
    assert s.is_dir("/a.txt/b") is False


def test_edge_a_path_not_found_status_means_absent(smb):
    share, s = smb
    share.fail = SMBOSError(NtStatus.STATUS_OBJECT_PATH_NOT_FOUND, PREFIX + "\\x\\y")
    assert s.exists("/x/y") is False
    assert s.is_dir("/x/y") is False


def test_edge_a_link_to_another_server_is_no_folder_here(smb):
    """smbclient cannot follow it; is_dir() keeps answering False so
    remove() deletes the link itself instead of failing."""
    share, s = smb
    share.fail = SMBLinkRedirectionError("cannot redirect", PREFIX + "\\lnk", "\\\\other\\x")
    assert s.is_dir("/lnk") is False
