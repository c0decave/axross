"""SFTP is_dir() says False only for "not found".

SSHSession.is_dir caught every OSError from lstat and answered False:
SFTP_PERMISSION_DENIED (PermissionError), SFTP_FAILURE (a bare IOError,
what OpenSSH sends for EIO, ESTALE ...), a socket timeout or reset, and
the ConnectionError of a session that is not connected. exists() was
already narrow (FileNotFoundError only). is_dir() decides whether the
transfer manager recurses into a source and whether remove() and
server_ops' replace-through-a-backup treat a path as a folder or a file;
a refused or failed lstat says neither.
"""

from __future__ import annotations

import errno
import stat as stat_module
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("paramiko")

from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


class _Sftp:
    """lstat() of a small tree; ``fail`` answers every lstat with it."""

    def __init__(self, fail: BaseException | None = None):
        self.fail = fail

    def lstat(self, path):
        if self.fail is not None:
            raise self.fail
        if path == "/dir":
            return SimpleNamespace(st_mode=stat_module.S_IFDIR | 0o755)
        if path == "/a.txt":
            return SimpleNamespace(st_mode=stat_module.S_IFREG | 0o644)
        # paramiko: SFTP_NO_SUCH_FILE -> IOError(errno.ENOENT, text)
        raise OSError(errno.ENOENT, "No such file")


@pytest.fixture
def session():
    patchers = []

    def make(sftp=None, *, not_connected: bool = False):
        s = SSHSession.__new__(SSHSession)
        s._profile = ConnectionProfile(name="t", protocol="sftp", host="h", username="u")
        if not_connected:
            prop = mock.PropertyMock(side_effect=ConnectionError("Not connected"))
        else:
            prop = mock.PropertyMock(return_value=sftp)
        patcher = mock.patch.object(SSHSession, "sftp", new_callable=lambda: prop)
        patcher.start()
        patchers.append(patcher)
        return s

    yield make
    for p in patchers:
        p.stop()


def test_happy_folder_file_and_absent(session):
    s = session(_Sftp())
    assert s.is_dir("/dir") is True
    assert s.is_dir("/a.txt") is False
    assert s.is_dir("/missing") is False
    assert s.exists("/a.txt") is True
    assert s.exists("/missing") is False


@pytest.mark.parametrize(
    "fail",
    [
        OSError(errno.EACCES, "Permission denied"),  # SFTP_PERMISSION_DENIED
        OSError("Failure"),  # SFTP_FAILURE
        TimeoutError("timed out"),
        ConnectionResetError("reset by peer"),
    ],
    ids=["permission", "failure", "timeout", "reset"],
)
def test_sad_a_failed_lstat_is_an_oserror_not_a_file(session, fail):
    s = session(_Sftp(fail))
    with pytest.raises(OSError):
        s.is_dir("/dir")
    with pytest.raises(OSError):
        s.exists("/dir")


def test_sad_not_connected_is_an_oserror(session):
    s = session(not_connected=True)
    with pytest.raises(OSError, match="Not connected"):
        s.is_dir("/dir")


def test_edge_a_file_on_the_way_is_no_folder(session):
    s = session(_Sftp(NotADirectoryError(errno.ENOTDIR, "Not a directory")))
    assert s.is_dir("/a.txt/b") is False
