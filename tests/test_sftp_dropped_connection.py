"""SFTP calls on a connection the server dropped raise OSError.

paramiko's SFTPClient turns EOF on the channel into
SSHException("Server connection dropped") (sftp_client._read_response),
which is not an OSError. SSHSession.list_dir / stat / is_dir / exists /
open_read ... let it through to callers that handle OSError (found by
tests/test_fuzz_sftp.py, a server closing the transport mid-request).
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import paramiko
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


class _DroppingSftp:
    """An SFTPClient whose every request finds the connection gone."""

    def __getattr__(self, name):
        def call(*args, **kwargs):
            raise paramiko.SSHException("Server connection dropped: ")

        return call


class _EofSftp:
    def __getattr__(self, name):
        def call(*args, **kwargs):
            raise EOFError()

        return call


def _session(sftp) -> SSHSession:
    s = SSHSession.__new__(SSHSession)
    s._profile = ConnectionProfile(name="t", protocol="sftp", host="h", username="u")
    type(s).sftp  # property exists
    patcher = mock.patch.object(
        SSHSession, "sftp", new_callable=mock.PropertyMock, return_value=sftp
    )
    patcher.start()
    s._patcher = patcher
    return s


OPS = {
    "list_dir": lambda s: s.list_dir("/"),
    "stat": lambda s: s.stat("/a"),
    "is_dir": lambda s: s.is_dir("/a"),
    "exists": lambda s: s.exists("/a"),
    "mkdir": lambda s: s.mkdir("/d"),
    "remove": lambda s: s.remove("/a"),
    "rename": lambda s: s.rename("/a", "/b"),
    "open_read": lambda s: s.open_read("/a"),
    "open_write": lambda s: s.open_write("/a"),
    "chmod": lambda s: s.chmod("/a", 0o644),
    "readlink": lambda s: s.readlink("/a"),
}


def test_happy_a_working_listing_still_lists():
    from tests.sftp_testkit import SftpServer

    tmp = Path(tempfile.mkdtemp()).resolve()
    try:
        (tmp / "srv").mkdir()
        (tmp / "srv" / "a.txt").write_bytes(b"x")
        home = tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        with mock.patch("pathlib.Path.home", return_value=home):
            srv = SftpServer(str(tmp / "srv"))
            profile = ConnectionProfile(
                name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"
            )
            s = SSHSession(profile)
            s.connect(password="x", on_unknown_host=lambda _e: True)
            try:
                assert [i.name for i in s.list_dir("/")] == ["a.txt"]
            finally:
                s.disconnect()
                srv.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.mark.parametrize("op", list(OPS))
@pytest.mark.parametrize("sftp", [_DroppingSftp(), _EofSftp()], ids=["ssh-exception", "eof"])
def test_sad_dropped_connection_is_an_oserror(op, sftp):
    s = _session(sftp)
    try:
        if op in ("is_dir", "exists"):
            # Not a "no": the answer is unknown, so the failure surfaces.
            with pytest.raises(OSError):
                OPS[op](s)
        else:
            with pytest.raises(OSError, match="connection"):
                OPS[op](s)
    finally:
        s._patcher.stop()


class _DroppingFile:
    """An SFTPFile whose connection dies after the open."""

    handle = b"h"

    def __init__(self) -> None:
        self.sftp = self

    def stat(self):
        return type("St", (), {"st_size": 10 * 1024 * 1024})()

    def readv(self, chunks):
        raise paramiko.SSHException("Server connection dropped: ")

    def seek(self, pos):
        pass

    def read(self, n):
        raise paramiko.SSHException("Server connection dropped: ")

    def _async_request(self, *a):
        raise paramiko.SSHException("Server connection dropped: ")

    _expecting: dict = {}

    def close(self):
        pass


def test_sad_connection_lost_mid_read_is_an_oserror():
    from core.sftp_io import open_read_ahead

    fh = open_read_ahead(_DroppingFile)
    with pytest.raises(OSError, match="connection"):
        fh.read(1024)
    with pytest.raises(OSError, match="connection"):
        fh.read()


def test_sad_connection_lost_mid_write_is_an_oserror():
    from core.sftp_io import PipelinedWriter

    w = PipelinedWriter(_DroppingFile())
    with pytest.raises(OSError, match="connection"):
        w.write(b"x" * 100)


def test_edge_normalize_falls_back_when_the_connection_dropped():
    s = _session(_DroppingSftp())
    try:
        assert s.normalize("/a/../b") == "/b"
    finally:
        s._patcher.stop()
