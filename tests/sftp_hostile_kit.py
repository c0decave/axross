"""A real paramiko SFTP server whose answers are scripted, for the SFTP
fuzz and regression suites.

``hostile_session()`` yields ``(script, session)``: an SSHSession connected
to the server and the ``_Script`` that decides what the server answers -
listings (SFTPAttributes, names may be bytes), stat results, file content,
a ``read_hook(offset, length) -> bytes | status`` for READ answers, and
``drop`` to close the connection on the next request.
"""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import paramiko
from paramiko import SFTPAttributes, SFTPHandle, SFTPServer
from paramiko.sftp import SFTP_FAILURE, SFTP_OK
from sftp_testkit import SftpServer, _Auth, _host_key, _Sftp

from core.profiles import ConnectionProfile
from core.ssh_client import SSHSession


def attr(name, size=5, mode=0o100644, mtime=1_700_000_000, uid=1000) -> SFTPAttributes:
    a = SFTPAttributes()
    a.filename = name
    a.st_size = size
    a.st_mode = mode
    a.st_mtime = mtime
    a.st_atime = mtime
    a.st_uid = uid
    a.st_gid = uid
    return a


class _Script:
    def __init__(self) -> None:
        self.listing: object = [attr("a.txt"), attr("sub", mode=0o040755)]
        self.stat: object = attr("a.txt")
        self.data = b"hello"
        self.read_hook = None
        self.drop = False
        self.transports: list = []

    def maybe_drop(self) -> bool:
        if self.drop:
            for t in self.transports:
                t.close()
            return True
        return False


class _ScriptedHandle(SFTPHandle):
    def __init__(self, script) -> None:
        super().__init__()
        self.script = script

    def read(self, offset, length):
        if self.script.maybe_drop():
            return SFTP_FAILURE
        if self.script.read_hook is not None:
            return self.script.read_hook(offset, length)
        return self.script.data[offset : offset + length]

    def stat(self):
        st = self.script.stat
        return st if not isinstance(st, SFTPAttributes) else attr("f", size=len(self.script.data))

    def close(self):
        return SFTP_OK


class _HostileSftp(_Sftp):
    def __init__(self, server, *args, script=None, **kw) -> None:
        super().__init__(server, *args, **kw)
        self.script = script

    def list_folder(self, path):
        if self.script.maybe_drop():
            return []
        return self.script.listing

    def stat(self, path):
        if self.script.maybe_drop():
            return SFTP_FAILURE
        return self.script.stat

    lstat = stat

    def remove(self, path):
        return SFTP_FAILURE if self.script.maybe_drop() else SFTP_OK

    def rmdir(self, path):
        return SFTP_FAILURE if self.script.maybe_drop() else SFTP_OK

    def open(self, path, flags, attr_):
        if self.script.maybe_drop():
            return SFTP_FAILURE
        return _ScriptedHandle(self.script)


class HostileSftpServer(SftpServer):
    def __init__(self) -> None:
        self.script = _Script()
        super().__init__("/nonexistent")

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(_host_key())
            t.set_subsystem_handler("sftp", SFTPServer, _HostileSftp, script=self.script)
            t.start_server(server=_Auth())
            self._transports.append(t)
            self.script.transports.append(t)


@contextlib.contextmanager
def hostile_session():
    tmp = Path(tempfile.mkdtemp())
    home = tmp / "home"
    (home / ".ssh").mkdir(parents=True)
    patcher = mock.patch("pathlib.Path.home", return_value=home)
    patcher.start()
    srv = HostileSftpServer()
    profile = ConnectionProfile(
        name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"
    )
    s = SSHSession(profile)
    s.connect(password="x", on_unknown_host=lambda _e: True)
    try:
        yield srv.script, s
    finally:
        try:
            s.disconnect()
        except Exception:  # noqa: BLE001 - teardown after a dropped connection
            pass
        srv.close()
        patcher.stop()
        shutil.rmtree(tmp, ignore_errors=True)
