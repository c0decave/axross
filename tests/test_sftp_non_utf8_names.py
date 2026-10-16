"""An SFTP folder holding a file name that is not UTF-8 still lists.

SFTP v3 file names are bytes; OpenSSH sends them as stored, so a latin-1
name on a Linux server is ordinary. paramiko decodes every name strictly
as UTF-8 (Message.get_text -> util.u), so SFTPClient.listdir_attr raised
UnicodeDecodeError and the whole folder could not be listed - an error
nothing catches (found by tests/test_fuzz_sftp.py). Names are now decoded
with replacement characters, as the FTP backend does. The twin: paramiko's
readlink() hands back BYTES for a target that is not UTF-8
(sftp_client._to_unicode), which SSHSession.readlink returned as is to
callers expecting str; it is decoded the same way now.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import paramiko  # noqa: E402
from paramiko import SFTPAttributes, SFTPServer  # noqa: E402
from sftp_testkit import SftpServer, _Auth, _host_key, _Sftp  # noqa: E402

from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


class _BytesNamesSftp(_Sftp):
    """Sends names and link targets as the bytes stored on disk, the way
    OpenSSH's sftp-server does (the stock test server encodes them as
    UTF-8 and fails on anything else)."""

    def list_folder(self, path):
        real = os.fsencode(self._real(path))
        out = []
        try:
            for name in os.listdir(real):
                a = SFTPAttributes.from_stat(os.lstat(os.path.join(real, name)))
                a.filename = name  # bytes
                out.append(a)
        except OSError as exc:
            return self._err(exc)
        return out

    def readlink(self, path):
        try:
            return os.readlink(os.fsencode(self._real(path)))  # bytes
        except OSError as exc:
            return self._err(exc)


class _BytesServer(SftpServer):
    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(_host_key())
            t.set_subsystem_handler(
                "sftp", SFTPServer, _BytesNamesSftp, root=self.root, stats=self.stats
            )
            t.start_server(server=_Auth())
            self._transports.append(t)


@pytest.fixture
def remote():
    tmp = Path(tempfile.mkdtemp()).resolve()
    root = tmp / "srv"
    root.mkdir()
    home = tmp / "home"
    (home / ".ssh").mkdir(parents=True)
    patcher = mock.patch("pathlib.Path.home", return_value=home)
    patcher.start()
    srv = _BytesServer(str(root))
    profile = ConnectionProfile(
        name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"
    )
    s = SSHSession(profile)
    s.connect(password="x", on_unknown_host=lambda _e: True)
    try:
        yield root, s
    finally:
        s.disconnect()
        srv.close()
        patcher.stop()
        shutil.rmtree(tmp, ignore_errors=True)


def test_happy_utf8_names_list(remote):
    root, s = remote
    (root / "café.txt").write_bytes(b"x")
    assert [i.name for i in s.list_dir("/")] == ["café.txt"]


def test_sad_latin1_name_lists_with_a_replacement_character(remote):
    root, s = remote
    with open(os.fsencode(str(root)) + b"/caf\xe9.txt", "wb") as fh:
        fh.write(b"x")
    (root / "ok.txt").write_bytes(b"yy")
    items = {i.name: i for i in s.list_dir("/")}
    assert set(items) == {"caf�.txt", "ok.txt"}
    assert items["ok.txt"].size == 2


def test_edge_non_utf8_symlink_target_reads_as_str(remote):
    root, s = remote
    os.symlink(os.fsencode(str(root)) + b"/t\xe9", str(root / "link"))
    target = s.readlink("/link")
    assert isinstance(target, str)
    assert target.endswith("/t�")


def test_happy_utf8_symlink_target(remote):
    root, s = remote
    os.symlink(str(root) + "/tö", str(root / "link"))
    assert s.readlink("/link").endswith("/tö")


def test_edge_recursive_delete_lists_non_utf8_children(remote):
    root, s = remote
    (root / "d").mkdir()
    (root / "d" / "plain.txt").write_bytes(b"x")
    with open(os.fsencode(str(root)) + b"/d/\xff.bin", "wb") as fh:
        fh.write(b"x")
    # The undecodable child cannot be addressed by its replaced name: the
    # delete fails cleanly instead of raising UnicodeDecodeError.
    with pytest.raises(OSError):
        s.remove("/d", recursive=True)
