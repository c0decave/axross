"""An SFTP folder holding a file name that is not UTF-8 still lists.

SFTP v3 file names are bytes; OpenSSH sends them as stored, so a latin-1
name on a Linux server is ordinary. paramiko decodes every name strictly
as UTF-8 (Message.get_text -> util.u), so SFTPClient.listdir_attr raised
UnicodeDecodeError and the whole folder could not be listed - an error
nothing catches (found by tests/test_fuzz_sftp.py). The twin: paramiko's
readlink() hands back BYTES for a target that is not UTF-8
(sftp_client._to_unicode), which SSHSession.readlink returned as is to
callers expecting str.

Names were then decoded with replacement characters: the entry showed but
could not be used - stat, open and remove asked for a name that is not
there, and a recursive delete of its folder failed with "No such file".
Now names and link targets decode with ``surrogateescape`` (as Python
decodes a local file name) and every request path encodes back the same
way (core.ssh_client._SurrogateSftpClient), so such a name round-trips.
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
from paramiko import SFTPAttributes  # noqa: E402
from sftp_testkit import (  # noqa: E402
    SftpServer,
    _Auth,
    _BytesPathSftpServer,
    _host_key,
    _Sftp,
)

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
                "sftp", _BytesPathSftpServer, _BytesNamesSftp, root=self.root, stats=self.stats
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


def test_sad_latin1_name_lists_as_python_decodes_a_local_name(remote):
    root, s = remote
    with open(os.fsencode(str(root)) + b"/caf\xe9.txt", "wb") as fh:
        fh.write(b"x")
    (root / "ok.txt").write_bytes(b"yy")
    items = {i.name: i for i in s.list_dir("/")}
    assert set(items) == {"caf\udce9.txt", "ok.txt"}
    assert set(items) == set(os.listdir(str(root)))  # LocalFS's name for it
    assert items["ok.txt"].size == 2


def test_sad_latin1_name_can_be_used_by_its_listed_name(remote):
    root, s = remote
    raw = os.fsencode(str(root)) + b"/caf\xe9.txt"
    with open(raw, "wb") as fh:
        fh.write(b"latin")
    name = next(i.name for i in s.list_dir("/"))
    assert s.stat("/" + name).size == 5
    with s.open_read("/" + name) as fh:
        assert fh.read() == b"latin"
    s.rename("/" + name, "/caf\udce9-2.txt")
    assert os.path.exists(os.fsencode(str(root)) + b"/caf\xe9-2.txt")
    with s.open_write("/new\udcff.bin") as fh:
        fh.write(b"w")
    assert open(os.fsencode(str(root)) + b"/new\xff.bin", "rb").read() == b"w"
    s.remove("/caf\udce9-2.txt")
    assert sorted(os.listdir(os.fsencode(str(root)))) == [b"new\xff.bin"]


def test_edge_non_utf8_symlink_target_reads_as_str(remote):
    root, s = remote
    os.symlink(os.fsencode(str(root)) + b"/t\xe9", str(root / "link"))
    target = s.readlink("/link")
    assert isinstance(target, str)
    assert target.endswith("/t\udce9")
    assert os.fsencode(target) == os.fsencode(str(root)) + b"/t\xe9"


def test_happy_utf8_symlink_target(remote):
    root, s = remote
    os.symlink(str(root) + "/tö", str(root / "link"))
    assert s.readlink("/link").endswith("/tö")


def test_edge_recursive_delete_removes_non_utf8_children(remote):
    root, s = remote
    (root / "d").mkdir()
    (root / "d" / "plain.txt").write_bytes(b"x")
    with open(os.fsencode(str(root)) + b"/d/\xff.bin", "wb") as fh:
        fh.write(b"x")
    # Each child is addressed by the bytes it was listed with.
    s.remove("/d", recursive=True)
    assert not (root / "d").exists()
