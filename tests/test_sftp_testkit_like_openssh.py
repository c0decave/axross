"""tests/sftp_testkit.py answers as OpenSSH's sftp-server does, and what
SSHSession does about it.

The kit's plain SSH_FXP_RENAME replaced an existing target (OpenSSH
refuses with SSH_FX_FAILURE; only posix-rename@openssh.com replaces) and
its SETSTAT did nothing, so the suite could not see what a real server
answers: rename_no_replace "worked" over an existing file, and a
rename_with_attributes whose attributes were never applied passed. With
the kit fixed, two real gaps showed: rename_no_replace onto an existing
file was a bare OSError ("Failure"), not FileExistsError, and list_dir of
a FILE was FileNotFoundError (OpenSSH maps ENOTDIR to SSH_FX_NO_SUCH_FILE),
not NotADirectoryError.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest import mock

import paramiko
import pytest

from core.profiles import ConnectionProfile
from core.ssh_client import SSHSession
from tests.sftp_testkit import SftpServer


@pytest.fixture
def remote(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    with mock.patch("pathlib.Path.home", return_value=home):
        srv = SftpServer(str(root))
        s = SSHSession(ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                         port=srv.port, username="u"))
        s.connect(password="x", on_unknown_host=lambda _e: True)
        try:
            yield root, s
        finally:
            s.disconnect()
            srv.close()


def _files(root: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}


def test_happy_the_kit_refuses_plain_rename_onto_an_existing_file(remote):
    root, s = remote
    (root / "a").write_bytes(b"A")
    (root / "b").write_bytes(b"B")
    with pytest.raises(IOError):
        s.sftp.rename("/a", "/b")  # paramiko's plain SSH_FXP_RENAME
    assert _files(root) == {"a": b"A", "b": b"B"}
    s.sftp.posix_rename("/a", "/b")
    assert _files(root) == {"b": b"A"}


def test_happy_the_kit_applies_setstat(remote):
    root, s = remote
    (root / "a").write_bytes(b"A")
    s.set_attributes("/a", mode=0o600, mtime=1_000_000_000)
    st = os.stat(root / "a")
    assert stat.S_IMODE(st.st_mode) == 0o600
    assert int(st.st_mtime) == 1_000_000_000


def test_sad_rename_no_replace_onto_an_existing_file_is_file_exists(remote):
    root, s = remote
    (root / "a").write_bytes(b"A")
    (root / "b").write_bytes(b"B")
    with pytest.raises(FileExistsError):
        s.rename_no_replace("/a", "/b")
    assert _files(root) == {"a": b"A", "b": b"B"}
    with pytest.raises(FileNotFoundError):
        s.rename_no_replace("/missing", "/c")


def test_happy_rename_replaces_through_posix_rename(remote):
    root, s = remote
    (root / "a").write_bytes(b"A")
    (root / "b").write_bytes(b"B")
    s.rename("/a", "/b")
    assert _files(root) == {"b": b"A"}


def test_edge_rename_with_attributes_sets_them_and_replaces(remote):
    root, s = remote
    (root / "a").write_bytes(b"A")
    (root / "b").write_bytes(b"B")
    assert s.rename_with_attributes("/a", "/b", mode=0o640, mtime=1_234_567_890) is True
    st = os.stat(root / "b")
    assert (root / "b").read_bytes() == b"A"
    assert stat.S_IMODE(st.st_mode) == 0o640 and int(st.st_mtime) == 1_234_567_890


def test_sad_list_dir_of_a_file_is_not_a_directory(remote):
    root, s = remote
    (root / "g").write_bytes(b"other")
    with pytest.raises(NotADirectoryError):
        s.list_dir("/g")
    with pytest.raises(FileNotFoundError):
        s.list_dir("/nope")
    # "g/" names a folder: OpenSSH answers ENOTDIR as "no such file".
    with pytest.raises(FileNotFoundError):
        s.stat("/g/")
    with pytest.raises(OSError):
        s.rename("/g", "/x/")
    assert _files(root) == {"g": b"other"}


def test_edge_paramiko_version_has_bytes_paths():
    """The surrogateescape encoding relies on SFTPClient._adjust_cwd
    taking bytes (paramiko.util.b passes them through)."""
    assert paramiko.util.b(b"caf\xe9") == b"caf\xe9"
