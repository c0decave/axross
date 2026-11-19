"""A writable FUSE mount keeps the mode a program asks for: ``create``'s
mode is the new file's from its first byte (ssh-keygen's 0600 key came out
as the server's default, often 0644), and ``chmod`` works - fusepy's
default refused it as "read-only file system". A read-only mount still
refuses it."""
from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest

from core import fuse_mount as FM
from core.local_fs import LocalFS


def _fuse(tmp_path, write_mode="buffer", writeable=True):
    return FM.BackendFuseFS(LocalFS(), str(tmp_path), writeable=writeable,
                            write_mode=write_mode, ttl_stat=0)


@pytest.mark.parametrize("write_mode", ["buffer", "stream"])
def test_happy_a_created_file_has_the_mode_asked_for(tmp_path, write_mode):
    fuse = _fuse(tmp_path, write_mode)
    old = os.umask(0o022)
    try:
        fh = fuse.create("/id_key", 0o600)
        fuse.write("/id_key", b"PRIVATE", 0, fh)
        fuse.flush("/id_key", fh)
        fuse.release("/id_key", fh)
    finally:
        os.umask(old)
    assert (tmp_path / "id_key").read_bytes() == b"PRIVATE"
    assert stat.S_IMODE(os.stat(tmp_path / "id_key").st_mode) == 0o600


def test_happy_chmod_reaches_the_backend(tmp_path):
    (tmp_path / "f").write_text("x")
    os.chmod(tmp_path / "f", 0o644)
    fuse = _fuse(tmp_path)
    fuse.chmod("/f", stat.S_IFREG | 0o600)
    assert stat.S_IMODE(os.stat(tmp_path / "f").st_mode) == 0o600


def test_edge_chmod_before_the_first_commit_is_the_commit_mode(tmp_path):
    fuse = _fuse(tmp_path)
    fh = fuse.create("/new", 0o644)
    fuse.chmod("/new", 0o600)  # install -m600: create, then chmod, then write
    fuse.write("/new", b"secret", 0, fh)
    fuse.release("/new", fh)
    assert stat.S_IMODE(os.stat(tmp_path / "new").st_mode) == 0o600


def test_sad_a_read_only_mount_refuses_chmod(tmp_path):
    (tmp_path / "f").write_text("x")
    fuse = _fuse(tmp_path, writeable=False)
    with pytest.raises(FM.FuseOSError) as info:
        fuse.chmod("/f", 0o600)
    assert info.value.errno == errno.EROFS
