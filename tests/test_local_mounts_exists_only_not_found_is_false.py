"""Local, NFS and iSCSI exists() and is_dir() say False only for "not found".

All three asked the kernel through calls that swallow every error:
``os.path.lexists`` (exists) and ``os.path.isdir`` (NFS is_dir) return
False for any OSError, and LocalFS / iSCSI is_dir caught OSError around
lstat. A soft NFS mount that timed out (ETIMEDOUT, EIO), a stale file
handle (ESTALE), a FUSE mount whose transport is gone (ENOTCONN, EIO), a
folder without search permission (EACCES): each read as "absent" or "no
folder". server_side_copy(overwrite=False) and the transfer worker's
no-clobber check take False from exists() as the go-ahead to write.

Only ENOENT and ENOTDIR (and a name the filesystem cannot hold) mean
False now; every other failure is an OSError.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import iscsi_client, nfs_client  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

FAILURES = [errno.EIO, errno.ESTALE, errno.ETIMEDOUT, errno.ENOTCONN, errno.EACCES]
FAILURE_IDS = ["EIO", "ESTALE", "ETIMEDOUT", "ENOTCONN", "EACCES"]


def _tree(root: Path) -> Path:
    (root / "dir").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"keep")
    os.symlink("a.txt", root / "link")
    os.symlink("nowhere", root / "dangling")
    return root


def _local(root: Path):
    return LocalFS(), str(root)


def _nfs(root: Path):
    s = nfs_client.NfsSession.__new__(nfs_client.NfsSession)
    s._mount_point = str(root)
    return s, ""


def _iscsi(root: Path):
    s = iscsi_client.IscsiSession.__new__(iscsi_client.IscsiSession)
    s._mount_point = str(root)
    return s, ""


BACKENDS = {"local": _local, "nfs": _nfs, "iscsi": _iscsi}


@pytest.fixture(params=list(BACKENDS))
def backend(request, tmp_path):
    root = _tree(tmp_path / "root")
    session, base = BACKENDS[request.param](root)
    return session, base, root


def _failing(monkeypatch, root: Path, code: int) -> None:
    """Every stat of a path under ``root`` fails with ``code``."""
    real_lstat, real_stat = os.lstat, os.stat
    prefix = str(root)

    def fail_or(real):
        def call(path, *args, **kwargs):
            if os.fspath(path).startswith(prefix + os.sep):
                raise OSError(code, os.strerror(code), os.fspath(path))
            return real(path, *args, **kwargs)

        return call

    monkeypatch.setattr(os, "lstat", fail_or(real_lstat))
    monkeypatch.setattr(os, "stat", fail_or(real_stat))


def test_happy_present_and_absent(backend):
    s, base, _root = backend
    assert s.exists(base + "/a.txt") is True
    assert s.exists(base + "/dir") is True
    assert s.is_dir(base + "/dir") is True
    assert s.is_dir(base + "/a.txt") is False
    assert s.exists(base + "/missing") is False
    assert s.is_dir(base + "/missing") is False


@pytest.mark.parametrize("code", FAILURES, ids=FAILURE_IDS)
def test_sad_a_failed_stat_is_an_oserror_not_absent(backend, monkeypatch, code):
    s, base, root = backend
    _failing(monkeypatch, root, code)
    with pytest.raises(OSError) as err:
        s.exists(base + "/a.txt")
    assert err.value.errno == code
    with pytest.raises(OSError) as err:
        s.is_dir(base + "/dir")
    assert err.value.errno == code


def test_sad_no_clobber_copy_keeps_the_target_on_a_stale_handle(backend, monkeypatch):
    from core.server_ops import server_side_copy

    s, base, root = backend
    (root / "new.txt").write_bytes(b"new")
    real_lstat = os.lstat
    target = str(root / "a.txt")

    def lstat(path, *args, **kwargs):
        if os.fspath(path) == target:
            raise OSError(errno.ESTALE, "Stale file handle", target)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(OSError):
        server_side_copy(s, base + "/new.txt", base + "/a.txt", overwrite=False)
    monkeypatch.setattr(os, "lstat", real_lstat)
    assert (root / "a.txt").read_bytes() == b"keep"


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_sad_a_folder_without_search_permission_is_not_empty(tmp_path):
    """Real EACCES: the entry may be there; nobody can say it is not."""
    locked = tmp_path / "locked"
    locked.mkdir()
    (locked / "a.txt").write_bytes(b"keep")
    locked.chmod(0)
    try:
        with pytest.raises(PermissionError):
            LocalFS().exists(str(locked / "a.txt"))
        with pytest.raises(PermissionError):
            LocalFS().is_dir(str(locked / "a.txt"))
    finally:
        locked.chmod(0o700)


def test_edge_a_file_on_the_way_means_absent(backend):
    s, base, _root = backend
    assert s.exists(base + "/a.txt/b") is False
    assert s.is_dir(base + "/a.txt/b") is False


def test_edge_links_are_entries_of_their_own(backend):
    """exists() names the entry itself: a dangling link is there."""
    s, base, _root = backend
    assert s.exists(base + "/dangling") is True
    assert s.exists(base + "/link") is True


def test_edge_a_name_the_filesystem_cannot_hold_is_absent(backend):
    s, base, _root = backend
    assert s.exists(base + "/" + "x" * 4096) is False
    assert s.is_dir(base + "/" + "x" * 4096) is False


def test_edge_local_exists_of_an_embedded_nul_is_absent():
    assert LocalFS().exists("/tmp/a\0b") is False


def test_edge_a_link_out_of_the_mount_is_no_folder(backend, tmp_path):
    s, base, root = backend
    (tmp_path / "outside").mkdir()
    os.symlink(str(tmp_path / "outside"), root / "out")
    assert s.is_dir(base + "/out") is False
    assert s.exists(base + "/out") is True
