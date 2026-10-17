"""atomic_write keeps the saved file's identity where a rename cannot.

Found in review (rounds 1 and 2, data integrity): every local save wrote a
temp file and renamed it over the target. That replaced the inode:

* a hard link to the file kept the OLD text,
* extended attributes (user.*, ACLs) were dropped,
* a writable file in a folder the user cannot write to could not be
  saved at all (the temp file cannot be created there),
* a read-only (0444) file the user owns failed with a confusing error
  about the temp file: it was given the target's mode BEFORE the data
  went in, so the truncating re-open was refused.

The rule now follows vim's ``backupcopy=auto``: a local file is written
IN PLACE when renaming would lose something (more than one hard link, a
folder without write permission, an owner or attribute the new file
cannot get). In place keeps the old bytes recoverable: a backup copy next
to the file when the folder is writable, else the old content in memory,
written back if the save fails part-way.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.atomic_io import atomic_write, atomic_write_stream  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

POSIX = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="POSIX permissions, not root"
)


def _mode(p) -> int:
    return stat.S_IMODE(os.stat(p).st_mode)


def _temps(folder) -> list[str]:
    return sorted(n for n in os.listdir(folder) if n.startswith(".tmp-"))


# --------------------------------------------------------------------------
# Happy path: the ordinary save is still the atomic rename
# --------------------------------------------------------------------------


def test_happy_plain_file_is_replaced_by_rename(tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"old")
    ino = os.stat(p).st_ino
    atomic_write(LocalFS(), str(p), b"new")
    assert p.read_bytes() == b"new"
    # A fresh inode: the atomic temp + rename route was taken.
    assert os.stat(p).st_ino != ino
    assert _temps(tmp_path) == []


def test_happy_hard_link_sees_the_new_content(tmp_path):
    a, b = tmp_path / "config.ini", tmp_path / "config-link.ini"
    a.write_bytes(b"old\n")
    os.link(a, b)
    ino = os.stat(a).st_ino
    atomic_write(LocalFS(), str(a), b"new\n")
    assert a.read_bytes() == b"new\n"
    assert b.read_bytes() == b"new\n"
    assert os.stat(a).st_ino == ino
    assert _temps(tmp_path) == []


@pytest.mark.skipif(not hasattr(os, "setxattr"), reason="no xattr API")
def test_happy_xattrs_survive_the_save(tmp_path):
    p = tmp_path / "x.txt"
    p.write_bytes(b"old")
    try:
        os.setxattr(p, "user.note", b"keep-me")
    except OSError:
        pytest.skip("this file system has no user xattrs")
    atomic_write(LocalFS(), str(p), b"new")
    assert p.read_bytes() == b"new"
    assert os.getxattr(p, "user.note") == b"keep-me"


@POSIX
def test_happy_writable_file_in_read_only_folder_is_saved(tmp_path):
    folder = tmp_path / "ro"
    folder.mkdir()
    p = folder / "notes.txt"
    p.write_bytes(b"x\n")
    folder.chmod(0o555)
    try:
        atomic_write(LocalFS(), str(p), b"y\n")
        assert p.read_bytes() == b"y\n"
    finally:
        folder.chmod(0o755)
    assert _temps(folder) == []


@POSIX
def test_happy_read_only_file_is_saved_and_stays_read_only(tmp_path):
    p = tmp_path / "photo.jpg"
    p.write_bytes(b"old")
    p.chmod(0o444)
    atomic_write(LocalFS(), str(p), b"new")
    assert p.read_bytes() == b"new"
    assert _mode(p) == 0o444
    assert _temps(tmp_path) == []


@POSIX
def test_happy_read_only_file_through_the_stream_writer(tmp_path):
    import io

    p = tmp_path / "photo.jpg"
    p.write_bytes(b"old")
    p.chmod(0o444)
    atomic_write_stream(LocalFS(), str(p), io.BytesIO(b"new"))
    assert p.read_bytes() == b"new"
    assert _mode(p) == 0o444


@POSIX
def test_edge_secret_mode_is_never_widened_while_writing(tmp_path, monkeypatch):
    """The temp of a 0400 secret may gain owner-write, nothing else."""
    p = tmp_path / "id_key"
    p.write_bytes(b"old")
    p.chmod(0o400)
    seen: list[int] = []
    real_open = LocalFS.open_write

    def spy(self, path, append=False):
        # The open that receives the data: the precreated temp exists.
        existed = os.path.exists(path)
        fh = real_open(self, path, append)
        if existed:
            seen.append(_mode(path))
        return fh

    monkeypatch.setattr(LocalFS, "open_write", spy)
    atomic_write(LocalFS(), str(p), b"new")
    assert seen and all(m & 0o077 == 0 for m in seen)
    assert _mode(p) == 0o400


# --------------------------------------------------------------------------
# Sad path: a failing in-place write leaves the old content
# --------------------------------------------------------------------------


def _fail_in_place_writes(monkeypatch, target: Path, fail_after: int = 2):
    """The first in-place write of *target* writes a few bytes and then
    fails like a full disk; later writes (the restore) work."""
    from core import atomic_io

    real = atomic_io._overwrite_local
    calls: list[int] = []

    def flaky(path, data):
        calls.append(1)
        if os.fspath(path) == str(target) and len(calls) == 1:
            with open(path, "r+b") as fh:
                fh.write(data[:fail_after])
            raise OSError(errno.ENOSPC, "No space left on device")
        real(path, data)

    monkeypatch.setattr(atomic_io, "_overwrite_local", flaky)


def test_sad_failed_in_place_write_with_hard_link_restores_the_old_content(
    tmp_path, monkeypatch
):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_bytes(b"old content")
    os.link(a, b)
    _fail_in_place_writes(monkeypatch, a)
    with pytest.raises(OSError):
        atomic_write(LocalFS(), str(a), b"brand new content")
    monkeypatch.undo()
    assert a.read_bytes() == b"old content"
    assert b.read_bytes() == b"old content"
    assert _temps(tmp_path) == []


@POSIX
def test_sad_failed_in_place_write_in_read_only_folder_restores_from_memory(
    tmp_path, monkeypatch
):
    folder = tmp_path / "ro"
    folder.mkdir()
    p = folder / "notes.txt"
    p.write_bytes(b"old content")
    folder.chmod(0o555)
    try:
        _fail_in_place_writes(monkeypatch, p)
        with pytest.raises(OSError):
            atomic_write(LocalFS(), str(p), b"brand new content")
        monkeypatch.undo()
        assert p.read_bytes() == b"old content"
    finally:
        folder.chmod(0o755)


@POSIX
def test_sad_read_only_file_in_read_only_folder_still_fails_cleanly(tmp_path):
    folder = tmp_path / "ro"
    folder.mkdir()
    p = folder / "locked.txt"
    p.write_bytes(b"old")
    p.chmod(0o444)
    folder.chmod(0o555)
    try:
        with pytest.raises(PermissionError):
            atomic_write(LocalFS(), str(p), b"new")
        assert p.read_bytes() == b"old"
    finally:
        folder.chmod(0o755)


# --------------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------------


def test_edge_new_file_takes_the_rename_route(tmp_path):
    p = tmp_path / "new.txt"
    atomic_write(LocalFS(), str(p), b"data")
    assert p.read_bytes() == b"data"
    assert _temps(tmp_path) == []


def test_edge_shrinking_in_place_truncates(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_bytes(b"a much longer old content")
    os.link(a, b)
    atomic_write(LocalFS(), str(a), b"short")
    assert b.read_bytes() == b"short"


def test_edge_hard_link_through_a_symlink_is_written_in_place(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_bytes(b"old")
    os.link(a, b)
    link = tmp_path / "via-link"
    link.symlink_to(a)
    atomic_write(LocalFS(), str(link), b"new")
    assert link.is_symlink()
    assert b.read_bytes() == b"new"


def test_edge_only_a_local_file_is_inspected(tmp_path):
    """A backend that is not LocalFS keeps the rename route: its paths
    are not paths on this machine, even when one happens to exist here."""
    from core import atomic_io

    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_bytes(b"old")
    os.link(a, b)

    class RemoteFS:
        pass

    assert atomic_io._keep_identity_reason(RemoteFS(), str(a)) is None
    assert atomic_io._keep_identity_reason(LocalFS(), str(a)) is not None
    assert atomic_io._keep_identity_reason(LocalFS(), str(tmp_path / "none")) is None
