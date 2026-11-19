"""A save that writes a file in place (it has other hard links, or another
owner) keeps its old content in a backup beside it until the write is
done. The backup was made by shutil.copyfile: 0666 less the umask, so a
0600 file's content was readable by anyone meanwhile - for good when the
restore failed - and a copy that failed half way (a full disk) was left."""
from __future__ import annotations

import os
import stat

import pytest

from core import atomic_io
from core.local_fs import LocalFS


def test_sad_the_backup_is_as_private_as_the_file(tmp_path, monkeypatch):
    secret = tmp_path / "secret.conf"
    secret.write_text("password=1\n")
    os.chmod(secret, 0o600)
    os.link(secret, tmp_path / "other-name")  # makes the save write in place
    seen = []
    real = atomic_io._overwrite_local

    def look(path, data):
        for name in os.listdir(tmp_path):
            if name.endswith(".bak"):
                seen.append(stat.S_IMODE(os.lstat(tmp_path / name).st_mode))
        return real(path, data)

    monkeypatch.setattr(atomic_io, "_overwrite_local", look)
    old = os.umask(0o022)
    try:
        atomic_io.atomic_write(LocalFS(), str(secret), b"password=2\n")
    finally:
        os.umask(old)
    assert seen and all(mode & 0o077 == 0 for mode in seen), [oct(m) for m in seen]
    assert secret.read_bytes() == b"password=2\n"
    assert sorted(os.listdir(tmp_path)) == ["other-name", "secret.conf"]


def test_sad_a_backup_that_fails_half_way_is_removed(tmp_path, monkeypatch):
    target = tmp_path / "f.txt"
    target.write_text("x" * 5000)
    os.link(target, tmp_path / "link")
    import shutil

    def full(src, dst, length=0):
        dst.write(src.read(100))
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(shutil, "copyfileobj", full)
    with pytest.raises(OSError):
        atomic_io.atomic_write(LocalFS(), str(target), b"new")
    assert sorted(os.listdir(tmp_path)) == ["f.txt", "link"]
    assert target.read_text() == "x" * 5000
