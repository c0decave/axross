"""Review round 3 (files): FUSE modes, cross-device trash copies. Each test
names what was measured before its fix."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX modes")


@posix_only
@pytest.mark.parametrize("writeable", [True, False])
def test_sad_fuse_shows_the_mode_the_backend_knows(tmp_path, writeable):
    """Measured before: every file was 0664 (0444 read-only), every folder
    0775 - ssh refused a 0600 key through the mount as "unprotected", and
    a script 0755 showed as not executable."""
    (tmp_path / "key").write_text("k")
    os.chmod(tmp_path / "key", 0o600)
    (tmp_path / "run.sh").write_text("x")
    os.chmod(tmp_path / "run.sh", 0o755)
    (tmp_path / "private").mkdir()
    os.chmod(tmp_path / "private", 0o700)
    fuse = FM.BackendFuseFS(LocalFS(), str(tmp_path), writeable=writeable, ttl_stat=0)
    strip = 0 if writeable else 0o222
    assert stat.S_IMODE(fuse.getattr("/key")["st_mode"]) == 0o600 & ~strip
    assert stat.S_IMODE(fuse.getattr("/run.sh")["st_mode"]) == 0o755 & ~strip
    st = fuse.getattr("/private")["st_mode"]
    assert stat.S_ISDIR(st) and stat.S_IMODE(st) == 0o700 & ~strip


def test_happy_fuse_without_a_known_mode_keeps_the_defaults():
    class Item:
        is_dir = False
        size = 1
        modified = None
        permissions = 0

    assert stat.S_IMODE(FM._stat_dict(Item(), writeable=True)["st_mode"]) == 0o664
    assert stat.S_IMODE(FM._stat_dict(Item(), writeable=False)["st_mode"]) == 0o444


@posix_only
def test_sad_fuse_does_not_show_setuid_bits(tmp_path):
    (tmp_path / "tool").write_text("x")
    os.chmod(tmp_path / "tool", 0o4755)
    fuse = FM.BackendFuseFS(LocalFS(), str(tmp_path), writeable=True, ttl_stat=0)
    assert stat.S_IMODE(fuse.getattr("/tool")["st_mode"]) == 0o755


@posix_only
def test_sad_a_cross_device_copy_is_private_while_its_data_goes_in(tmp_path, monkeypatch):
    """Measured before: copy2 / copytree made the copy (a Move to Trash or a
    Move onto another disk, a restore across disks) with the umask's 0644
    and 0755 first and set the source's mode after - a 0600 file, and the
    files of a 0700 folder, could be opened by anyone in between."""
    from core import server_ops

    src = tmp_path / "src"
    (src / "inner").mkdir(parents=True)
    os.chmod(src, 0o700)
    (src / "inner" / "open.txt").write_text("readable inside a private folder")
    os.chmod(src / "inner" / "open.txt", 0o644)
    key = tmp_path / "key"
    key.write_text("secret")
    os.chmod(key, 0o600)
    seen = []
    real = server_ops.shutil.copyfileobj

    def watch(fsrc, fdst, length=0):
        st = os.fstat(fdst.fileno())
        folders = [stat.S_IMODE(os.stat(p).st_mode) for p in (tmp_path / "dst",
                                                            tmp_path / "dst" / "inner")
                   if p.exists()]
        seen.append((stat.S_IMODE(st.st_mode), folders))
        return real(fsrc, fdst, length)

    monkeypatch.setattr(server_ops.shutil, "copyfileobj", watch)
    server_ops._move_across_devices(str(key), str(tmp_path / "key2"), OSError("EXDEV"))
    server_ops._move_across_devices(str(src), str(tmp_path / "dst"), OSError("EXDEV"))
    assert seen and all(mode == 0o600 for mode, _ in seen)
    assert all(m == 0o700 for _, folders in seen for m in folders)
    assert stat.S_IMODE(os.stat(tmp_path / "key2").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "dst" / "inner" / "open.txt").st_mode) == 0o644
    assert stat.S_IMODE(os.stat(tmp_path / "dst").st_mode) == 0o700
    assert not src.exists() and not key.exists()


@posix_only
def test_sad_trash_copy_across_devices_is_private_while_written(tmp_path, monkeypatch):
    from core import server_ops
    from core import trash as T

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    f = tmp_path / "photo.jpg"
    f.write_bytes(b"x" * 1000)
    os.chmod(f, 0o640)
    monkeypatch.setattr(T.os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError(18, "EXDEV")))
    seen = []
    real = server_ops.shutil.copyfileobj

    def watch(fsrc, fdst, length=0):
        seen.append(stat.S_IMODE(os.fstat(fdst.fileno()).st_mode))
        return real(fsrc, fdst, length)

    monkeypatch.setattr(server_ops.shutil, "copyfileobj", watch)
    trash_id = T.trash_copy(LocalFS(), str(f))
    assert seen == [0o600]
    assert T.entry_exists(LocalFS(), trash_id)


def test_sad_a_file_open_for_writing_shows_the_mode_it_was_created_with(tmp_path):
    fuse = FM.BackendFuseFS(LocalFS(), str(tmp_path), writeable=True, ttl_stat=0)
    fh = fuse.create("/id_key", 0o600)
    try:
        assert stat.S_IMODE(fuse.getattr("/id_key", fh)["st_mode"]) == 0o600
    finally:
        fuse.release("/id_key", fh)
