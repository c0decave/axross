"""A packed archive gets the mode of any new file (0666 less the umask),
not 0600 - unless what it holds is private: a file or folder the group or
others cannot read keeps the archive from them too. The archive is written
into the temp file made for it, never reopened by name."""
from __future__ import annotations

import os
import stat

import pytest

from core import packer as PK
from core.local_fs import LocalFS

FORMATS = ["zip", "tar.gz", "tar.xz", "7z"]


@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def _pack(tmp_path, fmt, **opts):
    return PK.pack(LocalFS(), str(tmp_path / "src"), ["a.txt", "d"], "out",
                   PK.PackOptions(fmt=fmt, **opts))


def _tree(tmp_path, file_mode=0o644, dir_mode=0o755):
    src = tmp_path / "src"
    (src / "d").mkdir(parents=True)
    (src / "a.txt").write_text("a")
    (src / "d" / "b.txt").write_text("b")
    os.chmod(src / "a.txt", file_mode)
    os.chmod(src / "d", dir_mode)
    return src


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_plain_pack_has_the_usual_mode(tmp_path, umask_022, fmt):
    if fmt == "7z":
        pytest.importorskip("py7zr")
    _tree(tmp_path)
    result = _pack(tmp_path, fmt)
    assert stat.S_IMODE(os.stat(result.path).st_mode) == 0o644


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_private_file_keeps_the_archive_private(tmp_path, umask_022, fmt):
    if fmt == "7z":
        pytest.importorskip("py7zr")
    _tree(tmp_path, file_mode=0o600)
    result = _pack(tmp_path, fmt)
    assert stat.S_IMODE(os.stat(result.path).st_mode) == 0o600


def test_a_private_folder_and_a_group_only_file(tmp_path, umask_022):
    _tree(tmp_path, dir_mode=0o700)
    assert stat.S_IMODE(os.stat(_pack(tmp_path, "zip").path).st_mode) == 0o600
    _tree(tmp_path / "g", file_mode=0o640)
    result = PK.pack(LocalFS(), str(tmp_path / "g" / "src"), ["a.txt"], "g",
                     PK.PackOptions(fmt="zip"))
    assert stat.S_IMODE(os.stat(result.path).st_mode) == 0o640


def test_the_umask_narrows_it(tmp_path):
    _tree(tmp_path)
    old = os.umask(0o077)
    try:
        result = _pack(tmp_path, "zip")
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(result.path).st_mode) == 0o600


@pytest.mark.parametrize("fmt", ["zip", "tar.gz", "7z"])
def test_the_temp_name_is_not_reopened(tmp_path, monkeypatch, fmt):
    """A writer that opened the temp file by name followed a symlink put
    there meanwhile (and the 7z writer removed the file and made it anew)."""
    if fmt == "7z":
        pytest.importorskip("py7zr")
    _tree(tmp_path)
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    real_open = os.open

    def open_then_swap(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if os.path.basename(str(path)).startswith(".tmp-") and flags & os.O_EXCL:
            os.unlink(path)
            os.symlink(victim, path)  # what someone else could do in a shared folder
        return fd

    monkeypatch.setattr(os, "open", open_then_swap)
    with pytest.raises(PK.PackError, match="replaced"):
        PK.pack(LocalFS(), str(tmp_path / "src"), ["a.txt"], "out", PK.PackOptions(fmt=fmt))
    monkeypatch.undo()
    assert victim.read_text() == "keep me"
    assert not os.path.lexists(str(tmp_path / "src" / "out") + PK.FORMATS[fmt].suffix)
