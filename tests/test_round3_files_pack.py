"""Review round 3 (files): Pack. Each test names what was measured before
its fix."""

from __future__ import annotations

import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import packer as PK  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

FS = LocalFS()
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX links and modes")


def _swap_after_collect(monkeypatch, path: Path, target: Path) -> None:
    """Between the walk and the read: *path* becomes a symlink to *target*
    (another local process that can write in the folder)."""
    real = PK._collect

    def collect(*args, **kwargs):
        out = real(*args, **kwargs)
        path.unlink()
        path.symlink_to(target)
        return out

    monkeypatch.setattr(PK, "_collect", collect)


@posix_only
@pytest.mark.parametrize("fmt", ["zip", "tar.gz", "7z", "gz"])
def test_sad_a_source_swapped_for_a_symlink_is_not_read(tmp_path, monkeypatch, fmt):
    """Measured before: the source was opened by name, following a symlink
    put in its place after the walk - the link's target (an SSH key, say)
    went into the archive under the listed name."""
    if fmt == "7z":
        pytest.importorskip("py7zr")
    src = tmp_path / "src"
    src.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("TOP")  # same size as the listed file
    (src / "a.txt").write_text("abc")
    _swap_after_collect(monkeypatch, src / "a.txt", secret)
    with pytest.raises(PK.PackError):
        PK.pack(FS, str(src), ["a.txt"], "out", PK.PackOptions(fmt=fmt))
    assert [p.name for p in src.iterdir()] == ["a.txt"]


@posix_only
def test_sad_a_source_replaced_by_another_file_is_not_read(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("abc")
    real = PK._collect

    def collect(*args, **kwargs):
        out = real(*args, **kwargs)
        os.replace(tmp_path / "other", src / "a.txt")
        return out

    (tmp_path / "other").write_text("xyz")
    monkeypatch.setattr(PK, "_collect", collect)
    with pytest.raises(PK.PackError, match="changed|replaced"):
        PK.pack(FS, str(src), ["a.txt"], "out", PK.PackOptions(fmt="zip"))


def test_sad_folders_count_toward_the_entry_limit(tmp_path, monkeypatch):
    """Measured before: only files were counted - a tree of a million empty
    folders was walked and listed in memory without a limit."""
    src = tmp_path / "src"
    for n in range(5):
        (src / f"d{n}").mkdir(parents=True)
    monkeypatch.setattr(PK, "MAX_PACK_FILES", 3)
    with pytest.raises(PK.PackError, match="more than 3"):
        PK.pack(FS, str(src), [f"d{n}" for n in range(5)], "out", PK.PackOptions(fmt="zip"))


@posix_only
def test_sad_local_7z_pack_does_not_keep_setuid_bits(tmp_path):
    """Measured before: py7zr read the local file by its path and stored
    its whole mode - 4755 went into the archive (zip and tar store 0755)."""
    py7zr = pytest.importorskip("py7zr")
    src = tmp_path / "src"
    src.mkdir()
    tool = src / "tool"
    tool.write_bytes(b"#!/bin/sh\n")
    os.chmod(tool, 0o4755)
    before = os.stat(tool).st_mtime
    result = PK.pack(FS, str(src), ["tool"], "out", PK.PackOptions(fmt="7z"))
    with py7zr.SevenZipFile(result.path) as zf:
        (info,) = [f for f in zf.files if f.filename == "tool"]
        assert stat.S_IMODE(info.posix_mode) == 0o755
        assert abs(info.lastwritetime.totimestamp() - before) < 2
    from core import archive as AR

    AR.extract(result.path, str(tmp_path / "out"))
    assert (tmp_path / "out" / "tool").read_bytes() == b"#!/bin/sh\n"


def test_happy_zip_and_tar_still_keep_the_mode(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "run.sh").write_text("x")
    os.chmod(src / "run.sh", 0o750)
    z = PK.pack(FS, str(src), ["run.sh"], "z", PK.PackOptions(fmt="zip"))
    with zipfile.ZipFile(z.path) as zf:
        assert (zf.getinfo("run.sh").external_attr >> 16) & 0o777 == 0o750
    t = PK.pack(FS, str(src), ["run.sh"], "t", PK.PackOptions(fmt="tar.gz"))
    with tarfile.open(t.path) as tf:
        assert tf.getmember("run.sh").mode == 0o750
