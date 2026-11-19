"""Review round 3 (files): Remove Metadata. Each test names what was
measured before its fix."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import metadata_tools as MT  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests import metadata_testkit as K  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX hard links and modes")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from core import security_mode

    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    yield
    security_mode.set_policy(previous)


@posix_only
def test_sad_in_place_cleaning_reaches_every_hard_link(tmp_path):
    """Measured before: the cleaned copy was renamed over the one name -
    the file's other names (a hard link in a backup or a photo library)
    kept the GPS position and the camera's serial number."""
    pics = tmp_path / "pics"
    pics.mkdir()
    f = K.write(pics / "photo.jpg", K.jpeg_bytes())
    other = tmp_path / "library.jpg"
    os.link(f, other)
    result = MT.remove_metadata(LocalFS(), str(f), mode=MT.MODE_IN_PLACE)
    assert result.status == "cleaned", result.error
    assert K.MARK not in f.read_bytes()
    assert K.MARK not in other.read_bytes()
    assert os.stat(f).st_ino == os.stat(other).st_ino
    assert "hard link" in result.note
    # The original stays in the trash - not cleaned with the file's names.
    from core import trash as T

    (entry,) = [e for e in T.list_trash(LocalFS()) if e.trash_id == result.trash_id]
    home_trash = Path(LocalFS().home()) / T.TRASH_DIRNAME
    kept = [p for p in home_trash.rglob("*") if p.is_file() and K.MARK in p.read_bytes()]
    assert kept, "the trash lost the original"


@posix_only
def test_sad_the_cleaned_file_is_made_beside_the_file_not_in_tmp(tmp_path, monkeypatch):
    """Measured before: the cleaned copy (a whole video) was written into the
    system temp folder - often a RAM disk - before it went into place."""
    pics = tmp_path / "pics"
    pics.mkdir()
    f = K.write(pics / "photo.jpg", K.jpeg_bytes())
    seen = {}
    real = MT._clean

    def clean(kind, src, dst, cancel):
        folder = os.path.dirname(dst)
        seen["folder"] = folder
        seen["mode"] = stat.S_IMODE(os.stat(folder).st_mode)
        return real(kind, src, dst, cancel)

    monkeypatch.setattr(MT, "_clean", clean)
    result = MT.remove_metadata(LocalFS(), str(f), mode=MT.MODE_COPY)
    assert result.status == "cleaned", result.error
    assert os.path.dirname(seen["folder"]) == str(pics)
    assert not seen["folder"].startswith(tempfile.gettempdir() + os.sep + "axross")
    assert seen["mode"] == 0o700
    assert not [p.name for p in pics.iterdir() if p.name.startswith(".")]


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="names descriptors by /proc")
def test_sad_a_failed_write_into_a_hard_linked_file_puts_the_original_back(tmp_path, monkeypatch):
    pics = tmp_path / "pics"
    pics.mkdir()
    original = K.jpeg_bytes()
    f = K.write(pics / "photo.jpg", original)
    os.link(f, tmp_path / "other.jpg")
    real_write = os.write
    calls = {"n": 0}

    def failing_write(fd, data):
        try:
            name = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            name = ""
        if name.endswith("photo.jpg"):
            calls["n"] += 1
        if calls["n"] == 1 and name.endswith("photo.jpg"):
            real_write(fd, bytes(data[:10]))
            raise OSError(28, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(MT.os, "write", failing_write)
    result = MT.remove_metadata(LocalFS(), str(f), mode=MT.MODE_IN_PLACE)
    assert result.status == "error"
    assert f.read_bytes() == original
    assert (tmp_path / "other.jpg").read_bytes() == original
