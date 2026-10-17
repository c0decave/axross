"""Undoing a metadata removal works when the trash is on another file system.

Before: ``trash.restore_over`` put the kept original back with
``os.replace(trash entry, target)``. ``trash_copy`` already falls back to
a copy when the file lives on another file system than the trash (a USB
stick, a data disk); the way back did not, failed with EXDEV ("Invalid
cross-device link") and left the cleaned file in place.

Now a cross-device restore copies the kept original (data, mode, times)
into the target's folder and renames it over the target there - still
atomic for the target - then drops the trash entry.
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import trash as T  # noqa: E402
from core.atomic_io import atomic_write_stream  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

CLEANED = b"CLEANED"


def _prepare(target: Path) -> tuple[LocalFS, str]:
    fs = LocalFS()
    target.write_bytes(b"ORIGINAL with metadata")
    os.chmod(target, 0o640)
    trash_id = T.trash_copy(fs, str(target))
    atomic_write_stream(fs, str(target), io.BytesIO(CLEANED))
    return fs, trash_id


def _exdev_for_trash(monkeypatch) -> list[str]:
    """Make every os.replace out of the trash fail like a cross-device one."""
    real = os.replace
    refused: list[str] = []
    trash_root = str(Path.home() / T.TRASH_DIRNAME)

    def replace(src, dst, *a, **k):
        if str(src).startswith(trash_root):
            refused.append(str(src))
            raise OSError(errno.EXDEV, "Invalid cross-device link", str(src))
        return real(src, dst, *a, **k)

    monkeypatch.setattr(T.os, "replace", replace)
    return refused


def test_happy_restore_over_falls_back_to_a_copy_across_devices(tmp_path, monkeypatch):
    target = tmp_path / "photo.jpg"
    fs, trash_id = _prepare(target)
    refused = _exdev_for_trash(monkeypatch)
    T.restore_over(
        fs, trash_id, target=str(target), expected_sha256=hashlib.sha256(CLEANED).hexdigest()
    )
    assert refused, "the cross-device path was not taken"
    assert target.read_bytes() == b"ORIGINAL with metadata"
    assert target.stat().st_mode & 0o777 == 0o640
    assert not T.entry_exists(fs, trash_id)
    assert [p.name for p in tmp_path.iterdir()] == ["photo.jpg"]  # no temp left


def test_sad_another_os_error_is_not_swallowed(tmp_path, monkeypatch):
    target = tmp_path / "photo.jpg"
    fs, trash_id = _prepare(target)

    def replace(src, dst, *a, **k):
        raise OSError(errno.EACCES, "Permission denied", str(dst))

    monkeypatch.setattr(T.os, "replace", replace)
    with pytest.raises(OSError) as info:
        T.restore_over(
            fs, trash_id, target=str(target), expected_sha256=hashlib.sha256(CLEANED).hexdigest()
        )
    assert info.value.errno == errno.EACCES
    assert target.read_bytes() == CLEANED
    assert T.entry_exists(fs, trash_id)


def test_edge_a_changed_target_is_still_refused_across_devices(tmp_path, monkeypatch):
    target = tmp_path / "photo.jpg"
    fs, trash_id = _prepare(target)
    target.write_bytes(b"edited since")
    _exdev_for_trash(monkeypatch)
    with pytest.raises(OSError, match="changed"):
        T.restore_over(
            fs, trash_id, target=str(target), expected_sha256=hashlib.sha256(CLEANED).hexdigest()
        )
    assert target.read_bytes() == b"edited since"
    assert T.entry_exists(fs, trash_id)


def test_edge_a_real_second_file_system(monkeypatch):
    other = "/dev/shm"
    if not os.path.isdir(other) or os.stat(other).st_dev == os.stat(Path.home()).st_dev:
        pytest.skip("no second file system next to the home directory")
    d = Path(tempfile.mkdtemp(prefix="axross-test-", dir=other))
    try:
        target = d / "photo.jpg"
        fs, trash_id = _prepare(target)
        T.restore_over(
            fs, trash_id, target=str(target), expected_sha256=hashlib.sha256(CLEANED).hexdigest()
        )
        assert target.read_bytes() == b"ORIGINAL with metadata"
    finally:
        shutil.rmtree(d)
