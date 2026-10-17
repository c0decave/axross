"""Temp files go to a RAM disk only on request, and never against TMPDIR.

Before: ``tmpfs_enabled`` defaulted to on, and at start main() pointed
``tempfile.tempdir`` - the directory of every temp file the process makes
without an explicit ``dir=`` - at the first tmpfs found (/run/user/$UID,
about a tenth of the RAM, or /dev/shm). That took download and upload
spools past 8 MiB, archive extraction and FUSE write buffers into RAM, and
an explicit ``TMPDIR`` was overridden.

Now routing to tmpfs is an opt-in (``"tmpfs_enabled": true`` in
``~/.config/axross/ramfs.json``), and an explicit ``TMPDIR`` always wins.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ramfs_settings as RS  # noqa: E402
from core import tmpfs_detect as TD  # noqa: E402


@pytest.fixture
def ram_disk(tmp_path, monkeypatch):
    """A stand-in tmpfs path, the settings cache reset, tempdir restored."""
    disk = tmp_path / "ramdisk"
    disk.mkdir()
    monkeypatch.setattr(TD, "preferred_tmpfs_dir", lambda: str(disk))
    monkeypatch.setattr(RS, "SETTINGS_FILE", tmp_path / "ramfs.json")
    monkeypatch.setattr(RS, "_CACHED", None)
    saved = tempfile.tempdir
    yield disk
    tempfile.tempdir = saved
    RS._CACHED = None


def _opt_in(path: Path) -> None:
    path.write_text(json.dumps({"tmpfs_enabled": True}), encoding="utf-8")


def test_happy_by_default_temp_files_stay_where_they_were(ram_disk, monkeypatch):
    monkeypatch.delenv("TMPDIR", raising=False)
    before = tempfile.tempdir
    assert RS.RamFsSettings().tmpfs_enabled is False
    assert TD.apply_tempdir_preference() is None
    assert tempfile.tempdir == before


def test_happy_an_opt_in_routes_temp_files_to_the_ram_disk(ram_disk, monkeypatch):
    monkeypatch.delenv("TMPDIR", raising=False)
    _opt_in(RS.SETTINGS_FILE)
    assert TD.apply_tempdir_preference() == str(ram_disk)
    assert tempfile.tempdir == str(ram_disk)


def test_sad_an_explicit_tmpdir_wins_over_the_opt_in(ram_disk, monkeypatch, tmp_path):
    chosen = tmp_path / "big-disk"
    chosen.mkdir()
    monkeypatch.setenv("TMPDIR", str(chosen))
    _opt_in(RS.SETTINGS_FILE)
    before = tempfile.tempdir
    assert TD.apply_tempdir_preference() is None
    assert tempfile.tempdir == before


def test_edge_an_empty_tmpdir_is_not_a_choice(ram_disk, monkeypatch):
    monkeypatch.setenv("TMPDIR", "")
    _opt_in(RS.SETTINGS_FILE)
    assert TD.apply_tempdir_preference() == str(ram_disk)


def test_edge_an_explicit_false_in_the_file_stays_off(ram_disk, monkeypatch):
    monkeypatch.delenv("TMPDIR", raising=False)
    RS.SETTINGS_FILE.write_text(json.dumps({"tmpfs_enabled": False}), encoding="utf-8")
    assert TD.apply_tempdir_preference() is None


def test_edge_no_ram_disk_found_changes_nothing(ram_disk, monkeypatch):
    monkeypatch.delenv("TMPDIR", raising=False)
    _opt_in(RS.SETTINGS_FILE)
    with mock.patch.object(TD, "preferred_tmpfs_dir", return_value=None):
        assert TD.apply_tempdir_preference() is None
