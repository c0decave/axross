"""Packing a ZIP of files dated before 1980 or after 2107 works.

A ZIP stores local date and time from 1980 to 2107. ``core.packer``
raised an older file's time to 1980-01-01 00:00 *UTC* and then turned
that into local time: west of UTC that is a 1979 date, and
``zipfile.ZipInfo`` refused it - "ZIP does not support timestamps before
1980" failed the whole pack for one file dated 1970 (reproducible builds,
the Nix store, unpacked old tarballs). A file dated after 2107 failed
with a struct error. The tar formats packed the same files.
"""

from __future__ import annotations

import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.local_fs import LocalFS  # noqa: E402
from core.packer import PackOptions, pack  # noqa: E402


@pytest.fixture
def west_of_utc(monkeypatch):
    if not hasattr(time, "tzset"):
        pytest.skip("no time.tzset on this platform")
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _pack_one(tmp_path, stamp: float):
    (tmp_path / "f.txt").write_text("hello")
    os.utime(tmp_path / "f.txt", (stamp, stamp))
    result = pack(LocalFS(), str(tmp_path), ["f.txt"], "bundle", PackOptions("zip"))
    with zipfile.ZipFile(result.path) as zf:
        return zf.getinfo("f.txt").date_time, zf.read("f.txt")


def test_edge_a_file_from_1970_west_of_utc(tmp_path, west_of_utc):
    date_time, data = _pack_one(tmp_path, 0)
    assert date_time == (1980, 1, 1, 0, 0, 0)
    assert data == b"hello"


def test_edge_a_file_from_after_2107(tmp_path):
    date_time, data = _pack_one(tmp_path, 4_410_000_000)  # 2109
    assert date_time[0] == 2107
    assert data == b"hello"


def test_happy_an_ordinary_date_is_kept(tmp_path, west_of_utc):
    stamp = time.mktime((2024, 6, 1, 12, 30, 10, 0, 0, -1))
    date_time, _data = _pack_one(tmp_path, stamp)
    assert date_time == (2024, 6, 1, 12, 30, 10)
