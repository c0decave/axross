"""A resumable copy that refuses an existing destination keeps refusing.

``resumable_copy`` without ``overwrite`` refuses a destination that
exists and that no resume manifest accounts for. It wrote its new
manifest before that check, though, and left it behind when it refused:
the same call a second time found a matching manifest, took the
destination for its own partial copy and overwrote it - an unrelated
file of the user's, replaced on the second try.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import copy_resume as CR  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.fixture
def files(tmp_path):
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    src.write_bytes(b"S" * 100_000)
    dst.write_bytes(b"PRECIOUS USER DATA")
    return src, dst, tmp_path / "manifest.json"


def test_sad_a_second_try_still_refuses_an_unrelated_destination(files):
    src, dst, manifest = files
    fs = LocalFS()
    for _try in range(2):
        with pytest.raises(FileExistsError):
            CR.resumable_copy(fs, str(src), fs, str(dst), manifest_path=manifest)
    assert dst.read_bytes() == b"PRECIOUS USER DATA"
    assert not manifest.exists()  # a refusal leaves no resume state behind


def test_happy_overwrite_still_replaces_it(files):
    src, dst, manifest = files
    fs = LocalFS()
    report = CR.resumable_copy(fs, str(src), fs, str(dst), manifest_path=manifest,
                               overwrite=True)
    assert report.completed
    assert dst.read_bytes() == b"S" * 100_000


def test_edge_a_missing_destination_is_copied(files):
    src, dst, manifest = files
    dst.unlink()
    fs = LocalFS()
    report = CR.resumable_copy(fs, str(src), fs, str(dst), manifest_path=manifest)
    assert report.completed
    assert dst.read_bytes() == b"S" * 100_000
