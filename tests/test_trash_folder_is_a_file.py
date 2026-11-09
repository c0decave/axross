"""A trash folder whose name a file took is named as the problem.

Measured before (review round 8): with ``~/.axross-trash`` a file, Del of
``x.txt`` failed with "x.txt is not a folder." - the file being trashed
got the blame. The check looked only whether the trash folder existed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture(autouse=True)
def _journal(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))


def test_sad_a_file_in_the_trash_folders_place_is_named(tmp_path):
    root = tmp_path / ".axross-trash"
    root.write_text("not a folder")
    victim = tmp_path / "x.txt"
    victim.write_text("keep me")
    with pytest.raises(OSError) as caught:
        T.trash(LocalFS(), str(victim), root=str(root))
    text = describe(caught.value)
    assert f"The trash folder {root} is not a folder" in text, text
    assert "x.txt" not in text
    assert victim.read_text() == "keep me"
    assert root.read_text() == "not a folder"


def test_happy_a_missing_trash_folder_is_made(tmp_path):
    root = tmp_path / ".axross-trash"
    victim = tmp_path / "x.txt"
    victim.write_text("data")
    trash_id = T.trash(LocalFS(), str(victim), root=str(root))
    assert root.is_dir() and (root / trash_id).read_text() == "data"


def test_edge_a_link_to_a_folder_serves_as_the_trash_folder(tmp_path):
    real = tmp_path / "real-trash"
    real.mkdir()
    root = tmp_path / ".axross-trash"
    os.symlink(real, root)
    victim = tmp_path / "x.txt"
    victim.write_text("data")
    trash_id = T.trash(LocalFS(), str(victim), root=str(root))
    assert not victim.exists() and (real / trash_id).read_text() == "data"


def test_sad_a_link_to_a_file_is_named_too(tmp_path):
    (tmp_path / "some-file").write_text("x")
    root = tmp_path / ".axross-trash"
    os.symlink(tmp_path / "some-file", root)
    victim = tmp_path / "x.txt"
    victim.write_text("data")
    with pytest.raises(OSError, match="The trash folder .* is not a folder"):
        T.trash(LocalFS(), str(victim), root=str(root))
    assert victim.exists()
