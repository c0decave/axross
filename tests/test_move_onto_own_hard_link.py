"""Moving or copying a file onto a hard link of itself (another name of
the same file) does nothing and says so: "b is the same file as a (a hard
link): nothing is copied or moved, both names stay" - not the bare
"source and destination are the same". Both names keep the data. A
case-only spelling of one entry is not called a hard link."""
from __future__ import annotations

import os
import threading

import pytest

from core.local_fs import LocalFS
from core.storage_identity import is_hard_link_of, same_target_message


def test_happy_the_message_names_the_hard_link(tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "sub" / "b.txt"
    b.parent.mkdir()
    a.write_text("data")
    os.link(a, b)
    fs = LocalFS()
    assert is_hard_link_of(fs, str(a), fs, str(b))
    text = same_target_message(fs, str(a), fs, str(b))
    assert "same file" in text and "hard link" in text and "both names stay" in text


def test_edge_one_entry_is_not_a_hard_link(tmp_path):
    a = tmp_path / "a.txt"
    a.write_text("data")
    os.link(a, tmp_path / "other")  # nlink 2, but a with itself is one entry
    fs = LocalFS()
    assert not is_hard_link_of(fs, str(a), fs, str(a))
    assert not is_hard_link_of(fs, str(a), fs, str(tmp_path / "." / "a.txt"))
    assert same_target_message(fs, str(a), fs, str(a)).startswith("source and destination")


@pytest.fixture
def app():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    global _APP
    _APP = QApplication.instance() or QApplication([])
    return _APP


_APP = None


@pytest.mark.parametrize("move", [True, False])
def test_happy_a_move_onto_its_hard_link_keeps_both(app, tmp_path, move):
    from core.transfer_manager import TransferManager

    a, b = tmp_path / "a.txt", tmp_path / "dst" / "a.txt"
    b.parent.mkdir()
    a.write_text("data")
    os.link(a, b)
    fs = LocalFS()
    manager = TransferManager()
    try:
        jobs = manager.transfer_files(fs, fs, [str(a)], str(b.parent), move=move)
    finally:
        manager.shutdown()
    assert a.read_text() == "data" and b.read_text() == "data"
    assert os.path.samefile(a, b)
    assert [j.error_message for j in jobs] == [
        f"{b} is the same file as {a} (a hard link): nothing is copied or moved, "
        "both names stay"]
