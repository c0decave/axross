"""The Find Files dialog after the search review (2026-11-19): brackets
in a name typed as text, sizes with a decimal comma (German UI)."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui import find_files_dialog as FD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_until(predicate, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


@pytest.fixture
def folder(tmp_path):
    root = tmp_path / "data"
    (root / "music").mkdir(parents=True)
    (root / "music" / "Song [Remix].mp3").write_bytes(b"x" * 10)
    (root / "music" / "Song R.mp3").write_bytes(b"x" * 10)
    (root / "IMG_1.jpg").write_bytes(b"x" * 2000)
    (root / "IMG_2.jpg").write_bytes(b"x" * 1000)
    return root


def _search(folder, name="", **fields) -> set[str]:
    dlg = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(folder), label=str(folder))])
    try:
        dlg.name_edit.setText(name)
        for field, value in fields.items():
            getattr(dlg, field).setText(value)
        dlg.start_search()
        assert wait_until(lambda: not dlg.is_running)
        assert "Cannot search" not in dlg.status_label.text(), dlg.status_label.text()
        return {dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())}
    finally:
        dlg.close()


def test_brackets_in_a_name_typed_as_text_are_part_of_the_name(folder):
    assert _search(folder, "Song [Remix]") == {"Song [Remix].mp3"}
    assert _search(folder, "[remix]") == {"Song [Remix].mp3"}


def test_a_pattern_with_a_star_keeps_its_character_set(folder):
    assert _search(folder, "IMG_[12].*") == {"IMG_1.jpg", "IMG_2.jpg"}
    assert _search(folder, "IMG_[2]*") == {"IMG_2.jpg"}


@pytest.mark.parametrize(("text", "value"), [("1,5K", 1536), ("1,5 MiB", 1572864),
                                             (" 0,5k ", 512)])
def test_a_size_with_a_decimal_comma(text, value):
    assert FD.parse_size(text) == value


@pytest.mark.parametrize("text", ["1,2,3", "1.000,5", ",5"])
def test_a_size_with_two_separators_is_refused(text):
    with pytest.raises(ValueError):
        FD.parse_size(text)


def test_the_size_fields_take_a_decimal_comma(folder):
    assert _search(folder, "IMG", min_size_edit="1,5K") == {"IMG_1.jpg"}


def test_a_name_search_lists_matching_folders_and_reveals_them(tmp_path):
    root = tmp_path / "data"
    (root / "Steuer 2025").mkdir(parents=True)
    (root / "Steuer 2025" / "beleg.pdf").write_bytes(b"x")
    (root / "steuer.txt").write_bytes(b"x")
    dlg = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(root), label=str(root))])
    try:
        dlg.name_edit.setText("steuer")
        dlg.start_search()
        assert wait_until(lambda: not dlg.is_running)
        rows = {dlg.table.item(r, 0).text(): r for r in range(dlg.table.rowCount())}
        assert set(rows) == {"Steuer 2025", "steuer.txt"}
        row = rows["Steuer 2025"]
        assert dlg.table.item(row, FD.COL_SIZE).text() == ""
        assert dlg.table.item(row, FD.COL_CATEGORY).text() == "Folder"
        revealed = []
        dlg.reveal_requested.connect(lambda backend, path: revealed.append(path))
        dlg.table.setCurrentCell(row, 0)
        dlg._activate_current()
        assert revealed == [str(root / "Steuer 2025")]
        # Content (or size, or a type) is about files: no folder then.
        dlg.contains_edit.setText("x")
        dlg.start_search()
        assert wait_until(lambda: not dlg.is_running)
        assert {dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())} == {
            "steuer.txt"}
    finally:
        dlg.close()


def test_the_window_opens_with_the_focus_in_name(tmp_path):
    dlg = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(tmp_path), label=str(tmp_path))])
    try:
        dlg.show()
        dlg.activateWindow()
        assert wait_until(lambda: dlg.focusWidget() is not None, timeout=2)
        assert dlg.focusWidget() is dlg.name_edit
    finally:
        dlg.close()


@pytest.mark.parametrize(("typed", "pattern"), [
    ("report", "*report*"), ("Song [Remix]", "*Song [[]Remix]*"), ("*.jpg", "*.jpg"),
    ("IMG_[0-9]*", "IMG_[0-9]*"), ("a?c", "a?c")])
def test_a_saved_name_comes_back_as_it_was_typed(typed, pattern):
    assert FD.name_pattern(typed) == pattern
    assert FD.name_text(pattern) == typed


def test_a_smart_folder_shows_the_name_as_typed_and_finds_the_same(folder):
    from core import file_search as FS
    from core.search_federation import SearchQuery

    data = FS.saved_search_to_dict(SearchQuery(name=FD.name_pattern("Song [Remix]")),
                                   [{"backend_name": "Local", "profile_name": "",
                                     "path": str(folder)}], use_index=False, tag="")
    dlg = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(folder), label=str(folder))],
                             saved=data)
    try:
        assert dlg.name_edit.text() == "Song [Remix]"
        dlg.start_search()
        assert wait_until(lambda: not dlg.is_running)
        assert {dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())} == {
            "Song [Remix].mp3"}
    finally:
        dlg.close()
