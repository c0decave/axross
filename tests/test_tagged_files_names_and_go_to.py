"""Tagged Files shows a file's name as the pane does and Go to File
selects the file.

Found in review (round 1 of the 2026-11 reviews, UI shell; repro: tag
local files named ``inv\\u202efdp.exe`` and ``a\\\\b.txt``, open View >
Tagged Files):

- the Name and Folder columns showed controls and bidi overrides as they
  are ("inv\\u202efdp.exe" read as "invexe.pdf"), where the file pane
  shows U+FFFD;
- a backslash in a local name split it: ``a\\\\b.txt`` in /data was listed
  as "b.txt" in "/data/a", and Go to File opened /data/a - a folder that
  is not there;
- Go to File opened the folder but selected nothing; the file is
  selected now, as Find Files' Reveal does.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import tags as T  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"


def _wait(cond, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "tags.json"
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    yield T.store()
    T.reset_cache()


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    for name in ("plain.txt", f"inv{RLO}fdp.exe", "a\\b.txt", "zz.txt"):
        (d / name).write_text("x")
    return d


@pytest.fixture
def win(tmp_path):
    from ui import main_window as MW

    patches = [
        mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"),
        mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"),
        mock.patch("pathlib.Path.home", return_value=tmp_path),
    ]
    for p in patches:
        p.start()
    try:
        window = MW.MainWindow()
    finally:
        for p in patches:
            p.stop()
    window._reconnect_timer.stop()
    window.show()
    yield window
    window._agent_dock.shutdown()
    window.close()
    window.deleteLater()


def _rows(dlg) -> dict[str, str]:
    return {dlg.files.item(r, 0).text(): dlg.files.item(r, 1).text()
            for r in range(dlg.files.rowCount())}


def _dialog(win):
    win._show_tagged_files()
    dlg = win._tagged_files_dialog
    dlg.select_tag("Important")
    return dlg


def _go_to(win, dlg, shown_name: str) -> None:
    row = next(r for r in range(dlg.files.rowCount()) if dlg.files.item(r, 0).text() == shown_name)
    dlg.files.selectRow(row)
    dlg.go_to_selected()


# -- happy ---------------------------------------------------------------------


def test_happy_go_to_file_selects_the_file(store, folder, win):
    store.tag("Local", "", str(folder / "plain.txt"), "Important")
    dlg = _dialog(win)
    assert _rows(dlg) == {"plain.txt": str(folder)}
    _go_to(win, dlg, "plain.txt")
    pane = win._active_pane
    assert _wait(lambda: pane.selected_items() == [str(folder / "plain.txt")])
    assert pane.current_path == str(folder)


# -- sad -----------------------------------------------------------------------


def test_sad_controls_and_bidi_are_shown_as_the_pane_shows_them(store, folder, tmp_path, win):
    store.tag("Local", "", str(folder / f"inv{RLO}fdp.exe"), "Important")
    odd = tmp_path / f"odd{RLO}dir"
    odd.mkdir()
    (odd / "x.txt").write_text("x")
    store.tag("Local", "", str(odd / "x.txt"), "Important")
    dlg = _dialog(win)
    rows = _rows(dlg)
    assert rows["inv\ufffdfdp.exe"] == str(folder)
    assert rows["x.txt"] == str(tmp_path / "odd\ufffddir")
    for r in range(dlg.files.rowCount()):
        for c in range(dlg.files.columnCount()):
            assert RLO not in dlg.files.item(r, c).text()
    _go_to(win, dlg, "inv\ufffdfdp.exe")  # the real file (the pane leaves such a name
    # out of file operations, so it is asked for the selected row itself)
    assert _wait(lambda: [i.name for i in win._active_pane._selected_source_items()]
                 == [f"inv{RLO}fdp.exe"])


def test_sad_a_backslash_in_a_local_name_is_part_of_the_name(store, folder, win):
    store.tag("Local", "", str(folder / "a\\b.txt"), "Important")
    dlg = _dialog(win)
    assert _rows(dlg) == {"a\\b.txt": str(folder)}
    _go_to(win, dlg, "a\\b.txt")
    pane = win._active_pane
    assert _wait(lambda: pane.selected_items() == [str(folder / "a\\b.txt")])
    assert pane.current_path == str(folder)


# -- edge ----------------------------------------------------------------------


def test_edge_a_windows_style_path_splits_at_its_backslashes(store, win):
    from ui.tag_ui import split_tagged_path

    assert split_tagged_path("C:\\Users\\me\\report.pdf") == ("C:\\Users\\me", "report.pdf")
    assert split_tagged_path("/srv/a\\b.txt") == ("/srv", "a\\b.txt")
    assert split_tagged_path("/top.txt") == ("/", "top.txt")
    assert split_tagged_path("bucket-key") == ("/", "bucket-key")
