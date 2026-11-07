"""The pane shows "." - this folder - as Linux listings do.

Feedback: show "." in listings; a drop or move onto "." goes into exactly
this folder (a drag from the other pane). Like "..", "." is navigation: it
is never selected for a copy, move, rename or delete - a delete of "."
would be the folder itself.
"""

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
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.3) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "sub").mkdir()
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / ".hidden").write_text("h")
    p = FilePaneWidget(LocalFS())
    p.resize(500, 400)
    p.show()
    p.navigate(str(tmp_path / "sub"))
    p.navigate(str(tmp_path))
    _pump()
    yield p
    p.close()
    p.deleteLater()


def _names(pane) -> list[str]:
    proxy = pane._proxy
    return [proxy.index(r, 0).data() for r in range(proxy.rowCount())]


def _row_of(pane, name: str) -> int:
    return _names(pane).index(name)


def test_happy_dot_comes_first_then_dotdot(pane):
    names = _names(pane)
    assert names[:2] == [".", ".."]
    assert ".hidden" not in names  # hidden files stay hidden, "." does not


def test_happy_dot_is_shown_at_the_root_too():
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(LocalFS())
    try:
        path, items = p._fetch_listing("/")
        assert [i.name for i in items[:1]] == ["."]
        assert ".." not in [i.name for i in items]
    finally:
        p.deleteLater()


def test_sad_select_all_and_a_click_never_select_dot(pane):
    pane._table.setFocus()
    pane._select_all()
    selected = {i.name for i in pane.selected_file_items()}
    assert "." not in selected and ".." not in selected
    assert "a.txt" in selected
    pane._table.clearSelection()
    pane._table.selectRow(_row_of(pane, "."))
    assert pane.selected_file_items() == []
    assert pane.selected_items() == []  # nothing to delete, copy or move


def test_happy_a_drop_on_dot_goes_into_this_folder(pane):
    table = pane._table
    rect = table.visualRect(pane._proxy.index(_row_of(pane, "."), 0))
    assert pane._folder_at(rect.center()) is None  # None: the pane's own folder
    rect = table.visualRect(pane._proxy.index(_row_of(pane, "sub"), 0))
    assert pane._folder_at(rect.center()).endswith("sub")


def test_edge_a_double_click_on_dot_stays(pane):
    here = pane._current_path
    pane._on_double_click(pane._proxy.index(_row_of(pane, "."), 0))
    _pump()
    assert pane._current_path == here


def test_edge_the_watched_listing_has_neither_dot_row(tmp_path):
    from ui.file_pane import FilePaneWidget

    backend = LocalFS()
    (tmp_path / "x").write_text("x")
    p = FilePaneWidget(LocalFS())
    try:
        path, items = p._fetch_listing(str(tmp_path))
        raw = FilePaneWidget._raw_listing(backend, path, items)
        assert [i.name for i in raw] == ["x"]
    finally:
        p.deleteLater()


def test_edge_is_nav_names_only_the_two_rows():
    assert FileItem(".", is_dir=True).is_nav and FileItem("..", is_dir=True).is_nav
    assert not FileItem(".x").is_nav and not FileItem("...").is_nav
