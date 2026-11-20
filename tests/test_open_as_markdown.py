"""Open With > Open as Markdown renders any file in the Markdown viewer: a
README without an extension or notes.txt (a double-click does that only for
Markdown names). Before: the Open With menu had Text and Hex, no Markdown."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "notes.txt").write_text("# Heading\n\n*bold*\n")
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    win._active_pane.navigate(str(folder))
    _pump()
    yield win, folder
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _menu_for(pane, name) -> QMenu:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            sel.select(proxy.index(row, 0), QItemSelectionModel.SelectionFlag.Select
                       | QItemSelectionModel.SelectionFlag.Rows)
    return pane._build_context_menu()


def _action(menu: QMenu, command: str):
    for action in menu.actions():
        if action.property("axCommand") == command:
            return action
        if action.menu() is not None:
            found = _action(action.menu(), command)
            if found is not None:
                return found
    return None


def test_happy_open_as_markdown_renders_a_txt_file(window, monkeypatch):
    win, folder = window
    pane = win._active_pane
    opened = []
    import ui.markdown_viewer as MDV

    monkeypatch.setattr(MDV, "open_markdown_viewer",
                        lambda backend, path, parent=None, **kw: opened.append(path))
    action = _action(_menu_for(pane, "notes.txt"), "open-markdown")
    assert action is not None and action.isEnabled()
    action.trigger()
    assert opened == [str(folder / "notes.txt")]
