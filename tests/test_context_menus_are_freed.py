"""Right-click menus are deleted once they close.

Review 4 (features/extensions): every right click in a file pane left its
menu (four QMenus, ~71 actions) on the pane for good - 500 right clicks
grew the process by ~130 MB - and the actions' slots kept a switched-off
extension's module alive. The archive pane, Find Files, the CAS dialog and
the metadata dialog built and kept their menus the same way.
"""

from __future__ import annotations

import gc
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _settle(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while True:
        APP.processEvents()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        if time.time() >= end:
            return
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "notes.txt").write_text("x")
    (folder / "sub").mkdir()
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    win._active_pane.navigate(str(folder))
    _settle(0.3)
    yield win
    win._quit_with_transfers = True
    win.close()
    win.deleteLater()
    _settle()


def _select(pane, name: str) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            sel.select(proxy.index(row, 0),
                       QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)


@pytest.fixture
def dismissed_menus(monkeypatch):
    """QMenu.exec returns at once, as when the user presses Escape."""
    shown = []
    monkeypatch.setattr(QMenu, "exec", lambda self, *a, **k: shown.append(self) or None)
    return shown


def test_happy_right_clicks_leave_no_menu_on_the_pane(window, dismissed_menus):
    pane = window._active_pane
    _select(pane, "notes.txt")
    for _ in range(20):
        pane._show_context_menu(None)
        _settle(0)
    assert len(dismissed_menus) == 20
    assert pane.findChildren(QMenu) == []


def test_happy_an_entry_chosen_in_the_menu_still_runs(window, monkeypatch):
    """The menu is deleted after exec() - an entry triggered inside it ran."""
    pane = window._active_pane
    _select(pane, "notes.txt")
    ran = []

    def choose(menu, *_a, **_k):
        for action in menu.actions():
            if action.property("axCommand") == "copy-path":
                action.triggered.connect(lambda *_: ran.append(True))
                action.trigger()
                return action
        return None

    monkeypatch.setattr(QMenu, "exec", choose)
    pane._show_context_menu(None)
    _settle(0)
    assert ran == [True]
    assert pane.findChildren(QMenu) == []


def test_sad_a_switched_off_extension_module_is_freed_after_right_clicks(window, dismissed_menus):
    import ui.extension_host as XH

    host = window.extension_host
    host.set_enabled("bundled:checksum_manifest", True)
    _settle(0.1)
    pane = window._active_pane
    _select(pane, "notes.txt")
    for _ in range(5):
        pane._show_context_menu(None)
        _settle(0)
    host.set_enabled("bundled:checksum_manifest", False)
    _settle(0.1)
    gc.collect()
    spare = XH._SPARE.get("axross_extension_bundled_checksum_manifest")
    assert spare is None or spare[1]() is None


def test_edge_the_header_menu_is_freed_too(window, dismissed_menus):
    pane = window._active_pane
    for _ in range(3):
        pane._show_header_menu(None)
        _settle(0)
    assert len(dismissed_menus) == 3
    assert pane.findChildren(QMenu) == []


def test_edge_archive_pane_and_bookmark_sidebar_free_their_menus(tmp_path, dismissed_menus):
    import io
    import zipfile

    from PyQt6.QtCore import QPoint

    from core.bookmarks import Bookmark, BookmarkManager
    import core.bookmarks as BM
    from ui.archive_pane import ArchivePaneWidget
    from ui.bookmark_sidebar import BookmarkSidebar

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", b"x")
    (tmp_path / "a.zip").write_bytes(buf.getvalue())
    archive = ArchivePaneWidget(str(tmp_path / "a.zip"))
    archive.show()
    _settle(0.1)
    for _ in range(3):
        archive._show_context_menu(QPoint(1, 1))
        _settle(0)
    assert archive.findChildren(QMenu) == []
    archive.deleteLater()

    old = BM.BOOKMARKS_FILE
    BM.BOOKMARKS_FILE = tmp_path / "bookmarks.json"
    try:
        manager = BookmarkManager()
        manager.add(Bookmark("tmp", "/tmp"))
        side = BookmarkSidebar(manager)
        side.show()
        _settle(0.1)
        for _ in range(3):
            side._show_context_menu(QPoint(1, 1))
            _settle(0)
        assert side.findChildren(QMenu) == []
        side.deleteLater()
    finally:
        BM.BOOKMARKS_FILE = old
    assert len(dismissed_menus) == 6
    _settle(0)
