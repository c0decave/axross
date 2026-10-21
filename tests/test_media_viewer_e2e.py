"""The media viewer end to end, from the real MainWindow (offscreen):
View -> View Media... on a local folder with nested images and a PDF,
recursive, overview, viewer, navigation, slideshow, Esc. Plus the pane's
context-menu entries and the paranoid-mode gate."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import security_mode  # noqa: E402
from tests.media_testkit import write_image, write_pdf  # noqa: E402
from ui import media_viewer as MV  # noqa: E402
from ui.main_window import MainWindow  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_until(cond, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


@pytest.fixture
def window():
    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    win = MainWindow()
    win.resize(1000, 700)
    win.show()
    APP.processEvents()
    yield win
    for w in QApplication.topLevelWidgets():
        if isinstance(w, MV.MediaViewerDialog):
            w.close()
    win.close()
    APP.processEvents()
    security_mode.set_policy(previous)


@pytest.fixture
def tree(tmp_path) -> Path:
    top = tmp_path / "photos"
    write_image(top / "a.png", size=(120, 80), color=(255, 0, 0))
    write_image(top / "trip" / "b.jpg", size=(80, 120), color=(0, 255, 0))
    write_image(top / "trip" / "day2" / "c.png", size=(64, 64), color=(0, 0, 255))
    write_pdf(top / "itinerary.pdf", pages=2)
    (top / "notes.txt").write_text("not media")
    return top


def _media_dialogs() -> list[MV.MediaViewerDialog]:
    return [
        w
        for w in QApplication.topLevelWidgets()
        if isinstance(w, MV.MediaViewerDialog) and w.isVisible()
    ]


def _answer_options(**choices) -> None:
    """Fill in the options dialog once it is up, then press OK."""

    def fill() -> None:
        dlg = QApplication.activeModalWidget()
        if not isinstance(dlg, MV.MediaViewOptionsDialog):
            QTimer.singleShot(10, fill)
            return
        dlg.recursive_box.setChecked(choices.get("recursive", False))
        dlg.video_box.setChecked(False)
        getattr(dlg, choices.get("mode", "overview") + "_radio").setChecked(True)
        dlg.accept()

    QTimer.singleShot(0, fill)


def _pane_at(window, path: Path):
    pane = window._active_pane
    pane.navigate(str(path))
    assert wait_until(lambda: pane.current_path == str(path))
    return pane


def test_e2e_view_media_recursive_overview_viewer_slideshow_escape(window, tree):
    _pane_at(window, tree)
    _answer_options(recursive=True, mode="overview")
    window._view_media_action.trigger()

    assert wait_until(lambda: len(_media_dialogs()) == 1)
    dlg = _media_dialogs()[0]
    assert wait_until(lambda: dlg.scan_finished)
    assert dlg.overview.count() == 4
    names = [i.name for i in dlg.overview.visible_items()]
    assert names == ["a.png", "b.jpg", "c.png", "itinerary.pdf"]
    assert wait_until(lambda: dlg.model.thumbnail_count() == 4)

    view = dlg.overview.view
    view.setCurrentIndex(view.model().index(0, 0))
    QTest.keyClick(view, Qt.Key.Key_Return)
    viewer = dlg.viewer
    assert dlg.stack.currentWidget() is viewer
    assert wait_until(lambda: viewer.mode == "image")
    assert viewer.current_item().name == "a.png"

    for expected in ("b.jpg", "c.png", "itinerary.pdf"):
        QTest.keyClick(viewer, Qt.Key.Key_Right)
        assert viewer.current_item().name == expected
    assert wait_until(lambda: viewer.mode == "pdf")
    QTest.keyClick(viewer, Qt.Key.Key_Down)  # pages have their own keys
    assert (viewer.current_item().name, viewer.current_page) == ("itinerary.pdf", 1)
    QTest.keyClick(viewer, Qt.Key.Key_Right)  # the last file: stays
    assert (viewer.current_item().name, viewer.current_page) == ("itinerary.pdf", 1)

    QTest.keyClick(viewer, Qt.Key.Key_Home)
    assert wait_until(lambda: viewer.mode == "image")
    viewer.start_slideshow(interval_ms=50)
    assert wait_until(lambda: viewer.current_index == 2, timeout=10)

    QTest.keyClick(viewer, Qt.Key.Key_Escape)
    assert dlg.stack.currentWidget() is dlg.overview
    assert not viewer.slideshow_active
    QTest.keyClick(dlg.overview.view, Qt.Key.Key_Escape)
    assert wait_until(lambda: not _media_dialogs())


def test_happy_slideshow_start_mode_from_the_view_menu(window, tree):
    _pane_at(window, tree)
    _answer_options(recursive=False, mode="slideshow")
    window._view_media_action.trigger()
    assert wait_until(lambda: len(_media_dialogs()) == 1)
    dlg = _media_dialogs()[0]
    assert wait_until(lambda: dlg.scan_finished)
    assert dlg.stack.currentWidget() is dlg.viewer
    assert dlg.viewer.slideshow_active
    assert [i.name for i in dlg.viewer.items()] == ["a.png", "itinerary.pdf"]


def test_happy_view_selected_media_from_the_context_menu(window, tree):
    pane = _pane_at(window, tree)
    pane._restore_selection({"a.png", "trip"}, "a.png")
    assert {i.name for i in pane.selected_file_items()} == {"a.png", "trip"}
    action = next(
        a for a in pane._build_context_menu().actions() if a.text() == "View Selected Media…"
    )
    _answer_options(recursive=False, mode="browse")
    action.trigger()
    assert wait_until(lambda: len(_media_dialogs()) == 1)
    dlg = _media_dialogs()[0]
    assert wait_until(lambda: dlg.scan_finished)
    assert sorted(i.name for i in dlg.viewer.items()) == ["a.png", "b.jpg"]


def test_edge_context_menu_offers_view_media_without_a_selection(window, tree):
    pane = _pane_at(window, tree)
    texts = [a.text() for a in pane._build_context_menu().actions()]
    assert "View Media…" in texts
    assert "View Selected Media…" not in texts


def test_sad_cancelling_the_options_opens_nothing(window, tree):
    _pane_at(window, tree)

    def cancel() -> None:
        dlg = QApplication.activeModalWidget()
        if not isinstance(dlg, MV.MediaViewOptionsDialog):
            QTimer.singleShot(10, cancel)
            return
        dlg.reject()

    QTimer.singleShot(0, cancel)
    window._view_media_action.trigger()
    wait_until(lambda: False, timeout=0.2)
    assert _media_dialogs() == []


def test_sad_paranoid_mode_refuses_the_media_viewer(window, tree, monkeypatch):
    _pane_at(window, tree)
    security_mode.set_policy("paranoid")
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **kw: warned.append(a))
    window._view_media_action.trigger()
    wait_until(lambda: False, timeout=0.1)
    assert warned and _media_dialogs() == []
