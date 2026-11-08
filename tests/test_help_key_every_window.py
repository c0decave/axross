"""F1 opens the right section outside the main window too (review round 2).

* ``MainWindow.show_context_help`` asked ``self.isAncestorOf(focus)``,
  which stops at a window boundary: in a detached workspace window F1 in a
  file pane opened the contents instead of *Multi-pane layout*.
* Non-modal windows (Find Files and the others) had no F1 at all - the
  window's F1 is a shortcut of the main window - though the handbook says
  "Anywhere else F1 opens the contents".
* The help topics ``find-files``, ``mail``, ``workspaces``, ``docks`` and
  ``handbook`` (core.handbook.SECTIONS) had no widget that used them.
* The Tours list's double click started the tour twice (``itemActivated``
  and ``itemDoubleClicked`` both connected), and a failed find in the
  handbook jumped to the top of the guide.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDockWidget, QLabel, QWidget  # noqa: E402

from core import handbook as H  # noqa: E402
from ui.handbook import HandbookDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while True:
        APP.processEvents()
        if time.time() >= end:
            return
        time.sleep(0.01)


@pytest.fixture(scope="module")
def _module_window(tmp_path_factory):
    from core import open_limits as OL
    from ui import main_window as MW

    tmp = tmp_path_factory.mktemp("help-window")
    patches = [
        mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp / "session.json"),
        mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp / "recents.json"),
        mock.patch.object(OL, "SETTINGS_PATH", tmp / "settings.json"),
    ]
    for patch in patches:
        patch.start()
    win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.resize(1280, 800)
    win.show()
    pump(0.1)
    try:
        yield win
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        pump()
        for patch in reversed(patches):
            patch.stop()


@pytest.fixture
def window(_module_window):
    _module_window.activateWindow()
    pump()
    yield _module_window
    for widget in APP.topLevelWidgets():
        if widget is not _module_window and widget.isVisible():
            widget.close()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _books() -> list[HandbookDialog]:
    return [w for w in APP.topLevelWidgets() if isinstance(w, HandbookDialog) and w.isVisible()]


def _f1(widget) -> list[str]:
    for book in _books():
        book.close()
    pump()
    widget.window().activateWindow()
    widget.setFocus()
    pump()
    QTest.keyClick(widget, Qt.Key.Key_F1)
    pump(0.1)
    return [book.current_heading() for book in _books()]


def test_sad_f1_in_a_pane_of_a_detached_workspace_opens_multi_pane_layout(window):
    window.new_workspace()
    pump(0.2)
    ws = window.current_workspace()
    window.detach_workspace(ws)
    pump(0.3)
    try:
        pane = window._active_pane
        assert pane.window() is ws.window
        assert window.show_context_help(pane._table).current_heading() == "Multi-pane layout"
        assert _f1(pane._table) == ["Multi-pane layout"]
        # A part of the detached window that is no pane: its section.
        label = QLabel("x", ws.window)
        assert window.show_context_help(label).current_heading() == H.SECTIONS["workspaces"]
    finally:
        ws.window.close()
        pump(0.2)


def test_sad_f1_in_find_files_opens_its_section(window):
    window._open_find_files()
    pump(0.2)
    dialog = window._find_dialogs[-1]
    assert _f1(dialog.focusWidget() or dialog) == [H.SECTIONS["find-files"]]


def test_happy_the_workspace_tabs_open_workspaces(window):
    from ui.handbook import help_topic_of

    assert help_topic_of(window._workspace_tabs.tabBar()) == "workspaces"


def test_happy_a_dock_without_a_section_opens_docks_and_a_mail_dock_mail(window):
    plain = QDockWidget("Extension", window)
    mail = QDockWidget("Mail: x", window)
    mail.setObjectName("mail-dock-x")
    for dock in (plain, mail):
        dock.setWidget(QLabel("inside"))
        window.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
    try:
        assert window.show_context_help(plain.widget()).current_heading() == \
            H.SECTIONS["docks"]
        assert window.show_context_help(mail.widget()).current_heading() == \
            H.SECTIONS["mail"]
    finally:
        for dock in (plain, mail):
            window.removeDockWidget(dock)
            dock.deleteLater()


def test_happy_f1_in_the_handbook_and_the_tours_opens_handbook_and_tours(window):
    book = window.show_handbook("transfers")
    pump()
    book.activateWindow()
    book.search.setFocus()
    pump()
    QTest.keyClick(book.search, Qt.Key.Key_F1)
    pump()
    assert book.current_heading() == H.SECTIONS["handbook"]
    assert _books() == [book]  # in this window, no second handbook
    tours = window.show_tours()
    pump()
    assert _f1(tours.list) == [H.SECTIONS["handbook"]]


def test_edge_every_non_modal_window_of_the_main_window_has_f1(window):
    """The contents at least: F1 reaches every window of its own."""
    from PyQt6.QtGui import QKeySequence, QShortcut

    window._show_tagged_files()
    window._show_scripting_guide()
    pump(0.2)
    for dialog in (window._tagged_files_dialog, window._scripting_guide):
        keys = [s.key() for s in dialog.findChildren(QShortcut)]
        assert QKeySequence("F1") in keys, type(dialog).__name__
    assert _f1(window._scripting_guide.focusWidget() or window._scripting_guide) == \
        [H.SECTIONS["scripting"]]


def test_sad_a_double_click_in_tours_starts_the_tour_once(window):
    calls: list = []
    original = window.start_tour

    def spy(tour_id):
        calls.append(tour_id)
        return original(tour_id)

    window.start_tour = spy
    try:
        dialog = window.show_tours()
        pump()
        item = dialog.list.topLevelItem(2)
        center = dialog.list.visualItemRect(item).center()
        viewport = dialog.list.viewport()
        QTest.mouseClick(viewport, Qt.MouseButton.LeftButton, pos=center)
        QTest.mouseDClick(viewport, Qt.MouseButton.LeftButton, pos=center)
        pump(0.2)
        assert len(calls) == 1
    finally:
        del window.start_tour
        if window._tour is not None:
            window._tour.end()
        pump()


def test_sad_a_failed_find_in_the_handbook_keeps_the_place():
    book = HandbookDialog(language="en")
    book.show()
    pump()
    try:
        assert book.go_to_heading("Logging")
        pump()
        scroll = book.view.verticalScrollBar().value()
        assert scroll > 0
        book.search.setText("zzqqxx-not-in-the-guide")
        assert book.find_next() is False
        pump()
        assert book.view.verticalScrollBar().value() == scroll
        assert book.current_heading() == "Logging"
        assert book.search_hint.text() == "Not found"
    finally:
        book.close()
        book.deleteLater()
