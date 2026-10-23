"""The editor window's [x] corner and closing it with its last tab.

Operator: *„editor hat kein close button...und schliesst auch
nicht wenn man nach dem letzten tab close tab sagt"*.

Root cause: every editor *dialog* got the [x] / maximize corner
(ui/close_corner.py; tests/test_editor_close_button.py covers
TextEditorDialog and HexEditorDialog), but the tabbed EditorWindow - a
QMainWindow, what Edit / F4 in a pane opens since the editor became tabs -
never installed it; on a window manager without title-bar buttons (the
operator's tiling setup) it had no visible close control. And close_tab()
removed the last tab and left an empty window behind.
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

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox, QToolButton  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
FS = LocalFS()
ASK = "ui.editor_window.QMessageBox.question"


def _wait_for_tabs(editor, count: int, timeout: float = 5.0) -> None:
    """open_in_editor reads in the background: the tab follows."""
    end = time.time() + timeout
    while time.time() < end and editor.tabs.count() != count:
        APP.processEvents()
        time.sleep(0.01)
    assert editor.tabs.count() == count


@pytest.fixture
def window():
    from ui.editor_window import EditorWindow

    win = EditorWindow()
    win.resize(900, 600)
    win.show()
    APP.processEvents()
    yield win
    with mock.patch(ASK, return_value=QMessageBox.StandardButton.Discard):
        win.close()
    win.deleteLater()
    APP.processEvents()


def _file(tmp_path, name="a.txt", text="x\n"):
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def _corner(win, name="axCloseCorner"):
    return win.findChild(QToolButton, name)


# -- the [x] corner ----------------------------------------------------------------------


def test_happy_the_editor_window_has_close_and_maximize_in_its_top_right_corner(window, tmp_path):
    window.open_file(FS, _file(tmp_path))
    APP.processEvents()
    close, maximize = _corner(window), _corner(window, "axMaximizeCorner")
    assert close is not None and maximize is not None
    assert close.isVisible() and maximize.isVisible() and not close.icon().isNull()
    pos = close.mapTo(window, close.rect().topLeft())
    assert pos.x() > window.width() * 0.8 and pos.y() < 60
    assert maximize.mapTo(window, maximize.rect().topLeft()).x() < pos.x()
    assert close.toolTip()


def test_happy_e2e_clicking_the_corner_closes_a_clean_editor(window, tmp_path):
    window.open_file(FS, _file(tmp_path))
    assert _corner(window) is not None  # None would abort QTest
    QTest.mouseClick(_corner(window), Qt.MouseButton.LeftButton)
    APP.processEvents()
    assert not window.isVisible()


def test_sad_the_corner_asks_for_unsaved_changes_and_cancel_keeps_the_window(window, tmp_path):
    tab = window.open_file(FS, _file(tmp_path))
    tab.editor.insertPlainText("edited")
    with mock.patch(ASK, return_value=QMessageBox.StandardButton.Cancel) as asked:
        _corner(window).click()
        APP.processEvents()
    assert asked.call_count == 1 and window.isVisible() and window.tabs.count() == 1


# -- closing the last tab ----------------------------------------------------------------


def test_happy_e2e_ctrl_w_on_the_last_tab_closes_the_window(window, tmp_path):
    window.open_file(FS, _file(tmp_path, "a.txt"))
    window.open_file(FS, _file(tmp_path, "b.txt"))
    editor = window.current_tab().editor
    editor.setFocus()
    APP.processEvents()
    QTest.keyClick(editor, Qt.Key.Key_W, Qt.KeyboardModifier.ControlModifier)
    assert window.tabs.count() == 1 and window.isVisible()  # one left: the window stays
    editor = window.current_tab().editor
    editor.setFocus()
    APP.processEvents()
    QTest.keyClick(editor, Qt.Key.Key_W, Qt.KeyboardModifier.ControlModifier)
    APP.processEvents()
    assert window.tabs.count() == 0 and not window.isVisible()


def test_happy_the_tab_x_of_the_last_tab_closes_the_window(window, tmp_path):
    window.open_file(FS, _file(tmp_path))
    window.tabs.tabCloseRequested.emit(0)
    APP.processEvents()
    assert not window.isVisible()


def test_sad_cancel_on_the_last_modified_tab_keeps_tab_and_window(window, tmp_path):
    tab = window.open_file(FS, _file(tmp_path))
    tab.editor.insertPlainText("edited")
    with mock.patch(ASK, return_value=QMessageBox.StandardButton.Cancel) as asked:
        assert window.close_tab(0) is False
    assert asked.call_count == 1  # asked once - not again by the window's own close
    assert window.isVisible() and window.tabs.count() == 1


def test_edge_discard_on_the_last_modified_tab_closes_without_asking_twice(window, tmp_path):
    path = _file(tmp_path)
    tab = window.open_file(FS, path)
    tab.editor.insertPlainText("edited")
    with mock.patch(ASK, return_value=QMessageBox.StandardButton.Discard) as asked:
        assert window.close_tab(0) is True
        APP.processEvents()
    assert asked.call_count == 1 and not window.isVisible()
    assert Path(path).read_text() == "x\n"


def test_edge_close_tab_in_an_empty_window_closes_it(window):
    assert window.tabs.count() == 0
    window.close_tab(window.tabs.currentIndex())
    APP.processEvents()
    assert not window.isVisible()


def test_edge_the_window_opens_again_after_its_last_tab_closed(tmp_path):
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    try:
        win.open_in_editor(FS, _file(tmp_path))
        editor = win._editor_window
        _wait_for_tabs(editor, 1)
        # The main window makes it a window of its own after the corner was
        # added: the title bar's Maximize stays.
        assert editor.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
        assert editor.findChild(QToolButton, "axCloseCorner").isVisible()
        editor.close_tab(0)
        APP.processEvents()
        assert not editor.isVisible()
        win.open_in_editor(FS, _file(tmp_path, "b.txt"))
        _wait_for_tabs(editor, 1)
        assert editor.isVisible() and editor.current_tab().path.endswith("b.txt")
    finally:
        with mock.patch(ASK, return_value=QMessageBox.StandardButton.Discard):
            win._editor_window.close()
            win.close()
        win.deleteLater()
        APP.processEvents()
