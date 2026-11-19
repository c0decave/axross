"""A pinned terminal pane takes the keys typed anywhere in its window.

Review 2026-11-19 (terminal round 1): the pin ("Pin: capture all keyboard
input") filtered only the events sent to the window object itself. A key
goes to the focus widget, so with the focus in a file pane, its filter or
the path bar, plain text went there - only keys that widget left alone
(Ctrl+W, ...) bubbled up to the window and on to the shell. Now every key
typed in a widget of the pinned pane's window goes to its terminal; the
terminal's own widgets (its search bar), other windows (a dialog, a menu)
and Ctrl+Shift+P (unpin) keep theirs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QLineEdit, QVBoxLayout, QWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def setup(monkeypatch):
    import ui.terminal_pane as tp

    monkeypatch.setattr(tp.TerminalPaneWidget, "_start_session", lambda self: None)
    top = QWidget()
    layout = QVBoxLayout(top)
    edit = QLineEdit()
    layout.addWidget(edit)
    term = tp.TerminalPaneWidget()
    layout.addWidget(term)
    top.show()
    top.activateWindow()
    QTest.qWaitForWindowExposed(top)
    sent: list[bytes] = []
    term._terminal.data_ready.connect(sent.append)
    yield top, edit, term, sent
    term.shutdown()
    top.close()
    top.deleteLater()
    APP.processEvents()


def _type(window: QWidget, key=Qt.Key.Key_A, mods=Qt.KeyboardModifier.NoModifier) -> None:
    """A key as the window system delivers it: to the window's focus widget."""
    QTest.keyClick(window.windowHandle(), key, mods)
    APP.processEvents()


def test_happy_a_pinned_terminal_takes_text_typed_into_another_widget(setup):
    top, edit, term, sent = setup
    term._btn_pin.setChecked(True)
    edit.setFocus()
    APP.processEvents()
    _type(top, Qt.Key.Key_A)
    _type(top, Qt.Key.Key_W, Qt.KeyboardModifier.ControlModifier)
    assert edit.text() == ""
    assert sent == [b"a", b"\x17"]


def test_happy_unpinned_the_widget_keeps_its_keys(setup):
    top, edit, term, sent = setup
    term._btn_pin.setChecked(True)
    term._btn_pin.setChecked(False)
    edit.setFocus()
    APP.processEvents()
    _type(top, Qt.Key.Key_A)
    assert edit.text() == "a"
    assert sent == []


def test_sad_ctrl_shift_p_unpins_from_another_widget(setup):
    top, edit, term, sent = setup
    term._btn_pin.setChecked(True)
    edit.setFocus()
    APP.processEvents()
    _type(top, Qt.Key.Key_P, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
    assert not term.is_pinned
    _type(top, Qt.Key.Key_B)
    assert edit.text() == "b"
    assert sent == []


def test_edge_the_terminal_itself_gets_each_key_once(setup):
    top, edit, term, sent = setup
    term._btn_pin.setChecked(True)
    term._terminal.setFocus()
    APP.processEvents()
    _type(top, Qt.Key.Key_A)
    assert sent == [b"a"]


def test_edge_the_terminal_search_bar_keeps_its_keys(setup):
    top, edit, term, sent = setup
    term._btn_pin.setChecked(True)
    term._terminal._toggle_search_bar()
    APP.processEvents()
    _type(top, Qt.Key.Key_X)
    assert term._terminal._search_bar._input.text() == "x"
    assert sent == []


def test_edge_a_dialog_keeps_its_keys(setup):
    top, edit, term, sent = setup
    term._btn_pin.setChecked(True)
    dialog = QDialog(top)
    field = QLineEdit(dialog)
    dialog.show()
    dialog.activateWindow()
    QTest.qWaitForWindowExposed(dialog)
    field.setFocus()
    APP.processEvents()
    _type(dialog, Qt.Key.Key_Q)
    dialog.close()
    assert field.text() == "q"
    assert sent == []
