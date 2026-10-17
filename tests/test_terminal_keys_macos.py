"""On macOS the terminal's Ctrl is the key labelled Control, Command stays
with the application.

Qt on macOS reports Command as ControlModifier and the Control key as
MetaModifier. The terminal treated ControlModifier as the shell's Ctrl:
Command+C / Command+V sent ^C / ^V to the shell, the real Control+C sent
nothing (MetaModifier was not handled), and after the shortcut fix
Command+Q and Command+W would have gone to the shell instead of quitting
or closing. The platform is switched by patching ``on_macos``.
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
from PyQt6.QtGui import QAction, QKeySequence  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow  # noqa: E402

from ui import terminal_widget as TW  # noqa: E402

COMMAND = Qt.KeyboardModifier.ControlModifier  # what Qt reports for Command on macOS
CONTROL = Qt.KeyboardModifier.MetaModifier  # what Qt reports for Control on macOS
SHIFT = Qt.KeyboardModifier.ShiftModifier


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _pump(app, n=5):
    for _ in range(n):
        app.processEvents()


@pytest.fixture
def mac_window(app, monkeypatch):
    monkeypatch.setattr(TW, "on_macos", lambda: True)
    win = QMainWindow()
    fired: list[str] = []
    for seq in ("Ctrl+Q", "Ctrl+W", "Ctrl+R", "F6"):  # Command+Q ... on macOS
        action = QAction(seq, win)
        action.setShortcut(QKeySequence(seq))
        action.triggered.connect(lambda _=False, s=seq: fired.append(s))
        win.addAction(action)
    term = TW.TerminalEmulator()
    win.setCentralWidget(term)
    win.resize(640, 360)
    win.show()
    _pump(app)
    term.setFocus()
    _pump(app)
    sent: list[bytes] = []
    term.data_ready.connect(sent.append)
    yield win, term, fired, sent
    win.close()
    win.deleteLater()
    _pump(app)


def _press(app, term, key, mods):
    term.setFocus()
    QTest.keyClick(term, key, mods)
    _pump(app)


# -- happy ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [(Qt.Key.Key_C, b"\x03"), (Qt.Key.Key_W, b"\x17"), (Qt.Key.Key_R, b"\x12")],
)
def test_happy_the_control_key_sends_control_bytes(app, mac_window, key, expected):
    _win, term, fired, sent = mac_window
    _press(app, term, key, CONTROL)
    assert sent == [expected]
    assert fired == []


def test_happy_command_c_copies_and_command_v_pastes_into_the_shell(app, mac_window):
    _win, term, fired, sent = mac_window
    term.append_output("hello world")
    term.selectAll()
    _press(app, term, Qt.Key.Key_C, COMMAND)
    assert QApplication.clipboard().text().strip() == "hello world"
    assert sent == []
    QApplication.clipboard().setText("ls -la")
    _press(app, term, Qt.Key.Key_V, COMMAND)
    assert sent == [b"ls -la"]


# -- sad -----------------------------------------------------------------------


@pytest.mark.parametrize(("key", "seq"), [(Qt.Key.Key_Q, "Ctrl+Q"), (Qt.Key.Key_W, "Ctrl+W")])
def test_sad_command_shortcuts_stay_with_the_application(app, mac_window, key, seq):
    _win, term, fired, sent = mac_window
    _press(app, term, key, COMMAND)
    assert fired == [seq]
    assert sent == []


def test_sad_an_unbound_command_key_types_nothing(app, mac_window):
    _win, term, fired, sent = mac_window
    _press(app, term, Qt.Key.Key_K, COMMAND)
    assert sent == []


# -- edge ----------------------------------------------------------------------


def test_edge_f6_and_typed_text_still_reach_the_shell(app, mac_window):
    _win, term, fired, sent = mac_window
    _press(app, term, Qt.Key.Key_F6, Qt.KeyboardModifier.NoModifier)
    QTest.keyClicks(term, "ab")
    _pump(app)
    assert fired == []
    assert sent == [b"\x1b[17~", b"a", b"b"]


def test_edge_linux_keeps_ctrl_as_the_shells_ctrl(app, monkeypatch):
    monkeypatch.setattr(TW, "on_macos", lambda: False)
    term = TW.TerminalEmulator()
    sent: list[bytes] = []
    term.data_ready.connect(sent.append)
    QTest.keyClick(term, Qt.Key.Key_C, COMMAND)  # ControlModifier = Ctrl on Linux
    QTest.keyClick(term, Qt.Key.Key_C, CONTROL)  # Meta (Super) is not Ctrl there
    assert sent[0] == b"\x03"
    assert b"\x03" not in sent[1:]
    term.deleteLater()
