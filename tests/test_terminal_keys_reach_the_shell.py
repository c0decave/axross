"""Keys typed into the terminal reach the shell, not the main window.

Reproduced 2026-10-17 with the terminal dock focused in the main window:
Ctrl+W closed a file pane, Ctrl+H toggled hidden files, Ctrl+R refreshed,
Ctrl+Shift+V split the panes, F6 moved the selected file to the other
pane and Ctrl+Q quit axross - none of them reached the shell. Qt offers
a key to the focus widget as a ShortcutOverride first; the terminal only
had keyPressEvent, so every application shortcut won.
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

CTRL = Qt.KeyboardModifier.ControlModifier
SHIFT = Qt.KeyboardModifier.ShiftModifier
ALT = Qt.KeyboardModifier.AltModifier
NONE = Qt.KeyboardModifier.NoModifier

# The application shortcuts of ui/main_window.py the terminal collided with,
# plus the ones it must leave to the application.
APP_KEYS = (
    "Ctrl+W", "Ctrl+Q", "Ctrl+R", "Ctrl+H", "Ctrl+M", "F1", "F5", "F6", "F12",
    "Ctrl+Shift+V", "Ctrl+Shift+N", "Ctrl+Shift+F", "Ctrl+=", "Ctrl+-", "Ctrl+0",
    "Alt+F",
)


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _pump(app, n=5):
    for _ in range(n):
        app.processEvents()


@pytest.fixture
def window(app):
    """A main window with application shortcuts and a focused terminal."""
    from ui.terminal_widget import TerminalEmulator

    win = QMainWindow()
    fired: list[str] = []
    for seq in APP_KEYS:
        action = QAction(seq, win)
        action.setShortcut(QKeySequence(seq))
        action.triggered.connect(lambda _=False, s=seq: fired.append(s))
        win.addAction(action)
    term = TerminalEmulator()
    win.setCentralWidget(term)
    win.resize(640, 360)
    win.show()
    win.activateWindow()
    _pump(app)
    term.setFocus()
    _pump(app)
    sent: list[bytes] = []
    term.data_ready.connect(sent.append)
    yield win, term, fired, sent
    win.close()
    win.deleteLater()
    _pump(app)


def _press(app, term, key, mods=NONE):
    term.setFocus()
    QTest.keyClick(term, key, mods)
    _pump(app)


# -- happy ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (Qt.Key.Key_W, b"\x17"),
        (Qt.Key.Key_Q, b"\x11"),
        (Qt.Key.Key_R, b"\x12"),
        (Qt.Key.Key_H, b"\x08"),
        (Qt.Key.Key_M, b"\x0d"),
    ],
)
def test_happy_ctrl_letters_reach_the_shell_not_the_window(app, window, key, expected):
    _win, term, fired, sent = window
    _press(app, term, key, CTRL)
    assert fired == []
    assert sent == [expected]


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        (Qt.Key.Key_F1, b"\x1bOP"),
        (Qt.Key.Key_F5, b"\x1b[15~"),
        (Qt.Key.Key_F6, b"\x1b[17~"),
        (Qt.Key.Key_F12, b"\x1b[24~"),
    ],
)
def test_happy_function_keys_reach_the_shell_as_xterm_sequences(app, window, key, expected):
    _win, term, fired, sent = window
    _press(app, term, key)
    assert fired == []
    assert sent == [expected]


def test_happy_ctrl_shift_v_pastes_the_clipboard_into_the_shell(app, window):
    _win, term, fired, sent = window
    QApplication.clipboard().setText("make install")
    _press(app, term, Qt.Key.Key_V, CTRL | SHIFT)
    assert fired == []
    assert sent == [b"make install"]


# -- sad -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "mods", "seq"),
    [
        (Qt.Key.Key_N, CTRL | SHIFT, "Ctrl+Shift+N"),
        (Qt.Key.Key_F, CTRL | SHIFT, "Ctrl+Shift+F"),
        (Qt.Key.Key_Equal, CTRL, "Ctrl+="),
        (Qt.Key.Key_Minus, CTRL, "Ctrl+-"),
        (Qt.Key.Key_0, CTRL, "Ctrl+0"),
        (Qt.Key.Key_F, ALT, "Alt+F"),
    ],
)
def test_sad_application_and_zoom_keys_stay_with_the_application(app, window, key, mods, seq):
    """Ctrl+Shift+letter, Alt+letter and the zoom / find keys are not
    terminal input: their shortcuts still fire and nothing goes out."""
    _win, term, fired, sent = window
    _press(app, term, key, mods)
    assert fired == [seq]
    assert sent == []


def test_sad_an_empty_clipboard_sends_nothing_on_ctrl_shift_v(app, window):
    _win, term, fired, sent = window
    QApplication.clipboard().clear()
    _press(app, term, Qt.Key.Key_V, CTRL | SHIFT)
    assert fired == []
    assert sent == []


# -- edge ----------------------------------------------------------------------


def test_edge_without_focus_the_application_shortcut_still_fires(app, window):
    """The claim belongs to the focused terminal only: with the focus
    elsewhere Ctrl+W is the application's again."""
    from PyQt6.QtWidgets import QLineEdit

    win, term, fired, sent = window
    other = QLineEdit()
    win.setMenuWidget(other)
    _pump(app)
    other.setFocus()
    _pump(app)
    QTest.keyClick(other, Qt.Key.Key_W, CTRL)
    _pump(app)
    assert fired == ["Ctrl+W"]
    assert sent == []


def test_edge_shortcut_override_claims_terminal_input_only(app):
    """The terminal claims Ctrl+letter, plain function, cursor and text
    keys; Ctrl+Shift+letter, Alt+letter, modified function keys and its
    own zoom / find keys stay with the application."""
    from PyQt6.QtCore import QEvent
    from PyQt6.QtGui import QKeyEvent

    from ui.terminal_widget import TerminalEmulator

    term = TerminalEmulator()
    sent: list[bytes] = []
    term.data_ready.connect(sent.append)
    cases = [
        (Qt.Key.Key_A, CTRL, "\x01", True),
        (Qt.Key.Key_Up, NONE, "", True),
        (Qt.Key.Key_F6, NONE, "", True),
        (Qt.Key.Key_Return, NONE, "\r", True),
        (Qt.Key.Key_X, NONE, "x", True),
        (Qt.Key.Key_X, CTRL | SHIFT, "\x18", False),
        (Qt.Key.Key_X, ALT, "x", False),
        (Qt.Key.Key_F6, SHIFT, "", False),
        (Qt.Key.Key_Equal, CTRL, "=", False),
        (Qt.Key.Key_F, CTRL | SHIFT, "\x06", False),
    ]
    for key, mods, text, claimed in cases:
        override = QKeyEvent(QEvent.Type.ShortcutOverride, key, mods, text)
        override.ignore()
        term.event(override)
        assert override.isAccepted() is claimed, (key, mods)
    term.deleteLater()


# -- cursor keys application mode ----------------------------------------------


@pytest.mark.parametrize(
    ("key", "normal", "application"),
    [
        (Qt.Key.Key_Up, b"\x1b[A", b"\x1bOA"),
        (Qt.Key.Key_Down, b"\x1b[B", b"\x1bOB"),
        (Qt.Key.Key_Right, b"\x1b[C", b"\x1bOC"),
        (Qt.Key.Key_Left, b"\x1b[D", b"\x1bOD"),
        (Qt.Key.Key_Home, b"\x1b[H", b"\x1bOH"),
        (Qt.Key.Key_End, b"\x1b[F", b"\x1bOF"),
    ],
)
def test_happy_cursor_keys_follow_the_mode_the_host_asked_for(app, key, normal, application):
    from ui.terminal_widget import TerminalEmulator

    term = TerminalEmulator()
    sent: list[bytes] = []
    term.data_ready.connect(sent.append)
    QTest.keyClick(term, key)
    term.append_output("\x1b[?1h")
    QTest.keyClick(term, key)
    term.append_output("\x1b[?1l")
    QTest.keyClick(term, key)
    assert sent == [normal, application, normal]
    term.deleteLater()


def test_sad_keys_that_are_not_cursor_keys_do_not_change_with_the_mode(app):
    from ui.terminal_widget import TerminalEmulator

    term = TerminalEmulator()
    sent: list[bytes] = []
    term.data_ready.connect(sent.append)
    term.append_output("\x1b[?1h")
    for key in (Qt.Key.Key_PageUp, Qt.Key.Key_Delete, Qt.Key.Key_F5):
        QTest.keyClick(term, key)
    assert sent == [b"\x1b[5~", b"\x1b[3~", b"\x1b[15~"]
    term.deleteLater()


def test_edge_the_mode_belongs_to_the_screen_shown(app):
    """A dock tab switch shows another screen: its own mode counts."""
    from core.vt_screen import VTScreen
    from ui.terminal_widget import TerminalEmulator

    term = TerminalEmulator()
    sent: list[bytes] = []
    term.data_ready.connect(sent.append)
    curses_screen, shell_screen = VTScreen(80, 24), VTScreen(80, 24)
    curses_screen.feed("\x1b[?1h")
    term.attach_screen(curses_screen)
    QTest.keyClick(term, Qt.Key.Key_Up)
    term.attach_screen(shell_screen)
    QTest.keyClick(term, Qt.Key.Key_Up)
    assert sent == [b"\x1bOA", b"\x1b[A"]
    term.deleteLater()
