"""The terminal sends the bytes xterm sends for Enter, Alt, Shift+Tab,
modified cursor keys and Ctrl+Space.

Reproduced 2026-11-19 (independent review): Enter sent LF (Ctrl+J) - a
program reading the keyboard raw (fzf, nano, mc, a curses menu) got
Ctrl+J; Alt+B / Alt+. sent the bare letter instead of ESC b / ESC .;
Shift+Tab sent nothing; Ctrl+Left sent a plain Left; Ctrl+Space sent a
blank instead of NUL (Emacs' set-mark).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtGui import QKeyEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

M = Qt.KeyboardModifier
K = Qt.Key
NONE, SHIFT, CTRL, ALT = M.NoModifier, M.ShiftModifier, M.ControlModifier, M.AltModifier


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def term(app, monkeypatch):
    import ui.terminal_widget as tw

    monkeypatch.setattr(tw, "on_macos", lambda: False)
    t = tw.TerminalEmulator()
    t.sent = []
    t.data_ready.connect(t.sent.append)
    yield t
    t.deleteLater()


def _press(term, key, mods=NONE, text=""):
    term.sent.clear()
    term.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, key, mods, text))
    return b"".join(term.sent)


@pytest.mark.parametrize(
    ("key", "mods", "text", "expected"),
    [
        (K.Key_Return, NONE, "\r", b"\r"),
        (K.Key_Enter, M.KeypadModifier, "\r", b"\r"),
        (K.Key_Backtab, SHIFT, "", b"\x1b[Z"),
        (K.Key_Space, CTRL, " ", b"\x00"),
        (K.Key_B, ALT, "b", b"\x1bb"),
        (K.Key_Period, ALT, ".", b"\x1b."),
        (K.Key_F, ALT | SHIFT, "F", b"\x1bF"),
        (K.Key_Backspace, ALT, "", b"\x1b\x7f"),
        (K.Key_Return, ALT, "\r", b"\x1b\r"),
        (K.Key_X, CTRL | ALT, "\x18", b"\x1b\x18"),
        (K.Key_Left, CTRL, "", b"\x1b[1;5D"),
        (K.Key_Right, CTRL, "", b"\x1b[1;5C"),
        (K.Key_Up, SHIFT, "", b"\x1b[1;2A"),
        (K.Key_Down, ALT, "", b"\x1b[1;3B"),
        (K.Key_Left, CTRL | SHIFT, "", b"\x1b[1;6D"),
        (K.Key_Home, CTRL, "", b"\x1b[1;5H"),
        (K.Key_End, SHIFT, "", b"\x1b[1;2F"),
        (K.Key_Delete, CTRL, "", b"\x1b[3;5~"),
        (K.Key_PageUp, SHIFT, "", b"\x1b[5;2~"),
        (K.Key_PageDown, ALT, "", b"\x1b[6;3~"),
    ],
)
def test_happy_keys_send_what_xterm_sends(term, key, mods, text, expected):
    assert _press(term, key, mods, text) == expected


def test_edge_modified_cursor_keys_ignore_application_mode(term):
    """xterm sends CSI 1;5 D for Ctrl+Left in either cursor key mode."""
    term.append_output("\x1b[?1h")
    assert _press(term, K.Key_Left, CTRL) == b"\x1b[1;5D"
    assert _press(term, K.Key_Left) == b"\x1bOD"


def test_sad_plain_keys_are_unchanged(term):
    assert _press(term, K.Key_Left) == b"\x1b[D"
    assert _press(term, K.Key_Delete) == b"\x1b[3~"
    assert _press(term, K.Key_Tab, NONE, "\t") == b"\t"
    assert _press(term, K.Key_Backspace) == b"\x7f"
    assert _press(term, K.Key_A, CTRL, "\x01") == b"\x01"
    assert _press(term, K.Key_X, NONE, "x") == b"x"
    assert _press(term, K.Key_X, SHIFT, "X") == b"X"


def test_edge_altgr_text_on_windows_is_plain_text(term):
    """Windows reports AltGr as Ctrl+Alt: AltGr+Q on a German keyboard is
    "@", which must arrive as "@"."""
    assert _press(term, K.Key_Q, CTRL | ALT, "@") == b"@"


def test_edge_option_composes_text_on_macos(app, monkeypatch):
    """On macOS Option types characters ("@" on a German keyboard): no
    ESC prefix there."""
    import ui.terminal_widget as tw

    monkeypatch.setattr(tw, "on_macos", lambda: True)
    t = tw.TerminalEmulator()
    sent: list[bytes] = []
    t.data_ready.connect(sent.append)
    t.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, K.Key_L, ALT, "@"))
    assert sent == [b"@"]
    t.deleteLater()


@pytest.mark.parametrize(
    ("key", "mods", "text"),
    [
        (K.Key_Backtab, SHIFT, ""),
        (K.Key_Space, CTRL, " "),
        (K.Key_Left, CTRL, ""),
        (K.Key_Up, SHIFT, ""),
        (K.Key_End, CTRL | SHIFT, ""),
    ],
)
def test_happy_the_terminal_claims_these_keys_from_shortcuts(term, key, mods, text):
    override = QKeyEvent(QEvent.Type.ShortcutOverride, key, mods, text)
    override.ignore()
    term.event(override)
    assert override.isAccepted()


def test_sad_alt_cursor_keys_stay_with_the_application(term):
    """Alt+Left / Alt+Right are History back / forward in the window."""
    override = QKeyEvent(QEvent.Type.ShortcutOverride, K.Key_Left, ALT, "")
    override.ignore()
    term.event(override)
    assert not override.isAccepted()
