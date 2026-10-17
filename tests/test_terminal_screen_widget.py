"""The terminal widget shows a VTScreen (core.vt_screen) and keeps the
pty the size of the widget.

Reproduced 2026-10-17 against zsh on macOS through the old widget: every
prompt line began with "%" and ~120 blanks, the prompt itself far to the
right (lines of 151-161 characters) - the widget dropped "\\r" and every
cursor move. And the pty was fixed at 120x40 whatever the widget showed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402

from tests.test_vt_screen import ZSH  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _pump(app, n=5):
    for _ in range(n):
        app.processEvents()


def _term(app, width=640, height=360):
    from ui.terminal_widget import TerminalEmulator

    t = TerminalEmulator()
    t.resize(width, height)
    t.show()
    _pump(app)
    return t


def _lines(t):
    return [line.rstrip() for line in t.toPlainText().split("\n")]


class FakeSession:
    def __init__(self):
        self.sizes = []
        self.written = b""
        self.out = []
        self.is_active = True

    def start(self):
        pass

    def resize(self, rows, cols):
        self.sizes.append((rows, cols))

    def write(self, data):
        self.written += data

    def read(self, size=4096):
        return self.out.pop(0) if self.out else b""

    def close(self):
        self.is_active = False


# -- happy ---------------------------------------------------------------------


def test_happy_the_zsh_prompt_is_at_column_zero_and_the_caret_on_the_cursor(app):
    t = _term(app)
    t.append_output(ZSH)
    lines = _lines(t)
    assert lines[:5] == ["Last login: today", "user@host ~ % ls /", "Applications    Users",
                         "Library         Volumes", "user@host ~ %"]
    assert not any(line.startswith("%") for line in lines)
    cursor = t.textCursor()
    assert cursor.blockNumber() == 4
    assert cursor.positionInBlock() == len("user@host ~ % ")


def test_happy_the_grid_follows_the_widget_size(app):
    t = _term(app, 640, 360)
    seen = []
    t.grid_resized.connect(lambda rows, cols: seen.append((rows, cols)))
    rows, cols = t.grid_size()
    assert (t.screen.rows, t.screen.cols) == (rows, cols)
    t.resize(960, 540)
    _pump(app)
    assert seen and seen[-1] == t.grid_size()
    assert t.grid_size()[1] > cols and t.grid_size()[0] > rows
    assert (t.screen.rows, t.screen.cols) == t.grid_size()


def test_happy_the_pane_gives_the_pty_the_widget_size_and_follows_resizes(app, monkeypatch):
    from ui import terminal_pane as TP

    fake = FakeSession()
    monkeypatch.setattr(TP, "LocalTerminalSession", lambda cwd=None: fake)
    pane = TP.TerminalPaneWidget()
    pane.resize(700, 400)
    pane.show()
    _pump(app)
    assert fake.sizes and fake.sizes[-1] == pane._terminal.grid_size()
    pane.resize(1000, 600)
    _pump(app)
    assert fake.sizes[-1] == pane._terminal.grid_size()
    fake.out.append("café \x1b[6n".encode())
    pane._poll_output()
    assert "café" in pane._terminal.toPlainText()
    assert fake.written.endswith(b"R")  # the cursor report went back to the host
    pane.shutdown()


# -- sad -----------------------------------------------------------------------


def test_sad_a_utf8_character_split_between_reads_arrives_whole(app):
    t = _term(app)
    t.feed_bytes("日".encode()[:2])
    t.feed_bytes("日".encode()[2:] + b"\xff!")
    assert _lines(t)[0] == "日�!"


def test_sad_session_messages_start_on_a_fresh_line(app):
    t = _term(app)
    t.append_output("user@host ~ % ")
    t.message("\n--- Session ended ---\n")
    assert "--- Session ended ---" in _lines(t)


# -- edge ----------------------------------------------------------------------


def test_edge_incremental_rendering_equals_a_full_rendering(app):
    t = _term(app)
    rows = t.screen.rows
    for i in range(3 * rows):
        t.append_output(f"line {i}\r\n")
    expected = list(t.screen.scrollback) + [line.rstrip() for line in t.screen.screen_lines()]
    assert _lines(t) == expected
    assert _lines(t)[0] == "line 0"


def test_edge_the_alternate_screen_hides_the_history_until_it_is_left(app):
    t = _term(app)
    t.append_output("".join(f"old {i}\r\n" for i in range(3 * t.screen.rows)))
    t.append_output("\x1b[?1049h\x1b[H\x1b[2Jeditor")
    assert _lines(t)[0] == "editor" and "old 0" not in t.toPlainText()
    t.append_output("\x1b[?1049l")
    assert _lines(t)[0] == "old 0"
    assert "editor" not in t.toPlainText()


def test_edge_dock_tabs_keep_their_own_screens(app):
    from ui.terminal_widget import TerminalDock

    dock = TerminalDock()
    dock.resize(800, 400)
    dock.show()
    _pump(app)
    a, b = FakeSession(), FakeSession()
    dock._session_combo.addItem("two")
    dock._get_or_create_tab("Local Shell").session = a
    dock._get_or_create_tab("two").session = b
    dock._active_key = "Local Shell"
    a.out.append(b"from a\r\n")
    b.out.append(b"from b\r\n")
    dock._poll_output()
    assert "from a" in dock._terminal.toPlainText()
    assert "from b" not in dock._terminal.toPlainText()
    dock._session_combo.setCurrentText("two")
    _pump(app)
    assert "from b" in dock._terminal.toPlainText()
    assert "from a" not in dock._terminal.toPlainText()
    assert b.sizes and b.sizes[-1] == dock._terminal.grid_size()
    dock.shutdown()
