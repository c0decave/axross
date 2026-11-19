"""Bracketed paste: a shell that asks for it (ESC[?2004h, bash 5.1+, zsh,
fish) gets a paste wrapped in ESC[200~ ... ESC[201~.

Reproduced 2026-11-19 (independent review): the mode was ignored, so a
pasted "cd /tmp\\nrm -rf build\\n" reached the shell as typed lines and
each ran at once, instead of being inserted as one edit the user confirms.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QMimeData  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def term(app):
    from ui.terminal_widget import TerminalEmulator

    t = TerminalEmulator()
    t.sent = []
    t.data_ready.connect(t.sent.append)
    yield t
    t.deleteLater()


def _paste(term, text: str) -> bytes:
    term.sent.clear()
    mime = QMimeData()
    mime.setText(text)
    term.insertFromMimeData(mime)
    return b"".join(term.sent)


def test_happy_the_screen_tracks_the_mode():
    from core.vt_screen import VTScreen

    screen = VTScreen(80, 24)
    assert screen.bracketed_paste is False
    screen.feed("\x1b[?2004h")
    assert screen.bracketed_paste is True
    screen.feed("\x1b[?2004l")
    assert screen.bracketed_paste is False
    screen.feed("\x1b[?1;2004h")
    assert screen.bracketed_paste is True
    screen.feed("\x1bc")  # a reset ends it
    assert screen.bracketed_paste is False


def test_happy_a_paste_is_wrapped_while_the_shell_asks(term):
    term.feed_bytes(b"\x1b[?2004h$ ")
    assert _paste(term, "cd /tmp\nrm -rf build\n") == (
        b"\x1b[200~cd /tmp\nrm -rf build\n\x1b[201~"
    )


def test_sad_without_the_mode_a_paste_is_sent_as_it_is(term):
    assert _paste(term, "ls\n") == b"ls\n"
    term.feed_bytes(b"\x1b[?2004h\x1b[?2004l")
    assert _paste(term, "ls\n") == b"ls\n"


def test_edge_a_pasted_end_marker_cannot_break_out(term):
    """Text carrying ESC[201~ itself would end the paste early and run the
    rest as typed: the markers in the text are removed."""
    term.feed_bytes(b"\x1b[?2004h")
    sent = _paste(term, "echo hi\x1b[201~rm -rf ~\n")
    assert sent == b"\x1b[200~echo hirm -rf ~\n\x1b[201~"
    assert sent.count(b"\x1b[201~") == 1


def test_edge_the_mode_belongs_to_the_screen_shown(term):
    from core.vt_screen import VTScreen

    other = VTScreen(80, 24)
    other.feed("\x1b[?2004h")
    term.attach_screen(other)
    assert _paste(term, "x") == b"\x1b[200~x\x1b[201~"
