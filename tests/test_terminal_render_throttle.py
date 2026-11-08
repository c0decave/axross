"""The terminal draws a flood of output about 60 times a second, not once
per piece (ui/terminal_widget.py request_render).

Measured 2026-11-08: 4 MB of ``cat`` output in 16 KiB polls drew 262
times (3.0 s of GUI time); ``yes`` spent 26 ms per 4 KiB piece in
QTextCursor.insertText. Every drawing also copied the whole scrollback
deque (5,000 lines). The counts below are deterministic: the frame
interval is set very long (or very short) instead of relying on the
speed of the machine.
"""

from __future__ import annotations

import collections
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtGui import QTextDocument  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
_OPEN: list = []


@pytest.fixture(autouse=True)
def _close_widgets():
    yield
    while _OPEN:
        widget = _OPEN.pop()
        try:
            widget.close()
            widget.deleteLater()
        except RuntimeError:
            pass
    APP.processEvents()


def _term(width=640, height=360):
    from ui.terminal_widget import TerminalEmulator

    t = TerminalEmulator()
    _OPEN.append(t)
    t.resize(width, height)
    t.show()
    for _ in range(5):
        APP.processEvents()
    return t


def _count(monkeypatch, obj, name) -> list:
    calls = []
    original = getattr(obj, name)

    def counting(*args, **kwargs):
        calls.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(obj, name, counting)
    return calls


def _drawn(t) -> str:
    """The document as it is, without the flush toPlainText does."""
    return t.document().toPlainText()


def _wait(cond, timeout_s=30.0):
    end = time.monotonic() + timeout_s
    while not cond():
        assert time.monotonic() < end, "timed out"
        APP.processEvents()
        time.sleep(0.002)


# -- happy ---------------------------------------------------------------------


def test_happy_a_flood_of_pieces_is_drawn_once_plus_once_at_the_end(monkeypatch):
    from ui import terminal_widget as TW

    monkeypatch.setattr(TW, "RENDER_INTERVAL_MS", 600_000)
    t = _term()
    renders = _count(monkeypatch, t, "_render")
    for i in range(200):
        t.feed_bytes(f"line {i}\r\n".encode())
    assert len(renders) == 1  # the first piece at once, the rest pending
    assert "line 199" not in _drawn(t)
    assert "line 199" in t.toPlainText()  # reading the text draws what is pending
    assert len(renders) == 2
    t.toPlainText()
    assert len(renders) == 2  # nothing pending: no drawing


def test_happy_the_first_output_after_a_quiet_spell_is_drawn_at_once(monkeypatch):
    t = _term()
    renders = _count(monkeypatch, t, "_render")
    t.append_output("user@host ~ % ")
    assert len(renders) == 1
    assert _drawn(t).startswith("user@host ~ %")


def test_happy_a_pending_drawing_comes_by_itself(monkeypatch):
    from ui import terminal_widget as TW

    monkeypatch.setattr(TW, "RENDER_INTERVAL_MS", 5)
    t = _term()
    t.append_output("first\r\n")
    t.append_output("second\r\n")
    _wait(lambda: "second" in _drawn(t))
    assert not t._render_pending


# -- sad -----------------------------------------------------------------------


def test_sad_an_output_drawing_copies_no_scrollback(monkeypatch):
    """Only the new lines are taken from the scrollback deque (from its
    end); iterating it from the start copied up to 5,000 lines a time."""
    from ui import terminal_widget as TW

    monkeypatch.setattr(TW, "RENDER_INTERVAL_MS", 0)
    t = _term()
    t.append_output("".join(f"old {i}\r\n" for i in range(3000)))
    iterations = []

    class CountingDeque(collections.deque):
        def __iter__(self):
            iterations.append(1)
            return super().__iter__()

    t.screen.scrollback = CountingDeque(t.screen.scrollback, maxlen=t.screen.scrollback.maxlen)
    t.flush_render()
    t.append_output("new 1\r\nnew 2\r\n")
    t.flush_render()
    assert iterations == []
    lines = _drawn(t).split("\n")
    assert "new 2" in lines and "old 2999" in lines


def test_sad_resize_attach_and_clear_still_draw_at_once(monkeypatch):
    """Drawings that are not output (the grid, another screen, Clear) never
    wait for the frame, and they take a pending one with them."""
    from core.vt_screen import VTScreen
    from ui import terminal_widget as TW

    monkeypatch.setattr(TW, "RENDER_INTERVAL_MS", 600_000)
    t = _term()
    t.append_output("a\r\n")
    t.append_output("pending\r\n")
    assert "pending" not in _drawn(t)
    other = VTScreen(80, 24)
    other.feed("other screen")
    t.attach_screen(other)
    assert _drawn(t).startswith("other screen")
    assert not t._render_pending and not t._frame_timer.isActive()
    t.clear()
    assert _drawn(t).strip() == ""


# -- edge ----------------------------------------------------------------------


def test_edge_thousands_of_new_lines_set_the_text_once(monkeypatch):
    """More new lines than RENDER_REPLACE_LINES: one setPlainText (Qt lays
    out a fresh document faster than it inserts and trims as many lines);
    a few new lines are inserted, not the whole text set anew."""
    from ui import terminal_widget as TW

    monkeypatch.setattr(TW, "RENDER_INTERVAL_MS", 0)
    t = _term()
    t.append_output("$ ")
    sets = _count(monkeypatch, t, "setPlainText")
    t.append_output("".join(f"row {i}\r\n" for i in range(TW.RENDER_REPLACE_LINES + 500)))
    assert len(sets) == 1
    t.append_output("one more\r\n")
    # The next drawing waits as long as the last one took (the big one may
    # take long on a loaded machine): draw what is pending, then compare.
    t.flush_render()
    assert len(sets) == 1
    reference = _term()
    reference.attach_screen(type(t.screen)(t.screen.cols, t.screen.rows))
    reference.screen.feed("$ " + "".join(f"row {i}\r\n" for i in range(TW.RENDER_REPLACE_LINES + 500))
                          + "one more\r\n")
    reference._render(full=True)
    assert _drawn(t) == _drawn(reference)


def test_edge_the_caret_and_find_see_the_pending_output(monkeypatch):
    from ui import terminal_widget as TW

    monkeypatch.setattr(TW, "RENDER_INTERVAL_MS", 600_000)
    t = _term()
    t.append_output("$ ")
    t.append_output("echo needle")
    assert t.textCursor().positionInBlock() == len("$ echo needle")
    t.append_output("\r\nfound haystack\r\n$ ")
    assert "haystack" not in _drawn(t)
    assert t.find("haystack", QTextDocument.FindFlag.FindBackward)
