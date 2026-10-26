"""core.vt_screen writes a run of plain ASCII text into its grid in slices,
not one character at a time.

Measured 2026-10-25 (scripts/ui_bench.py ``terminal_pty_cat``): with the
terminal polls fixed, ``cat`` of a 4 MiB file still spent ~2 s of GUI CPU,
most of it in VTScreen.feed's per-character loop - every printable
character went through the state check, ``_print`` and ``_width``. A run of
printable ASCII (one cell each, nothing to interpret) is now written a row
at a time, wrapping and scrolling exactly as character by character did.

The reference is the same screen fed one character at a time: a run of one
character takes the per-character path (``_print``).
"""

from __future__ import annotations

import random

import pytest

from core.vt_screen import VTScreen
from tests.test_vt_screen import ZSH


def _state(s: VTScreen) -> tuple:
    return (s.screen_lines(), s.cursor, s._wrap_pending, list(s.scrollback), s.scrolled_total,
            s.alternate, s._top, s._bottom, s._autowrap, s._saved, s._state,
            s._main[0] if s._main else None, s._main[1] if s._main else None)


def _both(text: str, cols: int = 20, rows: int = 6, scrollback: int = 50,
          pieces: int = 1) -> tuple[VTScreen, VTScreen]:
    whole = VTScreen(cols, rows, scrollback=scrollback)
    step = max(1, len(text) // pieces)
    for i in range(0, len(text), step):
        whole.feed(text[i:i + step])
    single = VTScreen(cols, rows, scrollback=scrollback)
    for ch in text:
        single.feed(ch)
    return whole, single


def _same(text: str, **kw) -> None:
    whole, single = _both(text, **kw)
    assert _state(whole) == _state(single), repr(text)
    assert whole.take_replies() == single.take_replies()


# -- happy ---------------------------------------------------------------------


def test_happy_a_line_of_text_is_written_without_a_call_per_character(monkeypatch):
    s = VTScreen(80, 24)
    calls = []
    original = VTScreen._print
    monkeypatch.setattr(VTScreen, "_print", lambda self, ch: (calls.append(ch),
                                                              original(self, ch))[1])
    s.feed("00000042 some text of a big file being shown by cat\r\n" * 3)
    assert calls == []
    assert s.screen_lines()[2].rstrip() == "00000042 some text of a big file being shown by cat"
    assert s.cursor == (3, 0)


def test_happy_shell_output_ends_the_same_as_character_by_character():
    _same(ZSH, cols=40, rows=10)
    listing = "".join(f"-rw-r--r-- 1 user user {i * 37:8d} Oct 25 file_{i:04d}.txt\r\n"
                      for i in range(60))
    _same(listing, cols=80, rows=24, pieces=7)


def test_happy_long_lines_wrap_and_scroll_the_same():
    _same(("x" * 53 + "\r\n") * 30, cols=20, rows=6)
    _same("y" * 500, cols=20, rows=6, pieces=9)


# -- sad -----------------------------------------------------------------------


def test_sad_autowrap_off_keeps_overwriting_the_last_cell():
    _same("\x1b[?7l" + "abcdefghijklmnopqrstuvwxyz0123456789", cols=10, rows=3)
    s = VTScreen(10, 3)
    s.feed("\x1b[?7l" + "abcdefghijklmnopqrstuvwxyz")
    assert s.screen_lines()[0] == "abcdefghiz" and s.cursor == (0, 9)


def test_sad_wide_combining_and_control_characters_inside_text():
    _same("ab日本cd́ef\x7fgh\x9bij\tk\x08l", cols=8, rows=4)
    _same("日本語のテキスト" * 5 + "plain ascii after wide text " * 3, cols=11, rows=5)


def test_sad_escape_sequences_split_across_feeds():
    text = "abc\x1b[2;5Hxyz\x1b]0;title\x07def\x1b[?1049hfull\x1b[?1049lend\x1b[6n"
    for pieces in (1, 3, len(text)):
        _same(text, cols=12, rows=4, pieces=pieces)


# -- edge ----------------------------------------------------------------------


def test_edge_exactly_one_row_of_text_leaves_the_wrap_pending():
    s = VTScreen(10, 3)
    s.feed("0123456789")
    assert s.cursor == (0, 9) and s._wrap_pending
    s.feed("a")
    assert s.screen_lines()[1].startswith("a") and s.cursor == (1, 1)
    _same("0123456789", cols=10, rows=3)
    _same("0123456789\r\n", cols=10, rows=3)


def test_edge_text_wrapping_inside_a_scroll_region_and_the_alternate_screen():
    _same("\x1b[2;4r\x1b[4;1H" + "q" * 95 + "\x1b[r", cols=10, rows=6)
    _same("\x1b[?1049h" + "w" * 130 + "\x1b[?1049l" + "after", cols=10, rows=4)


def test_edge_no_scrollback_and_a_one_column_screen():
    _same("hello world" * 7, cols=1, rows=2, scrollback=0)  # ASCII only: see below
    _same("hello world" * 7, cols=3, rows=1, scrollback=5)


@pytest.mark.parametrize("seed", range(150))
def test_edge_random_streams_end_the_same(seed):
    rnd = random.Random(seed)
    parts = ["text ", "x" * rnd.randint(1, 40), "\r\n", "\n", "\r", "\t", "\x08", "日", "é",
             "é", "\x1b[K", "\x1b[2J", "\x1b[3;4H", "\x1b[?7l", "\x1b[?7h", "\x1b[2;3r",
             "\x1b[r", "\x1b[?1049h", "\x1b[?1049l", "\x1b7", "\x1b8", "\x1bM", "\x1b[5@",
             "\x1b[3P", "\x1b[2L", "\x1b[S", "\x1b[0m", "\x07", "\x7f", "\x1b]2;t\x07",
             "\x1b[6n", "~" * 9]
    text = "".join(rnd.choice(parts) for _ in range(rnd.randint(5, 80)))
    # Two columns at least: a wide character on a one-column screen is an
    # IndexError in _print either way (the widget's grid has 20 at least).
    _same(text, cols=rnd.randint(2, 30), rows=rnd.randint(1, 8),
          scrollback=rnd.choice([0, 3, 100]), pieces=rnd.randint(1, 6))


# -- e2e -----------------------------------------------------------------------


def test_e2e_the_terminal_widget_shows_the_same_document(tmp_path):
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    from ui.terminal_widget import TerminalEmulator

    app = QApplication.instance() or QApplication([])
    text = "".join(f"{i:08d} a line of a file shown by cat, some longer than the widget "
                   f"{'is wide ' * (i % 13)}\r\n" for i in range(800))
    widgets = []
    for feed_whole in (True, False):
        t = TerminalEmulator()
        t.resize(640, 360)
        t.show()
        app.processEvents()
        if feed_whole:
            t.append_output(text)
        else:
            for line in text.splitlines(keepends=True):
                for ch in line:
                    t.screen.feed(ch)
            t.render()
        for _ in range(5):  # a scroll bar that appeared resizes the grid: let it
            app.processEvents()
        widgets.append(t)
    assert widgets[0].toPlainText() == widgets[1].toPlainText()
    assert widgets[0].textCursor().position() == widgets[1].textCursor().position()
    for t in widgets:
        t.close()
        t.deleteLater()
