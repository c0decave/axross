"""Scripts dock output: every kind of line break counts as a line.

Review 2026-11-20 (scripts round 2): the OutputLimiter that keeps a
flooding script from freezing the window counted "\\n" only, but the
output pane (a QTextCursor.insertText) starts a new block for a lone
"\\r", U+2028, U+2029 and Qt's own U+FDD0 / U+FDD1 as well. A progress
bar written with "\\r" (999 of them per counted line) made up to a
thousand blocks per line the limit allowed: 148 KB/s instead of 2.7 MB/s,
chunks of 0.6 s on the GUI thread. CR LF is one line end, also split
between two reads; a lone CR and the other separators are line ends,
counted against the limits; U+FDD0 / U+FDD1 are U+FFFD.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import script_runner as SR  # noqa: E402

BLOCK_BREAKS = ("\r", "\u2028", "\u2029", "\ufdd0", "\ufdd1")


def _blocks(text: str) -> int:
    """The blocks a QTextCursor.insertText of *text* makes beyond the first."""
    return text.count("\n") + sum(text.count(c) for c in BLOCK_BREAKS)


def test_sad_carriage_returns_count_against_the_line_limit():
    lim = SR.OutputLimiter(max_line_chars=100, max_lines=50)
    shown = lim.feed((b"\r" * 999 + b"\n") * 64)
    assert _blocks(shown) <= 51
    assert "\r" not in shown


def test_sad_unicode_separators_count_too():
    lim = SR.OutputLimiter(max_line_chars=100, max_lines=10)
    shown = lim.feed(("x\u2028" * 500 + "y\u2029" * 500 + "\ufdd0\ufdd1").encode())
    assert _blocks(shown) <= 11
    assert not any(c in shown for c in BLOCK_BREAKS)


def test_happy_crlf_is_one_line_end_also_across_two_reads():
    lim = SR.OutputLimiter()
    assert lim.feed(b"one\r\ntwo\r") + lim.feed(b"\nthree\r\n") == "one\ntwo\nthree\n"


def test_edge_a_lone_cr_at_the_very_end_is_a_line_end_on_flush():
    lim = SR.OutputLimiter()
    assert lim.feed(b"progress 100%\r") + lim.flush() == "progress 100%\n"


def test_happy_plain_output_is_unchanged():
    lim = SR.OutputLimiter(max_line_chars=50, max_lines=10)
    assert lim.feed(b"a\nb\n") == "a\nb\n"
