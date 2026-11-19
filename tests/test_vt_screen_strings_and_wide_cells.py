"""VTScreen: long OSC / DCS strings, controls inside CSI, wide-char halves.

Review 2026-11-19 (terminal round 1), each reproduced before the fix:

* An OSC or DCS string longer than 4096 characters - ``imgcat`` (OSC
  1337), a sixel picture (DCS q), a large OSC 52 copy - ended after 4096
  characters and the rest of its payload was printed on the screen as
  text, screens full of base64. A terminal consumes the string up to its
  terminator (BEL, ESC \\) or a CAN / SUB, however long: nothing of it is
  stored, so its length costs nothing.
* ESC inside a CSI sequence was swallowed with it, and the next sequence
  was printed as text (``ESC [ 1 ESC [ 3 1 m A`` showed ``[31mA``). A C0
  control inside a CSI is executed, ESC starts a new sequence, as xterm
  does; ESC inside a string followed by anything but ``\\`` starts one too.
* Overwriting one half of a wide character left the other half: a narrow
  character over the right half kept the wide one in front of it (the row
  one column too wide), over the left half it left an empty cell (the
  rest of the row one column to the left). Both halves go, as in xterm.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402

from core.vt_screen import VTScreen  # noqa: E402
from vt_screen_reference import VTScreen as ReferenceScreen  # noqa: E402

SCREENS = (VTScreen, ReferenceScreen)


def _row(screen, row: int = 0) -> str:
    return screen.screen_lines()[row]


@pytest.mark.parametrize("cls", SCREENS)
def test_happy_a_long_osc_payload_is_not_printed(cls):
    s = cls(80, 5)
    s.feed("\x1b]1337;File=inline=1:" + "QUJD" * 5000 + "\x07done")
    assert _row(s).rstrip() == "done"
    assert all(not line.strip() for line in s.screen_lines()[1:])


@pytest.mark.parametrize("cls", SCREENS)
def test_happy_a_long_sixel_dcs_ended_by_st_is_not_printed(cls):
    s = cls(80, 3)
    s.feed("\x1bPq" + "#0;2;0;0;0~~~~" * 1000 + "\x1b\\ok")
    assert _row(s).rstrip() == "ok"


@pytest.mark.parametrize("cls", SCREENS)
def test_happy_a_long_string_in_many_pieces_is_not_printed(cls):
    s = cls(40, 3)
    s.feed("\x1b]52;c;")
    for _ in range(300):
        s.feed("YWJj" * 50)
    s.feed("\x1b\\x")
    assert _row(s).rstrip() == "x"


@pytest.mark.parametrize("cls", SCREENS)
def test_sad_can_and_sub_abort_a_string(cls):
    for abort in ("\x18", "\x1a"):
        s = cls(20, 2)
        s.feed("\x1b]0;title" + abort + "seen")
        assert _row(s).rstrip() == "seen"


@pytest.mark.parametrize("cls", SCREENS)
def test_sad_esc_inside_a_csi_starts_a_new_sequence(cls):
    s = cls(20, 2)
    s.feed("\x1b[1\x1b[31mAB")
    assert _row(s).rstrip() == "AB"


@pytest.mark.parametrize("cls", SCREENS)
def test_sad_a_control_inside_a_csi_is_executed_and_the_csi_goes_on(cls):
    s = cls(20, 3)
    s.feed("abc\x1b[2\rC")  # CR inside the CSI, then CSI 2 C: two to the right
    s.feed("X")
    assert _row(s).rstrip() == "abX"
    s = cls(20, 3)
    s.feed("ab\x1b[\n1;1HZ")  # LF inside, then CSI 1;1 H
    assert _row(s).rstrip() == "Zb"


@pytest.mark.parametrize("cls", SCREENS)
def test_sad_esc_inside_a_string_followed_by_a_csi_runs_the_csi(cls):
    s = cls(20, 2)
    s.feed("\x1b]0;t\x1b[2CX")
    assert _row(s).rstrip() == "  X"


@pytest.mark.parametrize("cls", SCREENS)
def test_edge_a_narrow_character_over_the_right_half_erases_the_wide_one(cls):
    s = cls(10, 2)
    s.feed("中\x1b[1;2Hx")
    assert _row(s) == " x" + " " * 8


@pytest.mark.parametrize("cls", SCREENS)
def test_edge_a_narrow_character_over_the_left_half_erases_the_wide_one(cls):
    s = cls(10, 2)
    s.feed("中y\x1b[1;1Hx")
    assert _row(s) == "x y" + " " * 7


@pytest.mark.parametrize("cls", SCREENS)
def test_edge_a_run_of_text_over_wide_characters_keeps_the_row_width(cls):
    s = cls(10, 2)
    s.feed("中文字\x1b[1;2Habc")
    assert _row(s) == " abc字" + " " * 4
    assert sum(2 if c == "字" else len(c) for c in _row(s)) == 10


@pytest.mark.parametrize("cls", SCREENS)
def test_edge_a_wide_character_over_half_of_another_erases_it(cls):
    s = cls(10, 2)
    s.feed("中文\x1b[1;2H字")
    assert _row(s) == " 字" + " " * 7


def test_edge_the_flood_path_writes_over_wide_characters_the_same_way():
    """The bottom-row block path (_print_lines) erases a wide character
    whose half it overwrites, as the character-at-a-time path does."""
    fast, ref = VTScreen(10, 3), ReferenceScreen(10, 3)
    for s in (fast, ref):
        s.feed("\x1b[3;1H中文字\r")
        s.feed("abc\r\n" * 2)
    assert fast.screen_lines()[0].rstrip() == "abc 字"
    assert fast.screen_lines() == ref.screen_lines()
    assert list(fast.scrollback) == list(ref.scrollback)
