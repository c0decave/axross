"""core.vt_screen: the screen behind the terminal widget.

The widget used to strip every escape sequence and every carriage return
and append the rest. Measured 2026-10-17 against zsh on macOS: zsh's
PROMPT_SP writes "%", fills the line with spaces and returns with "\\r";
without the "\\r" each prompt landed ~120 columns to the right, behind a
"%" and a line of blanks. A shell, an editor or a pager needs a screen:
a cursor, carriage return, cursor moves, erase, scrolling, the alternate
screen.
"""

from __future__ import annotations

from collections import deque

from core.vt_screen import DEFAULT_SCROLLBACK, VTScreen

# zsh on macOS, shaped like the capture of 2026-10-17 (host and login line
# replaced): PROMPT_SP, the prompt, bracketed paste on, the echo of "ls /",
# bracketed paste off, the listing.
_SP = "\x1b[1m\x1b[7m%\x1b[27m\x1b[1m\x1b[0m" + " " * 39 + "\r \r"
_PROMPT = "\r\x1b[0m\x1b[27m\x1b[24m\x1b[Juser@host ~ % \x1b[K\x1b[?2004h"
ZSH = (
    "Last login: today\r\r\n" + _SP + _PROMPT + "l\x08ls /\x1b[?2004l\r\r\n"
    "Applications\tUsers\r\nLibrary\t\tVolumes\r\n" + _SP + _PROMPT
)


def screen(text: str, cols: int = 40, rows: int = 10, **kw) -> VTScreen:
    s = VTScreen(cols, rows, **kw)
    s.feed(text)
    return s


def visible(s: VTScreen) -> list[str]:
    return [line.rstrip() for line in s.screen_lines()]


def deque_of(lines) -> deque:
    return deque(lines, maxlen=DEFAULT_SCROLLBACK)


# -- happy ---------------------------------------------------------------------


def test_happy_the_zsh_prompt_starts_at_column_zero():
    s = screen(ZSH)
    lines = visible(s)
    assert lines[:5] == [
        "Last login: today",
        "user@host ~ % ls /",
        "Applications    Users",
        "Library         Volumes",
        "user@host ~ %",
    ]
    assert s.cursor == (4, len("user@host ~ % "))


def test_happy_carriage_return_overwrites_and_erase_clears():
    assert visible(screen("abcdef\rXY"))[0] == "XYcdef"
    assert visible(screen("abcdef\r\x1b[2C\x1b[K"))[0] == "ab"
    assert visible(screen("abcdef\r\x1b[3C\x1b[1K"))[0] == "    ef"
    assert visible(screen("abc\r\n123\x1b[2J"))[:2] == ["", ""]


def test_happy_cursor_addressing():
    s = screen("\x1b[3;5Hx\x1b[Ay\x1b[2Bz\x1b[10Dq\x1b[Gw\x1b[5d!")
    lines = visible(s)
    assert lines[1] == "     y"
    assert lines[2] == "    x"
    assert lines[3] == "w     z"
    assert lines[4] == " !"


def test_happy_output_past_the_last_row_scrolls_into_the_scrollback():
    s = screen("".join(f"line {i}\r\n" for i in range(25)), rows=10)
    assert [line.rstrip() for line in s.scrollback][:3] == ["line 0", "line 1", "line 2"]
    assert visible(s)[0] == "line 16"
    assert s.scrolled_total == 16


def test_happy_the_alternate_screen_leaves_the_shell_screen_as_it_was():
    s = screen("$ less file\r\n")
    s.feed("\x1b[?1049h\x1b[H\x1b[2Jpage one\x1b[10;1H:")
    assert visible(s)[0] == "page one" and s.alternate
    s.feed("\x1b[?1049l")
    assert not s.alternate
    assert visible(s)[0] == "$ less file"
    assert s.cursor == (1, 0)


# -- sad -----------------------------------------------------------------------


def test_sad_unknown_and_malformed_sequences_are_dropped():
    s = screen(
        "a\x1b[?9999z\x1b[1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18;19;20mb\x1b]0;title\x07c"
        "\x1bPdcs\x1b\\d\x1b(Be\x1b%Gf\x9bg"
    )
    assert visible(s)[0] == "abcdefg"


def test_sad_a_sequence_split_across_reads_still_works():
    s = VTScreen(20, 5)
    for part in ("abc\x1b", "[", "2", "D", "X\x1b]0;ti", "tle\x07Y"):
        s.feed(part)
    assert visible(s)[0] == "aXY"


def test_sad_huge_parameters_are_clamped():
    s = screen("\x1b[99999999;99999999Hx\x1b[99999999Ay\x1b[99999999@", cols=10, rows=4)
    assert s.cursor[0] == 0
    assert visible(s)[3].endswith("x")
    assert len(s.screen_lines()[0]) == 10


# -- edge ----------------------------------------------------------------------


def test_edge_autowrap_waits_for_the_next_character():
    s = screen("0123456789", cols=10, rows=3)
    assert s.cursor == (0, 9) and visible(s)[1] == ""
    s.feed("\r\n")
    assert visible(s)[:2] == ["0123456789", ""]
    s.feed("abcdefghijK")
    assert visible(s)[1:3] == ["abcdefghij", "K"]


def test_edge_resize_keeps_the_text_and_clamps_the_cursor():
    s = screen("hello world\r\nsecond", cols=20, rows=5)
    s.resize(8, 3)
    assert visible(s)[:2] == ["hello wo", "second"]
    assert s.cursor[1] <= 7
    s.resize(30, 6)
    assert visible(s)[0] == "hello wo"
    assert len(s.screen_lines()) == 6


def test_edge_wide_characters_take_two_columns():
    s = screen("日本x", cols=10)
    assert s.cursor == (0, 5)
    assert visible(s)[0] == "日本x"


def test_edge_backspace_at_the_left_margin_stays():
    assert screen("\x08\x08a").cursor == (0, 1)


def test_edge_a_cursor_report_is_answered():
    s = screen("ab\x1b[6n")
    assert s.take_replies() == b"\x1b[1;3R"
    assert s.take_replies() == b""


def test_edge_the_scrollback_is_bounded_and_the_counter_keeps_counting():
    s = screen("".join(f"{i}\r\n" for i in range(50)), rows=5, scrollback=10)
    assert len(s.scrollback) == 10
    assert s.scrolled_total == 46


def test_edge_a_scroll_region_scrolls_only_inside_it():
    s = screen("top\r\n\x1b[2;4r\x1b[4;1Ha\r\nb\r\nc", rows=6)
    lines = visible(s)
    assert lines[0] == "top"
    assert lines[1:4] == ["a", "b", "c"]
    assert s.scrolled_total == 0  # a region scroll keeps no scrollback


def test_edge_insert_delete_lines_and_characters():
    s = screen("1\r\n2\r\n3\x1b[2;1H\x1b[L", rows=5)
    assert visible(s)[:4] == ["1", "", "2", "3"]
    s.feed("\x1b[M")
    assert visible(s)[:3] == ["1", "2", "3"]
    s = screen("abcdef\x1b[1;3H\x1b[2P")
    assert visible(s)[0] == "abef"
    s.feed("\x1b[2@")
    assert visible(s)[0] == "ab  ef"
    s.feed("\x1b[1;1H\x1b[3X")
    assert visible(s)[0] == "    ef"


def test_edge_reverse_index_at_the_top_scrolls_down():
    s = screen("one\r\ntwo\x1b[H\x1bM", rows=4)
    assert visible(s)[:3] == ["", "one", "two"]


def test_edge_save_and_restore_the_cursor():
    s = screen("ab\x1b7\x1b[3;3Hx\x1b8y\x1b[s\x1b[4;1Hz\x1b[uw")
    assert visible(s)[0] == "abyw"


# -- resize with a saved cursor ------------------------------------------------
#
# Reproduced 2026-10-17: less on the alternate screen, the dock made smaller,
# less quit - the shell's cursor came back at row 23 of a 10-row grid and the
# next character raised IndexError. ESC 7 / CSI s kept a row past the grid
# the same way, and the shell lines that no longer fit while less was shown
# were dropped instead of moved into the scrollback.


def _shell_then_less(rows: int = 24) -> VTScreen:
    s = VTScreen(80, rows)
    s.feed("".join(f"line{i}\r\n" for i in range(30)) + "$ ")
    s.feed("\x1b[?1049h\x1b[24;1H:")
    return s


def test_happy_leaving_the_alternate_screen_after_a_shrink_puts_the_cursor_behind_the_prompt():
    s = _shell_then_less()
    s.resize(80, 10)
    assert s.cursor == (9, 1)  # less' prompt stays on the last row
    assert visible(s)[9] == ":"
    s.feed("\x1b[?1049l")
    assert s.cursor == (9, 2)
    assert visible(s)[9] == "$"
    s.feed("x")
    assert visible(s)[9] == "$ x"


def test_happy_shell_lines_that_no_longer_fit_go_to_the_scrollback_while_less_is_shown():
    s = VTScreen(80, 24)
    s.feed("\r\n".join(f"main{i}" for i in range(24)))
    s.feed("\x1b[?1049h")
    s.resize(80, 10)
    assert s.scrollback == deque_of(f"main{i}" for i in range(14))
    s.feed("\x1b[?1049l")
    assert visible(s)[0] == "main14"
    assert visible(s)[9] == "main23"
    assert s.cursor == (9, len("main23"))


def test_sad_a_cursor_saved_with_esc_7_or_csi_s_is_kept_inside_a_smaller_grid():
    s = VTScreen(80, 24)
    s.feed("\x1b[20;5H\x1b7")
    s.resize(80, 10)
    s.feed("\x1b8x")
    assert s.cursor[0] <= 9 and visible(s)[s.cursor[0]].endswith("x")
    s = VTScreen(80, 24)
    s.feed("\x1b[20;70H\x1b[s")
    s.resize(40, 10)
    s.feed("\x1b[uK")
    row, col = s.cursor
    assert row <= 9 and col <= 39
    assert "K" in visible(s)[row]


def test_edge_a_saved_cursor_moves_with_the_text_it_was_saved_on():
    s = VTScreen(20, 6)
    s.feed("\r\n".join(f"l{i}" for i in range(6)))  # cursor on "l5", row 5
    s.feed("\x1b[5;1H\x1b7")  # saved on "l4"
    s.resize(20, 3)  # l0..l2 go to the scrollback
    s.feed("\x1b8X")
    assert visible(s) == ["l3", "X4", "l5"]


def test_edge_growing_and_shrinking_on_the_alternate_screen_never_leaves_the_grid():
    s = _shell_then_less()
    for cols, rows in ((80, 5), (20, 40), (1, 1), (30, 3)):
        s.resize(cols, rows)
        assert 0 <= s.cursor[0] < s.rows and 0 <= s.cursor[1] < s.cols
    s.feed("\x1b[?1049l")
    assert 0 <= s.cursor[0] < s.rows and 0 <= s.cursor[1] < s.cols
    s.feed("\x1b8")
    assert 0 <= s.cursor[0] < s.rows and 0 <= s.cursor[1] < s.cols
    s.feed("still fine")


# -- the pending wrap ----------------------------------------------------------
#
# Reproduced 2026-10-17: a colour change (SGR) right after the last column
# cleared the pending wrap, so the next character overwrote the last cell -
# a coloured line of exactly the screen width lost a character.


def test_happy_a_colour_change_at_the_right_margin_keeps_the_pending_wrap():
    s = screen("\x1b[31m" + "x" * 20 + "\x1b[0mOK", cols=20, rows=4)
    assert visible(s)[:2] == ["x" * 20, "OK"]
    assert s.cursor == (1, 2)


def test_sad_a_cursor_move_or_an_erase_at_the_right_margin_still_ends_the_pending_wrap():
    s = screen("x" * 20 + "\x1b[DY", cols=20, rows=4)  # CUB: back one, overwrite
    assert visible(s)[:2] == ["x" * 18 + "Yx", ""]
    s = screen("x" * 20 + "\x1b[KY", cols=20, rows=4)  # EL: erase the last cell, write there
    assert visible(s)[:2] == ["x" * 19 + "Y", ""]
    s = screen("x" * 20 + "\x1b[1;20HY", cols=20, rows=4)  # CUP to the same cell
    assert visible(s)[:2] == ["x" * 19 + "Y", ""]


def test_edge_modes_save_and_reports_keep_the_pending_wrap():
    for seq in ("\x1b[4l", "\x1b[s", "\x1b[6n", "\x1b[0m\x1b[1;32m"):
        s = screen("x" * 10 + seq + "Z", cols=10, rows=3)
        assert visible(s)[:2] == ["x" * 10, "Z"], seq


# -- cursor keys application mode (DECCKM) -------------------------------------
#
# Reproduced 2026-10-17 with a curses program under TERM=xterm: keypad(True)
# sends ESC [ ? 1 h and then only understands ESC O A as KEY_UP; the
# ESC [ A the terminal sent arrived as three separate keys.


def test_happy_csi_question_1_h_and_l_switch_the_cursor_keys_mode():
    s = VTScreen(20, 5)
    assert s.application_cursor_keys is False
    s.feed("\x1b[?1h\x1b=")  # what curses' smkx sends for TERM=xterm
    assert s.application_cursor_keys is True
    s.feed("\x1b[?1l\x1b>")  # rmkx
    assert s.application_cursor_keys is False


def test_sad_the_ansi_mode_1_and_unrelated_private_modes_do_not_switch_it():
    s = VTScreen(20, 5)
    s.feed("\x1b[1h\x1b[?12h\x1b[?1000h\x1b[?10h")
    assert s.application_cursor_keys is False


def test_edge_the_mode_is_found_among_several_parameters_and_cleared_by_a_reset():
    s = VTScreen(20, 5)
    s.feed("\x1b[?1049;1h")
    assert s.application_cursor_keys is True and s.alternate
    s.feed("\x1b[?1049l")  # leaving the alternate screen keeps the key mode
    assert s.application_cursor_keys is True
    s.feed("\x1bc")
    assert s.application_cursor_keys is False
