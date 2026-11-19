"""VTScreen: edits and resizes never leave half of a wide character.

Review 2026-11-20 (terminal round 2), each reproduced before the fix:

* A resize that cut a row between the two halves of a wide character
  kept its left half in the last column - a character two columns wide
  in one, the row one column too wide.
* Erase in line (CSI K, both directions), erase characters (CSI X),
  delete characters (CSI P) and insert characters (CSI @) starting or
  ending inside a wide character left its other half: an empty cell
  (the rest of the row shifted one column left) or a wide character
  without its right half. As xterm does, the whole character goes.
* A wide character on a screen one column wide raised IndexError out of
  ``feed`` - a terminal dock squeezed narrow and ``echo 中`` stopped the
  output poll. It is not printed there (it does not fit).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402

from core.vt_screen import VTScreen, _width  # noqa: E402
from vt_screen_reference import VTScreen as ReferenceScreen  # noqa: E402

SCREENS = (VTScreen, ReferenceScreen)


def _cells_ok(screen) -> None:
    """Every row: each empty cell right after a wide character, every wide
    character followed by its empty cell, the row exactly cols wide."""
    for line in screen._grid:  # noqa: SLF001 - the cells themselves
        assert len(line) == screen.cols
        for i, cell in enumerate(line):
            if cell == "":
                assert i > 0 and line[i - 1] != "" and _width(line[i - 1]) == 2, line
            elif _width(cell) == 2:
                assert i + 1 < len(line) and line[i + 1] == "", line
        assert sum(_width(c) if c else 0 for c in line) == screen.cols


@pytest.mark.parametrize("cls", SCREENS)
def test_sad_a_resize_through_a_wide_character_drops_it_whole(cls):
    s = cls(10, 2)
    s.feed("abc中")  # 中 in columns 3 and 4
    s.resize(4, 2)
    _cells_ok(s)
    assert s.screen_lines()[0] == "abc "


@pytest.mark.parametrize("cls", SCREENS)
@pytest.mark.parametrize("seq, expected", [
    ("\x1b[1;3H\x1b[K", "a" + " " * 9),        # from the right half to the end
    ("\x1b[1;2H\x1b[1K", " " * 3 + "b" + " " * 6),  # start to the left half
    ("\x1b[1;3H\x1b[1X", "a" + " " * 2 + "b" + " " * 6),  # X on the right half
    ("\x1b[1;2H\x1b[1X", "a" + " " * 2 + "b" + " " * 6),  # X on the left half
    ("\x1b[1;3H\x1b[1P", "a b" + " " * 7),      # P from the right half
    ("\x1b[1;2H\x1b[1P", "a b" + " " * 7),      # P of the left half only
    ("\x1b[1;3H\x1b[2@", "a" + " " * 4 + "b" + " " * 4),  # @ inside it
])
def test_sad_an_edit_inside_a_wide_character_takes_it_whole(cls, seq, expected):
    s = cls(10, 2)
    s.feed("a中b")  # a, 中 in columns 1-2, b in 3
    s.feed(seq)
    _cells_ok(s)
    assert s.screen_lines()[0] == expected


@pytest.mark.parametrize("cls", SCREENS)
def test_edge_an_insert_that_pushes_a_wide_character_over_the_edge(cls):
    s = cls(6, 2)
    s.feed("abcd中")  # 中 in the last two columns
    s.feed("\x1b[1;1H\x1b[1@")
    _cells_ok(s)
    assert s.screen_lines()[0] == " abcd "


@pytest.mark.parametrize("cls", SCREENS)
def test_edge_a_wide_character_on_a_one_column_screen_does_not_raise(cls):
    s = cls(1, 3)
    s.feed("中x\r\n文")
    _cells_ok(s)
    assert "x" in "".join(s.screen_lines())


@pytest.mark.parametrize("cls", SCREENS)
def test_happy_edits_away_from_wide_characters_are_unchanged(cls):
    s = cls(10, 2)
    s.feed("abcdef\x1b[1;2H\x1b[2P\x1b[1;1H\x1b[1@\x1b[1;5H\x1b[K")
    _cells_ok(s)
    assert s.screen_lines()[0] == " adef".ljust(10)[:4] + " " * 6
