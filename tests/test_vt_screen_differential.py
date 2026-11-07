"""core.vt_screen takes the pieces an output flood is made of whole - and
leaves exactly the screen the character-at-a-time parser left.

Measured 2026-11-02 (scripts/bench_vt_screen.py, CPU time, best of
interleaved rounds against the 0.14.250 parser): parsing ``yes`` output
(40 000 lines of "y\\r\\n") took 65 ms, ``cat`` of 10 000 lines 22 ms, an
``ls --color`` listing of 4000 lines 152 ms. Each line went through
``_linefeed`` -> ``_scroll_up`` -> ``_push_scrollback`` and the CR and LF
through ``_control``, each CSI byte through ``_csi_char``, each OSC byte
through the state loop. Now lines of plain ASCII ended by CR LF at the
bottom of the shell's screen go in as a block (only the rows still on the
screen at the end are made, the rest go to the scrollback as text), a
CSI sequence or OSC string is taken with one regex match, SGR returns
before its parameters are parsed, and a line feed scrolls inline: 3 ms,
4 ms and 60 ms (lines wider than the screen 13 -> 5 ms, a full-screen
app 34 -> 25 ms, wide characters 29 -> 26 ms: none slower).

None of it may change what the screen shows. The reference is
tests/vt_screen_reference.py, the 0.14.250 parser kept as it was: both are
fed the same text - floods, ``ls --color``, a full-screen app, wide and
combining characters, overlong sequences, random tokens and random byte
soup - as UTF-8 cut at random byte offsets and decoded as the widget does
(escape sequences and characters split across feeds), with the screen
resized now and then, and after every piece the grid, cursor, scrollback,
counters, modes, the saved and the alternate screen, the parser state
and the replies must be the same.
"""

from __future__ import annotations

import codecs
import random

import pytest

from core.vt_screen import VTScreen
from tests.vt_screen_reference import VTScreen as Reference


def _state(s) -> tuple:
    return (s.cols, s.rows, s.screen_lines(), s._grid, s.cursor, list(s.scrollback),
            s.scrollback.maxlen, s.scrolled_total, s.alternate, s.application_cursor_keys,
            s._wrap_pending, s._top, s._bottom, s._autowrap, s._saved, s._main,
            s._state, s._params, s._string_len)


def _pieces(text: str, rnd: random.Random, sizes=(1, 2, 3, 5, 17, 80, 400, 4096)) -> list[str]:
    """*text* as UTF-8 cut at random byte offsets, decoded as the widget does."""
    raw = text.encode("utf-8", "surrogatepass")
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    out, i = [], 0
    while i < len(raw):
        n = rnd.choice(sizes)
        out.append(decoder.decode(raw[i:i + n]))
        i += n
    out.append(decoder.decode(b"", final=True))
    return out


def _feed(screen, piece: str):
    """What feed raised, if anything (a wide character on a one-column
    screen is an IndexError in both): the same has to happen to both."""
    try:
        screen.feed(piece)
    except IndexError as exc:
        return type(exc)
    return None


def _same(text: str, cols: int = 80, rows: int = 24, scrollback: int = 5000, *,
          seed: int = 0, sizes=(1, 2, 3, 5, 17, 80, 400, 4096), resize: bool = False) -> None:
    rnd = random.Random(seed)
    new, ref = VTScreen(cols, rows, scrollback=scrollback), Reference(cols, rows,
                                                                       scrollback=scrollback)
    for n, piece in enumerate(_pieces(text, rnd, sizes)):
        assert _feed(new, piece) == _feed(ref, piece), (n, piece)
        assert _state(new) == _state(ref), (n, piece)
        assert new.take_replies() == ref.take_replies(), (n, piece)
        if resize and rnd.random() < 0.05:
            size = rnd.randint(1, 40), rnd.randint(1, 12)
            new.resize(*size)
            ref.resize(*size)
            assert _state(new) == _state(ref), ("resize", size)


# -- inputs --------------------------------------------------------------------

_WORDS = ["alpha", "beta", "src", "build", "README.md", "x", "a-much-longer-name.tar.gz"]


def _cat(rnd: random.Random, lines: int, longest: int = 60) -> str:
    return "".join(" ".join(rnd.choice(_WORDS) for _ in range(rnd.randint(0, 12)))[:longest]
                   + "\r\n" for _ in range(lines))


def _ls_color(rnd: random.Random, lines: int) -> str:
    colours = ["01;34", "01;32", "00", "38;5;208", "40;31;01", ""]
    return "".join("".join(f"\x1b[0m\x1b[{rnd.choice(colours)}m{rnd.choice(_WORDS)}\x1b[0m  "
                           for _ in range(rnd.randint(1, 5))) + "\r\n" for _ in range(lines))


def _full_screen(rnd: random.Random, frames: int) -> str:
    out = ["\x1b[?1049h\x1b[?1h\x1b[H\x1b[2J"]
    for f in range(frames):
        out.append(f"\x1b[H\x1b[2;5r\x1b[5;1H\r\n\x1b[1;1H\x1b[r\x1b[Htop - {f}\x1b[K\r\n"
                   "┌" + "─" * rnd.randint(0, 50) + "┐\x1b[K\x1b[6;1H\x1b[J")
        for r in range(rnd.randint(1, 12)):
            out.append(f"\x1b[{r + 7};{rnd.randint(1, 5)}H\x1b[K{r:4d} user \x1b[7m{f}\x1b[27m "
                       f"proc{r}\x1b[{rnd.randint(1, 4)}X\x1b[2P\x1b[3@")
        out.append("\x1b[24;1H\x1bM\x1b[2L\x1b[M\x1b[S\x1b[2T\x1b7\x1b[10;10H\x1b8\x1b[s\x1b[u")
    out.append("\x1b[?1049l\x1b[?1l")
    return "".join(out)


def _wide(rnd: random.Random, lines: int) -> str:
    parts = ["你好", "é", "café", "\U0001f600", "Ａ", "über",
             "plain", " ", "̀", "​", "\U0001f468‍\U0001f469"]
    return "".join("".join(rnd.choice(parts) for _ in range(rnd.randint(0, 30))) + "\r\n"
                   for _ in range(lines))


_TOKENS = [
    "y", "text ", "\r\n", "\n", "\r", "\t", "\x08", "\x0b", "\x0c", "\x07", "\x00", "\x7f",
    "\x85", "\x9b", "日", "é", "\U0001f600", "\x1b", "\x1b[", "\x1b[K", "\x1b[1K",
    "\x1b[2J", "\x1b[3J", "\x1b[J", "\x1b[3;4H", "\x1b[H", "\x1b[99999;99999H", "\x1b[0;0f",
    "\x1b[5A", "\x1b[B", "\x1b[3C", "\x1b[2D", "\x1b[E", "\x1b[F", "\x1b[7G", "\x1b[3d",
    "\x1b[?7l", "\x1b[?7h", "\x1b[?1h", "\x1b[?1l", "\x1b[2;3r", "\x1b[3;2r", "\x1b[r",
    "\x1b[?1049h", "\x1b[?1049l", "\x1b[?47h", "\x1b[?1047l", "\x1b7", "\x1b8", "\x1bD",
    "\x1bE", "\x1bM", "\x1bc", "\x1b(B", "\x1b%G", "\x1b=", "\x1b>", "\x1b[5@", "\x1b[3P",
    "\x1b[2L", "\x1b[2M", "\x1b[S", "\x1b[3T", "\x1b[4X", "\x1b[0m", "\x1b[38:2:1:2:3m",
    "\x1b[1;31m", "\x1b[s", "\x1b[u", "\x1b[6n", "\x1b[5n", "\x1b[>c", "\x1b[?25h",
    "\x1b[ q", "\x1b[1\x07;2H", "\x1b[1é2H", "\x1b[1;2;3;4;5;6;7;8;9;10;11H",
    "\x1b[;5H", "\x1b[12;H", "\x1b[1:2;3H", "\x1b[٣H", "\x1b]0;title\x07",
    "\x1b]2;t\x1b\\", "\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\", "\x1bP+q\x1b\\",
    "\x1b_apc\x07", "\x1b^pm\x1bx", "\x1bXsos\x07", "\x1b]unterminated", "\\", "~" * 9,
]


def _tokens(rnd: random.Random, count: int) -> str:
    out = []
    for _ in range(count):
        roll = rnd.random()
        if roll < 0.15:
            out.append("".join(rnd.choice("ab ~xyz") for _ in range(rnd.randint(1, 120))))
        elif roll < 0.25:
            out.append(_cat(rnd, rnd.randint(1, 40), rnd.randint(1, 50)))
        else:
            out.append(rnd.choice(_TOKENS))
    return "".join(out)


_SOUP = ("\x1b" * 8 + "[[[]]" + "0123456789;;;:?>= " + "HfJKmrhlnABCDsu@PLMSTXcE78\\"
         + "\r\n" * 6 + "\t\x08\x07\x0b\x0c\x00\x7f" + "abcxyz~" * 3)


def _soup(rnd: random.Random, size: int) -> str:
    """Random characters weighted to escape sequences, plus random bytes
    (UTF-8 or not: undecodable ones become U+FFFD) and C1 controls."""
    out = []
    for _ in range(size):
        roll = rnd.random()
        if roll < 0.9:
            out.append(rnd.choice(_SOUP))
        elif roll < 0.95:
            out.append(bytes([rnd.randrange(256) for _ in range(3)]).decode("utf-8", "replace"))
        else:
            out.append(chr(rnd.choice([0x80, 0x84, 0x9b, 0x9d, 0x9f, 0xe9, 0x301, 0x4e00,
                                       0x1f600, 0xfffd])))
    return "".join(out)


# -- happy ---------------------------------------------------------------------


@pytest.mark.parametrize("size", [(80, 24), (20, 6), (132, 50)])
def test_happy_floods_of_lines_leave_the_same_screen(size):
    rnd = random.Random(sum(size))
    _same("y\r\n" * 3000, *size, sizes=(4096,))
    _same("y\r\n" * 3000, *size, seed=1)
    _same(_cat(rnd, 1500), *size, scrollback=1000, seed=2)


def test_happy_ls_color_a_full_screen_app_and_wide_text_leave_the_same_screen():
    rnd = random.Random(3)
    _same(_ls_color(rnd, 300), seed=3)
    _same(_full_screen(rnd, 40), seed=4)
    _same(_wide(rnd, 200), seed=5)
    _same(_wide(rnd, 100), cols=13, rows=5, seed=6)


def test_happy_a_flood_of_lines_goes_in_without_a_line_feed_per_line(monkeypatch):
    calls = []
    original = VTScreen._linefeed
    monkeypatch.setattr(VTScreen, "_linefeed", lambda self: (calls.append(1), original(self)))
    s = VTScreen(80, 24)
    s.feed("y\r\n" * 23)  # down to the bottom row: one at a time
    calls.clear()
    s.feed("y\r\n" * 5000)
    assert len(calls) < 5
    assert s.scrolled_total == 5000 and list(s.scrollback)[-1] == "y"
    assert s.screen_lines()[22].rstrip() == "y" and s.cursor == (23, 0)


def test_happy_the_bench_script_compares_old_and_new():
    """scripts/bench_vt_screen.py: the measurement behind the numbers above,
    run small (two workloads, one round) against the reference."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    from core.subprocess_env import worker_env

    root = Path(__file__).resolve().parent.parent
    out = subprocess.run(
        [sys.executable, str(root / "scripts" / "bench_vt_screen.py"),
         "--old", str(root / "tests" / "vt_screen_reference.py"), "--rounds", "1",
         "yes", "ls_color"],
        capture_output=True, text=True, timeout=120, cwd=root, env=worker_env(dict(os.environ)))
    assert out.returncode == 0, out.stderr
    lines = [line for line in out.stdout.splitlines() if line.strip()]
    assert [line.split()[0] for line in lines] == ["yes", "ls_color"], out.stdout


# -- sad -----------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_sad_random_byte_soup_in_random_pieces(seed):
    rnd = random.Random(seed)
    _same(_soup(rnd, 1500), rnd.randint(1, 30), rnd.randint(1, 8),
          rnd.choice([0, 1, 5, 100]), seed=seed, resize=True)


def test_sad_overlong_sequences_and_strings_are_cut_the_same():
    long_params = "\x1b[" + "1;" * 200 + "5H" + "\x1b[?" + "9" * 300 + "h" + "x"
    long_osc = "\x1b]0;" + "t" * 5000 + "\x07after" + "\x1bP" + "q" * 4096 + "\x1b\\end"
    exact = "\x1b]0;" + "t" * 4092 + "\x07" + "\x1b]" + "u" * 4097 + "v\x07w"
    for seed in range(4):
        _same(long_params * 3, 40, 10, seed=seed)
        _same(long_osc * 2, 40, 10, seed=seed, sizes=(1, 100, 1000, 4096, 9000))
        _same(exact * 2, 40, 10, seed=seed, sizes=(1, 7, 4093, 4096, 9000))


def test_sad_a_flood_meets_text_already_on_the_bottom_row():
    # The first line is written over what the bottom row held, wide cells too.
    _same("\x1b[24;1H" + "你" * 30 + "\r" + "ab\r\n" * 50 + "zz", sizes=(10000,))
    _same("\x1b[24;1Hlong text left here\r" + "y\r\n" * 3 + "\x1b[24;5Hq\r" + "y\r\n" * 40,
          sizes=(10000,))
    _same("\x1b[?7l" + "\x1b[24;1H" + "x" * 79 + "\r\n" * 30, sizes=(10000,))


# -- edge ----------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_edge_random_token_streams_on_random_screens(seed):
    rnd = random.Random(1000 + seed)
    _same(_tokens(rnd, 300), rnd.randint(1, 30), rnd.randint(1, 8),
          rnd.choice([0, 1, 3, 50]), seed=seed, resize=True)


def test_edge_lines_as_long_as_the_row_or_one_column_wide_screens():
    for cols in (1, 2, 5, 10):
        for length in (0, cols - 1, cols, cols + 1, 3 * cols):
            text = ("q" * length + "\r\n") * 40
            _same(text, cols, 3, scrollback=10, sizes=(10000,))
            _same(text, cols, 1, scrollback=0, seed=length)
            _same("\x1b[?7l" + text, cols, 2, scrollback=5, sizes=(10000,))


def test_edge_floods_in_a_scroll_region_on_the_alternate_screen_and_mid_screen():
    lines = "".join(f"line {i}\r\n" for i in range(60))
    for prefix in ("\x1b[2;5r\x1b[5;1H", "\x1b[?1049h", "\x1b[10;1H", "\x1b[24;3H",
                   "\x1b[1;24r\x1b[24;1H", "\x1b[24;80H", "\x1b[24;80Hx"):
        _same(prefix + lines + "end", sizes=(10000,))
        _same(prefix + lines + "end", seed=7)


def test_edge_more_lines_than_the_scrollback_keeps_at_once():
    for scrollback in (0, 1, 23, 24, 25, 100):
        _same("".join(f"{i}\r\n" for i in range(300)), 10, 24, scrollback, sizes=(10000,))
        _same("".join(f"{i}\r\n" for i in range(300)), 10, 4, scrollback, sizes=(10000,))
