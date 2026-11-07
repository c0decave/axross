"""A VT100 / xterm screen for the terminal widget: text in, lines out.

The terminal widget used to strip every escape sequence and every
carriage return and append what was left. That works for a plain
``cmd | less``-free bash, and nowhere else: zsh's PROMPT_SP writes "%",
fills the line with blanks and returns with "\\r", line editors redraw
with cursor moves, pagers and editors use the alternate screen.

``VTScreen`` keeps what a terminal keeps - a grid of ``rows`` x ``cols``
cells, a cursor, a scroll region, the alternate screen and a bounded
scrollback - and understands the control functions that shells, pagers,
editors and ``top`` actually send:

* C0: BS, HT, LF / VT / FF, CR, BEL (ignored); C1 controls are dropped.
* ESC: 7 / 8 (save / restore cursor), D (index), E (next line),
  M (reverse index), c (reset), charset designations (ignored).
* CSI: cursor moves A B C D E F G H f d, erase J K X, insert / delete
  @ P L M, scroll S T, region r, save / restore s u, modes h l
  (?1049 / ?1047 / ?47 alternate screen, ?1 cursor keys mode, ?7
  autowrap), device status n
  (the cursor report goes to ``take_replies``); SGR m is accepted and
  ignored - the widget shows text, not colours.
* OSC, DCS, PM and APC strings are consumed and dropped.

Pure Python, no Qt: the widget renders ``scrollback`` + ``screen_lines()``
and puts its caret on ``cursor``. Every count and size is clamped, so a
hostile host cannot make a parameter allocate or loop beyond the grid.
"""

from __future__ import annotations

import re
import unicodedata
from collections import deque
from functools import lru_cache

#: Lines kept above the screen.
DEFAULT_SCROLLBACK = 5000
#: Largest grid accepted by resize() - a stray huge size must not allocate.
MAX_COLS = 1000
MAX_ROWS = 500
#: An OSC / DCS string longer than this is cut off (a title is short).
_MAX_STRING = 4096
#: More CSI parameters than this are ignored.
_MAX_PARAMS = 32

_GROUND, _ESC, _ESC_INTER, _CSI, _STRING, _STRING_ESC = range(6)

#: CSI finals that move the cursor (A B C D E F G ` H f d a, r homes, u
#: restores) or edit the screen (J K X P @ L M): they end a pending wrap.
_ENDS_PENDING_WRAP = frozenset("ABCDEFG`HfdaruJKXP@LM")

#: Printable ASCII characters: one cell each, nothing to interpret -
#: written a row at a time (VTScreen._print_run).
_ASCII_RUN = re.compile(r"[\x20-\x7e]+")
#: Lines of printable ASCII, each ended by CR LF: what ``cat``, ``ls`` or
#: ``yes`` send - written a block at a time (VTScreen._print_lines).
_ASCII_LINES = re.compile(r"(?:[\x20-\x7e]*\r\n)+")
#: What follows CSI up to its final byte: parameters and intermediates.
_CSI_PARAMS = re.compile(r"[\x20-\x3f]*")
#: The end of an OSC / DCS / PM / APC string: BEL, or the ESC of ESC \.
_STRING_END = re.compile(r"[\x07\x1b]")
#: CSI parameters made of decimal numbers and ";" only - the usual kind.
_PLAIN_PARAMS = re.compile(r"[0-9;]*")


@lru_cache(maxsize=4096)
def _width(ch: str) -> int:
    """Columns *ch* takes: 0 for combining marks, 2 for wide, else 1."""
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


class VTScreen:
    """The screen state of one terminal session."""

    def __init__(
        self, cols: int = 80, rows: int = 24, *, scrollback: int = DEFAULT_SCROLLBACK
    ) -> None:
        self.cols = max(1, min(int(cols), MAX_COLS))
        self.rows = max(1, min(int(rows), MAX_ROWS))
        self.scrollback: deque[str] = deque(maxlen=max(0, int(scrollback)))
        #: Lines ever pushed into the scrollback (keeps counting past maxlen).
        self.scrolled_total = 0
        self._replies = bytearray()
        self._state = _GROUND
        self._params = ""
        self._string_len = 0
        self._reset()

    # -- state -----------------------------------------------------------------

    def _reset(self) -> None:
        self._grid = self._blank_grid()
        self._main: tuple | None = None  # saved main screen while the alternate is shown
        self._row = 0
        self._col = 0
        self._wrap_pending = False
        self._top = 0
        self._bottom = self.rows - 1
        self._autowrap = True
        self._saved = (0, 0)
        # DECCKM (?1h): cursor keys send ESC O A instead of ESC [ A.
        self._app_cursor_keys = False

    def _blank_line(self) -> list[str]:
        return [" "] * self.cols

    def _blank_grid(self) -> list[list[str]]:
        return [self._blank_line() for _ in range(self.rows)]

    @property
    def cursor(self) -> tuple[int, int]:
        """(row, column) of the cursor on the screen, both from 0."""
        return self._row, self._col

    @property
    def alternate(self) -> bool:
        """True while the alternate screen (pager, editor) is shown."""
        return self._main is not None

    def screen_lines(self) -> list[str]:
        """The visible rows as text, each ``cols`` cells wide (a wide
        character's second cell is not repeated)."""
        return ["".join(line) for line in self._grid]

    @property
    def application_cursor_keys(self) -> bool:
        """True while the host asked for cursor keys in application mode
        (``CSI ? 1 h``, what curses sends for ``keypad(TRUE)``): the keys
        must go out as ``ESC O A`` instead of ``ESC [ A``."""
        return self._app_cursor_keys

    def take_replies(self) -> bytes:
        """Answers the host asked for (cursor reports); empty when none."""
        out = bytes(self._replies)
        self._replies.clear()
        return out

    def resize(self, cols: int, rows: int) -> None:
        """New grid size. Text is kept (cut at the right edge); rows of the
        shell's screen that no longer fit above its cursor go to the
        scrollback, also while the alternate screen is shown. Every cursor
        - the live one, the shell's one saved by the alternate screen and
        the one saved by ESC 7 / CSI s - moves with its text and stays on
        the grid."""
        cols = max(1, min(int(cols), MAX_COLS))
        rows = max(1, min(int(rows), MAX_ROWS))
        if (cols, rows) == (self.cols, self.rows):
            return

        def fit(
            grid: list[list[str]], row: int, keep_scrollback: bool
        ) -> tuple[list[list[str]], int]:
            """*grid* at the new size and how many rows left it at the top;
            blank rows below the cursor *row* go first."""
            grid = [(line + [" "] * cols)[:cols] for line in grid]
            while len(grid) > rows and not "".join(grid[-1]).strip() and len(grid) - 1 > row:
                grid.pop()
            dropped = max(0, len(grid) - rows)
            for top in grid[:dropped]:
                if keep_scrollback:
                    self._push_scrollback(top)
            del grid[:dropped]
            while len(grid) < rows:
                grid.append([" "] * cols)
            return grid, dropped

        def clamp(row: int, col: int) -> tuple[int, int]:
            return max(0, min(row, rows - 1)), max(0, min(col, cols - 1))

        if self._main is not None:
            saved_grid, (saved_row, saved_col) = self._main
            saved_grid, dropped = fit(saved_grid, saved_row, True)
            self._main = (saved_grid, clamp(saved_row - dropped, saved_col))
        self._grid, dropped = fit(self._grid, self._row, self._main is None)
        self.cols, self.rows = cols, rows
        self._row, self._col = clamp(self._row - dropped, self._col)
        self._saved = clamp(self._saved[0] - dropped, self._saved[1])
        self._wrap_pending = False
        self._top, self._bottom = 0, rows - 1

    # -- input -----------------------------------------------------------------

    def feed(self, text: str) -> None:
        """Interpret *text* (decoded output of the host)."""
        # What a flood of output is made of - a run of plain text, CR, LF,
        # a CSI sequence, an OSC string - is taken in one step here; each
        # changes the screen exactly as one character at a time would.
        i, end = 0, len(text)
        while i < end:
            state = self._state
            if state == _GROUND:
                ch = text[i]
                # At the start of the bottom row of the shell's screen whole
                # lines of plain text go in as a block.
                if (
                    not self._col
                    and self._row == self._bottom == self.rows - 1
                    and not self._top
                    and self._main is None
                    and not self._wrap_pending
                    and (" " <= ch <= "~" or ch == "\r")
                ):
                    lines = _ASCII_LINES.match(text, i)
                    if lines:
                        self._print_lines(lines.group())
                        i = lines.end()
                        continue
                if " " <= ch <= "~":
                    j = _ASCII_RUN.match(text, i).end()
                    col = self._col
                    if col + (j - i) < self.cols and not self._wrap_pending:
                        # Fits on the row: no wrap, no scroll, just the cells.
                        self._grid[self._row][col:col + j - i] = text[i:j]
                        self._col = col + j - i
                    else:
                        self._print_run(text[i:j])
                    i = j
                    continue
                i += 1
                if ch == "\r":
                    self._col = 0
                    self._wrap_pending = False
                elif ch == "\n":
                    self._linefeed()
                elif ch == "\x1b":
                    self._state = _ESC
                else:
                    code = ord(ch)
                    if code >= 0x20 and code != 0x7F and not 0x80 <= code <= 0x9F:
                        self._print(ch)
                    else:
                        self._control(ch)
            elif state == _CSI:
                # Parameters and intermediates (the first 4 * _MAX_PARAMS are
                # kept), then the final byte; a control character aborts.
                j = _CSI_PARAMS.match(text, i).end()
                if j > i:
                    if len(self._params) < 4 * _MAX_PARAMS:
                        self._params = (self._params + text[i:j])[:4 * _MAX_PARAMS]
                    i = j
                    if i == end:
                        break
                ch = text[i]
                i += 1
                self._state = _GROUND
                if "@" <= ch <= "~":
                    self._csi(ch, self._params)
            elif state == _ESC:
                self._escape(text[i])
                i += 1
            elif state == _ESC_INTER:
                # ESC ( B, ESC % G, ...: one final byte after the intermediates.
                if not 0x20 <= ord(text[i]) <= 0x2F:
                    self._state = _GROUND
                i += 1
            elif state == _STRING:
                # Dropped up to BEL or ESC; the character past _MAX_STRING
                # ends it as well.
                found = _STRING_END.search(text, i)
                stop = found.start() if found else end
                room = _MAX_STRING - self._string_len
                if stop - i > room:
                    self._string_len += room + 1
                    self._state = _GROUND
                    i += room + 1
                    continue
                self._string_len += stop - i
                i = stop
                if i < end:
                    self._state = _GROUND if text[i] == "\x07" else _STRING_ESC
                    i += 1
            else:  # _STRING_ESC: ESC \ ends the string, anything else too
                self._state = _GROUND
                if text[i] == "\\":
                    i += 1
                # Else that character is read again, on the ground.

    def _control(self, ch: str) -> None:
        if ch == "\r":
            self._col = 0
            self._wrap_pending = False
        elif ch in "\n\x0b\x0c":
            self._linefeed()
        elif ch == "\x08":
            if self._col > 0:
                self._col -= 1
            self._wrap_pending = False
        elif ch == "\t":
            self._col = min(self.cols - 1, (self._col // 8 + 1) * 8)
            self._wrap_pending = False
        # BEL, NUL, SO / SI, DEL and C1: nothing to show.

    def _escape(self, ch: str) -> None:
        self._state = _GROUND
        if ch == "[":
            self._state = _CSI
            self._params = ""
        elif ch in "]P^_X":
            self._state = _STRING
            self._string_len = 0
        elif 0x20 <= ord(ch) <= 0x2F:
            self._state = _ESC_INTER
        elif ch == "7":
            self._saved = (self._row, self._col)
        elif ch == "8":
            self._row, self._col = self._saved
            self._wrap_pending = False
        elif ch == "D":
            self._linefeed()
        elif ch == "E":
            self._col = 0
            self._linefeed()
        elif ch == "M":
            self._reverse_index()
        elif ch == "c":
            self._reset()
        # ESC = / ESC > (keypad modes) and the rest: ignored.

    # -- printing --------------------------------------------------------------

    def _print(self, ch: str) -> None:
        width = _width(ch)
        if width == 0:
            return
        if self._wrap_pending:
            self._col = 0
            self._linefeed()
            self._wrap_pending = False
        if width == 2 and self._col == self.cols - 1:
            if not self._autowrap:
                return
            self._grid[self._row][self._col] = " "
            self._col = 0
            self._linefeed()
        line = self._grid[self._row]
        line[self._col] = ch
        if width == 2:
            line[self._col + 1] = ""
        last = self._col + width - 1
        if last >= self.cols - 1:
            self._col = self.cols - 1
            self._wrap_pending = self._autowrap
        else:
            self._col = last + 1

    def _print_run(self, run: str) -> None:
        """``_print`` of every character of *run* (printable ASCII: one cell
        each), a row at a time: the same cells, cursor, wraps and scrolls."""
        cols = self.cols
        i, end = 0, len(run)
        while i < end:
            if self._wrap_pending:
                self._col = 0
                self._linefeed()
            line = self._grid[self._row]
            col = self._col
            take = min(cols - col, end - i)
            line[col:col + take] = run[i:i + take]
            i += take
            if col + take < cols:
                self._col = col + take
                continue
            self._col = cols - 1
            self._wrap_pending = self._autowrap
            if not self._autowrap and i < end:
                line[cols - 1] = run[-1]  # each further character overwrites the last cell
                return

    def _print_lines(self, block: str) -> None:
        """``_print_run``, CR and LF of every line of *block* (printable
        ASCII, each line ended by CR LF) from the start of the bottom row
        of the shell's screen, the scroll region the whole screen: a line
        fills one row or wraps into more, each row scrolls the top one into
        the scrollback. Only the rows still on the screen at the end are
        made; the rows that pass through go to the scrollback as text."""
        cols, rows, grid = self.cols, self.rows, self._grid
        lines = block.split("\r\n")
        del lines[-1]  # after the last CR LF
        if max(map(len, lines)) > cols:
            if self._autowrap:  # a row each cols characters ("" is one row too)
                lines = [line[k:k + cols] for line in lines
                         for k in range(0, len(line), cols) or (0,)]
            else:  # each character past the row overwrites its last cell
                lines = [line if len(line) <= cols else line[:cols - 1] + line[-1]
                         for line in lines]
        count = len(lines)
        first = lines[0]
        grid[-1][:len(first)] = first  # over what the bottom row holds
        # What leaves the screen: its own rows, then the rows after the first.
        passing = max(1, count - rows + 1)  # lines[1:passing] leave as well
        if self.scrollback.maxlen:
            self.scrollback.extend("".join(row).rstrip() for row in grid[:count])
            self.scrollback.extend(line.rstrip() for line in lines[1:passing])
        self.scrolled_total += count
        grid[:] = (grid[count:]
                   + [list(line.ljust(cols)) for line in lines[passing:]]
                   + [[" "] * cols])

    def _push_scrollback(self, line: list[str]) -> None:
        if self.scrollback.maxlen:
            self.scrollback.append("".join(line).rstrip())
        self.scrolled_total += 1

    def _scroll_up(self, count: int = 1) -> None:
        count = max(1, min(count, self._bottom - self._top + 1))
        for _ in range(count):
            top = self._grid.pop(self._top)
            if self._top == 0 and self._main is None:
                self._push_scrollback(top)
            self._grid.insert(self._bottom, self._blank_line())

    def _scroll_down(self, count: int = 1) -> None:
        count = max(1, min(count, self._bottom - self._top + 1))
        for _ in range(count):
            self._grid.pop(self._bottom)
            self._grid.insert(self._top, self._blank_line())

    def _linefeed(self) -> None:
        self._wrap_pending = False
        row = self._row
        if row == self._bottom:
            # _scroll_up(1) - a step of every line of an output flood - inline.
            grid, top = self._grid, self._top
            line = grid.pop(top)
            if top == 0 and self._main is None:
                if self.scrollback.maxlen:
                    self.scrollback.append("".join(line).rstrip())
                self.scrolled_total += 1
            grid.insert(row, [" "] * self.cols)
        elif row < self.rows - 1:
            self._row = row + 1

    def _reverse_index(self) -> None:
        self._wrap_pending = False
        if self._row == self._top:
            self._scroll_down()
        elif self._row > 0:
            self._row -= 1

    # -- CSI -------------------------------------------------------------------

    def _csi(self, final: str, raw: str) -> None:
        if final == "m":
            return  # SGR: the widget shows text, not colours; no wrap ends
        private = raw[:1] in ("?", ">", "=", "<")
        body = raw[1:] if private else raw
        if _PLAIN_PARAMS.fullmatch(body):  # the usual "12;40"
            params = [min(int(part), 99999) if part else 0
                      for part in body.split(";")[:_MAX_PARAMS]]
        else:
            body = "".join(c for c in body if c.isdigit() or c in ";:")
            params = []
            for part in body.split(";")[:_MAX_PARAMS]:
                part = part.split(":")[0]
                params.append(min(int(part), 99999) if part.isdigit() else 0)

        def arg(i: int = 0, default: int = 1) -> int:
            value = params[i] if i < len(params) else 0
            return value if value else default

        if private:
            if final in "hl" and raw[:1] == "?":
                for mode in params:
                    self._private_mode(mode, final == "h")
            return

        # Only a cursor move or an edit of the screen ends a pending wrap;
        # SGR, modes, save and reports leave it, as xterm does.
        if final in _ENDS_PENDING_WRAP:
            self._wrap_pending = False
        rows, cols = self.rows, self.cols
        if final == "A":
            self._row = max(self._top if self._row >= self._top else 0, self._row - arg())
        elif final == "B":
            self._row = min(
                self._bottom if self._row <= self._bottom else rows - 1, self._row + arg()
            )
        elif final in "Ca":
            self._col = min(cols - 1, self._col + arg())
        elif final == "D":
            self._col = max(0, self._col - arg())
        elif final == "E":
            self._row = min(rows - 1, self._row + arg())
            self._col = 0
        elif final == "F":
            self._row = max(0, self._row - arg())
            self._col = 0
        elif final in "G`":
            self._col = min(cols - 1, arg() - 1)
        elif final in "Hf":
            self._row = min(rows - 1, arg(0) - 1)
            self._col = min(cols - 1, arg(1) - 1)
        elif final == "d":
            self._row = min(rows - 1, arg() - 1)
        elif final == "J":
            self._erase_display(arg(0, 0))
        elif final == "K":
            self._erase_line(arg(0, 0))
        elif final == "X":
            line = self._grid[self._row]
            for c in range(self._col, min(cols, self._col + arg())):
                line[c] = " "
        elif final == "P":
            line = self._grid[self._row]
            n = min(arg(), cols - self._col)
            del line[self._col:self._col + n]
            line.extend([" "] * n)
        elif final == "@":
            line = self._grid[self._row]
            n = min(arg(), cols - self._col)
            line[self._col:self._col] = [" "] * n
            del line[cols:]
        elif final == "L":
            if self._top <= self._row <= self._bottom:
                for _ in range(min(arg(), self._bottom - self._row + 1)):
                    self._grid.pop(self._bottom)
                    self._grid.insert(self._row, self._blank_line())
                self._col = 0
        elif final == "M":
            if self._top <= self._row <= self._bottom:
                for _ in range(min(arg(), self._bottom - self._row + 1)):
                    self._grid.pop(self._row)
                    self._grid.insert(self._bottom, self._blank_line())
                self._col = 0
        elif final == "S":
            self._scroll_up(arg())
        elif final == "T":
            self._scroll_down(arg())
        elif final == "r":
            top = arg(0) - 1
            bottom = (params[1] if len(params) > 1 and params[1] else rows) - 1
            top, bottom = max(0, top), min(rows - 1, bottom)
            if top < bottom:
                self._top, self._bottom = top, bottom
                self._row, self._col = 0, 0
        elif final == "s":
            self._saved = (self._row, self._col)
        elif final == "u":
            self._row, self._col = self._saved
        elif final == "n":
            if arg(0, 0) == 6:
                self._replies += f"\x1b[{self._row + 1};{self._col + 1}R".encode()
            elif arg(0, 0) == 5:
                self._replies += b"\x1b[0n"
        # Everything else: accepted, nothing to change.

    def _private_mode(self, mode: int, on: bool) -> None:
        if mode in (1049, 1047, 47):
            if on and self._main is None:
                self._main = (self._grid, (self._row, self._col))
                self._grid = self._blank_grid()
                self._top, self._bottom = 0, self.rows - 1
            elif not on and self._main is not None:
                self._grid, (self._row, self._col) = self._main
                self._main = None
                self._top, self._bottom = 0, self.rows - 1
            self._wrap_pending = False
        elif mode == 1:
            self._app_cursor_keys = on
        elif mode == 7:
            self._autowrap = on
            if not on:
                self._wrap_pending = False

    def _erase_line(self, how: int) -> None:
        line = self._grid[self._row]
        if how == 0:
            start, end = self._col, self.cols
        elif how == 1:
            start, end = 0, self._col + 1
        else:
            start, end = 0, self.cols
        for c in range(start, min(end, self.cols)):
            line[c] = " "

    def _erase_display(self, how: int) -> None:
        if how == 0:
            self._erase_line(0)
            rows = range(self._row + 1, self.rows)
        elif how == 1:
            self._erase_line(1)
            rows = range(0, self._row)
        else:
            rows = range(self.rows)
            if how == 3:
                self.scrollback.clear()
        for r in rows:
            self._grid[r] = self._blank_line()


__all__ = ["DEFAULT_SCROLLBACK", "MAX_COLS", "MAX_ROWS", "VTScreen"]
