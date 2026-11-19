"""The VT parser of core/vt_screen.py as it was in 0.14.250: every
character through the state machine one at a time (plain ASCII runs a row
at a time), every line feed through ``_scroll_up``.

tests/test_vt_screen_differential.py feeds it and the current VTScreen
the same output and asserts both screens agree: the current parser takes
lines, CSI sequences and strings in whole pieces and must not change
what the screen shows by it. Kept as it was - only this docstring is new.
A change of VTScreen's behaviour on purpose (a new control function, say)
has to be made here too, the same way.

Changed on purpose since (review 2026-11-19): a string is dropped however
long it is and CAN / SUB abort it; a C0 control inside a CSI runs and the
CSI goes on, ESC inside a CSI or a string starts a new sequence; a
character written over half of a wide character erases its other half.
Review 2026-11-20: an erase, insert or delete inside a wide character and
a resize through one take it whole; none is printed on a one-column screen.
"""

from __future__ import annotations

import re
import unicodedata
from collections import deque

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

#: Two or more printable ASCII characters: one cell each, nothing to
#: interpret - written a row at a time (VTScreen._print_run).
_ASCII_RUN = re.compile(r"[\x20-\x7e]{2,}")


def _width(ch: str) -> int:
    """Columns *ch* takes: 0 for combining marks, 2 for wide, else 1."""
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _erase_split_wide(line: list[str], start: int, stop: int) -> None:
    """Cells start..stop-1 are written next: a wide character only half
    of which is among them leaves a blank for its other half."""
    if 0 < start < len(line) and line[start] == "" and _width(line[start - 1]) == 2:
        line[start - 1] = " "
    if stop < len(line) and line[stop] == "":
        line[stop] = " "


def _blank_cells(line: list[str], start: int, stop: int) -> None:
    """Cells *start* to *stop* (exclusive) of *line* become blanks; a wide
    character with one half among them goes whole (erase, CSI K / X)."""
    stop = min(stop, len(line))
    if start >= stop:
        return
    _erase_split_wide(line, start, stop)
    line[start:stop] = [" "] * (stop - start)


def _close_right_edge(line: list[str]) -> None:
    """A wide character in the last cell of *line* lost its right half
    (a resize, CSI @ pushed it over the edge): it goes as a whole."""
    if line and line[-1] and _width(line[-1]) == 2:
        line[-1] = " "


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
            for line in grid:
                _close_right_edge(line)
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
        i, end = 0, len(text)
        while i < end:
            ch = text[i]
            i += 1
            state = self._state
            if state == _GROUND:
                code = ord(ch)
                if code >= 0x20 and code != 0x7F and not 0x80 <= code <= 0x9F:
                    # Followed by more plain text: the run goes in whole.
                    if code < 0x7F and i < end and " " <= text[i] <= "~":
                        run = _ASCII_RUN.match(text, i - 1)
                        self._print_run(run.group())
                        i = run.end()
                        continue
                    self._print(ch)
                elif ch == "\x1b":
                    self._state = _ESC
                else:
                    self._control(ch)
            elif state == _ESC:
                self._escape(ch)
            elif state == _ESC_INTER:
                # ESC ( B, ESC % G, ...: one final byte after the intermediates.
                if not 0x20 <= ord(ch) <= 0x2F:
                    self._state = _GROUND
            elif state == _CSI:
                self._csi_char(ch)
            elif state == _STRING:
                if ch in "\x07\x18\x1a":
                    self._state = _GROUND
                elif ch == "\x1b":
                    self._state = _STRING_ESC
                else:
                    self._string_len += 1
            else:  # _STRING_ESC: ESC \ ends the string, else ESC began a sequence
                self._state = _GROUND
                if ch != "\\":
                    self._state = _ESC
                    self.feed(ch)

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

    def _csi_char(self, ch: str) -> None:
        code = ord(ch)
        if 0x30 <= code <= 0x3F or 0x20 <= code <= 0x2F:  # parameters, intermediates
            if len(self._params) < 4 * _MAX_PARAMS:
                self._params += ch
            return
        if code < 0x20:
            if ch == "\x1b":
                self._state = _ESC
            elif ch in "\x18\x1a":
                self._state = _GROUND
            else:
                self._control(ch)  # and the CSI goes on
            return
        self._state = _GROUND
        if 0x40 <= code <= 0x7E:
            self._csi(ch, self._params)

    # -- printing --------------------------------------------------------------

    def _print(self, ch: str) -> None:
        width = _width(ch)
        if width == 0 or width > self.cols:
            return  # a wide character does not fit a screen one column wide
        if self._wrap_pending:
            self._col = 0
            self._linefeed()
            self._wrap_pending = False
        if width == 2 and self._col == self.cols - 1:
            if not self._autowrap:
                return
            _erase_split_wide(self._grid[self._row], self._col, self._col + 1)
            self._grid[self._row][self._col] = " "
            self._col = 0
            self._linefeed()
        line = self._grid[self._row]
        _erase_split_wide(line, self._col, self._col + width)
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
            _erase_split_wide(line, col, col + take)
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
        if self._row == self._bottom:
            self._scroll_up()
        elif self._row < self.rows - 1:
            self._row += 1

    def _reverse_index(self) -> None:
        self._wrap_pending = False
        if self._row == self._top:
            self._scroll_down()
        elif self._row > 0:
            self._row -= 1

    # -- CSI -------------------------------------------------------------------

    def _csi(self, final: str, raw: str) -> None:
        private = raw[:1] in ("?", ">", "=", "<")
        body = raw[1:] if private else raw
        body = "".join(c for c in body if c.isdigit() or c in ";:")
        params: list[int] = []
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
            _blank_cells(self._grid[self._row], self._col, self._col + arg())
        elif final == "P":
            line = self._grid[self._row]
            n = min(arg(), cols - self._col)
            _erase_split_wide(line, self._col, self._col + n)
            del line[self._col:self._col + n]
            line.extend([" "] * n)
        elif final == "@":
            line = self._grid[self._row]
            n = min(arg(), cols - self._col)
            _erase_split_wide(line, self._col, self._col)
            line[self._col:self._col] = [" "] * n
            del line[cols:]
            _close_right_edge(line)
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
        # m (SGR) and everything else: accepted, nothing to change.

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
        _blank_cells(line, start, end)

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
