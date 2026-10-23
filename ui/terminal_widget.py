"""Terminal widget — interactive SSH shell or local terminal in a dock."""

from __future__ import annotations

import codecs
import logging
import os
import select
import signal
import struct
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QDragLeaveEvent, QFont, QFontMetricsF, QKeyEvent, QKeySequence, QTextCursor
from PyQt6.QtWidgets import (
    QComboBox,
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.vt_screen import DEFAULT_SCROLLBACK, MAX_ROWS, VTScreen
from ui.pane_drag import PANE_MIME_TYPE

if TYPE_CHECKING:
    import paramiko

log = logging.getLogger(__name__)

#: Smallest grid the widget reports to the pty: shells misbehave below it.
MIN_GRID_COLS = 20
MIN_GRID_ROWS = 5

# Per-tab buffer cap. A malicious remote (compromised SSH server,
# local process producing infinite stdout) could otherwise saturate
# RAM by flooding output. 32 MiB is deep enough that interactive
# shell scrollback stays intact during realistic sessions, and tight
# enough that any absurd flood gets truncated within a second of
# arrival. Half-cap tail preservation keeps the RECENT output that a
# user actually cares about when the flood arrives.
TERMINAL_BUFFER_CAP_BYTES = 32 * 1024 * 1024


# OpSec: shell-history suppression sent on every freshly-invoked
# remote shell. Order matters — ``unset HISTFILE`` first so the
# subsequent commands don't get logged. Bash + zsh + dash/sh all
# silently no-op the knobs they don't recognise, so this is safe
# across the common shell mix. Telnet's _setup_prompt sends the
# same set; keep them aligned. See docs/OPSEC.md.
_SHELL_HISTORY_SUPPRESSION_SCRIPT = (
    b"unset HISTFILE; "
    b"export HISTFILE=/dev/null HISTSIZE=0 HISTFILESIZE=0 LESSHISTFILE=/dev/null; "
    b"set +o history 2>/dev/null; "
    b"setopt HIST_IGNORE_SPACE 2>/dev/null; "
    b"true\n"
)


# Terminal colour themes — keys go to setStyleSheet on the
# TerminalEmulator. Add new themes here and they appear in the
# "Theme" menu automatically.
TERMINAL_THEMES: dict[str, dict[str, str]] = {
    "Dark": {"bg": "#1e1e1e", "fg": "#d4d4d4", "sel": "#264f78"},
    "Solarized-Dark": {"bg": "#002b36", "fg": "#93a1a1", "sel": "#073642"},
    "Solarized-Light": {"bg": "#fdf6e3", "fg": "#586e75", "sel": "#eee8d5"},
    "Hacker": {"bg": "#000000", "fg": "#00ff00", "sel": "#005500"},
    "Amber": {"bg": "#1a0f00", "fg": "#ffb000", "sel": "#553c00"},
    "Light": {"bg": "#ffffff", "fg": "#000000", "sel": "#cce4ff"},
}
DEFAULT_TERMINAL_THEME = "Dark"

# Per-zoom step in points. Ctrl+= grows the font, Ctrl+- shrinks,
# Ctrl+0 resets. Caps below stop the user from accidentally
# zooming the widget into uselessness.
FONT_ZOOM_STEP = 1
FONT_MIN_PT = 6
FONT_MAX_PT = 28
FONT_DEFAULT_PT = 10


def on_macos() -> bool:
    return sys.platform == "darwin"


def _shell_ctrl() -> Qt.KeyboardModifier:
    """The modifier of the key labelled Ctrl / Control. Qt reports it as
    MetaModifier on macOS, where ControlModifier is Command."""
    return Qt.KeyboardModifier.MetaModifier if on_macos() else Qt.KeyboardModifier.ControlModifier


def _app_modifiers() -> Qt.KeyboardModifier:
    """Alt and the platform's command key (Command on macOS, Super
    elsewhere): their combinations belong to the application."""
    command = (
        Qt.KeyboardModifier.ControlModifier if on_macos() else Qt.KeyboardModifier.MetaModifier
    )
    return Qt.KeyboardModifier.AltModifier | command


def _is_copy_or_paste(event: QKeyEvent) -> bool:
    return event.matches(QKeySequence.StandardKey.Copy) or event.matches(
        QKeySequence.StandardKey.Paste
    )

# What a key sends to the host, as xterm sends it.
_CURSOR_KEYS: dict[int, bytes] = {
    Qt.Key.Key_Up: b"\x1b[A",
    Qt.Key.Key_Down: b"\x1b[B",
    Qt.Key.Key_Right: b"\x1b[C",
    Qt.Key.Key_Left: b"\x1b[D",
    Qt.Key.Key_Home: b"\x1b[H",
    Qt.Key.Key_End: b"\x1b[F",
}
#: The cursor keys while the host asked for application mode (?1h).
_CURSOR_KEYS_APPLICATION: dict[int, bytes] = {
    key: b"\x1bO" + seq[2:] for key, seq in _CURSOR_KEYS.items()
}
_EDIT_KEYS: dict[int, bytes] = {
    Qt.Key.Key_Delete: b"\x1b[3~",
    Qt.Key.Key_PageUp: b"\x1b[5~",
    Qt.Key.Key_PageDown: b"\x1b[6~",
    Qt.Key.Key_Return: b"\n",
    Qt.Key.Key_Enter: b"\n",
    Qt.Key.Key_Backspace: b"\x7f",
    Qt.Key.Key_Tab: b"\t",
    Qt.Key.Key_Escape: b"\x1b",
}
_FUNCTION_KEYS: dict[int, bytes] = {
    Qt.Key.Key_F1: b"\x1bOP",
    Qt.Key.Key_F2: b"\x1bOQ",
    Qt.Key.Key_F3: b"\x1bOR",
    Qt.Key.Key_F4: b"\x1bOS",
    Qt.Key.Key_F5: b"\x1b[15~",
    Qt.Key.Key_F6: b"\x1b[17~",
    Qt.Key.Key_F7: b"\x1b[18~",
    Qt.Key.Key_F8: b"\x1b[19~",
    Qt.Key.Key_F9: b"\x1b[20~",
    Qt.Key.Key_F10: b"\x1b[21~",
    Qt.Key.Key_F11: b"\x1b[23~",
    Qt.Key.Key_F12: b"\x1b[24~",
}


class TerminalEmulator(QPlainTextEdit):
    """Terminal widget: shows a :class:`core.vt_screen.VTScreen`.

    Output goes into the screen (``feed_bytes`` / ``append_output``), the
    widget shows its scrollback and its rows and puts the caret on its
    cursor. The grid is as large as the widget: ``grid_resized(rows,
    cols)`` tells the owner, which passes it on to the pty. Supports live
    font-size zoom (Ctrl+=, Ctrl+-, Ctrl+0) and a pluggable theme (see
    :data:`TERMINAL_THEMES`).
    """

    data_ready = pyqtSignal(bytes)
    #: The grid changed size (rows, cols): the pty must follow.
    grid_resized = pyqtSignal(int, int)

    def __init__(self, parent: QWidget | None = None, theme: str = DEFAULT_TERMINAL_THEME):
        super().__init__(parent)
        font = QFont("Monospace", FONT_DEFAULT_PT)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setReadOnly(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setUndoRedoEnabled(False)

        # Styling — picked from the theme map; fall back to "Dark"
        # if a profile referenced a theme we no longer ship.
        self._theme_name = theme if theme in TERMINAL_THEMES else DEFAULT_TERMINAL_THEME
        self._apply_theme(self._theme_name)

        # Search-in-scrollback overlay (built lazily on first Ctrl+Shift+F)
        self._search_bar = None
        # Qt drops blocks from the top past this: the screen's scrollback
        # plus its rows always fit.
        self.setMaximumBlockCount(DEFAULT_SCROLLBACK + MAX_ROWS + 1)
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._screen = VTScreen(80, 24)
        # What the document shows: which screen, how much of its
        # scrollback, how many screen rows at the end, which mode.
        self._shown: tuple | None = None
        # The document is a view of the screen: an edit that _render did not
        # make (a drag that moves the selection out, a cut) is drawn over.
        self._rendering = False
        self._redraw_timer = QTimer(self)
        self._redraw_timer.setSingleShot(True)
        self._redraw_timer.setInterval(0)
        self._redraw_timer.timeout.connect(lambda: self._render(full=True))
        self.document().contentsChange.connect(self._on_contents_change)
        self._render(full=True)

    @property
    def screen(self) -> VTScreen:
        return self._screen

    def attach_screen(self, screen: VTScreen) -> None:
        """Show *screen* (a dock tab's) from now on, at this widget's size."""
        self._screen = screen
        rows, cols = self.grid_size()
        screen.resize(cols, rows)
        self._render(full=True)

    def grid_size(self) -> tuple[int, int]:
        """(rows, cols) of text that fit into the visible area."""
        metrics = QFontMetricsF(self.font())
        margin = 2 * self.document().documentMargin()
        viewport = self.viewport()
        cell_w = max(1.0, metrics.horizontalAdvance("M"))
        cell_h = max(1.0, metrics.lineSpacing())
        cols = int((viewport.width() - margin) // cell_w)
        rows = int((viewport.height() - margin) // cell_h)
        return max(MIN_GRID_ROWS, rows), max(MIN_GRID_COLS, cols)

    def _update_grid(self) -> None:
        rows, cols = self.grid_size()
        if (rows, cols) != (self._screen.rows, self._screen.cols):
            self._screen.resize(cols, rows)
            self._render(full=True)
            self.grid_resized.emit(rows, cols)

    def resizeEvent(self, event):  # noqa: N802 — Qt
        """Re-pin the search bar to the top-right corner whenever the
        emulator resizes — without this, dragging the dock wider while
        the bar is open leaves it glued to the OLD right edge."""
        super().resizeEvent(event)
        self._update_grid()
        if self._search_bar is not None and self._search_bar.isVisible():
            self._search_bar._reposition()  # noqa: SLF001

    # ------------------------------------------------------------------
    # Theme + font zoom
    # ------------------------------------------------------------------

    def _apply_theme(self, name: str) -> None:
        """Swap the colour theme. ``name`` falls back to "Dark" when
        unknown so a stale profile reference can't blank the widget."""
        spec = TERMINAL_THEMES.get(name) or TERMINAL_THEMES[DEFAULT_TERMINAL_THEME]
        self._theme_name = name if name in TERMINAL_THEMES else DEFAULT_TERMINAL_THEME
        self.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {spec['bg']}; "
            f"color: {spec['fg']}; "
            f"selection-background-color: {spec['sel']}; }}"
        )

    def set_theme(self, name: str) -> None:
        """Public theme-switch entry point used by the dock toolbar
        and by :meth:`_TerminalTab` profile-restore logic."""
        self._apply_theme(name)

    @property
    def theme_name(self) -> str:
        return self._theme_name

    def zoom_font(self, delta_pt: int) -> None:
        """Adjust the terminal font size by ``delta_pt`` points. Bounds
        below stop runaway Ctrl+= from making the widget unreadable."""
        font = self.font()
        new_pt = max(FONT_MIN_PT, min(FONT_MAX_PT, font.pointSize() + delta_pt))
        if new_pt == font.pointSize():
            return
        font.setPointSize(new_pt)
        self.setFont(font)
        self._update_grid()

    def reset_font(self) -> None:
        font = self.font()
        font.setPointSize(FONT_DEFAULT_PT)
        self.setFont(font)
        self._update_grid()

    # ------------------------------------------------------------------
    # Search in scrollback (Ctrl+F)
    # ------------------------------------------------------------------

    def _toggle_search_bar(self) -> None:
        """Lazily build a small in-pane search bar. Re-pressing Ctrl+F
        toggles its visibility; Esc inside the bar dismisses it."""
        if self._search_bar is None:
            self._search_bar = _TerminalSearchBar(self, self)
        if self._search_bar.isVisible():
            self._search_bar.hide()
            self.setFocus()
        else:
            self._search_bar.show()
            self._search_bar.focus_input()

    def feed_bytes(self, data: bytes) -> None:
        """Output of the host as it arrived: a UTF-8 character split
        between two reads is decoded whole."""
        self.append_output(self._decoder.decode(data))

    def append_output(self, text: str) -> None:
        """Interpret *text* (decoded host output) and show the result.
        Answers the host asked for (a cursor report) go out on
        ``data_ready`` like typed input."""
        self._screen.feed(text)
        replies = self._screen.take_replies()
        if replies:
            self.data_ready.emit(replies)
        self._render()

    def message(self, text: str) -> None:
        """A note of axross itself ("--- Session ended ---"): each line
        break starts a fresh line, whatever the cursor did before."""
        self.append_output(text.replace("\r\n", "\n").replace("\n", "\r\n"))

    def _on_contents_change(self, _position: int, _removed: int, _added: int) -> None:
        if not self._rendering:
            self._redraw_timer.start()

    # ------------------------------------------------------------------
    # Paste, drops, input methods: input for the host, never an edit
    # ------------------------------------------------------------------

    @staticmethod
    def _has_plain_text(source) -> bool:
        # Not hasText(): in Qt 6 it is also true for URLs alone (files
        # dragged from a pane), and their text is a file:// URL.
        if source is None:
            return False
        if source.hasFormat(PANE_MIME_TYPE):
            # A dragged pane is never input for the host, whatever else the
            # drag carries; the terminal pane around this widget takes it.
            return False
        return any(fmt.split(";")[0].strip() == "text/plain" for fmt in source.formats())

    def canInsertFromMimeData(self, source) -> bool:  # noqa: N802 - Qt override
        return self._has_plain_text(source)

    def insertFromMimeData(self, source) -> None:  # noqa: N802 - Qt override
        """Paste (context menu, Ctrl+Shift+V, a middle click) and a text
        drop end here: the text goes to the host like typed input."""
        if self._has_plain_text(source):
            text = source.text()
            if text:
                self.data_ready.emit(text.encode("utf-8"))

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt override
        # Not QPlainTextEdit's drop: it moves the caret to the drop point
        # and, for a move within the widget, deletes the selection.
        mime = event.mimeData()
        if not self.canInsertFromMimeData(mime):
            event.ignore()
            return
        self.insertFromMimeData(mime)
        event.setDropAction(Qt.DropAction.CopyAction)
        event.accept()
        super().dragLeaveEvent(QDragLeaveEvent())  # clears the drop marker

    def inputMethodEvent(self, event) -> None:  # noqa: N802 - Qt override
        text = event.commitString()
        if text:
            self.data_ready.emit(text.encode("utf-8"))
        event.accept()

    def _context_menu(self) -> QMenu:
        """Copy, Paste (to the host) and Select All - no Cut, Delete, Undo:
        the screen belongs to the host."""
        menu = QMenu(self)
        copy = menu.addAction("Copy")
        copy.setEnabled(self.textCursor().hasSelection())
        copy.triggered.connect(self.copy)
        paste = menu.addAction("Paste")
        paste.setEnabled(self.canPaste())
        paste.triggered.connect(self.paste)
        menu.addSeparator()
        select_all = menu.addAction("Select All")
        select_all.triggered.connect(self.selectAll)
        return menu

    def contextMenuEvent(self, event) -> None:  # noqa: N802 - Qt override
        menu = self._context_menu()
        menu.exec(event.globalPos())
        menu.deleteLater()

    def clear(self) -> None:  # noqa: D102 - Qt override: the screen goes too
        self._screen.feed("\x1b[H\x1b[2J\x1b[3J")
        self._render(full=True)

    def _render(self, full: bool = False) -> None:
        """Bring the document up to the screen: new scrollback lines are
        added above the rows, the rows replaced; a different screen, a
        mode switch or lost lines draw everything again."""
        screen = self._screen
        lines = [line.rstrip() for line in screen.screen_lines()]
        row, col = screen.cursor
        prefix = "".join(screen._grid[row][:col])  # noqa: SLF001 - text left of the cursor
        if len(lines[row]) < len(prefix):
            lines[row] = lines[row].ljust(len(prefix))
        alternate = screen.alternate
        shown = self._shown
        doc = self.document()
        # Every edit below is the screen's own: not one to draw over.
        self._rendering = True
        try:
            if (
                full
                or shown is None
                or shown[0] is not screen
                or shown[2] != alternate
                or not 0 <= screen.scrolled_total - shown[1] <= len(screen.scrollback)
                or doc.blockCount() < shown[3]
            ):
                history = [] if alternate else list(screen.scrollback)
                self.setPlainText("\n".join(history + lines))
            else:
                new = screen.scrolled_total - shown[1]
                added = list(screen.scrollback)[len(screen.scrollback) - new:] if new else []
                cursor = QTextCursor(doc.findBlockByNumber(doc.blockCount() - shown[3]))
                cursor.movePosition(QTextCursor.MoveOperation.End, QTextCursor.MoveMode.KeepAnchor)
                cursor.insertText("\n".join(added + lines))
        finally:
            self._rendering = False
        self._shown = (screen, screen.scrolled_total, alternate, len(lines))
        block = doc.findBlockByNumber(doc.blockCount() - len(lines) + row)
        caret = QTextCursor(block)
        # QTextCursor counts UTF-16 units: an emoji or a Nerd Font icon from
        # the supplementary planes is two, one Python character.
        units = len(prefix.encode("utf-16-le", "surrogatepass")) // 2
        caret.setPosition(block.position() + min(units, max(0, block.length() - 1)))
        self.setTextCursor(caret)
        self.ensureCursorVisible()

    @staticmethod
    def _is_own_key(key: int, mods: Qt.KeyboardModifier) -> bool:
        """The terminal's own zoom (Ctrl+= / Ctrl+- / Ctrl+0) and find
        (Ctrl+Shift+F) keys: never sent to the host."""
        if not mods & Qt.KeyboardModifier.ControlModifier:
            return False
        if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal, Qt.Key.Key_Minus, Qt.Key.Key_0):
            return True
        return key == Qt.Key.Key_F and bool(mods & Qt.KeyboardModifier.ShiftModifier)

    def _claims_key(self, event: QKeyEvent) -> bool:
        """True when *event* is input for the host and must not trigger an
        application shortcut: Ctrl+letter, unmodified function, cursor and
        editing keys, text typed with or without Shift, and Ctrl+Shift+V
        (paste). Ctrl+Shift+letter, Alt / Meta combinations, modified
        function keys and the terminal's own zoom / find keys stay with
        the application - its shortcut fires when it has one."""
        key = event.key()
        mods = event.modifiers() & ~Qt.KeyboardModifier.KeypadModifier
        ctrl = _shell_ctrl()
        shift = Qt.KeyboardModifier.ShiftModifier
        if on_macos() and mods & Qt.KeyboardModifier.ControlModifier:
            # Command: only Copy and Paste are the terminal's own.
            return _is_copy_or_paste(event)
        if mods & _app_modifiers():
            return False
        if self._is_own_key(key, mods):
            return False
        if mods == ctrl | shift:
            return key == Qt.Key.Key_V
        if mods == ctrl:
            return Qt.Key.Key_A <= key <= Qt.Key.Key_Z
        if mods == Qt.KeyboardModifier.NoModifier and (
            key in _FUNCTION_KEYS or key in _CURSOR_KEYS or key in _EDIT_KEYS
        ):
            return True
        return bool(event.text()) and key not in _FUNCTION_KEYS

    def event(self, event: QEvent) -> bool:  # noqa: D102 - Qt override
        # Qt offers every key to the focus widget as a ShortcutOverride
        # before it looks for an application shortcut: accepting it here
        # makes Ctrl+W, Ctrl+Q, F6, ... a keyPressEvent of the terminal.
        if event.type() == QEvent.Type.ShortcutOverride and self._claims_key(event):
            event.accept()
            return True
        return super().event(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        mods = event.modifiers()
        text = event.text()

        # Font-zoom shortcuts BEFORE the Ctrl+letter forwarder below,
        # otherwise Ctrl+= / Ctrl+- get sent as ASCII to the remote
        # shell and never reach us.
        if key == Qt.Key.Key_V and mods == _shell_ctrl() | Qt.KeyboardModifier.ShiftModifier:
            self.paste()  # through insertFromMimeData: to the host
            return
        if on_macos() and mods & Qt.KeyboardModifier.ControlModifier:
            # Command+C / Command+V: the macOS copy and paste.
            if event.matches(QKeySequence.StandardKey.Copy):
                self.copy()
                return
            if event.matches(QKeySequence.StandardKey.Paste):
                self.paste()
                return
        if mods & Qt.KeyboardModifier.ControlModifier:
            if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
                self.zoom_font(+FONT_ZOOM_STEP)
                return
            if key == Qt.Key.Key_Minus:
                self.zoom_font(-FONT_ZOOM_STEP)
                return
            if key == Qt.Key.Key_0:
                self.reset_font()
                return
            # Search-in-scrollback: bind to Ctrl+SHIFT+F so the
            # bare Ctrl+F still reaches the remote shell where vim,
            # less, fzf, tmux all use it. Plain Ctrl+F falls through
            # to the Ctrl+letter forwarder below as 0x06.
            if key == Qt.Key.Key_F and (mods & Qt.KeyboardModifier.ShiftModifier):
                self._toggle_search_bar()
                return

        # Ctrl+<letter> → send as terminal control character
        if on_macos() and mods & Qt.KeyboardModifier.ControlModifier:
            return  # any other Command key is no input for the host
        if mods == _shell_ctrl() and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            ctrl_byte = bytes([key - Qt.Key.Key_A + 1])  # Ctrl+A=0x01 .. Ctrl+Z=0x1a
            self.data_ready.emit(ctrl_byte)
            return

        # Cursor and editing keys
        if key in _CURSOR_KEYS:
            table = (
                _CURSOR_KEYS_APPLICATION
                if self._screen.application_cursor_keys
                else _CURSOR_KEYS
            )
            self.data_ready.emit(table[key])
            return
        if key in _EDIT_KEYS:
            self.data_ready.emit(_EDIT_KEYS[key])
            return

        # Function keys, unmodified: a modified one is the application's.
        if key in _FUNCTION_KEYS:
            if not mods & ~Qt.KeyboardModifier.KeypadModifier:
                self.data_ready.emit(_FUNCTION_KEYS[key])
            return

        # Regular text
        if text:
            self.data_ready.emit(text.encode("utf-8"))


class LocalTerminalSession:
    """A local shell session using pty, optionally started in *cwd*.

    The shell enters *cwd* itself, after the fork: the GUI thread never
    asks the filesystem about it (a folder on a dead hard network mount
    never answers). A folder it cannot enter - gone, or not a folder -
    makes it start in the home folder, with a line saying so."""

    def __init__(self, cwd: str | None = None):
        self._cwd = cwd
        # Taken now, in the parent: a fork must not look anything up.
        self._fallback_cwd = str(Path.home())
        self._master_fd: int | None = None
        self._pid: int | None = None
        self._running = False
        # Windows: a winpty.PtyProcess (ConPTY) in place of the pty pair.
        self._winpty = None

    @property
    def is_active(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start a local shell."""
        try:
            import pty
        except ImportError:  # Windows has no pty module
            self._start_winpty()
            return
        pid, master_fd = pty.fork()
        if pid == 0:
            from core.subprocess_env import clean_child_env

            shell = os.environ.get("SHELL", "/bin/sh")
            # A frozen bundle points LD_LIBRARY_PATH at its own
            # extraction directory, and the shell would resolve
            # libreadline against ours — "symbol lookup error:
            # undefined symbol: rl_trim_arg_from_keyseq".
            env = clean_child_env(TERM="xterm")
            # The child must reach execve whatever happens: falling back
            # into the parent's Python code from a fork would run a second
            # copy of the application - hence every step guarded.
            # Without a folder the shell starts where axross runs, as always.
            for index, folder in enumerate((self._cwd, self._fallback_cwd) if self._cwd
                                           else ()):
                try:
                    os.chdir(folder)
                    env["PWD"] = folder
                    break
                except OSError as exc:
                    try:
                        os.write(2, f"axross: cannot enter {folder}: {exc}\r\n".encode())
                    except OSError:
                        pass
                    if index:
                        break
            os.execve(shell, [shell], env)
        else:
            self._pid = pid
            self._master_fd = master_fd
            self._running = True
            log.info("Local terminal started (PID %d)", pid)

    def _start_winpty(self) -> None:
        """Start ``COMSPEC`` in a ConPTY through pywinpty (Windows)."""
        try:
            from winpty import PtyProcess
        except ImportError as exc:
            raise OSError(
                "A local terminal needs a POSIX pty or, on Windows, pywinpty (pip install pywinpty)"
            ) from exc
        from core.subprocess_env import clean_child_env

        shell = os.environ.get("COMSPEC", "cmd.exe")
        # ConPTY takes the folder up front and refuses one that is gone.
        cwd = self._cwd if self._cwd and os.path.isdir(self._cwd) else self._fallback_cwd
        self._winpty = PtyProcess.spawn(
            [shell], cwd=cwd or None, env=clean_child_env(TERM="xterm")
        )
        self._pid = getattr(self._winpty, "pid", None)
        self._running = True
        log.info("Local terminal started (ConPTY, PID %s)", self._pid)

    def write(self, data: bytes) -> None:
        if self._winpty is not None:
            self._winpty.write(data.decode("utf-8", "replace"))
            return
        if self._master_fd is not None:
            os.write(self._master_fd, data)

    def read(self, size: int = 4096) -> bytes:
        if self._winpty is not None:
            return self._read_winpty(size)
        if self._master_fd is None:
            return b""
        try:
            r, _, _ = select.select([self._master_fd], [], [], 0.05)
            if r:
                return os.read(self._master_fd, size)
        except OSError as e:
            self._running = False
            log.debug("Local terminal read ended: %s", e)
        return b""

    def _read_winpty(self, size: int) -> bytes:
        # fileno() is a socket that pywinpty's reader thread feeds; select
        # waits on sockets on Windows too, so the read never blocks.
        try:
            r, _, _ = select.select([self._winpty.fileno()], [], [], 0.05)
            if r:
                return self._winpty.read(size).encode("utf-8")
        except (EOFError, OSError, ValueError) as e:
            self._running = False
            log.debug("Local terminal read ended: %s", e)
        return b""

    def resize(self, rows: int, cols: int) -> None:
        if self._winpty is not None:
            self._winpty.setwinsize(rows, cols)
            return
        if self._master_fd is not None:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            import fcntl
            import termios

            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, winsize)

    def close(self) -> None:
        # Closing the master pty first signals EOF to the child shell so
        # the common case ("user closes the tab") exits cleanly without
        # SIGTERM. SIGTERM is the safety net for shells that ignore EOF
        # (e.g. set -o ignoreeof), and SIGKILL the last resort.
        #
        # WNOHANG-only used to leak the child as <defunct>: returning
        # before the shell actually exits means subsequent test runs
        # (LocalTerminalSession spins one shell per session) accumulate
        # zombies inside the pytest-xdist worker, growing the process
        # table until the kernel refuses new clones. Block briefly here
        # — the shell exits in ms — and escalate to SIGKILL if it does
        # not.
        self._running = False
        if self._winpty is not None:
            proc, self._winpty, self._pid = self._winpty, None, None
            try:
                proc.close(force=True)
            except (OSError, EOFError):
                pass
            log.info("Local terminal closed")
            return
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None
        pid = self._pid
        self._pid = None
        if pid is not None:
            try:
                os.kill(pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
            if not self._reap(pid, grace_s=0.5):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                # SIGKILL is guaranteed to terminate; final wait is
                # blocking so we always reap the zombie.
                try:
                    os.waitpid(pid, 0)
                except (OSError, ChildProcessError):
                    pass
        log.info("Local terminal closed")

    @staticmethod
    def _reap(pid: int, grace_s: float) -> bool:
        """Poll-wait for child ``pid`` up to ``grace_s`` seconds.

        Returns True if the child was reaped within the grace window,
        False otherwise (caller should escalate to SIGKILL).
        """
        deadline = time.monotonic() + grace_s
        while True:
            try:
                gone, _ = os.waitpid(pid, os.WNOHANG)
            except (OSError, ChildProcessError):
                return True
            if gone != 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)


class SSHTerminalSession:
    """An SSH shell session using paramiko channel."""

    def __init__(
        self,
        transport: paramiko.Transport,
        suppress_history: bool = True,
        initial_dir: str | None = None,
        *,
        rows: int = 40,
        cols: int = 120,
    ):
        self._transport = transport
        # The pty size the shell starts with; resize() follows the widget.
        self._size = (int(rows), int(cols))
        # Remote folder to cd into once the shell is up (Open Terminal Here).
        self._initial_dir = initial_dir
        self._channel: paramiko.Channel | None = None
        self._running = False
        # When False, we skip the post-shell history-suppression
        # bytes — useful for users running their own boxes who want
        # bash_history kept normally. The safe default is True (red-
        # team / forensic engagements).
        self._suppress_history = bool(suppress_history)

    @property
    def is_active(self) -> bool:
        return self._running and self._channel is not None and not self._channel.closed

    def start(self) -> None:
        self._channel = self._transport.open_session()
        rows, cols = self._size
        self._channel.get_pty(term="xterm", width=cols, height=rows)
        self._channel.invoke_shell()
        self._running = True
        # OpSec: suppress shell history right after the shell starts.
        # The very next thing the user types ought not to land in
        # ~/.bash_history or the zsh history file. We send the
        # commands silently — the prompt comes back empty because
        # ``unset HISTFILE`` has no output. See docs/OPSEC.md.
        # Skipped when the user explicitly opted out per-profile
        # (``suppress_shell_history=False``).
        if self._suppress_history:
            try:
                self._channel.sendall(_SHELL_HISTORY_SUPPRESSION_SCRIPT)
            except Exception as exc:  # noqa: BLE001 — defensive
                log.debug("SSH terminal: history-suppression send failed: %s", exc)
        else:
            log.info("SSH terminal: history suppression disabled per profile")
        if self._initial_dir:
            from core.terminal_here import remote_cd_command

            try:
                self._channel.sendall(remote_cd_command(self._initial_dir))
            except ValueError as exc:
                log.warning("SSH terminal: not changing folder: %s", exc)
            except Exception as exc:  # noqa: BLE001 — defensive, like the line above
                log.debug("SSH terminal: cd send failed: %s", exc)
        log.info("SSH terminal session started")

    def write(self, data: bytes) -> None:
        if self._channel is not None and not self._channel.closed:
            self._channel.sendall(data)

    def read(self, size: int = 4096) -> bytes:
        if self._channel is None or self._channel.closed:
            self._running = False
            return b""
        try:
            if self._channel.recv_ready():
                return self._channel.recv(size)
        except Exception as e:
            self._running = False
            log.debug("SSH terminal read ended: %s", e)
        return b""

    def resize(self, rows: int, cols: int) -> None:
        if self._channel is not None and not self._channel.closed:
            try:
                self._channel.resize_pty(width=cols, height=rows)
            except Exception as e:
                log.debug("Could not resize SSH terminal: %s", e)

    def close(self) -> None:
        self._running = False
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception as e:
                log.debug("Could not close SSH terminal channel cleanly: %s", e)
            self._channel = None
        log.info("SSH terminal session closed")


class _TerminalSearchBar(QWidget):
    """Tiny in-pane search overlay for terminal scrollback. Triggered
    by Ctrl+F inside :class:`TerminalEmulator`. Esc closes it; Enter
    finds the next match; Shift+Enter finds the previous match."""

    def __init__(self, terminal: "TerminalEmulator", parent: QWidget):
        # Parent is the TerminalEmulator so the bar sits visually
        # over its top-right corner.
        super().__init__(parent)
        self._terminal = terminal
        self.setFixedHeight(28)
        self.setStyleSheet(
            "QWidget { background: rgba(40, 40, 40, 230); "
            "border-radius: 4px; padding: 2px; }"
            "QLineEdit { background: #2a2a2a; color: #e0e0e0; "
            "border: 1px solid #555; padding: 2px 4px; }"
            "QLabel { color: #e0e0e0; padding: 0 6px; }"
            "QPushButton { background: #444; color: #e0e0e0; "
            "border: 1px solid #555; padding: 2px 8px; }"
            "QPushButton:pressed { background: #666; }"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)
        self._input = QLineEdit()
        self._input.setPlaceholderText("Find in scrollback (Esc to close)")
        self._input.returnPressed.connect(self._find_next)
        layout.addWidget(self._input, stretch=1)
        prev_btn = QPushButton("Prev")
        prev_btn.clicked.connect(self._find_prev)
        layout.addWidget(prev_btn)
        next_btn = QPushButton("Next")
        next_btn.clicked.connect(self._find_next)
        layout.addWidget(next_btn)
        close_btn = QPushButton("×")
        close_btn.setFixedWidth(28)
        close_btn.clicked.connect(self.hide)
        layout.addWidget(close_btn)
        self.hide()
        self._reposition()

    def focus_input(self) -> None:
        self._input.setFocus()
        self._input.selectAll()

    def _reposition(self) -> None:
        # Pin to top-right of the parent (the TerminalEmulator).
        parent = self.parent()
        if parent is None:
            return
        margin = 4
        self.adjustSize()
        self.move(parent.width() - self.width() - margin, margin)

    def showEvent(self, event):  # noqa: N802 — Qt
        self._reposition()
        super().showEvent(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 — Qt
        if event.key() == Qt.Key.Key_Escape:
            self.hide()
            self._terminal.setFocus()
            return
        super().keyPressEvent(event)

    def _find_next(self) -> None:
        needle = self._input.text()
        if not needle:
            return
        if not self._terminal.find(needle):
            # Wrap to top.
            cur = self._terminal.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.Start)
            self._terminal.setTextCursor(cur)
            self._terminal.find(needle)

    def _find_prev(self) -> None:
        from PyQt6.QtGui import QTextDocument

        needle = self._input.text()
        if not needle:
            return
        if not self._terminal.find(
            needle,
            QTextDocument.FindFlag.FindBackward,
        ):
            cur = self._terminal.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            self._terminal.setTextCursor(cur)
            self._terminal.find(
                needle,
                QTextDocument.FindFlag.FindBackward,
            )


def _transport_alive(transport) -> bool:
    """True for an SSH transport that still carries its connection."""
    is_active = getattr(transport, "is_active", None)
    if not callable(is_active):
        return False
    try:
        return bool(is_active())
    except Exception:  # noqa: BLE001 - a broken transport is a dead one
        return False


class _TerminalTab:
    """Holds state for one terminal session: session object + output buffer."""

    def __init__(self, cwd: str | None = None, remote_dir: str | None = None):
        self.session: LocalTerminalSession | SSHTerminalSession | None = None
        self.buffer: str = ""  # accumulated output text
        # What the tab shows; output of a tab in the background goes here
        # too, so switching back shows the screen as the host left it.
        self.screen = VTScreen(80, 24)
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        # Folder a (re)started session begins in: local, or remote via cd.
        self.cwd = cwd
        self.remote_dir = remote_dir


class TerminalDock(QDockWidget):
    """Dockable terminal panel with local and SSH shell support."""

    # Fires whenever a terminal session produces new output. The
    # MainWindow uses this to highlight the dock's tab when the
    # user is looking at a different dock — background shell output
    # shouldn't stay invisible.
    activity = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__("Terminal", parent)
        self.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea
        )
        # Map combo-box index key to tab state
        self._tabs: dict[str, _TerminalTab] = {}
        self._active_key: str | None = None
        # Extra "Open Terminal Here" SSH entries -> the session name they
        # belong to, so remove_ssh_session takes them down as well.
        self._ssh_extra: dict[str, str] = {}
        self._setup_ui()

    def _setup_ui(self) -> None:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Toolbar
        toolbar = QHBoxLayout()

        self._session_combo = QComboBox()
        self._session_combo.addItem("Local Shell")
        self._session_combo.setMinimumWidth(200)
        self._session_combo.currentIndexChanged.connect(self._on_session_switched)
        toolbar.addWidget(QLabel("Session:"))
        toolbar.addWidget(self._session_combo)

        self._btn_start = QPushButton("Start")
        self._btn_start.clicked.connect(self._start_session)
        toolbar.addWidget(self._btn_start)

        self._btn_stop = QPushButton("Stop")
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._stop_session)
        toolbar.addWidget(self._btn_stop)

        self._btn_clear = QPushButton("Clear")
        self._btn_clear.clicked.connect(self._clear_output)
        toolbar.addWidget(self._btn_clear)

        # "+" — spawn a brand-new local sub-shell tab. Adds an entry
        # to the session combo with a unique label so the user can
        # juggle multiple local shells without losing the original.
        self._btn_new = QPushButton("+ Local")
        self._btn_new.setToolTip("Spawn a fresh local sub-shell as a new session entry.")
        self._btn_new.clicked.connect(self._spawn_local_subshell)
        toolbar.addWidget(self._btn_new)

        # Theme picker — drives _terminal.set_theme(). Persists per-
        # dock for the running session (not per-profile yet).
        from PyQt6.QtWidgets import QComboBox as _QCb

        self._theme_combo = _QCb()
        for theme_name in TERMINAL_THEMES:
            self._theme_combo.addItem(theme_name)
        self._theme_combo.setCurrentText(DEFAULT_TERMINAL_THEME)
        self._theme_combo.currentTextChanged.connect(self._on_theme_changed)
        toolbar.addWidget(QLabel("Theme:"))
        toolbar.addWidget(self._theme_combo)

        toolbar.addStretch()

        self._status_label = QLabel("Disconnected")
        toolbar.addWidget(self._status_label)

        layout.addLayout(toolbar)

        # Terminal emulator
        self._terminal = TerminalEmulator()
        self._terminal.data_ready.connect(self._on_input)
        self._terminal.grid_resized.connect(self._on_grid_resized)
        layout.addWidget(self._terminal, stretch=1)

        self.setWidget(container)

        # Read timer — polls ALL active sessions for output
        self._read_timer = QTimer(self)
        self._read_timer.setInterval(50)
        self._read_timer.timeout.connect(self._poll_output)

    def _current_key(self) -> str:
        return self._session_combo.currentText()

    def _get_or_create_tab(self, key: str) -> _TerminalTab:
        if key not in self._tabs:
            self._tabs[key] = _TerminalTab()
            if key == self._current_key():
                self._terminal.attach_screen(self._tabs[key].screen)
        return self._tabs[key]

    def _on_grid_resized(self, rows: int, cols: int) -> None:
        tab = self._tabs.get(self._current_key())
        if tab is not None and tab.session is not None and tab.session.is_active:
            tab.session.resize(rows, cols)

    def add_ssh_session(self, name: str, transport) -> None:
        """Register an SSH transport as a terminal option.

        An entry of the same name is re-pointed (and its running shell
        restarted) only when its own transport is gone - a reconnect. One
        whose transport is still alive belongs to another connection: the
        new transport gets an entry of its own instead of taking over a
        running shell on a different machine."""
        label = f"SSH: {name}"
        for i in range(self._session_combo.count()):
            if self._session_combo.itemText(i) == label:
                current = self._session_combo.itemData(i)
                if current is transport:
                    return  # already registered
                if _transport_alive(current):
                    extra = self._unique_label(label)
                    self._ssh_extra[extra] = name
                    self._session_combo.addItem(extra, userData=transport)
                    log.info("Registered SSH terminal option: %s", extra)
                    return
                self._session_combo.setItemData(i, transport)
                tab = self._tabs.get(label)
                if tab and isinstance(tab.session, SSHTerminalSession):
                    was_active = tab.session.is_active
                    tab.session.close()
                    tab.session = None
                    if was_active:
                        try:
                            # The pty the widget shows, as _start_session
                            # opens it - not the 40x120 default.
                            rows, cols = self._terminal.grid_size()
                            session = SSHTerminalSession(
                                transport, initial_dir=tab.remote_dir, rows=rows, cols=cols
                            )
                            session.start()
                            tab.session = session
                            self._read_timer.start()
                            if self._active_key == label:
                                self._btn_start.setEnabled(False)
                                self._btn_stop.setEnabled(True)
                                self._status_label.setText(f"Connected: {label}")
                            log.info(
                                "Restarted SSH terminal session for %s after transport update", name
                            )
                        except Exception as e:
                            log.error("Failed to restart SSH terminal for %s: %s", name, e)
                            if self._active_key == label:
                                self._btn_start.setEnabled(True)
                                self._btn_stop.setEnabled(False)
                                self._status_label.setText("Disconnected")
                                self._terminal.message(f"\n--- Reconnect failed: {e} ---\n")
                for j in range(self._session_combo.count()):
                    if self._ssh_extra.get(
                        self._session_combo.itemText(j)
                    ) == name and not _transport_alive(self._session_combo.itemData(j)):
                        self._session_combo.setItemData(j, transport)
                log.debug("Updated SSH terminal option: %s", label)
                return
        self._session_combo.addItem(label, userData=transport)
        log.info("Registered SSH terminal option: %s", label)

    def remove_ssh_session(self, name: str) -> None:
        """Remove an SSH terminal option, and the folder entries opened on it."""
        labels = [f"SSH: {name}"] + [
            lbl for lbl, owner in self._ssh_extra.items() if owner == name
        ]
        for label in labels:
            self._ssh_extra.pop(label, None)
            for i in range(self._session_combo.count()):
                if self._session_combo.itemText(i) == label:
                    # Stop session if active
                    tab = self._tabs.get(label)
                    if tab and tab.session:
                        tab.session.close()
                        tab.session = None
                    self._tabs.pop(label, None)
                    if self._active_key == label:
                        self._active_key = None
                    self._session_combo.removeItem(i)
                    break

    def _on_session_switched(self, _index: int) -> None:
        """User switched session in combo box — show that session's buffer."""
        key = self._current_key()
        if key == self._active_key:
            return

        self._active_key = key
        tab = self._get_or_create_tab(key)

        # Every tab keeps its own screen; the widget shows the selected one
        # at its own size, and that session's pty follows.
        self._terminal.attach_screen(tab.screen)
        if tab.session is not None and tab.session.is_active:
            tab.session.resize(*self._terminal.grid_size())

        # Update button states
        has_active_session = tab.session is not None and tab.session.is_active
        self._btn_start.setEnabled(not has_active_session)
        self._btn_stop.setEnabled(has_active_session)
        self._status_label.setText(key if has_active_session else "Disconnected")

    def _start_session(self) -> None:
        key = self._current_key()
        tab = self._get_or_create_tab(key)

        if tab.session and tab.session.is_active:
            return  # Already running

        idx = self._session_combo.currentIndex()
        transport = self._session_combo.itemData(idx)

        if transport is not None:
            # SSH session
            try:
                rows, cols = self._terminal.grid_size()
                tab.session = SSHTerminalSession(
                    transport, initial_dir=tab.remote_dir, rows=rows, cols=cols
                )
                tab.session.start()
                self._status_label.setText(f"Connected: {key}")
            except Exception as e:
                log.error("Failed to start SSH terminal: %s", e)
                self._terminal.message(f"\n--- Error: {e} ---\n")
                return
        else:
            # Local shell
            tab.session = LocalTerminalSession(cwd=tab.cwd)
            tab.session.start()
            tab.session.resize(*self._terminal.grid_size())
            self._status_label.setText("Local Shell")

        self._active_key = key
        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._read_timer.start()
        self._terminal.setFocus()

    def _stop_session(self) -> None:
        key = self._current_key()
        tab = self._tabs.get(key)
        if tab and tab.session:
            tab.session.close()
            tab.session = None
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._status_label.setText("Disconnected")
        self._terminal.message("\n--- Session ended ---\n")

    def _on_input(self, data: bytes) -> None:
        key = self._current_key()
        tab = self._tabs.get(key)
        if tab and tab.session and tab.session.is_active:
            tab.session.write(data)

    def _poll_output(self) -> None:
        any_active = False
        for key, tab in list(self._tabs.items()):
            if not tab.session:
                continue
            if not tab.session.is_active:
                tab.session.close()
                tab.session = None
                tab.buffer += "\n--- Session ended ---\n"
                if key == self._current_key():
                    self._btn_start.setEnabled(True)
                    self._btn_stop.setEnabled(False)
                    self._status_label.setText("Disconnected")
                    self._terminal.message("\n--- Session ended ---\n")
                else:
                    tab.screen.feed("\r\n--- Session ended ---\r\n")
                log.info("Terminal session ended: %s", key)
                continue
            any_active = True

            data = tab.session.read()
            if data:
                text = tab.decoder.decode(data)
                # Cap the buffer so a flooding remote can't saturate RAM.
                # Keep the trailing half of the cap when we overflow —
                # the recent output is what the user cares about if the
                # flood just arrived.
                if len(tab.buffer) + len(text) > TERMINAL_BUFFER_CAP_BYTES:
                    keep = TERMINAL_BUFFER_CAP_BYTES // 2
                    combined = tab.buffer + text
                    tab.buffer = combined[-keep:]
                else:
                    tab.buffer += text

                # The visible tab's screen is the widget's: it renders and
                # answers the host itself; a background tab's screen only
                # takes the text and its answers go out here.
                if key == self._current_key() and self._terminal.screen is tab.screen:
                    self._terminal.append_output(text)
                else:
                    tab.screen.feed(text)
                    replies = tab.screen.take_replies()
                    if replies:
                        tab.session.write(replies)
                # Any session producing output — raised or not — counts
                # as activity so the dock's tab gets highlighted when
                # the user is looking at Log or Transfers.
                self.activity.emit()

        if not any_active:
            self._read_timer.stop()

    def _clear_output(self) -> None:
        self._terminal.clear()
        key = self._current_key()
        tab = self._tabs.get(key)
        if tab:
            tab.buffer = ""

    def shutdown(self) -> None:
        self._read_timer.stop()
        for tab in self._tabs.values():
            if tab.session:
                tab.session.close()
                tab.session = None
        self._tabs.clear()

    # ------------------------------------------------------------------
    # New-shell + theme handlers
    # ------------------------------------------------------------------

    def _spawn_local_subshell(self) -> None:
        """Add a fresh "Local Shell #N" entry to the session combo,
        switch to it, AND start the underlying LocalTerminalSession
        immediately. The earlier version only added the combo entry
        and waited for the user to hit Start, which surprised people
        who expected the new tab to be live straight away."""
        # Find the next unused index. We start at #1 so the first
        # extra subshell reads naturally as "Local Shell 1".
        idx = 1
        while True:
            label = f"Local Shell {idx}"
            existing = [self._session_combo.itemText(i) for i in range(self._session_combo.count())]
            if label not in existing:
                break
            idx += 1
        self._session_combo.addItem(label)
        self._session_combo.setCurrentText(label)
        # Switching the combo wires up the tab; kicking _start_session
        # is what the user expects when they click "+ Local". If start
        # raises (no PTY available, etc.), we surface it via the
        # status label rather than letting the click silently no-op.
        try:
            self._start_session()
        except Exception as exc:  # noqa: BLE001 — UI-level catch
            log.error("Spawn local sub-shell failed: %s", exc)
            self._status_label.setText(f"Spawn failed: {exc}")
        log.info("Terminal dock: spawned %s", label)

    # ------------------------------------------------------------------
    # Open Terminal Here
    # ------------------------------------------------------------------

    def _unique_label(self, base: str) -> str:
        existing = {self._session_combo.itemText(i) for i in range(self._session_combo.count())}
        if base not in existing:
            return base
        n = 2
        while f"{base} #{n}" in existing:
            n += 1
        return f"{base} #{n}"

    def _open_tab(self, label: str, tab: _TerminalTab, transport=None) -> str:
        """Add *tab* as a new combo entry, switch to it and start it."""
        self._tabs[label] = tab
        self._session_combo.addItem(label, userData=transport)
        self._session_combo.setCurrentText(label)
        try:
            self._start_session()
        except Exception as exc:  # noqa: BLE001 — UI-level catch, like + Local
            log.error("Terminal dock: starting %s failed: %s", label, exc)
            self._status_label.setText(f"Start failed: {exc}")
        return label

    def open_local_shell_at(self, directory: str) -> str | None:
        """Open a fresh local shell whose working folder is *directory*.

        Returns the new entry's label, or None (with the reason in the
        status line) when the folder no longer exists.
        """
        folder = os.path.abspath(directory)
        if not os.path.isdir(folder):
            self._status_label.setText(f"{folder} is no longer a folder")
            log.warning("Terminal dock: %s is no longer a folder", folder)
            return None
        name = os.path.basename(folder.rstrip(os.sep)) or folder
        label = self._unique_label(f"Local Shell: {name}")
        log.info("Terminal dock: local shell in %s", folder)
        return self._open_tab(label, _TerminalTab(cwd=folder))

    def open_ssh_shell_at(self, name: str, transport, directory: str) -> str | None:
        """Open a fresh shell on *transport* (SSH session *name*) and cd to
        *directory*. Returns the label, or None when the folder name holds
        a control character that cannot be sent to a remote tty."""
        from core.terminal_here import remote_cd_command

        try:
            remote_cd_command(directory)
        except ValueError as exc:
            self._status_label.setText(str(exc))
            log.warning("Terminal dock: %s", exc)
            return None
        label = self._unique_label(f"SSH: {name} @ {directory}")
        self._ssh_extra[label] = name
        log.info("Terminal dock: SSH shell on %s in %s", name, directory)
        return self._open_tab(label, _TerminalTab(remote_dir=directory), transport)

    def _on_theme_changed(self, theme_name: str) -> None:
        """Live-swap the terminal's colour theme. Affects the visible
        widget for every tab (we only have one TerminalEmulator
        instance — output buffers are per-tab, the widget isn't)."""
        if hasattr(self, "_terminal"):
            self._terminal.set_theme(theme_name)
