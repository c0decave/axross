"""Terminal widget — interactive SSH shell or local terminal in a dock."""
from __future__ import annotations

import logging
import os
import pty
import select
import signal
import struct
import threading
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QKeyEvent, QTextCursor
from PyQt6.QtWidgets import (
    QComboBox,
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    import paramiko

log = logging.getLogger(__name__)

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
    "Dark":            {"bg": "#1e1e1e", "fg": "#d4d4d4", "sel": "#264f78"},
    "Solarized-Dark":  {"bg": "#002b36", "fg": "#93a1a1", "sel": "#073642"},
    "Solarized-Light": {"bg": "#fdf6e3", "fg": "#586e75", "sel": "#eee8d5"},
    "Hacker":          {"bg": "#000000", "fg": "#00ff00", "sel": "#005500"},
    "Amber":           {"bg": "#1a0f00", "fg": "#ffb000", "sel": "#553c00"},
    "Light":           {"bg": "#ffffff", "fg": "#000000", "sel": "#cce4ff"},
}
DEFAULT_TERMINAL_THEME = "Dark"

# Per-zoom step in points. Ctrl+= grows the font, Ctrl+- shrinks,
# Ctrl+0 resets. Caps below stop the user from accidentally
# zooming the widget into uselessness.
FONT_ZOOM_STEP = 1
FONT_MIN_PT = 6
FONT_MAX_PT = 28
FONT_DEFAULT_PT = 10


class TerminalEmulator(QPlainTextEdit):
    """Simple terminal emulator widget using QPlainTextEdit.

    Handles basic ANSI escape sequences for color and cursor control.
    Supports live font-size zoom (Ctrl+=, Ctrl+-, Ctrl+0) and a
    pluggable theme (see :data:`TERMINAL_THEMES`).
    """

    data_ready = pyqtSignal(bytes)

    def __init__(self, parent: QWidget | None = None,
                 theme: str = DEFAULT_TERMINAL_THEME):
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

        self._input_start = 0  # Position where user input begins
        # Search-in-scrollback overlay (built lazily on first Ctrl+Shift+F)
        self._search_bar = None

    def resizeEvent(self, event):  # noqa: N802 — Qt
        """Re-pin the search bar to the top-right corner whenever the
        emulator resizes — without this, dragging the dock wider while
        the bar is open leaves it glued to the OLD right edge."""
        super().resizeEvent(event)
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

    def reset_font(self) -> None:
        font = self.font()
        font.setPointSize(FONT_DEFAULT_PT)
        self.setFont(font)

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

    def append_output(self, text: str) -> None:
        """Append output text, stripping ANSI and terminal escape sequences."""
        import re
        # CSI sequences: ESC [ ... letter
        clean = re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]', '', text)
        # OSC sequences: ESC ] ... BEL or ESC ] ... ST
        clean = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', clean)
        # DCS/PM/APC sequences
        clean = re.sub(r'\x1b[P_^][^\x1b]*\x1b\\', '', clean)
        # Remaining standalone ESC sequences
        clean = re.sub(r'\x1b[()][0-9A-B]', '', clean)
        clean = re.sub(r'\x1b[=>]', '', clean)
        # BEL character
        clean = clean.replace('\x07', '')
        # Carriage return handling
        clean = clean.replace('\r\n', '\n').replace('\r', '')

        if not clean:
            return

        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Process backspace characters (\x08) for proper terminal behavior
        for ch in clean:
            if ch == '\x08':
                # Move cursor one position left (delete previous char visually)
                cursor.movePosition(QTextCursor.MoveOperation.Left, QTextCursor.MoveMode.KeepAnchor)
                cursor.removeSelectedText()
            else:
                cursor.insertText(ch)

        self.setTextCursor(cursor)
        self.ensureCursorVisible()
        self._input_start = cursor.position()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        mods = event.modifiers()
        text = event.text()

        # Font-zoom shortcuts BEFORE the Ctrl+letter forwarder below,
        # otherwise Ctrl+= / Ctrl+- get sent as ASCII to the remote
        # shell and never reach us.
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
            if (
                key == Qt.Key.Key_F
                and (mods & Qt.KeyboardModifier.ShiftModifier)
            ):
                self._toggle_search_bar()
                return

        # Ctrl+<letter> → send as terminal control character
        if mods == Qt.KeyboardModifier.ControlModifier and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            ctrl_byte = bytes([key - Qt.Key.Key_A + 1])  # Ctrl+A=0x01 .. Ctrl+Z=0x1a
            self.data_ready.emit(ctrl_byte)
            return

        # Arrow keys
        arrow_map = {
            Qt.Key.Key_Up: b'\x1b[A',
            Qt.Key.Key_Down: b'\x1b[B',
            Qt.Key.Key_Right: b'\x1b[C',
            Qt.Key.Key_Left: b'\x1b[D',
            Qt.Key.Key_Home: b'\x1b[H',
            Qt.Key.Key_End: b'\x1b[F',
            Qt.Key.Key_Delete: b'\x1b[3~',
            Qt.Key.Key_PageUp: b'\x1b[5~',
            Qt.Key.Key_PageDown: b'\x1b[6~',
        }
        if key in arrow_map:
            self.data_ready.emit(arrow_map[key])
            return

        # Enter
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.data_ready.emit(b'\n')
            return

        # Backspace
        if key == Qt.Key.Key_Backspace:
            self.data_ready.emit(b'\x7f')
            return

        # Tab
        if key == Qt.Key.Key_Tab:
            self.data_ready.emit(b'\t')
            return

        # Regular text
        if text:
            self.data_ready.emit(text.encode("utf-8"))


class LocalTerminalSession:
    """A local shell session using pty."""

    def __init__(self):
        self._master_fd: int | None = None
        self._pid: int | None = None
        self._running = False

    @property
    def is_active(self) -> bool:
        return self._running

    def start(self) -> None:
        """Start a local shell."""
        pid, master_fd = pty.fork()
        if pid == 0:
            shell = os.environ.get("SHELL", "/bin/sh")
            env = os.environ.copy()
            env["TERM"] = "xterm"
            os.execve(shell, [shell], env)
        else:
            self._pid = pid
            self._master_fd = master_fd
            self._running = True
            log.info("Local terminal started (PID %d)", pid)

    def write(self, data: bytes) -> None:
        if self._master_fd is not None:
            os.write(self._master_fd, data)

    def read(self, size: int = 4096) -> bytes:
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

    def resize(self, rows: int, cols: int) -> None:
        if self._master_fd is not None:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            import fcntl
            import termios
            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, winsize)

    def close(self) -> None:
        self._running = False
        if self._master_fd is not None:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = None
        if self._pid is not None:
            try:
                os.kill(self._pid, signal.SIGTERM)
                os.waitpid(self._pid, os.WNOHANG)
            except (OSError, ChildProcessError):
                pass
            self._pid = None
        log.info("Local terminal closed")


class SSHTerminalSession:
    """An SSH shell session using paramiko channel."""

    def __init__(
        self,
        transport: paramiko.Transport,
        suppress_history: bool = True,
    ):
        self._transport = transport
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
        self._channel.get_pty(term="xterm", width=120, height=40)
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
            needle, QTextDocument.FindFlag.FindBackward,
        ):
            cur = self._terminal.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            self._terminal.setTextCursor(cur)
            self._terminal.find(
                needle, QTextDocument.FindFlag.FindBackward,
            )


class _TerminalTab:
    """Holds state for one terminal session: session object + output buffer."""
    def __init__(self):
        self.session: LocalTerminalSession | SSHTerminalSession | None = None
        self.buffer: str = ""  # accumulated output text


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
        self._btn_new.setToolTip(
            "Spawn a fresh local sub-shell as a new session entry."
        )
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
        return self._tabs[key]

    def add_ssh_session(self, name: str, transport) -> None:
        """Register an SSH transport as a terminal option."""
        label = f"SSH: {name}"
        for i in range(self._session_combo.count()):
            if self._session_combo.itemText(i) == label:
                self._session_combo.setItemData(i, transport)
                tab = self._tabs.get(label)
                if tab and isinstance(tab.session, SSHTerminalSession):
                    was_active = tab.session.is_active
                    tab.session.close()
                    tab.session = None
                    if was_active:
                        try:
                            tab.session = SSHTerminalSession(transport)
                            tab.session.start()
                            self._read_timer.start()
                            if self._active_key == label:
                                self._btn_start.setEnabled(False)
                                self._btn_stop.setEnabled(True)
                                self._status_label.setText(f"Connected: {label}")
                            log.info("Restarted SSH terminal session for %s after transport update", name)
                        except Exception as e:
                            log.error("Failed to restart SSH terminal for %s: %s", name, e)
                            if self._active_key == label:
                                self._btn_start.setEnabled(True)
                                self._btn_stop.setEnabled(False)
                                self._status_label.setText("Disconnected")
                                self._terminal.append_output(f"\n--- Reconnect failed: {e} ---\n")
                log.debug("Updated SSH terminal option: %s", label)
                return
        self._session_combo.addItem(label, userData=transport)
        log.info("Registered SSH terminal option: %s", label)

    def remove_ssh_session(self, name: str) -> None:
        """Remove an SSH terminal option."""
        label = f"SSH: {name}"
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

        # Save current terminal content to previous tab
        if self._active_key and self._active_key in self._tabs:
            self._tabs[self._active_key].buffer = self._terminal.toPlainText()

        self._active_key = key
        tab = self._get_or_create_tab(key)

        # Restore buffer for the selected session
        self._terminal.setPlainText(tab.buffer)
        cursor = self._terminal.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self._terminal.setTextCursor(cursor)
        self._terminal.ensureCursorVisible()

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
                tab.session = SSHTerminalSession(transport)
                tab.session.start()
                self._status_label.setText(f"Connected: {key}")
            except Exception as e:
                log.error("Failed to start SSH terminal: %s", e)
                self._terminal.append_output(f"\n--- Error: {e} ---\n")
                return
        else:
            # Local shell
            tab.session = LocalTerminalSession()
            tab.session.start()
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
        self._terminal.append_output("\n--- Session ended ---\n")

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
                    self._terminal.append_output("\n--- Session ended ---\n")
                log.info("Terminal session ended: %s", key)
                continue
            any_active = True

            data = tab.session.read()
            if data:
                try:
                    text = data.decode("utf-8", errors="replace")
                except Exception:
                    text = data.decode("latin-1")
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

                # If this is the currently visible session, show output
                if key == self._current_key():
                    self._terminal.append_output(text)
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
            existing = [
                self._session_combo.itemText(i)
                for i in range(self._session_combo.count())
            ]
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

    def _on_theme_changed(self, theme_name: str) -> None:
        """Live-swap the terminal's colour theme. Affects the visible
        widget for every tab (we only have one TerminalEmulator
        instance — output buffers are per-tab, the widget isn't)."""
        if hasattr(self, "_terminal"):
            self._terminal.set_theme(theme_name)
