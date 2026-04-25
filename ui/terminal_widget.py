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


class TerminalEmulator(QPlainTextEdit):
    """Simple terminal emulator widget using QPlainTextEdit.

    Handles basic ANSI escape sequences for color and cursor control.
    """

    data_ready = pyqtSignal(bytes)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setReadOnly(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setUndoRedoEnabled(False)

        # Styling
        self.setStyleSheet(
            "QPlainTextEdit { background-color: #1e1e1e; color: #d4d4d4; "
            "selection-background-color: #264f78; }"
        )

        self._input_start = 0  # Position where user input begins

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

    def __init__(self, transport: paramiko.Transport):
        self._transport = transport
        self._channel: paramiko.Channel | None = None
        self._running = False

    @property
    def is_active(self) -> bool:
        return self._running and self._channel is not None and not self._channel.closed

    def start(self) -> None:
        self._channel = self._transport.open_session()
        self._channel.get_pty(term="xterm", width=120, height=40)
        self._channel.invoke_shell()
        self._running = True
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
