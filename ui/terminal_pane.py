"""Inline terminal pane — embeds a shell session as a splitter pane."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QKeyEvent, QShortcutEvent
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ui.terminal_widget import (
    LocalTerminalSession,
    SSHTerminalSession,
    TerminalEmulator,
)

if TYPE_CHECKING:
    import paramiko
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile

log = logging.getLogger(__name__)


class TerminalPaneWidget(QWidget):
    """Terminal session embedded as a pane in the main splitter."""

    close_requested = pyqtSignal()
    pane_focused = pyqtSignal()

    def __init__(
        self,
        transport: paramiko.Transport | None = None,
        label: str = "Local Shell",
        profile: ConnectionProfile | None = None,
        connection_manager: ConnectionManager | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._transport = transport
        self._label_text = label
        self._profile = profile
        self._connection_manager = connection_manager
        self._session: LocalTerminalSession | SSHTerminalSession | None = None

        self._setup_ui()
        self._start_session()

    @property
    def session_label(self) -> str:
        return self._label_text

    def _setup_ui(self) -> None:
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMinimumWidth(220)
        self.setMinimumHeight(150)

        # Border frame (like file panes)
        self._border_frame = QFrame(self)
        self._border_frame.setFrameShape(QFrame.Shape.Box)
        self._border_frame.setLineWidth(2)
        self._border_frame.setStyleSheet(
            "QFrame { border: 2px solid #569cd6; border-radius: 4px; }"
        )

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)
        outer_layout.addWidget(self._border_frame)

        inner_layout = QVBoxLayout(self._border_frame)
        inner_layout.setContentsMargins(2, 2, 2, 2)
        inner_layout.setSpacing(2)

        # Header bar
        header = QHBoxLayout()
        header.setSpacing(4)

        self._title = QLabel(f"\u2588 {self._label_text}")  # █ block char
        font = QFont()
        font.setBold(True)
        self._title.setFont(font)
        header.addWidget(self._title)

        header.addStretch()

        self._btn_pin = QPushButton("\U0001f4cc")  # 📌
        self._btn_pin.setFixedSize(22, 22)
        self._btn_pin.setCheckable(True)
        self._btn_pin.setToolTip("Pin: capture all keyboard input (Ctrl+Shift+P)")
        self._btn_pin.toggled.connect(self._toggle_pin)
        header.addWidget(self._btn_pin)

        btn_restart = QPushButton("Restart")
        btn_restart.setFixedHeight(22)
        btn_restart.clicked.connect(self._restart_session)
        header.addWidget(btn_restart)

        btn_close = QPushButton("\u2715")  # ✕
        btn_close.setFixedSize(22, 22)
        btn_close.setToolTip("Close terminal pane")
        btn_close.clicked.connect(self.close_requested.emit)
        header.addWidget(btn_close)

        inner_layout.addLayout(header)

        # Terminal emulator
        # Honour per-profile terminal_theme (set on ConnectionProfile
        # under the SCRIPTING-DOC-PANE feature). Empty string falls
        # back to the dock default; TerminalEmulator clamps unknown
        # names to "Dark".
        theme_name = ""
        if self._profile is not None:
            theme_name = getattr(self._profile, "terminal_theme", "") or ""
        from ui.terminal_widget import DEFAULT_TERMINAL_THEME
        self._terminal = TerminalEmulator(
            theme=theme_name or DEFAULT_TERMINAL_THEME,
        )
        self._terminal.data_ready.connect(self._on_input)
        inner_layout.addWidget(self._terminal, stretch=1)

        # Poll timer
        self._read_timer = QTimer(self)
        self._read_timer.setInterval(50)
        self._read_timer.timeout.connect(self._poll_output)

    def _get_transport(self):
        """Get an active transport, reconnecting via ConnectionManager if needed."""
        if self._transport is not None and self._transport.is_active():
            return self._transport

        if self._profile and self._connection_manager:
            session = self._connection_manager.get_session(self._profile)
            if session and hasattr(session, "transport") and session.transport:
                self._transport = session.transport
                return self._transport

            # Try to reconnect
            try:
                log.info("Terminal pane reconnecting to %s", self._label_text)
                password = self._profile.get_password() or ""
                session = self._connection_manager.connect(
                    self._profile, password=password,
                )
                if hasattr(session, "transport"):
                    self._transport = session.transport
                    return self._transport
            except Exception as e:
                log.error("Terminal pane reconnect failed: %s", e)

        return None

    def _start_session(self) -> None:
        if self._session and self._session.is_active:
            return

        try:
            if self._profile is not None or self._transport is not None:
                transport = self._get_transport()
                if transport is None:
                    self._terminal.append_output(
                        "\n--- No active connection. Connect to the host first. ---\n"
                    )
                    return
                # Honour per-profile history-suppression toggle so
                # users who want their own bash_history kept can opt
                # out. Default is the safe ``True``.
                suppress = True
                if self._profile is not None:
                    suppress = bool(getattr(
                        self._profile, "suppress_shell_history", True,
                    ))
                self._session = SSHTerminalSession(
                    transport, suppress_history=suppress,
                )
            else:
                self._session = LocalTerminalSession()
            self._session.start()
            self._read_timer.start()
            log.info("Terminal pane started: %s", self._label_text)
        except Exception as e:
            log.error("Failed to start terminal pane: %s", e)
            self._terminal.append_output(f"\n--- Error: {e} ---\n")

    def _restart_session(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
        self._terminal.clear()
        self._start_session()

    def _toggle_pin(self, pinned: bool) -> None:
        """Pin/unpin: when pinned, intercept ALL keyboard input for the terminal."""
        window = self.window()
        if pinned:
            window.installEventFilter(self)
            self._terminal.setFocus()
            self._border_frame.setStyleSheet(
                "QFrame { border: 2px solid #e5c07b; border-radius: 4px; }"
            )
            log.info("Terminal pane pinned: %s", self._label_text)
        else:
            window.removeEventFilter(self)
            self._border_frame.setStyleSheet(
                "QFrame { border: 2px solid #569cd6; border-radius: 4px; }"
            )
            log.info("Terminal pane unpinned: %s", self._label_text)

    @property
    def is_pinned(self) -> bool:
        return self._btn_pin.isChecked()

    def eventFilter(self, obj, event: QEvent) -> bool:
        """When pinned, intercept key events and shortcut events from the whole window."""
        etype = event.type()

        if etype == QEvent.Type.ShortcutOverride:
            # Accept all shortcut overrides so Qt doesn't trigger app shortcuts
            key_event = event
            # Let Ctrl+Shift+P through to toggle pin off
            if (key_event.modifiers() == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
                    and key_event.key() == Qt.Key.Key_P):
                return False
            event.accept()
            return True

        if etype == QEvent.Type.KeyPress:
            key_event = event
            # Let Ctrl+Shift+P through to toggle pin off
            if (key_event.modifiers() == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
                    and key_event.key() == Qt.Key.Key_P):
                self._btn_pin.setChecked(False)
                return True
            # Forward everything else to the terminal emulator
            self._terminal.keyPressEvent(key_event)
            return True

        return False

    def _on_input(self, data: bytes) -> None:
        if self._session and self._session.is_active:
            self._session.write(data)

    def _poll_output(self) -> None:
        if not self._session:
            return
        if not self._session.is_active:
            self._session.close()
            self._session = None
            self._read_timer.stop()
            self._terminal.append_output("\n--- Session ended ---\n")
            return

        data = self._session.read()
        if data:
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = data.decode("latin-1")
            self._terminal.append_output(text)

    def shutdown(self) -> None:
        if self._btn_pin.isChecked():
            self._btn_pin.setChecked(False)
        self._read_timer.stop()
        if self._session:
            self._session.close()
            self._session = None
        # Release connection ref if we hold one
        if self._profile and self._connection_manager:
            self._connection_manager.release(self._profile)

    def mousePressEvent(self, event):
        self.pane_focused.emit()
        super().mousePressEvent(event)

    def focusInEvent(self, event):
        self.pane_focused.emit()
        super().focusInEvent(event)
