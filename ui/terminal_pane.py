"""Inline terminal pane — embeds a shell session as a splitter pane."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from PyQt6 import sip
from PyQt6.QtCore import QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from ui.pane_drag import DraggableHeader, PaneDropZones
from ui.terminal_widget import (
    POLL_BUSY_INTERVAL_MS,
    POLL_INTERVAL_MS,
    LocalTerminalSession,
    SSHTerminalSession,
    TerminalEmulator,
    drain_output,
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
    #: "Bookmark this Terminal": the main window makes a terminal bookmark.
    bookmark_requested = pyqtSignal()
    #: A pane was dropped here: dragged pane id, this pane, zone
    #: ("left"/"right"/"top"/"bottom") - as FilePaneWidget.pane_drop_requested.
    pane_drop_requested = pyqtSignal(str, object, str)

    def __init__(
        self,
        transport: paramiko.Transport | None = None,
        label: str = "Local Shell",
        profile: ConnectionProfile | None = None,
        connection_manager: ConnectionManager | None = None,
        parent: QWidget | None = None,
        cwd: str | None = None,
    ):
        super().__init__(parent)
        self._transport = transport
        self._label_text = label
        self._profile = profile
        # Folder the shell starts in: a local shell is started there, a
        # remote one is sent a ``cd`` there. None: the application's folder
        # (local) or the login folder (remote).
        self._cwd = cwd
        self._connection_manager = connection_manager
        self._session: LocalTerminalSession | SSHTerminalSession | None = None
        # ConnectionManager references this pane holds; shutdown gives
        # back exactly these, never one it did not take.
        self._refs = 0
        #: The window the pin's key filter is installed on (see _pin_to).
        self._pin_window = None

        self._setup_ui()
        self._start_session()

    @property
    def session_label(self) -> str:
        return self._label_text

    @property
    def profile(self) -> ConnectionProfile | None:
        return self._profile

    @property
    def is_running(self) -> bool:
        """A shell session is open in this pane."""
        return self._session is not None and self._session.is_active

    @property
    def holds_session(self) -> bool:
        """This pane holds a reference on its profile's connection (given
        back by :meth:`shutdown`)."""
        return self._refs > 0

    @property
    def is_local(self) -> bool:
        """A local shell: neither a profile nor a transport behind it."""
        return self._profile is None and self._transport is None

    @property
    def start_directory(self) -> str | None:
        """The folder the shell was started in (local) or sent to (remote)."""
        return self._cwd

    def working_directory(self) -> str | None:
        """The folder a local shell is in now, when that is cheap to know:
        its /proc entry on Linux, else the folder it was started in. None
        for a remote shell, or when neither is known."""
        if not self.is_local:
            return None
        session = self._session
        pid = getattr(session, "_pid", None)
        if session is not None and session.is_active and pid:
            try:
                return os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                pass
        return self._cwd

    def _setup_ui(self) -> None:
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        # Pane drags only (ui/pane_drag.py): a text drop is the terminal
        # widget's, which takes it before it gets here.
        self.setAcceptDrops(True)
        self.setMinimumWidth(220)
        self.setMinimumHeight(150)

        # Border frame (like file panes)
        self._border_frame = QFrame(self)
        self._border_frame.setFrameShape(QFrame.Shape.Box)
        self._border_frame.setLineWidth(2)
        self._border_frame.setObjectName("axPaneBorder")
        self._border_frame.setStyleSheet(
            "QFrame#axPaneBorder { border: 2px solid #569cd6; border-radius: 4px; }"
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

        # The drag handle, as a file pane's header: drag it onto another
        # pane (or a workspace tab) to move this pane there.
        self._title = DraggableHeader(self)
        self._title.setText(f"\u2588 {self._label_text}")  # █ block char
        self._title.setCursor(Qt.CursorShape.OpenHandCursor)
        self._title.setToolTip(tr("Drag to move the pane"))
        font = QFont()
        font.setBold(True)
        self._title.setFont(font)
        header.addWidget(self._title)

        header.addStretch()

        self._btn_bookmark = QPushButton("\u2606")  # ☆, as the file pane's button
        self._btn_bookmark.setFixedSize(22, 22)
        self._btn_bookmark.setToolTip(tr("Bookmark this Terminal"))
        self._btn_bookmark.clicked.connect(lambda _checked=False: self.bookmark_requested.emit())
        header.addWidget(self._btn_bookmark)

        # Move to Workspace ▸ (ui/workspaces.py): filled by the window.
        self._btn_workspace = QPushButton("\u21c4")  # ⇄
        self._btn_workspace.setFixedSize(22, 22)
        self._btn_workspace.setToolTip(tr("Move to Workspace"))
        self._btn_workspace.setMenu(self.workspace_menu())
        header.addWidget(self._btn_workspace)

        self._btn_pin = QPushButton()
        from ui.icon_provider import icon

        self._btn_pin.setIcon(icon("pin"))
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
        self._terminal.grid_resized.connect(self._on_grid_resized)
        inner_layout.addWidget(self._terminal, stretch=1)

        # Drop zones for a dragged pane, drawn over the terminal
        self._pane_drop = PaneDropZones(self)
        self._drop_overlay = self._pane_drop.overlay

        # Poll timer
        self._read_timer = QTimer(self)
        self._read_timer.setInterval(POLL_INTERVAL_MS)
        self._read_timer.timeout.connect(self._poll_output)

    def _get_transport(self):
        """Get an active transport, reconnecting via ConnectionManager if needed."""
        if self._transport is not None and self._transport.is_active():
            self._hold_live_session()
            return self._transport

        if self._profile and self._connection_manager:
            session = self._connection_manager.get_session(self._profile)
            if session is not None:
                if not getattr(session, "transport", None):
                    # Live, but not a shell-capable backend: connecting
                    # again would only hand back the same session.
                    return None
                self._transport = session.transport
                self._hold_live_session()
                return self._transport

            # The session this pane held is gone; give its reference
            # back before connect() takes a new one.
            self._release_refs()
            try:
                log.info("Terminal pane reconnecting to %s", self._label_text)
                password = self._profile.get_password() or ""
                session = self._connection_manager.connect(
                    self._profile,
                    password=password,
                )
            except Exception as e:
                log.error("Terminal pane reconnect failed: %s", e)
                return None
            self._refs += 1
            transport = getattr(session, "transport", None)
            if transport:
                self._transport = transport
                return self._transport
            self._release_refs()

        return None

    def _hold_live_session(self) -> None:
        """Take one reference on the live session the profile holds, so
        it stays open while this pane uses its transport."""
        if self._refs or not (self._profile and self._connection_manager):
            return
        if self._connection_manager.acquire(self._profile):
            self._refs = 1

    def _release_refs(self) -> None:
        while self._refs > 0:
            self._refs -= 1
            try:
                self._connection_manager.release(self._profile)
            except Exception:  # noqa: BLE001 - a dead session must not block a close
                log.debug("Terminal pane: releasing %s failed", self._label_text, exc_info=True)

    def _start_session(self) -> None:
        if self._session and self._session.is_active:
            return

        try:
            if self._profile is not None or self._transport is not None:
                transport = self._get_transport()
                if transport is None:
                    self._terminal.message(
                        "\n--- No active connection. Connect to the host first. ---\n"
                    )
                    return
                # Honour per-profile history-suppression toggle so
                # users who want their own bash_history kept can opt
                # out. Default is the safe ``True``.
                suppress = True
                if self._profile is not None:
                    suppress = bool(
                        getattr(
                            self._profile,
                            "suppress_shell_history",
                            True,
                        )
                    )
                rows, cols = self._terminal.grid_size()
                self._session = SSHTerminalSession(
                    transport,
                    suppress_history=suppress,
                    initial_dir=self._cwd,
                    rows=rows,
                    cols=cols,
                )
            else:
                self._session = LocalTerminalSession(cwd=self._cwd)
            self._session.start()
            # The shell's idea of the screen is the widget's.
            self._session.resize(*self._terminal.grid_size())
            self._read_timer.start()
            log.info("Terminal pane started: %s", self._label_text)
        except Exception as e:
            log.error("Failed to start terminal pane: %s", e)
            self._terminal.message(f"\n--- Error: {e} ---\n")

    def _restart_session(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
        self._terminal.clear()
        self._start_session()

    def _pin_to(self, window) -> None:
        """Move the pin's key filter to *window* (None: no window at all).

        The filter sits on the window it was installed on, not on this
        pane: removing it from ``self.window()`` after the pane moved to
        another window (a detach, a move to another workspace) left it on
        the old one, whose keys then went on to this terminal for good."""
        old = self._pin_window
        if old is window:
            return
        self._pin_window = None
        if old is not None and not sip.isdeleted(old):
            old.removeEventFilter(self)
            try:
                old.destroyed.disconnect(self._pin_window_destroyed)
            except TypeError:  # not connected
                pass
        if window is not None:
            window.installEventFilter(self)
            window.destroyed.connect(self._pin_window_destroyed)
            self._pin_window = window

    def _pin_window_destroyed(self, *_args) -> None:
        # The window went (a detached workspace came back as a tab): the
        # pin goes on in the window this pane is in now - once the window
        # is fully gone, which may take this pane with it (application end).
        self._pin_window = None
        QTimer.singleShot(0, lambda: self._repin_after_window_loss())

    def _repin_after_window_loss(self) -> None:
        if sip.isdeleted(self) or not self.is_pinned or self._pin_window is not None:
            return
        self._pin_to(self.window())

    def _toggle_pin(self, pinned: bool) -> None:
        """Pin/unpin: when pinned, intercept ALL keyboard input for the terminal."""
        if pinned:
            self._pin_to(self.window())
            self._terminal.setFocus()
            self._border_frame.setStyleSheet(
                "QFrame#axPaneBorder { border: 2px solid #e5c07b; border-radius: 4px; }"
            )
            log.info("Terminal pane pinned: %s", self._label_text)
        else:
            self._pin_to(None)
            self._border_frame.setStyleSheet(
                "QFrame#axPaneBorder { border: 2px solid #569cd6; border-radius: 4px; }"
            )
            log.info("Terminal pane unpinned: %s", self._label_text)

    @property
    def is_pinned(self) -> bool:
        return self._btn_pin.isChecked()

    def eventFilter(self, obj, event: QEvent) -> bool:
        """When pinned, intercept key events and shortcut events from the whole window."""
        window = self.window()
        if obj is not window:
            # This pane moved to another window while pinned: the old
            # window's keys are its own again, the pin goes with the pane.
            # (Not while it is lifted out of a layout and is its own window.)
            if obj is self._pin_window and window is not self:
                self._pin_to(window if self.is_pinned else None)
            return False
        etype = event.type()

        if etype == QEvent.Type.ShortcutOverride:
            # Accept all shortcut overrides so Qt doesn't trigger app shortcuts
            key_event = event
            # Let Ctrl+Shift+P through to toggle pin off
            if (
                key_event.modifiers()
                == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
                and key_event.key() == Qt.Key.Key_P
            ):
                return False
            event.accept()
            return True

        if etype == QEvent.Type.KeyPress:
            key_event = event
            # Let Ctrl+Shift+P through to toggle pin off
            if (
                key_event.modifiers()
                == (Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
                and key_event.key() == Qt.Key.Key_P
            ):
                self._btn_pin.setChecked(False)
                return True
            # Forward everything else to the terminal emulator
            self._terminal.keyPressEvent(key_event)
            return True

        return False

    def workspace_menu(self):
        """The header button's menu: the window's other workspaces."""
        from PyQt6.QtWidgets import QMenu

        menu = getattr(self, "_workspace_menu", None)
        if menu is None:
            menu = QMenu(self)
            menu.aboutToShow.connect(self._fill_workspace_menu)
            self._workspace_menu = menu
        return menu

    def _fill_workspace_menu(self) -> None:
        filler = getattr(self.window(), "fill_move_menu_for", None)
        self._workspace_menu.clear()
        if filler is None:
            self._workspace_menu.addAction(tr("No workspaces here")).setEnabled(False)
            return
        filler(self, self._workspace_menu)

    def run_command(self, argv: list[str]) -> bool:
        """Type *argv*, quoted for a POSIX shell, into this local shell and
        press Enter - for interactive tools (TestDisk, PhotoRec). False for
        a remote shell or one that did not start."""
        import shlex

        if not self.is_local or not argv:
            return False
        self._start_session()
        if not (self._session and self._session.is_active):
            return False
        self._session.write((shlex.join(argv) + "\n").encode("utf-8"))
        return True

    def _on_input(self, data: bytes) -> None:
        if self._session and self._session.is_active:
            self._session.write(data)

    def _on_grid_resized(self, rows: int, cols: int) -> None:
        if self._session and self._session.is_active:
            self._session.resize(rows, cols)

    def _poll_output(self) -> None:
        if not self._session:
            return
        if not self._session.is_active:
            self._session.close()
            self._session = None
            self._read_timer.stop()
            self._terminal.message("\n--- Session ended ---\n")
            return

        # Everything the shell wrote, drawn once; a flood: again at once.
        taken, more = drain_output(
            self._session, lambda data: self._terminal.feed_bytes(data, render=False))
        if taken:
            self._terminal.render()
        self._read_timer.setInterval(POLL_BUSY_INTERVAL_MS if more else POLL_INTERVAL_MS)

    def shutdown(self) -> None:
        if self._btn_pin.isChecked():
            self._btn_pin.setChecked(False)
        self._read_timer.stop()
        if self._session:
            self._session.close()
            self._session = None
        self._release_refs()

    # -- a dragged pane dropped here ------------------------------------------------

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt override
        if not self._pane_drop.enter(event):
            event.ignore()

    def dragMoveEvent(self, event) -> None:  # noqa: N802 - Qt override
        if not self._pane_drop.move(event):
            event.ignore()

    def dragLeaveEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._pane_drop.leave()
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:  # noqa: N802 - Qt override
        pane_drop = self._pane_drop.drop(event)
        if pane_drop is None:
            event.ignore()
            return
        source_id, zone = pane_drop
        self.pane_drop_requested.emit(source_id, self, zone)
        log.info("Pane drop: zone=%s onto terminal %s", zone, self._label_text)

    def mousePressEvent(self, event):
        self.pane_focused.emit()
        super().mousePressEvent(event)

    def focusInEvent(self, event):
        self.pane_focused.emit()
        super().focusInEvent(event)
