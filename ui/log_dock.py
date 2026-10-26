"""Log dock widget — shows application log messages in real time."""

from __future__ import annotations

import logging
import weakref

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
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

from core.i18n import tr


class _LogSignalBridge(QObject):
    """Bridge to safely emit log records from any thread to the GUI thread."""

    log_record = pyqtSignal(str, int)  # formatted message, level number


class _QtLogHandler(logging.Handler):
    """Logging handler that emits records via a Qt signal."""

    def __init__(self, bridge: _LogSignalBridge):
        super().__init__()
        self._bridge_ref = weakref.ref(bridge)
        self._closed = False

    def emit(self, record: logging.LogRecord) -> None:
        if self._closed:
            return
        bridge = self._bridge_ref()
        if bridge is None:
            self._closed = True
            return
        try:
            msg = self.format(record)
            bridge.log_record.emit(msg, record.levelno)
        except RuntimeError as exc:
            if "has been deleted" in str(exc):
                self._closed = True
                return
            self.handleError(record)
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        self._closed = True
        super().close()


LEVEL_COLORS = {
    logging.DEBUG: "#888888",
    logging.INFO: "#d4d4d4",
    logging.WARNING: "#e5c07b",
    logging.ERROR: "#e06c75",
    logging.CRITICAL: "#ff0000",
}


class LogDock(QDockWidget):
    """Dockable panel showing application log messages."""

    # Fires when a log line lands AND passes the level filter - once for
    # the records of one burst, which are written together.
    # MainWindow uses this to colour the dock's tab label when the
    # dock isn't currently raised, so background activity doesn't
    # stay invisible.
    activity = pyqtSignal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__("Log", parent)
        self.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea
        )
        self._min_level = logging.DEBUG
        self._setup_ui()
        self._install_handler()

    def _setup_ui(self) -> None:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        # Toolbar
        toolbar = QHBoxLayout()

        toolbar.addWidget(QLabel("Level:"))

        self._level_combo = QComboBox()
        self._level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self._level_combo.setCurrentText("DEBUG")
        self._level_combo.currentTextChanged.connect(self._on_level_changed)
        toolbar.addWidget(self._level_combo)

        self._btn_clear = QPushButton("Clear")
        self._btn_clear.clicked.connect(self._clear)
        toolbar.addWidget(self._btn_clear)

        self._btn_scroll = QPushButton("Auto-Scroll")
        self._btn_scroll.setCheckable(True)
        self._btn_scroll.setChecked(True)
        self._btn_scroll.setToolTip(tr("Keep the newest line in view"))
        # Switched on: the newest line at once, not only with the next record.
        self._btn_scroll.toggled.connect(self._on_auto_scroll_toggled)
        toolbar.addWidget(self._btn_scroll)

        toolbar.addStretch()

        self._count_label = QLabel("0 messages")
        toolbar.addWidget(self._count_label)

        layout.addLayout(toolbar)

        # Log output
        self._log_view = QPlainTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setMaximumBlockCount(5000)
        font = QFont("Monospace", 9)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._log_view.setFont(font)
        self._log_view.setStyleSheet(
            "QPlainTextEdit { background-color: #1e1e1e; color: #d4d4d4; }"
        )
        layout.addWidget(self._log_view, stretch=1)
        # The scroll range also changes after a record: when the layout runs
        # late (a dock behind another tab), on a resize, when the line cap
        # drops the oldest lines. Auto-Scroll follows every one of them.
        self._log_view.verticalScrollBar().rangeChanged.connect(self._follow_newest)

        self.setWidget(container)
        self._msg_count = 0
        # Records wait here for the next turn of the event loop and are
        # written together (_write_pending): a burst is one edit per run of
        # lines of one level, not one edit, label and scroll per record.
        self._pending: list[tuple[str, int]] = []
        self._formats: dict[int, QTextCharFormat] = {}
        self._write_timer = QTimer(self)
        self._write_timer.setSingleShot(True)
        self._write_timer.setInterval(0)
        self._write_timer.timeout.connect(self._write_pending)

    def _install_handler(self) -> None:
        self._bridge = _LogSignalBridge(self)
        self._bridge.log_record.connect(self._on_log_record)

        self._handler = _QtLogHandler(self._bridge)
        self._handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        self._handler.setLevel(logging.DEBUG)
        self._handler._axross_log_dock = True  # type: ignore[attr-defined]
        self.destroyed.connect(lambda _obj=None: self.shutdown())

        # Attach to root logger to capture all messages
        root = logging.getLogger()
        for handler in list(root.handlers):
            if getattr(handler, "_axross_log_dock", False):
                root.removeHandler(handler)
        root.addHandler(self._handler)

    def _on_log_record(self, message: str, level: int) -> None:
        if level < self._min_level:
            return
        self._pending.append((message, level))
        if not self._write_timer.isActive():
            self._write_timer.start()
            self.activity.emit()  # once per burst, as its first record arrives

    def _format(self, level: int) -> QTextCharFormat:
        fmt = self._formats.get(level)
        if fmt is None:
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(LEVEL_COLORS.get(level, "#d4d4d4")))
            self._formats[level] = fmt
        return fmt

    def _write_pending(self) -> None:
        """Write the records collected since the last turn of the event loop."""
        pending, self._pending = self._pending, []
        if not pending:
            return
        self._msg_count += len(pending)
        # The view keeps its newest lines only: older records of the burst
        # would be written just to be dropped again.
        cap = self._log_view.maximumBlockCount()
        if cap > 0:
            pending = pending[-cap:]
        # A cursor of its own: the view's cursor is where the user clicked
        # or marked text, and must stay there.
        cursor = QTextCursor(self._log_view.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.beginEditBlock()
        try:
            run: list[str] = []
            run_level = pending[0][1]
            for message, level in pending:
                if level != run_level:
                    cursor.insertText("".join(run), self._format(run_level))
                    run, run_level = [], level
                run.append(message + "\n")
            cursor.insertText("".join(run), self._format(run_level))
        finally:
            cursor.endEditBlock()

        self._count_label.setText(f"{self._msg_count} messages")

        self._follow_newest()

    def _follow_newest(self, *_range) -> None:
        """With Auto-Scroll on, show the newest line.

        By the scroll bar, not ``ensureCursorVisible()``: that shows the
        view's text cursor, which a click into the log moves - Auto-Scroll
        then pinned the view to the clicked line (reported: "auto scroll
        ... scheint ... nicht zu funktionieren")."""
        if self._btn_scroll.isChecked():
            bar = self._log_view.verticalScrollBar()
            bar.setValue(bar.maximum())

    def _on_auto_scroll_toggled(self, on: bool) -> None:
        if on:
            self._follow_newest()

    def _on_level_changed(self, text: str) -> None:
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
        }
        self._min_level = level_map.get(text, logging.DEBUG)

    def _clear(self) -> None:
        self._pending.clear()  # arrived before the click: cleared with the rest
        self._log_view.clear()
        self._msg_count = 0
        self._count_label.setText("0 messages")

    def shutdown(self) -> None:
        root = logging.getLogger()
        if getattr(self, "_handler", None) is not None:
            if self._handler in root.handlers:
                root.removeHandler(self._handler)
            self._handler.close()
            self._handler = None
