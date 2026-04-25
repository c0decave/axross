"""Log dock widget — shows application log messages in real time."""
from __future__ import annotations

import logging

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QTextCharFormat
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


class _LogSignalBridge(QObject):
    """Bridge to safely emit log records from any thread to the GUI thread."""
    log_record = pyqtSignal(str, int)  # formatted message, level number


class _QtLogHandler(logging.Handler):
    """Logging handler that emits records via a Qt signal."""

    def __init__(self, bridge: _LogSignalBridge):
        super().__init__()
        self._bridge = bridge

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self._bridge.log_record.emit(msg, record.levelno)
        except Exception:
            self.handleError(record)


LEVEL_COLORS = {
    logging.DEBUG: "#888888",
    logging.INFO: "#d4d4d4",
    logging.WARNING: "#e5c07b",
    logging.ERROR: "#e06c75",
    logging.CRITICAL: "#ff0000",
}


class LogDock(QDockWidget):
    """Dockable panel showing application log messages."""

    # Fires every time a log line lands AND passes the level filter.
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

        self.setWidget(container)
        self._msg_count = 0

    def _install_handler(self) -> None:
        self._bridge = _LogSignalBridge(self)
        self._bridge.log_record.connect(self._on_log_record)

        self._handler = _QtLogHandler(self._bridge)
        self._handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)-7s] %(name)s: %(message)s", datefmt="%H:%M:%S")
        )
        self._handler.setLevel(logging.DEBUG)
        self._handler._axross_log_dock = True  # type: ignore[attr-defined]

        # Attach to root logger to capture all messages
        root = logging.getLogger()
        for handler in list(root.handlers):
            if getattr(handler, "_axross_log_dock", False):
                root.removeHandler(handler)
        root.addHandler(self._handler)

    def _on_log_record(self, message: str, level: int) -> None:
        if level < self._min_level:
            return

        color = LEVEL_COLORS.get(level, "#d4d4d4")

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))

        cursor = self._log_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(message + "\n", fmt)

        self._msg_count += 1
        self._count_label.setText(f"{self._msg_count} messages")

        if self._btn_scroll.isChecked():
            self._log_view.ensureCursorVisible()

        self.activity.emit()

    def _on_level_changed(self, text: str) -> None:
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
        }
        self._min_level = level_map.get(text, logging.DEBUG)

    def _clear(self) -> None:
        self._log_view.clear()
        self._msg_count = 0
        self._count_label.setText("0 messages")

    def shutdown(self) -> None:
        root = logging.getLogger()
        if getattr(self, "_handler", None) is not None:
            root.removeHandler(self._handler)
