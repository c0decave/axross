"""Hex editor dialog for viewing/editing binary files."""
from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QRect
from PyQt6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QKeyEvent,
    QKeySequence,
    QPainter,
    QPaintEvent,
    QWheelEvent,
)
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollBar,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)

MAX_HEX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit for hex editor
BYTES_PER_LINE = 16


class HexWidget(QWidget):
    """Custom widget that renders a hex dump with offset | hex | ASCII columns.

    Supports editing individual bytes, cursor navigation, and selection.
    """

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        self._data = bytearray()
        self._cursor_pos = 0  # Byte offset of cursor
        self._cursor_nibble = 0  # 0 = high nibble, 1 = low nibble
        self._selection_start = -1
        self._selection_end = -1
        self._modified_offsets: set[int] = set()
        self._scroll_offset = 0  # First visible line index
        self._editing_hex = True  # True = hex column, False = ASCII column

        # Font setup
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self._fm = QFontMetrics(font)
        self._char_w = self._fm.horizontalAdvance("0")
        self._char_h = self._fm.height()

        # Colors
        self._bg_color = QColor("#1e1e1e")
        self._text_color = QColor("#d4d4d4")
        self._offset_color = QColor("#569cd6")
        self._ascii_color = QColor("#ce9178")
        self._modified_color = QColor("#e06c75")
        self._cursor_color = QColor("#264f78")
        self._selection_color = QColor("#264f78")
        self._separator_color = QColor("#444444")

        # Layout metrics
        self._offset_chars = 10  # "00000000: "
        self._hex_start = self._offset_chars * self._char_w
        self._hex_chars = BYTES_PER_LINE * 3  # "XX " per byte
        self._ascii_start = self._hex_start + self._hex_chars * self._char_w + self._char_w
        self._total_width = self._ascii_start + BYTES_PER_LINE * self._char_w + self._char_w

        self.setMinimumWidth(self._total_width)
        self.setMinimumHeight(self._char_h * 10)

        # Scrollbar will be set externally
        self._scrollbar: QScrollBar | None = None

    def set_scrollbar(self, scrollbar: QScrollBar) -> None:
        self._scrollbar = scrollbar
        scrollbar.valueChanged.connect(self._on_scroll)
        self._update_scrollbar()

    def set_data(self, data: bytes) -> None:
        self._data = bytearray(data)
        self._cursor_pos = 0
        self._cursor_nibble = 0
        self._selection_start = -1
        self._selection_end = -1
        self._modified_offsets.clear()
        self._scroll_offset = 0
        self._update_scrollbar()
        self.update()

    def get_data(self) -> bytes:
        return bytes(self._data)

    @property
    def is_modified(self) -> bool:
        return len(self._modified_offsets) > 0

    def _visible_lines(self) -> int:
        return max(1, self.height() // self._char_h)

    def _total_lines(self) -> int:
        return max(1, (len(self._data) + BYTES_PER_LINE - 1) // BYTES_PER_LINE)

    def _update_scrollbar(self) -> None:
        if self._scrollbar:
            total = self._total_lines()
            visible = self._visible_lines()
            self._scrollbar.setRange(0, max(0, total - visible))
            self._scrollbar.setPageStep(visible)

    def _on_scroll(self, value: int) -> None:
        self._scroll_offset = value
        self.update()

    def _ensure_cursor_visible(self) -> None:
        line = self._cursor_pos // BYTES_PER_LINE
        visible = self._visible_lines()
        if line < self._scroll_offset:
            self._scroll_offset = line
        elif line >= self._scroll_offset + visible:
            self._scroll_offset = line - visible + 1
        if self._scrollbar:
            self._scrollbar.setValue(self._scroll_offset)
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), self._bg_color)
        painter.setFont(self.font())

        visible = self._visible_lines()
        start_line = self._scroll_offset
        end_line = min(start_line + visible + 1, self._total_lines())

        for line_idx in range(start_line, end_line):
            y = (line_idx - start_line) * self._char_h
            offset = line_idx * BYTES_PER_LINE
            line_bytes = self._data[offset:offset + BYTES_PER_LINE]

            # Offset column
            painter.setPen(self._offset_color)
            offset_text = f"{offset:08X}: "
            painter.drawText(0, y + self._fm.ascent(), offset_text)

            # Separator line
            painter.setPen(self._separator_color)
            sep_x = int(self._hex_start - self._char_w * 0.5)
            painter.drawLine(sep_x, y, sep_x, y + self._char_h)
            sep_x2 = int(self._ascii_start - self._char_w * 0.5)
            painter.drawLine(sep_x2, y, sep_x2, y + self._char_h)

            # Hex + ASCII columns
            for i, byte in enumerate(line_bytes):
                byte_offset = offset + i
                is_cursor = byte_offset == self._cursor_pos
                is_selected = (
                    self._selection_start >= 0
                    and min(self._selection_start, self._selection_end)
                    <= byte_offset
                    <= max(self._selection_start, self._selection_end)
                )
                is_modified = byte_offset in self._modified_offsets

                # Hex position
                hex_x = int(self._hex_start + i * 3 * self._char_w)
                hex_text = f"{byte:02X}"

                # Draw cursor/selection background in hex
                if is_cursor and self._editing_hex:
                    painter.fillRect(
                        QRect(hex_x, y, int(self._char_w * 2), self._char_h),
                        self._cursor_color,
                    )
                elif is_selected:
                    painter.fillRect(
                        QRect(hex_x, y, int(self._char_w * 2), self._char_h),
                        self._selection_color,
                    )

                painter.setPen(self._modified_color if is_modified else self._text_color)
                painter.drawText(hex_x, y + self._fm.ascent(), hex_text)

                # ASCII position
                ascii_x = int(self._ascii_start + i * self._char_w)
                ascii_char = chr(byte) if 32 <= byte < 127 else "."

                # Draw cursor/selection background in ASCII
                if is_cursor and not self._editing_hex:
                    painter.fillRect(
                        QRect(ascii_x, y, self._char_w, self._char_h),
                        self._cursor_color,
                    )
                elif is_selected:
                    painter.fillRect(
                        QRect(ascii_x, y, self._char_w, self._char_h),
                        self._selection_color,
                    )

                painter.setPen(self._modified_color if is_modified else self._ascii_color)
                painter.drawText(ascii_x, y + self._fm.ascent(), ascii_char)

        painter.end()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        mods = event.modifiers()
        text = event.text()

        # Tab — switch between hex and ASCII editing
        if key == Qt.Key.Key_Tab:
            self._editing_hex = not self._editing_hex
            self._cursor_nibble = 0
            self.update()
            return

        # Navigation
        if key == Qt.Key.Key_Left:
            if self._editing_hex:
                if self._cursor_nibble == 1:
                    self._cursor_nibble = 0
                elif self._cursor_pos > 0:
                    self._cursor_pos -= 1
                    self._cursor_nibble = 1
            else:
                if self._cursor_pos > 0:
                    self._cursor_pos -= 1
            self._ensure_cursor_visible()
            return

        if key == Qt.Key.Key_Right:
            if self._editing_hex:
                if self._cursor_nibble == 0:
                    self._cursor_nibble = 1
                elif self._cursor_pos < len(self._data) - 1:
                    self._cursor_pos += 1
                    self._cursor_nibble = 0
            else:
                if self._cursor_pos < len(self._data) - 1:
                    self._cursor_pos += 1
            self._ensure_cursor_visible()
            return

        if key == Qt.Key.Key_Up:
            if self._cursor_pos >= BYTES_PER_LINE:
                self._cursor_pos -= BYTES_PER_LINE
            self._ensure_cursor_visible()
            return

        if key == Qt.Key.Key_Down:
            if self._cursor_pos + BYTES_PER_LINE < len(self._data):
                self._cursor_pos += BYTES_PER_LINE
            self._ensure_cursor_visible()
            return

        if key == Qt.Key.Key_Home:
            if mods & Qt.KeyboardModifier.ControlModifier:
                self._cursor_pos = 0
            else:
                self._cursor_pos = (self._cursor_pos // BYTES_PER_LINE) * BYTES_PER_LINE
            self._cursor_nibble = 0
            self._ensure_cursor_visible()
            return

        if key == Qt.Key.Key_End:
            if mods & Qt.KeyboardModifier.ControlModifier:
                self._cursor_pos = len(self._data) - 1 if self._data else 0
            else:
                if not self._data:
                    self._cursor_pos = 0
                else:
                    line_start = (self._cursor_pos // BYTES_PER_LINE) * BYTES_PER_LINE
                    self._cursor_pos = min(line_start + BYTES_PER_LINE - 1, len(self._data) - 1)
            self._cursor_nibble = 0
            self._ensure_cursor_visible()
            return

        if key in (Qt.Key.Key_PageUp, Qt.Key.Key_PageDown):
            delta = self._visible_lines() * BYTES_PER_LINE
            if key == Qt.Key.Key_PageUp:
                self._cursor_pos = max(0, self._cursor_pos - delta)
            else:
                self._cursor_pos = min(len(self._data) - 1, self._cursor_pos + delta)
            self._ensure_cursor_visible()
            return

        # Editing in hex mode
        if self._editing_hex and text and len(text) == 1:
            if not self._data:
                return
            ch = text.upper()
            if ch in "0123456789ABCDEF":
                nibble_val = int(ch, 16)
                old_byte = self._data[self._cursor_pos]
                if self._cursor_nibble == 0:
                    new_byte = (nibble_val << 4) | (old_byte & 0x0F)
                    self._data[self._cursor_pos] = new_byte
                    self._modified_offsets.add(self._cursor_pos)
                    self._cursor_nibble = 1
                else:
                    new_byte = (old_byte & 0xF0) | nibble_val
                    self._data[self._cursor_pos] = new_byte
                    self._modified_offsets.add(self._cursor_pos)
                    self._cursor_nibble = 0
                    if self._cursor_pos < len(self._data) - 1:
                        self._cursor_pos += 1
                self.update()
                return

        # Editing in ASCII mode
        if not self._editing_hex and text and len(text) == 1:
            if not self._data:
                return
            byte_val = ord(text)
            if 0 <= byte_val < 256:
                self._data[self._cursor_pos] = byte_val
                self._modified_offsets.add(self._cursor_pos)
                if self._cursor_pos < len(self._data) - 1:
                    self._cursor_pos += 1
                self.update()
                return

        super().keyPressEvent(event)

    def wheelEvent(self, event: QWheelEvent) -> None:
        delta = event.angleDelta().y()
        lines = -delta // 40 if delta else 0
        new_offset = max(0, min(self._scroll_offset + lines, self._total_lines() - self._visible_lines()))
        self._scroll_offset = new_offset
        if self._scrollbar:
            self._scrollbar.setValue(new_offset)
        self.update()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            pos = self._pos_to_offset(event.position().x(), event.position().y())
            if pos >= 0:
                self._cursor_pos = pos
                self._cursor_nibble = 0
                self.update()

    def _pos_to_offset(self, x: float, y: float) -> int:
        """Convert mouse coordinates to byte offset."""
        line = int(y / self._char_h) + self._scroll_offset
        if line < 0 or line >= self._total_lines():
            return -1

        offset = line * BYTES_PER_LINE

        # Check if click is in hex area
        if self._hex_start <= x < self._ascii_start - self._char_w:
            col = int((x - self._hex_start) / (3 * self._char_w))
            col = max(0, min(col, BYTES_PER_LINE - 1))
            self._editing_hex = True
            return min(offset + col, len(self._data) - 1)

        # Check if click is in ASCII area
        if x >= self._ascii_start:
            col = int((x - self._ascii_start) / self._char_w)
            col = max(0, min(col, BYTES_PER_LINE - 1))
            self._editing_hex = False
            return min(offset + col, len(self._data) - 1)

        return -1

    def goto_offset(self, offset: int) -> None:
        """Jump cursor to a specific byte offset."""
        if 0 <= offset < len(self._data):
            self._cursor_pos = offset
            self._cursor_nibble = 0
            self._ensure_cursor_visible()

    def search_bytes(self, pattern: bytes) -> int:
        """Search for a byte pattern starting from cursor. Returns offset or -1."""
        start = self._cursor_pos + 1
        idx = self._data.find(pattern, start)
        if idx == -1 and start > 0:
            idx = self._data.find(pattern, 0, start)
        if idx >= 0:
            self._cursor_pos = idx
            self._ensure_cursor_visible()
        return idx

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_scrollbar()


class HexEditorDialog(QDialog):
    """Hex editor dialog for viewing/editing binary files via any FileBackend."""

    def __init__(
        self,
        backend: FileBackend,
        file_path: str,
        parent: QWidget | None = None,
        read_only: bool = False,
    ):
        super().__init__(parent)
        self._backend = backend
        self._file_path = file_path
        self._original_data = b""
        self._read_only = read_only

        filename = file_path.rsplit(backend.separator(), 1)[-1]
        prefix = "View Hex" if read_only else "Hex"
        self.setWindowTitle(f"{prefix}: {filename} [{backend.name}]")
        self.resize(900, 600)

        self._setup_ui()
        self._load_file()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Info bar
        info = QHBoxLayout()
        self._path_label = QLabel(self._file_path)
        self._path_label.setStyleSheet("color: #666;")
        info.addWidget(self._path_label)

        self._size_label = QLabel()
        self._size_label.setStyleSheet("color: #666;")
        info.addStretch()
        info.addWidget(self._size_label)
        layout.addLayout(info)

        # Hex view + scrollbar
        hex_layout = QHBoxLayout()
        self._hex_widget = HexWidget()
        hex_layout.addWidget(self._hex_widget, stretch=1)

        self._scrollbar = QScrollBar(Qt.Orientation.Vertical)
        self._hex_widget.set_scrollbar(self._scrollbar)
        hex_layout.addWidget(self._scrollbar)

        layout.addLayout(hex_layout, stretch=1)

        # Search / goto bar
        search_layout = QHBoxLayout()

        search_layout.addWidget(QLabel("Search:"))
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Hex bytes (e.g. FF 00 AB) or text: hello")
        self._search_edit.returnPressed.connect(self._on_search)
        search_layout.addWidget(self._search_edit)

        search_btn = QPushButton("Find Next")
        search_btn.clicked.connect(self._on_search)
        search_layout.addWidget(search_btn)

        search_layout.addWidget(QLabel("Goto:"))
        self._goto_edit = QLineEdit()
        self._goto_edit.setPlaceholderText("Hex offset (e.g. 1A0)")
        self._goto_edit.setFixedWidth(120)
        self._goto_edit.returnPressed.connect(self._on_goto)
        search_layout.addWidget(self._goto_edit)

        goto_btn = QPushButton("Go")
        goto_btn.clicked.connect(self._on_goto)
        search_layout.addWidget(goto_btn)

        layout.addLayout(search_layout)

        # Status bar
        status = QHBoxLayout()
        self._status_label = QLabel()
        status.addWidget(self._status_label)

        self._offset_label = QLabel("Offset: 0x00000000")
        self._offset_label.setStyleSheet("color: #666;")
        status.addStretch()
        status.addWidget(self._offset_label)

        self._mode_label = QLabel("[HEX]")
        self._mode_label.setStyleSheet("color: #666;")
        status.addWidget(self._mode_label)
        layout.addLayout(status)

        # Buttons
        btn_layout = QHBoxLayout()

        self._btn_save = QPushButton("Save")
        self._btn_save.setShortcut(QKeySequence("Ctrl+S"))
        self._btn_save.setEnabled(False)
        self._btn_save.clicked.connect(self._save_file)
        if self._read_only:
            self._btn_save.hide()
        btn_layout.addWidget(self._btn_save)

        self._btn_reload = QPushButton("Reload")
        self._btn_reload.clicked.connect(self._reload_file)
        btn_layout.addWidget(self._btn_reload)

        btn_layout.addStretch()

        self._btn_close = QPushButton("Close")
        self._btn_close.clicked.connect(self._on_close)
        btn_layout.addWidget(self._btn_close)

        layout.addLayout(btn_layout)

        # Update status on cursor move
        self._hex_widget.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:
        if watched is self._hex_widget:
            if event.type() in (
                event.Type.KeyPress,
                event.Type.MouseButtonPress,
                event.Type.KeyRelease,
            ):
                self._update_status()
        return super().eventFilter(watched, event)

    def _update_status(self) -> None:
        pos = self._hex_widget._cursor_pos
        self._offset_label.setText(f"Offset: 0x{pos:08X} ({pos})")
        self._mode_label.setText("[HEX]" if self._hex_widget._editing_hex else "[ASCII]")

        if self._hex_widget.is_modified:
            self._btn_save.setEnabled(True)
            self._status_label.setText(
                f"Modified ({len(self._hex_widget._modified_offsets)} bytes changed)"
            )
        else:
            self._status_label.setText("Loaded")

    def _load_file(self) -> None:
        try:
            stat = self._backend.stat(self._file_path)
            if stat.size > MAX_HEX_FILE_SIZE:
                QMessageBox.warning(
                    self,
                    "File Too Large",
                    f"File is {stat.size_human} — only files under 10 MB supported in hex editor.",
                )
                self.reject()
                return

            self._size_label.setText(f"{stat.size:,} bytes")

            with self._backend.open_read(self._file_path) as f:
                self._original_data = f.read()

            self._hex_widget.set_data(self._original_data)
            self._status_label.setText("Loaded")
            self._btn_save.setEnabled(False)
            log.debug("Hex loaded: %s (%d bytes)", self._file_path, len(self._original_data))

        except OSError as e:
            log.error("Cannot read file %s: %s", self._file_path, e)
            QMessageBox.critical(self, "Error", f"Cannot read file:\n{e}")
            self.reject()

    def _reload_file(self) -> None:
        if self._hex_widget.is_modified:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "Reload and discard changes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        self._load_file()

    def _save_file(self) -> None:
        try:
            # Conflict check
            try:
                with self._backend.open_read(self._file_path) as f:
                    current = f.read()
                if current != self._original_data:
                    reply = QMessageBox.question(
                        self,
                        "File Changed",
                        "File was modified on server. Overwrite?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    )
                    if reply != QMessageBox.StandardButton.Yes:
                        return
            except OSError:
                pass

            content = self._hex_widget.get_data()

            # Atomic save via temp file
            parent = self._backend.parent(self._file_path)
            filename = self._file_path.rsplit(self._backend.separator(), 1)[-1]
            temp_name = f".{filename}.hex-{uuid.uuid4().hex[:8]}.tmp"
            temp_path = self._backend.join(parent, temp_name)

            try:
                with self._backend.open_write(temp_path) as f:
                    f.write(content)
                try:
                    self._backend.rename(temp_path, self._file_path)
                except OSError:
                    if self._backend.exists(self._file_path):
                        self._backend.remove(self._file_path)
                        self._backend.rename(temp_path, self._file_path)
                    else:
                        raise
            finally:
                try:
                    if self._backend.exists(temp_path):
                        self._backend.remove(temp_path)
                except OSError:
                    pass

            self._original_data = content
            self._hex_widget._modified_offsets.clear()
            self._btn_save.setEnabled(False)
            self._status_label.setText("Saved")
            log.info("Hex saved: %s (%d bytes)", self._file_path, len(content))

        except OSError as e:
            log.error("Cannot save file %s: %s", self._file_path, e)
            QMessageBox.critical(self, "Save Error", f"Cannot save:\n{e}")

    def _on_search(self) -> None:
        query = self._search_edit.text().strip()
        if not query:
            return

        # Try as text: prefix
        if query.lower().startswith("text:"):
            text_query = query[5:].strip()
            if text_query:
                pattern = text_query.encode("utf-8")
            else:
                return
        else:
            # Parse as hex bytes
            try:
                hex_str = query.replace(" ", "").replace(",", "")
                pattern = bytes.fromhex(hex_str)
            except ValueError:
                # Fallback: treat as text search
                pattern = query.encode("utf-8")

        idx = self._hex_widget.search_bytes(pattern)
        if idx >= 0:
            self._status_label.setText(f"Found at offset 0x{idx:08X}")
        else:
            self._status_label.setText("Not found")

    def _on_goto(self) -> None:
        text = self._goto_edit.text().strip()
        if not text:
            return
        try:
            if text.lower().startswith("0x"):
                offset = int(text, 16)
            else:
                offset = int(text, 16)
            self._hex_widget.goto_offset(offset)
            self._update_status()
        except ValueError:
            self._status_label.setText("Invalid offset")

    def _on_close(self) -> None:
        if self._hex_widget.is_modified:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "Discard changes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        self.accept()

    def closeEvent(self, event) -> None:
        if self._hex_widget.is_modified:
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "Discard changes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        event.accept()
