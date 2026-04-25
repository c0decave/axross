"""Text editor dialog for viewing/editing remote and local files."""
from __future__ import annotations

import logging
import uuid
from typing import TYPE_CHECKING

from PyQt6.QtGui import QFont, QKeySequence
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB limit


class TextEditorDialog(QDialog):
    """Simple text editor for viewing/editing files via any FileBackend."""

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
        self._original_content = b""
        self._loading = False
        self._modified = False
        self._read_only = read_only

        filename = file_path.rsplit(backend.separator(), 1)[-1]
        prefix = "View" if read_only else "Edit"
        self.setWindowTitle(f"{prefix}: {filename} [{backend.name}]")
        self.resize(800, 600)

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

        # Editor
        self._editor = QPlainTextEdit()
        font = QFont("Monospace", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._editor.setFont(font)
        self._editor.setTabStopDistance(32)
        self._editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._editor.textChanged.connect(self._on_text_changed)
        if self._read_only:
            self._editor.setReadOnly(True)
        layout.addWidget(self._editor, stretch=1)

        # Status bar
        status = QHBoxLayout()
        self._status_label = QLabel()
        status.addWidget(self._status_label)

        self._encoding_label = QLabel("UTF-8")
        self._encoding_label.setStyleSheet("color: #666;")
        status.addStretch()
        status.addWidget(self._encoding_label)
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

    def _load_file(self) -> None:
        try:
            # Check size first
            stat = self._backend.stat(self._file_path)
            if stat.size > MAX_FILE_SIZE:
                QMessageBox.warning(
                    self,
                    "File Too Large",
                    f"File is {stat.size_human} — only files under 1 MB are supported.",
                )
                self.reject()
                return

            self._size_label.setText(stat.size_human)

            with self._backend.open_read(self._file_path) as f:
                self._original_content = f.read()

            # Try UTF-8, fallback to Latin-1
            try:
                text = self._original_content.decode("utf-8")
                self._encoding_label.setText("UTF-8")
            except UnicodeDecodeError:
                text = self._original_content.decode("latin-1")
                self._encoding_label.setText("Latin-1")

            self._loading = True
            self._editor.blockSignals(True)
            self._editor.setPlainText(text)
            self._editor.blockSignals(False)
            self._loading = False
            self._modified = False
            self._btn_save.setEnabled(False)
            self._status_label.setText("Loaded")
            log.debug("Loaded file: %s (%d bytes)", self._file_path, len(self._original_content))

        except OSError as e:
            log.error("Cannot read file %s: %s", self._file_path, e)
            QMessageBox.critical(self, "Error", f"Cannot read file:\n{e}")
            self.reject()

    def _on_text_changed(self) -> None:
        if self._loading:
            return
        self._modified = True
        self._btn_save.setEnabled(True)
        self._status_label.setText("Modified")

    def _reload_file(self) -> None:
        if not self._confirm_discard_changes("Reload and discard unsaved changes?"):
            return
        self._load_file()

    def _save_file(self) -> None:
        try:
            # Check for remote conflict by content hash — the earlier
            # stat-based size/mtime pre-check was dead code (its result
            # was never compared to anything), so dropping it here saves
            # one backend round-trip per save.
            try:
                with self._backend.open_read(self._file_path) as f:
                    current_content = f.read()

                if current_content != self._original_content:
                    reply = QMessageBox.question(
                        self,
                        "File Changed",
                        "The file has been modified on the server since you opened it.\n"
                        "Overwrite with your changes?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    )
                    if reply != QMessageBox.StandardButton.Yes:
                        return
            except OSError as e:
                log.warning("Could not check for remote conflict, proceeding: %s", e)

            # Encode and write
            encoding = "utf-8" if self._encoding_label.text() == "UTF-8" else "latin-1"
            content = self._editor.toPlainText().encode(encoding)

            self._save_atomic(content)

            self._original_content = content
            self._modified = False
            self._btn_save.setEnabled(False)
            self._status_label.setText("Saved")
            log.info("Saved file: %s (%d bytes)", self._file_path, len(content))

        except OSError as e:
            log.error("Cannot save file %s: %s", self._file_path, e)
            QMessageBox.critical(self, "Save Error", f"Cannot save file:\n{e}")

    def _save_atomic(self, content: bytes) -> None:
        parent = self._backend.parent(self._file_path)
        filename = self._file_path.rsplit(self._backend.separator(), 1)[-1]
        temp_name = f".{filename}.edit-{uuid.uuid4().hex[:8]}.tmp"
        temp_path = self._backend.join(parent, temp_name)

        try:
            with self._backend.open_write(temp_path) as f:
                f.write(content)

            try:
                self._backend.rename(temp_path, self._file_path)
            except OSError:
                if self._backend.exists(self._file_path) and not self._backend.is_dir(self._file_path):
                    self._backend.remove(self._file_path)
                    self._backend.rename(temp_path, self._file_path)
                else:
                    raise
        finally:
            try:
                if self._backend.exists(temp_path):
                    self._backend.remove(temp_path)
            except OSError:
                log.warning("Could not remove temporary editor file %s", temp_path)

    def _confirm_discard_changes(self, prompt: str) -> bool:
        if not self._modified:
            return True
        reply = QMessageBox.question(
            self,
            "Unsaved Changes",
            prompt,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _on_close(self) -> None:
        if not self._confirm_discard_changes("You have unsaved changes. Discard them?"):
            return
        self.accept()

    def closeEvent(self, event) -> None:
        if not self._confirm_discard_changes("You have unsaved changes. Discard them?"):
            event.ignore()
            return
        event.accept()
