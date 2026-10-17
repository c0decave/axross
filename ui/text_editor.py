"""Text editor dialog for viewing/editing remote and local files."""

from __future__ import annotations

import difflib
import logging
import re
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

from core.open_limits import DEFAULT_MAX_OPEN_MB, describe_limit, max_open_bytes
from ui.close_corner import make_close_corner, make_maximize_corner

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)

# Default cap, kept for importers; the effective limit is the user
# setting (core.open_limits), read at every open.
MAX_FILE_SIZE = DEFAULT_MAX_OPEN_MB * 1024 * 1024


class EditorReadLimitError(OSError):
    """Raised when a backend returns more data than the editor cap."""


_UTF8_BOM = b"\xef\xbb\xbf"


#: Everything QPlainTextEdit turns into a block break. The widget keeps
#: none of them, so the save has to put back the one each line had.
_LINE_BREAK = re.compile("(\r\n|\r|\n|\u2029)")


def _split_lines(text: str) -> tuple[list[str], list[str]]:
    """*text* as the editor's blocks and the break that ended each one
    (``""`` after the last block)."""
    parts = _LINE_BREAK.split(text)
    return parts[0::2], parts[1::2] + [""]


def _common_newline(endings: list[str]) -> str:
    """The line ending most lines use (first seen wins a tie), else LF.
    New lines get it."""
    counts: dict[str, int] = {}
    for ending in endings:
        if ending in ("\r\n", "\r", "\n"):
            counts[ending] = counts.get(ending, 0) + 1
    return max(counts, key=counts.get) if counts else "\n"


def _line_endings(old_lines, old_endings, new_lines, default: str) -> list[str]:
    """The ending for each of *new_lines*: a line that is still there, or
    was edited in place, keeps the one it had; a new line gets *default*.

    Joining every line with one ending rewrote the untouched lines of a
    file that mixes LF and CRLF."""
    endings = [default] * len(new_lines)
    # Common head and tail first: an edit is local, and the matcher then
    # only sees the changed middle of a large file.
    head = 0
    limit = min(len(old_lines), len(new_lines))
    while head < limit and old_lines[head] == new_lines[head]:
        endings[head] = old_endings[head]
        head += 1
    tail = 0
    while (
        tail < limit - head
        and old_lines[len(old_lines) - 1 - tail] == new_lines[len(new_lines) - 1 - tail]
    ):
        endings[len(new_lines) - 1 - tail] = old_endings[len(old_lines) - 1 - tail]
        tail += 1
    old_mid = old_lines[head : len(old_lines) - tail]
    new_mid = new_lines[head : len(new_lines) - tail]
    matcher = difflib.SequenceMatcher(None, old_mid, new_mid, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag not in ("equal", "replace"):
            continue
        for k in range(min(i2 - i1, j2 - j1)):
            endings[head + j1 + k] = old_endings[head + i1 + k]
    for k in range(len(endings) - 1):
        if not endings[k]:
            endings[k] = default
    if endings:
        endings[-1] = ""
    return endings


def _read_capped(handle, cap: int | None = None) -> bytes:
    if cap is None:
        cap = max_open_bytes()
    data = handle.read(cap + 1)
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if len(data) > cap:
        raise EditorReadLimitError(f"file exceeds {cap} byte editor cap")
    return bytes(data)


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
        self._newline = "\n"
        # The file's lines and the break after each, as last read or saved.
        self._lines: list[str] = [""]
        self._endings: list[str] = [""]
        self._bom = False
        self._loading = False
        self._modified = False
        self._read_only = read_only
        # True once the file was read: a dialog whose load failed must
        # neither open nor save an empty buffer over the real file.
        self._loaded_once = False

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
        self._path_label.setProperty("role", "muted")
        info.addWidget(self._path_label)

        self._size_label = QLabel()
        self._size_label.setProperty("role", "muted")
        info.addStretch()
        info.addWidget(self._size_label)
        info.addWidget(make_maximize_corner(self))
        info.addWidget(make_close_corner(self, self._on_close))
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
        self._encoding_label.setProperty("role", "muted")
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
            if stat.size > max_open_bytes():
                QMessageBox.warning(
                    self,
                    "File Too Large",
                    f"File is {stat.size_human} — only files up to {describe_limit()} "
                    "are opened (change it under View → Open Size Limit…).",
                )
                self.reject()
                return

            self._size_label.setText(stat.size_human)

            with self._backend.open_read(self._file_path) as f:
                self._original_content = _read_capped(f)

            # Try UTF-8, fallback to Latin-1. The BOM and the line ending
            # are remembered: the text widget drops the one and folds the
            # other into "\n", and a save must write back what it read.
            self._bom = False
            try:
                text = self._original_content.decode("utf-8")
                self._encoding_label.setText("UTF-8")
                if self._original_content.startswith(_UTF8_BOM):
                    self._bom = True
                    text = text[1:]
            except UnicodeDecodeError:
                text = self._original_content.decode("latin-1")
                self._encoding_label.setText("Latin-1")

            self._remember_lines(text)
            self._loading = True
            self._editor.blockSignals(True)
            self._editor.setPlainText(text)
            self._editor.blockSignals(False)
            self._loading = False
            self._modified = False
            self._btn_save.setEnabled(False)
            self._status_label.setText("Loaded")
            self._loaded_once = True
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

    def exec(self) -> int:
        # ``_load_file`` already said why and called reject() from the
        # constructor; without this the caller's exec() showed the empty
        # editor anyway.
        if not self._loaded_once:
            return 0
        return super().exec()

    def _save_file(self) -> None:
        if not self._loaded_once:
            QMessageBox.warning(
                self,
                "Save Refused",
                "The file was never read, so saving would replace content nobody has seen.",
            )
            return
        try:
            # Check for remote conflict by content hash — the earlier
            # stat-based size/mtime pre-check was dead code (its result
            # was never compared to anything), so dropping it here saves
            # one backend round-trip per save.
            try:
                with self._backend.open_read(self._file_path) as f:
                    current_content = _read_capped(f)

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
            except EditorReadLimitError as e:
                QMessageBox.warning(
                    self,
                    "File Too Large",
                    f"Cannot safely check remote changes:\n{e}",
                )
                return
            except OSError as e:
                log.warning("Could not check for remote conflict, proceeding: %s", e)

            # Encode and write
            encoding = "utf-8" if self._encoding_label.text() == "UTF-8" else "latin-1"
            try:
                content = self._encoded_text(encoding)
            except UnicodeEncodeError as e:
                QMessageBox.critical(
                    self,
                    "Save Error",
                    f"The text holds characters {encoding.upper()} cannot store "
                    f"(the file was opened as {encoding.upper()}); nothing was written:\n{e}",
                )
                return

            self._save_atomic(content)

            self._remember_lines(self._saved_text)
            self._original_content = content
            self._modified = False
            self._btn_save.setEnabled(False)
            self._status_label.setText("Saved")
            log.info("Saved file: %s (%d bytes)", self._file_path, len(content))

        except OSError as e:
            log.error("Cannot save file %s: %s", self._file_path, e)
            QMessageBox.critical(self, "Save Error", f"Cannot save file:\n{e}")

    def _encoded_text(self, encoding: str) -> bytes:
        """The editor's text as the bytes the file should hold.

        Built from the blocks, not ``toPlainText()``: that one rewrites
        no-break spaces as plain spaces and U+2028 as a line break. Lines
        are joined with the file's own line ending and a UTF-8 BOM the
        file started with is put back."""
        lines = []
        block = self._editor.document().begin()
        while block.isValid():
            lines.append(block.text())
            block = block.next()
        endings = _line_endings(self._lines, self._endings, lines, self._newline)
        text = "".join(line + ending for line, ending in zip(lines, endings))
        content = text.encode(encoding)
        self._saved_text = text
        if self._bom:
            content = _UTF8_BOM + content
        return content

    def _remember_lines(self, text: str) -> None:
        self._lines, self._endings = _split_lines(text)
        self._newline = _common_newline(self._endings)

    def _save_atomic(self, content: bytes) -> None:
        from core.atomic_io import atomic_write

        atomic_write(self._backend, self._file_path, content)

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

    def reject(self) -> None:
        # Esc must not throw away edits silently either.
        if not self._confirm_discard_changes("You have unsaved changes. Discard them?"):
            return
        super().reject()

    def closeEvent(self, event) -> None:
        if not self._confirm_discard_changes("You have unsaved changes. Discard them?"):
            event.ignore()
            return
        event.accept()
