"""Text editor dialog for viewing/editing remote and local files."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PyQt6 import sip
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QKeySequence, QTextOption
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

from core.i18n import format_count, tr
from core.open_limits import DEFAULT_MAX_OPEN_MB, describe_limit, max_open_bytes
from core.remote_name import sanitize_for_display as _shown
from ui.close_corner import add_close_corner
from ui.scan_job import ScanJob

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)

# Default cap, kept for importers; the effective limit is the user
# setting (core.open_limits), read at every open.
MAX_FILE_SIZE = DEFAULT_MAX_OPEN_MB * 1024 * 1024


# The byte-faithful helpers live in core.text_document, shared with the
# tabbed editor (ui/editor_window.py); imported here under their old names.
from core.text_document import (  # noqa: E402
    _UTF8_BOM,
    EditorReadLimitError,
    _common_newline,
    _line_endings,
    _read_capped,
    _split_lines,
    decode,
)
from ui.icon_provider import set_window_icon


class _TooLarge(Exception):
    """The file is larger than the open size limit; ``str()`` its size."""


def _read_text(backend, path: str, cap: int) -> dict:
    """The file at *path* read and decoded (off the GUI thread with
    *background*): its size, bytes, text, encoding, BOM and longest line."""
    from ui.editor_window import _longest_line

    stat = backend.stat(path)
    if stat.size > cap:
        raise _TooLarge(stat.size_human)
    with backend.open_read(path) as f:
        raw = _read_capped(f)
    # As the tabbed editor reads it: UTF-16 by its BOM, UTF-8 (with or
    # without BOM), else Latin-1.
    text, encoding, bom = decode(raw)
    longest, line = _longest_line(text)
    return {"size": stat.size_human, "raw": raw, "text": text, "encoding": encoding,
            "bom": bom, "longest": longest, "line": line}


class TextEditorDialog(QDialog):
    """Simple text editor for viewing/editing files via any FileBackend.

    With *background* the file is read off the GUI thread (the window shows
    "Loading…" meanwhile and closes with a message when the read fails);
    without it the constructor reads. A line too long to lay out unwrapped
    opens wrapped, one longer still read-only as well (the tabbed editor's
    limits, ui.editor_window)."""

    #: A save went through: the pane showing the file's folder refreshes.
    saved = pyqtSignal()

    def __init__(
        self,
        backend: FileBackend,
        file_path: str,
        parent: QWidget | None = None,
        read_only: bool = False,
        *,
        background: bool = False,
    ):
        super().__init__(parent)
        set_window_icon(self, "edit")
        self._background = background
        self._load_job: ScanJob | None = None
        self._backend = backend
        self._file_path = file_path
        self._original_content = b""
        self._newline = "\n"
        # The file's lines and the break after each, as last read or saved.
        self._lines: list[str] = [""]
        self._endings: list[str] = [""]
        self._bom = False
        #: The encoding the file was read with (core.text_document.decode)
        #: and, for UTF-16, its byte order: a save writes them back.
        self._encoding = "utf-8"
        self._utf16_codec = "utf-16-le"
        self._loading = False
        self._saving = False
        self._modified = False
        self._read_only = read_only
        # True once the file was read: a dialog whose load failed must
        # neither open nor save an empty buffer over the real file.
        self._loaded_once = False

        filename = file_path.rsplit(backend.separator(), 1)[-1]
        prefix = tr("View") if read_only else tr("Edit")
        self.setWindowTitle(f"{prefix}: {_shown(filename)} [{backend.name}]")
        self.resize(800, 600)

        self._setup_ui()
        self._load_file()

    @property
    def loaded(self) -> bool:
        """Whether the file was read; a dialog whose load failed is not shown."""
        return self._loaded_once

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Info bar
        info = QHBoxLayout()
        self._path_label = QLabel(_shown(self._file_path))
        self._path_label.setTextFormat(Qt.TextFormat.PlainText)
        self._path_label.setProperty("role", "muted")
        info.addWidget(self._path_label)

        self._size_label = QLabel()
        self._size_label.setProperty("role", "muted")
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
        self._encoding_label.setProperty("role", "muted")
        status.addStretch()
        status.addWidget(self._encoding_label)
        layout.addLayout(status)

        # Buttons
        btn_layout = QHBoxLayout()

        self._btn_save = QPushButton(tr("Save"))
        self._btn_save.setShortcut(QKeySequence("Ctrl+S"))
        self._btn_save.setEnabled(False)
        self._btn_save.clicked.connect(self._save_file)
        if self._read_only:
            self._btn_save.hide()
        btn_layout.addWidget(self._btn_save)

        self._btn_reload = QPushButton(tr("Reload"))
        self._btn_reload.clicked.connect(self._reload_file)
        btn_layout.addWidget(self._btn_reload)

        btn_layout.addStretch()

        self._btn_close = QPushButton(tr("Close"))
        self._btn_close.clicked.connect(self._on_close)
        btn_layout.addWidget(self._btn_close)

        layout.addLayout(btn_layout)
        # The title row: icon, name, _ [] x (the [x] asks about unsaved edits).
        add_close_corner(self, self._on_close)

    def _load_file(self) -> None:
        cap = max_open_bytes()
        if not self._background:
            try:
                result = _read_text(self._backend, self._file_path, cap)
            except (_TooLarge, OSError) as exc:
                self._load_failed(exc)
                return
            self._show_loaded(result)
            return
        job = self._load_job
        if job is None:
            job = self._load_job = ScanJob(self)
            job.finished.connect(self._on_load_finished)
        # Nothing to edit or save until the text is there.
        self._editor.setReadOnly(True)
        self._btn_save.setEnabled(False)
        self._btn_reload.setEnabled(False)
        self._status_label.setText(tr("Loading…"))
        backend, path = self._backend, self._file_path
        job.start(lambda _cancel, _progress: _read_text(backend, path, cap), replace=True)

    @property
    def loading(self) -> bool:
        return self._load_job is not None and self._load_job.running

    def _on_load_finished(self, kind: str, value, _cancelled: bool) -> None:
        self._btn_reload.setEnabled(True)
        if kind == "done":
            self._show_loaded(value)
        else:
            self._editor.setReadOnly(self._read_only)
            self._load_failed(value)

    def _show_loaded(self, result: dict) -> None:
        from ui.editor_window import READ_ONLY_LINE_CHARS, WRAP_LINE_CHARS

        self._size_label.setText(result["size"])
        self._original_content = raw = result["raw"]
        # The encoding, the BOM and the line ending are remembered: the
        # text widget drops the one and folds the other into "\n", and a
        # save must write back what it read.
        text, self._encoding, self._bom = result["text"], result["encoding"], result["bom"]
        if self._encoding == "utf-16":
            self._utf16_codec = "utf-16-be" if raw.startswith(b"\xfe\xff") else "utf-16-le"
        self._encoding_label.setText(
            {"utf-8": "UTF-8", "utf-16": "UTF-16"}.get(self._encoding, "Latin-1"))
        longest, line = result["longest"], result["line"]
        # A line this long laid out unwrapped held the window for seconds
        # at every change; wrapped before the text is set (not after).
        self._editor.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.WidgetWidth if longest > WRAP_LINE_CHARS
            else QPlainTextEdit.LineWrapMode.NoWrap)
        # Anywhere, not at a word boundary first: a line with no place to
        # break (a hex dump) was searched for one from every character on.
        self._editor.setWordWrapMode(
            QTextOption.WrapMode.WrapAnywhere if longest > WRAP_LINE_CHARS
            else QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        too_long = longest > READ_ONLY_LINE_CHARS
        self._remember_lines(text)
        self._loading = True
        self._editor.blockSignals(True)
        self._editor.setPlainText(text)
        self._editor.blockSignals(False)
        self._loading = False
        self._editor.setReadOnly(self._read_only or too_long)
        self._modified = False
        self._btn_save.setEnabled(False)
        if too_long:
            self._status_label.setText(tr(
                "Line {line} is {chars} characters long: shown wrapped and read-only – "
                "typing in it is slow.").format(line=line, chars=format_count(longest)))
        else:
            self._status_label.setText(tr("Loaded"))
        self._loaded_once = True
        log.debug("Loaded file: %s (%d bytes)", self._file_path, len(raw))

    def _load_failed(self, exc: BaseException) -> None:
        if isinstance(exc, _TooLarge):
            QMessageBox.warning(
                self,
                tr("File Too Large"),
                tr("File is {size_human} – only files up to {describe_limit} are opened "
                    "(change it under Edit → Settings… → Files & Panes → Open Size Limit).").format(size_human=str(exc), describe_limit=describe_limit()),
            )
        else:
            log.error("Cannot read file %s: %s", self._file_path, exc)
            QMessageBox.critical(self, tr("Error"), tr("Cannot read file:\n{e}").format(e=exc))
        self._modified = False
        self.reject()

    def _on_text_changed(self) -> None:
        if self._loading:
            return
        self._modified = True
        self._btn_save.setEnabled(True)
        self._status_label.setText(tr("Modified"))

    def _reload_file(self) -> None:
        if not self._confirm_discard_changes(tr("Reload and discard unsaved changes?")):
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
                tr("Save Refused"),
                tr("The file was never read, so saving would replace content nobody has seen."),
            )
            return
        if self._saving:
            return
        # The windows stay live while the server answers (ui.off_gui): no
        # typing meanwhile - an edit then would count as saved.
        self._saving = True
        was_read_only = self._editor.isReadOnly()
        self._editor.setReadOnly(True)
        try:
            self._save_now()
        finally:
            if not sip.isdeleted(self):
                self._saving = False
                self._editor.setReadOnly(was_read_only)

    def _save_now(self) -> None:
        try:
            # Check for remote conflict by content hash — the earlier
            # stat-based size/mtime pre-check was dead code (its result
            # was never compared to anything), so dropping it here saves
            # one backend round-trip per save.
            from ui.off_gui import run_off_gui

            backend, path = self._backend, self._file_path

            def read_current() -> bytes:
                with backend.open_read(path) as f:
                    return _read_capped(f)

            try:
                # off the GUI thread, the windows live meanwhile (ui.off_gui)
                current_content = run_off_gui(read_current, status=self._status_label.setText,
                                              text=tr("Checking…"))
                if sip.isdeleted(self):
                    return

                if current_content != self._original_content:
                    reply = QMessageBox.question(
                        self,
                        tr("File Changed"),
                        tr("The file has been modified on the server since you opened it.\n"
                        "Overwrite with your changes?"),
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.No,
                    )
                    if reply != QMessageBox.StandardButton.Yes:
                        return
            except EditorReadLimitError as e:
                QMessageBox.warning(
                    self,
                    tr("File Too Large"),
                    tr("Cannot safely check remote changes:\n{e}").format(e=e),
                )
                return
            except OSError as e:
                log.warning("Could not check for remote conflict, proceeding: %s", e)

            # Encode and write
            encoding = self._encoding
            try:
                content = self._encoded_text()
            except UnicodeEncodeError as e:
                QMessageBox.critical(
                    self,
                    tr("Save Error"),
                    tr("The text holds characters {upper} cannot store (the file was opened "
                        "as {upper}); nothing was written:\n{e}").format(upper=encoding.upper(), e=e),
                )
                return

            run_off_gui(lambda: self._save_atomic(content), status=self._status_label.setText,
                        text=tr("Saving…"))
            if sip.isdeleted(self):
                return

            self._remember_lines(self._saved_text)
            self._original_content = content
            self._modified = False
            self._btn_save.setEnabled(False)
            self._status_label.setText(tr("Saved"))
            log.info("Saved file: %s (%d bytes)", self._file_path, len(content))
            self.saved.emit()

        except OSError as e:
            log.error("Cannot save file %s: %s", self._file_path, e)
            QMessageBox.critical(self, tr("Save Error"), tr("Cannot save file:\n{e}").format(e=e))

    def _encoded_text(self) -> bytes:
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
        if self._encoding == "utf-16":
            # The BOM, in the byte order the file had ("utf-16" alone
            # writes the host's).
            content = ("\ufeff" + text).encode(self._utf16_codec)
        else:
            content = text.encode(self._encoding)
            if self._bom and self._encoding == "utf-8":
                content = _UTF8_BOM + content
        self._saved_text = text
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
            tr("Unsaved Changes"),
            prompt,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _on_close(self) -> None:
        if not self._confirm_discard_changes(tr("You have unsaved changes. Discard them?")):
            return
        self.accept()

    def reject(self) -> None:
        # Esc must not throw away edits silently either.
        if not self._confirm_discard_changes(tr("You have unsaved changes. Discard them?")):
            return
        super().reject()

    def closeEvent(self, event) -> None:
        if not self._confirm_discard_changes(tr("You have unsaved changes. Discard them?")):
            event.ignore()
            return
        event.accept()
