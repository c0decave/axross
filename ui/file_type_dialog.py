"""Identify File Type: one table row per selected entry.

Opened from the pane's context menu. Each row shows what the content
really is (:mod:`core.file_type`), what the extension claims, a mismatch
warning, the size and - for text - encoding and line endings.

Detection runs on a :class:`~ui.scan_job.ScanJob` (a daemon thread, not a
QThread), and every read inside it has its own deadline, so a slow or dead
remote fills its row with "timed out" while the window stays usable.
Closing the window abandons the job: a late result reaches nobody, and
there is no running QThread whose destruction could abort the process.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import file_type as FT
from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.format_utils import format_size
from ui.scan_job import BusyStrip, ScanJob

log = logging.getLogger(__name__)

COLUMNS = (
    "File",
    "Detected type",
    "MIME type",
    "Extension claims",
    "Verdict",
    "Size",
    "Encoding",
    "Line endings",
    "file(1)",
)
_COL = {name: i for i, name in enumerate(COLUMNS)}

#: Background of a mismatch verdict - the warning accent used elsewhere
#: (ui.log_dock, the archive extract entry).
_WARNING = QColor("#e5c07b")
_WARNING_TEXT = QColor("#000000")


def _claim_text(info: FT.FileTypeInfo) -> str:
    if info.kind != FT.KIND_FILE:
        return ""
    if not info.extension:
        return tr("no extension")
    if not info.extension_mime:
        return tr("{ext} (unknown extension)").format(ext=info.extension)
    return f"{info.extension_mime} ({info.extension})"


def _cells(info: FT.FileTypeInfo) -> list[str]:
    is_file = info.kind == FT.KIND_FILE
    return [
        info.name,
        info.description or info.kind,
        info.mime,
        _claim_text(info),
        info.verdict if is_file else "",
        format_size(info.size) if info.size is not None else "",
        info.encoding,
        info.line_endings,
        info.file_command,
    ]


class FileTypeDialog(QDialog):
    """Detected type, claimed type and mismatch warning for some paths."""

    def __init__(
        self,
        backend,
        paths: list[str],
        *,
        parent: QWidget | None = None,
        max_bytes: int = FT.DEFAULT_MAX_BYTES,
        timeout: float = FT.DEFAULT_TIMEOUT,
        use_file_command: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._backend = backend
        self._paths = list(paths)
        self._max_bytes = max_bytes
        self._timeout = timeout
        self._use_file_command = use_file_command
        self._results: list[FT.FileTypeInfo | None] = [None] * len(self._paths)
        # Filled by the worker thread, drained on the UI thread.
        self._incoming: list[tuple[int, FT.FileTypeInfo]] = []
        self._drained = 0
        self._done = False
        self._closed = False
        label = self._paths[0] if len(self._paths) == 1 else tr("{n} items").format(
            n=len(self._paths)
        )
        self.setWindowTitle(tr("File Type") + f" — {label}")
        self.resize(1000, 320)

        root = QVBoxLayout(self)
        add_close_corner(self)

        self.table = QTableWidget(len(self._paths), len(COLUMNS), self)
        self.table.setHorizontalHeaderLabels([tr(c) for c in COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for row, path in enumerate(self._paths):
            self._set_row(row, [FT.name_of(path), tr("detecting…")] + [""] * (len(COLUMNS) - 2))
            self.table.item(row, _COL["File"]).setToolTip(path)
        self.table.setColumnWidth(_COL["File"], 200)
        self.table.setColumnWidth(_COL["Detected type"], 180)
        self.table.setColumnWidth(_COL["MIME type"], 170)
        self.table.setColumnWidth(_COL["Extension claims"], 190)
        root.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setProperty("role", "muted")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self.job = ScanJob(
            self,
            formatter=lambda s: tr("Identifying… {done} of {total}").format(
                done=s["scanned"], total=len(self._paths)
            ),
        )
        self.job.progress.connect(lambda _text: self._drain())
        self.job.finished.connect(self._on_finished)
        self.busy = BusyStrip(self.job, self, cancel_text=tr("Cancel"))
        root.addWidget(self.busy)

        buttons = QHBoxLayout()
        self.copy_button = QPushButton(tr("Copy"))
        self.copy_button.setToolTip(tr("Copy the selected rows (or all rows) as text"))
        self.copy_button.clicked.connect(self.copy_rows)
        buttons.addWidget(self.copy_button)
        buttons.addStretch(1)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        root.addLayout(buttons)

    # -- state for callers and tests -----------------------------------------
    @property
    def idle(self) -> bool:
        """True once every row has its final content."""
        return self._done

    def results(self) -> list[FT.FileTypeInfo | None]:
        return list(self._results)

    def row_texts(self, row: int) -> tuple[str, ...]:
        cells = (self.table.item(row, c) for c in range(self.table.columnCount()))
        return tuple(cell.text() if cell is not None else "" for cell in cells)

    # -- detection ---------------------------------------------------------------
    def start(self) -> None:
        backend, paths, incoming = self._backend, list(self._paths), self._incoming
        options = {
            "max_bytes": self._max_bytes,
            "timeout": self._timeout,
            "use_file_command": self._use_file_command,
        }

        def work(cancel, progress):
            for index, path in enumerate(paths):
                info = FT.identify(backend, path, cancel=cancel, **options)
                incoming.append((index, info))  # list.append is atomic
                progress(index + 1, 0, path)
            return len(paths)

        self.job.start(work)

    def _drain(self) -> None:
        if self._closed:
            return
        while self._drained < len(self._incoming):
            index, info = self._incoming[self._drained]
            self._drained += 1
            self._results[index] = info
            self._show(index, info)

    def _on_finished(self, kind: str, value, cancelled: bool) -> None:
        if self._closed:
            return
        self._drain()
        for row, info in enumerate(self._results):
            if info is None:
                path = self._paths[row]
                info = FT.FileTypeInfo(
                    path=path,
                    name=FT.name_of(path),
                    kind=FT.KIND_CANCELLED if cancelled or kind == "done" else FT.KIND_ERROR,
                    description=tr("cancelled") if cancelled or kind == "done" else tr("failed"),
                    error="" if kind == "done" else str(value),
                )
                self._results[row] = info
                self._show(row, info)
        if kind != "done":
            log.warning("file type detection failed: %r", value)
            self.status_label.setText(tr("Failed: {error}").format(error=value))
        else:
            self.status_label.setText(self._summary_text(cancelled))
        self._done = True

    def _summary_text(self, cancelled: bool) -> str:
        files = [i for i in self._results if i is not None and i.kind == FT.KIND_FILE]
        mismatches = sum(1 for i in files if i.mismatch)
        problems = sum(
            1
            for i in self._results
            if i is not None and i.kind in (FT.KIND_ERROR, FT.KIND_TIMEOUT)
        )
        parts = [tr("{n} file(s) identified").format(n=len(files))]
        parts.append(
            tr("1 mismatch") if mismatches == 1 else tr("{n} mismatches").format(n=mismatches)
        )
        if problems:
            parts.append(tr("{n} unreadable").format(n=problems))
        if cancelled:
            parts.append(tr("cancelled"))
        return ", ".join(parts)

    # -- rows --------------------------------------------------------------------
    def _set_row(self, row: int, cells: list[str]) -> None:
        for col, text in enumerate(cells):
            item = self.table.item(row, col)
            if item is None:
                item = QTableWidgetItem()
                self.table.setItem(row, col, item)
            item.setText(text)

    def _show(self, row: int, info: FT.FileTypeInfo) -> None:
        self._set_row(row, _cells(info))
        self.table.item(row, _COL["File"]).setToolTip(info.path)
        detected = self.table.item(row, _COL["Detected type"])
        detected.setToolTip(info.error or f"{info.description}\n{info.mime}\n{info.engine}")
        verdict = self.table.item(row, _COL["Verdict"])
        if info.mismatch:
            font = verdict.font()
            font.setBold(True)
            verdict.setFont(font)
            verdict.setBackground(_WARNING)
            verdict.setForeground(_WARNING_TEXT)
            verdict.setText(tr("mismatch"))
            verdict.setToolTip(
                tr("The content is {real}, but the extension {ext} claims {claimed}.").format(
                    real=info.mime, ext=info.extension, claimed=info.extension_mime
                )
            )
        elif info.verdict == FT.UNKNOWN and info.kind == FT.KIND_FILE:
            verdict.setToolTip(
                tr("Nothing to compare: no known extension, or the content cannot tell.")
            )
        if info.file_command:
            self.table.item(row, _COL["file(1)"]).setToolTip(info.file_command)

    # -- copy --------------------------------------------------------------------
    def copy_rows(self) -> None:
        rows = sorted({i.row() for i in self.table.selectedIndexes()}) or list(
            range(self.table.rowCount())
        )
        lines = ["\t".join(COLUMNS)] + ["\t".join(self.row_texts(r)) for r in rows]
        QApplication.clipboard().setText("\n".join(lines))
        self.status_label.setText(tr("{n} row(s) copied").format(n=len(rows)))

    # -- teardown ----------------------------------------------------------------
    def _abandon(self) -> None:
        self._closed = True
        self.job.abandon()

    def done(self, result: int) -> None:  # noqa: D102 - Qt override (Esc, close corner)
        self._abandon()
        super().done(result)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._abandon()
        super().closeEvent(event)


__all__ = ["COLUMNS", "FileTypeDialog"]
