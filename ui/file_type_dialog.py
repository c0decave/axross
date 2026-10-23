"""Identify File Type: one table row per selected entry.

Opened from the pane's context menu. Each row shows what the content
really is (:mod:`core.file_type`), what the extension claims, a mismatch
warning, the size and - for text - encoding and line endings.

Detection runs on a :class:`~ui.scan_job.ScanJob` (a daemon thread, not a
QThread), and every read inside it has its own deadline, so a slow or dead
remote fills its row with "timed out" while the window stays usable.
Closing the window abandons the job: a late result reaches nobody, and
there is no running QThread whose destruction could abort the process.

:class:`FolderFileTypeDialog` (*Identify Files in This Folder…*) does the
same for every file directly in one folder - listed and read through the
backend, so remote panes work - with a disk image's partition note and, for
local files, sift's kind; bounded by :data:`core.file_type.FOLDER_MAX_FILES`.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
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

    #: (path, FileTypeInfo) of each row as it is identified - the pane keeps
    #: what it learns (Disk Image… in its menu for an image by content).
    identified = pyqtSignal(str, object)

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
        self.disk_image_button = QPushButton(tr("Disk Image…"))
        self.disk_image_button.setToolTip(
            tr("Partitions and file systems of the selected disk image; mount one read-only"))
        self.disk_image_button.setEnabled(False)
        self.disk_image_button.clicked.connect(self.open_disk_image)
        buttons.addWidget(self.disk_image_button)
        self.table.itemSelectionChanged.connect(self._update_disk_image_button)
        self.folder_button = QPushButton(tr("Identify Files in This Folder…"))
        self.folder_button.setToolTip(
            tr("Identify every file of the folder these entries are in"))
        self.folder_button.setEnabled(bool(self._paths))
        self.folder_button.clicked.connect(self.open_folder_scan)
        buttons.addWidget(self.folder_button)
        buttons.addStretch(1)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        root.addLayout(buttons)

    # -- the whole folder ------------------------------------------------------------
    def open_folder_scan(self):
        """Identify Files in This Folder… for the folder the first entry is
        in. Opened beside this window, owned by the same parent (the pane
        keeps it in its list when it is the parent)."""
        if not self._paths:
            return None
        folder = self._backend.parent(self._paths[0])
        owner = self.parent()
        opener = getattr(owner, "identify_folder", None)
        if callable(opener):
            return opener(folder)
        dlg = FolderFileTypeDialog(self._backend, folder, parent=owner)
        dlg.show()
        dlg.start()
        return dlg

    # -- disk images ---------------------------------------------------------------
    def _disk_image_row(self) -> int | None:
        rows = {i.row() for i in self.table.selectedIndexes()}
        if len(rows) != 1:
            return None
        row = rows.pop()
        info = self._results[row] if row < len(self._results) else None
        if info is None or not FT.is_disk_image(info):
            return None
        return row

    def _update_disk_image_button(self) -> None:
        self.disk_image_button.setEnabled(self._disk_image_row() is not None)

    def open_disk_image(self) -> None:
        """Disk Image… for the selected row - recognised by content, so an
        image without a telling name gets it too."""
        row = self._disk_image_row()
        if row is None:
            return
        from ui import disk_image_dialog as DID

        owner = self.parent().window() if self.parent() is not None else None
        dlg = DID.DiskImageDialog(self._backend, self._paths[row], parent=self.parent() or self,
                                  open_folder=getattr(owner, "open_local_folder", None))
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.show()
        dlg.start()

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
            self.identified.emit(self._paths[index], info)
        self._update_disk_image_button()  # a selected row may just have been identified

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


FOLDER_COLUMNS = ("File", "Detected type", "MIME type", "Verdict", "Size", "Note", "sift")
_FCOL = {name: i for i, name in enumerate(FOLDER_COLUMNS)}


class _SortItem(QTableWidgetItem):
    """A cell that sorts by its ``UserRole`` value (sizes as numbers) and
    by folded text otherwise."""

    def __lt__(self, other) -> bool:  # noqa: D105 - Qt sort hook
        mine = self.data(Qt.ItemDataRole.UserRole)
        theirs = other.data(Qt.ItemDataRole.UserRole)
        if mine is not None and theirs is not None:
            return mine < theirs
        return self.text().casefold() < other.text().casefold()


class FolderFileTypeDialog(QDialog):
    """Identify Files in This Folder…: one sortable row per file directly in
    *folder* - detected type, MIME type, the mismatch verdict, size, a note
    (a disk image's container, partition table and partition count) and,
    for local files when sift is installed, sift's kind.

    Listing and reading run on a ScanJob through the backend API, bounded by
    *max_files* files, *max_bytes* per file (and
    :data:`core.file_type.IMAGE_NOTE_MAX_BYTES` for a partition note) and
    *timeout* seconds per read; Cancel stops after the file in progress.
    file(1) is not asked (one process per file). A row opens *Disk Image…*
    (disk images) or *Properties…*; a double-click picks the one that fits."""

    def __init__(
        self,
        backend,
        folder: str,
        *,
        parent: QWidget | None = None,
        max_files: int = FT.FOLDER_MAX_FILES,
        max_bytes: int = FT.DEFAULT_MAX_BYTES,
        timeout: float = FT.DEFAULT_TIMEOUT,
        use_sift: bool | None = None,
    ) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        from core import file_categories as FC

        self._backend = backend
        self.folder = folder
        self._max_files = int(max_files)
        self._max_bytes = int(max_bytes)
        self._timeout = timeout
        if use_sift is None:
            use_sift = FT._is_local(backend) and FC.sift_available()
        self._use_sift = bool(use_sift)
        # Filled by the worker thread, drained on the UI thread: ("listed",
        # FolderListing) once, then ("row", index, info, note, sift_kind).
        self._incoming: list[tuple] = []
        self._drained = 0
        self._listing: FT.FolderListing | None = None
        self._entries: list[dict] = []
        self._done = False
        self._closed = False
        self.setWindowTitle(tr("Identify Files") + f" — {folder}")
        self.resize(1000, 480)

        root = QVBoxLayout(self)
        add_close_corner(self)
        self.table = QTableWidget(0, len(FOLDER_COLUMNS), self)
        self.table.setHorizontalHeaderLabels([tr(c) for c in FOLDER_COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for name, width in (("File", 220), ("Detected type", 200), ("MIME type", 180),
                            ("Verdict", 80), ("Size", 90), ("Note", 260)):
            self.table.setColumnWidth(_FCOL[name], width)
        self.table.setColumnHidden(_FCOL["sift"], not self._use_sift)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.itemDoubleClicked.connect(lambda _item: self._activate())
        root.addWidget(self.table, stretch=1)

        self.status_label = QLabel(tr("Listing {folder}…").format(folder=folder))
        self.status_label.setProperty("role", "muted")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self.job = ScanJob(
            self,
            formatter=lambda st: tr("Identifying… {done} of {total}").format(
                done=st["scanned"], total=st["indexed"]),
        )
        self.job.progress.connect(lambda _text: self._drain())
        self.job.finished.connect(self._on_finished)
        self.busy = BusyStrip(self.job, self, cancel_text=tr("Cancel"))
        root.addWidget(self.busy)

        buttons = QHBoxLayout()
        self.copy_button = QPushButton(tr("Copy"))
        self.copy_button.setToolTip(tr("Copy the selected row (or all rows) as text"))
        self.copy_button.clicked.connect(self.copy_rows)
        buttons.addWidget(self.copy_button)
        self.disk_image_button = QPushButton(tr("Disk Image…"))
        self.disk_image_button.setToolTip(
            tr("Partitions and file systems of the selected disk image; mount one read-only"))
        self.disk_image_button.clicked.connect(self.open_disk_image)
        buttons.addWidget(self.disk_image_button)
        self.properties_button = QPushButton(tr("Properties…"))
        self.properties_button.setToolTip(tr("Size, dates, owner and permissions of the file"))
        self.properties_button.clicked.connect(self.show_properties)
        buttons.addWidget(self.properties_button)
        buttons.addStretch(1)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        root.addLayout(buttons)
        self._update_buttons()

    # -- state for callers and tests -----------------------------------------
    @property
    def idle(self) -> bool:
        return self._done

    def row_texts(self, row: int) -> tuple[str, ...]:
        cells = (self.table.item(row, c) for c in range(self.table.columnCount()))
        return tuple(cell.text() if cell is not None else "" for cell in cells)

    # -- work ----------------------------------------------------------------
    def start(self) -> None:
        backend, folder, incoming = self._backend, self.folder, self._incoming
        max_files, max_bytes, timeout = self._max_files, self._max_bytes, self._timeout
        use_sift = self._use_sift

        def work(cancel, progress):
            from core import file_categories as FC

            listing = FT.list_folder(backend, folder, max_files=max_files, cancel=cancel)
            incoming.append(("listed", listing))  # list.append is atomic
            total = len(listing.files)
            progress(0, total, folder)
            for index, (path, item) in enumerate(listing.files):
                if cancel():
                    break
                info = FT.identify(backend, path, max_bytes=max_bytes, timeout=timeout,
                                   cancel=cancel, use_file_command=False)
                note = ""
                if FT.is_disk_image(info) and not cancel():
                    note = FT.disk_image_note(backend, path, size=info.size, timeout=timeout,
                                              cancel=cancel)
                kind = FC.sift_kind(path) if use_sift and info.kind == FT.KIND_FILE else ""
                incoming.append(("row", index, item, info, note, kind))
                progress(index + 1, total, path)
            return total

        self.job.start(work)

    def _drain(self) -> None:
        if self._closed:
            return
        sorting = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)  # rows keep their place while cells change
        try:
            while self._drained < len(self._incoming):
                message = self._incoming[self._drained]
                self._drained += 1
                if message[0] == "listed":
                    self._add_rows(message[1])
                else:
                    _tag, index, item, info, note, kind = message
                    self._show(index, item, info, note, kind)
        finally:
            self.table.setSortingEnabled(sorting)
        self._update_buttons()

    def _add_rows(self, listing: FT.FolderListing) -> None:
        self._listing = listing
        self.table.setRowCount(len(listing.files))
        for row, (path, item) in enumerate(listing.files):
            size = int(getattr(item, "size", 0) or 0)
            entry = {"path": path, "item": item, "info": None, "note": "", "row_item": None}
            cells = [FT.name_of(path), tr("detecting…"), "", "", format_size(size), "", ""]
            for col, text in enumerate(cells):
                cell = _SortItem(text)
                if col == _FCOL["Size"]:
                    cell.setData(Qt.ItemDataRole.UserRole, size)
                    cell.setTextAlignment(
                        Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.table.setItem(row, col, cell)
            name_cell = self.table.item(row, _FCOL["File"])
            name_cell.setToolTip(path)
            name_cell.setData(Qt.ItemDataRole.UserRole + 1, row)
            entry["row_item"] = name_cell
            self._entries.append(entry)

    def _show(self, index: int, item, info: FT.FileTypeInfo, note: str, kind: str) -> None:
        entry = self._entries[index]
        entry.update(info=info, note=note, item=item)
        row = entry["row_item"].row()
        is_file = info.kind == FT.KIND_FILE
        verdict = tr("mismatch") if info.mismatch else (info.verdict if is_file else "")
        values = {
            "Detected type": info.description or info.kind,
            "MIME type": info.mime,
            "Verdict": verdict,
            "Note": note or (info.error if not is_file else ""),
            "sift": kind,
        }
        for name, text in values.items():
            self.table.item(row, _FCOL[name]).setText(text)
        detected = self.table.item(row, _FCOL["Detected type"])
        detected.setToolTip(info.error or f"{info.description}\n{info.mime}\n{info.engine}")
        if info.mismatch:
            cell = self.table.item(row, _FCOL["Verdict"])
            font = cell.font()
            font.setBold(True)
            cell.setFont(font)
            cell.setBackground(_WARNING)
            cell.setForeground(_WARNING_TEXT)
            cell.setToolTip(
                tr("The content is {real}, but the extension {ext} claims {claimed}.").format(
                    real=info.mime, ext=info.extension, claimed=info.extension_mime))
        if note:
            self.table.item(row, _FCOL["Note"]).setToolTip(note)

    def _on_finished(self, kind: str, value, cancelled: bool) -> None:
        if self._closed:
            return
        self._drain()
        for index, entry in enumerate(self._entries):
            if entry["info"] is None:
                info = FT.FileTypeInfo(
                    path=entry["path"], name=FT.name_of(entry["path"]),
                    kind=FT.KIND_CANCELLED if cancelled or kind == "done" else FT.KIND_ERROR,
                    description=tr("cancelled") if cancelled or kind == "done" else tr("failed"))
                self._show(index, entry["item"], info, "", "")
        if kind != "done":
            log.warning("folder file type scan of %s failed: %r", self.folder, value)
            self.status_label.setText(tr("Failed: {error}").format(error=value))
        else:
            self.status_label.setText(self._summary_text(cancelled))
        self.table.setSortingEnabled(True)
        self._done = True
        self._update_buttons()

    def _summary_text(self, cancelled: bool) -> str:
        infos = [e["info"] for e in self._entries if e["info"] is not None]
        files = [i for i in infos if i.kind == FT.KIND_FILE]
        mismatches = sum(1 for i in files if i.mismatch)
        images = sum(1 for i in files if FT.is_disk_image(i))
        problems = sum(1 for i in infos if i.kind in (FT.KIND_ERROR, FT.KIND_TIMEOUT))
        parts = [tr("{n} file(s) identified").format(n=len(files))]
        parts.append(tr("1 mismatch") if mismatches == 1
                     else tr("{n} mismatches").format(n=mismatches))
        if images:
            parts.append(tr("{n} disk image(s)").format(n=images))
        if problems:
            parts.append(tr("{n} unreadable").format(n=problems))
        listing = self._listing
        if listing is not None:
            if listing.folders:
                parts.append(tr("1 folder not entered") if listing.folders == 1
                             else tr("{n} folders not entered").format(n=listing.folders))
            if listing.skipped:
                parts.append(tr("{n} unsafe name(s) skipped").format(n=listing.skipped))
            if listing.truncated:
                parts.append(tr("only the first {n} files").format(n=self._max_files))
        if cancelled:
            parts.append(tr("cancelled"))
        return ", ".join(parts)

    # -- acting on a row ---------------------------------------------------------
    def _selected_entry(self) -> dict | None:
        rows = {i.row() for i in self.table.selectedIndexes()}
        if len(rows) != 1:
            return None
        cell = self.table.item(rows.pop(), _FCOL["File"])
        index = cell.data(Qt.ItemDataRole.UserRole + 1) if cell is not None else None
        return self._entries[index] if isinstance(index, int) else None

    def _update_buttons(self) -> None:
        entry = self._selected_entry()
        info = entry["info"] if entry is not None else None
        self.disk_image_button.setEnabled(info is not None and FT.is_disk_image(info))
        self.properties_button.setEnabled(entry is not None)

    def _activate(self) -> None:
        if self.disk_image_button.isEnabled():
            self.open_disk_image()
        elif self.properties_button.isEnabled():
            self.show_properties()

    def open_disk_image(self) -> None:
        entry = self._selected_entry()
        if entry is None or entry["info"] is None or not FT.is_disk_image(entry["info"]):
            return
        from ui import disk_image_dialog as DID

        owner = self.parent().window() if self.parent() is not None else None
        dlg = DID.DiskImageDialog(self._backend, entry["path"], parent=self.parent() or self,
                                  open_folder=getattr(owner, "open_local_folder", None))
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        dlg.show()
        dlg.start()

    def show_properties(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            return
        from ui import properties_dialog as PD

        try:
            dialog = PD.PropertiesDialog(self._backend, entry["path"], entry["item"], parent=self)
        except OSError as exc:
            QMessageBox.warning(self, tr("Properties"), str(exc))
            return
        dialog.exec()

    def copy_rows(self) -> None:
        rows = sorted({i.row() for i in self.table.selectedIndexes()}) or list(
            range(self.table.rowCount()))
        visible = [c for c in range(len(FOLDER_COLUMNS)) if not self.table.isColumnHidden(c)]
        lines = ["\t".join(FOLDER_COLUMNS[c] for c in visible)]
        lines += ["\t".join(self.row_texts(r)[c] for c in visible) for r in rows]
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


__all__ = ["COLUMNS", "FOLDER_COLUMNS", "FileTypeDialog", "FolderFileTypeDialog"]
