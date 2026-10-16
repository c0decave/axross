"""Metadata UI: the metadata window, its settings and the viewers' side panel.

* :class:`MetadataDialog` - opened from the pane's context menu (Show /
  Remove / Export Metadata…) for the selection or the folder: one table of
  file, group, field and value with a filter, Copy, Export… (JSON / CSV)
  and Remove Metadata. Folders are read flat unless "Include subfolders"
  is ticked. Reading and removing run on a :class:`~ui.scan_job.ScanJob`
  with progress and Cancel; the window never blocks.
* :class:`MetadataSettingsDialog` - Tools -> Metadata Settings…: write mode
  (in place / cleaned copy) and whether to confirm before removing (off by
  default).
* :class:`MetadataPanel` - the side panel of the image and media viewers
  (toggled with I): the current item's metadata and "Remove metadata".

The work itself is :mod:`core.metadata_tools`.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import metadata_tools as MT
from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob, shorten

log = logging.getLogger("ui.metadata_dialog")

#: Rows the table shows at most; an export always has everything.
MAX_TABLE_ROWS = 20_000
COLUMNS = ("File", "Group", "Field", "Value")
_KEPT_COLOUR = QColor(128, 128, 128)

SHOW, REMOVE, EXPORT = "show", "remove", "export"


def _ask_to_remove(parent, count: int) -> bool:
    """True when removal may go ahead: always, unless the setting asks for
    a confirmation and the user declines it."""
    if not MT.confirm_before_remove():
        return True
    mode = MT.write_mode()
    how = (
        tr("The originals are kept in the trash; Edit → Undo puts them back.")
        if mode == MT.MODE_IN_PLACE
        else tr("Cleaned copies are written next to the originals.")
    )
    answer = QMessageBox.question(
        parent,
        tr("Remove Metadata"),
        tr("Remove the metadata of {n} file(s)?").format(n=count) + "\n\n" + how,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No,
    )
    return answer == QMessageBox.StandardButton.Yes


def _summary(batch: MT.BatchResult) -> str:
    counts: dict[str, int] = {}
    for r in batch.results:
        counts[r.status] = counts.get(r.status, 0) + 1
    parts = [tr("Metadata removed from {n} file(s)").format(n=counts.get(MT.CLEANED, 0))]
    if counts.get(MT.UNCHANGED):
        parts.append(tr("{n} had none").format(n=counts[MT.UNCHANGED]))
    if counts.get(MT.UNSUPPORTED):
        parts.append(tr("{n} not supported").format(n=counts[MT.UNSUPPORTED]))
    if counts.get(MT.ERROR):
        parts.append(tr("{n} failed").format(n=counts[MT.ERROR]))
    if batch.cancelled:
        parts.append(tr("cancelled"))
    copies = [r.output for r in batch.results if r.status == MT.CLEANED and r.mode == MT.MODE_COPY]
    if copies:
        parts.append(tr("{n} cleaned copies written").format(n=len(copies)))
    return ", ".join(parts)


def _problems(batch: MT.BatchResult) -> str:
    lines = [
        f"{r.path}: {r.error or r.note}"
        for r in batch.results
        if r.status in (MT.ERROR, MT.UNSUPPORTED) or r.note
    ]
    return "\n".join(lines[:30])


class _Table(QTableWidget):
    """The metadata table shared by the window and the panel."""

    def __init__(self, columns, parent=None) -> None:
        super().__init__(0, len(columns), parent)
        self.setHorizontalHeaderLabels([tr(c) for c in columns])
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.verticalHeader().setVisible(False)
        self.setWordWrap(False)
        # Cut long paths in the middle: cut at the end, every row of a
        # folder showed the same prefix and never the file name.
        self.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        for col in range(len(columns) - 1):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)

    def add_row(
        self, cells: list[str], *, kept: bool = False, tip: str = "", path: str = ""
    ) -> None:
        """*path* is the full file path shown as the first cell's tooltip,
        where an elided path would otherwise hide it."""
        row = self.rowCount()
        self.insertRow(row)
        for col, text in enumerate(cells):
            item = QTableWidgetItem(text)
            hint = tip
            if kept:
                item.setForeground(_KEPT_COLOUR)
                hint = tr("Kept when metadata is removed")
            if col == 0 and path:
                hint = f"{path}\n{hint}" if hint else path
            if hint:
                item.setToolTip(hint)
            self.setItem(row, col, item)

    def row_texts(self, row: int) -> tuple[str, ...]:
        cells = (self.item(row, c) for c in range(self.columnCount()))
        return tuple(cell.text() if cell is not None else "" for cell in cells)


def _fill(table: _Table, reports, *, with_file: bool) -> int:
    """Rows for *reports*; returns how many rows were left out by the cap."""
    table.setUpdatesEnabled(False)
    table.setRowCount(0)
    dropped = 0
    try:
        for r in reports:
            prefix = [r.path] if with_file else []
            path = r.path if with_file else ""
            if r.error:
                if table.rowCount() < MAX_TABLE_ROWS:
                    table.add_row(prefix + [tr("Error"), "", r.error], path=path)
                else:
                    dropped += 1
            if not r.fields and not r.error:
                if table.rowCount() < MAX_TABLE_ROWS:
                    table.add_row(prefix + ["", "", tr("no metadata")], path=path)
                else:
                    dropped += 1
            for f in r.fields:
                if table.rowCount() >= MAX_TABLE_ROWS:
                    dropped += 1
                    continue
                table.add_row(
                    prefix + [f.group, f.name, f.value], kept=not f.removable, path=path
                )
    finally:
        table.setUpdatesEnabled(True)
    return dropped


# ---------------------------------------------------------------------------
# The metadata window
# ---------------------------------------------------------------------------


class MetadataDialog(QDialog):
    """Show, export and remove the metadata of files and folders."""

    #: Files were rewritten (the pane refreshes its listing).
    changed = pyqtSignal()

    def __init__(
        self,
        backend,
        targets: list[tuple[str, bool]],
        *,
        action: str = SHOW,
        recursive: bool = False,
        parent: QWidget | None = None,
    ) -> None:
        """*targets* are ``(path, is_folder)`` pairs: the selection, or the
        folder itself. *action* ``remove`` on files starts removing as soon
        as they are read; on folders it waits for the Remove button, so the
        subfolder choice can be made first. ``export`` asks for a file once
        the first read is done. Subfolders are off unless *recursive*: the
        choice is made per window, never carried over, so a later removal on
        another folder cannot go deep by accident."""
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._backend = backend
        self._targets = list(targets)
        self._action = action
        self._reports: list[MT.MetadataReport] = []
        self._phase = ""
        self._first_scan_done = False
        self._prefix = ""
        self._closed = False
        has_folder = any(is_dir for _p, is_dir in self._targets)
        label = self._targets[0][0] if len(self._targets) == 1 else tr("{n} items").format(
            n=len(self._targets)
        )
        self.setWindowTitle(tr("Metadata") + f" — {label}")
        self.resize(900, 600)

        root = QVBoxLayout(self)
        add_close_corner(self)
        top = QHBoxLayout()
        self.recursive_box = QCheckBox(tr("Include subfolders"))
        self.recursive_box.setChecked(recursive)
        self.recursive_box.setVisible(has_folder)
        self.recursive_box.toggled.connect(self._recursive_toggled)
        top.addWidget(self.recursive_box)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(tr("Filter…"))
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self._apply_filter)
        top.addWidget(self.filter_edit, stretch=1)
        root.addLayout(top)

        self.table = _Table(COLUMNS, self)
        self.table.setColumnWidth(0, 260)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 180)
        root.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setProperty("role", "muted")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        self.job = ScanJob(
            self,
            formatter=lambda s: tr("Working… {done} file(s)").format(done=s["scanned"])
            + f" — {shorten(s['path'])}",
        )
        self.job.finished.connect(self._on_finished)
        self.busy = BusyStrip(self.job, self, cancel_text=tr("Cancel"))
        root.addWidget(self.busy)

        buttons = QHBoxLayout()
        self.copy_button = QPushButton(tr("Copy"))
        self.copy_button.setToolTip(tr("Copy the selected rows (or all shown rows) as text"))
        self.copy_button.clicked.connect(self.copy_selection)
        buttons.addWidget(self.copy_button)
        self.export_button = QPushButton(tr("Export…"))
        self.export_button.setToolTip(tr("Save everything as JSON or CSV"))
        self.export_button.clicked.connect(self.export)
        buttons.addWidget(self.export_button)
        buttons.addStretch(1)
        self.remove_button = QPushButton(tr("Remove Metadata"))
        self.remove_button.setToolTip(
            tr("Remove the metadata of every file listed (orientation and colour profile stay)")
        )
        self.remove_button.clicked.connect(self.remove)
        buttons.addWidget(self.remove_button)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        root.addLayout(buttons)

    # -- state for callers and tests -----------------------------------------
    @property
    def idle(self) -> bool:
        return self._first_scan_done and not self.job.running

    def reports(self) -> list[MT.MetadataReport]:
        return list(self._reports)

    def file_names(self) -> list[str]:
        return sorted(r.name for r in self._reports)

    def removable_count(self) -> int:
        return sum(r.removable for r in self._reports)

    def row_count(self) -> int:
        return self.table.rowCount()

    def visible_rows(self) -> list[tuple[str, ...]]:
        return [
            self.table.row_texts(r)
            for r in range(self.table.rowCount())
            if not self.table.isRowHidden(r)
        ]

    # -- reading ---------------------------------------------------------------
    def start(self) -> None:
        self._scan()

    def _scan(self) -> None:
        backend, targets = self._backend, list(self._targets)
        recursive = self.recursive_box.isChecked()

        def work(cancel, progress):
            reports: list[MT.MetadataReport] = []
            for path, is_dir in targets:
                if cancel():
                    break
                if is_dir:
                    base = len(reports)
                    batch = MT.scan_metadata(
                        backend,
                        path,
                        recursive=recursive,
                        cancel=cancel,
                        progress=lambda d, _t, p: progress(base + d, 0, p),
                    )
                    reports.extend(batch.reports)
                else:
                    reports.append(MT.read_metadata(backend, path, cancel=cancel))
                    progress(len(reports), 0, path)
            return reports

        self._phase = "scan"
        self.job.start(work, replace=True)

    def _recursive_toggled(self, _checked: bool) -> None:
        if self._first_scan_done or self.job.running:
            self._prefix = ""
            self._scan()

    def _on_finished(self, kind: str, value, cancelled: bool) -> None:
        phase, self._phase = self._phase, ""
        if self._closed:
            return
        if kind != "done":
            log.warning("metadata %s failed: %r", phase, value)
            self.status_label.setText(tr("Failed: {error}").format(error=value))
            self._first_scan_done = True
            return
        if phase == "remove":
            batch: MT.BatchResult = value
            self._prefix = _summary(batch)
            problems = _problems(batch)
            self.status_label.setToolTip(problems)
            if any(r.status == MT.CLEANED for r in batch.results):
                self.changed.emit()
            self._scan()
            return
        first = not self._first_scan_done
        self._reports = list(value)
        self._first_scan_done = True
        dropped = _fill(self.table, self._reports, with_file=True)
        self._apply_filter(self.filter_edit.text())
        parts = [
            tr("{files} file(s), {fields} field(s), {removable} removable").format(
                files=len(self._reports),
                fields=sum(len(r.fields) for r in self._reports),
                removable=self.removable_count(),
            )
        ]
        if dropped:
            parts.append(tr("{n} more rows not shown; Export has them all").format(n=dropped))
        if cancelled:
            parts.append(tr("cancelled"))
        text = ", ".join(parts)
        self.status_label.setText(f"{self._prefix} — {text}" if self._prefix else text)
        if first and not cancelled:
            if self._action == EXPORT:
                self.export()
            elif self._action == REMOVE and not any(d for _p, d in self._targets):
                self.remove()

    # -- filter / copy / export ---------------------------------------------------
    def _apply_filter(self, text: str) -> None:
        needle = text.strip().lower()
        for row in range(self.table.rowCount()):
            hide = bool(needle) and needle not in " ".join(self.table.row_texts(row)).lower()
            self.table.setRowHidden(row, hide)

    def copy_selection(self) -> None:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        if not rows:
            rows = [r for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)]
        lines = ["\t".join(self.table.row_texts(r)) for r in rows if not self.table.isRowHidden(r)]
        QApplication.clipboard().setText("\n".join(lines))
        self.status_label.setText(tr("{n} row(s) copied").format(n=len(lines)))

    def export(self) -> None:
        if not self._reports:
            self.status_label.setText(tr("Nothing to export"))
            return
        path, chosen = QFileDialog.getSaveFileName(
            self,
            tr("Export Metadata"),
            "metadata.json",
            "JSON (*.json);;CSV (*.csv)",
        )
        if not path:
            return
        fmt = "csv" if path.lower().endswith(".csv") or (
            "csv" in (chosen or "").lower() and not path.lower().endswith(".json")
        ) else "json"
        if not path.lower().endswith("." + fmt):
            path += "." + fmt
        text = MT.export_reports(self._reports, fmt)
        try:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
        except OSError as exc:
            QMessageBox.warning(self, tr("Export Metadata"), f"{path}\n\n{exc}")
            return
        self.status_label.setText(
            tr("Exported {n} file(s) to {path}").format(n=len(self._reports), path=path)
        )

    # -- removing ---------------------------------------------------------------
    def remove(self) -> None:
        if self.job.running:
            return
        paths = [r.path for r in self._reports if r.kind and (r.removable or r.error)]
        if not paths:
            self.status_label.setText(tr("Nothing to remove"))
            return
        if not _ask_to_remove(self, len(paths)):
            return
        backend = self._backend
        source = self._targets[0][0] if len(self._targets) == 1 else ""

        def work(cancel, progress):
            return MT.remove_many(
                backend, paths, cancel=cancel, progress=progress, source=source
            )

        self._phase = "remove"
        self.job.start(work)

    # -- teardown ---------------------------------------------------------------
    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._closed = True
        self.job.abandon()
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class MetadataSettingsDialog(QDialog):
    """Tools -> Metadata Settings…"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Metadata Settings"))
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(tr("When metadata is removed:")))
        self.in_place_radio = QRadioButton(
            tr("Replace the file (the original is kept in the trash; Edit → Undo restores it)")
        )
        self.copy_radio = QRadioButton(
            tr("Write a cleaned copy next to it (name.clean.ext), leave the original")
        )
        mode = MT.write_mode()
        self.in_place_radio.setChecked(mode == MT.MODE_IN_PLACE)
        self.copy_radio.setChecked(mode == MT.MODE_COPY)
        layout.addWidget(self.in_place_radio)
        layout.addWidget(self.copy_radio)
        self.confirm_box = QCheckBox(tr("Ask before removing metadata"))
        self.confirm_box.setChecked(MT.confirm_before_remove())
        layout.addWidget(self.confirm_box)
        caps = MT.capabilities()
        missing = [f"{kind}: {cap.reason}" for kind, cap in caps.items() if cap.reason]
        if missing:
            note = QLabel("\n".join(missing))
            note.setProperty("role", "muted")
            note.setWordWrap(True)
            layout.addWidget(note)
        box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        layout.addWidget(box)

    def accept(self) -> None:
        MT.set_write_mode(MT.MODE_COPY if self.copy_radio.isChecked() else MT.MODE_IN_PLACE)
        MT.set_confirm_before_remove(self.confirm_box.isChecked())
        super().accept()


# ---------------------------------------------------------------------------
# Viewer side panel
# ---------------------------------------------------------------------------


class MetadataPanel(QWidget):
    """The current item's metadata beside a viewer; reads only while shown."""

    #: The file at this path had its metadata removed.
    removed = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setMinimumWidth(280)
        self.setMaximumWidth(460)
        self._backend = None
        self.path = ""
        self._loaded_path = None
        self._phase = ""
        self._report: MT.MetadataReport | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 0, 0, 0)
        self.title = QLabel(tr("Metadata"))
        self.title.setWordWrap(True)
        layout.addWidget(self.title)
        self.table = _Table(("Group", "Field", "Value"), self)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 110)
        layout.addWidget(self.table, stretch=1)
        self.status_label = QLabel("")
        self.status_label.setProperty("role", "muted")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.remove_button = QPushButton(tr("Remove metadata"))
        self.remove_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.remove_button.setToolTip(
            tr("Remove this file's metadata (orientation and colour profile stay)")
        )
        self.remove_button.clicked.connect(self.remove)
        self.remove_button.setEnabled(False)
        layout.addWidget(self.remove_button)
        self.job = ScanJob(self)
        self.job.finished.connect(self._on_finished)

    @property
    def idle(self) -> bool:
        return not self.job.running and self._loaded_path == self.path

    def row_count(self) -> int:
        return self.table.rowCount()

    def removable_count(self) -> int:
        return self._report.removable if self._report is not None else 0

    def set_target(self, backend, path: str) -> None:
        self._backend, self.path = backend, path
        self.title.setText(path.rsplit("/", 1)[-1] or path)
        self.title.setToolTip(path)
        if self.isVisible():
            self.load()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        if self.path and self._loaded_path != self.path and not self.job.running:
            self.load()

    def load(self) -> None:
        if self._backend is None or not self.path:
            return
        backend, path = self._backend, self.path
        self._phase = "read"
        self.remove_button.setEnabled(False)
        self.status_label.setText(tr("Reading…"))
        self.job.start(lambda cancel, _p: (path, MT.read_metadata(backend, path, cancel=cancel)),
                       replace=True)

    def remove(self) -> None:
        if self._backend is None or not self.path or self.job.running:
            return
        if not _ask_to_remove(self, 1):
            return
        backend, path = self._backend, self.path
        self._phase = "remove"
        self.remove_button.setEnabled(False)
        self.status_label.setText(tr("Removing…"))
        self.job.start(lambda cancel, _p: (path, MT.remove_metadata(backend, path, cancel=cancel)))

    def _on_finished(self, kind: str, value, cancelled: bool) -> None:
        phase, self._phase = self._phase, ""
        if kind != "done":
            self.status_label.setText(tr("Failed: {error}").format(error=value))
            self._loaded_path = self.path
            return
        path, result = value
        if phase == "remove":
            r: MT.RemoveResult = result
            if r.status == MT.CLEANED:
                text = tr("Metadata removed")
                if r.mode == MT.MODE_COPY:
                    text += " — " + tr("cleaned copy: {path}").format(path=r.output)
                if r.note:
                    text += f" ({r.note})"
                self.status_label.setText(text)
                self.removed.emit(path)
            else:
                self.status_label.setText(r.error or tr("Nothing to remove"))
            self._loaded_path = None
            if path == self.path:
                self.load()
            return
        if path != self.path:  # superseded by a newer target
            self.load()
            return
        self._report = result
        self._loaded_path = path
        _fill(self.table, [result], with_file=False)
        if result.error:
            self.status_label.setText(result.error)
        else:
            self.status_label.setText(
                tr("{n} field(s), {removable} removable").format(
                    n=len(result.fields), removable=result.removable
                )
            )
        self.remove_button.setEnabled(bool(result.removable or (result.error and result.kind)))


__all__ = ["MetadataDialog", "MetadataPanel", "MetadataSettingsDialog"]
