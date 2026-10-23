"""Metadata UI: the metadata window, its settings and the viewers' side panel.

* :class:`MetadataDialog` - opened from the pane's context menu (Show /
  Remove / Export Metadata…) for the selection or the folder: one row per
  file, its fields one after another as ``key: value``, with a filter,
  Copy, Export… (JSON / CSV) and Remove Metadata. A double-click or the
  context menu's Properties… opens :class:`MetadataDetailsDialog`; the
  context menu also removes the metadata of the selected files only.
  Folders are read flat unless "Include subfolders" is ticked. Reading and
  removing run on a :class:`~ui.scan_job.ScanJob` with progress and
  Cancel; the window never blocks.
* :class:`MetadataDetailsDialog` - every field of one file, grouped, one
  field per line with the value wrapped; Copy and Remove Metadata.
* :class:`MetadataSettingsPage` - Edit -> Settings… -> Metadata (Tools ->
  Metadata Settings… opens it): write mode (in place / cleaned copy) and
  whether to confirm before removing (off by default);
  :class:`MetadataSettingsDialog` is the same form as a dialog.
* :class:`MetadataPanel` - the side panel of the image and media viewers
  (toggled with I): the current item's metadata and "Remove metadata".

The work itself is :mod:`core.metadata_tools`.
"""

from __future__ import annotations

import html
import logging

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QTextOption
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
    QMenu,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QStyledItemDelegate,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
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
COLUMNS = ("File", "Metadata")
#: Characters of one value in a file's row; Properties shows it whole.
SUMMARY_VALUE_CHARS = 48
#: Characters of a file's whole row.
SUMMARY_CHARS = 2_000
#: Fields named in a row's tooltip.
TOOLTIP_FIELDS = 20
#: Characters of one value in Properties; longer ones end with a note.
DETAIL_VALUE_CHARS = 20_000
_KEPT_COLOUR = QColor(128, 128, 128)
_SEP = " · "

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


class _ElideRight(QStyledItemDelegate):
    """Cuts a column at the end, where the table cuts in the middle."""

    def initStyleOption(self, option, index) -> None:  # noqa: N802 - Qt override
        super().initStyleOption(option, index)
        option.textElideMode = Qt.TextElideMode.ElideRight


def _fill_fields(table: _Table, report: MT.MetadataReport) -> None:
    """One row per field of *report*: the viewers' side panel."""
    table.setUpdatesEnabled(False)
    table.setRowCount(0)
    try:
        if report.error:
            table.add_row([tr("Error"), "", report.error])
        if not report.fields and not report.error:
            table.add_row(["", "", tr("no metadata")])
        for f in report.fields:
            table.add_row([f.group, f.name, f.value], kept=not f.removable)
    finally:
        table.setUpdatesEnabled(True)


def _one_line(text: str, limit: int) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def summary_line(report: MT.MetadataReport) -> str:
    """*report* on one line: its fields one after another as
    ``key: value``, long values cut; the error first when there is one."""
    parts = []
    if report.error:
        parts.append(tr("Error") + ": " + _one_line(report.error, SUMMARY_VALUE_CHARS * 2))
    for f in report.fields:
        name = _one_line(f.name, SUMMARY_VALUE_CHARS)
        parts.append(f"{name}: {_one_line(f.value, SUMMARY_VALUE_CHARS)}")
    if not parts:
        return tr("no metadata")
    return _one_line(_SEP.join(parts), SUMMARY_CHARS)


def _row_tooltip(report: MT.MetadataReport) -> str:
    lines = [report.path]
    if report.error:
        lines.append(tr("Error") + ": " + report.error)
    for f in report.fields[:TOOLTIP_FIELDS]:
        lines.append(f"{f.group} / {f.name}: {_one_line(f.value, SUMMARY_VALUE_CHARS)}")
    if len(report.fields) > TOOLTIP_FIELDS:
        lines.append(tr("… {n} more").format(n=len(report.fields) - TOOLTIP_FIELDS))
    kept = len(report.fields) - report.removable
    if kept:
        lines.append(tr("{n} field(s) kept when metadata is removed").format(n=kept))
    lines.append(tr("Double-click for Properties"))
    return "\n".join(lines)


def _field_lines(report: MT.MetadataReport, needle: str = "") -> list[str]:
    """Tab-separated ``path, group, field, value`` lines of *report*, only
    those containing *needle* when one is given."""
    if report.error:
        lines = ["\t".join((report.path, tr("Error"), "", report.error))]
    elif not report.fields:
        lines = ["\t".join((report.path, "", "", tr("no metadata")))]
    else:
        lines = []
    lines += ["\t".join((report.path, f.group, f.name, f.value)) for f in report.fields]
    if needle:
        lines = [line for line in lines if needle in line.lower()]
    return lines


def _search_text(report: MT.MetadataReport) -> str:
    return "\n".join(_field_lines(report)).lower()


def _fill_files(table: _Table, reports) -> int:
    """One row per report; returns how many were left out by the cap."""
    table.setUpdatesEnabled(False)
    table.setRowCount(0)
    try:
        for index, r in enumerate(reports[:MAX_TABLE_ROWS]):
            table.add_row([r.path, summary_line(r)], tip=_row_tooltip(r))
            table.item(table.rowCount() - 1, 0).setData(Qt.ItemDataRole.UserRole, index)
    finally:
        table.setUpdatesEnabled(True)
    return max(0, len(reports) - MAX_TABLE_ROWS)


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
        self._search: list[str] = []
        #: Open Properties windows; they follow a rescan of their file.
        self.details_dialogs: list[MetadataDetailsDialog] = []
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
        self.table.setColumnWidth(0, 300)
        self.table.setItemDelegateForColumn(1, _ElideRight(self.table))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(lambda index: self.open_details(index.row()))
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
        self.copy_button.setToolTip(
            tr("Copy the fields of the selected files (or of all shown files) as text")
        )
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
        self.remove_button.clicked.connect(lambda: self.remove())
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

    def field_count(self) -> int:
        return sum(len(r.fields) for r in self._reports)

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
        dropped = _fill_files(self.table, self._reports)
        self._search = [_search_text(r) for r in self._reports[: self.table.rowCount()]]
        self._apply_filter(self.filter_edit.text())
        self._refresh_details()
        parts = [
            tr("{files} file(s), {fields} field(s), {removable} removable").format(
                files=len(self._reports),
                fields=sum(len(r.fields) for r in self._reports),
                removable=self.removable_count(),
            )
        ]
        if dropped:
            parts.append(tr("{n} more files not shown; Export has them all").format(n=dropped))
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
            hide = bool(needle) and needle not in self._search[row]
            self.table.setRowHidden(row, hide)

    def _report_at(self, row: int) -> MT.MetadataReport | None:
        item = self.table.item(row, 0)
        index = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        return self._reports[index] if isinstance(index, int) else None

    def selected_reports(self) -> list[MT.MetadataReport]:
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        reports = (self._report_at(r) for r in rows if not self.table.isRowHidden(r))
        return [r for r in reports if r is not None]

    def copy_selection(self) -> None:
        reports = self.selected_reports()
        if not reports:
            rows = [r for r in range(self.table.rowCount()) if not self.table.isRowHidden(r)]
            reports = [r for r in (self._report_at(row) for row in rows) if r is not None]
        needle = self.filter_edit.text().strip().lower()
        lines = [line for r in reports for line in _field_lines(r, needle)]
        QApplication.clipboard().setText("\n".join(lines))
        self.status_label.setText(tr("{n} field(s) copied").format(n=len(lines)))

    # -- Properties and the context menu ------------------------------------------
    def open_details(self, row: int) -> None:
        report = self._report_at(row)
        if report is None:
            return
        for details in self.details_dialogs:
            if details.path == report.path:
                details.raise_()
                details.activateWindow()
                return
        details = MetadataDetailsDialog(report, parent=self)
        details.remove_requested.connect(lambda path: self.remove([path]))
        details.destroyed.connect(
            lambda _obj=None, d=details: self.details_dialogs.remove(d)
            if d in self.details_dialogs
            else None
        )
        self.details_dialogs.append(details)
        details.show()

    def _refresh_details(self) -> None:
        by_path = {r.path: r for r in self._reports}
        for details in list(self.details_dialogs):
            report = by_path.get(details.path)
            if report is not None:
                details.set_report(report)

    def build_context_menu(self) -> QMenu:
        menu = QMenu(self)
        selected = self.selected_reports()
        props = menu.addAction(tr("Properties…"))
        props.setEnabled(len(selected) >= 1)
        props.triggered.connect(lambda: self.open_details(self.table.currentRow()))
        copy = menu.addAction(tr("Copy"))
        copy.triggered.connect(self.copy_selection)
        menu.addSeparator()
        remove = menu.addAction(tr("Remove Metadata"))
        paths = [r.path for r in selected]
        remove.setEnabled(bool(paths) and not self.job.running)
        remove.triggered.connect(lambda: self.remove(paths))
        return menu

    def _show_context_menu(self, pos) -> None:
        row = self.table.rowAt(pos.y())
        if row >= 0 and not self.table.selectionModel().isRowSelected(row):
            self.table.selectRow(row)
        self.build_context_menu().exec(self.table.viewport().mapToGlobal(pos))

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
    def remove(self, only: list[str] | None = None) -> None:
        """Remove the metadata of every file listed, or of the paths in
        *only* (the selection, one file's Properties)."""
        if self.job.running:
            return
        wanted = set(only) if only is not None else None
        paths = [
            r.path
            for r in self._reports
            if r.kind and (r.removable or r.error) and (wanted is None or r.path in wanted)
        ]
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
        for details in list(self.details_dialogs):
            details.close()
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Properties of one file
# ---------------------------------------------------------------------------


def _details_html(report: MT.MetadataReport) -> str:
    """Every field of *report*, grouped, one per line. All text is escaped:
    the values come from the file."""
    esc = html.escape
    kept_colour = _KEPT_COLOUR.name()
    rows = []
    if report.error:
        rows.append(
            f'<tr><td colspan="2"><b>{esc(tr("Error"))}:</b> {esc(report.error)}</td></tr>'
        )
    group = None
    for f in report.fields:
        if f.group != group:
            group = f.group
            rows.append(
                '<tr><td colspan="2" style="padding-top:10px">'
                f"<b>{esc(group)}</b></td></tr>"
            )
        value = f.value
        if len(value) > DETAIL_VALUE_CHARS:
            value = value[:DETAIL_VALUE_CHARS] + "… " + tr("({n} more characters)").format(
                n=len(f.value) - DETAIL_VALUE_CHARS
            )
        style = f' style="color:{kept_colour}"' if not f.removable else ""
        note = f' <i>({esc(tr("kept"))})</i>' if not f.removable else ""
        rows.append(
            f'<tr{style}><td valign="top" width="32%">{esc(f.name)}{note}</td>'
            f'<td valign="top">{esc(value).replace(chr(10), "<br>")}</td></tr>'
        )
    if not report.fields and not report.error:
        rows.append(f'<tr><td colspan="2">{esc(tr("no metadata"))}</td></tr>')
    return '<table width="100%" cellspacing="0" cellpadding="3">' + "".join(rows) + "</table>"


class MetadataDetailsDialog(QDialog):
    """Properties of one file: all of its metadata, grouped, one field per
    line with the value wrapped; Copy and Remove Metadata."""

    #: Remove the metadata of the file at this path (the owner does it).
    remove_requested = pyqtSignal(str)

    def __init__(self, report: MT.MetadataReport, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowFlag(Qt.WindowType.Window)
        self.resize(640, 560)
        layout = QVBoxLayout(self)
        self.close_corner = add_close_corner(self)
        self.title = QLabel()
        self.title.setStyleSheet("font-weight: bold")
        self.title.setWordWrap(True)
        layout.addWidget(self.title)
        self.path_label = QLabel()
        self.path_label.setProperty("role", "muted")
        self.path_label.setWordWrap(True)
        self.path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.path_label)
        self.counts_label = QLabel()
        self.counts_label.setProperty("role", "muted")
        layout.addWidget(self.counts_label)
        self.view = QTextBrowser()
        self.view.setOpenLinks(False)
        self.view.setOpenExternalLinks(False)
        self.view.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        layout.addWidget(self.view, stretch=1)
        legend = QLabel(tr("Grey fields are kept when metadata is removed."))
        legend.setProperty("role", "muted")
        layout.addWidget(legend)
        buttons = QHBoxLayout()
        copy = QPushButton(tr("Copy"))
        copy.setToolTip(tr("Copy every field as text"))
        copy.clicked.connect(self.copy_all)
        buttons.addWidget(copy)
        buttons.addStretch(1)
        self.remove_button = QPushButton(tr("Remove Metadata"))
        self.remove_button.clicked.connect(lambda: self.remove_requested.emit(self.path))
        buttons.addWidget(self.remove_button)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        self.set_report(report)

    @property
    def path(self) -> str:
        return self.report.path

    def set_report(self, report: MT.MetadataReport) -> None:
        self.report = report
        self.setWindowTitle(tr("Properties") + f" — {report.name}")
        self.title.setText(report.name)
        self.path_label.setText(report.path)
        self.counts_label.setText(
            tr("{n} field(s), {removable} removable").format(
                n=len(report.fields), removable=report.removable
            )
        )
        scroll = self.view.verticalScrollBar().value()
        self.view.setHtml(_details_html(report))
        self.view.verticalScrollBar().setValue(scroll)
        self.remove_button.setEnabled(bool(report.kind and (report.removable or report.error)))

    def kept_names(self) -> list[str]:
        return [f.name for f in self.report.fields if not f.removable]

    def copy_all(self) -> None:
        QApplication.clipboard().setText("\n".join(_field_lines(self.report)))


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class _MetadataSettingsForm:
    """Write mode and confirmation; :class:`MetadataSettingsPage` (Edit >
    Settings… > Metadata) and :class:`MetadataSettingsDialog` share it."""

    def _build_form(self, layout: QVBoxLayout) -> None:
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

    def _chosen(self) -> tuple[str, bool]:
        mode = MT.MODE_COPY if self.copy_radio.isChecked() else MT.MODE_IN_PLACE
        return mode, self.confirm_box.isChecked()

    def _store(self) -> None:
        mode, confirm = self._chosen()
        MT.set_write_mode(mode)
        MT.set_confirm_before_remove(confirm)


class MetadataSettingsPage(_MetadataSettingsForm, QWidget):
    """Edit > Settings… > Metadata (Tools > Metadata Settings… opens it)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        QWidget.__init__(self, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._build_form(layout)
        layout.addStretch(1)
        self._baseline = self._chosen()

    def is_dirty(self) -> bool:
        return self._chosen() != self._baseline

    def save(self) -> bool:
        self._store()
        self._baseline = self._chosen()
        return True


class MetadataSettingsDialog(_MetadataSettingsForm, QDialog):
    """The metadata settings as a dialog of their own (OK / Cancel)."""

    def __init__(self, parent: QWidget | None = None) -> None:
        QDialog.__init__(self, parent)
        self.setWindowTitle(tr("Metadata Settings"))
        layout = QVBoxLayout(self)
        self._build_form(layout)
        box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        layout.addWidget(box)
        add_close_corner(self)

    def accept(self) -> None:
        self._store()
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
        _fill_fields(self.table, result)
        if result.error:
            self.status_label.setText(result.error)
        else:
            self.status_label.setText(
                tr("{n} field(s), {removable} removable").format(
                    n=len(result.fields), removable=result.removable
                )
            )
        self.remove_button.setEnabled(bool(result.removable or (result.error and result.kind)))


__all__ = [
    "MetadataDetailsDialog",
    "MetadataDialog",
    "MetadataPanel",
    "MetadataSettingsDialog",
    "MetadataSettingsPage",
    "summary_line",
]
