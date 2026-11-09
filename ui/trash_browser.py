"""Trash browser dialog — list / restore / empty.

Thin wrapper over :mod:`core.trash`. Presents the entries for a
single backend in a table, with Restore / Permanently-Delete /
Empty-Trash buttons. Each action runs on a background job (one at a
time, with a status strip and Cancel between entries), so a large
trashed folder on a slow share does not freeze the window; failures
collect per-item and get shown once at the end.

The listing loads on its own background job too (one listing plus one
sidecar read per entry, which on a slow share took long enough to freeze
the window before it showed): the window opens at once with "Loading the
trash…", the action buttons wait for the rows, and a newer load supersedes
an older one, whose result is dropped.
"""

from __future__ import annotations

import logging
from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import trash as T
from core.i18n import tr, tr_n
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob, shorten
from ui.icon_provider import set_window_icon

log = logging.getLogger("ui.trash_browser")


def _format_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n:.0f} PiB"


class TrashBrowserDialog(QDialog):
    """List core.trash entries for *backend* and allow restore / empty."""

    def __init__(self, backend, parent=None) -> None:
        super().__init__(parent)
        set_window_icon(self, "trash")
        self._backend = backend
        self.setWindowTitle(tr("Trash — {name}").format(
            name=getattr(backend, "name", type(backend).__name__)))
        self.resize(720, 420)
        self._build_ui()
        self._reload()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)
        # F1: the handbook (its contents) - the main window's F1 does not reach this window.
        from ui.handbook import install_help_key

        install_help_key(self)

        self._info = QLabel("")
        root.addWidget(self._info)

        self._table = QTableWidget(0, 4, self)
        self._table.setHorizontalHeaderLabels([tr("Original Path"), tr("Size"), tr("Trashed At"), tr("ID")])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        from ui.column_fit import ColumnFitter

        # Original Path takes the free width; every divider stays draggable.
        self._columns = ColumnFitter(self._table, fill=0)
        root.addWidget(self._table, stretch=1)

        btn_row = QHBoxLayout()
        self._restore_btn = QPushButton(tr("Restore"))
        self._restore_btn.clicked.connect(self._do_restore)
        btn_row.addWidget(self._restore_btn)

        self._delete_btn = QPushButton(tr("Delete Permanently"))
        self._delete_btn.clicked.connect(self._do_delete_permanent)
        btn_row.addWidget(self._delete_btn)

        self._empty_btn = QPushButton(tr("Empty Trash"))
        self._empty_btn.clicked.connect(self._do_empty)
        btn_row.addWidget(self._empty_btn)

        btn_row.addStretch(1)

        # One background action at a time; its status line sits above the
        # buttons, and the action buttons are off while it runs.
        self._job = ScanJob(self, formatter=self._progress_text)
        self._job.finished.connect(self._on_job_finished)
        self._busy_strip = BusyStrip(self._job, self, cancel_text=tr("Cancel"))
        root.addWidget(self._busy_strip)
        self._on_done = None
        # The listing has its own job: replacing a running load drops the
        # older result, so a slow, stale listing never overwrites a newer one.
        self._load_job = ScanJob(self)
        self._load_job.finished.connect(self._on_loaded)
        self._loading = False

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        close.accepted.connect(self.accept)
        btn_row.addWidget(close)

        root.addLayout(btn_row)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    @property
    def loading(self) -> bool:
        """The listing is being read in the background."""
        return self._loading

    def _reload(self) -> None:
        """Read the trash listing off the GUI thread; the rows are filled by
        :meth:`_on_loaded`. A load already running is superseded."""
        backend = self._backend

        def work(_cancelled, _report):
            return T.list_trash(backend)

        self._loading = True
        self._update_buttons()
        self._info.setText(tr("Loading the trash…"))
        self._load_job.start(work, replace=True)

    def _on_loaded(self, kind: str, value, _cancelled: bool) -> None:
        self._loading = False
        self._update_buttons()
        if kind == "error":
            log.warning("Could not list the trash: %s", value)
            self._fill([])
            QMessageBox.warning(
                self,
                tr("Trash"),
                tr("Could not list trash:\n{error}").format(error=value),
            )
            return
        self._fill(value)

    def _fill(self, entries) -> None:
        self._table.setRowCount(0)
        for e in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            path_item = QTableWidgetItem(e.original_path)
            # Stash the entry on the row so buttons can grab it back.
            path_item.setData(Qt.ItemDataRole.UserRole, e)
            self._table.setItem(row, 0, path_item)
            self._table.setItem(row, 1, QTableWidgetItem(_format_size(e.size)))
            when = (
                e.trashed_at.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(e.trashed_at, datetime)
                else str(e.trashed_at)
            )
            self._table.setItem(row, 2, QTableWidgetItem(when))
            self._table.setItem(row, 3, QTableWidgetItem(e.trash_id))
        self._info.setText(tr_n(len(entries), "{n} entry in trash.", "{n} entries in trash."))

    def _selected_entries(self) -> list:
        out = []
        rows = {idx.row() for idx in self._table.selectedIndexes()}
        for row in sorted(rows):
            item = self._table.item(row, 0)
            if item is None:
                continue
            entry = item.data(Qt.ItemDataRole.UserRole)
            if entry is not None:
                out.append(entry)
        return out

    # ------------------------------------------------------------------
    # Background job
    # ------------------------------------------------------------------
    @property
    def busy(self) -> bool:
        """An action of this dialog, or its listing, runs in the background."""
        return self._on_done is not None or self._loading

    def _update_buttons(self) -> None:
        # An action needs the current rows and runs one at a time.
        enabled = not self.busy
        for button in (self._restore_btn, self._delete_btn, self._empty_btn):
            button.setEnabled(enabled)

    def _progress_text(self, state: dict) -> str:
        return (
            tr("Working… {scanned} of {indexed} — {path}").format(
                scanned=state['scanned'], indexed=state['indexed'], path=shorten(state['path']))
        )

    def _run(self, work, on_done) -> bool:
        """Start *work(cancelled, report)* in the background; *on_done(kind,
        value, cancelled)* runs on the GUI thread when it ends. Refused
        while another action runs."""
        if self.busy:
            return False
        self._on_done = on_done
        self._update_buttons()
        self._job.start(work)
        return True

    def _on_job_finished(self, kind: str, value, cancelled: bool) -> None:
        on_done, self._on_done = self._on_done, None
        self._reload()
        if on_done is not None:
            on_done(kind, value, cancelled)

    def done(self, result: int) -> None:  # noqa: D102 - Qt override
        # Closing while an action runs: it stops after the entry in progress
        # and nothing is reported to a dialog that is gone.
        self._job.abandon()
        self._load_job.abandon()
        self._on_done = None
        self._loading = False
        super().done(result)

    def _per_entry(self, entries, action):
        """Work for the job: *action(entry)* for each entry; an OSError is
        collected, Cancel stops between entries. Returns (done, errors)."""

        def work(cancelled, report):
            done, errors = 0, []
            for index, entry in enumerate(entries):
                if cancelled():
                    break
                report(index, len(entries), entry.original_path)
                errors_before = len(errors)
                action(entry, errors)
                if len(errors) == errors_before:
                    done += 1
            return done, errors

        return work

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _do_restore(self) -> None:
        if self.busy:
            return
        entries = self._selected_entries()
        if not entries:
            QMessageBox.information(
                self,
                tr("Restore"),
                tr("Select at least one entry to restore."),
            )
            return
        backend = self._backend

        def restore(entry, errors) -> None:
            try:
                T.restore(backend, entry.trash_id)
            except OSError as exc:
                errors.append(f"{entry.original_path}: {exc}")
                log.warning("Restore failed for %s: %s", entry.trash_id, exc)

        def done(kind, value, cancelled) -> None:
            if kind == "error":
                QMessageBox.warning(self, tr("Restore"), tr("Failed:\n{value}").format(value=value))
                return
            restored, errors = value
            if errors:
                QMessageBox.warning(
                    self,
                    tr("Restore"),
                    tr("{restored} restored, {failed} failed:\n").format(
                        restored=restored, failed=len(errors)) + "\n".join(errors[:10]),
                )

        self._run(self._per_entry(entries, restore), done)

    def _do_delete_permanent(self) -> None:
        if self.busy:
            return
        entries = self._selected_entries()
        if not entries:
            return
        reply = QMessageBox.question(
            self,
            tr("Delete Permanently"),
            tr_n(len(entries), "Delete {n} entry from trash permanently? This cannot be undone.",
                 "Delete {n} entries from trash permanently? This cannot be undone."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        backend, trash_root = self._backend, self._trash_root()

        def delete(entry, errors) -> None:
            # core.trash.delete_entry: the data first, the sidecar only once
            # it is gone. Both went regardless: data that could not be
            # removed lost its sidecar and vanished from this list, still
            # on disk. Now the entry stays listed, with the error.
            try:
                T.delete_entry(backend, entry.trash_id, root=trash_root)
            except OSError as exc:
                errors.append(f"{entry.original_path}: {exc}")

        def done(kind, value, cancelled) -> None:
            if kind == "error":
                QMessageBox.warning(self, tr("Delete Permanent"), tr("Failed:\n{value}").format(value=value))
                return
            _deleted, errors = value
            if errors:
                QMessageBox.warning(self, tr("Delete Permanent"), "\n".join(errors[:10]))

        self._run(self._per_entry(entries, delete), done)

    def _do_empty(self) -> None:
        if self.busy:
            return
        reply = QMessageBox.question(
            self,
            tr("Empty Trash"),
            tr("Permanently delete ALL entries from trash?\nThis cannot be undone."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        backend = self._backend

        def work(cancelled, report):
            report(0, 1, tr("emptying the trash"))
            return T.empty_trash(backend)

        def done(kind, value, cancelled) -> None:
            if kind == "error":
                QMessageBox.warning(self, tr("Empty Trash"), tr("Failed:\n{value}").format(value=value))
                return
            QMessageBox.information(
                self,
                tr("Empty Trash"),
                tr_n(value, "Removed {n} entry.", "Removed {n} entries."),
            )

        self._run(work, done)

    def _trash_root(self) -> str:
        """Resolve the backend's trash root (same logic as core.trash)."""
        try:
            base = self._backend.home()
        except Exception:
            base = "/"
        if not base:
            base = "/"
        return self._backend.join(base, T.TRASH_DIRNAME)
