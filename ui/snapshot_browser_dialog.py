"""Snapshot/Versions browser — dialog over :mod:`core.snapshot_browser`.

Backends with native versioning (S3 with bucket versioning enabled,
Azure Blob versioning, Dropbox, Google Drive, OneDrive, WebDAV with
DeltaV) return a list of :class:`FileVersion` from
``backend.list_versions(path)``. This dialog renders that list as a
timeline and lets the user:

* **Save Version As…**  — stream the historical bytes to a local
  file via QFileDialog. Safe default: never overwrites the live
  path on the backend.
* **Restore as Current** — read the historical bytes and write them
  back to the live path via ``backend.open_write``. Confirmation
  required because this is destructive on the backend.

Backends without versioning return an empty list — the dialog shows
"No versions reported" and disables the action buttons.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import snapshot_browser as SB
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob

log = logging.getLogger("ui.snapshot_browser_dialog")


def _basename(path: str) -> str:
    """Return the last segment of *path*, robust against trailing
    separators and against backends that mix / and \\ (SMB, Azure
    Files). Returns empty string for paths that are nothing but
    separators (caller should substitute a fallback)."""
    cleaned = path.rstrip("/\\")
    if not cleaned:
        return ""
    # Find the rightmost separator across both styles.
    last_slash = cleaned.rfind("/")
    last_back = cleaned.rfind("\\")
    sep_pos = max(last_slash, last_back)
    return cleaned[sep_pos + 1 :] if sep_pos >= 0 else cleaned


def _format_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n:.0f} PiB"


def _format_when(when: datetime) -> str:
    if isinstance(when, datetime):
        return when.strftime("%Y-%m-%d %H:%M:%S")
    return str(when)


class SnapshotBrowserDialog(QDialog):
    """Versions table for a single (backend, path) pair."""

    def __init__(self, backend, path: str, parent=None) -> None:
        super().__init__(parent)
        self._backend = backend
        self._path = path
        backend_name = getattr(backend, "name", type(backend).__name__)
        self.setWindowTitle(f"Versions — {path} [{backend_name}]")
        self.resize(820, 460)
        self._entries: list = []
        # Saving / restoring a version streams the whole file: it runs in a
        # thread with a progress line, and Cancel / Esc / Close stop it.
        self._job = ScanJob(self, formatter=lambda st: f"Copying… {_format_size(st['scanned'])}")
        self._job.finished.connect(self._on_job_finished)
        self._job_ctx: dict = {}
        self._build_ui()
        self._reload()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)

        self._info = QLabel(self._path)
        self._info.setProperty("role", "muted")
        self._info.setWordWrap(True)
        root.addWidget(self._info)

        self._table = QTableWidget(0, 5, self)
        self._table.setHorizontalHeaderLabels(
            ["Modified", "Size", "Label", "Version ID", "Current"]
        )
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        from ui.column_fit import ColumnFitter

        # Label takes the free width; every divider stays draggable.
        self._columns = ColumnFitter(self._table, fill=2)
        root.addWidget(self._table, stretch=1)

        btn_row = QHBoxLayout()
        self._save_btn = QPushButton("Save Version As…", self)
        self._save_btn.clicked.connect(self._save_as_selected)
        btn_row.addWidget(self._save_btn)

        self._restore_btn = QPushButton("Restore as Current", self)
        self._restore_btn.clicked.connect(self._restore_selected)
        btn_row.addWidget(self._restore_btn)

        btn_row.addStretch(1)

        self._strip = BusyStrip(self._job, self, cancel_text="Cancel")
        self._busy_bar = self._strip.bar
        self._progress_label = self._strip.label
        self._cancel_btn = self._strip.cancel_button
        self._job.started.connect(lambda: self._set_actions_enabled(False))
        root.addWidget(self._strip)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        close.accepted.connect(self.accept)
        btn_row.addWidget(close)
        root.addLayout(btn_row)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def _reload(self) -> None:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self._entries = SB.browse(self._backend, self._path)
        finally:
            QApplication.restoreOverrideCursor()

        self._table.setRowCount(0)
        for e in self._entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            when_item = QTableWidgetItem(_format_when(e.modified))
            when_item.setData(Qt.ItemDataRole.UserRole, e)
            self._table.setItem(row, 0, when_item)
            self._table.setItem(row, 1, QTableWidgetItem(_format_size(e.size)))
            self._table.setItem(row, 2, QTableWidgetItem(e.label))
            self._table.setItem(row, 3, QTableWidgetItem(e.version_id))
            self._table.setItem(
                row,
                4,
                QTableWidgetItem("yes" if e.is_current else ""),
            )

        self._info.setText(
            f"{self._path}  —  {len(self._entries)} version{'' if len(self._entries) == 1 else 's'}"
        )
        has_entries = bool(self._entries)
        self._save_btn.setEnabled(has_entries)
        self._restore_btn.setEnabled(has_entries)

    def _selected_entry(self):
        rows = {idx.row() for idx in self._table.selectedIndexes()}
        if not rows:
            return None
        item = self._table.item(next(iter(sorted(rows))), 0)
        if item is None:
            return None
        return item.data(Qt.ItemDataRole.UserRole)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _save_as_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            QMessageBox.information(
                self,
                "Save Version",
                "Select a version row first.",
            )
            return
        suggested = f"{_basename(self._path) or 'file'}.{entry.version_id[:12]}"
        target, _ = QFileDialog.getSaveFileName(
            self,
            "Save Version As",
            suggested,
        )
        if not target:
            return
        self._job_ctx = {"op": "save", "entry": entry, "target": target}

        def work(cancel, progress) -> int:
            # Copied into a sibling temp file and moved over the target only
            # when complete: a failed or cancelled save must not cost the
            # user the file they chose to replace.
            done = 0
            folder, name = os.path.split(target)
            partial = os.path.join(folder, f".{name}.{uuid.uuid4().hex[:12]}.part")
            try:
                with SB.read_snapshot(entry) as src, open(partial, "xb") as dst:
                    while True:
                        if cancel():
                            break
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        dst.write(chunk)
                        done += len(chunk)
                        progress(done, 0, "")
            except BaseException:
                self._remove_partial(partial)
                raise
            if cancel():
                self._remove_partial(partial)
                return done
            try:
                os.replace(partial, target)
            except BaseException:
                self._remove_partial(partial)
                raise
            return done

        self._job.start(work)

    @staticmethod
    def _remove_partial(target: str) -> None:
        try:
            os.unlink(target)
        except OSError:
            pass

    def _set_actions_enabled(self, enabled: bool) -> None:
        self._save_btn.setEnabled(enabled)
        self._restore_btn.setEnabled(enabled)

    def _on_job_finished(self, kind: str, value, cancelled: bool) -> None:
        self._set_actions_enabled(True)
        ctx = self._job_ctx
        entry = ctx.get("entry")
        if ctx.get("op") == "save":
            title, failed = "Save Version", "Could not save version"
            done_text = f"Saved version {entry.version_id} → {ctx.get('target')}"
        else:
            title, failed = "Restore Version", "Restore failed"
            done_text = (
                f"Restored version {entry.version_id} as the current contents of {self._path}."
            )
        if kind == "error":
            QMessageBox.warning(self, title, f"{failed}:\n{value}")
            return
        if cancelled:
            QMessageBox.information(self, title, "Cancelled — nothing was changed.")
            return
        QMessageBox.information(self, title, done_text)
        if ctx.get("op") == "restore":
            self._reload()

    def reject(self) -> None:
        # Esc, Close and the window's own close stop a running copy.
        self._job.abandon()
        super().reject()

    def closeEvent(self, event) -> None:
        self._job.abandon()
        super().closeEvent(event)

    def _restore_selected(self) -> None:
        entry = self._selected_entry()
        if entry is None:
            QMessageBox.information(
                self,
                "Restore Version",
                "Select a version row first.",
            )
            return
        if entry.is_current:
            QMessageBox.information(
                self,
                "Restore Version",
                "That entry is already the current version.",
            )
            return
        reply = QMessageBox.question(
            self,
            "Restore Version",
            f"Overwrite the current contents of\n{self._path}\n"
            f"with version {entry.version_id} ({_format_when(entry.modified)})?\n\n"
            "This is destructive on the backend.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._job_ctx = {"op": "restore", "entry": entry}
        backend, path = self._backend, self._path

        def work(cancel, progress) -> int:
            from core.atomic_io import atomic_write_stream

            class _Stop(OSError):
                pass

            def on_chunk(done: int) -> None:
                progress(done, 0, "")
                if cancel():
                    # raising unwinds atomic_write_stream, which discards its temp file
                    raise _Stop("cancelled")

            try:
                with SB.read_snapshot(entry) as src:
                    return atomic_write_stream(
                        backend, path, src, chunk_size=1024 * 1024, on_chunk=on_chunk
                    )
            except _Stop:
                return 0

        self._job.start(work)
