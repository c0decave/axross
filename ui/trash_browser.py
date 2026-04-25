"""Trash browser dialog — list / restore / empty.

Thin wrapper over :mod:`core.trash`. Presents the entries for a
single backend in a table, with Restore / Permanently-Delete /
Empty-Trash buttons. Each action goes straight to the backend;
failures collect per-item and get shown once at the end.
"""
from __future__ import annotations

import logging
from datetime import datetime

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import trash as T

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
        self._backend = backend
        self.setWindowTitle(
            f"Trash — {getattr(backend, 'name', type(backend).__name__)}"
        )
        self.resize(720, 420)
        self._build_ui()
        self._reload()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        self._info = QLabel("")
        root.addWidget(self._info)

        self._table = QTableWidget(0, 4, self)
        self._table.setHorizontalHeaderLabels(
            ["Original Path", "Size", "Trashed At", "ID"]
        )
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setSelectionMode(
            QTableWidget.SelectionMode.ExtendedSelection
        )
        self._table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(self._table, stretch=1)

        btn_row = QHBoxLayout()
        self._restore_btn = QPushButton("Restore")
        self._restore_btn.clicked.connect(self._do_restore)
        btn_row.addWidget(self._restore_btn)

        self._delete_btn = QPushButton("Delete Permanently")
        self._delete_btn.clicked.connect(self._do_delete_permanent)
        btn_row.addWidget(self._delete_btn)

        self._empty_btn = QPushButton("Empty Trash")
        self._empty_btn.clicked.connect(self._do_empty)
        btn_row.addWidget(self._empty_btn)

        btn_row.addStretch(1)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        close.accepted.connect(self.accept)
        btn_row.addWidget(close)

        root.addLayout(btn_row)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def _reload(self) -> None:
        try:
            entries = T.list_trash(self._backend)
        except OSError as exc:
            QMessageBox.warning(
                self, "Trash",
                f"Could not list trash:\n{exc}",
            )
            entries = []
        self._table.setRowCount(0)
        for e in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            path_item = QTableWidgetItem(e.original_path)
            # Stash the entry on the row so buttons can grab it back.
            path_item.setData(Qt.ItemDataRole.UserRole, e)
            self._table.setItem(row, 0, path_item)
            self._table.setItem(row, 1, QTableWidgetItem(_format_size(e.size)))
            when = e.trashed_at.strftime("%Y-%m-%d %H:%M:%S") \
                if isinstance(e.trashed_at, datetime) else str(e.trashed_at)
            self._table.setItem(row, 2, QTableWidgetItem(when))
            self._table.setItem(row, 3, QTableWidgetItem(e.trash_id))
        self._info.setText(
            f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} "
            f"in trash."
        )

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
    # Actions
    # ------------------------------------------------------------------
    def _do_restore(self) -> None:
        entries = self._selected_entries()
        if not entries:
            QMessageBox.information(
                self, "Restore", "Select at least one entry to restore.",
            )
            return
        errors: list[str] = []
        restored = 0
        for e in entries:
            try:
                T.restore(self._backend, e.trash_id)
                restored += 1
            except OSError as exc:
                errors.append(f"{e.original_path}: {exc}")
                log.warning("Restore failed for %s: %s", e.trash_id, exc)
        self._reload()
        if errors:
            QMessageBox.warning(
                self, "Restore",
                f"{restored} restored, {len(errors)} failed:\n"
                + "\n".join(errors[:10]),
            )

    def _do_delete_permanent(self) -> None:
        entries = self._selected_entries()
        if not entries:
            return
        reply = QMessageBox.question(
            self, "Delete Permanently",
            f"Delete {len(entries)} entr"
            f"{'y' if len(entries) == 1 else 'ies'} "
            f"from trash permanently? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        errors: list[str] = []
        for e in entries:
            data_file = self._backend.join(
                self._trash_root(), e.trash_id,
            )
            meta_file = self._backend.join(
                self._trash_root(), e.trash_id + T.META_SUFFIX,
            )
            try:
                self._backend.remove(data_file, recursive=True)
            except OSError as exc:
                errors.append(f"{e.original_path} data: {exc}")
            try:
                self._backend.remove(meta_file)
            except OSError as exc:
                errors.append(f"{e.original_path} meta: {exc}")
        self._reload()
        if errors:
            QMessageBox.warning(
                self, "Delete Permanent",
                "\n".join(errors[:10]),
            )

    def _do_empty(self) -> None:
        reply = QMessageBox.question(
            self, "Empty Trash",
            "Permanently delete ALL entries from trash?\n"
            "This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            removed = T.empty_trash(self._backend)
        except OSError as exc:
            QMessageBox.warning(
                self, "Empty Trash", f"Failed:\n{exc}",
            )
            return
        self._reload()
        QMessageBox.information(
            self, "Empty Trash", f"Removed {removed} entr"
            f"{'y' if removed == 1 else 'ies'}.",
        )

    def _trash_root(self) -> str:
        """Resolve the backend's trash root (same logic as core.trash)."""
        try:
            base = self._backend.home()
        except Exception:
            base = "/"
        if not base:
            base = "/"
        return self._backend.join(base, T.TRASH_DIRNAME)
