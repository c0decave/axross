"""Global metadata search — dialog over :mod:`core.metadata_index`.

The metadata index is a client-side SQLite store populated on demand
by ``index_dir(backend, root, backend_id=...)``. This dialog wraps
two operations:

* **Search** — combine name substring, extension, size range, and
  mtime window via ``search_all``. Results are returned newest-first.
* **Index Current Pane** — walk the active pane's current directory
  (recursively, depth- and entry-capped per ``core.metadata_index``)
  so subsequent searches find what's there.

Searching costs zero network — it's a SQLite SELECT. Indexing is
the expensive step. We keep the two split so a user can search the
index even when offline.
"""
from __future__ import annotations

import logging
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import metadata_index as MX

log = logging.getLogger("ui.metadata_search_dialog")


def _format_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n:.0f} PiB"


def _format_when(when) -> str:
    if isinstance(when, datetime):
        return when.strftime("%Y-%m-%d %H:%M")
    return str(when) if when else ""


def _backend_id_for(backend) -> str:
    """Stable id we use as the index key. Matches what we'd pass to
    ``metadata_index.index_dir(backend_id=...)`` when indexing the
    current pane: ``<class_name>:<backend.name>``. Stable across
    sessions for the same connection profile."""
    cls = type(backend).__name__
    name = getattr(backend, "name", "") or ""
    return f"{cls}:{name}" if name else cls


class MetadataSearchDialog(QDialog):
    """Dialog: search inputs + results table + per-backend indexer."""

    # Emitted when the user double-clicks a row. Caller can route the
    # active pane there. Args: (backend_id, path, is_dir).
    open_requested = pyqtSignal(str, str, bool)

    def __init__(self, active_pane=None, parent=None) -> None:
        super().__init__(parent)
        self._active_pane = active_pane
        self.setWindowTitle("Find in Index")
        self.resize(880, 560)
        self._build_ui()
        self._update_status()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        criteria = QGroupBox("Criteria", self)
        form = QFormLayout(criteria)
        self._needle_edit = QLineEdit()
        self._needle_edit.setPlaceholderText("substring of name (case-insensitive)")
        self._needle_edit.returnPressed.connect(self._do_search)
        form.addRow("Name contains:", self._needle_edit)

        self._ext_edit = QLineEdit()
        self._ext_edit.setPlaceholderText("e.g. pdf  (no dot)")
        form.addRow("Extension:", self._ext_edit)

        size_row = QHBoxLayout()
        self._min_size = QSpinBox()
        self._min_size.setRange(0, 2_000_000_000)
        self._min_size.setSuffix(" B")
        self._max_size = QSpinBox()
        self._max_size.setRange(0, 2_000_000_000)
        self._max_size.setSpecialValueText("(no limit)")
        self._max_size.setSuffix(" B")
        size_row.addWidget(QLabel("min"))
        size_row.addWidget(self._min_size)
        size_row.addWidget(QLabel("max"))
        size_row.addWidget(self._max_size)
        size_row.addStretch(1)
        form.addRow("Size:", size_row)

        scope_row = QHBoxLayout()
        self._only_active = QCheckBox("Only active pane's backend")
        scope_row.addWidget(self._only_active)
        scope_row.addStretch(1)
        form.addRow("Scope:", scope_row)

        root.addWidget(criteria)

        btn_row = QHBoxLayout()
        self._search_btn = QPushButton("Search", self)
        self._search_btn.setDefault(True)
        self._search_btn.clicked.connect(self._do_search)
        btn_row.addWidget(self._search_btn)

        self._index_btn = QPushButton("Index Current Pane…", self)
        self._index_btn.clicked.connect(self._do_index_active)
        self._index_btn.setEnabled(self._active_pane is not None)
        btn_row.addWidget(self._index_btn)

        btn_row.addStretch(1)
        self._status = QLabel("")
        self._status.setStyleSheet("color: #666;")
        btn_row.addWidget(self._status)
        root.addLayout(btn_row)

        self._table = QTableWidget(0, 5, self)
        self._table.setHorizontalHeaderLabels(
            ["Name", "Path", "Size", "Modified", "Backend"]
        )
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.doubleClicked.connect(self._on_row_activated)
        root.addWidget(self._table, stretch=1)

        close_btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Close, self,
        )
        close_btns.rejected.connect(self.reject)
        close_btns.accepted.connect(self.accept)
        root.addWidget(close_btns)

    # ------------------------------------------------------------------
    # Index / search actions
    # ------------------------------------------------------------------
    def _do_search(self) -> None:
        kwargs = {
            "needle": self._needle_edit.text().strip() or None,
            "ext": self._ext_edit.text().strip() or None,
            "min_size": int(self._min_size.value()),
            "max_size": int(self._max_size.value()) if self._max_size.value() > 0 else None,
        }
        if self._only_active.isChecked() and self._active_pane is not None:
            kwargs["backend_id"] = _backend_id_for(self._active_pane.backend)
        try:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            try:
                entries = MX.search_all(**kwargs)
            finally:
                QApplication.restoreOverrideCursor()
        except Exception as exc:  # noqa: BLE001 — surface DB errors
            QMessageBox.warning(
                self, "Search", f"Search failed:\n{exc}",
            )
            return
        self._populate(entries)

    def _populate(self, entries: list) -> None:
        self._table.setRowCount(0)
        for e in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            name_item = QTableWidgetItem(e.name)
            name_item.setData(Qt.ItemDataRole.UserRole, e)
            self._table.setItem(row, 0, name_item)
            self._table.setItem(row, 1, QTableWidgetItem(e.path))
            self._table.setItem(row, 2, QTableWidgetItem(_format_size(e.size)))
            self._table.setItem(row, 3, QTableWidgetItem(_format_when(e.modified)))
            self._table.setItem(row, 4, QTableWidgetItem(e.backend_id))
        self._update_status(found=len(entries))

    def _do_index_active(self) -> None:
        pane = self._active_pane
        if pane is None:
            return
        backend = pane.backend
        path = pane.current_path
        bid = _backend_id_for(backend)
        reply = QMessageBox.question(
            self, "Index Pane",
            f"Walk and index every entry under\n{path}\n"
            f"on backend [{bid}]?\n\nDepth- and entry-capped per "
            "core.metadata_index defaults.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        # Single push + single pop discipline (see file_pane._show_checksum).
        error: Exception | None = None
        added = 0
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            try:
                added = MX.index_dir(backend, path, backend_id=bid)
            except Exception as exc:  # noqa: BLE001 — surface to user
                error = exc
        finally:
            QApplication.restoreOverrideCursor()
        if error is not None:
            QMessageBox.warning(
                self, "Index", f"Indexing failed:\n{error}",
            )
            return
        QMessageBox.information(
            self, "Index", f"Indexed {added} entries under {path}.",
        )
        self._update_status()

    def _update_status(self, found: int | None = None) -> None:
        try:
            total = MX.row_count()
        except Exception:
            total = 0
        if found is None:
            self._status.setText(f"{total} entries in index")
        else:
            self._status.setText(
                f"{found} match{'es' if found != 1 else ''}  ·  "
                f"{total} entries in index"
            )

    def _on_row_activated(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            return
        item = self._table.item(row, 0)
        if item is None:
            return
        e = item.data(Qt.ItemDataRole.UserRole)
        if e is None:
            return
        self.open_requested.emit(e.backend_id, e.path, bool(e.is_dir))
