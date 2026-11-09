"""Global metadata search — dialog over :mod:`core.metadata_index`.

The metadata index is a client-side SQLite store populated on demand
by ``index_dir(backend, root, backend_id=...)``. This dialog wraps
two operations:

* **Search** — combine name substring, extension, size range, and
  mtime window via ``search_all``. Results are returned newest-first.
* **Index Current Pane** — walk the active pane's current directory
  (recursively, depth- and entry-capped per ``core.metadata_index``)
  so subsequent searches find what's there. Edit > Index Active Folder…
  opens this window and starts it. The index is one SQLite file,
  :func:`core.metadata_index.default_db_path` (shown in the window).

Searching costs zero network — it's a SQLite SELECT. Indexing is
the expensive step. We keep the two split so a user can search the
index even when offline.
"""

from __future__ import annotations

import logging
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
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
from core.i18n import format_count, tr, tr_n
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob
from ui.handbook import install_help_key
from ui.icon_provider import set_window_icon

log = logging.getLogger("ui.metadata_search_dialog")

#: The most matches the table shows. The search asks the index for one
#: more, to say when there are more (a search for "" listed every row of a
#: large index and filled the table one insertRow at a time).
RESULT_LIMIT = 5000


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
        set_window_icon(self, "find-index")
        install_help_key(self, "index")  # F1: its handbook section (a window of its own)
        self._active_pane = active_pane
        self.setWindowTitle(tr("Find in Index"))
        self.resize(880, 560)
        # The walk can take minutes: it runs in a thread (progress, Cancel, Esc).
        self._job = ScanJob(self)
        self._job.finished.connect(self._on_index_finished)
        # A search runs off the GUI thread too; a new one replaces it.
        self._search_job = ScanJob(self)
        self._search_job.finished.connect(self._on_search_finished)
        self._build_ui()
        self._update_status()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)

        criteria = QGroupBox(tr("Criteria"), self)
        form = QFormLayout(criteria)
        self._needle_edit = QLineEdit()
        self._needle_edit.setPlaceholderText(tr("substring of name (case-insensitive)"))
        # Enter searches through the default button (Search); a
        # returnPressed connection on top searched twice.
        form.addRow(tr("Name contains:"), self._needle_edit)

        self._ext_edit = QLineEdit()
        self._ext_edit.setPlaceholderText(tr("e.g. pdf  (no dot)"))
        form.addRow(tr("Suffix:"), self._ext_edit)

        size_row = QHBoxLayout()
        self._min_size = QSpinBox()
        self._min_size.setRange(0, 2_000_000_000)
        self._min_size.setSuffix(" B")
        self._max_size = QSpinBox()
        self._max_size.setRange(0, 2_000_000_000)
        self._max_size.setSpecialValueText(tr("(no limit)"))
        self._max_size.setSuffix(" B")
        size_row.addWidget(QLabel(tr("min")))
        size_row.addWidget(self._min_size)
        size_row.addWidget(QLabel(tr("max")))
        size_row.addWidget(self._max_size)
        size_row.addStretch(1)
        form.addRow(tr("Size:"), size_row)

        scope_row = QHBoxLayout()
        self._only_active = QCheckBox(tr("Only active pane's backend"))
        scope_row.addWidget(self._only_active)
        scope_row.addStretch(1)
        form.addRow(tr("Scope:"), scope_row)

        root.addWidget(criteria)

        btn_row = QHBoxLayout()
        self._search_btn = QPushButton(tr("Search"), self)
        self._search_btn.setDefault(True)
        self._search_btn.clicked.connect(self._do_search)
        btn_row.addWidget(self._search_btn)

        self._index_btn = QPushButton(tr("Index Current Pane…"), self)
        self._index_btn.clicked.connect(self._do_index_active)
        self._index_btn.setEnabled(self._active_pane is not None)
        btn_row.addWidget(self._index_btn)

        index_path = str(MX.default_db_path())
        self._index_btn.setToolTip(
            tr("Record names, sizes and dates below the active pane's folder.\nStored in {path}")
            .format(path=index_path)
        )
        btn_row.addStretch(1)
        self._status = QLabel("")
        self._status.setProperty("role", "muted")
        btn_row.addWidget(self._status)
        root.addLayout(btn_row)

        # Where the index lives (operator question: "wo und in welcher
        # Datei wird das indexing eigentlich gespeichert?").
        self.location_label = QLabel(tr("Index file: {path}").format(path=index_path), self)
        self.location_label.setProperty("role", "muted")
        self.location_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(self.location_label)

        self._table = QTableWidget(0, 5, self)
        self._table.setHorizontalHeaderLabels([tr("Name"), tr("Path"), tr("Size"), tr("Modified"), tr("Backend")])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        from ui.column_fit import ColumnFitter

        # Path takes the free width, Name keeps its content; every divider
        # stays draggable.
        self._columns = ColumnFitter(self._table, fill=1, keep=(0,))
        self._table.doubleClicked.connect(self._on_row_activated)
        root.addWidget(self._table, stretch=1)

        # One status line at the bottom while an index run is going.
        self._strip = BusyStrip(self._job, self)
        self._busy_bar = self._strip.bar
        self._progress_label = self._strip.label
        self._cancel_btn = self._strip.cancel_button
        self._job.started.connect(lambda: self._index_btn.setEnabled(False))
        root.addWidget(self._strip)

        close_btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Close,
            self,
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
        kwargs["limit"] = RESULT_LIMIT + 1
        self._status.setText(tr("Searching…"))
        self._search_job.start(lambda cancel, _progress: MX.search_all(cancel=cancel, **kwargs),
                               replace=True)

    def _on_search_finished(self, kind: str, value, cancelled: bool) -> None:
        if cancelled:
            return
        if kind == "error":
            QMessageBox.warning(self, tr("Search"), tr("Search failed:\n{value}").format(value=value))
            self._update_status()
            return
        self._populate(value)

    def _populate(self, entries: list) -> None:
        """Fill the table in one pass: the row count set once, painting off
        while the items go in (insertRow per entry froze the window on a
        large result)."""
        more = len(entries) > RESULT_LIMIT
        entries = entries[:RESULT_LIMIT]
        table = self._table
        sorting = table.isSortingEnabled()
        table.setSortingEnabled(False)
        table.setUpdatesEnabled(False)
        try:
            table.clearContents()
            table.setRowCount(len(entries))
            for row, e in enumerate(entries):
                name_item = QTableWidgetItem(e.name)
                name_item.setData(Qt.ItemDataRole.UserRole, e)
                table.setItem(row, 0, name_item)
                table.setItem(row, 1, QTableWidgetItem(e.path))
                table.setItem(row, 2, QTableWidgetItem(_format_size(e.size)))
                table.setItem(row, 3, QTableWidgetItem(_format_when(e.modified)))
                table.setItem(row, 4, QTableWidgetItem(e.backend_id))
        finally:
            table.setUpdatesEnabled(True)
            table.setSortingEnabled(sorting)
        self._update_status(found=len(entries), more=more)

    def start_index_active(self) -> None:
        """Index the active pane's folder (Edit > Index Active Folder…)."""
        self._do_index_active()

    def _do_index_active(self) -> None:
        pane = self._active_pane
        if pane is None:
            return
        backend = pane.backend
        path = pane.current_path
        bid = _backend_id_for(backend)
        if self._job.running and not self._job.cancelling:
            return  # an index run is already going
        where = getattr(backend, "name", "") or type(backend).__name__
        reply = QMessageBox.question(
            self,
            tr("Index Folder"),
            tr("Add every file and folder in\n{path}\n({where}) to the search index?\n\n"
               "Subfolders are included, up to {depth} levels deep and {entries} entries "
               "in all.").format(path=path, where=where, depth=MX.MAX_WALK_DEPTH,
                                 entries=format_count(MX.MAX_WALK_ENTRIES)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._index_root = path
        self._job.start(
            lambda cancel, progress: MX.reindex_dir(
                backend, path, backend_id=bid, cancel=cancel, progress=progress
            )
        )

    def _on_index_finished(self, kind: str, value, cancelled: bool) -> None:
        self._index_btn.setEnabled(self._active_pane is not None)
        path = self._index_root
        if kind == "error":
            QMessageBox.warning(self, tr("Index Folder"),
                                tr("Indexing failed:\n{error}").format(error=value))
            return
        indexed, removed = value if isinstance(value, tuple) else (value, 0)
        if cancelled:
            text = tr_n(indexed, "Cancelled – {n} entry indexed so far under {path}.",
                        "Cancelled – {n} entries indexed so far under {path}.", path=path)
        else:
            text = tr_n(indexed, "Indexed {n} entry under {path}.",
                        "Indexed {n} entries under {path}.", path=path)
            if removed:
                text += "\n" + tr_n(removed, "Removed {n} entry that no longer exists.",
                                     "Removed {n} entries that no longer exist.")
        QMessageBox.information(self, tr("Index Folder"), text)
        self._update_status()

    def reject(self) -> None:
        # Esc, Close and the window's own close must stop a running index.
        self._job.abandon()
        self._search_job.abandon()
        super().reject()

    def closeEvent(self, event) -> None:
        self._job.abandon()
        self._search_job.abandon()
        super().closeEvent(event)

    def _update_status(self, found: int | None = None, more: bool = False) -> None:
        try:
            total = MX.row_count()
        except Exception:
            total = 0
        in_index = tr_n(total, "{n} entry in index", "{n} entries in index")
        if found is None:
            self._status.setText(in_index)
        elif more:
            self._status.setText(
                tr("Showing the first {n} matches – there are more; narrow the search.").format(
                    n=format_count(found)) + "  ·  " + in_index)
        else:
            self._status.setText(
                tr_n(found, "{n} match", "{n} matches") + "  ·  " + in_index)

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
