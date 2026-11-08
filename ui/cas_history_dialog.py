"""Duplicate Index & History — the Duplicate Finder's index on its own.

Every rebuild of the duplicate index is recorded as a scan
(:func:`core.cas.list_scans`). This view lists them — root, backend,
started / finished, files indexed, files still in the index, duplicate
groups, status — and acts on one scan or on the whole index:

* **Show Duplicates** — the finder, limited to that scan's groups
  (:attr:`CasHistoryDialog.show_duplicates_requested`).
* **Re-scan** — rebuild the same root on the same backend, in the
  background with progress and Cancel; a new scan is recorded.
* **Remove from Index…** — forget that scan's rows; files are untouched.
* **Clear Whole Index…** — forget everything; files are untouched.

Rows indexed before scans were recorded form one "earlier scans" entry:
it can be shown and removed, not re-scanned (its root is unknown).
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from core import cas as CAS
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob
from ui.icon_provider import set_window_icon
from core.i18n import tr, tr_n

log = logging.getLogger("ui.cas_history_dialog")

COLUMNS = (
    "Scan",
    "Root",
    "Backend",
    "Started",
    "Finished",
    "Files",
    "In index",
    "Duplicate groups",
    "Status",
)
(
    COL_SCAN,
    COL_ROOT,
    COL_BACKEND,
    COL_STARTED,
    COL_FINISHED,
    COL_FILES,
    COL_IN_INDEX,
    COL_GROUPS,
    COL_STATUS,
) = range(len(COLUMNS))


def _when(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value is not None else ""


class CasHistoryDialog(QDialog):
    """Every scan of the duplicate index, with per-scan and whole-index actions."""

    #: A scan's duplicates should be shown (scan_id; 0 = earlier scans).
    show_duplicates_requested = pyqtSignal(int)
    #: The index changed here (removed, cleared, re-scanned).
    index_changed = pyqtSignal()

    def __init__(self, parent=None, backends=None) -> None:
        """*backends* maps ``backend_id`` to a connected backend (a list of
        backends is accepted too); a scan can only be re-scanned on one."""
        super().__init__(parent)
        set_window_icon(self, "duplicates")
        if isinstance(backends, dict):
            self._backends = dict(backends)
        else:
            self._backends = {CAS.backend_id_for(b): b for b in (backends or [])}
        self.setWindowTitle(tr("Duplicate Index & History"))
        self.resize(1000, 420)
        self._job = ScanJob(self)
        self._job.finished.connect(self._on_rescan_finished)
        self._rescan_root = ""
        self._build_ui()
        self.reload()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)

        intro = QLabel(
            tr("Every scan that built the Duplicate Finder's index. Removing a scan or "
            "clearing the index only forgets index rows — files are never touched.")
        )
        intro.setProperty("role", "muted")
        intro.setWordWrap(True)
        root.addWidget(intro)

        self._tree = QTreeWidget(self)
        self._tree.setColumnCount(len(COLUMNS))
        self._tree.setHeaderLabels([tr(c) for c in COLUMNS])
        self._tree.setRootIsDecorated(False)
        self._tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        from ui.column_fit import ColumnFitter

        # Root takes the free width; every divider stays draggable.
        self._columns = ColumnFitter(self._tree, fill=COL_ROOT)
        self._tree.currentItemChanged.connect(lambda *_a: self._update_buttons())
        self._tree.itemDoubleClicked.connect(lambda *_a: self._show_duplicates())
        root.addWidget(self._tree, stretch=1)

        row = QHBoxLayout()
        self._show_btn = QPushButton(tr("Show Duplicates"), self)
        self._show_btn.setToolTip(tr("Open the Duplicate Finder on this scan's duplicate groups"))
        self._show_btn.clicked.connect(self._show_duplicates)
        row.addWidget(self._show_btn)
        self._rescan_btn = QPushButton(tr("Re-scan"), self)
        self._rescan_btn.setToolTip(tr("Walk the same folder on the same backend again"))
        self._rescan_btn.clicked.connect(self._rescan)
        row.addWidget(self._rescan_btn)
        self._remove_btn = QPushButton(tr("Remove from Index…"), self)
        self._remove_btn.setToolTip(tr("Forget this scan's rows; the files stay where they are"))
        self._remove_btn.clicked.connect(self._remove_scan)
        row.addWidget(self._remove_btn)
        row.addStretch(1)
        self._refresh_btn = QPushButton(tr("Refresh"), self)
        self._refresh_btn.clicked.connect(self.reload)
        row.addWidget(self._refresh_btn)
        self._clear_btn = QPushButton(tr("Clear Whole Index…"), self)
        self._clear_btn.setToolTip(tr("Forget every scan and every row; the files stay"))
        self._clear_btn.clicked.connect(self._clear_index)
        row.addWidget(self._clear_btn)
        root.addLayout(row)

        self._strip = BusyStrip(self._job, self)
        root.addWidget(self._strip)
        self._job.started.connect(self._update_buttons)

        self._status = QLabel("", self)
        self._status.setProperty("role", "muted")
        root.addWidget(self._status)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        root.addWidget(close)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def reload(self) -> None:
        current = self.selected_scan()
        self._tree.clear()
        try:
            scans = CAS.list_scans(None)
        except Exception as exc:  # noqa: BLE001 — show the failure, keep the dialog
            log.warning("CAS.list_scans failed: %s", exc)
            scans = []
            self._status.setText(tr("Could not read the index: {exc}").format(exc=exc))
        for scan in scans:
            item = QTreeWidgetItem(self._tree)
            earlier = scan.scan_id == CAS.EARLIER_SCANS
            item.setText(COL_SCAN, tr("earlier") if earlier else f"#{scan.scan_id}")
            item.setText(
                COL_ROOT, tr("(rows indexed before scans were recorded)") if earlier else scan.root
            )
            item.setToolTip(COL_ROOT, scan.root)
            item.setText(COL_BACKEND, scan.backend_id)
            item.setText(COL_STARTED, _when(scan.started_at))
            item.setText(COL_FINISHED, _when(scan.finished_at))
            item.setText(COL_FILES, str(scan.files_indexed))
            item.setText(COL_IN_INDEX, str(scan.files_in_index))
            item.setText(COL_GROUPS, str(scan.duplicate_groups))
            item.setText(COL_STATUS, tr(scan.status))
            if scan.error:
                item.setToolTip(COL_STATUS, scan.error)
            for col in (COL_FILES, COL_IN_INDEX, COL_GROUPS):
                item.setTextAlignment(col, Qt.AlignmentFlag.AlignRight)
            item.setData(COL_SCAN, Qt.ItemDataRole.UserRole, scan)
            if current is not None and current.scan_id == scan.scan_id:
                self._tree.setCurrentItem(item)
        if self._tree.currentItem() is None and self._tree.topLevelItemCount():
            self._tree.setCurrentItem(self._tree.topLevelItem(0))
        if scans:
            self._status.setText(tr_n(len(scans), "{n} scan in the index", "{n} scans in the index"))
        self._update_buttons()

    def scan_of(self, item) -> CAS.ScanRecord | None:
        return item.data(COL_SCAN, Qt.ItemDataRole.UserRole) if item is not None else None

    def selected_scan(self) -> CAS.ScanRecord | None:
        return self.scan_of(self._tree.currentItem()) if hasattr(self, "_tree") else None

    def _update_buttons(self) -> None:
        scan = self.selected_scan()
        busy = self._job.running
        self._show_btn.setEnabled(scan is not None)
        self._rescan_btn.setEnabled(
            scan is not None and scan.scan_id != CAS.EARLIER_SCANS and not busy
        )
        self._remove_btn.setEnabled(scan is not None and not busy)
        self._clear_btn.setEnabled(self._tree.topLevelItemCount() > 0 and not busy)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _show_duplicates(self) -> None:
        scan = self.selected_scan()
        if scan is not None:
            self.show_duplicates_requested.emit(scan.scan_id)

    def _rescan(self) -> None:
        scan = self.selected_scan()
        if scan is None or scan.scan_id == CAS.EARLIER_SCANS or self._job.running:
            return
        backend = self._backends.get(scan.backend_id)
        if backend is None:
            QMessageBox.information(
                self,
                tr("Re-scan"),
                tr("Scan #{scan_id} ran on backend [{backend_id}], which is not open in "
                    "any pane. Open a pane on that host and try again.").format(scan_id=scan.scan_id, backend_id=scan.backend_id),
            )
            return
        self._rescan_root = scan.root
        bid, root, algorithm = scan.backend_id, scan.root, scan.algorithm or "sha256"
        # As the finder's rebuild: files without a native checksum are read
        # (only those that can have a duplicate), and the stats say what was
        # left out.
        stats = CAS.RebuildStats()
        self._rescan_stats = stats
        self._job.start(
            lambda cancel, progress: CAS.rebuild(
                backend,
                root,
                backend_id=bid,
                algorithm=algorithm,
                cancel=cancel,
                progress=progress,
                read_missing=True,
                stats=stats,
            )
        )

    def _on_rescan_finished(self, kind: str, value, cancelled: bool) -> None:
        if kind == "error":
            QMessageBox.warning(self, tr("Re-scan"), tr("Re-scan failed:\n{value}").format(value=value))
        elif cancelled:
            self._status.setText(tr("Cancelled — {value} file(s) indexed under {rescan_root}").format(value=value, rescan_root=self._rescan_root))
        else:
            self._status.setText(tr("Indexed {value} file(s) under {rescan_root}").format(value=value, rescan_root=self._rescan_root))
        stats = getattr(self, "_rescan_stats", None)
        if kind != "error" and stats is not None:
            left_out = []
            if stats.unreadable_count:
                left_out.append(tr("{unreadable_count} could not be read").format(unreadable_count=stats.unreadable_count))
            if stats.unlisted_count:
                left_out.append(tr("{unlisted_count} folder(s) could not be listed").format(unlisted_count=stats.unlisted_count))
            if stats.no_checksum:
                left_out.append(tr("{no_checksum} without a checksum").format(no_checksum=stats.no_checksum))
            if left_out:
                self._status.setText(self._status.text() + " — " + ", ".join(left_out))
        text = self._status.text()
        self.reload()
        if kind != "error":
            self._status.setText(text)
        self.index_changed.emit()

    def _remove_scan(self) -> None:
        scan = self.selected_scan()
        if scan is None or self._job.running:
            return
        what = (
            tr("the rows indexed before scans were recorded")
            if scan.scan_id == CAS.EARLIER_SCANS
            else tr("scan #{scan_id} of {root}").format(scan_id=scan.scan_id, root=scan.root)
        )
        reply = QMessageBox.question(
            self,
            tr("Remove from Index"),
            tr("Forget {what} ({files_in_index} indexed file(s))?\n\nOnly the index "
                "rows go; the files are not touched.").format(what=what, files_in_index=scan.files_in_index),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            removed = CAS.remove_scan(None, scan.scan_id)
        finally:
            QApplication.restoreOverrideCursor()
        self.reload()
        self._status.setText(tr("Removed {removed} row(s) from the index").format(removed=removed))
        self.index_changed.emit()

    def _clear_index(self) -> None:
        if self._job.running:
            return
        reply = QMessageBox.question(
            self,
            tr("Clear Whole Index"),
            tr("Forget every scan and every indexed file of the Duplicate Finder?\n\n"
            "The files themselves are not touched; a rebuild indexes them again."),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            removed = CAS.clear_index(None)
        finally:
            QApplication.restoreOverrideCursor()
        self.reload()
        self._status.setText(tr("Index cleared — {removed} row(s) removed").format(removed=removed))
        self.index_changed.emit()

    # A running re-scan must not outlive the dialog.
    def reject(self) -> None:
        self._job.abandon()
        super().reject()

    def closeEvent(self, event) -> None:
        self._job.abandon()
        super().closeEvent(event)


__all__ = ["COLUMNS", "CasHistoryDialog"]
