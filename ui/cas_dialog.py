"""Duplicate Finder — dialog over :mod:`core.cas`.

Named for what it does, not for how. "CAS" is the storage technique
behind it and means nothing to someone looking for a way to find
duplicate files, which is how the feature went unnoticed.

The CAS index is a client-side SQLite store mapping
``(backend_id, path) -> (algorithm, value, size)``. Two files
sharing ``(algorithm, value)`` are duplicates regardless of which
backend they live on. This dialog wraps two operations:

* **Rebuild from Active Pane** — walk the pane's current directory,
  call ``backend.checksum(path)`` for each file, and upsert every
  result into the CAS DB. Skips files whose backend can't produce
  a cheap native checksum (per the established library contract).
* **Find Duplicates** — group rows by ``(algorithm, value)`` where
  count >= 2 and render each group's files. Each group also gets
  an ``ax-cas://<algo>:<hex>`` URL the user can copy.
* **Move Selected to Trash** — only the selected copies, and only after
  :func:`core.cas.delete_duplicates` re-checked on the live backend that
  each still holds the indexed content and that a genuine other copy
  survives. Removal goes to the axross trash, so it can be undone. When
  every copy of a group is selected (Ctrl+A), the first copy is kept.
* **Mark All Duplicates (keep first)** — selects every copy but the first
  of each group. The rows of a group are shown in survivor order (oldest
  modification time first, see :func:`core.cas.survivor_key`), so the
  first row is the copy that stays.
* **Show** — all scans, one recorded scan, or only the copies inside a
  folder; **Index & History…** opens :mod:`ui.cas_history_dialog`.

A "Rebuild" run is the only way fresh data lands in the index (and it is
recorded as a scan); a "Find" run is a SELECT and free.
"""

from __future__ import annotations

import logging
from datetime import datetime

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from core import cas as CAS
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob

log = logging.getLogger("ui.cas_dialog")

COL_NAME, COL_FOLDER, COL_SIZE, COL_MODIFIED, COL_BACKEND, COL_HASH = range(6)

MARK_ALL_TEXT = "Mark All Duplicates (keep first)"
SURVIVOR_TIP = (
    "First in its group: kept by “Mark All Duplicates (keep first)” and when "
    "every copy is selected — the oldest copy; ties go to the shorter, then "
    "the alphabetically first path."
)


# The plan lives in core so the scripting API (``axross.dedupe``) and this
# dialog decide alike; re-exported here for existing imports.
DeletionPlan = CAS.DeletionPlan
plan_deletion = CAS.plan_deletion


def _format_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n //= 1024
    return f"{n:.0f} PiB"


def _split_path(path: str) -> tuple[str, str]:
    """``(folder, name)`` of an index path — local or remote, ``/`` or ``\\``."""
    trimmed = path.rstrip("/\\") or path
    cut = max(trimmed.rfind("/"), trimmed.rfind("\\"))
    if cut < 0:
        return "", trimmed
    return trimmed[:cut] or trimmed[: cut + 1], trimmed[cut + 1 :]


_backend_id_for = CAS.backend_id_for


def _format_mtime(mtime) -> str:
    if mtime is None:
        return "unknown"
    try:
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return "unknown"


def scan_label(scan) -> str:
    """One line for a scan in the Show list."""
    if scan.scan_id == CAS.EARLIER_SCANS:
        return "Earlier scans (before scan history)"
    when = scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else "?"
    return f"Scan #{scan.scan_id}: {scan.root} [{scan.backend_id}] — {when} ({scan.status})"


class CasDuplicatesDialog(QDialog):
    """Tree of duplicate-content groups, with rebuild + copy-URL."""

    open_requested = pyqtSignal(str, str)  # backend_id, path

    def __init__(self, active_pane=None, parent=None, backends=None, scan_id=None) -> None:
        """*backends* are the connected backends of every open pane; a copy
        on one of them can be verified as the survivor of a deletion.
        *scan_id* opens the finder on the duplicates of that scan."""
        super().__init__(parent)
        self._scope: tuple = ("all", None) if scan_id is None else ("scan", int(scan_id))
        self._history_dialog = None
        self._active_pane = active_pane
        self._backends: dict = {}
        for backend in [getattr(active_pane, "backend", None), *(backends or [])]:
            if backend is not None:
                self._backends.setdefault(_backend_id_for(backend), backend)
        self.setWindowTitle("Duplicate Finder")
        self.resize(1000, 600)
        # Background work: the rebuild walk + hashing and the verified delete
        # can take minutes, so they run in a thread while the dialog stays
        # live (progress, Cancel, Esc). One job at a time, told apart by kind.
        self._job_kind = "rebuild"
        self._job = ScanJob(self, formatter=self._format_progress)
        self._job.finished.connect(self._on_job_finished)
        self._build_ui()
        self._populate_scopes()
        self._reload()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)

        intro = QLabel(
            "Indexed files grouped by content hash — every row in a group "
            "holds identical content, wherever it lives. Use “Rebuild from "
            "Active Pane” to index a directory first."
        )
        intro.setProperty("role", "muted")
        intro.setWordWrap(True)
        root.addWidget(intro)

        scope_row = QHBoxLayout()
        scope_row.addWidget(QLabel("Show:", self))
        self._scope_combo = QComboBox(self)
        self._scope_combo.setToolTip(
            "All scans; one scan (every group with a copy from it, all copies "
            "shown); or only the copies inside a folder"
        )
        self._scope_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self._scope_combo.currentIndexChanged.connect(self._on_scope_chosen)
        scope_row.addWidget(self._scope_combo, stretch=1)
        self._history_btn = QPushButton("Index && History…", self)
        self._history_btn.setToolTip(
            "Every scan that built the index: show its duplicates, re-scan, "
            "remove it from the index, or clear the whole index"
        )
        self._history_btn.clicked.connect(self._open_history)
        scope_row.addWidget(self._history_btn)
        root.addLayout(scope_row)

        btn_row = QHBoxLayout()
        self._rebuild_btn = QPushButton("Rebuild from Active Pane…", self)
        self._rebuild_btn.clicked.connect(self._do_rebuild_active)
        self._rebuild_btn.setEnabled(self._active_pane is not None)
        btn_row.addWidget(self._rebuild_btn)

        self._refresh_btn = QPushButton("Refresh", self)
        self._refresh_btn.clicked.connect(self._refresh)
        btn_row.addWidget(self._refresh_btn)

        self._mark_all_btn = QPushButton(MARK_ALL_TEXT, self)
        self._mark_all_btn.setToolTip(
            "Select every copy except the first of each group — the oldest by "
            "modification time. Review, then Move Selected to Trash."
        )
        self._mark_all_btn.clicked.connect(self._mark_all_duplicates)
        btn_row.addWidget(self._mark_all_btn)

        self._copy_btn = QPushButton("Copy ax-cas URL", self)
        self._copy_btn.clicked.connect(self._copy_url)
        btn_row.addWidget(self._copy_btn)

        self._delete_btn = QPushButton("Move Selected to Trash…", self)
        self._delete_btn.setToolTip(
            "Move the selected copies to the axross trash (restorable via Show Trash). "
            "Each file is re-checked first, and at least one verified copy of every "
            "group is always kept: when every copy of a group is selected, the first "
            "(oldest) one stays."
        )
        self._delete_btn.clicked.connect(self._delete_selected)
        btn_row.addWidget(self._delete_btn)

        self._export_btn = QPushButton("Copy list", self)
        self._export_btn.setToolTip("Copy every duplicate group to the clipboard")
        self._export_btn.clicked.connect(self._export)
        btn_row.addWidget(self._export_btn)

        btn_row.addStretch(1)
        self._status = QLabel("")
        self._status.setProperty("role", "muted")
        btn_row.addWidget(self._status)
        root.addLayout(btn_row)

        # Said when the survivor rule could not use a modification time.
        self._undated_label = QLabel("", self)
        self._undated_label.setProperty("role", "muted")
        self._undated_label.setWordWrap(True)
        self._undated_label.setVisible(False)
        root.addWidget(self._undated_label)

        # Tree: parent rows are the dup-group hash; children are the
        # actual paths. Doing it as a QTreeWidget keeps the visual
        # grouping obvious without us having to draw alternating
        # backgrounds in a flat table.
        self._tree = QTreeWidget(self)
        self._tree.setColumnCount(6)
        self._tree.setHeaderLabels(["Name", "Folder", "Size", "Modified", "Backend", "Hash"])
        font = self._tree.font()
        # Monospace is much nicer for hashes.
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._tree.setFont(font)
        # The file name gets its own column: inside one long path column it
        # sat at the end and was the first thing elided. Whatever still has
        # to be shortened keeps both ends; the tooltip holds the full path.
        self._tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        header = self._tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(COL_NAME, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(COL_FOLDER, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(COL_SIZE, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_MODIFIED, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(COL_BACKEND, QHeaderView.ResizeMode.ResizeToContents)
        # A full sha256 is 64 characters and used to take the room the
        # names needed; it is in the tooltip and in "Copy ax-cas URL".
        header.setSectionResizeMode(COL_HASH, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(COL_HASH, 140)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        delete_key = QShortcut(QKeySequence(QKeySequence.StandardKey.Delete), self._tree)
        delete_key.setContext(Qt.ShortcutContext.WidgetShortcut)
        delete_key.activated.connect(self._delete_selected)
        # Removing duplicates is inherently a multi-row action, and the
        # default single-selection tree made "delete the copies I don't
        # want" a one-at-a-time affair.
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self._tree, stretch=1)

        # One status line at the bottom while a scan runs.
        self._strip = BusyStrip(self._job, self)
        self._busy_bar = self._strip.bar
        self._progress_label = self._strip.label
        self._cancel_btn = self._strip.cancel_button
        self._job.started.connect(lambda: self._rebuild_btn.setEnabled(False))
        root.addWidget(self._strip)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        close.accepted.connect(self.accept)
        root.addWidget(close)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def scope(self) -> tuple:
        """``("all", None)``, ``("scan", scan_id)`` or ``("folder", path)``."""
        return self._scope

    def set_scope(self, kind: str, value=None) -> None:
        """Show all scans, one scan's duplicates, or a folder's."""
        if kind not in ("all", "scan", "folder"):
            raise ValueError(f"unknown scope {kind!r}")
        self._scope = (kind, int(value) if kind == "scan" else value)
        self._populate_scopes()
        self._reload()

    def _populate_scopes(self) -> None:
        """Fill the Show list: all scans, every recorded scan, the folder
        choice (and the folder in use, if any); select the current scope."""
        combo = self._scope_combo
        combo.blockSignals(True)
        try:
            combo.clear()
            combo.addItem("All scans", ("all", None))
            try:
                scans = CAS.list_scans(None)
            except Exception as exc:  # noqa: BLE001 — a broken index must not hide the dialog
                log.warning("CAS.list_scans failed: %s", exc)
                scans = []
            for scan in scans:
                combo.addItem(scan_label(scan), ("scan", scan.scan_id))
            kind, value = self._scope
            if kind == "scan" and not any(s.scan_id == value for s in scans):
                combo.addItem(f"Scan #{value} (no longer in the index)", ("scan", value))
            if kind == "folder" and value:
                combo.addItem(f"Only inside folder: {value}", ("folder", value))
            combo.addItem("Only inside folder…", ("folder", None))
            for i in range(combo.count()):
                if tuple(combo.itemData(i)) == tuple(self._scope):
                    combo.setCurrentIndex(i)
                    break
        finally:
            combo.blockSignals(False)

    def _on_scope_chosen(self, index: int) -> None:
        data = self._scope_combo.itemData(index)
        if not data:
            return
        kind, value = data
        if kind == "folder" and value is None:
            start = getattr(self._active_pane, "current_path", "") or ""
            if self._scope[0] == "folder":
                start = self._scope[1]
            text, ok = QInputDialog.getText(
                self,
                "Only Inside Folder",
                "Show only duplicates whose copies lie inside this folder (on any backend):",
                text=start,
            )
            text = (text or "").strip()
            if not ok or not text:
                self._populate_scopes()  # back to the scope still in use
                return
            value = text
        self.set_scope(kind, value)

    def _refresh(self) -> None:
        self._populate_scopes()
        self._reload()

    def _query_groups(self) -> list:
        """Groups of every algorithm in the index (rebuild defaults to sha256,
        but a backend may have registered md5: S3 ETag, Azure Content-MD5)."""
        kind, value = self._scope
        if kind == "scan":
            return CAS.duplicates(None, None, scan_id=value)
        if kind == "folder":
            return CAS.duplicates(None, None, folder=value)
        return CAS.duplicates(None, None)

    def _reload(self) -> None:
        self._tree.clear()
        # Kept so plan_deletion can see whole groups, not just the rows
        # the user happened to click — the safety check needs to know
        # how many copies a group started with.
        self._groups: list[list] = []
        total_files = 0
        undated = 0
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            try:
                groups = self._query_groups()
            except Exception as exc:  # noqa: BLE001
                log.warning("CAS.duplicates failed: %s", exc)
                groups = []
            for group in groups:
                if not group:
                    continue
                total_files += len(group)
                undated += CAS.has_undated(group)
                self._groups.append(list(group))
                parent = QTreeWidgetItem(self._tree)
                head = group[0]
                parent.setText(COL_NAME, f"[{head.algorithm}] {len(group)} copies")
                parent.setText(COL_SIZE, _format_size(head.size))
                parent.setText(COL_HASH, head.value)
                parent.setToolTip(COL_HASH, f"{head.algorithm}:{head.value}")
                parent.setData(
                    COL_NAME, Qt.ItemDataRole.UserRole, ("group", head.algorithm, head.value)
                )
                # Rows come in survivor order: the first one is the copy that stays.
                for position, entry in enumerate(group):
                    folder, name = _split_path(entry.path)
                    child = QTreeWidgetItem(parent)
                    child.setText(COL_NAME, name)
                    child.setText(COL_FOLDER, folder)
                    child.setText(COL_SIZE, _format_size(entry.size))
                    child.setText(COL_MODIFIED, _format_mtime(entry.mtime))
                    child.setText(COL_BACKEND, entry.backend_id)
                    for col in (COL_NAME, COL_FOLDER):
                        child.setToolTip(col, entry.path)
                    if position == 0:
                        font = child.font(COL_MODIFIED)
                        font.setBold(True)
                        child.setFont(COL_MODIFIED, font)
                        child.setToolTip(COL_MODIFIED, SURVIVOR_TIP)
                    child.setData(COL_NAME, Qt.ItemDataRole.UserRole, ("entry", entry))
                parent.setExpanded(True)
        finally:
            QApplication.restoreOverrideCursor()
        self._tree.resizeColumnToContents(COL_NAME)
        # Wide enough for the names, but never so wide the folder vanishes.
        cap = max(200, self._tree.viewport().width() // 2)
        if self._tree.columnWidth(COL_NAME) > cap:
            self._tree.setColumnWidth(COL_NAME, cap)
        self._undated_label.setText(
            f"{undated} group(s) contain copies without a modification time: those "
            "sort after dated copies, then by path, so “first” there means the "
            "shortest path. Rebuild the index to record the times."
        )
        self._undated_label.setVisible(undated > 0)
        self._status.setText(
            f"{len(self._groups)} duplicate group(s) covering {total_files} file(s)"
        )

    def _do_rebuild_active(self) -> None:
        pane = self._active_pane
        if pane is None:
            return
        backend = pane.backend
        path = pane.current_path
        bid = _backend_id_for(backend)
        if self._job.running and not self._job.cancelling:
            return  # a scan is already running
        reply = QMessageBox.question(
            self,
            "Rebuild CAS",
            f"Walk and (re)hash every file under\n{path}\n"
            f"on backend [{bid}]?\n\nNative checksum is used where "
            "available; files on backends without one are skipped.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._rebuild_root = path
        self._job_kind = "rebuild"
        self._job.start(
            lambda cancel, progress: CAS.rebuild(
                backend, path, backend_id=bid, cancel=cancel, progress=progress
            )
        )

    def _format_progress(self, state: dict) -> str:
        from ui.scan_job import shorten

        if self._job_kind == "delete":
            return f"Checking and moving to trash… {state['indexed']} moved — " + shorten(
                state["path"]
            )
        return (
            f"Working… {state['indexed']} indexed, {state['scanned']} scanned"
            f" — {shorten(state['path'])}"
        )

    def _on_job_finished(self, kind: str, value, cancelled: bool) -> None:
        if self._job_kind == "delete":
            self._on_delete_finished(kind, value, cancelled)
        else:
            self._on_rebuild_finished(kind, value, cancelled)

    def _on_rebuild_finished(self, kind: str, value, cancelled: bool) -> None:
        self._rebuild_btn.setEnabled(self._active_pane is not None)
        path = self._rebuild_root
        if kind == "error":
            QMessageBox.warning(self, "Rebuild CAS", f"Rebuild failed:\n{value}")
            return
        if cancelled:
            text = f"Cancelled — {value} file(s) indexed so far under {path}."
        else:
            text = f"Indexed {value} file(s) under {path}."
        QMessageBox.information(self, "Rebuild CAS", text)
        self._refresh()

    def reject(self) -> None:
        # Esc, the Close button and the window's own close all land here or
        # in closeEvent; a running scan must not outlive the dialog.
        self._job.abandon()
        super().reject()

    def closeEvent(self, event) -> None:
        self._job.abandon()
        super().closeEvent(event)

    def _selected_kind_payload(self):
        item = self._tree.currentItem()
        if item is None:
            return None, None
        data = item.data(COL_NAME, Qt.ItemDataRole.UserRole)
        if not data:
            return None, None
        return data[0], data[1:]

    def selected_entries(self) -> list:
        """Every ``CasEntry`` row currently selected in the tree."""
        entries = []
        for item in self._tree.selectedItems():
            data = item.data(COL_NAME, Qt.ItemDataRole.UserRole)
            if data and data[0] == "entry":
                entries.append(data[1])
        return entries

    def _delete_selected(self) -> None:
        if self._job.running:
            return  # one background job at a time
        selected = self.selected_entries()
        if not selected:
            QMessageBox.information(
                self, "Move to Trash", "Select the file rows you want to remove."
            )
            return

        # Every copy of a group selected (Ctrl+A): its first copy is kept.
        plan = plan_deletion(selected, getattr(self, "_groups", []))
        if not plan.deletable:
            return

        # Only backends we actually hold: the index spans hosts that may
        # not be connected, and those copies can neither be removed nor
        # re-checked from here.
        mine = [e for e in plan.deletable if e.backend_id in self._backends]
        others = len(plan.deletable) - len(mine)
        if not mine:
            QMessageBox.information(
                self,
                "Not reachable from here",
                "The selected copies live on backends that are not open in any "
                "pane. Open a pane on that host and try again.",
            )
            return

        hosts = sorted({e.backend_id for e in mine})
        kept = f"{plan.survivors} " + ("copy is kept" if plan.survivors == 1 else "copies are kept")
        if plan.auto_kept:
            kept += (
                f" — in {len(plan.auto_kept)} group(s) every copy was selected, so "
                "the first (oldest) copy of each stays"
            )
        confirm = QMessageBox.question(
            self,
            "Move to Trash",
            f"Move {len(mine)} file(s) on {', '.join(hosts)} to the axross trash?\n"
            f"{kept}.\n\n"
            "Each file is re-checked first: it is only moved if it still holds "
            "the indexed content and another verified copy remains. Trashed "
            "files can be restored via Show Trash."
            + (
                f"\n\n{others} selected copy/copies live on backends that are not "
                "open and are skipped."
                if others
                else ""
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        groups = list(getattr(self, "_groups", []))
        backends = dict(self._backends)
        self._job_kind = "delete"
        self._job.start(
            lambda cancel, progress: CAS.delete_duplicates(
                mine,
                groups,
                backends,
                cancel=cancel,
                progress=lambda done, moved, path: progress(done, moved, path),
            )
        )

    def _on_delete_finished(self, kind: str, value, cancelled: bool) -> None:
        self._rebuild_btn.setEnabled(self._active_pane is not None)
        if kind == "error":
            QMessageBox.warning(self, "Move to Trash", f"Failed:\n{value}")
            self._reload()
            return
        outcome = value
        lines = [f"{len(outcome.removed)} file(s) moved to the axross trash."]
        if cancelled:
            lines.append("Cancelled before every file was handled.")
        if outcome.refused or outcome.failed:
            lines.append("")
            lines += [f"Kept {e.path}: {why}" for e, why in outcome.refused[:10]]
            lines += [f"Failed {e.path}: {why}" for e, why in outcome.failed[:10]]
            hidden = len(outcome.refused) + len(outcome.failed) - 20
            if hidden > 0:
                lines.append(f"… and {hidden} more")
            QMessageBox.warning(self, "Move to Trash", "\n".join(lines))
        else:
            QMessageBox.information(self, "Move to Trash", "\n".join(lines))
        self._refresh()
        self._status.setText(f"Moved {len(outcome.removed)} duplicate(s) to trash")

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------
    def _show_context_menu(self, pos) -> None:
        item = self._tree.itemAt(pos)
        if item is not None and not item.isSelected():
            self._tree.setCurrentItem(item)
        self.build_context_menu(item).exec(self._tree.viewport().mapToGlobal(pos))

    def build_context_menu(self, item) -> QMenu:
        """The right-click menu for *item* (a file row, a group row or None)."""
        menu = QMenu(self)
        data = item.data(COL_NAME, Qt.ItemDataRole.UserRole) if item is not None else None
        kind = data[0] if data else None

        if kind == "entry":
            entry = data[1]
            menu.addAction(
                "Open Containing Folder",
                lambda: self.open_requested.emit(entry.backend_id, entry.path),
            )
            menu.addAction("Keep This Copy, Select the Others", lambda: self._keep_only(item))
            menu.addSeparator()
            menu.addAction("Copy Path", lambda: self._to_clipboard(entry.path))
            menu.addAction("Copy File Name", lambda: self._to_clipboard(_split_path(entry.path)[1]))
            menu.addAction(
                "Copy ax-cas URL",
                lambda: self._to_clipboard(CAS.cas_url(entry.algorithm, entry.value)),
            )
        elif kind == "group":
            _kind, algo, value = data
            menu.addAction("Select All but One", lambda: self._select_all_but_one([item]))
            menu.addAction("Copy ax-cas URL", lambda: self._to_clipboard(CAS.cas_url(algo, value)))
            menu.addAction("Copy All Paths", lambda: self._copy_group_paths(item))

        if kind is not None:
            menu.addSeparator()
        menu.addAction(MARK_ALL_TEXT, self._mark_all_duplicates)
        menu.addAction("Clear Selection", self._tree.clearSelection)
        menu.addSeparator()
        has_files = bool(self.selected_entries())
        trash = menu.addAction("Move Selected to Trash…", self._delete_selected)
        trash.setEnabled(has_files and not self._job.running)
        forget = menu.addAction("Remove Selected from Index", self._forget_selected)
        forget.setEnabled(has_files and not self._job.running)
        return menu

    def _keep_only(self, keep) -> None:
        group = keep.parent()
        if group is None:
            return
        self._tree.clearSelection()
        for i in range(group.childCount()):
            child = group.child(i)
            if child is not keep:
                child.setSelected(True)

    def _mark_all_duplicates(self) -> None:
        """Select every copy except the first (the survivor) of each group."""
        self._select_all_but_one(
            [self._tree.topLevelItem(i) for i in range(self._tree.topLevelItemCount())]
        )
        self._status.setText(f"{len(self.selected_entries())} duplicate(s) marked")

    def _select_all_but_one(self, groups) -> None:
        """Select every copy except the first of each group — the rows are in
        survivor order, so that is the oldest copy. The user sees the result
        and can change it before removing anything."""
        self._tree.clearSelection()
        for group in groups:
            for i in range(1, group.childCount()):
                group.child(i).setSelected(True)

    def _copy_group_paths(self, group) -> None:
        paths = []
        for i in range(group.childCount()):
            data = group.child(i).data(COL_NAME, Qt.ItemDataRole.UserRole)
            if data and data[0] == "entry":
                paths.append(data[1].path)
        self._to_clipboard("\n".join(paths))

    def _to_clipboard(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)
        self._status.setText("Copied to clipboard")

    def _forget_selected(self) -> None:
        """Drop the selected rows from the index; the files stay untouched.
        For stale rows — a rebuild brings back whatever still exists."""
        forgotten = 0
        for entry in self.selected_entries():
            try:
                forgotten += CAS.remove(None, entry.backend_id, entry.path)
            except Exception as exc:  # noqa: BLE001 — report, keep going
                log.warning("CAS index removal failed for %s: %s", entry.path, exc)
        self._refresh()
        self._status.setText(f"Removed {forgotten} row(s) from the index")

    def _export(self) -> None:
        lines = ["algorithm\thash\tbackend\tpath\tsize"]
        for group in getattr(self, "_groups", []):
            for entry in group:
                lines.append(
                    f"{entry.algorithm}\t{entry.value}\t{entry.backend_id}\t"
                    f"{entry.path}\t{entry.size}"
                )
        if len(lines) == 1:
            lines.append("# no duplicate groups in the index")
        QGuiApplication.clipboard().setText("\n".join(lines) + "\n")
        self._status.setText(f"{len(lines) - 1} row(s) copied to clipboard")

    def _copy_url(self) -> None:
        kind, payload = self._selected_kind_payload()
        if kind == "group":
            algo, value = payload
            url = CAS.cas_url(algo, value)
        elif kind == "entry":
            entry = payload[0]
            url = CAS.cas_url(entry.algorithm, entry.value)
        else:
            QMessageBox.information(
                self,
                "Copy URL",
                "Select a duplicate group (or any file in one) first.",
            )
            return
        QGuiApplication.clipboard().setText(url)
        self._status.setText(f"Copied {url} to clipboard")

    def _open_history(self) -> None:
        """The Index / History view, following this finder: "Show Duplicates"
        there sets the scope here, and every change reloads it."""
        from ui.cas_history_dialog import CasHistoryDialog

        if self._history_dialog is not None and self._history_dialog.isVisible():
            self._history_dialog.raise_()
            self._history_dialog.activateWindow()
            return
        dlg = CasHistoryDialog(parent=self, backends=self._backends)
        dlg.show_duplicates_requested.connect(lambda sid: self.set_scope("scan", sid))
        dlg.index_changed.connect(self._refresh)
        dlg.finished.connect(lambda _code: self._forget_history(dlg))
        self._history_dialog = dlg
        dlg.open()

    def _forget_history(self, dlg) -> None:
        if self._history_dialog is dlg:
            self._history_dialog = None
        dlg.deleteLater()  # a child of the finder: gone once closed

    def _on_double_click(self, item: QTreeWidgetItem, _col: int) -> None:
        data = item.data(COL_NAME, Qt.ItemDataRole.UserRole)
        if not data or data[0] != "entry":
            return
        entry = data[1]
        self.open_requested.emit(entry.backend_id, entry.path)
