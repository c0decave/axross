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
  survives. Removal goes to the axross trash, so it can be undone.

A "Rebuild" run is the only way fresh data lands in the index; a
"Find" run is a SELECT and free.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
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

COL_NAME, COL_FOLDER, COL_SIZE, COL_BACKEND, COL_HASH = range(5)


@dataclass(frozen=True)
class DeletionPlan:
    """What a delete request resolves to, after the safety check."""

    #: Entries that may be removed.
    deletable: list = field(default_factory=list)
    #: Hash values of groups held back because every copy was selected.
    refused_groups: list = field(default_factory=list)
    #: Copies that would remain across the affected groups.
    survivors: int = 0


def plan_deletion(selected, groups) -> DeletionPlan:
    """Resolve a selection into a plan that cannot erase content.

    A duplicate group exists precisely because the same bytes live in
    more than one place. Selecting every row in a group and pressing
    delete would remove the content entirely — turning a deduplication
    tool into a deletion tool, in one click, on data the user believes
    is safely duplicated.

    So a group whose every copy is selected is refused as a whole rather
    than partially applied: dropping "one of them" silently would leave
    the user with a survivor they did not choose. Refusals are returned
    so the UI can explain itself, and they never block deletions in
    other groups — one reckless selection should not cost the rest of
    an intended cleanup.

    A group of one is not a duplicate and is likewise refused; deleting
    a lone file is ordinary deletion and belongs in the file pane.
    """
    selected_keys = {(e.backend_id, e.path, e.value) for e in selected}
    deletable: list = []
    refused: list = []
    survivors = 0

    for group in groups:
        in_group = [e for e in group if (e.backend_id, e.path, e.value) in selected_keys]
        if not in_group:
            continue
        remaining = len(group) - len(in_group)
        if remaining < 1:
            refused.append(group[0].value)
            continue
        deletable.extend(in_group)
        survivors += remaining

    return DeletionPlan(deletable=deletable, refused_groups=refused, survivors=survivors)


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


def _backend_id_for(backend) -> str:
    """Same shape as the metadata-search dialog — ``<class>:<name>``
    or just ``<class>`` when the backend has no display name."""
    cls = type(backend).__name__
    name = getattr(backend, "name", "") or ""
    return f"{cls}:{name}" if name else cls


class CasDuplicatesDialog(QDialog):
    """Tree of duplicate-content groups, with rebuild + copy-URL."""

    open_requested = pyqtSignal(str, str)  # backend_id, path

    def __init__(self, active_pane=None, parent=None, backends=None) -> None:
        """*backends* are the connected backends of every open pane; a copy
        on one of them can be verified as the survivor of a deletion."""
        super().__init__(parent)
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

        btn_row = QHBoxLayout()
        self._rebuild_btn = QPushButton("Rebuild from Active Pane…", self)
        self._rebuild_btn.clicked.connect(self._do_rebuild_active)
        self._rebuild_btn.setEnabled(self._active_pane is not None)
        btn_row.addWidget(self._rebuild_btn)

        self._refresh_btn = QPushButton("Refresh", self)
        self._refresh_btn.clicked.connect(self._reload)
        btn_row.addWidget(self._refresh_btn)

        self._copy_btn = QPushButton("Copy ax-cas URL", self)
        self._copy_btn.clicked.connect(self._copy_url)
        btn_row.addWidget(self._copy_btn)

        self._delete_btn = QPushButton("Move Selected to Trash…", self)
        self._delete_btn.setToolTip(
            "Move the selected copies to the axross trash (restorable via Show Trash). "
            "Each file is re-checked first, and at least one verified copy of every "
            "group is always kept."
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

        # Tree: parent rows are the dup-group hash; children are the
        # actual paths. Doing it as a QTreeWidget keeps the visual
        # grouping obvious without us having to draw alternating
        # backgrounds in a flat table.
        self._tree = QTreeWidget(self)
        self._tree.setColumnCount(5)
        self._tree.setHeaderLabels(["Name", "Folder", "Size", "Backend", "Hash"])
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
    def _reload(self) -> None:
        self._tree.clear()
        # Kept so plan_deletion can see whole groups, not just the rows
        # the user happened to click — the safety check needs to know
        # how many copies a group started with.
        self._groups: list[list] = []
        # Try a few common algorithms; CAS rebuild defaults to sha256
        # but a backend could've registered md5 (S3 ETag, Azure
        # Content-MD5) so we surface those groups too.
        algos = ("sha256", "md5", "etag", "dropbox", "quickxor")
        total_groups = 0
        total_files = 0
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            for algo in algos:
                try:
                    groups = CAS.duplicates(None, algo)
                except Exception as exc:  # noqa: BLE001
                    log.warning("CAS.duplicates(%s) failed: %s", algo, exc)
                    continue
                for group in groups:
                    if not group:
                        continue
                    total_groups += 1
                    total_files += len(group)
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
                    for entry in group:
                        folder, name = _split_path(entry.path)
                        child = QTreeWidgetItem(parent)
                        child.setText(COL_NAME, name)
                        child.setText(COL_FOLDER, folder)
                        child.setText(COL_SIZE, _format_size(entry.size))
                        child.setText(COL_BACKEND, entry.backend_id)
                        for col in (COL_NAME, COL_FOLDER):
                            child.setToolTip(col, entry.path)
                        child.setData(COL_NAME, Qt.ItemDataRole.UserRole, ("entry", entry))
                    parent.setExpanded(True)
        finally:
            QApplication.restoreOverrideCursor()
        self._tree.resizeColumnToContents(COL_NAME)
        # Wide enough for the names, but never so wide the folder vanishes.
        cap = max(200, self._tree.viewport().width() // 2)
        if self._tree.columnWidth(COL_NAME) > cap:
            self._tree.setColumnWidth(COL_NAME, cap)
        self._status.setText(f"{total_groups} duplicate group(s) covering {total_files} file(s)")

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
        self._reload()

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

        plan = plan_deletion(selected, getattr(self, "_groups", []))

        if plan.refused_groups:
            QMessageBox.warning(
                self,
                "Every copy selected",
                f"{len(plan.refused_groups)} group(s) had ALL their copies selected. "
                "Removing those would erase the content entirely, so they were "
                "left alone — deselect at least one copy per group to proceed.",
            )
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
        confirm = QMessageBox.question(
            self,
            "Move to Trash",
            f"Move {len(mine)} file(s) on {', '.join(hosts)} to the axross trash?\n"
            f"{plan.survivors} indexed copy/copies will remain.\n\n"
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
        self._status.setText(f"Moved {len(outcome.removed)} duplicate(s) to trash")
        self._reload()

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
        menu.addAction(
            "Select Duplicates in Every Group (keep one)",
            lambda: self._select_all_but_one(
                [self._tree.topLevelItem(i) for i in range(self._tree.topLevelItemCount())]
            ),
        )
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

    def _select_all_but_one(self, groups) -> None:
        """Select every copy except the first of each group — the user
        sees the result and can change it before removing anything."""
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
        self._reload()
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

    def _on_double_click(self, item: QTreeWidgetItem, _col: int) -> None:
        data = item.data(COL_NAME, Qt.ItemDataRole.UserRole)
        if not data or data[0] != "entry":
            return
        entry = data[1]
        self.open_requested.emit(entry.backend_id, entry.path)
