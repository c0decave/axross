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

A "Rebuild" run is the only way fresh data lands in the index; a
"Find" run is a SELECT and free.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from core import cas as CAS

log = logging.getLogger("ui.cas_dialog")


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


def _backend_id_for(backend) -> str:
    """Same shape as the metadata-search dialog — ``<class>:<name>``
    or just ``<class>`` when the backend has no display name."""
    cls = type(backend).__name__
    name = getattr(backend, "name", "") or ""
    return f"{cls}:{name}" if name else cls


class CasDuplicatesDialog(QDialog):
    """Tree of duplicate-content groups, with rebuild + copy-URL."""

    open_requested = pyqtSignal(str, str)  # backend_id, path

    def __init__(self, active_pane=None, parent=None) -> None:
        super().__init__(parent)
        self._active_pane = active_pane
        self.setWindowTitle("Duplicate Finder")
        self.resize(900, 600)
        self._build_ui()
        self._reload()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        intro = QLabel(
            "Indexed files grouped by content hash — every row in a group "
            "holds identical content, wherever it lives. Use “Rebuild from "
            "Active Pane” to index a directory first."
        )
        intro.setStyleSheet("color: #666;")
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

        self._delete_btn = QPushButton("Delete selected copies…", self)
        self._delete_btn.setToolTip(
            "Remove the selected duplicates. At least one copy of every "
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
        self._status.setStyleSheet("color: #666;")
        btn_row.addWidget(self._status)
        root.addLayout(btn_row)

        # Tree: parent rows are the dup-group hash; children are the
        # actual paths. Doing it as a QTreeWidget keeps the visual
        # grouping obvious without us having to draw alternating
        # backgrounds in a flat table.
        self._tree = QTreeWidget(self)
        self._tree.setColumnCount(4)
        self._tree.setHeaderLabels(["Algo / Path", "Size", "Backend", "Hash / —"])
        font = self._tree.font()
        # Monospace is much nicer for hashes.
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._tree.setFont(font)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        # Removing duplicates is inherently a multi-row action, and the
        # default single-selection tree made "delete the copies I don't
        # want" a one-at-a-time affair.
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        root.addWidget(self._tree, stretch=1)

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
                    parent.setText(0, f"[{head.algorithm}] {len(group)} copies")
                    parent.setText(1, _format_size(head.size))
                    parent.setText(2, "—")
                    parent.setText(3, head.value)
                    parent.setData(
                        0, Qt.ItemDataRole.UserRole, ("group", head.algorithm, head.value)
                    )
                    for entry in group:
                        child = QTreeWidgetItem(parent)
                        child.setText(0, entry.path)
                        child.setText(1, _format_size(entry.size))
                        child.setText(2, entry.backend_id)
                        child.setText(3, "")
                        child.setData(
                            0,
                            Qt.ItemDataRole.UserRole,
                            ("entry", entry),
                        )
                    parent.setExpanded(True)
        finally:
            QApplication.restoreOverrideCursor()
        self._status.setText(f"{total_groups} duplicate group(s) covering {total_files} file(s)")

    def _do_rebuild_active(self) -> None:
        pane = self._active_pane
        if pane is None:
            return
        backend = pane.backend
        path = pane.current_path
        bid = _backend_id_for(backend)
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
        # Single push + single pop discipline (see file_pane._show_checksum).
        error: Exception | None = None
        added = 0
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            try:
                added = CAS.rebuild(backend, path, backend_id=bid)
            except Exception as exc:  # noqa: BLE001 — surface to user
                error = exc
        finally:
            QApplication.restoreOverrideCursor()
        if error is not None:
            QMessageBox.warning(
                self,
                "Rebuild CAS",
                f"Rebuild failed:\n{error}",
            )
            return
        QMessageBox.information(
            self,
            "Rebuild CAS",
            f"Indexed {added} file(s) under {path}.",
        )
        self._reload()

    def _selected_kind_payload(self):
        item = self._tree.currentItem()
        if item is None:
            return None, None
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data:
            return None, None
        return data[0], data[1:]

    def selected_entries(self) -> list:
        """Every ``CasEntry`` row currently selected in the tree."""
        entries = []
        for item in self._tree.selectedItems():
            data = item.data(0, Qt.ItemDataRole.UserRole)
            if data and data[0] == "entry":
                entries.append(data[1])
        return entries

    def _delete_selected(self) -> None:
        selected = self.selected_entries()
        if not selected:
            QMessageBox.information(
                self, "Delete duplicates", "Select the file rows you want to remove."
            )
            return

        plan = plan_deletion(selected, getattr(self, "_groups", []))

        if plan.refused_groups:
            QMessageBox.warning(
                self,
                "Every copy selected",
                f"{len(plan.refused_groups)} group(s) had ALL their copies selected. "
                "Deleting those would erase the content entirely, so they were "
                "left alone — deselect at least one copy per group to proceed.",
            )
        if not plan.deletable:
            return

        pane = self._active_pane
        backend = getattr(pane, "backend", None) if pane is not None else None
        if backend is None:
            QMessageBox.information(
                self,
                "No backend",
                "Deleting needs an active pane whose backend holds the files.",
            )
            return

        # Only touch entries that belong to the backend we actually
        # hold. The index spans hosts that may not be connected, and
        # deleting on the wrong one is unrecoverable.
        bid = _backend_id_for(backend)
        mine = [e for e in plan.deletable if e.backend_id == bid]
        others = len(plan.deletable) - len(mine)
        if not mine:
            QMessageBox.information(
                self,
                "Not reachable from here",
                "The selected copies live on backends other than the active "
                "pane's. Open a pane on that host and delete from there.",
            )
            return

        confirm = QMessageBox.question(
            self,
            "Delete duplicates",
            f"Delete {len(mine)} file(s) from {bid}?\n"
            f"{plan.survivors} copy/copies will remain."
            + (
                f"\n\n{others} selected copy/copies live elsewhere and are skipped."
                if others
                else ""
            )
            + "\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        removed, errors = 0, []
        for entry in mine:
            try:
                backend.remove(entry.path)
            except OSError as exc:
                errors.append(f"{entry.path}: {exc}")
                continue
            removed += 1
            try:
                CAS.remove(None, entry.backend_id, entry.path)
            except Exception as exc:  # noqa: BLE001 — index drift must not mask success
                log.warning("CAS index cleanup failed for %s: %s", entry.path, exc)

        if errors:
            QMessageBox.warning(
                self,
                "Some deletions failed",
                f"{removed} removed, {len(errors)} failed:\n" + "\n".join(errors[:10]),
            )
        self._status.setText(f"Deleted {removed} duplicate(s)")
        self._reload()

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
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data or data[0] != "entry":
            return
        entry = data[1]
        self.open_requested.emit(entry.backend_id, entry.path)
