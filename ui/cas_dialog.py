"""Duplicate Finder — dialog over :mod:`core.cas`.

Named for what it does, not for how. "CAS" is the storage technique
behind it and means nothing to someone looking for a way to find
duplicate files, which is how the feature went unnoticed.

The CAS index is a client-side SQLite store mapping
``(backend_id, path) -> (algorithm, value, size)``. Two files
sharing ``(algorithm, value)`` are duplicates regardless of which
backend they live on. This dialog wraps these operations:

* **Rebuild from Active Pane** — walk the pane's current directory,
  hash every file with the backend's own checksum and upsert the result
  into the CAS DB, in the background with counts, bytes and Cancel. A
  backend without a content checksum (SMB, plain FTP, WebDAV that only
  has ETags) has its files read instead — only those that share their
  size with another file, and only as far as their first bytes match
  (:func:`core.cas.rebuild`). The report names what was skipped and why.
* **Find Duplicates** — group rows by ``(algorithm, value)`` where
  count >= 2 and render each group's files, largest waste first, with the
  bytes each group and all of them would free. Each group also gets an
  ``ax-cas://<algo>:<hex>`` URL the user can copy. Empty files and
  groups that are only hard links of one file are hidden unless asked.
* **Filter / At least / Sort** — by name or path (``*.jpg``), by file
  size, and by space to reclaim, size, copies, name or folder.
* **Move Selected to Trash** — only the selected copies, and only after
  :func:`core.cas.delete_duplicates` re-checked on the live backend that
  each still holds the indexed content and that a genuine other copy
  survives. Removal goes to the axross trash, so it can be undone. When
  every copy of a group is selected (Ctrl+A), the first copy is kept.
* **Mark All Duplicates (keep first)** — selects every copy but the first
  of each group. The rows of a group are shown in survivor order (oldest
  modification time first, see :func:`core.cas.survivor_key`), so the
  first row is the copy that stays. **Mark, Keeping…** offers the other
  rules of :func:`core.cas.mark_duplicates`: the newest copy, the
  shortest path, the copy inside a folder, or "the copies inside a
  folder go". A hard link of a kept copy is never marked.
* **Show** — all scans, one recorded scan, or only the copies inside a
  folder; **Index & History…** opens :mod:`ui.cas_history_dialog`.

The window never waits on the index: queries run off the GUI thread
(:func:`ui.off_gui.run_off_gui`) and the rows of thousands of groups are
added in chunks, the first ones at once.

A "Rebuild" run is the only way fresh data lands in the index (and it is
recorded as a scan); a "Find" run is a SELECT and free.
"""

from __future__ import annotations

import fnmatch
import logging
from datetime import datetime

from PyQt6.QtCore import QEventLoop, QItemSelection, QItemSelectionModel, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from core import cas as CAS
from core.i18n import tr, tr_n
from ui.close_corner import add_close_corner
from ui.plain_text import plain_tooltip
from ui.scan_job import BusyStrip, ScanJob
from ui.icon_provider import set_window_icon

log = logging.getLogger("ui.cas_dialog")

COL_NAME, COL_FOLDER, COL_SIZE, COL_MODIFIED, COL_BACKEND, COL_HASH = range(6)

MARK_ALL_TEXT = "Mark All Duplicates (keep first)"
SURVIVOR_TIP = (
    "First in its group: kept by “Mark All Duplicates (keep first)” and when "
    "every copy is selected — the oldest copy; ties go to the shorter, then "
    "the alphabetically first path."
)
HARD_LINK_TIP = (
    "The same file as another row of this group (a hard link): removing this "
    "name frees no space, and it is never marked."
)

#: Groups whose rows are added to the tree at once; the rest follow in
#: chunks of this size, one per event-loop turn.
RENDER_CHUNK = 200

#: "At least" choices: label, bytes.
MIN_SIZES = (
    ("Any size", 0),
    ("1 KiB", 1024),
    ("100 KiB", 100 * 1024),
    ("1 MiB", 1024**2),
    ("10 MiB", 10 * 1024**2),
    ("100 MiB", 100 * 1024**2),
    ("1 GiB", 1024**3),
)

#: Sort choices: label, key name (see _SORT_KEYS).
SORTS = (
    ("Most space to reclaim", "reclaim"),
    ("Largest files", "size"),
    ("Most copies", "copies"),
    ("Name", "name"),
    ("Folder", "folder"),
)

#: The "Mark, Keeping…" rules: label, rule of core.cas.mark_duplicates.
KEEP_RULE_LABELS = (
    ("Keep the Oldest Copy (first)", "oldest"),
    ("Keep the Newest Copy", "newest"),
    ("Keep the Shortest Path", "shortest-path"),
    ("Keep the Copy Inside a Folder…", "keep-in-folder"),
    ("Mark the Copies Inside a Folder…", "mark-in-folder"),
)


# The plan lives in core so the scripting API (``axross.dedupe``) and this
# dialog decide alike; re-exported here for existing imports.
DeletionPlan = CAS.DeletionPlan
plan_deletion = CAS.plan_deletion


def _format_size(n: int) -> str:
    """``512 B``, ``1.5 KiB`` … ``2.0 TiB``: one decimal from KiB on (a
    floored ``1 GiB`` for 1.9 GiB undersold the waste by half)."""
    value = float(max(0, int(n or 0)))
    if value < 1024:
        return f"{value:.0f} B"
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        value /= 1024
        if value < 1024:
            return f"{value:.1f} {unit}"
    return f"{value / 1024:.1f} PiB"


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
        return tr("unknown")
    try:
        return datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return tr("unknown")


def scan_label(scan) -> str:
    """One line for a scan in the Show list."""
    if scan.scan_id == CAS.EARLIER_SCANS:
        return tr("Earlier scans (before scan history)")
    when = scan.started_at.strftime("%Y-%m-%d %H:%M") if scan.started_at else "?"
    return tr("Scan #{id}: {root} [{backend}] — {when} ({status})").format(
        id=scan.scan_id, root=scan.root, backend=scan.backend_id, when=when, status=tr(scan.status))


def path_matcher(text: str):
    """A predicate on full paths for the Filter field, or None for "all".

    Words with ``*``, ``?`` or ``[`` are glob patterns, matched against the
    file name - or, when the pattern holds a separator, against the end of
    the path (``photos/*.jpg``) - case-insensitively; several are separated
    by spaces (``*.jpg *.png``).
    Any other text is a case-insensitive part of the path."""
    text = (text or "").strip()
    if not text:
        return None
    if not any(c in text for c in "*?["):
        needle = text.casefold()
        return lambda path: needle in path.casefold()
    patterns = []
    for word in text.casefold().split():
        if "/" in word or "\\" in word:
            # A folder part: anchored at a separator, wherever it is.
            if not word.startswith(("*", "/", "\\")):
                word = "*/" + word
            patterns.append((True, word))
        else:
            patterns.append((False, word))

    def match(path: str) -> bool:
        folded = path.casefold()
        name = _split_path(folded)[1]
        return any(fnmatch.fnmatchcase(folded if whole else name, pattern)
                   for whole, pattern in patterns)

    return match


def _group_size(group) -> int:
    return max((int(e.size or 0) for e in group), default=0)


class _Group(list):
    """The rows of one duplicate group (survivor order) and its figures,
    worked out once - off the GUI thread - instead of per sort and filter."""

    def __init__(self, rows) -> None:
        super().__init__(rows)
        self.size = _group_size(self)
        self.distinct = CAS.distinct_copies(self)
        self.reclaim = CAS.reclaimable_bytes(self)
        self.empty = bool(self) and CAS.is_empty_content(self[0])
        self.undated = CAS.has_undated(self)


_SORT_KEYS = {
    "reclaim": lambda g: (-g.reclaim, -g.size, g[0].path),
    "size": lambda g: (-g.size, -len(g), g[0].path),
    "copies": lambda g: (-len(g), -g.size, g[0].path),
    "name": lambda g: (_split_path(g[0].path)[1].casefold(), g[0].path),
    "folder": lambda g: (g[0].path.casefold(), g[0].path),
}


def _entry_key(entry) -> tuple:
    return (entry.backend_id, entry.path, entry.algorithm, entry.value)


class _GroupTree(QTreeWidget):
    """The finder's tree. A selection change of many rows (Mark All over
    thousands of groups, or a click that clears such a selection) is
    applied with painting held: Qt otherwise unites one screen region per
    row, which grows with the square of the rows - 3000 groups took
    seconds, 20000 minutes. One repaint follows instead."""

    MANY = 64

    def selectionChanged(self, selected, deselected) -> None:  # noqa: N802 - Qt override
        if len(selected) + len(deselected) > self.MANY and self.updatesEnabled():
            self.setUpdatesEnabled(False)
            try:
                super().selectionChanged(selected, deselected)
            finally:
                self.setUpdatesEnabled(True)
            self.viewport().update()
        else:
            super().selectionChanged(selected, deselected)


class CasDuplicatesDialog(QDialog):
    """Tree of duplicate-content groups, with rebuild + copy-URL."""

    open_requested = pyqtSignal(str, str)  # backend_id, path
    #: Identical folders: open that folder in a pane / bookmark it.
    open_folder_requested = pyqtSignal(str, str)  # backend_id, folder
    bookmark_folder_requested = pyqtSignal(str, str)  # backend_id, folder

    def __init__(self, active_pane=None, parent=None, backends=None, scan_id=None) -> None:
        """*backends* are the connected backends of every open pane; a copy
        on one of them can be verified as the survivor of a deletion.
        *scan_id* opens the finder on the duplicates of that scan."""
        super().__init__(parent)
        set_window_icon(self, "duplicates")
        self._scope: tuple = ("all", None) if scan_id is None else ("scan", int(scan_id))
        self._history_dialog = None
        self._active_pane = active_pane
        self._backends: dict = {}
        for backend in [getattr(active_pane, "backend", None), *(backends or [])]:
            if backend is not None:
                self._backends.setdefault(_backend_id_for(backend), backend)
        # Every group of the scope as loaded (the deletion plan needs whole
        # groups); the groups the filters let through, in display order;
        # how many of those have rows in the tree.
        self._groups: list[list] = []
        self._view: list[list] = []
        self._rendered = 0
        self._render_gen = 0
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.setInterval(0)
        self._render_timer.timeout.connect(self._render_more)
        self._summary = (0, 0, 0)
        self._loading = False
        self._reload_again = False
        self._folder_groups: list = []
        self._rebuild_stats: CAS.RebuildStats | None = None
        self._rebuild_bid = ""
        self._delete_total = 0
        self.setWindowTitle(tr("Duplicate Finder"))
        self.resize(1100, 650)
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
            tr("Indexed files grouped by content hash — every row in a group "
            "holds identical content, wherever it lives. Use “Rebuild from "
            "Active Pane” to index a directory first.")
        )
        intro.setProperty("role", "muted")
        intro.setWordWrap(True)
        root.addWidget(intro)

        scope_row = QHBoxLayout()
        scope_row.addWidget(QLabel(tr("Show:"), self))
        self._scope_combo = QComboBox(self)
        self._scope_combo.setToolTip(
            tr("All scans; one scan (every group with a copy from it, all copies "
            "shown); or only the copies inside a folder")
        )
        self._scope_combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self._scope_combo.currentIndexChanged.connect(self._on_scope_chosen)
        scope_row.addWidget(self._scope_combo, stretch=1)
        self._folders_check = QCheckBox(tr("Identical folders"), self)
        self._folders_check.setToolTip(
            tr("Folders with the same content: recursively the same relative paths and "
            "names, every file with the same hash (the folder's own name may differ). "
            "Only folders inside a completed scan are compared; empty folders are not "
            "in the index."))
        self._folders_check.toggled.connect(lambda _on: self._reload())
        scope_row.addWidget(self._folders_check)
        self._history_btn = QPushButton(tr("Index && History…"), self)
        self._history_btn.setToolTip(
            tr("Every scan that built the index: show its duplicates, re-scan, "
            "remove it from the index, or clear the whole index")
        )
        self._history_btn.clicked.connect(self._open_history)
        scope_row.addWidget(self._history_btn)
        root.addLayout(scope_row)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel(tr("Filter:"), self))
        self._filter_edit = QLineEdit(self)
        self._filter_edit.setClearButtonEnabled(True)
        self._filter_edit.setPlaceholderText(tr("Name or path, e.g. *.jpg *.png or holiday (Ctrl+F)"))
        self._filter_edit.setToolTip(
            tr("Show only groups with a copy whose path contains this text, or whose "
            "name matches one of the patterns (*, ?, [...]); not case-sensitive")
        )
        # Typing re-filters once it pauses, not on every key.
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(250)
        self._filter_timer.timeout.connect(self._apply_view)
        self._filter_edit.textChanged.connect(lambda _t: self._filter_timer.start())
        self._filter_edit.returnPressed.connect(self._apply_view)
        filter_row.addWidget(self._filter_edit, stretch=2)
        filter_row.addWidget(QLabel(tr("At least:"), self))
        self._min_size_combo = QComboBox(self)
        for label, size in MIN_SIZES:
            self._min_size_combo.addItem(tr(label), size)
        self._min_size_combo.setToolTip(tr("Hide groups of files smaller than this"))
        self._min_size_combo.currentIndexChanged.connect(lambda _i: self._apply_view())
        filter_row.addWidget(self._min_size_combo)
        filter_row.addWidget(QLabel(tr("Sort:"), self))
        self._sort_combo = QComboBox(self)
        for label, key in SORTS:
            self._sort_combo.addItem(tr(label), key)
        self._sort_combo.setToolTip(tr("Order of the groups; the copies of a group stay in "
                                    "survivor order (the first one is kept)"))
        self._sort_combo.currentIndexChanged.connect(lambda _i: self._apply_view())
        filter_row.addWidget(self._sort_combo)
        self._empty_check = QCheckBox(tr("Empty files"), self)
        self._empty_check.setToolTip(
            tr("Every empty file has the same hash. They are hidden by default: "
            "removing them frees nothing, and many have to exist (__init__.py, "
            ".gitkeep, lock and marker files).")
        )
        self._empty_check.toggled.connect(lambda _on: self._apply_view())
        filter_row.addWidget(self._empty_check)
        self._links_check = QCheckBox(tr("Hard links"), self)
        self._links_check.setToolTip(
            tr("Show groups whose rows are all names of one file (hard links): "
            "there is nothing to reclaim in them")
        )
        self._links_check.toggled.connect(lambda _on: self._apply_view())
        filter_row.addWidget(self._links_check)
        root.addLayout(filter_row)

        btn_row = QHBoxLayout()
        self._rebuild_btn = QPushButton(tr("Rebuild from Active Pane…"), self)
        self._rebuild_btn.clicked.connect(self._do_rebuild_active)
        self._rebuild_btn.setEnabled(self._active_pane is not None)
        btn_row.addWidget(self._rebuild_btn)

        self._refresh_btn = QPushButton(tr("Refresh"), self)
        self._refresh_btn.setToolTip(tr("Read the index again (F5)"))
        self._refresh_btn.clicked.connect(self._refresh)
        btn_row.addWidget(self._refresh_btn)

        self._mark_all_btn = QPushButton(tr(MARK_ALL_TEXT), self)
        self._mark_all_btn.setToolTip(
            tr("Select every copy except the first of each group — the oldest by "
            "modification time. Review, then Move Selected to Trash.")
        )
        self._mark_all_btn.clicked.connect(self._mark_all_duplicates)
        btn_row.addWidget(self._mark_all_btn)

        self._keep_btn = QPushButton(tr("Mark, Keeping…"), self)
        self._keep_btn.setToolTip(
            tr("Select every copy except the one a rule keeps: the newest, the "
            "shortest path, the one inside a folder — or select the copies "
            "inside a folder. One copy of every group always stays.")
        )
        self._keep_menu = self._build_keep_menu(self._keep_btn)
        self._keep_btn.setMenu(self._keep_menu)
        btn_row.addWidget(self._keep_btn)

        self._copy_btn = QPushButton(tr("Copy ax-cas URL"), self)
        self._copy_btn.clicked.connect(self._copy_url)
        btn_row.addWidget(self._copy_btn)

        self._delete_btn = QPushButton(tr("Move Selected to Trash…"), self)
        self._delete_btn.setToolTip(
            tr("Move the selected copies to the axross trash (restorable via Show Trash). "
            "Each file is re-checked first, and at least one verified copy of every "
            "group is always kept: when every copy of a group is selected, the first "
            "(oldest) one stays. (Del)")
        )
        self._delete_btn.clicked.connect(self._delete_selected)
        btn_row.addWidget(self._delete_btn)

        self._export_btn = QPushButton(tr("Copy list"), self)
        self._export_btn.setToolTip(tr("Copy every duplicate group shown to the clipboard"))
        self._export_btn.clicked.connect(self._export)
        btn_row.addWidget(self._export_btn)
        btn_row.addStretch(1)
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
        self._tree = _GroupTree(self)
        self._tree.setColumnCount(6)
        self._tree.setHeaderLabels([tr("Name"), tr("Folder"), tr("Size"), tr("Modified"), tr("Backend"), tr("Hash")])
        # Every row has one height: Qt then lays out thousands of rows
        # without measuring each.
        self._tree.setUniformRowHeights(True)
        font = self._tree.font()
        # Monospace is much nicer for hashes.
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._tree.setFont(font)
        # The file name gets its own column: inside one long path column it
        # sat at the end and was the first thing elided. Whatever still has
        # to be shortened keeps both ends; the tooltip holds the full path.
        self._tree.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        from ui.column_fit import ColumnFitter

        header = self._tree.header()
        # Folder takes the free width, the others fit their content; every
        # divider stays draggable (ui.column_fit).
        self._columns = ColumnFitter(self._tree, fill=COL_FOLDER, keep=(COL_NAME,))
        # A full sha256 is 64 characters and used to take the room the
        # names needed; it is in the tooltip and in "Copy ax-cas URL".
        header.setSectionResizeMode(COL_HASH, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(COL_HASH, 140)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        delete_key = QShortcut(QKeySequence(QKeySequence.StandardKey.Delete), self._tree)
        delete_key.setContext(Qt.ShortcutContext.WidgetShortcut)
        delete_key.activated.connect(self._delete_selected)
        for key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            open_key = QShortcut(QKeySequence(key), self._tree)
            open_key.setContext(Qt.ShortcutContext.WidgetShortcut)
            open_key.activated.connect(self._open_current)
        find_key = QShortcut(QKeySequence(QKeySequence.StandardKey.Find), self)
        find_key.activated.connect(self._focus_filter)
        refresh_key = QShortcut(QKeySequence(Qt.Key.Key_F5), self)
        refresh_key.activated.connect(self._refresh)
        # Removing duplicates is inherently a multi-row action, and the
        # default single-selection tree made "delete the copies I don't
        # want" a one-at-a-time affair.
        self._tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self._tree.itemDoubleClicked.connect(self._on_double_click)
        self._tree.currentItemChanged.connect(lambda cur, _prev: self._show_details(cur))
        self._tree.currentItemChanged.connect(lambda _cur, _prev: self._update_buttons())
        self._tree.itemSelectionChanged.connect(self._on_selection_changed)
        root.addWidget(self._tree, stretch=1)

        # The current row in full: path, exact size, identity, hash.
        self._details = QLabel("", self)
        # A path is the file's own name, from any server: never markup.
        self._details.setTextFormat(Qt.TextFormat.PlainText)
        self._details.setProperty("role", "muted")
        self._details.setWordWrap(True)
        self._details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(self._details)

        self._status = QLabel("", self)
        self._status.setProperty("role", "muted")
        self._status.setWordWrap(True)
        root.addWidget(self._status)

        # One status line at the bottom while a scan runs.
        self._strip = BusyStrip(self._job, self)
        self._busy_bar = self._strip.bar
        self._progress_label = self._strip.label
        self._cancel_btn = self._strip.cancel_button
        self._job.started.connect(self._on_job_started)
        root.addWidget(self._strip)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        close.accepted.connect(self.accept)
        root.addWidget(close)

    def _build_keep_menu(self, parent) -> QMenu:
        menu = QMenu(parent)
        for label, rule in KEEP_RULE_LABELS:
            if rule == "mark-in-folder":
                menu.addSeparator()
            menu.addAction(tr(label), lambda r=rule: self.mark(r))
        return menu

    def _on_job_started(self) -> None:
        self._rebuild_btn.setEnabled(False)
        self._busy_bar.setRange(0, 0)
        self._update_buttons()

    def _update_buttons(self) -> None:
        """Enable only what has something to act on: an empty index left
        Mark All, Mark Keeping, Copy URL, Move to Trash and Copy list
        clickable ("1 row(s) copied" of an empty table)."""
        if not hasattr(self, "_export_btn"):
            return
        running = self._job.running
        folders = self.folder_mode()
        groups = self._tree.topLevelItemCount() > 0
        self._mark_all_btn.setEnabled(groups and not running)
        self._keep_btn.setEnabled(groups and not folders and not running)
        kind, _payload = self._selected_kind_payload()
        self._copy_btn.setEnabled(kind in ("group", "entry"))
        chosen = bool(self.selected_folders() if folders else self.selected_entries())
        self._delete_btn.setEnabled(chosen and not running)
        self._export_btn.setEnabled(bool(self._view) and not folders)

    def _focus_filter(self) -> None:
        self._filter_edit.setFocus()
        self._filter_edit.selectAll()

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
        from ui.off_gui import run_off_gui

        try:
            scans = run_off_gui(lambda: CAS.list_scans(None))
        except Exception as exc:  # noqa: BLE001 — a broken index must not hide the dialog
            log.warning("CAS.list_scans failed: %s", exc)
            scans = []
        combo = self._scope_combo
        combo.blockSignals(True)
        try:
            combo.clear()
            combo.addItem(tr("All scans"), ("all", None))
            for scan in scans:
                combo.addItem(scan_label(scan), ("scan", scan.scan_id))
            kind, value = self._scope
            if kind == "scan" and not any(s.scan_id == value for s in scans):
                combo.addItem(tr("Scan #{value} (no longer in the index)").format(value=value), ("scan", value))
            if kind == "folder" and value:
                combo.addItem(tr("Only inside folder: {value}").format(value=value), ("folder", value))
            combo.addItem(tr("Only inside folder…"), ("folder", None))
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
                tr("Only Inside Folder"),
                tr("Show only duplicates whose copies lie inside this folder (on any backend):"),
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

    def _query_groups(self, scope=None) -> list:
        """Groups of every algorithm in the index (rebuild defaults to sha256,
        but a backend may have registered md5: S3 ETag, Azure Content-MD5)."""
        kind, value = scope if scope is not None else self._scope
        if kind == "scan":
            return CAS.duplicates(None, None, scan_id=value)
        if kind == "folder":
            return CAS.duplicates(None, None, folder=value)
        return CAS.duplicates(None, None)

    def folder_mode(self) -> bool:
        return self._folders_check.isChecked()

    def _reload_folders(self) -> None:
        from core import cas_folders as CF
        from ui.off_gui import run_off_gui

        kind, value = self._scope
        inside = value if kind == "folder" else None
        try:
            groups = run_off_gui(lambda: CF.identical_folders(None, folder=inside))
        except Exception as exc:  # noqa: BLE001
            log.warning("identical folders failed: %s", exc)
            groups = []
        self._folder_groups = groups
        self._render_folders()

    def _render_folders(self) -> None:
        self._tree.clear()
        match = path_matcher(self._filter_edit.text())
        least = int(self._min_size_combo.currentData() or 0)
        shown = [
            members for members in self._folder_groups
            if members[0][0].size >= least
            and (match is None or any(match(copy.path) for copy, _e in members))
        ]
        for members in shown:
            head = members[0][0]
            parent = QTreeWidgetItem(self._tree)
            parent.setText(COL_NAME, tr_n(len(members), "{n} identical folder", "{n} identical folders")
                           + " · " + tr_n(head.files, "{n} file", "{n} files"))
            parent.setText(COL_SIZE, _format_size(head.size))
            parent.setData(COL_NAME, Qt.ItemDataRole.UserRole, ("folder-group", members))
            for copy, entries in members:
                folder, name = _split_path(copy.path)
                child = QTreeWidgetItem(parent)
                child.setText(COL_NAME, name)
                child.setText(COL_FOLDER, folder)
                child.setText(COL_SIZE, _format_size(copy.size))
                child.setText(COL_BACKEND, copy.backend_id)
                for col in (COL_NAME, COL_FOLDER):
                    child.setToolTip(col, plain_tooltip(copy.path))
                child.setData(COL_NAME, Qt.ItemDataRole.UserRole, ("folder", (copy, entries)))
            parent.setExpanded(True)
        self._undated_label.setVisible(False)
        reclaim = sum(m[0][0].size * (len(m) - 1) for m in shown)
        text = tr_n(len(shown), "{n} group of identical folders",
                    "{n} groups of identical folders")
        if shown:
            text += tr(" — {size} to reclaim").format(size=_format_size(reclaim))
        if len(shown) != len(self._folder_groups):
            text += tr(" ({n} more hidden by the filters)").format(
                n=len(self._folder_groups) - len(shown))
        self._status.setText(text)
        self._update_buttons()

    def _reload(self) -> None:
        """Read the index again and show it. Re-entered while it waits (a
        finished job refreshing meanwhile), it reads once more afterwards."""
        if self._loading:
            self._reload_again = True
            return
        self._loading = True
        try:
            while True:
                self._reload_again = False
                self._load_once()
                if not self._reload_again:
                    break
        finally:
            self._loading = False

    def _load_once(self) -> None:
        from ui.off_gui import run_off_gui

        self._render_gen += 1  # stop rows of an earlier load still being added
        self._tree.clear()
        if self.folder_mode():
            self._groups = []
            self._view = []
            self._rendered = 0
            self._reload_folders()
            return
        scope = self._scope
        try:
            groups = run_off_gui(
                lambda: [_Group(g) for g in self._query_groups(scope) if g],
                status=self._status.setText, text=tr("Reading the duplicate index…"))
        except Exception as exc:  # noqa: BLE001
            log.warning("CAS.duplicates failed: %s", exc)
            groups = []
        # Kept so plan_deletion can see whole groups, not just the rows
        # the user happened to click — the safety check needs to know
        # how many copies a group started with.
        self._groups = groups
        self._apply_view()

    def _passes(self, group, match, least: int) -> bool:
        if not self._empty_check.isChecked() and group.empty:
            return False
        if not self._links_check.isChecked() and group.distinct < 2:
            return False
        if least and group.size < least:
            return False
        return match is None or any(match(e.path) for e in group)

    def _apply_view(self) -> None:
        """Filter and sort the loaded groups and show them: the first
        RENDER_CHUNK at once, the rest a chunk per event-loop turn."""
        self._filter_timer.stop()
        if self.folder_mode():
            self._render_folders()
            return
        self._render_gen += 1
        self._tree.clear()
        self._details.setText("")
        match = path_matcher(self._filter_edit.text())
        least = int(self._min_size_combo.currentData() or 0)
        view = [g for g in self._groups if self._passes(g, match, least)]
        view.sort(key=_SORT_KEYS[self._sort_combo.currentData() or "reclaim"])
        self._view = view
        self._rendered = 0
        self._summary = (
            sum(len(g) for g in view),
            sum(g.reclaim for g in view),
            sum(1 for g in view if g.undated),
        )
        self._render_chunk()
        self._tree.resizeColumnToContents(COL_NAME)
        # Wide enough for the names, but never so wide the folder vanishes.
        cap = max(200, self._tree.viewport().width() // 2)
        if self._tree.columnWidth(COL_NAME) > cap:
            self._tree.setColumnWidth(COL_NAME, cap)
        undated = self._summary[2]
        self._undated_label.setText(
            tr("{undated} group(s) contain copies without a modification time: those "
                "sort after dated copies, then by path, so “first” there means the "
                "shortest path. Rebuild the index to record the times.").format(undated=undated)
        )
        self._undated_label.setVisible(undated > 0)
        self._update_status()
        self._schedule_render()

    def _update_status(self) -> None:
        files, reclaim, _undated = self._summary
        text = (tr_n(len(self._view), "{n} duplicate group", "{n} duplicate groups")
                + " " + tr_n(files, "covering {n} file", "covering {n} files"))
        if self._view:
            text += tr(" — {size} to reclaim").format(size=_format_size(reclaim))
        hidden = len(self._groups) - len(self._view)
        if hidden:
            text += tr(" ({n} more hidden by the filters)").format(n=hidden)
        if self._rendered < len(self._view):
            text += tr(" — showing {n}, adding the rest…").format(n=self._rendered)
        self._status.setText(text)
        self._update_buttons()

    def _schedule_render(self) -> None:
        # A timer owned by the dialog: it dies with it, so no chunk is ever
        # added to a closed window.
        if self._rendered < len(self._view):
            self._render_timer.start()

    def _render_more(self) -> None:
        if self._rendered >= len(self._view):
            return
        self._render_chunk()
        self._update_status()
        self._schedule_render()

    def render_all(self) -> bool:
        """Add every row still to come, keeping the window painted; False
        when a reload replaced the view meanwhile."""
        gen = self._render_gen
        while self._rendered < len(self._view):
            self._render_chunk()
            QApplication.processEvents(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
            if gen != self._render_gen:
                return False
        self._update_status()
        return True

    def _render_chunk(self) -> None:
        start = self._rendered
        chunk = self._view[start:start + RENDER_CHUNK]
        if not chunk:
            return
        parents = [self._group_item(group) for group in chunk]
        self._tree.setUpdatesEnabled(False)
        try:
            self._tree.addTopLevelItems(parents)
            for parent in parents:
                parent.setExpanded(True)
        finally:
            self._tree.setUpdatesEnabled(True)
        self._rendered = start + len(chunk)

    def _group_item(self, group) -> QTreeWidgetItem:
        parent = QTreeWidgetItem()
        head = group[0]
        distinct = group.distinct
        reclaim = group.reclaim
        label = f"[{head.algorithm}] " + tr_n(len(group), "{n} copy", "{n} copies")
        if distinct < len(group):
            links = len(group) - distinct
            label += " (" + tr_n(links, "{n} hard link", "{n} hard links") + ")"
        if reclaim:
            label += tr(" · {size} to reclaim").format(size=_format_size(reclaim))
        parent.setText(COL_NAME, label)
        parent.setText(COL_SIZE, _format_size(group.size))
        parent.setText(COL_HASH, head.value)
        parent.setToolTip(COL_HASH, f"{head.algorithm}:{head.value}")
        parent.setData(COL_NAME, Qt.ItemDataRole.UserRole, ("group", head.algorithm, head.value))
        ids = [e.file_id for e in group if e.file_id is not None]
        linked = {i for i in ids if ids.count(i) > 1}
        # Rows come in survivor order: the first one is the copy that stays.
        children = []
        for position, entry in enumerate(group):
            folder, name = _split_path(entry.path)
            child = QTreeWidgetItem()
            child.setText(COL_NAME, name)
            child.setText(COL_FOLDER, folder)
            size_text = _format_size(entry.size)
            if entry.file_id in linked:
                size_text += tr(" · hard link")
                child.setToolTip(COL_SIZE, tr(HARD_LINK_TIP))
            child.setText(COL_SIZE, size_text)
            child.setText(COL_MODIFIED, _format_mtime(entry.mtime))
            child.setText(COL_BACKEND, entry.backend_id)
            for col in (COL_NAME, COL_FOLDER):
                child.setToolTip(col, plain_tooltip(entry.path))
            if position == 0:
                font = child.font(COL_MODIFIED)
                font.setBold(True)
                child.setFont(COL_MODIFIED, font)
                child.setToolTip(COL_MODIFIED, tr(SURVIVOR_TIP))
            child.setData(COL_NAME, Qt.ItemDataRole.UserRole, ("entry", entry))
            children.append(child)
        parent.addChildren(children)
        return parent

    def visible_groups(self) -> list:
        """The groups the filters let through, in display order."""
        return list(self._view)

    # ------------------------------------------------------------------
    # Details line
    # ------------------------------------------------------------------
    def _show_details(self, item) -> None:
        data = item.data(COL_NAME, Qt.ItemDataRole.UserRole) if item is not None else None
        if not data:
            self._details.setText("")
            return
        if data[0] == "entry":
            entry = data[1]
            parts = [entry.path, tr("{n:,} bytes").format(n=entry.size),
                     tr("modified {when}").format(when=_format_mtime(entry.mtime)),
                     f"[{entry.backend_id}]", f"{entry.algorithm}:{entry.value}"]
            group = self._group_of(item)
            if entry.file_id is not None and group:
                twins = [e.path for e in group
                         if e.file_id == entry.file_id and e.path != entry.path]
                if twins:
                    parts.append(tr("same file as {paths}").format(paths=", ".join(twins[:3])))
            self._details.setText(" · ".join(parts))
        elif data[0] == "group":
            group = self._group_of(item.child(0)) if item.childCount() else None
            if group:
                self._details.setText(
                    tr("{n} copies of {size:,} bytes · {reclaimable_bytes} to reclaim · "
                        "{cas_url}").format(n=len(group), size=group[0].size, reclaimable_bytes=_format_size(CAS.reclaimable_bytes(group)), cas_url=CAS.cas_url(group[0].algorithm, group[0].value))
                )
        elif data[0] == "folder":
            copy = data[1][0]
            self._details.setText(tr("{path} · {files} file(s) · {size:,} bytes").format(path=copy.path, files=copy.files, size=copy.size))
        else:
            self._details.setText("")

    def _group_of(self, child):
        """The CasEntry rows of the group *child* belongs to."""
        parent = child.parent() if child is not None else None
        if parent is None:
            return None
        rows = []
        for i in range(parent.childCount()):
            data = parent.child(i).data(COL_NAME, Qt.ItemDataRole.UserRole)
            if data and data[0] == "entry":
                rows.append(data[1])
        return rows

    def _on_selection_changed(self) -> None:
        self._update_buttons()
        if self._job.running:
            return
        entries = self.selected_entries()
        if not entries:
            if not self.folder_mode() and not self._loading:
                self._update_status()
            return
        total = sum(int(e.size or 0) for e in entries)
        self._status.setText(tr_n(len(entries), "{n} file selected — {size}",
                                  "{n} files selected — {size}", size=_format_size(total)))

    # ------------------------------------------------------------------
    # Rebuild
    # ------------------------------------------------------------------
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
            tr("Rebuild CAS"),
            tr("Walk and (re)hash every file under\n{path}\non backend [{bid}]?\n\nNative "
                "checksum is used where available. Where the backend has none, files "
                "are read and hashed here — only those that share their size with "
                "another file, and only as far as their first bytes match.").format(path=path, bid=bid),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._rebuild_root = path
        self._rebuild_bid = bid
        self._job_kind = "rebuild"
        stats = CAS.RebuildStats()
        self._rebuild_stats = stats
        self._job.start(
            lambda cancel, progress: CAS.rebuild(
                backend, path, backend_id=bid, cancel=cancel, progress=progress,
                read_missing=True, stats=stats,
            )
        )

    def _format_progress(self, state: dict) -> str:
        from ui.scan_job import shorten

        where = shorten(state["path"])
        if self._job_kind in ("delete", "delete-folders"):
            total = self._delete_total
            if self._job_kind == "delete" and total:
                self._busy_bar.setRange(0, total)
                self._busy_bar.setValue(min(total, int(state["scanned"])))
                return (tr("Checking and moving to trash… {scanned} of {total} checked, {indexed} "
                    "moved — {where}").format(scanned=state['scanned'], total=total, indexed=state['indexed'], where=where))
            return tr("Checking and moving to trash… {indexed} moved — ").format(indexed=state['indexed']) + where
        stats = self._rebuild_stats
        if stats is not None and stats.phase == "read" and stats.read_total:
            self._busy_bar.setRange(0, stats.read_total)
            self._busy_bar.setValue(min(stats.read_total, stats.read_done))
            return (
                tr("Reading files without a checksum… {read_done} of {read_total}, "
                    "{indexed} indexed, {bytes_hashed} hashed — {where}").format(read_done=stats.read_done, read_total=stats.read_total, indexed=state['indexed'], bytes_hashed=_format_size(stats.bytes_hashed), where=where)
            )
        text = tr("Working… {indexed} indexed, {scanned} scanned").format(indexed=state['indexed'], scanned=state['scanned'])
        if stats is not None:
            text += tr(", {bytes_hashed} hashed").format(bytes_hashed=_format_size(stats.bytes_hashed))
            if stats.unchanged:
                text += tr(" ({unchanged} unchanged)").format(unchanged=stats.unchanged)
        return text + f" — {where}"

    def _on_job_finished(self, kind: str, value, cancelled: bool) -> None:
        self._busy_bar.setRange(0, 0)
        self._update_buttons()
        if self._job_kind == "delete-folders":
            self._on_folders_trashed(kind, value, cancelled)
        elif self._job_kind == "delete":
            self._on_delete_finished(kind, value, cancelled)
        else:
            self._on_rebuild_finished(kind, value, cancelled)

    def _on_rebuild_finished(self, kind: str, value, cancelled: bool) -> None:
        self._rebuild_btn.setEnabled(self._active_pane is not None)
        path = self._rebuild_root
        if kind == "error":
            QMessageBox.warning(self, tr("Rebuild CAS"), tr("Rebuild failed:\n{value}").format(value=value))
            return
        text, trouble = rebuild_report(
            value, path, self._rebuild_stats, cancelled, self._rebuild_bid
        )
        (QMessageBox.warning if trouble else QMessageBox.information)(self, tr("Rebuild CAS"), text)
        self._refresh()

    def reject(self) -> None:
        # Esc, the Close button and the window's own close all land here or
        # in closeEvent; a running scan must not outlive the dialog.
        self._job.abandon()
        self._render_gen += 1
        self._render_timer.stop()
        super().reject()

    def closeEvent(self, event) -> None:
        self._job.abandon()
        self._render_gen += 1
        self._render_timer.stop()
        super().closeEvent(event)

    # ------------------------------------------------------------------
    # Selection and removal
    # ------------------------------------------------------------------
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
        if self.folder_mode():
            self._trash_selected_folders()
            return
        if self._job.running:
            return  # one background job at a time
        selected = self.selected_entries()
        if not selected:
            QMessageBox.information(
                self, tr("Move to Trash"), tr("Select the file rows you want to remove.")
            )
            return

        # Every copy of a group selected (Ctrl+A): its first copy is kept.
        plan = plan_deletion(selected, self._groups)
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
                tr("Not reachable from here"),
                tr("The selected copies live on backends that are not open in any "
                "pane. Open a pane on that host and try again."),
            )
            return

        hosts = sorted({e.backend_id for e in mine})
        size = sum(int(e.size or 0) for e in mine)
        kept = tr_n(plan.survivors, "{n} copy is kept", "{n} copies are kept")
        if plan.auto_kept:
            kept += (
                tr(" — in {n} group(s) every copy was selected, so the first (oldest) "
                    "copy of each stays").format(n=len(plan.auto_kept))
            )
        confirm = QMessageBox.question(
            self,
            tr("Move to Trash"),
            tr("Move {n} file(s) ({size}) on {hosts} to the axross "
                "trash?\n{kept}.\n\nEach file is re-checked first: it is only moved if it "
                "still holds the indexed content and another verified copy remains. "
                "Trashed files can be restored via Show Trash.").format(n=len(mine), size=_format_size(size), hosts=', '.join(hosts), kept=kept)
            + (
                tr("\n\n{others} selected copy/copies live on backends that are not open "
                    "and are skipped.").format(others=others)
                if others
                else ""
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        groups = list(self._groups)
        backends = dict(self._backends)
        self._job_kind = "delete"
        self._delete_total = len(mine)
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
            QMessageBox.warning(self, tr("Move to Trash"), tr("Failed:\n{value}").format(value=value))
            self._reload()
            return
        outcome = value
        freed = sum(int(e.size or 0) for e in outcome.removed)
        lines = [tr("{n} file(s) moved to the axross trash ({freed}).").format(n=len(outcome.removed), freed=_format_size(freed))]
        if cancelled:
            lines.append(tr("Cancelled before every file was handled."))
        aliases = [e for e, why in outcome.refused if why == CAS.ALIAS_REASON]
        refused = [(e, why) for e, why in outcome.refused if why != CAS.ALIAS_REASON]
        if aliases:
            lines.append(
                tr("{n} selected name(s) are hard links of the copy that stays and were "
                    "left alone: removing them frees nothing.").format(n=len(aliases))
            )
        if refused or outcome.failed:
            lines.append("")
            lines += [tr("Kept {path}: {why}").format(path=e.path, why=why) for e, why in refused[:10]]
            lines += [tr("Failed {path}: {why}").format(path=e.path, why=why) for e, why in outcome.failed[:10]]
            hidden = len(refused) + len(outcome.failed) - 20
            if hidden > 0:
                lines.append(tr("… and {hidden} more").format(hidden=hidden))
            QMessageBox.warning(self, tr("Move to Trash"), "\n".join(lines))
        else:
            QMessageBox.information(self, tr("Move to Trash"), "\n".join(lines))
        self._refresh()
        self._status.setText(
            tr("Moved {n} duplicate(s) to trash, {freed} freed").format(n=len(outcome.removed), freed=_format_size(freed))
        )

    # ------------------------------------------------------------------
    # Identical folders
    # ------------------------------------------------------------------
    def selected_folders(self) -> list:
        """``(FolderCopy, entries)`` of every selected folder row."""
        out = []
        for item in self._tree.selectedItems():
            data = item.data(COL_NAME, Qt.ItemDataRole.UserRole)
            if data and data[0] == "folder":
                out.append(data[1])
        return out

    def _trash_selected_folders(self) -> None:
        """Move the selected folders to the trash; each group keeps one
        folder that is not selected (its first one when all are), and
        every removal is checked live first (core.cas_folders)."""
        if self._job.running:
            return
        chosen = {(c.backend_id, c.path) for c, _e in self.selected_folders()}
        if not chosen:
            QMessageBox.information(self, tr("Move to Trash"), tr("Select the folder rows to remove."))
            return
        pairs = []
        for members in self._folder_groups:
            keep = next((m for m in members if (m[0].backend_id, m[0].path) not in chosen),
                        members[0])
            for member in members:
                key = (member[0].backend_id, member[0].path)
                if key in chosen and member is not keep:
                    pairs.append((member, keep))
        if not pairs:
            return
        confirm = QMessageBox.question(
            self, tr("Move to Trash"),
            tr("Move {n} folder(s) to the axross trash?\n\nEach is checked first: it "
                "must still hold exactly the indexed files with their indexed content, "
                "and the folder kept must hold a separate, intact copy of every one. "
                "Trashed folders can be restored via Show Trash.").format(n=len(pairs)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes:
            return
        backends = dict(self._backends)

        def work(cancel, progress):
            from core import cas_folders as CF

            results = []
            for done, (remove, keep) in enumerate(pairs, 1):
                if cancel():
                    break
                results.append((remove[0], CF.trash_identical_folder(
                    backends, remove, keep, cancel=cancel)))
                progress(done, sum(1 for _c, o in results if o.removed), remove[0].path)
            return results

        self._job_kind = "delete-folders"
        self._job.start(work)

    def _on_folders_trashed(self, kind: str, value, cancelled: bool) -> None:
        self._rebuild_btn.setEnabled(self._active_pane is not None)
        if kind == "error":
            QMessageBox.warning(self, tr("Move to Trash"), tr("Failed:\n{value}").format(value=value))
        else:
            moved = [c for c, o in value if o.removed]
            kept = [(c, o.reason) for c, o in value if not o.removed]
            lines = [tr("{n} folder(s) moved to the axross trash.").format(n=len(moved))]
            if cancelled:
                lines.append(tr("Cancelled before every folder was handled."))
            lines += [tr("Kept {path}: {why}").format(path=c.path, why=why) for c, why in kept[:10]]
            (QMessageBox.warning if kept else QMessageBox.information)(
                self, tr("Move to Trash"), "\n".join(lines))
        self._refresh()

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
                tr("Open Containing Folder"),
                lambda: self.open_requested.emit(entry.backend_id, entry.path),
            )
            menu.addAction(tr("Keep This Copy, Select the Others"), lambda: self._keep_only(item))
            folder = _split_path(entry.path)[0]
            if folder:
                menu.addAction(
                    tr("Mark Every Copy Inside This Folder"),
                    lambda: self.mark("mark-in-folder", folder),
                )
                menu.addAction(
                    tr("Keep One Copy Inside This Folder, Mark the Others"),
                    lambda: self.mark("keep-in-folder", folder),
                )
            menu.addSeparator()
            menu.addAction(tr("Copy Path"), lambda: self._to_clipboard(entry.path))
            menu.addAction(tr("Copy File Name"), lambda: self._to_clipboard(_split_path(entry.path)[1]))
            menu.addAction(
                tr("Copy ax-cas URL"),
                lambda: self._to_clipboard(CAS.cas_url(entry.algorithm, entry.value)),
            )
        elif kind == "folder":
            copy = data[1][0]
            menu.addAction(tr("Open in Pane"),
                           lambda: self.open_folder_requested.emit(copy.backend_id, copy.path))
            menu.addAction(tr("Bookmark Folder…"),
                           lambda: self.bookmark_folder_requested.emit(copy.backend_id, copy.path))
            menu.addAction(tr("Keep This Folder, Select the Others"), lambda: self._keep_only(item))
            menu.addSeparator()
            menu.addAction(tr("Copy Path"), lambda: self._to_clipboard(copy.path))
        elif kind == "folder-group":
            menu.addAction(tr("Select All but One"), lambda: self._select_all_but_one([item]))
        elif kind == "group":
            _kind, algo, value = data
            menu.addAction(tr("Select All but One"), lambda: self._select_all_but_one([item]))
            menu.addAction(tr("Copy ax-cas URL"), lambda: self._to_clipboard(CAS.cas_url(algo, value)))
            menu.addAction(tr("Copy All Paths"), lambda: self._copy_group_paths(item))

        if kind is not None:
            menu.addSeparator()
        menu.addAction(tr(MARK_ALL_TEXT), self._mark_all_duplicates)
        keeping = menu.addMenu(tr("Mark All Duplicates, Keeping"))
        for label, rule in KEEP_RULE_LABELS:
            keeping.addAction(tr(label), lambda r=rule: self.mark(r))
        keeping.setEnabled(not self.folder_mode())
        menu.addAction(tr("Clear Selection"), self._tree.clearSelection)
        menu.addSeparator()
        has_files = bool(self.selected_entries()) or bool(self.selected_folders())
        trash = menu.addAction(tr("Move Selected to Trash…"), self._delete_selected)
        trash.setEnabled(has_files and not self._job.running)
        forget = menu.addAction(tr("Remove Selected from Index"), self._forget_selected)
        forget.setEnabled(has_files and not self._job.running)
        return menu

    @staticmethod
    def _file_id_of(item):
        data = item.data(COL_NAME, Qt.ItemDataRole.UserRole) if item is not None else None
        return data[1].file_id if data and data[0] == "entry" else None

    def _keep_only(self, keep) -> None:
        group = keep.parent()
        if group is None:
            return
        kept_id = self._file_id_of(keep)
        rows = []
        for i in range(group.childCount()):
            child = group.child(i)
            if child is keep:
                continue
            if kept_id is not None and self._file_id_of(child) == kept_id:
                continue  # a hard link of the kept copy: removing it frees nothing
            rows.append(child)
        self._select_items(rows)

    def _select_items(self, items) -> None:
        """Select exactly *items*, in one selection change (one per row
        made thousands of rows take seconds)."""
        selection = QItemSelection()
        last = self._tree.columnCount() - 1
        for item in items:
            index = self._tree.indexFromItem(item)
            if index.isValid():
                selection.select(index, self._tree.indexFromItem(item, last))
        flags = QItemSelectionModel.SelectionFlag.ClearAndSelect
        self._tree.selectionModel().select(selection, flags)

    def _mark_all_duplicates(self) -> None:
        """Select every copy except the first (the survivor) of each group."""
        if self.folder_mode():
            self._select_all_but_one(
                [self._tree.topLevelItem(i) for i in range(self._tree.topLevelItemCount())]
            )
            marked = len(self.selected_folders())
            self._status.setText(tr_n(marked, "{n} duplicate folder marked",
                                      "{n} duplicate folders marked"))
            return
        self.mark("oldest")

    def mark(self, rule: str, folder: str | None = None) -> int:
        """Select the copies :func:`core.cas.mark_duplicates` chooses under
        *rule* in every group shown; asks for the folder of the folder
        rules when *folder* is None. Returns how many were marked."""
        if self.folder_mode():
            return 0
        if rule in ("keep-in-folder", "mark-in-folder") and not folder:
            start = getattr(self._active_pane, "current_path", "") or ""
            prompt = (tr("Keep the copies inside this folder and mark the others "
                         "(groups without a copy there are left alone):")
                      if rule == "keep-in-folder" else
                      tr("Mark the copies inside this folder (a group with every copy "
                         "inside keeps its oldest one):"))
            text, ok = QInputDialog.getText(self, tr("Folder"), prompt, text=start)
            folder = (text or "").strip()
            if not ok or not folder:
                return 0
        if not self.render_all():
            return 0
        result = CAS.mark_duplicates(self._view, rule, folder)
        keys = {_entry_key(e) for e in result.marked}
        rows = []
        for i in range(self._tree.topLevelItemCount()):
            group = self._tree.topLevelItem(i)
            for j in range(group.childCount()):
                child = group.child(j)
                data = child.data(COL_NAME, Qt.ItemDataRole.UserRole)
                if data and data[0] == "entry" and _entry_key(data[1]) in keys:
                    rows.append(child)
        self._select_items(rows)
        size = sum(int(e.size or 0) for e in result.marked)
        if rows:
            text = tr_n(len(rows), "{n} duplicate marked — {size}",
                        "{n} duplicates marked — {size}", size=_format_size(size))
        else:
            text = tr("No duplicates to mark")
        if result.untouched:
            text += "; " + tr_n(result.untouched,
                                "{n} group has no copy inside {folder} and is left alone",
                                "{n} groups have no copy inside {folder} and are left alone",
                                folder=folder)
        self._status.setText(text)
        return len(rows)

    def _select_all_but_one(self, groups) -> None:
        """Select every copy except the first of each group — the rows are in
        survivor order, so that is the oldest copy (and its hard links stay
        with it). The user sees the result and can change it before
        removing anything."""
        rows = []
        for group in groups:
            kept_id = self._file_id_of(group.child(0)) if group.childCount() else None
            for i in range(1, group.childCount()):
                child = group.child(i)
                if kept_id is not None and self._file_id_of(child) == kept_id:
                    continue
                rows.append(child)
        self._select_items(rows)

    def _copy_group_paths(self, group) -> None:
        paths = []
        for i in range(group.childCount()):
            data = group.child(i).data(COL_NAME, Qt.ItemDataRole.UserRole)
            if data and data[0] == "entry":
                paths.append(data[1].path)
        self._to_clipboard("\n".join(paths))

    def _to_clipboard(self, text: str) -> None:
        QGuiApplication.clipboard().setText(text)
        self._status.setText(tr("Copied to clipboard"))

    def _forget_selected(self) -> None:
        """Drop the selected rows from the index; the files stay untouched.
        For stale rows — a rebuild brings back whatever still exists."""
        from ui.off_gui import run_off_gui

        keys = [(e.backend_id, e.path) for e in self.selected_entries()]
        try:
            forgotten = run_off_gui(lambda: CAS.remove_many(None, keys))
        except Exception as exc:  # noqa: BLE001 — report, keep the dialog
            log.warning("CAS index removal failed: %s", exc)
            forgotten = 0
        self._refresh()
        self._status.setText(tr_n(forgotten, "Removed {n} row from the index",
                                  "Removed {n} rows from the index"))

    def _export(self) -> None:
        lines = ["algorithm\thash\tbackend\tpath\tsize"]
        if not self._view:
            self._status.setText(tr("No duplicate groups to copy"))
            return
        for group in self._view:
            for entry in group:
                lines.append(
                    f"{entry.algorithm}\t{entry.value}\t{entry.backend_id}\t"
                    f"{entry.path}\t{entry.size}"
                )
        QGuiApplication.clipboard().setText("\n".join(lines) + "\n")
        self._status.setText(tr_n(len(lines) - 1, "{n} row copied to the clipboard",
                                  "{n} rows copied to the clipboard"))

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
                tr("Copy URL"),
                tr("Select a duplicate group (or any file in one) first."),
            )
            return
        QGuiApplication.clipboard().setText(url)
        self._status.setText(tr("Copied {url} to clipboard").format(url=url))

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

    def _open_current(self) -> None:
        item = self._tree.currentItem()
        if item is not None:
            self._on_double_click(item, 0)

    def _on_double_click(self, item: QTreeWidgetItem, _col: int) -> None:
        data = item.data(COL_NAME, Qt.ItemDataRole.UserRole)
        if data and data[0] == "folder":
            copy = data[1][0]
            self.open_folder_requested.emit(copy.backend_id, copy.path)
            return
        if not data or data[0] != "entry":
            return
        entry = data[1]
        self.open_requested.emit(entry.backend_id, entry.path)


def rebuild_report(count, root: str, stats, cancelled: bool, backend_id: str = "") -> tuple:
    """``(text, trouble)`` for the end of a rebuild: what was indexed, and
    every file or folder left out and why. *trouble* is true when something
    could not be read or listed."""
    if cancelled:
        lines = [tr("Cancelled — {count} file(s) indexed so far under {root}.").format(count=count, root=root)]
    else:
        lines = [tr("Indexed {count} file(s) under {root}.").format(count=count, root=root)]
    if stats is None:
        return lines[0], False
    where = f"[{backend_id}]" if backend_id else tr("this backend")
    done = [tr("{hashed} hashed ({bytes_hashed})").format(hashed=stats.hashed, bytes_hashed=_format_size(stats.bytes_hashed))]
    if stats.unchanged:
        done.append(tr("{unchanged} unchanged since the last scan").format(unchanged=stats.unchanged))
    lines.append(", ".join(done) + ".")
    if stats.read:
        lines.append(tr("{read} file(s) were read and hashed here: {where} has no checksum of "
            "its own.").format(read=stats.read, where=where))
    if stats.unique_size:
        lines.append(tr("{unique_size} file(s) without a checksum were not read: no other file "
            "has their size (or their first bytes), so they have no duplicate.").format(unique_size=stats.unique_size))
    if stats.no_checksum:
        lines.append(tr("{no_checksum} file(s) skipped: {where} has no content checksum for "
            "them.").format(no_checksum=stats.no_checksum, where=where))
    if stats.special:
        lines.append(tr("{special} special file(s) (FIFOs, sockets, devices) skipped.").format(special=stats.special))
    if stats.pruned:
        lines.append(tr_n(stats.pruned, "{n} index entry of files no longer there removed.",
                          "{n} index entries of files no longer there removed."))
    if stats.truncated:
        lines.append(tr("The walk stopped at its limit ({MAX_WALK_ENTRIES:,} entries or "
            "{MAX_WALK_DEPTH} folder levels): the rest was not scanned.").format(MAX_WALK_ENTRIES=CAS.MAX_WALK_ENTRIES, MAX_WALK_DEPTH=CAS.MAX_WALK_DEPTH))
    trouble = bool(stats.unreadable_count or stats.unlisted_count)
    if stats.unreadable_count:
        lines.append("")
        lines.append(tr("{unreadable_count} file(s) could not be read:").format(unreadable_count=stats.unreadable_count))
        lines += [f"  {p}: {why}" for p, why in stats.unreadable[:5]]
        if stats.unreadable_count > 5:
            lines.append(tr("  … and {count} more").format(count=stats.unreadable_count - 5))
    if stats.unlisted_count:
        lines.append("")
        lines.append(tr("{unlisted_count} folder(s) could not be listed (their files were not "
            "scanned; their index entries are kept):").format(unlisted_count=stats.unlisted_count))
        lines += [f"  {p}: {why}" for p, why in stats.unlisted[:5]]
        if stats.unlisted_count > 5:
            lines.append(tr("  … and {count} more").format(count=stats.unlisted_count - 5))
    return "\n".join(lines), trouble
