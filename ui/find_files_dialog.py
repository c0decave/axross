"""Find Files: search folders on any open connection by name, type,
content and inside archives (Edit > Find Files…, Alt+F7, or a pane's
"Find in This Folder…").

The search itself is :func:`core.file_search.run_search`, run on a
:class:`ui.scan_job.ScanJob` thread: hits are queued by the worker and
added to the table by a timer on the GUI thread, so rows stream in while
the window stays responsive; Stop (or closing the window) cancels.

The dialog does not navigate itself. Activating a row asks the main
window through signals: reveal a file in a pane, open an archive member
in the archive view, open an index hit, send paths to the Agent, or keep
the search as a Smart Folder in the bookmarks.
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime

from PyQt6.QtCore import QDate, QEvent, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import file_categories as FC
from core import file_search as FS
from core.i18n import tr
from core.search_federation import SearchQuery
from ui.close_corner import add_close_corner
from ui.scan_job import BusyStrip, ScanJob, shorten

log = logging.getLogger("ui.find_files_dialog")

COL_NAME, COL_FOLDER, COL_SIZE, COL_MODIFIED, COL_CATEGORY, COL_BACKEND, COL_SNIPPET = range(7)
_HEADERS = ("Name", "Folder", "Size", "Modified", "Category", "Backend", "Snippet")
#: Rows added per timer tick, so a flood of hits never freezes the window.
_ROWS_PER_TICK = 500
_SORT_ROLE = Qt.ItemDataRole.UserRole + 1
_ROW_ROLE = Qt.ItemDataRole.UserRole
_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(text: str) -> int:
    """``""`` -> -1 (no bound); ``10``, ``10K``, ``1.5 MiB``, ``2g``, ``3 kb``
    -> bytes (binary units). ``ValueError`` for anything else."""
    if not text.strip():
        return -1
    m = _SIZE_RE.match(text)
    if m is None:
        raise ValueError(f"{text.strip()!r} is not a size (e.g. 500, 10K, 1.5M, 2G)")
    value = float(m.group(1)) * _UNITS[m.group(2).lower()]
    if not math.isfinite(value) or value > 2**62:
        raise ValueError(f"{text.strip()!r} is too large")
    return int(value)


def _format_size(n: int) -> str:
    value = float(max(n, 0))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def _format_when(epoch: float) -> str:
    if not epoch:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch))
    except (OverflowError, OSError, ValueError):
        return ""


@dataclass
class ScopeChoice:
    """A folder the dialog offers: *backend* + *path*. ``available=False``
    rows (a saved Smart Folder's connection that is not open) are shown
    greyed out and never searched."""

    backend: object
    path: str
    label: str = ""
    checked: bool = True
    profile_name: str = ""
    available: bool = True
    backend_name: str = ""

    def __post_init__(self) -> None:
        if not self.backend_name:
            from core.local_fs import LocalFS

            if self.backend is None or isinstance(self.backend, LocalFS):
                self.backend_name = "Local"
            else:
                self.backend_name = getattr(self.backend, "name", "") or type(self.backend).__name__
        if not self.label:
            self.label = (
                self.path if self.backend_name == "Local" else f"{self.backend_name}:{self.path}"
            )


class _SortItem(QTableWidgetItem):
    """Sorts by the value in :data:`_SORT_ROLE` (sizes, times) when set."""

    def __lt__(self, other) -> bool:
        mine, theirs = self.data(_SORT_ROLE), other.data(_SORT_ROLE)
        if mine is not None and theirs is not None:
            return mine < theirs
        return super().__lt__(other)


#: The Name cell. A name has no sort value, so a _SortItem only fell back to
#: Qt's comparison - through a Python call per comparison (~66,000 per
#: batch of rows at 5000 results); a plain item compares the same in Qt.
_NameItem = QTableWidgetItem


class FindFilesDialog(QDialog):
    """Search criteria, folders, results; see the module docstring."""

    #: (backend, path): show this file selected in a pane.
    reveal_requested = pyqtSignal(object, str)
    #: (backend, archive path, member): open the archive view for a member.
    open_archive_requested = pyqtSignal(object, str, str)
    #: (backend id, path, is_dir): an offline-index hit (as Find in Index).
    index_open_requested = pyqtSignal(str, str, bool)
    #: (backend, paths): attach to the Agent's current tab.
    send_to_agent_requested = pyqtSignal(object, list)
    #: (name, saved search): keep as a Smart Folder.
    save_smart_folder_requested = pyqtSignal(str, dict)

    def __init__(
        self,
        scopes: list[ScopeChoice],
        parent: QWidget | None = None,
        *,
        saved: dict | None = None,
        autostart: bool = False,
        index_db=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Find Files"))
        self.resize(1100, 760)
        self._index_db = index_db
        self._rows: list[tuple[FS.SearchScope, object]] = []
        self._queue: deque = deque()
        self._started = 0.0
        self._job = ScanJob(self, interval_ms=120, formatter=self._progress_text)
        self._job.finished.connect(self._on_finished)
        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(100)
        self._drain_timer.timeout.connect(self._drain)
        self._build_ui()
        for choice in scopes:
            self._add_scope(choice)
        if saved is not None and self._apply_saved(saved) and autostart:
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(self.start_search)
            timer.start(0)

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)
        top = QHBoxLayout()
        root.addLayout(top)

        criteria = QGroupBox(tr("Find"), self)
        form = QFormLayout(criteria)
        name_row = QHBoxLayout()
        self.name_edit = QLineEdit(self)
        self.name_edit.setPlaceholderText(tr("part of the name, or a pattern like *.pdf"))
        self.name_edit.setToolTip(
            tr("Text without * ? [ ] matches anywhere in the name; a pattern (*.jpg, IMG_????.*) "
               "the whole name. Upper and lower case are the same.")
        )
        self.name_edit.returnPressed.connect(self.start_search)
        self.name_regex_box = QCheckBox(tr("Regex"), self)
        self.name_regex_box.setToolTip(tr("The name is a regular expression (case-sensitive; "
                                          "(?i) ignores case)"))
        name_row.addWidget(self.name_edit, 1)
        name_row.addWidget(self.name_regex_box)
        form.addRow(tr("Name:"), name_row)

        text_row = QHBoxLayout()
        self.contains_edit = QLineEdit(self)
        self.contains_edit.setPlaceholderText(tr("text inside the file (optional)"))
        self.contains_edit.setToolTip(
            tr("Searched line by line in the first 32 MiB of each file - with ripgrep (rg) "
               "when it is installed")
        )
        self.contains_edit.returnPressed.connect(self.start_search)
        self.contains_regex_box = QCheckBox(tr("Regex"), self)
        self.case_box = QCheckBox(tr("Case-sensitive"), self)
        text_row.addWidget(self.contains_edit, 1)
        text_row.addWidget(self.contains_regex_box)
        text_row.addWidget(self.case_box)
        form.addRow(tr("Contains:"), text_row)

        size_row = QHBoxLayout()
        self.min_size_edit = QLineEdit(self)
        self.min_size_edit.setPlaceholderText(tr("min, e.g. 10K"))
        self.max_size_edit = QLineEdit(self)
        self.max_size_edit.setPlaceholderText(tr("max, e.g. 2G"))
        size_row.addWidget(self.min_size_edit)
        size_row.addWidget(QLabel("–", self))
        size_row.addWidget(self.max_size_edit)
        form.addRow(tr("Size:"), size_row)

        date_row = QHBoxLayout()
        today = QDate.currentDate()
        self.after_box = QCheckBox(tr("after"), self)
        self.after_edit = QDateEdit(today.addYears(-1), self)
        self.before_box = QCheckBox(tr("before"), self)
        self.before_edit = QDateEdit(today, self)
        for edit in (self.after_edit, self.before_edit):
            edit.setCalendarPopup(True)
            edit.setDisplayFormat("yyyy-MM-dd")
        date_row.addWidget(self.after_box)
        date_row.addWidget(self.after_edit)
        date_row.addWidget(self.before_box)
        date_row.addWidget(self.before_edit)
        date_row.addStretch(1)
        form.addRow(tr("Modified:"), date_row)

        options = QHBoxLayout()
        self.archives_box = QCheckBox(tr("Inside archives"), self)
        self.archives_box.setToolTip(
            tr("Also look into zip, tar, gz / bz2 / xz / zst, 7z and rar files and archives "
               "nested in them")
        )
        self.hidden_box = QCheckBox(tr("Hidden files"), self)
        self.hidden_box.setChecked(True)
        self.noise_box = QCheckBox(tr("Skip .git, node_modules, caches"), self)
        self.noise_box.setChecked(True)
        self.noise_box.setToolTip(", ".join(SearchQuery().ignore_dirs))
        self.depth_spin = QSpinBox(self)
        self.depth_spin.setRange(-1, 500)
        self.depth_spin.setValue(30)
        self.depth_spin.setSpecialValueText(tr("unlimited"))
        self.depth_spin.setPrefix(tr("depth "))
        self.tag_combo = QComboBox(self)
        self.tag_combo.setToolTip(tr("Only files that carry this tag (an archive's tag counts "
                                     "for its members), offline-index hits included"))
        self.tag_combo.addItem(tr("Any tag"), "")
        from core import tags as TG

        for tag in TG.store().tags():
            self.tag_combo.addItem(tag.name, tag.name)
        for widget in (self.archives_box, self.hidden_box, self.noise_box, self.depth_spin,
                       self.tag_combo):
            options.addWidget(widget)
        options.addStretch(1)
        form.addRow(tr("Options:"), options)
        top.addWidget(criteria, 3)

        right = QVBoxLayout()
        scope_box = QGroupBox(tr("Look in"), self)
        scope_layout = QVBoxLayout(scope_box)
        self.scope_list = QListWidget(self)
        self.scope_list.setToolTip(tr("Ticked folders are searched, on any open connection"))
        scope_layout.addWidget(self.scope_list, 1)
        scope_buttons = QHBoxLayout()
        self.add_folder_btn = QPushButton(tr("Add Folder…"), self)
        self.add_folder_btn.clicked.connect(self._choose_folder)
        self.remove_folder_btn = QPushButton(tr("Remove"), self)
        self.remove_folder_btn.clicked.connect(self._remove_folder)
        scope_buttons.addWidget(self.add_folder_btn)
        scope_buttons.addWidget(self.remove_folder_btn)
        scope_buttons.addStretch(1)
        scope_layout.addLayout(scope_buttons)
        self.index_box = QCheckBox(tr("Also search the offline index"), self)
        from core import metadata_index as MX

        db = self._index_db or MX.default_db_path()
        self.index_box.setToolTip(
            tr("Names, sizes and dates recorded by Edit > Index Active Folder… (no file "
               "content); works for connections that are closed now. Stored in {path}").format(
                path=db)
        )
        scope_layout.addWidget(self.index_box)
        right.addWidget(scope_box, 1)
        top.addLayout(right, 2)

        cats = QGroupBox(tr("Types (any of the ticked)"), self)
        grid = QGridLayout(cats)
        self.category_boxes: dict[str, QCheckBox] = {}
        for i, cid in enumerate(FC.category_ids()):
            # A QCheckBox reads a lone "&" as its shortcut marker: double it.
            box = QCheckBox(tr(FC.label(cid)).replace("&", "&&"), self)
            box.setToolTip(tr(FC.CATEGORIES[cid].description))
            self.category_boxes[cid] = box
            grid.addWidget(box, i // 6, i % 6)
        root.addWidget(cats)

        buttons = QHBoxLayout()
        self.search_btn = QPushButton(tr("Search"), self)
        self.search_btn.setDefault(True)
        self.search_btn.clicked.connect(self.start_search)
        self.save_btn = QPushButton(tr("Save as Smart Folder…"), self)
        self.save_btn.setToolTip(tr("Keep this search in the bookmarks; a click runs it again"))
        self.save_btn.clicked.connect(lambda _checked=False: self.save_as_smart_folder())
        buttons.addWidget(self.search_btn)
        buttons.addWidget(self.save_btn)
        self.status_label = QLabel("", self)
        self.status_label.setProperty("role", "muted")
        self.status_label.setWordWrap(True)
        buttons.addWidget(self.status_label, 1)
        root.addLayout(buttons)

        self.table = QTableWidget(0, len(_HEADERS), self)
        self.table.setHorizontalHeaderLabels([tr(h) for h in _HEADERS])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(lambda _index: self._activate_current())
        self.table.installEventFilter(self)
        from ui.column_fit import ColumnFitter

        self._columns = ColumnFitter(self.table, fill=COL_FOLDER, keep=(COL_NAME,))
        root.addWidget(self.table, 1)

        self._strip = BusyStrip(self._job, self, cancel_text=tr("Stop"))
        self.stop_btn = self._strip.cancel_button
        root.addWidget(self._strip)

        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        close.rejected.connect(self.reject)
        root.addWidget(close)

    def eventFilter(self, watched, event) -> bool:
        if (
            watched is self.table
            and event.type() == QEvent.Type.KeyPress
            and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and event.modifiers() == Qt.KeyboardModifier.NoModifier
        ):
            self._activate_current()
            return True
        return super().eventFilter(watched, event)

    # ------------------------------------------------------------------
    # Folders
    # ------------------------------------------------------------------
    def _add_scope(self, choice: ScopeChoice) -> None:
        text = choice.label if choice.available else tr("{label} (not connected)").format(
            label=choice.label)
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, choice)
        flags = Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable
        if choice.available:
            flags |= Qt.ItemFlag.ItemIsEnabled
        item.setFlags(flags)
        checked = choice.checked and choice.available
        item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        self.scope_list.addItem(item)

    def _choose_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, tr("Add Folder"))
        if folder:
            from core.local_fs import LocalFS

            self._add_scope(ScopeChoice(LocalFS(), folder))

    def _remove_folder(self) -> None:
        for item in self.scope_list.selectedItems():
            self.scope_list.takeItem(self.scope_list.row(item))

    def _checked_scopes(self) -> list[ScopeChoice]:
        out = []
        for i in range(self.scope_list.count()):
            item = self.scope_list.item(i)
            choice = item.data(Qt.ItemDataRole.UserRole)
            if choice.available and item.checkState() == Qt.CheckState.Checked:
                out.append(choice)
        return out

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def build_query(self) -> tuple[SearchQuery, list[ScopeChoice], bool]:
        """The query, the folders and the index switch from the fields;
        ``ValueError`` with a message for the status line."""
        text = self.name_edit.text().strip()
        name = regex = ""
        if self.name_regex_box.isChecked():
            regex = text
        elif text:
            name = text if any(c in text for c in "*?[") else f"*{text}*"
        try:
            min_size = parse_size(self.min_size_edit.text())
            max_size = parse_size(self.max_size_edit.text())
        except ValueError as exc:
            raise ValueError(tr("Size: {error}").format(error=exc)) from None
        after = before = 0.0
        if self.after_box.isChecked():
            after = datetime.combine(self.after_edit.date().toPyDate(), datetime.min.time())
            after = after.timestamp()
        if self.before_box.isChecked():
            before = datetime.combine(self.before_edit.date().toPyDate(), datetime.max.time())
            before = before.timestamp()
        query = SearchQuery(
            name=name,
            regex=regex,
            contains=self.contains_edit.text(),
            contains_is_regex=self.contains_regex_box.isChecked(),
            case_sensitive=self.case_box.isChecked(),
            min_size=min_size,
            max_size=max_size,
            modified_after=after,
            modified_before=before,
            max_depth=self.depth_spin.value(),
            categories=tuple(c for c, box in self.category_boxes.items() if box.isChecked()),
            search_archives=self.archives_box.isChecked(),
            include_hidden=self.hidden_box.isChecked(),
        )
        if not self.noise_box.isChecked():
            query.ignore_dirs = ()
        query.validate()
        scopes = self._checked_scopes()
        use_index = self.index_box.isChecked()
        if not scopes and not use_index:
            raise ValueError(tr("Choose at least one folder to look in, or the offline index."))
        return query, scopes, use_index

    def _apply_saved(self, data: dict) -> bool:
        try:
            query, _scopes, options = FS.saved_search_from_dict(data)
        except ValueError as exc:
            self.status_label.setText(tr("This saved search is damaged: {error}").format(error=exc))
            return False
        if query.regex:
            self.name_regex_box.setChecked(True)
            self.name_edit.setText(query.regex)
        else:
            self.name_edit.setText(query.name)
        self.contains_edit.setText(query.contains)
        self.contains_regex_box.setChecked(query.contains_is_regex)
        self.case_box.setChecked(query.case_sensitive)
        self.min_size_edit.setText(str(query.min_size) if query.min_size >= 0 else "")
        self.max_size_edit.setText(str(query.max_size) if query.max_size >= 0 else "")
        for box, edit, value in (
            (self.after_box, self.after_edit, query.modified_after),
            (self.before_box, self.before_edit, query.modified_before),
        ):
            box.setChecked(bool(value))
            if value:
                day = datetime.fromtimestamp(value).date()
                edit.setDate(QDate(day.year, day.month, day.day))
        self.depth_spin.setValue(query.max_depth)
        for cid, box in self.category_boxes.items():
            box.setChecked(cid in query.categories)
        self.archives_box.setChecked(query.search_archives)
        self.hidden_box.setChecked(query.include_hidden)
        self.noise_box.setChecked(bool(query.ignore_dirs))
        self.index_box.setChecked(options["use_index"])
        self.set_tag(options["tag"])
        return True

    def set_tag(self, name: str) -> None:
        """Choose the tag filter; a tag deleted since the search was saved
        stays chosen, so the search does not widen to untagged files."""
        index = self.tag_combo.findData(name)
        if index < 0:
            self.tag_combo.addItem(name, name)
            index = self.tag_combo.count() - 1
        self.tag_combo.setCurrentIndex(index)

    def selected_tag(self) -> str:
        return self.tag_combo.currentData() or ""

    # ------------------------------------------------------------------
    # Running
    # ------------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        return self._job.running

    def start_search(self) -> None:
        try:
            query, choices, use_index = self.build_query()
        except ValueError as exc:
            self.status_label.setText(tr("Cannot search: {error}").format(error=exc))
            return
        scopes = [FS.SearchScope(c.backend, c.path, label=c.label) for c in choices]
        names = {id(scope): choice.backend_name for scope, choice in zip(scopes, choices)}
        tag = self.selected_tag()
        tagged: FS.HitFilter | None = None
        if tag:
            from core import tags as TG

            store = TG.store()

            def has_tag(scope, hit) -> bool:
                if scope.kind == "index":
                    # The index names a backend "<class>:<name>" (Find in
                    # Index); tags name it by its display name.
                    backend = scope.label.partition(":")[2] or scope.label
                else:
                    backend = names.get(id(scope))
                return backend is not None and tag in store.tags_of(
                    backend, hit.archive_path or hit.path)

            tagged = has_tag
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setSortingEnabled(True)
        self._rows = []
        queue: deque = deque()
        self._queue = queue
        index_db = self._index_db

        def work(cancel, progress):
            return FS.run_search(
                scopes,
                query,
                on_hit=lambda scope, hit: queue.append((scope, hit)),
                cancel=cancel,
                progress=progress,
                use_index=use_index,
                index_db=index_db,
                accept=tagged,
            )

        self._started = time.monotonic()
        self.status_label.setText(tr("Searching…"))
        self._job.start(work, replace=True)
        self._drain_timer.start()

    def _progress_text(self, state: dict) -> str:
        return tr("Searching… {found} found, {scanned} scanned — {path}").format(
            found=state["indexed"], scanned=state["scanned"], path=shorten(state["path"]))

    def _drain(self, everything: bool = False) -> None:
        queue = self._queue
        if not queue:
            return
        self.table.setSortingEnabled(False)
        try:
            added = 0
            while queue and (everything or added < _ROWS_PER_TICK):
                scope, hit = queue.popleft()
                self._append_row(scope, hit)
                added += 1
        finally:
            self.table.setSortingEnabled(True)

    def _append_row(self, scope: FS.SearchScope, hit) -> None:
        index = len(self._rows)
        self._rows.append((scope, hit))
        name, folder = _split_display(scope, hit)
        row = self.table.rowCount()
        self.table.insertRow(row)
        name_item = _NameItem(name)
        name_item.setData(_ROW_ROLE, index)
        name_item.setToolTip(hit.path)
        size_item = _SortItem(_format_size(hit.size) if not hit.is_dir else "")
        size_item.setData(_SORT_ROLE, int(hit.size))
        size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        when_item = _SortItem(_format_when(hit.mtime))
        when_item.setData(_SORT_ROLE, float(hit.mtime))
        snippet = QTableWidgetItem(hit.snippet)
        snippet.setToolTip(hit.snippet)
        cells = (
            name_item,
            QTableWidgetItem(folder),
            size_item,
            when_item,
            QTableWidgetItem(tr(FC.label(hit.category)) if hit.category else ""),
            QTableWidgetItem(hit.backend_label),
            snippet,
        )
        for col, item in enumerate(cells):
            self.table.setItem(row, col, item)

    def _on_finished(self, kind: str, value, cancelled: bool) -> None:
        self._drain_timer.stop()
        self._drain(everything=True)
        if kind == "error":
            self.status_label.setText(tr("Search failed: {error}").format(error=value))
            return
        summary: FS.SearchSummary = value
        parts = [tr("{found} found · {scanned} scanned in {secs:.1f} s").format(
            found=summary.found, scanned=summary.scanned, secs=summary.elapsed_s)]
        engines = sorted(set(summary.engines.values()))
        if engines:
            parts.append(", ".join(engines))
        if summary.truncated:
            parts.append(tr("stopped at the limit of {n} results").format(
                n=FS.SearchLimits().max_hits))
        if cancelled or summary.cancelled:
            parts.append(tr("cancelled"))
        if summary.skipped:
            parts.append(tr("skipped: {what}").format(
                what=", ".join(f"{k} {v}" for k, v in sorted(summary.skipped.items()))))
        if summary.errors:
            parts.append(tr("{n} could not be read").format(n=len(summary.errors)))
        self.status_label.setText(" · ".join(parts))
        self.status_label.setToolTip("\n".join(summary.errors))

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def _row_entry(self, row: int):
        item = self.table.item(row, COL_NAME)
        if item is None:
            return None
        index = item.data(_ROW_ROLE)
        if index is None or not 0 <= index < len(self._rows):
            return None
        return self._rows[index]

    def _selected_entries(self) -> list:
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        out = []
        for row in rows:
            entry = self._row_entry(row)
            if entry is not None:
                out.append(entry)
        return out

    def _activate_current(self) -> None:
        entry = self._row_entry(self.table.currentRow())
        if entry is not None:
            self._activate(*entry)

    def _activate(self, scope: FS.SearchScope, hit) -> None:
        if scope.kind == "index":
            self.index_open_requested.emit(scope.label, hit.path, bool(hit.is_dir))
        elif hit.archive_path:
            self.open_archive_requested.emit(scope.backend, hit.archive_path, hit.member)
        else:
            self.reveal_requested.emit(scope.backend, hit.path)

    def _reveal(self, scope: FS.SearchScope, hit) -> None:
        if scope.kind == "index":
            self.index_open_requested.emit(scope.label, hit.path, bool(hit.is_dir))
        else:
            self.reveal_requested.emit(scope.backend, hit.archive_path or hit.path)

    def _build_context_menu(self) -> QMenu:
        menu = QMenu(self)
        entries = self._selected_entries()
        current = self._row_entry(self.table.currentRow())
        open_action = menu.addAction(tr("Open"))
        open_action.setEnabled(current is not None)
        open_action.triggered.connect(lambda _c=False: self._activate_current())
        reveal = menu.addAction(tr("Reveal in Pane"))
        reveal.setEnabled(current is not None)
        reveal.triggered.connect(lambda _c=False, e=current: e and self._reveal(*e))
        copy = menu.addAction(tr("Copy Path"))
        copy.setEnabled(bool(entries))
        copy.triggered.connect(lambda _c=False, e=entries: self._copy_paths(e))
        agent = menu.addAction(tr("Send to Agent"))
        agent.setEnabled(any(scope.kind != "index" for scope, _hit in entries))
        agent.triggered.connect(lambda _c=False, e=entries: self._send_to_agent(e))
        return menu

    def _show_context_menu(self, pos) -> None:
        if self.table.itemAt(pos) is None:
            return
        self._build_context_menu().exec(self.table.viewport().mapToGlobal(pos))

    def _copy_paths(self, entries: list) -> None:
        QApplication.clipboard().setText("\n".join(hit.path for _scope, hit in entries))

    def _send_to_agent(self, entries: list) -> None:
        groups: dict[int, tuple[object, list[str]]] = {}
        for scope, hit in entries:
            if scope.kind == "index":
                continue
            path = hit.archive_path or hit.path
            backend, paths = groups.setdefault(id(scope.backend), (scope.backend, []))
            if path not in paths:
                paths.append(path)
        for backend, paths in groups.values():
            self.send_to_agent_requested.emit(backend, paths)

    # ------------------------------------------------------------------
    # Smart Folder
    # ------------------------------------------------------------------
    def save_as_smart_folder(self, name: str | None = None) -> bool:
        """Emit :pyattr:`save_smart_folder_requested` for the current
        fields; asks for a name unless *name* is given."""
        try:
            query, choices, use_index = self.build_query()
        except ValueError as exc:
            self.status_label.setText(tr("Cannot save: {error}").format(error=exc))
            return False
        if name is None:
            default = self.name_edit.text().strip() or ", ".join(
                FC.label(c) for c in query.categories) or tr("Search")
            name, ok = QInputDialog.getText(self, tr("Save as Smart Folder"), tr("Name:"),
                                            text=default)
            if not ok:
                return False
        name = name.strip()
        if not name:
            return False
        # A folder of a closed connection (from a Smart Folder) stays part of
        # the search: it is greyed out here, not dropped from the definition.
        kept = list(choices)
        for i in range(self.scope_list.count()):
            choice = self.scope_list.item(i).data(Qt.ItemDataRole.UserRole)
            if not choice.available and choice.checked:
                kept.append(choice)
        scopes = [{"backend_name": c.backend_name, "profile_name": c.profile_name,
                   "path": c.path} for c in kept]
        data = FS.saved_search_to_dict(query, scopes, use_index=use_index,
                                       tag=self.selected_tag())
        self.save_smart_folder_requested.emit(name, data)
        self.status_label.setText(tr("Saved as Smart Folder '{name}' in the bookmarks.").format(
            name=name))
        return True

    # ------------------------------------------------------------------
    # Closing
    # ------------------------------------------------------------------
    def reject(self) -> None:
        self._stop_all()
        super().reject()

    def closeEvent(self, event) -> None:
        self._stop_all()
        super().closeEvent(event)

    def _stop_all(self) -> None:
        self._job.abandon()
        self._drain_timer.stop()


def _split_display(scope: FS.SearchScope, hit) -> tuple[str, str]:
    """(name, folder) columns of a hit."""
    path = hit.path
    if hit.archive_path:
        head, _sep, tail = path.rpartition("/")
        folder = head[:-1] if head.endswith("!") else head
        return tail, folder
    backend = scope.backend
    if backend is not None and hasattr(backend, "parent"):
        try:
            folder = backend.parent(path)
            name = path[len(folder):].lstrip("/\\") if path.startswith(folder) else path
            return name or path, folder
        except Exception:  # noqa: BLE001 - display only
            pass
    head, _sep, tail = path.replace("\\", "/").rpartition("/")
    return tail or path, head or "/"


__all__ = ["FindFilesDialog", "ScopeChoice", "parse_size"]
