"""Non-modal archive preview pane (Task A3).

This module is the read-only listing UI for archives. It does **no
extraction** of its own — extraction wiring + progress is Task A4.
What lives here:

* :func:`build_archive_tree` — a PURE function turning the flat member
  list from :func:`core.archive.list_archive` into a
  :class:`~PyQt6.QtGui.QStandardItemModel` directory tree. No file IO,
  no widget show. This is the unit-tested core.
* :func:`selected_member_names` — maps a tree view's current selection
  to the set of archive member names to extract (a folder pulls in all
  its descendant files).
* :class:`ArchivePaneWidget` — the headless-instantiable widget that
  loads an archive, renders the tree, and EMITS extraction signals. It
  never extracts.

Directory tree construction
---------------------------
Archives store a flat member list. A member named ``d/sub/f.txt``
implies two ancestor directories (``d/`` and ``d/sub/``) that may have
no explicit entry of their own. :func:`build_archive_tree` walks each
member's path segments and lazily creates any missing intermediate
folder row, so the tree always shows the full hierarchy even when the
archive omitted the directory entries. Explicit ``is_dir`` entries land
on the same folder rows (created on demand if their parents came first).

Member-name recovery
---------------------
Every Name item carries the FULL archive member name in
``Qt.ItemDataRole.UserRole``. File rows store the member verbatim;
folder rows store their directory prefix with a trailing ``/`` (e.g.
``d/sub/``). That makes selection → member-names fully recoverable
without re-deriving paths from the visible tree text.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from core.archive import (
    ArchiveEntry,
    RarUnavailable,
    UnsafeArchive,
    list_archive,
    strip_archive_extension,
)

log = logging.getLogger("ui.archive_pane")

# Column layout — index order matters; the Name column (0) is the only
# one that carries the UserRole member name.
COL_NAME = 0
COL_SIZE = 1
COL_COMPRESSED = 2
COL_RATIO = 3
COL_MODIFIED = 4
_HEADERS = ("Name", "Size", "Compressed", "Ratio", "Modified")


def _fmt_size(n: int) -> str:
    """Human-readable byte count. Matches the local ``_format_size``
    convention used elsewhere in ``ui/`` (cas_dialog, trash_browser, …)
    — binary units, no external dependency."""
    if n < 0:
        n = 0
    if n < 1024:
        return f"{n} B"
    val = float(n)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        val /= 1024
        if val < 1024:
            return f"{val:.1f} {unit}"
    return f"{val:.1f} PiB"


def _fmt_ratio(entry: ArchiveEntry) -> str:
    """Render an entry's space-saving ratio as ``NN%``. Directories and
    empty entries (``ratio == 0.0``) render as an empty string rather
    than ``0%`` — there's nothing to compress, so a percentage is
    misleading noise in the tree."""
    if entry.is_dir or entry.size <= 0:
        return ""
    return f"{round(entry.ratio * 100)}%"


def _fmt_mtime(mtime: float | None) -> str:
    """Format an epoch float as a local ``YYYY-MM-DD HH:MM`` stamp.
    ``None`` (the format had no usable timestamp) renders empty."""
    if mtime is None:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
    except (ValueError, OverflowError, OSError):
        return ""


def _split_segments(name: str) -> list[str]:
    """Split an archive member name into non-empty path segments.
    Normalises backslashes to ``/`` and drops empty segments (leading,
    trailing, or doubled separators) so ``d//sub/`` → ``['d', 'sub']``.
    Pure path math — never touches the filesystem."""
    normalised = name.replace("\\", "/")
    return [seg for seg in normalised.split("/") if seg]


def _make_row(
    label: str,
    member: str,
    *,
    size: str = "",
    compressed: str = "",
    ratio: str = "",
    modified: str = "",
) -> list[QStandardItem]:
    """Build one model row (five items). The Name item carries the full
    member name (or dir prefix) in ``UserRole``; every item is made
    non-editable — this is a read-only listing."""
    name_item = QStandardItem(label)
    name_item.setData(member, Qt.ItemDataRole.UserRole)
    cells = [
        name_item,
        QStandardItem(size),
        QStandardItem(compressed),
        QStandardItem(ratio),
        QStandardItem(modified),
    ]
    for cell in cells:
        cell.setEditable(False)
    return cells


def build_archive_tree(entries: list[ArchiveEntry]) -> QStandardItemModel:
    """Build a directory-tree :class:`QStandardItemModel` from a (possibly
    flat) archive member list.

    Columns: Name, Size, Compressed, Ratio, Modified.

    * Intermediate directories implied by a path (``d/sub/f.txt`` implies
      ``d/`` and ``d/sub/``) are created as folder rows even when the
      archive has no explicit entry for them.
    * Explicit ``is_dir`` entries land on the matching folder row
      (created on demand if a child arrived first), so a folder is never
      duplicated.
    * The Name item of every row stores the FULL member name in
      ``Qt.ItemDataRole.UserRole``: files store their verbatim member
      name, folders store their dir prefix with a trailing ``/`` (e.g.
      ``d/sub/``). Selection → member names is therefore recoverable
      from the model alone.

    PURE: takes entries, returns a model. No file IO, no widget show.
    """
    model = QStandardItemModel()
    model.setHorizontalHeaderLabels(list(_HEADERS))
    root = model.invisibleRootItem()

    # Cache of dir-prefix -> the folder's Name QStandardItem, so repeated
    # path prefixes resolve to the same row and intermediate dirs are
    # created exactly once.
    dir_items: dict[str, QStandardItem] = {}

    def _ensure_dir(prefix_segments: list[str]) -> QStandardItem | None:
        """Return the Name item for the directory described by
        *prefix_segments*, creating it (and any missing ancestors) on
        demand. Empty segments → the invisible root (None marker)."""
        if not prefix_segments:
            return None
        prefix = "/".join(prefix_segments) + "/"
        existing = dir_items.get(prefix)
        if existing is not None:
            return existing
        parent_item = _ensure_dir(prefix_segments[:-1])
        parent = parent_item if parent_item is not None else root
        row = _make_row(prefix_segments[-1], prefix)
        parent.appendRow(row)
        name_item = row[COL_NAME]
        dir_items[prefix] = name_item
        return name_item

    for entry in entries:
        segments = _split_segments(entry.name)
        if not segments:
            # Empty / root-only name — nothing meaningful to place.
            continue
        if entry.is_dir:
            # Explicit directory entry: ensure the folder row exists. Use
            # the entry's own member name (preserving its exact trailing
            # form) on the UserRole if we are creating it fresh; the
            # implied-prefix form is equivalent for selection purposes.
            _ensure_dir(segments)
            continue
        # File entry: ensure parent dirs, then append the file row.
        parent_item = _ensure_dir(segments[:-1])
        parent = parent_item if parent_item is not None else root
        row = _make_row(
            segments[-1],
            entry.name,
            size=_fmt_size(entry.size),
            compressed=_fmt_size(entry.compressed),
            ratio=_fmt_ratio(entry),
            modified=_fmt_mtime(entry.mtime),
        )
        parent.appendRow(row)

    return model


def _is_folder_item(name_item: QStandardItem) -> bool:
    """A row is a folder iff its stored member name ends with ``/`` OR it
    has children. The trailing-slash test alone covers the rows
    :func:`build_archive_tree` creates; the ``hasChildren`` fallback is
    defensive against any caller-built model."""
    member = name_item.data(Qt.ItemDataRole.UserRole)
    if isinstance(member, str) and member.endswith("/"):
        return True
    return name_item.hasChildren()


def _collect_descendant_files(name_item: QStandardItem, out: list[str]) -> None:
    """Append the member names of every FILE descendant under the folder
    represented by *name_item* (depth-first). Folders themselves are not
    added — only leaf file rows contribute extractable member names."""
    for r in range(name_item.rowCount()):
        child = name_item.child(r, COL_NAME)
        if child is None:
            continue
        if _is_folder_item(child):
            _collect_descendant_files(child, out)
        else:
            member = child.data(Qt.ItemDataRole.UserRole)
            if isinstance(member, str) and member:
                out.append(member)


def selected_member_names(tree_view: QTreeView) -> list[str]:
    """Return the de-duplicated archive member names implied by *tree_view*'s
    current selection.

    * A selected FILE row contributes its own member name.
    * A selected FOLDER row contributes every descendant FILE member name
      under it (recursively); the folder prefix itself is not returned.

    De-duplication is by value (a file selected both directly and via an
    ancestor folder appears once). Insertion order is preserved for a
    stable, testable result.
    """
    model = tree_view.model()
    if model is None:
        return []
    sel_model = tree_view.selectionModel()
    if sel_model is None:
        return []

    seen: set[str] = set()
    ordered: list[str] = []

    def _add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            ordered.append(name)

    # selectedRows() yields one index per selected row at column 0; fall
    # back to filtering selectedIndexes() to the Name column if the view
    # has no single-column row-selection behaviour configured.
    indexes = sel_model.selectedRows(COL_NAME)
    if not indexes:
        indexes = [ix for ix in sel_model.selectedIndexes() if ix.column() == COL_NAME]

    for index in indexes:
        item = model.itemFromIndex(index)
        if item is None:
            continue
        if _is_folder_item(item):
            files: list[str] = []
            _collect_descendant_files(item, files)
            for f in files:
                _add(f)
        else:
            member = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(member, str):
                _add(member)

    return ordered


class ArchivePaneWidget(QWidget):
    """Non-modal archive preview pane.

    Loads *archive_path* via :func:`core.archive.list_archive`, renders a
    directory tree, and exposes the user's selection as extractable member
    names. It EMITS extraction signals but performs NO extraction — that
    wiring (and progress) is Task A4.

    Signals
    -------
    extract_all()
        "Alles extrahieren" was triggered — extract the whole archive.
    extract_selected(list)
        "Auswahl extrahieren" was triggered — payload is the list of
        member names from the current selection (see
        :func:`selected_member_names`).
    extract_to()
        "Nach…" was triggered — extract somewhere the user picks.
    open_member(str)
        A file row was double-clicked — payload is the member name.

    Attributes
    ----------
    load_error : str | None
        ``None`` when the archive listed cleanly. Otherwise a safe,
        user-facing message describing why the listing failed
        (``RarUnavailable`` message, refused unsafe archive, etc.). The
        widget always instantiates; a load failure yields an empty tree
        and a populated status label rather than an exception.
    """

    extract_all = pyqtSignal()
    extract_selected = pyqtSignal(list)
    extract_to = pyqtSignal()
    open_member = pyqtSignal(str)

    def __init__(
        self,
        archive_path: str,
        on_open_member: Callable[[str], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._archive_path = archive_path
        self._on_open_member = on_open_member
        self.load_error: str | None = None
        self._entries: list[ArchiveEntry] = []

        self._build_ui()
        self._load()

    # -- UI construction --------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        self._header_label = QLabel()
        self._header_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self._header_label)

        self._tree = QTreeView()
        self._tree.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection,
        )
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.doubleClicked.connect(self._on_double_clicked)
        layout.addWidget(self._tree, stretch=1)

        btn_row = QHBoxLayout()
        self._btn_all = QPushButton("Alles extrahieren")
        self._btn_all.clicked.connect(self.extract_all.emit)
        btn_row.addWidget(self._btn_all)

        self._btn_selected = QPushButton("Auswahl extrahieren")
        self._btn_selected.clicked.connect(self._emit_extract_selected)
        btn_row.addWidget(self._btn_selected)

        self._btn_to = QPushButton("Nach…")
        self._btn_to.clicked.connect(self.extract_to.emit)
        btn_row.addWidget(self._btn_to)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._status_label = QLabel()
        self._status_label.setStyleSheet("color: #666;")
        layout.addWidget(self._status_label)

    # -- Loading ----------------------------------------------------------

    def _load(self) -> None:
        """List the archive and populate the tree. Any listing failure is
        caught and surfaced via :attr:`load_error` + the status label;
        the widget never raises out of ``__init__``."""
        basename = os.path.basename(self._archive_path)
        try:
            self._entries = list_archive(self._archive_path)
        except RarUnavailable as exc:
            # Missing optional capability — surface the remediation hint
            # verbatim. NOT a hostile archive; show its message, empty tree.
            self.load_error = str(exc)
            self._set_empty_model()
            self._header_label.setText(basename)
            self._status_label.setText(self.load_error)
            log.info("archive listing unavailable for %r: %s", self._archive_path, exc)
            return
        except UnsafeArchive as exc:
            # Refused / hostile archive — show a safe message, no traceback.
            self.load_error = f"Archiv abgelehnt: {exc}"
            self._set_empty_model()
            self._header_label.setText(basename)
            self._status_label.setText(self.load_error)
            log.warning("archive refused %r: %s", self._archive_path, exc)
            return
        except Exception as exc:  # noqa: BLE001 — last-resort safety net
            # Any other failure (corrupt file, OSError, format-library
            # quirk). Never crash the pane; show a generic safe message.
            self.load_error = f"Archiv konnte nicht gelesen werden: {exc}"
            self._set_empty_model()
            self._header_label.setText(basename)
            self._status_label.setText(self.load_error)
            log.warning("archive listing failed %r: %s", self._archive_path, exc)
            return

        model = build_archive_tree(self._entries)
        self._tree.setModel(model)
        self._tree.expandToDepth(0)

        fmt = self._format_label(self._archive_path)
        n_files = sum(1 for e in self._entries if not e.is_dir)
        total = sum(max(0, e.size) for e in self._entries if not e.is_dir)
        self._header_label.setText(
            f"{basename} [{fmt}] — {n_files} entries, {_fmt_size(total)}",
        )
        self._status_label.setText("Bereit")

    def _set_empty_model(self) -> None:
        """Install a header-only empty model so the tree is valid (and
        ``rowCount() == 0``) after a load failure."""
        model = QStandardItemModel()
        model.setHorizontalHeaderLabels(list(_HEADERS))
        self._tree.setModel(model)

    @staticmethod
    def _format_label(path: str) -> str:
        """Short uppercase format tag derived from the extension, for the
        header label. Best-effort cosmetic only."""
        base = os.path.basename(path)
        stem = strip_archive_extension(base)
        # The stripped-off remainder (if any) is the extension chain.
        ext = base[len(stem):].lstrip(".")
        return ext.upper() if ext else "archive"

    # -- Signals / interaction -------------------------------------------

    def _emit_extract_selected(self) -> None:
        members = selected_member_names(self._tree)
        self.extract_selected.emit(members)

    def selected_members(self) -> list[str]:
        """Public accessor: the member names implied by the current
        selection. Thin wrapper over :func:`selected_member_names` for
        callers (and tests) that don't want to import the free function."""
        return selected_member_names(self._tree)

    def _on_double_clicked(self, index) -> None:
        model = self._tree.model()
        if model is None or not index.isValid():
            return
        # Always resolve to the Name column for the member name.
        name_index = index.sibling(index.row(), COL_NAME)
        item = model.itemFromIndex(name_index) if hasattr(model, "itemFromIndex") else None
        if item is None:
            return
        if _is_folder_item(item):
            # Default tree behaviour handles expand/collapse; nothing to do.
            return
        member = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(member, str) and member:
            self.open_member.emit(member)
            if self._on_open_member is not None:
                self._on_open_member(member)
