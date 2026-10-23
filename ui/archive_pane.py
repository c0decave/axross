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
import stat
import time
from typing import Callable

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from core.archive import (
    ArchiveEntry,
    RarUnavailable,
    UnsafeArchive,
    is_supported_archive,
    list_archive,
    strip_archive_extension,
)
from core.i18n import tr

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
        if is_supported_archive(entry.name):
            row[COL_NAME].setToolTip(tr("An archive: double-click opens it here"))
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


def format_label(path: str) -> str:
    """Short uppercase format tag from the extension chain (``TAR.GZ``),
    for headers and the Type of a member. Cosmetic only."""
    base = os.path.basename(path.rstrip("/"))
    stem = strip_archive_extension(base)
    ext = base[len(stem):].lstrip(".")
    return ext.upper() if ext else "archive"


_KIND_LABELS = {
    "dir": "Folder",
    "symlink": "Symbolic link",
    "hardlink": "Hard link",
    "other": "Special file",
}
_KIND_BITS = {"dir": stat.S_IFDIR, "symlink": stat.S_IFLNK}


def member_info(entry: ArchiveEntry) -> list[tuple[str, str]]:
    """``(label, value)`` rows of the Properties of one member: name,
    type, size, compressed size, modification time and mode. PURE."""
    from ui.format_utils import format_size

    kind = "dir" if entry.is_dir else entry.kind
    if kind in _KIND_LABELS:
        kind_text = tr(_KIND_LABELS[kind])
    elif is_supported_archive(entry.name):
        kind_text = tr("Archive ({format})").format(format=format_label(entry.name))
    else:
        kind_text = tr("File")
    if entry.mode is None:
        mode_text = "—"
    else:
        bits = _KIND_BITS.get(kind, stat.S_IFREG) | entry.mode
        mode_text = f"{stat.filemode(bits)} ({entry.mode:04o})"
    if entry.mtime is None:
        modified = "—"
    else:
        try:
            modified = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.mtime))
        except (ValueError, OverflowError, OSError):
            modified = "—"
    return [
        ("Name", entry.name),
        ("Type", kind_text),
        ("Size", format_size(max(0, entry.size))),
        ("Compressed", f"{max(0, entry.compressed)} bytes"),
        ("Modified", modified),
        ("Mode", mode_text),
    ]


class MemberPropertiesDialog(QDialog):
    """The Properties of one archive member (or folder in it)."""

    def __init__(self, rows: list[tuple[str, str]], parent: QWidget | None = None) -> None:
        from ui.close_corner import add_close_corner

        super().__init__(parent)
        self._values = dict(rows)
        self.setWindowTitle(tr("Properties") + f" — {self._values.get('Name', '')}")
        layout = QVBoxLayout(self)
        add_close_corner(self)
        form = QFormLayout()
        for label, value in rows:
            text = QLabel(value, self)
            text.setTextFormat(Qt.TextFormat.PlainText)  # member names are not markup
            text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            text.setWordWrap(True)
            form.addRow(tr(label) + ":", text)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self) -> dict[str, str]:
        return dict(self._values)


class ArchivePaneWidget(QWidget):
    """Non-modal archive preview pane.

    Loads *archive_path* via :func:`core.archive.list_archive`, renders a
    directory tree, and exposes the user's selection as extractable member
    names. It EMITS extraction signals but performs NO extraction — that
    wiring (and progress) is Task A4.

    Signals
    -------
    extract_all()
        "Extract All" was triggered — extract the whole archive.
    extract_selected(list)
        "Extract Selected" was triggered — payload is the list of
        member names from the current selection (see
        :func:`selected_member_names`).
    extract_to()
        "Extract To…" was triggered — extract somewhere the user picks.
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
    #: Extract the selected members into a folder the user picks.
    extract_selected_to = pyqtSignal(list)
    #: Back to the archive this nested one was opened from.
    back_requested = pyqtSignal()

    def __init__(
        self,
        archive_path: str,
        on_open_member: Callable[[str], None] | None = None,
        parent: QWidget | None = None,
        *,
        chain: tuple[str, ...] = (),
    ) -> None:
        super().__init__(parent)
        self._archive_path = archive_path
        self._on_open_member = on_open_member
        #: The names of the archives this one is nested in, outermost first.
        self.chain = tuple(chain)
        self.load_error: str | None = None
        self._entries: list[ArchiveEntry] = []
        self._properties_dialog: MemberPropertiesDialog | None = None

        self._build_ui()
        self._load()

    # -- UI construction --------------------------------------------------

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        self._btn_back = QPushButton(tr("Back"))
        self._btn_back.setToolTip(tr("Back to the archive this one is in"))
        self._btn_back.clicked.connect(self.back_requested.emit)
        self._btn_back.setVisible(bool(self.chain))
        top.addWidget(self._btn_back)
        self._header_label = QLabel()
        self._header_label.setStyleSheet("font-weight: bold;")
        self._header_label.setTextFormat(Qt.TextFormat.PlainText)
        top.addWidget(self._header_label, stretch=1)
        layout.addLayout(top)

        self._tree = QTreeView()
        self._tree.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection,
        )
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        self._tree.doubleClicked.connect(self._on_double_clicked)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        # Columns as in the file pane: every divider draggable, the numbers
        # as wide as their content, Name the free width; a column the user
        # dragged keeps its width (ui.column_fit).
        from ui.column_fit import ColumnFitter

        self._columns = ColumnFitter(self._tree, fill=0)
        layout.addWidget(self._tree, stretch=1)

        btn_row = QHBoxLayout()
        self._btn_all = QPushButton("Extract All")
        self._btn_all.clicked.connect(self.extract_all.emit)
        btn_row.addWidget(self._btn_all)

        self._btn_selected = QPushButton("Extract Selected")
        self._btn_selected.clicked.connect(self._emit_extract_selected)
        btn_row.addWidget(self._btn_selected)

        self._btn_to = QPushButton("Extract To…")
        self._btn_to.clicked.connect(self.extract_to.emit)
        btn_row.addWidget(self._btn_to)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._status_label = QLabel()
        self._status_label.setProperty("role", "muted")
        layout.addWidget(self._status_label)

    # -- Loading ----------------------------------------------------------

    def _load(self) -> None:
        """List the archive and populate the tree. Any listing failure is
        caught and surfaced via :attr:`load_error` + the status label;
        the widget never raises out of ``__init__``."""
        basename = self.display_name()
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
            self.load_error = f"Archive rejected: {exc}"
            self._set_empty_model()
            self._header_label.setText(basename)
            self._status_label.setText(self.load_error)
            log.warning("archive refused %r: %s", self._archive_path, exc)
            return
        except Exception as exc:  # noqa: BLE001 — last-resort safety net
            # Any other failure (corrupt file, OSError, format-library
            # quirk). Never crash the pane; show a generic safe message.
            self.load_error = f"Archive could not be read: {exc}"
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
        self._status_label.setText("Ready")

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
        return format_label(path)

    def display_name(self) -> str:
        """``outer.tar › inner.zip``: where this archive is."""
        return " › ".join((*self.chain, os.path.basename(self._archive_path)))

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
            self._open(member)

    def _open(self, member: str) -> None:
        self.open_member.emit(member)
        if self._on_open_member is not None:
            self._on_open_member(member)

    # -- right-click menu and properties ---------------------------------

    def _selected_items(self) -> list[QStandardItem]:
        model = self._tree.model()
        sel = self._tree.selectionModel()
        if model is None or sel is None or not hasattr(model, "itemFromIndex"):
            return []
        items = [model.itemFromIndex(ix) for ix in sel.selectedRows(COL_NAME)]
        return [i for i in items if i is not None]

    #: Each entry's file pane command (ui.file_pane.CONTEXT_COMMANDS): its
    #: icon is the one this entry shows, so a command looks the same in both.
    _ICON_OF = {
        "open": "open-text",
        "open-archive": "preview-archive",
        "extract-selected": "extract",
        "extract-selected-to": "extract",
        "extract-all": "extract",
        "extract-to": "extract",
        "properties": "properties",
    }

    def build_context_menu(self) -> QMenu:
        """Open / Open Archive for one file, Extract Selected (To…) for a
        selection, Extract All (To…), and Properties for one row."""
        from ui.file_pane import CONTEXT_COMMANDS
        from ui.icon_provider import icon

        menu = QMenu(self)
        items = self._selected_items()

        def entry(command: str, label: str, slot, icon_of: str = "") -> None:
            action = menu.addAction(label)
            action.setProperty("axCommand", command)
            icon_name = CONTEXT_COMMANDS[self._ICON_OF[icon_of or command]][0]
            if icon_name:
                action.setProperty("axIcon", icon_name)
                action.setIcon(icon(icon_name))
            action.triggered.connect(lambda _checked=False: slot())

        if len(items) == 1 and not _is_folder_item(items[0]):
            member = items[0].data(Qt.ItemDataRole.UserRole)
            nested = is_supported_archive(member)
            label = tr("&Open Archive") if nested else tr("&Open")
            entry("open", label, lambda m=member: self._open(m),
                  icon_of="open-archive" if nested else "open")
            menu.addSeparator()
        if items:
            entry("extract-selected", tr("E&xtract Selected"), self._emit_extract_selected)
            entry(
                "extract-selected-to",
                tr("Extract Selected &To…"),
                lambda: self.extract_selected_to.emit(self.selected_members()),
            )
            menu.addSeparator()
        entry("extract-all", tr("Extract &All"), self.extract_all.emit)
        entry("extract-to", tr("Extract A&ll To…"), self.extract_to.emit)
        if len(items) == 1:
            menu.addSeparator()
            member = items[0].data(Qt.ItemDataRole.UserRole)
            entry("properties", tr("&Properties…"), lambda m=member: self.show_properties(m))
        return menu

    def _show_context_menu(self, pos) -> None:
        self.build_context_menu().exec(self._tree.viewport().mapToGlobal(pos))

    def member_entry(self, member: str) -> ArchiveEntry | None:
        return next((e for e in self._entries if e.name == member), None)

    def properties_rows(self, member: str) -> list[tuple[str, str]]:
        """What Properties shows for *member*: its listing entry, or for a
        folder the archive implies without an entry a summary of what is
        in it; plus where the archive is."""
        entry = self.member_entry(member)
        if entry is None:
            entry = ArchiveEntry(member, 0, 0, None, member.endswith("/"), None,
                                 "dir" if member.endswith("/") else "file")
        rows = member_info(entry)
        if entry.is_dir:
            # Compared by segments, as build_archive_tree places them: a
            # member stored as ``dir\file`` or ``dir//file`` is in ``dir/``.
            base = _split_segments(member)
            inside = []  # (entry, its segments below the folder)
            for e in self._entries:
                segments = _split_segments(e.name)
                if len(segments) > len(base) and segments[: len(base)] == base:
                    inside.append((e, segments[len(base):]))
            files = [e for e, _parts in inside if not e.is_dir]
            folders: set[str] = set()  # every folder below, implied or listed
            for e, parts in inside:
                for depth in range(1, len(parts) + (1 if e.is_dir else 0)):
                    folders.add("/".join(parts[:depth]))
            total = sum(max(0, e.size) for e in files)
            from ui.format_utils import human_bytes

            rows = [r for r in rows if r[0] not in ("Size", "Compressed")]
            rows.insert(2, ("Contents", tr("{files} file(s), {folders} folder(s), {size}").format(
                files=len(files), folders=len(folders), size=human_bytes(total))))
        rows.append(("Archive", self.display_name()))
        return rows

    def show_properties(self, member: str) -> MemberPropertiesDialog:
        old = self._properties_dialog
        if old is not None:
            old.close()
        dialog = MemberPropertiesDialog(self.properties_rows(member), parent=self)
        self._properties_dialog = dialog
        dialog.show()
        return dialog
