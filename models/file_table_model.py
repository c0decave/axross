from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from html import escape

from core.i18n import tr
from PyQt6.QtCore import (
    QAbstractItemModel,
    QAbstractProxyModel,
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QRegularExpression,
    Qt,
)

from PyQt6.QtGui import QBrush, QColor, QFont, QPalette
from PyQt6.QtWidgets import QApplication

from core.remote_name import sanitize_for_display
from models.file_item import NAV_NAMES, FileItem
from ui.format_utils import measured_bytes
from ui.icon_provider import entry_icon
from ui.themes import hidden_entry_color, is_hex_colour

COLUMNS = ("Name", "Size", "Modified", "Permissions", "Owner")
COL_NAME, COL_SIZE, COL_MODIFIED, COL_PERMS, COL_OWNER = range(5)

_ITALIC: QFont | None = None


def _italic() -> QFont:
    """Font of hidden entries: the view's font, italic. A QFont with only
    the italic property set resolves the rest against the view's font.
    Made on first use - a QFont needs the application to exist."""
    global _ITALIC
    if _ITALIC is None:
        _ITALIC = QFont()
        _ITALIC.setItalic(True)
    return _ITALIC


# -- sorting --------------------------------------------------------------------------------
#
# The order: "." first, then "..", then folders, then files - each group
# by the column's value, ascending. Descending is the same order reversed
# (files first, "." last), ties keeping the order they had: what
# QSortFilterProxyModel did with the former lessThan, and what
# ``sorted(key=(group, value), reverse=True)`` does. Sorted by positions
# with a precomputed value list (``sorted(rows, key=values.__getitem__)``):
# no Python call per row or comparison, ~5x quicker than a tuple key per
# item for 100,000 entries.

def _column_values(items: list[FileItem], names: list[str], column: int,
                   computed: dict[str, tuple[int, bool]] | None) -> list:
    """The value column *column* sorts *items* by, one per item."""
    if column == COL_NAME:
        return [n.lower() for n in names]
    if column == COL_SIZE:
        if computed:
            return [computed[it.name][0] if it.is_dir and it.name in computed else it.size
                    for it in items]
        return [it.size for it in items]
    if column == COL_MODIFIED:
        return [it.modified for it in items]
    if column == COL_PERMS:
        return [it.permissions for it in items]
    if column == COL_OWNER:
        return [it.owner for it in items]
    return [0] * len(items)


def _groups(names: list[str], items: list[FileItem]) -> list[int]:
    """The sort group of each item: 0 ".", 2 "..", 6 a folder, 7 a file -
    the former key ``(not is_nav, name != ".", not is_dir)`` as one number
    (is_nav is a name in NAV_NAMES)."""
    return [(0 if n in NAV_NAMES else 4) + (0 if n == "." else 2) + (0 if d else 1)
            for n, d in zip(names, [it.is_dir for it in items])]


#: Rows sorted per piece by :func:`sort_positions` with ``in_pieces``.
_SORT_PIECE = 16384


def sort_positions(items: list[FileItem], column: int, order: Qt.SortOrder,
                   computed: dict[str, tuple[int, bool]] | None = None,
                   names: list[str] | None = None,
                   groups: list[int] | None = None,
                   in_pieces: bool = False) -> list[int]:
    """The positions of *items* in their sorted order (stable: ties keep
    the order they have in *items*). *column* must be a valid column;
    *names* and *groups* (of :class:`_RowCache`) are worked out when not
    given.

    *in_pieces* (the listing thread): sorted piece by piece, then the
    sorted pieces merged - ~1.5x the work, but no single C call holds the
    GIL longer than ~20 ms (one sort of 100,000 names held it 45 ms, and
    the GUI thread waited that long)."""
    descending = order == Qt.SortOrder.DescendingOrder
    if names is None:
        names = [it.name for it in items]
    if groups is None:
        groups = _groups(names, items)
    values = _column_values(items, names, column, computed)
    key = values.__getitem__
    # By value, then (stable) by group: the same order as one sort by
    # (group, value) - also reversed, where both passes keep ties in the
    # order they had - with no tuple per row.
    n = len(items)
    if in_pieces and n > 2 * _SORT_PIECE:
        positions = []
        for start in range(0, n, _SORT_PIECE):
            positions += sorted(range(start, min(n, start + _SORT_PIECE)), key=key,
                                reverse=descending)
        positions.sort(key=key, reverse=descending)  # merges the sorted runs
    else:
        positions = sorted(range(n), key=key, reverse=descending)
    positions.sort(key=groups.__getitem__, reverse=descending)
    return positions


# -- what the filter reads ------------------------------------------------------------------

#: Row classes (_RowCache.classes): "." / ".." (always shown), an entry,
#: a hidden entry (shown only with hidden files on).
_NAV, _ENTRY, _HIDDEN = 0, 1, 2


def _row_class(item: FileItem) -> int:
    if item.is_nav:
        return _NAV
    return _HIDDEN if item.is_hidden else _ENTRY


class _RowCache:
    """Per-row facts the filter reads, aligned with an item list: the
    names, their casefolded forms (a case-insensitive filter compares
    those, ``needle in folded[row]``, without a call per row), each row's
    class and the rows shown while hidden entries are not. Worked out once
    per listing - on the listing thread when it comes as a
    :class:`PreparedListing` - and permuted with the items on a sort."""

    __slots__ = ("items", "names", "folded", "classes", "unhidden", "groups")

    def __init__(self, items: list[FileItem], names=None, folded=None, classes=None,
                 unhidden=None, groups=None):
        self.items = items
        self.names = [it.name for it in items] if names is None else names
        self.folded = [n.casefold() for n in self.names] if folded is None else folded
        self.classes = [_row_class(it) for it in items] if classes is None else classes
        self.unhidden = [i for i, c in enumerate(self.classes) if c != _HIDDEN] \
            if unhidden is None else unhidden
        #: The sort group of each row (see _groups).
        self.groups = _groups(self.names, items) if groups is None else groups

    def copy_for(self, items: list[FileItem]) -> _RowCache:
        """The same facts for a copy of the item list (own lists: refresh
        changes them in place)."""
        return _RowCache(items, list(self.names), list(self.folded), list(self.classes),
                         list(self.unhidden), list(self.groups))

    def permuted(self, items: list[FileItem], positions: list[int]) -> _RowCache:
        """The cache of *items* = the old items at *positions*."""
        names, folded, classes, groups = self.names, self.folded, self.classes, self.groups
        return _RowCache(items, [names[i] for i in positions], [folded[i] for i in positions],
                         [classes[i] for i in positions], None,
                         [groups[i] for i in positions])

    def refresh(self, first: int, last: int) -> None:
        """Rows *first*..*last* were replaced in place: read them again."""
        items = self.items
        for row in range(max(0, first), min(last, len(items) - 1) + 1):
            item = items[row]
            self.names[row] = item.name
            self.folded[row] = item.name.casefold()
            self.classes[row] = _row_class(item)
            self.groups[row] = _groups([item.name], [item])[0]
        self.unhidden = [i for i, c in enumerate(self.classes) if c != _HIDDEN]


class PreparedListing(list):
    """A listing (a list of FileItem, usable as one) with its sorted order
    and filter facts already worked out - on the thread that listed it
    (ui.file_pane ``_fetch_listing``), so showing 100,000 entries does not
    sort them on the GUI thread. :meth:`FileTableModel.set_items` uses the
    work when the sort is still the one it was done for and the list was
    not changed since; otherwise it sorts as for a plain list."""

    def __init__(self, items, sort_spec: tuple[int, Qt.SortOrder] | None):
        super().__init__(items)
        self.sort_spec = sort_spec
        self._length = len(self)
        listed = list(self)
        cache = _RowCache(listed)
        positions = None
        if sort_spec is not None and 0 <= sort_spec[0] < len(COLUMNS):
            positions = sort_positions(listed, *sort_spec, names=cache.names,
                                       groups=cache.groups, in_pieces=True)
        elif sort_spec is not None and sort_spec[1] == Qt.SortOrder.DescendingOrder:
            # No valid column: the listing order, reversed for descending.
            positions = list(range(len(listed) - 1, -1, -1))
        if positions is not None:
            listed = [listed[i] for i in positions]
            cache = cache.permuted(listed, positions)
        self.sorted_items = listed
        self.cache = cache

    def usable_for(self, sort_spec) -> bool:
        return self.sort_spec == sort_spec and len(self) == self._length


class FileTableModel(QAbstractTableModel):
    """Table model backed by a list of FileItem objects."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: list[FileItem] = []
        self._listing: list[FileItem] = []  # order as listed, for "unsorted"
        self._sort_spec: tuple[int, Qt.SortOrder] | None = None
        self._highlight_hidden = True
        # (palette cache key, brush or None) - the muted colour is worked
        # out once per application palette, not once per painted cell.
        self._hidden_brush: tuple[int, QBrush | None] | None = None
        self._hidden_color: str | None = None
        self._hidden_color_brush: QBrush | None = None
        #: FileItem -> its tag names (core.tags), set by the pane; the
        #: tooltip of the Name column lists them.
        self.tag_lookup = None
        #: Folder name -> (bytes, incomplete) measured by Calculate Size for
        #: THIS listing; a new listing (set_items) drops it.
        self._computed: dict[str, tuple[int, bool]] = {}
        #: Names of the entries a pending Cut holds (ui.cut_clipboard): drawn
        #: dimmed until they are pasted or the cut is dropped. Kept across
        #: listings of the folder; the pane sets it.
        self._cut_names: frozenset[str] = frozenset()
        #: The filter facts of _items (see row_cache).
        self._cache: _RowCache | None = None
        #: During a sort's layoutChanged: old row -> new row (FileSortProxyModel
        #: maps its rows with it instead of filtering again).
        self._moved: list[int] | None = None

    @property
    def sort_spec(self) -> tuple[int, Qt.SortOrder] | None:
        """``(column, order)`` of the current sort, or None."""
        return self._sort_spec

    @property
    def highlight_hidden(self) -> bool:
        """Hidden entries (``FileItem.is_hidden``) are drawn in italics
        and, where it stays readable, in the theme's muted text colour."""
        return self._highlight_hidden

    @highlight_hidden.setter
    def highlight_hidden(self, value: bool) -> None:
        value = bool(value)
        if value == self._highlight_hidden:
            return
        self._highlight_hidden = value
        self._emit_hidden_style_changed()

    @property
    def hidden_color(self) -> str | None:
        """The user's colour for hidden entries (``#rrggbb``), or ``None``
        for the theme's muted colour."""
        return self._hidden_color

    @hidden_color.setter
    def hidden_color(self, value: str | None) -> None:
        if value is not None:
            if not is_hex_colour(value):
                raise ValueError(f"not a #rrggbb colour: {value!r}")
            value = value.lower()
        if value == self._hidden_color:
            return
        self._hidden_color = value
        self._hidden_color_brush = QBrush(QColor(value)) if value is not None else None
        self._emit_hidden_style_changed()

    def _emit_hidden_style_changed(self) -> None:
        if self._items:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._items) - 1, len(COLUMNS) - 1),
                [Qt.ItemDataRole.FontRole, Qt.ItemDataRole.ForegroundRole],
            )

    def _hidden_foreground(self) -> QBrush | None:
        if self._hidden_color_brush is not None:
            return self._hidden_color_brush
        palette = QApplication.palette()
        key = palette.cacheKey()
        if self._hidden_brush is None or self._hidden_brush[0] != key:
            colour = hidden_entry_color(palette)
            self._hidden_brush = (key, QBrush(colour) if colour is not None else None)
        return self._hidden_brush[1]

    @property
    def cut_names(self) -> frozenset[str]:
        return self._cut_names

    def set_cut_names(self, names) -> None:
        """Draw the entries named *names* dimmed (a pending Cut holds them)."""
        names = frozenset(names)
        if names == self._cut_names:
            return
        self._cut_names = names
        if self._items:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(len(self._items) - 1, len(COLUMNS) - 1),
                [Qt.ItemDataRole.ForegroundRole],
            )

    @staticmethod
    def _cut_foreground() -> QBrush:
        """The palette's disabled text colour: a cut entry looks unavailable."""
        palette = QApplication.palette()
        return QBrush(palette.color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text))

    def set_items(self, items: list[FileItem], keep_sizes: bool = False) -> None:
        """Show *items*. Folder sizes Calculate Size measured go - unless
        *keep_sizes* (the same folder listed again by itself: after a change
        the watcher saw, after an operation): then those of folders still
        there stay - a calculation can take minutes.

        *items* may be a :class:`PreparedListing`: then the sort and the
        filter facts worked out on the listing thread are taken as they
        are, unless the sort changed meanwhile."""
        self.beginResetModel()
        if keep_sizes and self._computed:
            folders = {item.name for item in items if item.is_dir}
            self._computed = {k: v for k, v in self._computed.items() if k in folders}
        else:
            self._computed = {}
        self._listing = list(items)
        sizes_matter = bool(self._computed) and self._sort_spec is not None \
            and self._sort_spec[0] == COL_SIZE
        if isinstance(items, PreparedListing) and not sizes_matter \
                and items.usable_for(self._sort_spec):
            self._items = list(items.sorted_items)
            self._cache = items.cache.copy_for(self._items)
        else:
            self._items = self._sorted(self._listing)
            self._cache = None
        self.endResetModel()

    def row_cache(self) -> _RowCache:
        """The filter facts of the current items (worked out on first use)."""
        cache = self._cache
        if cache is None or cache.items is not self._items:
            cache = self._cache = _RowCache(self._items)
        return cache

    def entry_count(self) -> int:
        """The entries listed, without the "." and ".." rows."""
        return len(self._items) - self.row_cache().classes.count(_NAV)

    def set_computed_sizes(self, sizes: dict[str, tuple[int, bool]]) -> None:
        """Show the size Calculate Size measured for these folders of the
        current listing (``name -> (bytes, incomplete)``) in the Size column,
        and sort by it, until the next listing."""
        if not sizes:
            return
        self._computed.update({str(k): (int(v[0]), bool(v[1])) for k, v in sizes.items()})
        if self._sort_spec is not None and self._sort_spec[0] == COL_SIZE:
            self.sort(*self._sort_spec)
        if self._items:
            self.dataChanged.emit(
                self.index(0, COL_SIZE),
                self.index(len(self._items) - 1, COL_SIZE),
                [Qt.ItemDataRole.DisplayRole],
            )

    def computed_size(self, name: str) -> tuple[int, bool] | None:
        return self._computed.get(name)

    def _positions(self, items: list[FileItem]) -> list[int]:
        """Positions of *items* in the current sort order."""
        column, order = self._sort_spec
        if not 0 <= column < len(COLUMNS):
            # Qt: no valid sort column means the source (listing) order,
            # reversed for descending (measured against the former proxy).
            at = {id(item): row for row, item in enumerate(items)}
            listing = self._listing[::-1] if order == Qt.SortOrder.DescendingOrder \
                else self._listing
            return [at[id(item)] for item in listing if id(item) in at]
        cache = self._cache
        if cache is not None and cache.items is items:
            return sort_positions(items, column, order, self._computed,
                                  names=cache.names, groups=cache.groups)
        return sort_positions(items, column, order, self._computed)

    def _sorted(self, items: list[FileItem]) -> list[FileItem]:
        if self._sort_spec is None:
            return list(items)
        return [items[i] for i in self._positions(items)]

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """Sort in Python's ``sorted`` over precomputed values — no Python
        call per row or comparison (a ``lessThan`` per comparison was
        ~275 000 calls for 20 000 rows)."""
        self._sort_spec = (column, order)
        hint = QAbstractItemModel.LayoutChangeHint.VerticalSortHint
        self.layoutAboutToBeChanged.emit([], hint)
        # From the current order, like QSortFilterProxyModel's stable sort of
        # its current mapping: ties keep the order of the previous sort; only
        # a new listing (set_items) starts from the listing order.
        items = self._items
        self.row_cache()  # names and groups for the sort; the filter reads it anyway
        positions = self._positions(items)
        if len(positions) != len(items):  # an item not in the listing: keep all
            seen = set(positions)
            positions += [i for i in range(len(items)) if i not in seen]
        new_items = [items[i] for i in positions]
        new_row_of_old = [0] * len(new_items)
        for row, old in enumerate(positions):
            new_row_of_old[old] = row
        cache = self._cache
        self._cache = cache.permuted(new_items, positions) \
            if cache is not None and cache.items is items else None
        self._items = new_items
        persistent = self.persistentIndexList()
        if persistent:
            self.changePersistentIndexList(
                persistent,
                [self.index(new_row_of_old[i.row()], i.column()) for i in persistent],
            )
        self._moved = new_row_of_old
        try:
            self.layoutChanged.emit([], hint)
        finally:
            self._moved = None

    def display_text(self, item: FileItem, col: int) -> str | None:
        """What column *col* shows for *item* (its DisplayRole)."""
        if col == COL_NAME:
            # Shown, not used: a server's name with controls or bidi
            # overrides ("report\u202efdp.exe" reads as "reportexe.pdf")
            # shows them as U+FFFD. Every operation still uses item.name.
            return sanitize_for_display(item.name)
        if item.is_nav and col in (COL_MODIFIED, COL_PERMS, COL_OWNER):
            # "." and ".." are the pane's own rows, made without a stat: their
            # 1970 time and "d---------" were placeholders, not the folder's
            return ""
        if col == COL_SIZE:
            if item.is_dir and item.name in self._computed:
                return measured_bytes(*self._computed[item.name])
            return item.size_human
        if col == COL_MODIFIED:
            if item.stat_error:
                return "?"
            return item.modified.strftime("%Y-%m-%d %H:%M")
        if col == COL_PERMS:
            return item.mode_str
        if col == COL_OWNER:
            owner = item.owner
            if item.group:
                owner += f":{item.group}"
            return owner
        return None

    def get_item(self, row: int) -> FileItem | None:
        if 0 <= row < len(self._items):
            return self._items[row]
        return None

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._items)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self._items):
            return None
        return self.item_data(self._items[index.row()], index.column(), role)

    def item_data(self, item: FileItem, col: int, role: int):
        """:meth:`data` of *item* in column *col* (FileSortProxyModel asks
        this directly, without a source index per call)."""
        if role == Qt.ItemDataRole.DisplayRole:
            return self.display_text(item, col)

        if item.is_nav and col == COL_NAME and role == Qt.ItemDataRole.ToolTipRole:
            # The pane's own rows say what they are (round 6: "." looked
            # like an entry): "." is this folder - a drop target - and
            # ".." the parent. Not italic: that is the look of a hidden entry.
            return (tr("This folder: drop entries here to put them into it")
                    if item.name == "." else tr("The parent folder"))

        if role == Qt.ItemDataRole.ToolTipRole and col == COL_NAME and not item.is_nav:
            # Tooltips are always rendered as rich text: escape the name so
            # markup inside a hostile file name is shown literally, and keep
            # long names on one line (no wrapping in the middle of a name).
            tags = self.tag_lookup(item) if self.tag_lookup is not None else []
            note = f"<br>Tags: {escape(', '.join(tags))}" if tags else ""
            if item.stat_error:
                note += f"<br>Attributes unreadable: {escape(item.stat_error)}"
            # Display filter as in the cell: a bidi override in a name
            # would reorder the tooltip's text around it.
            return f"<p style='white-space:pre'>{escape(sanitize_for_display(item.name))}{note}</p>"

        if role == Qt.ItemDataRole.DecorationRole and col == COL_NAME:
            return entry_icon(item.is_dir)

        if (
            role == Qt.ItemDataRole.ForegroundRole
            and self._cut_names
            and item.name in self._cut_names
            and not item.is_nav
        ):
            return self._cut_foreground()

        if (
            role in (Qt.ItemDataRole.FontRole, Qt.ItemDataRole.ForegroundRole)
            and self._highlight_hidden
            and item.is_hidden
            and not item.is_nav
        ):
            if role == Qt.ItemDataRole.FontRole:
                return _italic()
            return self._hidden_foreground()

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col == COL_SIZE:
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter

        return None

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(COLUMNS):
                return tr(COLUMNS[section])
        return None

    # QAbstractTableModel.flags depends only on index validity, so both
    # answers are constants; building them per call (several enum ORs) was
    # most of the cost of selectedRows() on large listings.
    _VALID_FLAGS = (
        Qt.ItemFlag.ItemIsSelectable
        | Qt.ItemFlag.ItemIsEnabled
        | Qt.ItemFlag.ItemNeverHasChildren
        | Qt.ItemFlag.ItemIsDragEnabled
    )
    _INVALID_FLAGS = Qt.ItemFlag.ItemIsDropEnabled

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        return self._VALID_FLAGS if index.isValid() else self._INVALID_FLAGS

    def supportedDropActions(self) -> Qt.DropAction:
        return Qt.DropAction.CopyAction | Qt.DropAction.MoveAction


def prepare_listing(items: list[FileItem], model: FileTableModel | None) -> PreparedListing:
    """*items* as a :class:`PreparedListing` for *model*'s current sort -
    for the listing thread (reads only the sort spec, a tuple)."""
    return PreparedListing(items, model.sort_spec if model is not None else None)




# -- the filter -----------------------------------------------------------------------------

_FIXED, _REGEX = "fixed", "regex"
_ROOT = QModelIndex()
_LAYOUT_HINT = QAbstractItemModel.LayoutChangeHint.VerticalSortHint
#: Up to this (runs x (persistent indexes + runs / 2)) a filter change is
#: reported run by run (see FileSortProxyModel._refilter).
_RUN_WORK = 20_000


_MISSING_RUN = re.compile(b"\\x00+")


def _kept(rows: list[int], others: set[int]) -> bytes:
    """One byte per entry of *rows*: 1 when its row is in *others*, else 0
    (worked out in C, as the runs below)."""
    return bytes(map(others.__contains__, rows))


def _run_count(kept: bytes) -> int:
    """How many runs of 0 *kept* holds."""
    return kept.count(b"\x01\x00") + kept.startswith(b"\x00")


def _missing_runs(kept: bytes) -> list[tuple[int, int]]:
    """The runs of 0 in *kept* as ``(first, last)`` positions."""
    return [(m.start(), m.end() - 1) for m in _MISSING_RUN.finditer(kept)]


class FileSortProxyModel(QAbstractProxyModel):
    """The rows of a FileTableModel the pane shows: "." and "..", the
    entries whose name holds the filter text (case-insensitive in the
    pane), hidden entries only when they are to be shown, and - with a
    ``tag:<name>`` filter - only tagged entries. The source model sorts;
    this proxy keeps its order and only leaves rows out.

    Formerly a QSortFilterProxyModel: Qt called a Python
    ``filterAcceptsRow`` for every row of every listing, sort and filter
    keystroke (900,000 calls, 12.7 s, for nine keys over 100,000 entries).
    Now the shown rows are one ascending list (``_rows``: proxy row ->
    source row), worked out in one list comprehension over the casefolded
    names the model keeps (``needle in folded[row]``); a filter text that
    grows narrows the previous result instead of testing every row again.
    A sort maps the shown rows through the sort's permutation. Selection
    and current index follow their entries: a filter change is reported as
    rows removed and inserted (see _refilter), a sort as a layout change
    that moves the persistent indexes, as the former proxy's did.

    The QSortFilterProxyModel calls the pane, the thumbnail view and tests
    make are kept: ``setFilterFixedString`` / ``RegularExpression`` /
    ``Wildcard``, ``setFilterCaseSensitivity``, ``filterRegularExpression``,
    ``invalidate`` / ``invalidateFilter``, ``mapToSource`` /
    ``mapFromSource``, ``sort``. A subclass that overrides
    ``filterAcceptsRow`` gets it asked per row, as Qt did. A fixed text
    compares casefolded names when case-insensitive: "STRASSE" also finds
    "straße" (Qt compared simple case folds).
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._show_hidden = False
        #: FileItem -> bool, or None: "tag:<name>" in the pane's filter.
        self._tag_filter = None
        #: The FileTableModel filtered, or None for another source model.
        self._file_model: FileTableModel | None = None
        #: proxy row -> source row, ascending.
        self._rows: list[int] = []
        self._mode = _FIXED
        self._text = ""
        self._case = Qt.CaseSensitivity.CaseSensitive
        self._regex: QRegularExpression | None = None  # made on first use
        self._key_column = 0
        self._sort_role = Qt.ItemDataRole.DisplayRole
        self._sort_column = -1
        self._sort_order = Qt.SortOrder.AscendingOrder
        #: (cache, show_hidden, folded, needle, rows) of the last fixed-text pass.
        self._last_pass = None
        #: Over a source layout change: the source items before it (a
        #: FileTableModel) or source persistent indexes (another model).
        self._before_layout = None
        self._connections: list = []

    # -- source -----------------------------------------------------------------------------

    def setSourceModel(self, model) -> None:  # noqa: N802 - Qt override
        self.beginResetModel()
        for signal, slot in self._connections:
            try:
                signal.disconnect(slot)
            except (TypeError, RuntimeError):
                pass
        self._connections = []
        super().setSourceModel(model)
        self._file_model = model if isinstance(model, FileTableModel) else None
        self._last_pass = None
        if model is not None:
            reset = (self._source_about_to_reset, self._source_reset)
            for signal, slot in (
                (model.modelAboutToBeReset, reset[0]),
                (model.modelReset, reset[1]),
                (model.layoutAboutToBeChanged, self._source_layout_about_to_change),
                (model.layoutChanged, self._source_layout_changed),
                (model.dataChanged, self._source_data_changed),
                (model.headerDataChanged, self.headerDataChanged),
                (model.rowsAboutToBeInserted, reset[0]), (model.rowsInserted, reset[1]),
                (model.rowsAboutToBeRemoved, reset[0]), (model.rowsRemoved, reset[1]),
                (model.rowsAboutToBeMoved, reset[0]), (model.rowsMoved, reset[1]),
                (model.columnsAboutToBeInserted, reset[0]), (model.columnsInserted, reset[1]),
                (model.columnsAboutToBeRemoved, reset[0]), (model.columnsRemoved, reset[1]),
                (model.columnsAboutToBeMoved, reset[0]), (model.columnsMoved, reset[1]),
            ):
                signal.connect(slot)
                self._connections.append((signal, slot))
        self._rows = self._compute_rows()
        self.endResetModel()

    def _source_about_to_reset(self, *_args) -> None:
        self.beginResetModel()

    def _source_reset(self, *_args) -> None:
        self._last_pass = None
        self._rows = self._compute_rows()
        self.endResetModel()

    def _source_layout_about_to_change(self, *_args) -> None:
        self.layoutAboutToBeChanged.emit([], _LAYOUT_HINT)
        model = self._file_model
        if model is not None:
            self._before_layout = model._items
            return
        # Another source: hold the persistent indexes' source entries.
        src, rows = self.sourceModel(), self._rows
        self._before_layout = [
            (idx, QPersistentModelIndex(src.index(rows[idx.row()], idx.column())))
            for idx in self.persistentIndexList() if 0 <= idx.row() < len(rows)
        ]

    def _source_layout_changed(self, *_args) -> None:
        model = self._file_model
        before, self._before_layout = self._before_layout, None
        self._last_pass = None
        old_rows = self._rows
        if model is not None:
            moved = model._moved
            if moved is not None and len(moved) == len(model._items) \
                    and all(0 <= row < len(moved) for row in old_rows[-1:]):
                # A sort: the same entries are shown, in their new order.
                self._show_rows(sorted(map(moved.__getitem__, old_rows)), old_rows,
                                moved.__getitem__)
            else:
                old_items = before if before is not None else []
                at = {id(item): row for row, item in enumerate(model._items)}
                self._show_rows(self._compute_rows(), old_rows, lambda source: at.get(
                    id(old_items[source])) if source < len(old_items) else None)
        else:
            self._rows = self._compute_rows()
            held = before or []
            if held:
                self.changePersistentIndexList(
                    [idx for idx, _source in held],
                    [self._index_of_source(source.row(), idx.column()) if source.isValid()
                     else QModelIndex() for idx, source in held])
        self.layoutChanged.emit([], _LAYOUT_HINT)

    def _source_data_changed(self, top_left, bottom_right, roles=()) -> None:
        model = self._file_model
        if (model is not None
                and (not roles or Qt.ItemDataRole.DisplayRole in roles)
                and top_left.column() <= self._key_column <= bottom_right.column()):
            # Rows replaced in place: what the filter reads may have changed.
            cache = model._cache
            if cache is not None and cache.items is model._items:
                cache.refresh(top_left.row(), bottom_right.row())
            self.invalidateFilter()
        rows = self._rows
        if not rows:
            return
        first = bisect_left(rows, top_left.row())
        last = bisect_right(rows, bottom_right.row()) - 1
        if first <= last:
            self.dataChanged.emit(self.index(first, top_left.column()),
                                  self.index(last, bottom_right.column()), list(roles or ()))

    # -- which rows -------------------------------------------------------------------------

    def _custom_rule(self) -> bool:
        """A subclass (or a test) replaced filterAcceptsRow: ask it per row."""
        return type(self).filterAcceptsRow is not _OWN_FILTER_ACCEPTS_ROW

    def _compute_rows(self) -> list[int]:
        model = self._file_model
        if model is None:
            src = self.sourceModel()
            return list(range(src.rowCount())) if src is not None else []
        if self._custom_rule():
            accepts, root = self.filterAcceptsRow, QModelIndex()
            return [row for row in range(model.rowCount()) if accepts(row, root)]
        cache = model.row_cache()
        candidates = range(len(cache.names)) if self._show_hidden else cache.unhidden
        classes = cache.classes
        tag = self._tag_filter
        if tag is not None:
            items = cache.items
            candidates = [r for r in candidates if classes[r] == _NAV or tag(items[r])]
        if self._mode == _FIXED:
            if not self._text:
                return list(candidates)
            folded = self._case == Qt.CaseSensitivity.CaseInsensitive
            names = cache.folded if folded else cache.names
            needle = self._text.casefold() if folded else self._text
            last = self._last_pass
            if (tag is None and last is not None and last[0] is cache
                    and last[1] == self._show_hidden and last[2] == folded and last[3] in needle):
                # The text grew (or is the same): only the rows the previous
                # text showed can still match.
                candidates = last[4]
            rows = [r for r in candidates if needle in names[r] or classes[r] == _NAV]
            self._last_pass = (cache, self._show_hidden, folded, needle, rows) \
                if tag is None else None
            return rows
        regex = self.filterRegularExpression()
        if not regex.pattern():
            return list(candidates)
        match, names = regex.match, cache.names
        return [r for r in candidates if classes[r] == _NAV or match(names[r]).hasMatch()]

    def _proxy_row(self, source_row: int) -> int | None:
        rows = self._rows
        at = bisect_left(rows, source_row)
        return at if at < len(rows) and rows[at] == source_row else None

    def _index_of_source(self, source_row: int, column: int) -> QModelIndex:
        row = self._proxy_row(source_row)
        return self.createIndex(row, column) if row is not None else QModelIndex()

    def _refilter(self) -> None:
        """Work the shown rows out again; when they changed, say so as rows
        removed and rows inserted - one signal pair per contiguous run.

        Not as a plain layout change: QItemSelectionModel takes a shortcut
        over a layout change while one range selects the whole table (more
        than 1000 cells) - it selects the whole table again afterwards, or
        keeps the range from its first to its last entry - so Show Hidden
        Files selected the dot files between "." and the last entry, and a
        filter switch selected entries never selected. Over removals and
        insertions every selected entry still shown stays selected and no
        other one is, as with the former QSortFilterProxyModel.

        A selection model, though, walks all its ranges for every removal
        and insertion - through this Python ``parent()`` - and every removal
        inside a selected range adds a range: thousands of runs under a big
        selection took half a minute. Past _RUN_WORK, the first run is
        still reported as such (the selection model then holds its selection
        as ranges, which ends its shortcut) and the rest as one layout
        change that moves every persistent index to its entry's new row."""
        new_rows = self._compute_rows()
        old_rows = self._rows
        if new_rows == old_rows:
            return
        # 0 in kept_old: no longer shown; 0 in kept_new: shown now. A text
        # that grew only removes, one that shrank only adds: one pass then.
        if len(new_rows) <= len(old_rows):
            kept_old = _kept(old_rows, set(new_rows))
            kept_new = (b"\x01" * len(new_rows) if kept_old.count(b"\x01") == len(new_rows)
                        else _kept(new_rows, set(old_rows)))
        else:
            kept_new = _kept(new_rows, set(old_rows))
            kept_old = (b"\x01" * len(old_rows) if kept_new.count(b"\x01") == len(old_rows)
                        else _kept(old_rows, set(new_rows)))
        runs = _run_count(kept_old) + _run_count(kept_new)
        rows = list(old_rows)
        self._rows = rows
        if runs > 1 and runs * (len(self.persistentIndexList()) + runs // 2) > _RUN_WORK:
            last = kept_old.rfind(b"\x00")
            if last >= 0:  # the last run removed
                first = kept_old.rfind(b"\x01", 0, last) + 1
                self.beginRemoveRows(_ROOT, first, last)
                del rows[first:last + 1]
                self.endRemoveRows()
            else:  # the first run inserted
                first = kept_new.find(b"\x00")
                last = kept_new.find(b"\x01", first)
                last = (len(kept_new) if last < 0 else last) - 1
                self.beginInsertRows(_ROOT, first, last)
                rows[first:first] = new_rows[first:last + 1]
                self.endInsertRows()
            self.layoutAboutToBeChanged.emit([], _LAYOUT_HINT)
            self._show_rows(new_rows, rows, None)
            self.layoutChanged.emit([], _LAYOUT_HINT)
            return
        # From the last run back: the rows before a run keep their place.
        for first, last in reversed(_missing_runs(kept_old)):
            self.beginRemoveRows(_ROOT, first, last)
            del rows[first:last + 1]
            self.endRemoveRows()
        # Now the rows kept, in order; each run goes in at its final place.
        for first, last in _missing_runs(kept_new):
            self.beginInsertRows(_ROOT, first, last)
            rows[first:first] = new_rows[first:last + 1]
            self.endInsertRows()
        self._rows = new_rows

    def _show_rows(self, new_rows: list[int], old_rows: list[int], moved) -> None:
        """Show *new_rows*; every persistent index goes to its entry's new
        row (*moved*: old source row -> new source row or None; None: the
        source rows stayed), or becomes invalid when its entry is no
        longer shown."""
        persistent = self.persistentIndexList()
        self._rows = new_rows
        if not persistent:
            return
        targets = []
        invalid = QModelIndex()
        for idx in persistent:
            row = idx.row()
            target = invalid
            if 0 <= row < len(old_rows):
                source = old_rows[row] if moved is None else moved(old_rows[row])
                if source is not None:
                    target = self._index_of_source(source, idx.column())
            targets.append(target)
        self.changePersistentIndexList(persistent, targets)

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # noqa: N802
        """Whether source row *source_row* is shown - the rule for one row
        (the proxy itself works it out for all rows at once)."""
        if self._file_model is None:
            return True
        return self._accepts(self._file_model.get_item(source_row))

    def _accepts(self, item: FileItem | None) -> bool:
        if item is None:
            return False
        # "." and ".." are always visible
        if item.is_nav:
            return True
        # Hidden files filter: dot names and entries the backend flags hidden
        if not self._show_hidden and item.is_hidden:
            return False
        if self._tag_filter is not None and not self._tag_filter(item):
            return False
        if self._mode == _FIXED:
            if not self._text:
                return True
            if self._case == Qt.CaseSensitivity.CaseInsensitive:
                return self._text.casefold() in item.name.casefold()
            return self._text in item.name
        regex = self.filterRegularExpression()
        return not regex.pattern() or regex.match(item.name).hasMatch()

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # noqa: N802
        """Never called: the source model sorts. Kept so code (and tests)
        written against the former QSortFilterProxyModel still find it."""
        return False

    # -- the filter settings (QSortFilterProxyModel's calls) ---------------------------------

    def _options(self) -> QRegularExpression.PatternOption:
        if self._case == Qt.CaseSensitivity.CaseInsensitive:
            return QRegularExpression.PatternOption.CaseInsensitiveOption
        return QRegularExpression.PatternOption.NoPatternOption

    def setFilterFixedString(self, text: str) -> None:  # noqa: N802 - Qt API
        """Show the entries whose name holds *text* as written."""
        self._mode, self._text, self._regex = _FIXED, str(text or ""), None
        self._refilter()

    def setFilterRegularExpression(self, pattern) -> None:  # noqa: N802 - Qt API
        """A QRegularExpression brings its own case option (as in Qt); a
        pattern string gets the current case sensitivity."""
        if isinstance(pattern, QRegularExpression):
            self._regex = QRegularExpression(pattern)
            insensitive = bool(pattern.patternOptions()
                               & QRegularExpression.PatternOption.CaseInsensitiveOption)
            self._case = (Qt.CaseSensitivity.CaseInsensitive if insensitive
                          else Qt.CaseSensitivity.CaseSensitive)
        else:
            self._regex = QRegularExpression(str(pattern or ""), self._options())
        self._mode, self._text = _REGEX, ""
        self.invalidateFilter()

    def setFilterWildcard(self, pattern: str) -> None:  # noqa: N802 - Qt API
        converted = QRegularExpression.wildcardToRegularExpression(
            str(pattern or ""),
            QRegularExpression.WildcardConversionOption.UnanchoredWildcardConversion)
        self._regex = QRegularExpression(converted, self._options())
        self._mode, self._text = _REGEX, ""
        self.invalidateFilter()

    def filterRegularExpression(self) -> QRegularExpression:  # noqa: N802 - Qt API
        """The filter as a QRegularExpression (a fixed text escaped)."""
        if self._regex is None:
            self._regex = QRegularExpression(QRegularExpression.escape(self._text),
                                             self._options())
        return self._regex

    def setFilterCaseSensitivity(self, case: Qt.CaseSensitivity) -> None:  # noqa: N802
        if case == self._case:
            return
        self._case = case
        if self._mode == _FIXED:
            self._regex = None
        elif self._regex is not None:
            self._regex = QRegularExpression(self._regex.pattern(), self._options())
        self.invalidateFilter()

    def filterCaseSensitivity(self) -> Qt.CaseSensitivity:  # noqa: N802 - Qt API
        return self._case

    def setFilterKeyColumn(self, column: int) -> None:  # noqa: N802 - Qt API
        """Kept for the former proxy's callers: the name is what is filtered."""
        self._key_column = column

    def filterKeyColumn(self) -> int:  # noqa: N802 - Qt API
        return self._key_column

    def setSortRole(self, role: int) -> None:  # noqa: N802 - Qt API
        self._sort_role = role

    def sortRole(self) -> int:  # noqa: N802 - Qt API
        return self._sort_role

    def sortColumn(self) -> int:  # noqa: N802 - Qt API
        return self._sort_column

    def sortOrder(self) -> Qt.SortOrder:  # noqa: N802 - Qt API
        return self._sort_order

    def invalidateFilter(self) -> None:  # noqa: N802 - Qt API
        self._last_pass = None
        self._refilter()

    def invalidate(self) -> None:
        self.invalidateFilter()

    def set_tag_filter(self, predicate) -> None:
        self._tag_filter = predicate
        self.invalidateFilter()

    def entry_counts(self) -> tuple[int, int, int]:
        """``(shown, hidden, filtered_out)``: the entries shown (not "."
        and ".."), the hidden ones left out while hidden entries are not
        shown, and the ones the filter text or tag leaves out.

        The pane's count said "10 items" while 7 were shown, and a folder
        that looked empty "1 item" for a hidden .part file (UX review
        round 7)."""
        model = self._file_model
        if model is None:
            src = self.sourceModel()
            return (self.rowCount(), 0, (src.rowCount() if src is not None else 0)
                    - self.rowCount())
        cache = model.row_cache()
        nav = cache.classes.count(_NAV)
        entries = len(cache.classes) - nav
        shown = max(0, len(self._rows) - nav)
        hidden = 0 if self._show_hidden else len(cache.classes) - len(cache.unhidden)
        return shown, hidden, max(0, entries - hidden - shown)

    @property
    def show_hidden(self) -> bool:
        return self._show_hidden

    @show_hidden.setter
    def show_hidden(self, value: bool) -> None:
        self._show_hidden = value
        self.invalidateFilter()

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """The source model sorts (see FileTableModel.sort); the proxy keeps
        its source order and only filters."""
        self._sort_column, self._sort_order = column, order
        model = self.sourceModel()
        if model is not None:
            model.sort(column, order)

    # -- rows -------------------------------------------------------------------------------

    def source_rows(self, count: int) -> list[int]:
        """The source rows of the first *count* rows shown, in order."""
        return self._rows[:max(0, count)]

    def source_rows_of(self, rows: list[int]) -> list[int]:
        """The source rows of the shown *rows*, in their order."""
        shown = self._rows
        n = len(shown)
        return [shown[row] for row in rows if 0 <= row < n]

    def nav_rows(self) -> list[int]:
        """The shown rows of "." and ".." (the pane never selects them),
        without a look at every row: they are first or last."""
        model = self._file_model
        if model is None:
            return []
        classes = model.row_cache().classes
        nav = [source for source, c in enumerate(classes[:4]) if c == _NAV]
        tail = max(4, len(classes) - 4)
        nav += [tail + i for i, c in enumerate(classes[tail:]) if c == _NAV]
        if len(nav) != classes.count(_NAV):  # an unsorted listing: anywhere
            nav = [source for source, c in enumerate(classes) if c == _NAV]
        return [row for row in map(self._proxy_row, nav) if row is not None]

    # -- QAbstractItemModel -----------------------------------------------------------------

    def index(self, row: int, column: int, parent: QModelIndex = _ROOT) -> QModelIndex:
        if 0 <= row < len(self._rows) and 0 <= column < self.columnCount() \
                and not parent.isValid():
            return self.createIndex(row, column)
        return QModelIndex()

    def parent(self, *args):
        if not args:
            return QObject.parent(self)
        return QModelIndex()

    def sibling(self, row: int, column: int, index: QModelIndex) -> QModelIndex:
        return self.index(row, column)

    def rowCount(self, parent: QModelIndex = _ROOT) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = _ROOT) -> int:  # noqa: N802
        if self._file_model is not None:
            return 0 if parent.isValid() else len(COLUMNS)
        src = self.sourceModel()
        return src.columnCount() if src is not None and not parent.isValid() else 0

    def hasChildren(self, parent: QModelIndex = _ROOT) -> bool:  # noqa: N802
        return not parent.isValid() and bool(self._rows)

    def mapToSource(self, proxy_index: QModelIndex) -> QModelIndex:  # noqa: N802
        src = self.sourceModel()
        if src is None or not proxy_index.isValid():
            return QModelIndex()
        row = proxy_index.row()
        if not 0 <= row < len(self._rows):
            return QModelIndex()
        return src.index(self._rows[row], proxy_index.column())

    def mapFromSource(self, source_index: QModelIndex) -> QModelIndex:  # noqa: N802
        if not source_index.isValid():
            return QModelIndex()
        return self._index_of_source(source_index.row(), source_index.column())

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        model = self._file_model
        if model is None:
            src = self.sourceModel()
            return src.data(self.mapToSource(index), role) if src is not None else None
        rows = self._rows
        row = index.row()
        if not 0 <= row < len(rows) or not index.isValid():
            return None
        items = model._items
        source = rows[row]
        if source >= len(items):
            return None
        return model.item_data(items[source], index.column(), role)

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if self._file_model is not None:
            return FileTableModel._VALID_FLAGS if index.isValid() \
                else FileTableModel._INVALID_FLAGS
        src = self.sourceModel()
        return src.flags(self.mapToSource(index)) if src is not None \
            else Qt.ItemFlag.NoItemFlags

    def headerData(self, section: int, orientation: Qt.Orientation,  # noqa: N802
                   role: int = Qt.ItemDataRole.DisplayRole):
        src = self.sourceModel()
        if src is None:
            return None
        if orientation == Qt.Orientation.Vertical:
            if not 0 <= section < len(self._rows):
                return None
            section = self._rows[section]
        return src.headerData(section, orientation, role)


_OWN_FILTER_ACCEPTS_ROW = FileSortProxyModel.filterAcceptsRow
