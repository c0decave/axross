from __future__ import annotations

from html import escape

from PyQt6.QtCore import (
    QAbstractItemModel,
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)

from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import QApplication

from models.file_item import FileItem
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

_COLUMN_KEY = {
    COL_NAME: lambda it: it.name.lower(),
    COL_SIZE: lambda it: it.size,
    COL_MODIFIED: lambda it: it.modified,
    COL_PERMS: lambda it: it.permissions,
    COL_OWNER: lambda it: it.owner,
}


def _sort_key(column: int, computed: dict[str, tuple[int, bool]] | None = None):
    """ ".." first, then directories, then the column value — ascending.
    Descending is the same key reversed, which (stable on both sides) is
    exactly what QSortFilterProxyModel did with the former lessThan:
    files before directories and ".." last. A folder whose size
    Calculate Size measured (*computed*) sorts by that size."""
    listed = _COLUMN_KEY.get(column, lambda it: 0)
    value = listed
    if column == COL_SIZE and computed:

        def value(it):
            if it.is_dir and it.name in computed:
                return computed[it.name][0]
            return listed(it)

    return lambda it: (it.name != "..", not it.is_dir, value(it))


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

    def set_items(self, items: list[FileItem]) -> None:
        self.beginResetModel()
        self._computed = {}
        self._listing = list(items)
        self._items = self._sorted(self._listing)
        self.endResetModel()

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

    def _sorted(self, items: list[FileItem]) -> list[FileItem]:
        if self._sort_spec is None:
            return list(items)
        column, order = self._sort_spec
        if not 0 <= column < len(COLUMNS):
            # Qt: no valid sort column means the source (listing) order,
            # reversed for descending (measured against the former proxy).
            if order == Qt.SortOrder.DescendingOrder:
                return self._listing[::-1]
            return list(self._listing)
        return sorted(
            items,
            key=_sort_key(column, self._computed),
            reverse=order == Qt.SortOrder.DescendingOrder,
        )

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """Sort in Python's ``sorted`` — one key per row instead of a Python
        ``lessThan`` call per comparison (~275 000 for 20 000 rows)."""
        self._sort_spec = (column, order)
        hint = QAbstractItemModel.LayoutChangeHint.VerticalSortHint
        self.layoutAboutToBeChanged.emit([], hint)
        # From the current order, like QSortFilterProxyModel's stable sort of
        # its current mapping: ties keep the order of the previous sort; only
        # a new listing (set_items) starts from the listing order.
        old_row = {id(item): row for row, item in enumerate(self._items)}
        new_items = self._sorted(self._items)
        new_row_of_old = [0] * len(new_items)
        for row, item in enumerate(new_items):
            new_row_of_old[old_row[id(item)]] = row
        self._items = new_items
        persistent = self.persistentIndexList()
        self.changePersistentIndexList(
            persistent,
            [self.index(new_row_of_old[i.row()], i.column()) for i in persistent],
        )
        self.layoutChanged.emit([], hint)

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

        item = self._items[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == COL_NAME:
                return item.name
            if col == COL_SIZE:
                if item.is_dir and item.name in self._computed:
                    return measured_bytes(*self._computed[item.name])
                return item.size_human
            if col == COL_MODIFIED:
                return item.modified.strftime("%Y-%m-%d %H:%M")
            if col == COL_PERMS:
                return item.mode_str
            if col == COL_OWNER:
                owner = item.owner
                if item.group:
                    owner += f":{item.group}"
                return owner

        if role == Qt.ItemDataRole.ToolTipRole and col == COL_NAME and item.name != "..":
            # Tooltips are always rendered as rich text: escape the name so
            # markup inside a hostile file name is shown literally, and keep
            # long names on one line (no wrapping in the middle of a name).
            tags = self.tag_lookup(item) if self.tag_lookup is not None else []
            note = f"<br>Tags: {escape(', '.join(tags))}" if tags else ""
            return f"<p style='white-space:pre'>{escape(item.name)}{note}</p>"

        if role == Qt.ItemDataRole.DecorationRole and col == COL_NAME:
            return entry_icon(item.is_dir)

        if (
            role in (Qt.ItemDataRole.FontRole, Qt.ItemDataRole.ForegroundRole)
            and self._highlight_hidden
            and item.is_hidden
            and item.name != ".."
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
                return COLUMNS[section]
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


class FileSortProxyModel(QSortFilterProxyModel):
    """Proxy model that sorts directories before files."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._show_hidden = False
        #: FileItem -> bool, or None: "tag:<name>" in the pane's filter.
        self._tag_filter = None

    def set_tag_filter(self, predicate) -> None:
        self._tag_filter = predicate
        self.invalidateFilter()

    @property
    def show_hidden(self) -> bool:
        return self._show_hidden

    @show_hidden.setter
    def show_hidden(self, value: bool) -> None:
        self._show_hidden = value
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if not isinstance(model, FileTableModel):
            return True
        item = model.get_item(source_row)
        if item is None:
            return False
        # ".." is always visible
        if item.name == "..":
            return True
        # Hidden files filter: dot names and entries the backend flags hidden
        if not self._show_hidden and item.is_hidden:
            return False
        if self._tag_filter is not None and not self._tag_filter(item):
            return False
        # Text filter from filter bar
        regex = self.filterRegularExpression()
        if regex.pattern():
            return regex.match(item.name).hasMatch()
        return True

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        """The source model sorts (see FileTableModel.sort); the proxy keeps
        its source order and only filters."""
        model = self.sourceModel()
        if isinstance(model, FileTableModel):
            model.sort(column, order)
            return
        super().sort(column, order)
