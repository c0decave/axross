from __future__ import annotations

from html import escape

from PyQt6.QtCore import (
    QAbstractItemModel,
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)

from models.file_item import FileItem
from ui.icon_provider import entry_icon

COLUMNS = ("Name", "Size", "Modified", "Permissions", "Owner")
COL_NAME, COL_SIZE, COL_MODIFIED, COL_PERMS, COL_OWNER = range(5)

_COLUMN_KEY = {
    COL_NAME: lambda it: it.name.lower(),
    COL_SIZE: lambda it: it.size,
    COL_MODIFIED: lambda it: it.modified,
    COL_PERMS: lambda it: it.permissions,
    COL_OWNER: lambda it: it.owner,
}


def _sort_key(column: int):
    """ ".." first, then directories, then the column value — ascending.
    Descending is the same key reversed, which (stable on both sides) is
    exactly what QSortFilterProxyModel did with the former lessThan:
    files before directories and ".." last."""
    value = _COLUMN_KEY.get(column, lambda it: 0)
    return lambda it: (it.name != "..", not it.is_dir, value(it))


class FileTableModel(QAbstractTableModel):
    """Table model backed by a list of FileItem objects."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: list[FileItem] = []
        self._listing: list[FileItem] = []  # order as listed, for "unsorted"
        self._sort_spec: tuple[int, Qt.SortOrder] | None = None

    def set_items(self, items: list[FileItem]) -> None:
        self.beginResetModel()
        self._listing = list(items)
        self._items = self._sorted(self._listing)
        self.endResetModel()

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
        return sorted(items, key=_sort_key(column), reverse=order == Qt.SortOrder.DescendingOrder)

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
            return f"<p style='white-space:pre'>{escape(item.name)}</p>"

        if role == Qt.ItemDataRole.DecorationRole and col == COL_NAME:
            return entry_icon(item.is_dir)

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
