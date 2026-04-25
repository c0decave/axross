from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QFileIconProvider, QStyle

from models.file_item import FileItem

COLUMNS = ("Name", "Size", "Modified", "Permissions", "Owner")
COL_NAME, COL_SIZE, COL_MODIFIED, COL_PERMS, COL_OWNER = range(5)


class FileTableModel(QAbstractTableModel):
    """Table model backed by a list of FileItem objects."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: list[FileItem] = []
        self._icon_provider = QFileIconProvider()

    def set_items(self, items: list[FileItem]) -> None:
        self.beginResetModel()
        self._items = list(items)
        self.endResetModel()

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

        if role == Qt.ItemDataRole.DecorationRole and col == COL_NAME:
            if item.is_dir:
                return self._icon_provider.icon(QFileIconProvider.IconType.Folder)
            return self._icon_provider.icon(QFileIconProvider.IconType.File)

        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col == COL_SIZE:
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(COLUMNS):
                return COLUMNS[section]
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        base_flags = super().flags(index)
        if index.isValid():
            return (
                base_flags
                | Qt.ItemFlag.ItemIsDragEnabled
                | Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
            )
        return base_flags | Qt.ItemFlag.ItemIsDropEnabled

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
        # Hidden files filter
        if not self._show_hidden and item.name.startswith("."):
            return False
        # Text filter from filter bar
        regex = self.filterRegularExpression()
        if regex.pattern():
            return regex.match(item.name).hasMatch()
        return True

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        model = self.sourceModel()
        if not isinstance(model, FileTableModel):
            return super().lessThan(left, right)

        left_item = model.get_item(left.row())
        right_item = model.get_item(right.row())

        if left_item is None or right_item is None:
            return False

        # ".." always sorts first
        if left_item.name == "..":
            return True
        if right_item.name == "..":
            return False

        # Directories always come before files
        if left_item.is_dir != right_item.is_dir:
            return left_item.is_dir

        col = left.column()
        if col == COL_NAME:
            return left_item.name.lower() < right_item.name.lower()
        if col == COL_SIZE:
            return left_item.size < right_item.size
        if col == COL_MODIFIED:
            return left_item.modified < right_item.modified
        if col == COL_PERMS:
            return left_item.permissions < right_item.permissions
        if col == COL_OWNER:
            return left_item.owner < right_item.owner

        return False
