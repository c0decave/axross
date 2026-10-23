"""The result of Calculate Size: one row per folder, sortable by every column.

Calculate Size (``FilePaneWidget._calculate_dir_size``) walks the selected
folders with :func:`core.tree_size.tree_size` on a background job. This
dialog shows what it found - name, size, files, folders inside, the share
of the total and what could not be measured - with the totals below.

Byte counts stay Python ints from the walk to the sort key: nothing here
passes them through a Qt int (32 bits; 3 GiB would arrive negative).
"""

from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.format_utils import measured_bytes as size_text

#: Shown for a share that has no meaning (nothing measured at all).
DASH = "—"

COLUMNS = ("Name", "Size", "Files", "Folders", "Share", "Notes")
COL_NAME, COL_SIZE, COL_FILES, COL_FOLDERS, COL_SHARE, COL_NOTES = range(len(COLUMNS))


@dataclass(frozen=True)
class SizeRow:
    """One measured folder. ``folders`` counts the folders inside it."""

    name: str
    bytes: int
    files: int
    folders: int
    unreadable: int = 0
    depth_capped: bool = False

    @property
    def incomplete(self) -> bool:
        """Some of it could not be measured: the size is a lower bound."""
        return bool(self.unreadable or self.depth_capped)

    @property
    def notes(self) -> str:
        notes = []
        if self.unreadable:
            notes.append(
                tr("1 folder could not be read")
                if self.unreadable == 1
                else tr("{n} folders could not be read").format(n=self.unreadable)
            )
        if self.depth_capped:
            notes.append(tr("depth limit reached"))
        return ", ".join(notes)


def rows_from_results(results) -> list[SizeRow]:
    """``(name, TreeSize)`` pairs of the walk as rows. ``TreeSize.folders``
    counts the folder itself when it could be listed; the row counts the
    folders inside it."""
    return [
        SizeRow(
            name=str(name),
            bytes=int(r.bytes),
            files=int(r.files),
            folders=max(0, int(r.folders) - 1),
            unreadable=int(r.unreadable),
            depth_capped=bool(r.depth_capped),
        )
        for name, r in results
    ]


class DirSizeModel(QAbstractTableModel):
    """The rows, sorted in Python (by the raw numbers, not the text)."""

    def __init__(self, rows: list[SizeRow], parent=None) -> None:
        super().__init__(parent)
        self._rows = list(rows)
        self._total = sum(r.bytes for r in self._rows)

    # -- read ---------------------------------------------------------------
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt
        return 0 if parent.isValid() else len(COLUMNS)

    def share(self, row: SizeRow) -> float | None:
        return None if self._total <= 0 else 100.0 * row.bytes / self._total

    def cell(self, row: SizeRow, column: int) -> str:
        if column == COL_NAME:
            return row.name
        if column == COL_SIZE:
            return size_text(row.bytes, row.incomplete)
        if column == COL_FILES:
            return str(row.files)
        if column == COL_FOLDERS:
            return str(row.folders)
        if column == COL_SHARE:
            share = self.share(row)
            return DASH if share is None else f"{share:.1f} %"
        return row.notes

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        row = self._rows[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return self.cell(row, index.column())
        if role == Qt.ItemDataRole.ToolTipRole and index.column() == COL_SIZE:
            return tr("{n} bytes").format(n=f"{row.bytes:,}")
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in (
            COL_SIZE, COL_FILES, COL_FOLDERS, COL_SHARE,
        ):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        return None

    def headerData(  # noqa: N802 - Qt
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(COLUMNS):
                return tr(COLUMNS[section])
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.ToolTipRole:
            if section == COL_FOLDERS:
                return tr("Folders inside it")
        return None

    # -- sort ---------------------------------------------------------------
    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        keys = {
            COL_NAME: lambda r: r.name.lower(),
            COL_SIZE: lambda r: r.bytes,
            COL_FILES: lambda r: r.files,
            COL_FOLDERS: lambda r: r.folders,
            COL_SHARE: lambda r: r.bytes,
            COL_NOTES: lambda r: r.notes,
        }
        key = keys.get(column)
        if key is None:
            return
        self.layoutAboutToBeChanged.emit()
        # The view's selection and current row are persistent indexes: they
        # move with their rows, or a selected folder's highlight stayed on
        # its row number and marked another folder after the sort.
        persistent = self.persistentIndexList()
        held = [self._rows[i.row()] if 0 <= i.row() < len(self._rows) else None
                for i in persistent]
        # Stable: ties keep their name order.
        self._rows.sort(key=lambda r: r.name.lower())
        self._rows.sort(key=key, reverse=order == Qt.SortOrder.DescendingOrder)
        position = {id(row): n for n, row in enumerate(self._rows)}
        self.changePersistentIndexList(
            persistent,
            [QModelIndex() if row is None else self.index(position[id(row)], i.column())
             for i, row in zip(persistent, held)],
        )
        self.layoutChanged.emit()

    # -- for callers and tests ----------------------------------------------
    def rows(self) -> list[SizeRow]:
        return list(self._rows)

    def raw_bytes(self) -> list[int]:
        return [r.bytes for r in self._rows]


class DirSizeDialog(QDialog):
    """Non-modal: it can stay open next to the pane it came from."""

    def __init__(self, rows: list[SizeRow], folder: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Directory Size") + f" — {folder}")
        self.resize(640, 360)
        layout = QVBoxLayout(self)
        add_close_corner(self)

        self.model = DirSizeModel(rows, self)
        self.table = QTableView(self)
        self.table.setModel(self.model)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        from ui.column_fit import ColumnFitter

        # As in the file pane: every divider draggable, the numbers as wide
        # as their content, Name the free width (ui.column_fit).
        self._columns = ColumnFitter(self.table, fill=COL_NAME)
        # Largest first: what the user asked the question for.
        self.table.sortByColumn(COL_SIZE, Qt.SortOrder.DescendingOrder)
        layout.addWidget(self.table)

        self._total = QLabel(self._total_line(rows), self)
        self._total.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self._total)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, self)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _total_line(rows: list[SizeRow]) -> str:
        total = sum(r.bytes for r in rows)
        files = sum(r.files for r in rows)
        folders = sum(r.folders for r in rows)
        incomplete = any(r.incomplete for r in rows)
        return tr("Total: {size}, {files} files, {folders} folders").format(
            size=size_text(total, incomplete), files=files, folders=folders
        )

    # -- for callers and tests ----------------------------------------------
    def displayed_rows(self) -> list[tuple[str, ...]]:
        """Every row's cells as shown, in the view's order."""
        return [
            tuple(self.model.cell(row, c) for c in range(len(COLUMNS)))
            for row in self.model.rows()
        ]

    def total_text(self) -> str:
        return self._total.text()


__all__ = [
    "COLUMNS",
    "DirSizeDialog",
    "DirSizeModel",
    "SizeRow",
    "rows_from_results",
]
