"""Help > Third-Party Software…: the projects axross uses and ships.

One row per entry of resources/credits/third_party.json (core.third_party):
name, what axross uses it for, licence, how it comes to the user, and the
upstream link. A filter narrows the table; a link opens in the browser only
when its cell is clicked or Open Link is pressed - never on selection,
keyboard navigation or Enter.
"""

from __future__ import annotations

import time
from pathlib import Path

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, Qt, QUrl
from PyQt6.QtGui import QPalette, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from core import third_party
from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.column_fit import ColumnFitter

COL_NAME, COL_PURPOSE, COL_LICENSE, COL_SHIPS, COL_LINK = range(5)
#: Item role holding what the filter looks at (core.third_party.search_text).
SEARCH_ROLE = Qt.ItemDataRole.UserRole + 1
#: Item role holding the entry's URL (on every cell of the row).
URL_ROLE = Qt.ItemDataRole.UserRole + 2


class _FilterModel(QSortFilterProxyModel):
    """Rows whose search text contains the filter text (case-insensitive)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._needle = ""

    def set_needle(self, text: str) -> None:
        self._needle = (text or "").strip().casefold()
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:  # noqa: N802 - Qt API
        if not self._needle:
            return True
        index = self.sourceModel().index(row, COL_NAME, parent)
        return self._needle in (index.data(SEARCH_ROLE) or "")


def _tooltip(entry: third_party.Entry) -> str:
    lines = [entry.name]
    if entry.version:
        lines.append(tr("Version:") + " " + entry.version)
    if entry.via:
        lines.append(tr("Used by:") + " " + entry.via)
    if entry.note:
        lines.append(entry.note)
    return "\n".join(lines)


class ThirdPartyDialog(QDialog):
    def __init__(self, parent=None, data_file: Path | str | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Third-Party Software"))
        self.resize(1000, 640)
        self._last_open = ("", 0.0)

        layout = QVBoxLayout(self)
        self.thanks = QLabel(tr(
            "axross is built on the work of many people. These are the projects axross "
            "uses or ships, with their licences. Thank you to everyone who writes and "
            "maintains them."))
        self.thanks.setWordWrap(True)
        layout.addWidget(self.thanks)

        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        self.error_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.error_label.hide()
        layout.addWidget(self.error_label)

        row = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(tr("Filter by name, use, licence…"))
        self.filter_edit.setClearButtonEnabled(True)
        row.addWidget(self.filter_edit, 1)
        self.count_label = QLabel()
        row.addWidget(self.count_label)
        layout.addLayout(row)

        self._source = QStandardItemModel(0, 5, self)
        self._source.setHorizontalHeaderLabels(
            [tr("Name"), tr("Used for"), tr("Licence"), tr("Comes with"), tr("Link")])
        self._proxy = _FilterModel(self)
        self._proxy.setSourceModel(self._source)
        self._proxy.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self.table = QTableView()
        self.table.setModel(self._proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.verticalHeader().hide()
        self.table.setWordWrap(False)
        # Every divider draggable, the purpose column takes the free width.
        self._columns = ColumnFitter(self.table, fill=COL_PURPOSE, keep=(COL_NAME,))
        layout.addWidget(self.table, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.open_button = QPushButton(tr("Open Link"))
        self.open_button.setToolTip(tr("Open the selected project's page in the browser"))
        self.open_button.setEnabled(False)
        # A QPushButton in a dialog is auto-default: Enter anywhere would
        # "click" it and open a link nobody clicked.
        self.open_button.setAutoDefault(False)
        buttons.addButton(self.open_button, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        add_close_corner(self)

        self._fill(data_file)
        self.filter_edit.textChanged.connect(self._on_filter)
        # clicked only: activated also fires for Enter and double-clicks.
        self.table.clicked.connect(self._on_clicked)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self._update_button())
        self.open_button.clicked.connect(self._open_selected)

    # ------------------------------------------------------------------
    def _fill(self, data_file) -> None:
        try:
            entries = third_party.load(data_file)
        except third_party.DataError as exc:
            self.error_label.setText(
                tr("The list of third-party software could not be read:") + f" {exc}")
            self.error_label.show()
            self.filter_edit.setEnabled(False)
            self._total = 0
            self._update_count()
            return
        self._total = len(entries)
        link_brush = self.palette().brush(QPalette.ColorRole.Link)
        for entry in third_party.by_name(entries):
            cells = [QStandardItem(entry.name), QStandardItem(entry.purpose),
                     QStandardItem(entry.license), QStandardItem(third_party.ships_label(entry)),
                     QStandardItem(entry.url)]
            for cell in cells:
                cell.setData(entry.url, URL_ROLE)
            cells[COL_NAME].setData(third_party.search_text(entry), SEARCH_ROLE)
            cells[COL_NAME].setToolTip(_tooltip(entry))
            cells[COL_PURPOSE].setToolTip(entry.purpose)
            link = cells[COL_LINK]
            link.setForeground(link_brush)
            font = link.font()
            font.setUnderline(True)
            link.setFont(font)
            link.setToolTip(tr("Click to open in the browser"))
            self._source.appendRow(cells)
        self.table.sortByColumn(COL_NAME, Qt.SortOrder.AscendingOrder)
        self._update_count()

    def _update_count(self) -> None:
        self.count_label.setText(
            tr("{shown} of {total}").format(shown=self._proxy.rowCount(), total=self._total))

    def _update_button(self) -> None:
        self.open_button.setEnabled(bool(self.table.selectionModel().selectedRows()))

    def _on_filter(self, text: str) -> None:
        self._proxy.set_needle(text)
        self._update_count()
        self._update_button()

    def _on_clicked(self, index: QModelIndex) -> None:
        if index.isValid() and index.column() == COL_LINK:
            self._open(index.data(URL_ROLE))

    def _open_selected(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self._open(rows[0].data(URL_ROLE))

    def _open(self, url: str | None) -> None:
        """Hand *url* to the browser (core.desktop_open: the frozen build
        too). The same link twice within a double-click opens once."""
        if not url or not third_party.valid_url(url):
            return
        now = time.monotonic()
        last_url, last_time = self._last_open
        if url == last_url and now - last_time < QApplication.doubleClickInterval() / 1000:
            return
        self._last_open = (url, now)
        from core import desktop_open

        desktop_open.open_url(QUrl(url))
