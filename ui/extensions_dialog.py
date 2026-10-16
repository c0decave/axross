"""Extensions > Manage Extensions…: every extension found, switched on or
off one by one, with the reason when one cannot be loaded."""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import extensions as EX
from core.i18n import tr

_COLUMNS = ("On", "Name", "Version", "Source", "Description", "Status")

WARNING = (
    "An extension is Python code that runs inside axross with your rights - "
    "it can read, change and send anything you can. Switch on only extensions "
    "you trust. Nothing of an extension runs while it is off."
)


class ExtensionsDialog(QDialog):
    def __init__(self, host, parent=None) -> None:
        super().__init__(parent)
        self._host = host
        self._ids: list[str] = []
        self._filling = False
        self.setWindowTitle(tr("Extensions"))
        self.resize(860, 420)

        layout = QVBoxLayout(self)
        self._warning = QLabel(tr(WARNING))
        self._warning.setWordWrap(True)
        layout.addWidget(self._warning)
        self._blocked = QLabel(
            tr("The paranoid security mode is on: no extension is loaded.")
        )
        self._blocked.setStyleSheet("font-weight: bold;")
        layout.addWidget(self._blocked)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in _COLUMNS])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        folder_btn = QPushButton(tr("Open Extensions Folder"))
        folder_btn.clicked.connect(open_extensions_folder)
        reload_btn = QPushButton(tr("Reload"))
        reload_btn.clicked.connect(self._reload)
        buttons.addWidget(folder_btn)
        buttons.addWidget(reload_btn)
        buttons.addStretch(1)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        box.rejected.connect(self.reject)
        buttons.addWidget(box)
        layout.addLayout(buttons)
        self.refresh()

    # -- table ----------------------------------------------------------------
    def refresh(self) -> None:
        allowed = EX.extensions_allowed()
        self._blocked.setVisible(not allowed)
        enabled = EX.enabled_ids()
        infos = EX.discover()
        self._filling = True
        try:
            self.table.setRowCount(0)
            self._ids = []
            for info in infos:
                row = self.table.rowCount()
                self.table.insertRow(row)
                self._ids.append(info.ext_id)
                check = QTableWidgetItem()
                flags = Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable
                if allowed and not info.error:
                    flags |= Qt.ItemFlag.ItemIsEnabled
                check.setFlags(flags)
                check.setCheckState(
                    Qt.CheckState.Checked if info.ext_id in enabled else Qt.CheckState.Unchecked
                )
                self.table.setItem(row, 0, check)
                status = info.error or self._host.error(info.ext_id)
                if not status:
                    status = (
                        tr("loaded") if self._host.module(info.ext_id) is not None else tr("off")
                    )
                cells = (info.name, info.version, info.source, info.description, status)
                for col, text in enumerate(cells, start=1):
                    item = QTableWidgetItem(text)
                    item.setToolTip(f"{info.path}\n{text}" if col == 1 else text)
                    self.table.setItem(row, col, item)
        finally:
            self._filling = False

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._filling or item.column() != 0:
            return
        ext_id = self._ids[item.row()]
        self._host.set_enabled(ext_id, item.checkState() == Qt.CheckState.Checked)
        # Not from inside the table's own signal: refresh() rebuilds the rows.
        QTimer.singleShot(0, self.refresh)

    def _reload(self) -> None:
        self._host.reload()
        self.refresh()

    # -- for tests ----------------------------------------------------------------
    def row_of(self, ext_id: str) -> int:
        return self._ids.index(ext_id) if ext_id in self._ids else -1

    def is_checked(self, row: int) -> bool:
        return self.table.item(row, 0).checkState() == Qt.CheckState.Checked

    def set_checked(self, row: int, on: bool) -> None:
        self.table.item(row, 0).setCheckState(
            Qt.CheckState.Checked if on else Qt.CheckState.Unchecked
        )

    def warning_text(self) -> str:
        return self._warning.text()


def open_extensions_folder() -> None:
    """Create the user's extension folder if needed and show it."""
    from PyQt6.QtCore import QUrl

    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))


__all__ = ["ExtensionsDialog", "WARNING", "open_extensions_folder"]
