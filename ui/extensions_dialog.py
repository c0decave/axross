"""Every extension found, switched on or off one by one, with the reason
when one cannot be loaded: :class:`ExtensionsPage` in Edit > Settings…
(Extensions > Manage Extensions… opens it), :class:`ExtensionsDialog` as a
dialog of its own."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import desktop_open
from core import extensions as EX
from core.i18n import tr
from ui.close_corner import add_close_corner

_COLUMNS = ("On", "Name", "Version", "Source", "Description", "Status")

WARNING = (
    "An extension is Python code that runs inside axross with your rights - "
    "it can read, change and send anything you can. Switch on only extensions "
    "you trust. Nothing of an extension runs while it is off."
)


class _ExtensionsForm:
    """The extension table with the warning, Open Extensions Folder and
    Reload. :class:`ExtensionsDialog` switches an extension at once;
    :class:`ExtensionsPage` (Edit > Settings…) keeps the switches until the
    Settings dialog saves, like every other setting there."""

    #: True: a tick switches the extension at once; False: on save().
    _immediate = True

    def _build_form(self, host, layout: QVBoxLayout) -> QHBoxLayout:
        """Build the form into *layout*; returns the button row."""
        self._host = host
        self._ids: list[str] = []
        self._filling = False
        #: ext id -> on/off chosen here and not yet applied (deferred mode).
        self._pending: dict[str, bool] = {}

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
        from ui.column_fit import ColumnFitter

        # The description takes the free width; name, version and source
        # keep their content (a long description and status squeezed the
        # name to "…"); every divider stays draggable.
        self._columns = ColumnFitter(self.table, fill=4, keep=(1, 2, 3))
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        folder_btn = QPushButton(tr("Open Extensions Folder"))
        # The desktop's file manager: this page sits in the modal Settings
        # dialog, so a pane behind it would not be seen.
        folder_btn.clicked.connect(lambda _checked=False: open_extensions_folder(self))
        reload_btn = QPushButton(tr("Reload"))
        reload_btn.clicked.connect(self._reload)
        buttons.addWidget(folder_btn)
        buttons.addWidget(reload_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        self.refresh()
        return buttons

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
                on = self._pending.get(info.ext_id, info.ext_id in enabled)
                check.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
                self.table.setItem(row, 0, check)
                status = info.error or self._host.error(info.ext_id)
                if not status:
                    status = (
                        tr("loaded") if self._host.module(info.ext_id) is not None else tr("off")
                    )
                if info.ext_id in self._pending:
                    status = tr("switched on when saved") if on else tr("switched off when saved")
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
        on = item.checkState() == Qt.CheckState.Checked
        if self._immediate:
            self._host.set_enabled(ext_id, on)
        elif on == (ext_id in EX.enabled_ids()):
            self._pending.pop(ext_id, None)  # back to what is stored
        else:
            self._pending[ext_id] = on
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


class ExtensionsPage(_ExtensionsForm, QWidget):
    """Edit > Settings… > Extensions (Extensions > Manage Extensions… opens
    it): the ticks are applied when the Settings dialog saves."""

    _immediate = False

    def __init__(self, host, parent=None) -> None:
        QWidget.__init__(self, parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self._build_form(host, layout)

    def pending(self) -> dict[str, bool]:
        return dict(self._pending)

    def is_dirty(self) -> bool:
        return bool(self._pending)

    def save(self) -> bool:
        """Switch the chosen extensions on or off (each is stored by the host)."""
        for ext_id, on in list(self._pending.items()):
            try:
                self._host.set_enabled(ext_id, on)
            except OSError as exc:
                QMessageBox.warning(self, tr("Extensions"), str(exc))
                return False
            del self._pending[ext_id]
        self.refresh()
        return True


class ExtensionsDialog(_ExtensionsForm, QDialog):
    """The extension table as a dialog of its own; a tick switches at once."""

    def __init__(self, host, parent=None) -> None:
        QDialog.__init__(self, parent)
        self.setWindowTitle(tr("Extensions"))
        self.resize(860, 420)
        layout = QVBoxLayout(self)
        buttons = self._build_form(host, layout)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        box.rejected.connect(self.reject)
        buttons.addWidget(box)
        add_close_corner(self)


def ensure_extensions_folder() -> Path:
    """The user's extension folder, created (owner only) when missing.
    Raises ``OSError`` when it cannot be."""
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return folder


def open_extensions_folder(parent: QWidget | None = None) -> bool:
    """Create the user's extension folder if needed and show it in the
    desktop's file manager; a failure is shown in a message box. Returns
    whether the file manager could be started."""
    try:
        folder = ensure_extensions_folder()
    except OSError as exc:
        QMessageBox.warning(
            parent,
            tr("Extensions"),
            tr("Could not create {folder}: {error}").format(
                folder=EX.extensions_dir(), error=exc.strerror or exc
            ),
        )
        return False
    if not desktop_open.open_url(QUrl.fromLocalFile(str(folder))):
        QMessageBox.warning(
            parent,
            tr("Extensions"),
            tr("Could not open {folder} in the desktop's file manager.").format(folder=folder),
        )
        return False
    return True


__all__ = [
    "ExtensionsDialog",
    "ExtensionsPage",
    "WARNING",
    "ensure_extensions_folder",
    "open_extensions_folder",
]
