"""The server field of the chat account editor: an editable drop-down of
known public servers (core.chat_servers) - the user can always type a
server of their own - with "Refresh list", which fetches the public
directories off the GUI thread and keeps the bundled snapshot when that
fails.

The entries come from the network: they are shown as plain text (a
QComboBox item), never as markup.
"""

from __future__ import annotations

import logging
import threading

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QToolButton, QVBoxLayout, QWidget

from core import chat_servers as S
from core.i18n import tr
from core.thread_relay import GuiCall
from ui.icon_provider import icon

log = logging.getLogger(__name__)

ORIGIN_TEXT = {
    "bundled": "List of {date} shipped with axross",
    "cache": "List of {date}, refreshed from the public directory",
    "fetched": "List of {date}, refreshed from the public directory",
}


class ServerBox(QWidget):
    """An editable combo box of public servers plus a "Refresh list" button.
    :meth:`text` is what the user typed or chose (the host); choosing an
    entry emits :attr:`chosen` with the core.chat_servers.ServerEntry, so the
    editor can fill the port, TLS or the user id as well."""

    chosen = pyqtSignal(object)

    def __init__(self, protocol: str, value: str = "", parent=None, *, load=None, refresh=None,
                 placeholder: str = "") -> None:
        super().__init__(parent)
        self.protocol = protocol
        self._load = load or S.load
        self._refresh = refresh or S.refresh
        self._typed = value
        self._busy = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(2)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        self.combo = QComboBox()
        self.combo.setEditable(True)
        self.combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.combo.setMaxVisibleItems(20)
        self.combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.combo.setMinimumContentsLength(28)
        self.combo.lineEdit().setPlaceholderText(placeholder)
        self.combo.lineEdit().textEdited.connect(self._edited)
        self.combo.activated.connect(self._activated)
        row.addWidget(self.combo, 1)
        self.refresh_button = QToolButton()
        self.refresh_button.setIcon(icon("refresh"))
        self.refresh_button.setText(tr("Refresh list"))
        self.refresh_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.refresh_button.setToolTip(tr("Fetch the list of public servers from the public directory "
                                          "(through the proxy of Settings → Network & Proxy)"))
        self.refresh_button.clicked.connect(self.refresh)
        row.addWidget(self.refresh_button)
        outer.addLayout(row)
        self.info = QLabel()
        self.info.setTextFormat(Qt.TextFormat.PlainText)
        self.info.setProperty("role", "muted")
        self.info.setWordWrap(True)
        outer.addWidget(self.info)
        self.entries: list[S.ServerEntry] = []
        self.fill(self._load(protocol))
        self.set_text(value)

    # -- the value ----------------------------------------------------------------------
    def text(self) -> str:
        return self.combo.currentText()

    def set_text(self, value: str) -> None:
        self._typed = value
        self.combo.setEditText(value)
        if value.startswith("@"):
            self.combo.lineEdit().setCursorPosition(0)

    def _edited(self, text: str) -> None:
        self._typed = text

    def _activated(self, index: int) -> None:
        entry = self.combo.itemData(index)
        # the combo put the item's label into the line; the editor puts the
        # host (or the user id on the server) there
        self.combo.setEditText(self._typed)
        if isinstance(entry, S.ServerEntry):
            self.chosen.emit(entry)

    # -- the list -----------------------------------------------------------------------
    def fill(self, server_list: S.ServerList) -> None:
        text = self.combo.currentText()
        self.entries = list(server_list.entries)
        self.combo.blockSignals(True)
        try:
            self.combo.clear()
            for entry in self.entries:
                self.combo.addItem(entry.label(), entry)
                self.combo.setItemData(self.combo.count() - 1, entry.source or entry.host,
                                       Qt.ItemDataRole.ToolTipRole)
            self.combo.setCurrentIndex(-1)
            self.combo.setEditText(text)
        finally:
            self.combo.blockSignals(False)
        # the drop-down as wide as its longest line (within reason), not the field
        metrics = self.combo.view().fontMetrics()
        widest = max((metrics.horizontalAdvance(e.label()) for e in self.entries), default=0)
        self.combo.view().setMinimumWidth(min(widest + 40, 760))
        if self.entries:
            template = ORIGIN_TEXT.get(server_list.origin, ORIGIN_TEXT["bundled"])
            self.info.setText(tr(template).format(date=server_list.date or "?") + " - "
                              + tr("{n} servers; or type your own.").format(n=len(self.entries)))
        else:
            self.info.setText(tr("No list of public servers – type the server."))

    def refresh(self) -> None:
        """Fetch the directories on a worker thread; the answer (or the
        problem) comes back on the GUI thread."""
        if self._busy:
            return
        self._busy = True
        self.refresh_button.setEnabled(False)
        self.info.setText(tr("Fetching the list of public servers…"))
        done = GuiCall(self._refreshed)
        protocol, fetch = self.protocol, self._refresh

        def work() -> None:
            try:
                result = fetch(protocol)
            except S.ServerListError as exc:
                result = exc
            except Exception as exc:  # noqa: BLE001 - reported, never raised on a worker
                log.warning("Chat server list refresh failed", exc_info=True)
                result = S.ServerListError(str(exc) or type(exc).__name__)
            done(result)

        threading.Thread(target=work, name=f"chat-servers-{protocol}", daemon=True).start()

    def _refreshed(self, result) -> None:
        self._busy = False
        self.refresh_button.setEnabled(True)
        if isinstance(result, S.ServerList):
            self.fill(result)
            return
        # keep what is shown (the snapshot or the last refresh)
        current = self._load(self.protocol)
        self.fill(current)
        self.info.setText(tr("The list could not be refreshed ({problem}); showing the {kind}.").format(
            problem=str(result)[:300],
            kind=tr("list shipped with axross") if current.origin == "bundled" else tr("last refreshed list")))
