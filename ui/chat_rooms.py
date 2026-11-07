"""The public channel / room list of the chat panel (the panel on its right
side): the server's list - IRC ``LIST``, the Matrix room directory, the
rooms of an XMPP server's group chat service - with a filter field; a
double click joins.

Big lists stay responsive: what the client sends arrives in batches
(core.chat.ROOM_BATCH) and is appended to the view as it comes, matching
the filter; a new filter is applied once typing pauses; the list is capped
(core.chat.MAX_ROOM_LIST). Names and topics come from the server: they are
plain-text cells of a table model, never markup.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core import chat as C
from core.i18n import tr
from ui.icon_provider import icon

log = logging.getLogger(__name__)

COL_NAME, COL_USERS, COL_TOPIC = range(3)
#: Milliseconds the filter waits for typing to pause.
FILTER_DELAY_MS = 200


class RoomModel(QAbstractTableModel):
    """The rooms of one account's list; :meth:`set_filter` shows those whose
    name, title or topic contains the text (case-insensitive)."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.rooms: list[C.RoomInfo] = []
        self._keys: list[str] = []      # lowered "name title topic" per room
        self.shown: list[int] = []      # indexes into rooms
        self.text = ""
        self.request_id = 0
        self.loading = False
        self.problem = ""
        self._sort = (COL_USERS, Qt.SortOrder.DescendingOrder)

    # -- filling ------------------------------------------------------------------------
    def reset(self, request_id: int) -> None:
        self.beginResetModel()
        self.rooms, self._keys, self.shown = [], [], []
        self.request_id, self.loading, self.problem = request_id, True, ""
        self.endResetModel()

    def add(self, rooms: list[C.RoomInfo]) -> None:
        """Append a batch; the matching rooms show at the end at once (the
        list is sorted when it is complete)."""
        room_space = C.MAX_ROOM_LIST - len(self.rooms)
        rooms = rooms[:max(room_space, 0)]
        if not rooms:
            return
        start = len(self.rooms)
        self.rooms.extend(rooms)
        self._keys.extend(f"{r.name}\n{r.title}\n{r.topic}".lower() for r in rooms)
        text = self.text
        new = [i for i in range(start, len(self.rooms)) if not text or text in self._keys[i]]
        if new:
            first = len(self.shown)
            self.beginInsertRows(QModelIndex(), first, first + len(new) - 1)
            self.shown.extend(new)
            self.endInsertRows()

    def finish(self, problem: str) -> None:
        self.loading, self.problem = False, problem
        self.sort(*self._sort)

    def set_filter(self, text: str) -> None:
        self.text = text.strip().lower()
        self.beginResetModel()
        text = self.text
        self.shown = [i for i, key in enumerate(self._keys) if not text or text in key]
        self._sort_shown()
        self.endResetModel()

    # -- the table ----------------------------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802 - Qt override
        return 0 if parent.isValid() else len(self.shown)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802 - Qt override
        return 0 if parent.isValid() else 3

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return (tr("Name"), tr("Users"), tr("Topic"))[section]
        return None

    def room(self, row: int) -> C.RoomInfo | None:
        return self.rooms[self.shown[row]] if 0 <= row < len(self.shown) else None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        room = self.room(index.row()) if index.isValid() else None
        if room is None:
            return None
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == COL_NAME:
                return room.title if room.title and room.title != room.name else room.name
            if col == COL_USERS:
                return str(room.users) if room.users >= 0 else ""
            return room.topic
        if role == Qt.ItemDataRole.ToolTipRole:
            # plain text: a tooltip that looks like markup would be rendered
            return Qt.convertFromPlainText(room.name + (f"\n{room.title}" if room.title else "")
                                           + (f"\n\n{room.topic}" if room.topic else ""))
        if role == Qt.ItemDataRole.TextAlignmentRole and col == COL_USERS:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        self._sort = (column, order)
        self.layoutAboutToBeChanged.emit()
        self._sort_shown()
        self.layoutChanged.emit()

    def _sort_shown(self) -> None:
        column, order = self._sort
        rooms = self.rooms
        if column == COL_USERS:
            key = lambda i: rooms[i].users  # noqa: E731
        elif column == COL_TOPIC:
            key = lambda i: rooms[i].topic.lower()  # noqa: E731
        else:
            key = lambda i: (rooms[i].title or rooms[i].name).lower()  # noqa: E731
        self.shown.sort(key=key, reverse=order == Qt.SortOrder.DescendingOrder)


class RoomListPanel(QWidget):
    """The list of the current account. :attr:`join_requested` carries the
    name to join (what ChatClient.join takes)."""

    join_requested = pyqtSignal(str)

    def __init__(self, label: str = "Room List", parent=None) -> None:
        super().__init__(parent)
        self.label = label
        self.client: C.ChatClient | None = None
        self.models: dict[str, RoomModel] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        title = QLabel(tr(label))
        title.setTextFormat(Qt.TextFormat.PlainText)
        font = title.font()
        font.setBold(True)
        title.setFont(font)
        head.addWidget(title, 1)
        self.refresh_button = QPushButton(icon("refresh"), tr("Refresh"))
        self.refresh_button.setToolTip(tr("Ask the server for its list again (where the server can "
                                          "search, the filter is sent along)"))
        self.refresh_button.clicked.connect(self.refresh)
        head.addWidget(self.refresh_button)
        layout.addLayout(head)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(tr("Filter by name or topic"))
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(lambda _t: self._filter_timer.start())
        layout.addWidget(self.filter)
        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(FILTER_DELAY_MS)
        self._filter_timer.timeout.connect(self._apply_filter)
        self.table = QTableView()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setWordWrap(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(self.table.fontMetrics().height() + 6)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.doubleClicked.connect(self._double_clicked)
        layout.addWidget(self.table, 1)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self._empty = RoomModel(self)
        self.table.setModel(self._empty)
        self._update_status()

    # -- which account ------------------------------------------------------------------
    def model_for(self, account_id: str) -> RoomModel:
        model = self.models.get(account_id)
        if model is None:
            model = RoomModel(self)
            self.models[account_id] = model
        return model

    def show_client(self, client: C.ChatClient | None) -> None:
        """Show the list of *client*'s account (asked for on first show when
        the panel is visible and the account online)."""
        self.client = client
        if client is None:
            self.table.setModel(self._empty)
        else:
            model = self.model_for(client.account.account_id)
            if model.text != self.filter.text().strip().lower():
                model.set_filter(self.filter.text())
            if self.table.model() is not model:
                self.table.setModel(model)
                self.table.sortByColumn(*model._sort)
            if self.isVisible() and not model.rooms and not model.loading and not model.problem \
                    and client.state == C.STATE_ONLINE:
                self.refresh()
        self._update_status()

    def forget(self, account_id: str) -> None:
        model = self.models.pop(account_id, None)
        if model is not None and self.table.model() is model:
            self.table.setModel(self._empty)
            self.client = None
            self._update_status()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        if self.client is not None:
            self.show_client(self.client)

    # -- asking --------------------------------------------------------------------------
    def refresh(self) -> None:
        client = self.client
        if client is None:
            return
        if client.state != C.STATE_ONLINE:
            self.status.setText(tr("Connect first - the list comes from the server."))
            return
        model = self.model_for(client.account.account_id)
        # the id is the client's next one: batches of an older request are dropped
        model.reset(client._room_list_id + 1)
        rid = client.request_room_list(self.filter.text())
        model.request_id = rid
        self._update_status()

    # -- from the client (GUI thread) ------------------------------------------------------
    def add_batch(self, account_id: str, rid: int, rooms) -> None:
        if not isinstance(rooms, list):
            return
        model = self.model_for(account_id)
        if rid > model.request_id:
            model.reset(rid)  # a newer list - one asked for by hand (IRC /quote LIST)
        elif rid != model.request_id:
            return  # an older request's
        model.add(rooms)
        if self.table.model() is model:
            self._update_status()

    def list_done(self, account_id: str, rid: int, problem: str) -> None:
        model = self.models.get(account_id)
        if model is None or rid != model.request_id:
            return
        model.finish(problem)
        if self.table.model() is model:
            self._update_status()

    # -- the view ------------------------------------------------------------------------
    def _apply_filter(self) -> None:
        model = self.table.model()
        if isinstance(model, RoomModel):
            model.set_filter(self.filter.text())
            self._update_status()

    def _double_clicked(self, index) -> None:
        model = self.table.model()
        room = model.room(index.row()) if isinstance(model, RoomModel) else None
        if room is not None:
            self.join_requested.emit(room.name)

    def _update_status(self) -> None:
        model = self.table.model()
        online = self.client is not None and self.client.state == C.STATE_ONLINE
        self.refresh_button.setEnabled(online)
        if self.client is None:
            text = tr("Choose an account.")
        elif not isinstance(model, RoomModel) or (not model.rooms and not model.loading and not model.problem):
            text = tr("Refresh asks the server for its list.") if online else tr("Not connected.")
        else:
            total, shown = len(model.rooms), len(model.shown)
            text = tr("{shown} of {total} shown").format(shown=shown, total=total) if model.text \
                else tr("{total} in the list").format(total=total)
            if model.loading:
                text = tr("Loading…") + " " + text
            elif model.problem:
                text += " - " + tr(model.problem)
            if not model.loading and total:
                text += " - " + tr("double-click joins")
        self.status.setText(text)
