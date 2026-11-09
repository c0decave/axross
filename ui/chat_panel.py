"""The panel of the chat extensions (IRC, Matrix, XMPP): accounts and their
conversations on the left, the open conversation on the right, any
conversation detachable into a window of its own.

It knows protocols only through core.chat (Protocol, ChatClient): one panel
serves one protocol; the extension passes its Protocol.

What arrives is shown as plain text (core.chat.clean_text): no HTML of the
sender, no images, no link previews. A web address becomes a link that is
opened only after the user saw the whole address and agreed.
"""

from __future__ import annotations

import html
import logging
import re
import time
import unicodedata
import zlib

from PyQt6 import sip
from PyQt6.QtCore import QEvent, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTextBrowser,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import chat as C
from core.i18n import tr
from core.remote_name import sanitize_for_display
from core.thread_relay import GuiCall
from ui.chat_rooms import RoomListPanel
from ui.close_corner import add_close_corner
from ui.icon_provider import has_icon, icon, set_window_icon

log = logging.getLogger(__name__)

ROLE_ACCOUNT = Qt.ItemDataRole.UserRole
ROLE_KEY = Qt.ItemDataRole.UserRole + 1

#: Sender name colours (mid tones, readable on light and dark backgrounds).
NICK_COLOURS = ("#c0392b", "#2471a3", "#1e8449", "#9a7d0a", "#7d3c98", "#ca6f1e", "#138d75",
                "#b03a2e", "#2e86c1", "#28b463", "#af601a", "#6c3483")
STATE_TEXT = {
    C.STATE_OFFLINE: "offline",
    C.STATE_CONNECTING: "connecting…",
    C.STATE_ONLINE: "online",
    C.STATE_ERROR: "error",
}
ENC_SHORT = {
    C.ENC_NONE: "Not encrypted",
    C.ENC_TRANSPORT: "TLS to the server",
    C.ENC_E2E_UNTRUSTED: "End-to-end (unverified keys)",
    C.ENC_E2E: "End-to-end, verified",
    C.ENC_FAILED: "Not decryptable",
}
_URL = re.compile(r"\bhttps?://[^\s<>\"'`]{1,2000}", re.I)


def nick_colour(name: str) -> str:
    return NICK_COLOURS[zlib.crc32(name.lower().encode("utf-8")) % len(NICK_COLOURS)]


def linkify(text: str) -> str:
    """*text* (raw, from the network) escaped as HTML, its web addresses as
    links. The addresses are found in the raw text, so an escaped "&gt;"
    never becomes part of one."""
    out, pos = [], 0
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        out.append(html.escape(text[pos:m.start()]))
        safe = html.escape(url, quote=True)
        out.append(f'<a href="{safe}">{safe}</a>')
        pos = m.start() + len(url)
    out.append(html.escape(text[pos:]))
    return "".join(out)


def _label_scripts(label: str) -> set[str]:
    """The scripts (LATIN, CYRILLIC, GREEK ...) of the letters in *label*."""
    scripts = set()
    for char in label:
        if char.isalpha():
            name = unicodedata.name(char, "")
            scripts.add(name.split(" ", 1)[0] if name else "?")
    return scripts


def host_warnings(ace_host: str) -> list[str]:
    """Warnings for a link's host in its ASCII (punycode) form: an
    internationalised name (``xn--``), which can imitate another one, and
    one whose labels mix letters of several scripts (a Cyrillic "а" in
    "аpple.com"). Like the mail view's link notes."""
    labels = [label for label in ace_host.lower().split(".") if label]
    shown = []
    for label in labels:
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except (UnicodeError, ValueError):
                label = "\ufffd"
        shown.append(label)
    warnings = []
    if any(label.startswith("xn--") for label in labels) or not ace_host.isascii():
        warnings.append(tr("Warning: the name uses non-ASCII letters ({name}) and can "
                           "imitate another address.").format(
                               name=sanitize_for_display(".".join(shown))))
    mixed = sorted(set().union(*(s for s in map(_label_scripts, shown) if len(s) > 1)))
    if mixed:
        warnings.append(tr("Warning: the name mixes letters of several scripts ({scripts}) - "
                           "a typical look-alike.").format(scripts=", ".join(mixed)))
    return warnings


def link_question(url: QUrl) -> str:
    """The Open Link question for *url*: the address percent-encoded, the
    host in its ASCII form on a line of its own, then any warning.
    ``url.toString()`` decoded the host, so ``xn--pple-43d.com`` showed as
    "аpple.com" with a Cyrillic "а" - the mail view's way, shared."""
    encoded = QUrl.ComponentFormattingOption.FullyEncoded
    text = sanitize_for_display(url.toString(encoded))
    ace = sanitize_for_display(url.host(encoded))
    lines = [tr("Open this address in the browser?"), "", text, "",
             tr("Host: {host}").format(host=ace or tr("(no host)"))]
    warnings = host_warnings(ace)
    if warnings:
        lines += ["", *warnings]
    return "\n".join(lines)


def message_html(message: C.ChatMessage, conversation_encryption: str = "") -> str:
    """One message as a line of HTML; everything from the network escaped."""
    stamp = time.strftime("%H:%M", time.localtime(message.timestamp))
    text = linkify(message.text).replace("\n", "<br>")
    sender = html.escape(message.sender)
    colour = nick_colour(message.sender)
    mark = ""
    if message.encryption == C.ENC_FAILED:
        mark = f' <span style="color:#c0392b">[{html.escape(tr("not decryptable"))}]</span>'
    elif message.encryption == C.ENC_E2E_UNTRUSTED and conversation_encryption != C.ENC_E2E_UNTRUSTED:
        mark = f' <span style="color:#ca6f1e">[{html.escape(tr("unverified key"))}]</span>'
    elif conversation_encryption in (C.ENC_E2E, C.ENC_E2E_UNTRUSTED) and message.encryption in (
            C.ENC_TRANSPORT, C.ENC_NONE) and message.kind in (C.KIND_MESSAGE, C.KIND_ACTION):
        mark = f' <span style="color:#c0392b">[{html.escape(tr("not end-to-end encrypted"))}]</span>'
    if message.note:
        mark += f' <span style="color:#7f8c8d">({html.escape(message.note)})</span>'
    time_html = f'<span style="color:#7f8c8d">{stamp}</span> '
    if message.kind == C.KIND_ACTION:
        body = f'<i>* <span style="color:{colour}">{sender}</span> {text}</i>'
    elif message.kind == C.KIND_NOTICE:
        body = f'<span style="color:{colour}">-{sender}-</span> {text}'
    elif message.kind == C.KIND_SYSTEM:
        body = f'<span style="color:#7f8c8d"><i>{text}</i></span>'
    elif message.kind == C.KIND_ERROR:
        body = f'<span style="color:#c0392b">{text}</span>'
    else:
        weight = "bold" if message.outgoing else "normal"
        body = f'<span style="color:{colour};font-weight:{weight}">{sender}</span>: {text}'
    return time_html + body + mark


# --- the input line ----------------------------------------------------------------

class ChatInput(QLineEdit):
    """Enter sends; Up/Down walk the history; Tab completes a name or a command."""

    submitted = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setMaxLength(C.MAX_TEXT)
        self._history: list[str] = []
        self._index = 0
        self.names: callable = lambda: []
        self.commands: tuple[str, ...] = ()
        self._completion: tuple[str, list[str], int] | None = None
        self.returnPressed.connect(self._submit)

    def _submit(self) -> None:
        text = self.text()
        if not text.strip():
            return
        self._history.append(text)
        self._history = self._history[-200:]
        self._index = len(self._history)
        self.clear()
        self.submitted.emit(text)

    def event(self, event) -> bool:
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            self.complete()
            return True
        return super().event(event)

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key != Qt.Key.Key_Tab:
            self._completion = None
        if key == Qt.Key.Key_Up and self._history:
            self._index = max(0, self._index - 1)
            self.setText(self._history[self._index])
            return
        if key == Qt.Key.Key_Down and self._history:
            self._index = min(len(self._history), self._index + 1)
            self.setText(self._history[self._index] if self._index < len(self._history) else "")
            return
        super().keyPressEvent(event)

    def complete(self) -> None:
        text, pos = self.text(), self.cursorPosition()
        if self._completion is None:
            start = text.rfind(" ", 0, pos) + 1
            word = text[start:pos]
            if not word:
                return
            if start == 0 and word.startswith("/"):
                pool = [f"/{c}" for c in self.commands]
            else:
                pool = list(self.names())
            matches = sorted({n for n in pool if n.lower().startswith(word.lower())}, key=str.lower)
            if not matches:
                return
            self._completion = (text[:start] + "\x00" + text[pos:], matches, -1)
        template, matches, index = self._completion
        index = (index + 1) % len(matches)
        self._completion = (template, matches, index)
        before, after = template.split("\x00", 1)
        word = matches[index]
        if not before and not word.startswith("/"):
            word += ": "
        elif not after:
            word += " "
        self.setText(before + word + after)
        self.setCursorPosition(len(before + word))


# --- one conversation ----------------------------------------------------------------

class ConversationView(QWidget):
    """Topic, messages, members and the input line of one conversation."""

    security_requested = pyqtSignal()
    detach_requested = pyqtSignal()
    open_direct_requested = pyqtSignal(str)

    def __init__(self, client: C.ChatClient, key: str, parent=None) -> None:
        super().__init__(parent)
        self.client, self.key = client, key
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self.title = QLabel()
        bold = QFont(self.title.font())
        bold.setBold(True)
        self.title.setFont(bold)
        self.title.setTextFormat(Qt.TextFormat.PlainText)
        head.addWidget(self.title)
        self.topic = QLabel()
        self.topic.setTextFormat(Qt.TextFormat.PlainText)
        self.topic.setWordWrap(False)
        self.topic.setMinimumWidth(40)
        head.addWidget(self.topic, 1)
        self.security = QToolButton()
        self.security.setAutoRaise(True)
        self.security.clicked.connect(self.security_requested)
        head.addWidget(self.security)
        self.detach = QToolButton()
        self.detach.setText(tr("Window"))
        self.detach.setToolTip(tr("Open this conversation in a window of its own"))
        self.detach.setAutoRaise(True)
        self.detach.clicked.connect(self.detach_requested)
        head.addWidget(self.detach)
        layout.addLayout(head)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.view = QTextBrowser()
        self.view.setOpenLinks(False)
        self.view.setOpenExternalLinks(False)
        self.view.anchorClicked.connect(self._link)
        self.view.document().setMaximumBlockCount(C.HISTORY_LIMIT)
        self.view.setPlaceholderText(tr("No messages yet."))
        split.addWidget(self.view)
        self.members = QListWidget()
        self.members.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.members.itemDoubleClicked.connect(
            lambda item: self.open_direct_requested.emit(item.data(ROLE_KEY) or ""))
        split.addWidget(self.members)
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 1)
        layout.addWidget(split, 1)
        self.input = ChatInput()
        self.input.commands = client.commands
        self.input.names = self._names
        self.input.submitted.connect(lambda text: self.client.send(self.key, text))
        layout.addWidget(self.input)
        self._rendered = 0
        self.refresh()
        for message in client.history(key):
            self.add_message(message)

    def _names(self) -> list[str]:
        conv = self.client.conversation(self.key)
        return [m.name for m in conv.members.values()] if conv else []

    def refresh(self) -> None:
        conv = self.client.conversation(self.key)
        if conv is None:
            return
        self.title.setText(conv.title)
        topic = conv.topic.replace("\n", " ")
        self.topic.setText(topic[:300])
        # Plain text as rich text (escaped): a topic is the server's text,
        # never markup Qt renders (as ui/chat_rooms.py shows room names).
        self.topic.setToolTip(Qt.convertFromPlainText(topic) if topic else "")
        self.security.setText(tr(ENC_SHORT.get(conv.encryption, conv.encryption)))
        from ui.security_badge import security_icon, tooltip_html

        info = self.client.conversation_security(self.key)
        self.security.setIcon(security_icon(info))
        self.security.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.security.setToolTip(tooltip_html(info))
        colour = {C.ENC_E2E: "#1e8449", C.ENC_E2E_UNTRUSTED: "#ca6f1e", C.ENC_FAILED: "#c0392b",
                  C.ENC_NONE: "#c0392b"}.get(conv.encryption, "")
        self.security.setStyleSheet(f"color:{colour}" if colour else "")
        show_members = conv.kind == C.CONV_CHANNEL
        self.members.setVisible(show_members)
        if show_members:
            self._fill_members(conv)
        self.input.setEnabled(conv.joined or conv.kind != C.CONV_CHANNEL)
        self.input.setPlaceholderText(tr("Message") if conv.kind != C.CONV_SERVER
                                      else tr("/command - /help lists them"))

    def _fill_members(self, conv: C.Conversation) -> None:
        def rank(member: C.Member):
            return (0 if member.role else 1, member.role[:1], member.name.lower())
        members = sorted(conv.members.values(), key=rank)[:5000]
        self.members.setUpdatesEnabled(False)
        self.members.clear()
        for member in members:
            item = QListWidgetItem(f"{member.role[:1]}{member.display or member.name}")
            item.setData(ROLE_KEY, member.name)
            if member.away:
                item.setForeground(QColor("#7f8c8d"))
            self.members.addItem(item)
        self.members.setUpdatesEnabled(True)

    def add_message(self, message: C.ChatMessage) -> None:
        conv = self.client.conversation(self.key)
        enc = conv.encryption if conv else ""
        bar = self.view.verticalScrollBar()
        at_end = bar.value() >= bar.maximum() - 4
        cursor = QTextCursor(self.view.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        if self._rendered:
            cursor.insertBlock()
        cursor.insertHtml(message_html(message, enc))
        self._rendered += 1
        if at_end:
            bar.setValue(bar.maximum())

    def _link(self, url: QUrl) -> None:
        if url.scheme().lower() not in ("http", "https"):
            return
        answer = QMessageBox.question(
            self, tr("Open Link"), link_question(url),
            QMessageBox.StandardButton.Open | QMessageBox.StandardButton.Cancel)
        if answer == QMessageBox.StandardButton.Open:
            from core.desktop_open import open_url

            open_url(url)


class ChatWindow(QDialog):
    """A conversation in a window of its own (not modal), with the corner
    buttons of every axross window; closing it - [x], Esc, the window
    manager - puts the conversation back into the panel."""

    closed = pyqtSignal(object)

    def __init__(self, view: ConversationView, title: str) -> None:
        super().__init__(None)
        set_window_icon(self, "chat")
        self.setModal(False)
        self.view = view
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        layout.addWidget(view)
        # QStackedWidget.removeWidget hid the view: shown here, or the
        # window stayed empty.
        view.show()
        add_close_corner(self)
        self.resize(640, 480)

    def reject(self) -> None:
        self.close()

    def closeEvent(self, event) -> None:
        self.closed.emit(self)
        super().closeEvent(event)


# --- accounts ------------------------------------------------------------------------

def protocol_icon(protocol: C.Protocol) -> str:
    """The icon of *protocol*'s own network (irc, matrix, xmpp), so its
    windows tell themselves apart from another network's; the generic
    bubble for a protocol without one."""
    return protocol.name if has_icon(protocol.name) else "chat"


class AccountEditor(QDialog):
    """The fields of one account, from its protocol's FieldSpecs."""

    def __init__(self, protocol: C.Protocol, account: C.Account | None, parent=None) -> None:
        super().__init__(parent)
        set_window_icon(self, protocol_icon(protocol))
        self.protocol = protocol
        self.account = account or C.Account(protocol=protocol.name, name="")
        self.setWindowTitle(tr("{protocol} Account").format(protocol=protocol.title))
        form = QFormLayout(self)
        self.name = QLineEdit(self.account.name)
        self.name.setMaxLength(100)
        form.addRow(tr("Name"), self.name)
        self.widgets: dict[str, QWidget] = {}
        for spec in protocol.fields:
            value = self.account.settings.get(spec.key, spec.default)
            if spec.secret:
                value = ""
            widget = self._widget(spec, value)
            self.widgets[spec.key] = widget
            label = tr(spec.label)
            form.addRow(label, widget)
            if spec.help:
                widget.setToolTip(tr(spec.help))
        self.autoconnect = QCheckBox(tr("Connect when axross starts"))
        self.autoconnect.setChecked(self.account.autoconnect)
        form.addRow("", self.autoconnect)
        self.problem = QLabel()
        self.problem.setStyleSheet("color:#c0392b")
        self.problem.setWordWrap(True)
        form.addRow(self.problem)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)
        add_close_corner(self)

    def _widget(self, spec: C.FieldSpec, value) -> QWidget:
        if spec.key == self.protocol.server_field and spec.kind == "text":
            # the public servers in an editable drop-down (core.chat_servers)
            from ui.chat_server_box import ServerBox

            box = ServerBox(self.protocol.name, str(value or ""), self,
                            placeholder=tr(spec.help) if spec.help else "")
            box.chosen.connect(self._server_chosen)
            self.server_box = box
            return box
        if spec.kind == "password":
            w = QLineEdit()
            w.setEchoMode(QLineEdit.EchoMode.Password)
            stored = C.account_secret(self.account, spec.key) if self.account.name else None
            w.setPlaceholderText(tr("stored - leave empty to keep") if stored else "")
            return w
        if spec.kind == "int":
            w = QSpinBox()
            w.setRange(0, 65535)
            try:
                w.setValue(int(value))
            except (TypeError, ValueError):
                w.setValue(int(spec.default or 0))
            return w
        if spec.kind == "bool":
            w = QCheckBox()
            w.setChecked(value is True)
            return w
        if spec.kind == "choice":
            w = QComboBox()
            for data, label in spec.choices:
                w.addItem(tr(label), data)
            index = w.findData(value)
            w.setCurrentIndex(max(index, 0))
            return w
        if spec.kind == "lines":
            w = QPlainTextEdit()
            w.setPlainText("\n".join(value) if isinstance(value, list) else str(value or ""))
            w.setFixedHeight(70)
            return w
        if spec.kind == "file":
            box = QWidget()
            row = QHBoxLayout(box)
            row.setContentsMargins(0, 0, 0, 0)
            edit = QLineEdit(str(value or ""))
            pick = QPushButton(tr("Choose…"))
            pick.clicked.connect(lambda: self._pick_file(edit))
            row.addWidget(edit, 1)
            row.addWidget(pick)
            box.edit = edit
            return box
        w = QLineEdit(str(value or ""))
        w.setPlaceholderText(tr(spec.help) if spec.help else "")
        return w

    def _server_chosen(self, entry) -> None:
        """A public server was chosen: fill in what it implies (port, TLS,
        the user id on its domain) - every field stays editable."""
        if self.protocol.apply_server is None:
            return
        settings, _secrets = self.values()
        try:
            updates = self.protocol.apply_server(entry, settings)
        except Exception:  # noqa: BLE001 - a malformed entry leaves the form as it is
            log.warning("Applying the server %s failed", entry, exc_info=True)
            return
        for key, value in updates.items():
            self.set_value(key, value)

    def set_value(self, key: str, value) -> None:
        """Put *value* into the field *key* (as its widget takes it)."""
        w = self.widgets.get(key)
        if w is None:
            return
        if hasattr(w, "set_text"):
            w.set_text(str(value))
        elif isinstance(w, QSpinBox):
            w.setValue(int(value))
        elif isinstance(w, QCheckBox):
            w.setChecked(value is True)
        elif isinstance(w, QComboBox):
            index = w.findData(value)
            if index >= 0:
                w.setCurrentIndex(index)
        elif isinstance(w, QLineEdit):
            w.setText(str(value))
            if str(value).startswith("@"):
                w.setCursorPosition(0)

    def _pick_file(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, tr("Choose File"), edit.text())
        if path:
            edit.setText(path)

    def values(self) -> tuple[dict, dict]:
        """(settings, secrets) as entered; a secret left empty is not in secrets."""
        settings, secrets_ = {}, {}
        for spec in self.protocol.fields:
            w = self.widgets[spec.key]
            if spec.kind == "password":
                if w.text():
                    secrets_[spec.key] = w.text()
                continue
            if spec.kind == "int":
                value = w.value()
            elif spec.kind == "bool":
                value = w.isChecked()
            elif spec.kind == "choice":
                value = w.currentData()
            elif spec.kind == "lines":
                value = [l.strip() for l in w.toPlainText().splitlines() if l.strip()][:500]
            elif spec.kind == "file":
                value = w.edit.text().strip()
            else:
                value = w.text().strip()
            settings[spec.key] = value
        return settings, secrets_

    def _accept(self) -> None:
        settings, secrets_ = self.values()
        name = self.name.text().strip()
        problem = None if name else tr("The account needs a name.")
        problem = problem or self.protocol.validate(settings)
        for spec in self.protocol.fields:
            if spec.required and not spec.secret and not settings.get(spec.key):
                problem = problem or tr("{field} is missing.").format(field=tr(spec.label))
        if problem:
            self.problem.setText(tr(problem))
            return
        self.account.name = C.clean_name(name, 100)
        self.account.settings = {**self.account.settings, **settings}
        self.account.autoconnect = self.autoconnect.isChecked()
        kept_only_now = [k for k, v in secrets_.items() if not C.store_account_secret(self.account, k, v)]
        if kept_only_now:
            QMessageBox.warning(self, tr("Keyring"), tr(
                "The keyring cannot store passwords right now; they are kept until axross "
                "closes and asked again next time."))
        self.accept()


# --- the panel ---------------------------------------------------------------------------

class ChatPanel(QWidget):
    """Accounts and conversations of one protocol."""

    #: something worth a status bar message (a highlight while the panel is hidden)
    attention = pyqtSignal(str)

    def __init__(self, protocol: C.Protocol, parent=None, *, accounts_path=None) -> None:
        super().__init__(parent)
        self.protocol = protocol
        self._accounts_path = accounts_path
        self.clients: dict[str, C.ChatClient] = {}
        self.views: dict[tuple[str, str], ConversationView] = {}
        self.windows: dict[tuple[str, str], ChatWindow] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        bar = QHBoxLayout()
        self.accounts_button = QPushButton(tr("Accounts…"))
        self.accounts_button.clicked.connect(self.edit_accounts)
        self.connect_button = QPushButton(tr("Connect"))
        self.connect_button.clicked.connect(self._toggle_connection)
        self.join_button = QPushButton(tr(protocol.join_label))
        self.join_button.clicked.connect(self._join)
        self.direct_button = QPushButton(tr(protocol.direct_label))
        self.direct_button.clicked.connect(self._direct)
        self.rooms_button = QPushButton(icon("chat-rooms"), tr(protocol.room_list_label))
        self.rooms_button.setCheckable(True)
        self.rooms_button.setToolTip(tr("Show the server's public list on the right; a double click joins"))
        self.rooms_button.toggled.connect(self._show_rooms)
        for b in (self.accounts_button, self.connect_button, self.join_button, self.direct_button):
            bar.addWidget(b)
        bar.addStretch(1)
        bar.addWidget(self.rooms_button)
        layout.addLayout(bar)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        self.tree.currentItemChanged.connect(self._current_changed)
        split.addWidget(self.tree)
        self.stack = QStackedWidget()
        self.empty = QLabel(tr("Add an account with Accounts…, then connect."))
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setWordWrap(True)
        self.stack.addWidget(self.empty)
        split.addWidget(self.stack)
        # the server's public channel / room list (ui/chat_rooms.py)
        self.rooms = RoomListPanel(protocol.room_list_label)
        self.rooms.join_requested.connect(self._join_listed)
        self.rooms.setVisible(False)
        split.addWidget(self.rooms)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 4)
        split.setStretchFactor(2, 2)
        self.split = split
        layout.addWidget(split, 1)
        self.status = QLabel()
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.status)
        self._account_items: dict[str, QTreeWidgetItem] = {}
        self._conv_items: dict[tuple[str, str], QTreeWidgetItem] = {}
        for account in C.load_accounts(self._accounts_path):
            if account.protocol == protocol.name:
                self._add_client(account)
        self._update_buttons()

    # -- accounts -----------------------------------------------------------------
    def all_accounts(self) -> list[C.Account]:
        return [c.account for c in self.clients.values()]

    def save_accounts(self) -> None:
        others = [a for a in C.load_accounts(self._accounts_path) if a.protocol != self.protocol.name]
        C.save_accounts(others + self.all_accounts(), self._accounts_path)

    def _add_client(self, account: C.Account) -> C.ChatClient:
        client = self.protocol.make_client(account)
        # The clients report from their asyncio thread: the save runs in the
        # GUI thread, which owns self.clients and writes chat.json too.
        save_in_gui = GuiCall(self.save_accounts)
        client.on_account_changed = lambda _a: save_in_gui()
        self.clients[account.account_id] = client
        item = QTreeWidgetItem([account.name])
        item.setData(0, ROLE_ACCOUNT, account.account_id)
        item.setData(0, ROLE_KEY, client.server_key)
        self.tree.addTopLevelItem(item)
        item.setExpanded(True)
        self._account_items[account.account_id] = item
        self._conv_items[(account.account_id, client.server_key)] = item
        client.state_changed.connect(lambda s, d, aid=account.account_id: self._state(aid, s, d))
        client.conversation_changed.connect(lambda k, aid=account.account_id: self._conversation(aid, k))
        client.conversation_removed.connect(lambda k, aid=account.account_id: self._removed(aid, k))
        client.message_added.connect(lambda m, aid=account.account_id: self._message(aid, m))
        client.request.connect(lambda r, aid=account.account_id: self._request(aid, r))
        client.room_list_batch.connect(lambda rid, rooms, aid=account.account_id: self._rooms_batch(aid, rid, rooms))
        client.room_list_done.connect(lambda rid, problem, aid=account.account_id: self._rooms_done(aid, rid, problem))
        for conv in client.conversations():
            self._conversation(account.account_id, conv.key)
        self._state(account.account_id, client.state, client.detail)
        return client

    def show_missing(self, text: str, open_features=None, key: str = "extra:chat") -> None:
        """*text* (what this network lacks here) where the conversations
        go, with a link that opens Help > Features… at *key*, the feature
        that installs it - before, a pip command to type was the only way.
        Without *open_features* (no window to ask) the text alone."""
        if open_features is None:
            self.empty.setText(text)
            return
        self.empty.setTextFormat(Qt.TextFormat.RichText)
        self.empty.setText(f'{html.escape(text)}<br><br><a href="{html.escape(key)}">'
                           f'{html.escape(tr("Show in Features…"))}</a>')
        self.empty.linkActivated.connect(lambda link: open_features(link))

    def connect_autostart(self) -> None:
        for client in self.clients.values():
            if client.account.autoconnect:
                client.connect_account()

    def edit_accounts(self) -> None:
        dialog = AccountsDialog(self)
        dialog.exec()

    def add_account(self, account: C.Account) -> C.ChatClient:
        client = self._add_client(account)
        self.save_accounts()
        self.tree.setCurrentItem(self._account_items[account.account_id])
        return client

    def remove_account(self, account_id: str) -> None:
        client = self.clients.pop(account_id, None)
        if client is None:
            return
        client.shutdown()
        self.rooms.forget(account_id)
        C.forget_account_secrets(client.account, [f.key for f in self.protocol.fields if f.secret]
                                 + list(getattr(client, "extra_secrets", ())))
        for key in [k for k in self.views if k[0] == account_id]:
            self._drop_view(key)
        item = self._account_items.pop(account_id)
        for key in [k for k in self._conv_items if k[0] == account_id]:
            self._conv_items.pop(key)
        self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
        self.save_accounts()
        self._update_buttons()

    def account_edited(self, account: C.Account) -> None:
        """The account's settings changed: a new client (disconnected) with them."""
        client = self.clients.get(account.account_id)
        if client is None:
            return
        was_online = client.state in (C.STATE_ONLINE, C.STATE_CONNECTING)
        self.remove_account_keep_secrets(account.account_id)
        new = self._add_client(account)
        self.save_accounts()
        if was_online:
            new.connect_account()

    def remove_account_keep_secrets(self, account_id: str) -> None:
        client = self.clients.pop(account_id, None)
        if client is None:
            return
        client.shutdown()
        self.rooms.forget(account_id)
        for key in [k for k in self.views if k[0] == account_id]:
            self._drop_view(key)
        item = self._account_items.pop(account_id)
        for key in [k for k in self._conv_items if k[0] == account_id]:
            self._conv_items.pop(key)
        self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))

    # -- selection -------------------------------------------------------------------
    def current(self) -> tuple[C.ChatClient | None, str]:
        item = self.tree.currentItem()
        if item is None:
            if len(self.clients) == 1:
                client = next(iter(self.clients.values()))
                return client, client.server_key
            return None, ""
        account_id = item.data(0, ROLE_ACCOUNT)
        return self.clients.get(account_id), item.data(0, ROLE_KEY)

    def _current_changed(self, item, _previous) -> None:
        self._update_buttons()
        if item is None:
            self.stack.setCurrentWidget(self.empty)
            return
        account_id, key = item.data(0, ROLE_ACCOUNT), item.data(0, ROLE_KEY)
        self.show_conversation(account_id, key)

    def show_conversation(self, account_id: str, key: str) -> ConversationView | None:
        client = self.clients.get(account_id)
        if client is None or client.conversation(key) is None:
            return None
        view = self.view_for(account_id, key)
        window = self.windows.get((account_id, key))
        if window is not None:
            window.raise_()
            window.activateWindow()
        else:
            self.stack.setCurrentWidget(view)
            view.input.setFocus()
        client.mark_read(key)
        item = self._conv_items.get((account_id, key))
        if item is not None and self.tree.currentItem() is not item:
            self.tree.setCurrentItem(item)
        return view

    def view_for(self, account_id: str, key: str) -> ConversationView:
        view = self.views.get((account_id, key))
        if view is None:
            client = self.clients[account_id]
            view = ConversationView(client, key)
            view.security_requested.connect(lambda: self._security(account_id, key))
            view.detach_requested.connect(lambda: self.detach(account_id, key))
            view.open_direct_requested.connect(lambda name: self._open_direct(account_id, name))
            self.views[(account_id, key)] = view
            self.stack.addWidget(view)
        return view

    def _drop_view(self, key: tuple[str, str]) -> None:
        window = self.windows.pop(key, None)
        if window is not None:
            window.closed.disconnect()
            window.close()
            window.deleteLater()
        view = self.views.pop(key, None)
        if view is not None and not sip.isdeleted(view):
            self.stack.removeWidget(view)
            view.deleteLater()

    def detach(self, account_id: str, key: str) -> None:
        if (account_id, key) in self.windows:
            return
        view = self.view_for(account_id, key)
        client = self.clients[account_id]
        conv = client.conversation(key)
        self.stack.removeWidget(view)
        self.stack.setCurrentWidget(self.empty)
        window = ChatWindow(view, f"{conv.title if conv else key} - {client.account.name}")
        view.detach.setVisible(False)
        window.closed.connect(lambda w, k=(account_id, key): self._window_closed(k))
        self.windows[(account_id, key)] = window
        window.show()

    def _window_closed(self, key: tuple[str, str]) -> None:
        window = self.windows.pop(key, None)
        if window is None:
            return
        view = window.view
        if not sip.isdeleted(view):
            view.setParent(None)
            view.detach.setVisible(True)
            self.stack.addWidget(view)
            current = self.tree.currentItem()
            if current is not None and (current.data(0, ROLE_ACCOUNT), current.data(0, ROLE_KEY)) == key:
                self.stack.setCurrentWidget(view)
        window.deleteLater()

    # -- buttons ------------------------------------------------------------------------
    def _update_buttons(self) -> None:
        client, _ = self.current()
        online = client is not None and client.state == C.STATE_ONLINE
        busy = client is not None and client.state == C.STATE_CONNECTING
        self.connect_button.setEnabled(client is not None)
        self.connect_button.setText(tr("Disconnect") if online or busy else tr("Connect"))
        self.join_button.setEnabled(online)
        self.direct_button.setEnabled(online)
        self.rooms_button.setEnabled(client is not None and client.supports_room_list)
        if self.rooms.client is not client or self.rooms.isVisible():
            self.rooms.show_client(client)
        if client is None:
            self.status.setText(tr("No account.") if not self.clients else "")
        else:
            state = tr(STATE_TEXT.get(client.state, client.state))
            self.status.setText(f"{client.account.name}: {state}" + (f" - {client.detail}" if client.detail else ""))

    def _toggle_connection(self) -> None:
        client, _ = self.current()
        if client is None:
            return
        if client.state in (C.STATE_ONLINE, C.STATE_CONNECTING):
            client.disconnect_account()
        else:
            client.connect_account()
        self._update_buttons()

    def _join(self) -> None:
        client, _ = self.current()
        if client is None:
            return
        text, ok = QInputDialog.getText(self, tr(self.protocol.join_label).rstrip("…"),
                                        tr(self.protocol.join_prompt))
        if ok and text.strip():
            client.join(text)

    def _show_rooms(self, shown: bool) -> None:
        self.rooms.setVisible(shown)
        if shown:
            client, _ = self.current()
            self.rooms.show_client(client)

    def _join_listed(self, name: str) -> None:
        client = self.rooms.client
        if client is not None and client.state == C.STATE_ONLINE and name.strip():
            client.join(name)

    def _rooms_batch(self, account_id: str, rid: int, rooms) -> None:
        if not self._gone():
            self.rooms.add_batch(account_id, rid, rooms)

    def _rooms_done(self, account_id: str, rid: int, problem: str) -> None:
        if not self._gone():
            self.rooms.list_done(account_id, rid, problem)

    def _direct(self) -> None:
        client, _ = self.current()
        if client is None:
            return
        text, ok = QInputDialog.getText(self, tr(self.protocol.direct_label).rstrip("…"),
                                        tr(self.protocol.direct_prompt))
        if ok and text.strip():
            self._open_direct(client.account.account_id, text)

    def _open_direct(self, account_id: str, name: str) -> None:
        client = self.clients.get(account_id)
        if client is not None and name.strip():
            client.open_direct(name.strip())
            self._pending_open = (account_id, name.strip())

    def _tree_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if item is None:
            return
        account_id, key = item.data(0, ROLE_ACCOUNT), item.data(0, ROLE_KEY)
        client = self.clients.get(account_id)
        if client is None:
            return
        menu = QMenu(self)
        conv = client.conversation(key)
        if conv is not None and conv.kind != C.CONV_SERVER:
            menu.addAction(tr("Open in Window"), lambda: self.detach(account_id, key))
            menu.addAction(tr("Encryption…"), lambda: self._security(account_id, key))
            for label, callback in self.protocol.conversation_actions:
                menu.addAction(tr(label), lambda cb=callback: cb(self, client, key))
            menu.addSeparator()
            menu.addAction(tr("Leave") if conv.kind == C.CONV_CHANNEL else tr("Close"),
                           lambda: client.leave(key))
        else:
            if client.state in (C.STATE_ONLINE, C.STATE_CONNECTING):
                menu.addAction(tr("Disconnect"), client.disconnect_account)
            else:
                menu.addAction(tr("Connect"), client.connect_account)
            menu.addAction(tr("Edit Account…"), lambda: self._edit(account_id))
        try:
            menu.exec(self.tree.viewport().mapToGlobal(pos))
        finally:
            menu.deleteLater()  # else every right click leaves it behind

    def _edit(self, account_id: str) -> None:
        client = self.clients.get(account_id)
        if client is None:
            return
        editor = AccountEditor(self.protocol, client.account, self)
        if editor.exec() == QDialog.DialogCode.Accepted:
            self.account_edited(editor.account)

    def _security(self, account_id: str, key: str) -> None:
        client = self.clients.get(account_id)
        if client is None:
            return
        if self.protocol.show_security is not None:
            self.protocol.show_security(self, client, key)
            return
        conv = client.conversation(key)
        QMessageBox.information(self, tr("Encryption"), tr(C.ENC_TEXT.get(conv.encryption if conv else "", "")))

    # -- from the clients ------------------------------------------------------------------
    def _gone(self) -> bool:
        """The panel or its tree is already destroyed: a client (it lives on
        its own) still reported - its tree items are gone with the tree."""
        tree = self.__dict__.get("tree")
        return sip.isdeleted(self) or tree is None or sip.isdeleted(tree)

    def _state(self, account_id: str, state: str, detail: str) -> None:
        if self._gone():
            return
        item = self._account_items.get(account_id)
        client = self.clients.get(account_id)
        if item is None or client is None:
            return
        item.setText(0, f"{client.account.name} ({tr(STATE_TEXT.get(state, state))})")
        self._show_security(item, client.link_security())
        for (aid, key), conv_item in list(self._conv_items.items()):
            if aid == account_id and conv_item is not item:
                self._show_security(conv_item, client.conversation_security(key))
        self._update_buttons()

    def _conversation(self, account_id: str, key: str) -> None:
        if self._gone():
            return
        client = self.clients.get(account_id)
        if client is None:
            return
        conv = client.conversation(key)
        if conv is None:
            return
        item = self._conv_items.get((account_id, key))
        if item is None:
            if conv.kind == C.CONV_SERVER:
                return
            item = QTreeWidgetItem([conv.title])
            item.setData(0, ROLE_ACCOUNT, account_id)
            item.setData(0, ROLE_KEY, key)
            self._account_items[account_id].addChild(item)
            self._conv_items[(account_id, key)] = item
            pending = getattr(self, "_pending_open", None)
            if pending and pending[0] == account_id and conv.kind == C.CONV_DIRECT:
                self._pending_open = None
                QTimer.singleShot(0, lambda: self.show_conversation(account_id, key))
        if conv.kind != C.CONV_SERVER:
            label = conv.title + (f" ({conv.unread})" if conv.unread else "")
            if conv.kind == C.CONV_CHANNEL and not conv.joined:
                label += " - " + tr("left")
            item.setText(0, label)
        if conv.kind != C.CONV_SERVER:
            self._show_security(item, client.conversation_security(key))
        font = item.font(0)
        font.setBold(conv.highlight or conv.unread > 0)
        item.setFont(0, font)
        item.setForeground(0, QColor("#c0392b") if conv.highlight else QColor())
        view = self.views.get((account_id, key))
        if view is not None:
            view.refresh()

    @staticmethod
    def _show_security(item: QTreeWidgetItem, info) -> None:
        """The tree row's icon says how the account's link or the
        conversation is protected; the tooltip says exactly what."""
        from ui.security_badge import security_icon, tooltip_html

        item.setIcon(0, security_icon(info))
        item.setToolTip(0, tooltip_html(info, item.text(0)))

    def _removed(self, account_id: str, key: str) -> None:
        if self._gone():
            return
        self._drop_view((account_id, key))
        item = self._conv_items.pop((account_id, key), None)
        if item is not None and item.parent() is not None:
            item.parent().removeChild(item)

    def _message(self, account_id: str, message: C.ChatMessage) -> None:
        if self._gone():
            return
        key = (account_id, message.conversation)
        view = self.views.get(key)
        if view is None and message.conversation in (self.current()[1],):
            view = self.view_for(*key)
        if view is not None:
            view.add_message(message)
        client = self.clients.get(account_id)
        if client is None:
            return
        visible = (view is not None and view.isVisible() and
                   (self.stack.currentWidget() is view or key in self.windows))
        if visible:
            client.mark_read(message.conversation)
        conv = client.conversation(message.conversation)
        if conv is not None and conv.highlight and not visible and not message.outgoing:
            self.attention.emit(tr("{title}: {sender} wrote to you").format(
                title=conv.title, sender=message.sender))

    def _request(self, account_id: str, request: object) -> None:
        if self._gone():
            return
        client = self.clients.get(account_id)
        if client is None:
            return
        if self.protocol.handle_request is not None and self.protocol.handle_request(self, client, request):
            return
        if getattr(request, "kind", "") == "certificate":
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle(tr("Untrusted Certificate"))
            box.setText(tr("{host}:{port} presented a certificate axross cannot verify.").format(
                host=request.host, port=request.port))
            box.setInformativeText(
                tr(request.reason) + "\n\n" + tr("SHA-256 fingerprint:") + "\n" + request.fingerprint + "\n\n"
                + tr("Trust it only if you compared this fingerprint with one the server's operator "
                     "published. It is pinned: a different certificate later is refused."))
            trust = box.addButton(tr("Trust This Certificate"), QMessageBox.ButtonRole.AcceptRole)
            box.addButton(QMessageBox.StandardButton.Cancel)
            box.exec()
            client.answer(request, box.clickedButton() is trust)

    # -- shutdown ------------------------------------------------------------------------
    def shutdown(self) -> None:
        for client in list(self.clients.values()):
            try:
                client.shutdown()
            except Exception:  # noqa: BLE001 - closing anyway
                pass
        for key in list(self.windows):
            self._drop_view(key)


class AccountsDialog(QDialog):
    def __init__(self, panel: ChatPanel) -> None:
        super().__init__(panel)
        set_window_icon(self, protocol_icon(panel.protocol))
        self.panel = panel
        self.setWindowTitle(tr("{protocol} Accounts").format(protocol=panel.protocol.title))
        layout = QVBoxLayout(self)
        self.list = QListWidget()
        layout.addWidget(self.list)
        row = QHBoxLayout()
        for label, slot in ((tr("Add…"), self._add), (tr("Edit…"), self._edit), (tr("Remove"), self._remove)):
            b = QPushButton(label)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch(1)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self._fill()
        add_close_corner(self)

    def _fill(self) -> None:
        self.list.clear()
        for account in self.panel.all_accounts():
            item = QListWidgetItem(account.name)
            item.setData(ROLE_ACCOUNT, account.account_id)
            self.list.addItem(item)

    def _selected(self) -> str | None:
        item = self.list.currentItem()
        return item.data(ROLE_ACCOUNT) if item else None

    def _add(self) -> None:
        editor = AccountEditor(self.panel.protocol, None, self)
        if editor.exec() == QDialog.DialogCode.Accepted:
            self.panel.add_account(editor.account)
            self._fill()

    def _edit(self) -> None:
        account_id = self._selected()
        if account_id:
            self.panel._edit(account_id)
            self._fill()

    def _remove(self) -> None:
        account_id = self._selected()
        if not account_id:
            return
        client = self.panel.clients.get(account_id)
        answer = QMessageBox.question(self, tr("Remove Account"), tr(
            "Remove the account {name}? Its stored password and keys are deleted.").format(
                name=client.account.name if client else ""),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            self.panel.remove_account(account_id)
            self._fill()
