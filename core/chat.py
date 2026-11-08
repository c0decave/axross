"""What the chat extensions (IRC, Matrix, XMPP) have in common.

A protocol client (core.chat_irc, core.chat_matrix, core.chat_xmpp) is a
:class:`ChatClient`: a QObject living on the GUI thread whose network side
runs on an asyncio loop of its own thread (:class:`AsyncRunner`). It reports
through Qt signals - emitted from the loop's thread, delivered queued on the
GUI thread - and is driven by plain method calls that hand coroutines to
the loop. The panel (ui/chat_panel.py) knows only this interface.

Everything a server or another user sends is untrusted: text goes through
:func:`clean_text` (control characters, bidi overrides and other invisible
tricks removed, bounded length) before it is shown; nothing is rendered as
HTML, no link or image is fetched.

Accounts are kept in ``~/.config/axross/chat.json`` (0600, no secrets);
passwords, tokens and keys in the keyring (core.credentials), under
``chat:<protocol>:<account id>``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import threading
import time
import unicodedata
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from PyQt6.QtCore import QObject, pyqtSignal

log = logging.getLogger(__name__)

#: Longest message text kept (characters); longer ones are cut with a note.
MAX_TEXT = 16_000
#: Messages kept per conversation in memory.
HISTORY_LIMIT = 5_000
#: Conversations one account may hold (a server can make us join many).
MAX_CONVERSATIONS = 2_000


def modules_installed(*names: str) -> bool:
    """Whether every top-level module of *names* can be imported, without
    importing it (a chat library costs a few hundred ms and tens of MB;
    a panel only needs to know whether to offer Help > Features…)."""
    import importlib.util

    for name in names:
        try:
            if importlib.util.find_spec(name) is None:
                return False
        except (ImportError, ValueError):
            return False
    return True

# --- text from the network -------------------------------------------------------

# Bidi overrides/isolates, zero-width and other format characters that can
# make text show differently from what it is (a spoofed link, a reordered
# command); category Cf is dropped except ZWJ/ZWNJ, which emoji and some
# scripts need.
_KEEP_FORMAT = {"\u200c", "\u200d"}
_IRC_FORMAT = re.compile(r"\x03(?:\d{1,2}(?:,\d{1,2})?)?|\x04(?:[0-9a-fA-F]{6}(?:,[0-9a-fA-F]{6})?)?|[\x02\x0f\x11\x16\x1d\x1e\x1f]")


def clean_text(text: str, limit: int = MAX_TEXT, *, multiline: bool = True) -> str:
    """*text* safe to show: IRC formatting codes, control characters (tab
    and, if *multiline*, newline kept), bidi controls and other invisible
    format characters removed; at most *limit* characters."""
    if not isinstance(text, str):
        text = str(text)
    if len(text) > limit * 4:
        text = text[: limit * 4]
    text = _IRC_FORMAT.sub("", text)
    out = []
    for ch in text:
        if ch == "\t" or (multiline and ch == "\n"):
            out.append(ch)
            continue
        if ch == "\r":
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cs", "Co", "Cn"):
            continue
        if cat == "Cf" and ch not in _KEEP_FORMAT:
            continue
        out.append(ch)
    text = "".join(out)
    if len(text) > limit:
        text = text[:limit] + " […]"
    return text


def clean_name(text: str, limit: int = 200) -> str:
    """A name (nick, room, contact) safe to show on one line."""
    return clean_text(text, limit, multiline=False).strip()


# --- the model ------------------------------------------------------------------

#: Encryption of a conversation or message, from weakest to strongest.
ENC_NONE = "none"          # plain over the network (no TLS)
ENC_TRANSPORT = "tls"      # TLS to the server; the server reads it
ENC_E2E_UNTRUSTED = "e2e-untrusted"  # end-to-end, some keys not verified
ENC_E2E = "e2e"            # end-to-end, all keys verified or trusted
ENC_FAILED = "e2e-failed"  # meant to be end-to-end, could not be decrypted

ENC_TEXT = {
    ENC_NONE: "Not encrypted",
    ENC_TRANSPORT: "Encrypted to the server (TLS) - the server can read it",
    ENC_E2E_UNTRUSTED: "End-to-end encrypted - not every key is verified",
    ENC_E2E: "End-to-end encrypted, keys verified",
    ENC_FAILED: "Could not be decrypted",
}

KIND_MESSAGE = "message"
KIND_ACTION = "action"     # /me
KIND_NOTICE = "notice"
KIND_SYSTEM = "system"     # joins, topic changes, our own notes
KIND_ERROR = "error"

CONV_SERVER = "server"     # the account's own status/console
CONV_CHANNEL = "channel"   # IRC channel, Matrix room, XMPP group chat
CONV_DIRECT = "direct"     # one-to-one


@dataclass
class ChatMessage:
    conversation: str
    sender: str
    text: str
    timestamp: float = field(default_factory=time.time)
    kind: str = KIND_MESSAGE
    outgoing: bool = False
    encryption: str = ENC_TRANSPORT
    message_id: str = ""
    #: Set by the client when the sender's key is known not to be verified.
    note: str = ""


@dataclass
class Member:
    name: str
    display: str = ""
    #: Status prefix (IRC "@", "+"), role or power ("admin", "moderator").
    role: str = ""
    away: bool = False


@dataclass
class Conversation:
    key: str
    kind: str
    title: str
    topic: str = ""
    encryption: str = ENC_TRANSPORT
    unread: int = 0
    highlight: bool = False
    joined: bool = True
    members: dict[str, Member] = field(default_factory=dict)
    history: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LIMIT))


# --- accounts -------------------------------------------------------------------

@dataclass
class RoomInfo:
    """One entry of a server's public channel / room list. *name* is what
    :meth:`ChatClient.join` takes (``#channel``, ``#room:server``,
    ``room@conference.server``); *users* is -1 when the server does not say."""
    name: str
    title: str = ""
    users: int = -1
    topic: str = ""


#: Entries of one room list kept at most (IRC networks list 50 000+).
MAX_ROOM_LIST = 100_000
#: Entries handed to the GUI per batch while a list arrives.
ROOM_BATCH = 500


@dataclass
class FieldSpec:
    """One field of a protocol's account dialog."""
    key: str
    label: str
    kind: str = "text"     # text | password | int | bool | choice | lines | file
    default: Any = ""
    choices: tuple = ()
    help: str = ""
    required: bool = False
    secret: bool = False   # kept in the keyring, not in chat.json


@dataclass
class Account:
    protocol: str
    name: str
    settings: dict = field(default_factory=dict)
    account_id: str = field(default_factory=lambda: secrets.token_hex(6))
    autoconnect: bool = False

    @property
    def keyring_profile(self) -> str:
        return f"chat:{self.protocol}:{self.account_id}"


_ACCOUNT_ID = re.compile(r"[0-9a-f]{6,32}")
_PROTOCOL = re.compile(r"[a-z]{2,16}")


def accounts_file() -> Path:
    return Path.home() / ".config" / "axross" / "chat.json"


def load_accounts(path: Path | None = None) -> list[Account]:
    """The saved accounts; a missing, unreadable or tampered file gives the
    entries that are well-formed (none when it is not JSON)."""
    path = path or accounts_file()
    try:
        if path.stat().st_size > 1_000_000:
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return []
    entries = data.get("accounts") if isinstance(data, dict) else None
    out: list[Account] = []
    seen: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        protocol, name = entry.get("protocol"), entry.get("name")
        account_id, settings = entry.get("account_id"), entry.get("settings")
        if not (isinstance(protocol, str) and _PROTOCOL.fullmatch(protocol)):
            continue
        if not (isinstance(account_id, str) and _ACCOUNT_ID.fullmatch(account_id)) or account_id in seen:
            continue
        if not isinstance(name, str) or not isinstance(settings, dict):
            continue
        seen.add(account_id)
        out.append(Account(protocol=protocol, name=clean_name(name, 100), settings=settings,
                           account_id=account_id, autoconnect=entry.get("autoconnect") is True))
    return out


def save_accounts(accounts: Iterable[Account], path: Path | None = None) -> None:
    from core.secure_storage import write_secret_file

    path = path or accounts_file()
    os.makedirs(path.parent, mode=0o700, exist_ok=True)
    data = {"version": 1, "accounts": [asdict(a) for a in accounts]}
    write_secret_file(str(path), json.dumps(data, indent=1, sort_keys=True) + "\n")


#: Secrets kept for this run only, when the keyring cannot store them:
#: (keyring profile, name) -> value.
_SESSION_SECRETS: dict[tuple[str, str], str] = {}


def account_secret(account: Account, name: str) -> str | None:
    from core import credentials

    value = _SESSION_SECRETS.get((account.keyring_profile, name))
    if value is not None:
        return value
    return credentials.get_secret(account.keyring_profile, name)


def store_account_secret(account: Account, name: str, value: str | None) -> bool:
    """Keep (or with None/"" remove) one secret of *account* in the keyring.
    False: the keyring could not keep it - it is kept for this run only."""
    from core import credentials

    key = (account.keyring_profile, name)
    if not value:
        _SESSION_SECRETS.pop(key, None)
        credentials.delete_secret(account.keyring_profile, name)
        return True
    if credentials.store_secret(account.keyring_profile, name, value):
        _SESSION_SECRETS.pop(key, None)
        return True
    _SESSION_SECRETS[key] = value
    return False


def forget_account_secrets(account: Account, names: Iterable[str]) -> None:
    for name in names:
        store_account_secret(account, name, None)


def state_dir(account: Account) -> Path:
    """A private folder for the account's protocol state (encryption keys,
    sync tokens): ``~/.local/state/axross/chat/<protocol>-<id>``, 0700."""
    base = Path.home() / ".local" / "state" / "axross" / "chat"
    path = base / f"{account.protocol}-{account.account_id}"
    os.makedirs(path, mode=0o700, exist_ok=True)
    for p in (base, path):
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    return path


# --- the asyncio side -----------------------------------------------------------

class AsyncRunner:
    """An asyncio loop on a daemon thread of its own."""

    def __init__(self, name: str) -> None:
        self._name = name
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        self.start()
        assert self._loop is not None
        return self._loop

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._ready.clear()
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()
        self._ready.wait(5)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            try:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:  # noqa: BLE001 - shutting down
                pass
            loop.close()

    def submit(self, coro, on_error: Callable[[BaseException], None] | None = None):
        """Run *coro* on the loop; returns its concurrent future. An
        exception goes to *on_error* (on the loop's thread) or the log."""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)

        def done(f):
            if f.cancelled():
                return
            exc = f.exception()
            if exc is not None:
                if on_error is not None:
                    on_error(exc)
                else:
                    log.warning("%s: %s", self._name, exc, exc_info=exc)
        future.add_done_callback(done)
        return future

    def stop(self, timeout: float = 5.0) -> None:
        loop, thread = self._loop, self._thread
        if loop is None or thread is None:
            return
        try:
            loop.call_soon_threadsafe(loop.stop)
        except RuntimeError:
            pass
        thread.join(timeout)
        self._loop = self._thread = None


# --- the client interface --------------------------------------------------------

STATE_OFFLINE = "offline"
STATE_CONNECTING = "connecting"
STATE_ONLINE = "online"
STATE_ERROR = "error"


class ChatClient(QObject):
    """One account's connection. Subclasses implement the ``_``-methods
    (coroutines on the loop) and call the ``_emit_``/``_add_`` helpers from
    the loop; the GUI calls the public methods."""

    #: (state, detail)
    state_changed = pyqtSignal(str, str)
    #: a conversation appeared or changed (title, topic, encryption, members)
    conversation_changed = pyqtSignal(str)
    conversation_removed = pyqtSignal(str)
    #: a ChatMessage
    message_added = pyqtSignal(object)
    #: something the user has to answer: a request object of the protocol
    #: (verification, trust decision, invite); the panel shows it
    request = pyqtSignal(object)
    #: (request id, [RoomInfo, ...]) - a batch of the public room list
    room_list_batch = pyqtSignal(int, object)
    #: (request id, problem or "") - the list is complete (or failed)
    room_list_done = pyqtSignal(int, str)

    protocol = ""
    #: "/command" names the input line offers (completion and /help)
    commands: tuple[str, ...] = ()
    #: the client can list the server's public channels / rooms
    supports_room_list = False
    #: the end-to-end scheme of the protocol ("Megolm", "OMEMO"), for the
    #: security tooltip
    e2e_scheme = ""

    def __init__(self, account: Account, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.account = account
        self.state = STATE_OFFLINE
        self.detail = ""
        self._lock = threading.RLock()
        self._conversations: dict[str, Conversation] = {}
        self.runner = AsyncRunner(f"chat-{account.protocol}-{account.account_id}")
        self.server_key = "*server*"
        #: what protects the link to the server, read from the live
        #: connection (core.conn_security.SecurityInfo); None: not connected
        self._link_info = None
        self._room_list_id = 0
        self._add_conversation(self.server_key, CONV_SERVER, account.name or account.protocol)

    # -- read by the GUI ----------------------------------------------------------
    def conversations(self) -> list[Conversation]:
        with self._lock:
            return list(self._conversations.values())

    def conversation(self, key: str) -> Conversation | None:
        with self._lock:
            return self._conversations.get(key)

    def history(self, key: str) -> list[ChatMessage]:
        with self._lock:
            conv = self._conversations.get(key)
            return list(conv.history) if conv else []

    # -- how it is protected ---------------------------------------------------------
    def link_security(self):
        """The protection of the connection to the server: negotiated when
        connected (TLS version, certificate), else as configured."""
        info = self._link_info
        if info is not None and self.state in (STATE_ONLINE, STATE_CONNECTING):
            return info
        return self.configured_link_security()

    def configured_link_security(self):
        """The protection the account's settings ask for (subclasses say more)."""
        from core import conn_security as CS

        conv = self.conversation(self.server_key)
        if conv is not None and conv.encryption == ENC_NONE:
            return CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "No TLS - cleartext - anyone on the network can "
                                   "read it, the password too")
        return CS.SecurityInfo(CS.LEVEL_TLS, "TLS to the server, certificate verified")

    def conversation_security(self, key: str):
        """The protection of conversation *key*: end-to-end (and whether every
        key is verified) or only the link to the server, which reads it."""
        from core import conn_security as CS

        conv = self.conversation(key)
        link = self.link_security()
        if conv is None or conv.kind == CONV_SERVER:
            return link
        if conv.encryption in (ENC_TRANSPORT, ENC_NONE):
            if link.level in (CS.LEVEL_CLEARTEXT, CS.LEVEL_UNKNOWN):
                return link
            return CS.SecurityInfo(link.level, f"Not end-to-end encrypted - the server can read it; "
                                   f"to the server: {link.summary}", link.negotiated, link.details)
        scheme = f" ({self.e2e_scheme})" if self.e2e_scheme else ""
        return CS.from_chat(conv.encryption, ENC_TEXT.get(conv.encryption, conv.encryption) + scheme,
                            negotiated=True, details=(f"To the server: {link.summary}",))

    # -- the public room list --------------------------------------------------------
    def request_room_list(self, search: str = "") -> int:
        """Ask for the server's public channels / rooms; batches arrive by
        :attr:`room_list_batch`, the end by :attr:`room_list_done`. Returns
        the request id (an older request's batches carry their own id)."""
        self._room_list_id += 1
        rid = self._room_list_id
        if not self.supports_room_list:
            self.room_list_done.emit(rid, "This server type has no public room list.")
            return rid
        self.runner.submit(self._room_list(rid, search.strip()),
                           on_error=lambda e: self.room_list_done.emit(rid, error_text(e)))
        return rid

    async def _room_list(self, rid: int, search: str) -> None:
        raise ChatError("This server type has no public room list.")

    def _emit_rooms(self, rid: int, rooms: Iterable[RoomInfo]) -> None:
        """Hand a batch to the GUI, every field cleaned (untrusted)."""
        batch = []
        for room in rooms:
            name = clean_name(room.name, 300)
            if not name:
                continue
            try:
                users = int(room.users)
            except (TypeError, ValueError):
                users = -1
            batch.append(RoomInfo(name=name, title=clean_name(room.title, 200),
                                  users=users if 0 <= users < 100_000_000 else -1,
                                  topic=clean_text(str(room.topic).replace("\n", " "), 400,
                                                   multiline=False)))
        if batch:
            self.room_list_batch.emit(rid, batch)

    def mark_read(self, key: str) -> None:
        with self._lock:
            conv = self._conversations.get(key)
            if conv is None or (conv.unread == 0 and not conv.highlight):
                return
            conv.unread, conv.highlight = 0, False
        self.conversation_changed.emit(key)

    # -- called by the GUI --------------------------------------------------------
    def connect_account(self) -> None:
        if self.state in (STATE_CONNECTING, STATE_ONLINE):
            return
        self._set_state(STATE_CONNECTING, "")
        self.runner.submit(self._connect(), on_error=self._failed)

    def disconnect_account(self) -> None:
        if self.state == STATE_OFFLINE:
            return
        future = self.runner.submit(self._disconnect(), on_error=self._failed)
        try:
            future.result(5)
        except Exception:  # noqa: BLE001 - offline anyway
            pass
        self._set_state(STATE_OFFLINE, "")

    def shutdown(self) -> None:
        """Disconnect and stop the loop (the panel closes)."""
        try:
            self.disconnect_account()
        finally:
            self.runner.stop()

    def send(self, key: str, text: str) -> None:
        """What the user typed in conversation *key*: a message or a
        "/command" (a leading "//" sends a literal "/")."""
        if not text.strip():
            return
        if text.startswith("/") and not text.startswith("//"):
            name, _, rest = text[1:].partition(" ")
            self.runner.submit(self._command(key, name.lower(), rest.strip()),
                               on_error=lambda e: self._error_in(key, e))
            return
        if text.startswith("//"):
            text = text[1:]
        self.runner.submit(self._send_text(key, text), on_error=lambda e: self._error_in(key, e))

    def join(self, target: str) -> None:
        self.runner.submit(self._join(target.strip()), on_error=lambda e: self._error_in(self.server_key, e))

    def open_direct(self, target: str) -> None:
        self.runner.submit(self._open_direct(target.strip()),
                           on_error=lambda e: self._error_in(self.server_key, e))

    def leave(self, key: str) -> None:
        conv = self.conversation(key)
        if conv is None or conv.kind == CONV_SERVER:
            return
        self.runner.submit(self._leave(key), on_error=lambda e: self._error_in(self.server_key, e))

    def answer(self, request: object, answer: object) -> None:
        """The user's answer to something :attr:`request` asked."""
        self.runner.submit(self._answer(request, answer), on_error=lambda e: self._error_in(self.server_key, e))

    # -- for subclasses (the loop's thread) ------------------------------------------
    async def _connect(self) -> None:
        raise NotImplementedError

    async def _disconnect(self) -> None:
        raise NotImplementedError

    async def _send_text(self, key: str, text: str) -> None:
        raise NotImplementedError

    async def _command(self, key: str, name: str, args: str) -> None:
        self._note(key, f"Unknown command: /{name}", KIND_ERROR)

    async def _join(self, target: str) -> None:
        raise NotImplementedError

    async def _open_direct(self, target: str) -> None:
        raise NotImplementedError

    async def _leave(self, key: str) -> None:
        raise NotImplementedError

    async def _answer(self, request: object, answer: object) -> None:
        return None

    def _set_state(self, state: str, detail: str) -> None:
        self.state, self.detail = state, detail
        if state in (STATE_OFFLINE, STATE_ERROR):
            self._link_info = None
        self.state_changed.emit(state, detail)

    def _failed(self, exc: BaseException) -> None:
        text = error_text(exc)
        self._note(self.server_key, text, KIND_ERROR)
        self._set_state(STATE_ERROR, text)

    def _error_in(self, key: str, exc: BaseException) -> None:
        self._note(key, error_text(exc), KIND_ERROR)

    def _add_conversation(self, key: str, kind: str, title: str, **fields) -> Conversation:
        with self._lock:
            conv = self._conversations.get(key)
            if conv is None:
                if len(self._conversations) >= MAX_CONVERSATIONS:
                    raise ChatError("too many conversations")
                conv = Conversation(key=key, kind=kind, title=clean_name(title) or key, **fields)
                self._conversations[key] = conv
            else:
                conv.joined = True
                for name, value in fields.items():
                    setattr(conv, name, value)
        self.conversation_changed.emit(key)
        return conv

    def _update_conversation(self, key: str, **fields) -> None:
        with self._lock:
            conv = self._conversations.get(key)
            if conv is None:
                return
            for name, value in fields.items():
                if name in ("title", "topic") and isinstance(value, str):
                    value = clean_name(value, 200) if name == "title" else clean_text(value, 1000, multiline=False)
                setattr(conv, name, value)
        self.conversation_changed.emit(key)

    def _remove_conversation(self, key: str) -> None:
        with self._lock:
            if key == self.server_key or self._conversations.pop(key, None) is None:
                return
        self.conversation_removed.emit(key)

    def _set_members(self, key: str, members: dict[str, Member]) -> None:
        with self._lock:
            conv = self._conversations.get(key)
            if conv is None:
                return
            conv.members = members
        self.conversation_changed.emit(key)

    def _add_message(self, message: ChatMessage, *, highlight_words: Iterable[str] = ()) -> None:
        message.text = clean_text(message.text)
        message.sender = clean_name(message.sender)
        with self._lock:
            conv = self._conversations.get(message.conversation)
            if conv is None:
                return
            conv.history.append(message)
            if not message.outgoing and message.kind in (KIND_MESSAGE, KIND_ACTION, KIND_NOTICE):
                conv.unread += 1
                lowered = message.text.lower()
                if conv.kind == CONV_DIRECT or any(w and w.lower() in lowered for w in highlight_words):
                    conv.highlight = True
        self.message_added.emit(message)

    def _note(self, key: str, text: str, kind: str = KIND_SYSTEM) -> None:
        if self.conversation(key) is None:
            key = self.server_key
        self._add_message(ChatMessage(conversation=key, sender="", text=text, kind=kind,
                                      encryption=ENC_NONE))


class ChatError(Exception):
    """An error whose text is meant for the user."""


def error_text(exc: BaseException) -> str:
    if isinstance(exc, ChatError):
        return str(exc)
    if isinstance(exc, asyncio.TimeoutError):
        return "The server did not answer in time."
    if isinstance(exc, ConnectionRefusedError):
        return "The server refused the connection."
    if isinstance(exc, OSError) and getattr(exc, "strerror", None):
        return f"Network error: {exc.strerror}"
    text = str(exc) or type(exc).__name__
    return clean_text(text, 500, multiline=False)


# --- protocols -------------------------------------------------------------------

@dataclass
class Protocol:
    """What the panel needs to know of a protocol."""
    name: str                       # "irc"
    title: str                      # "IRC"
    fields: tuple[FieldSpec, ...]
    make_client: Callable[[Account], ChatClient]
    #: label of "join" ("Join Channel…", "Join Room…") and its prompt
    join_label: str = "Join…"
    join_prompt: str = "Name:"
    direct_label: str = "New Conversation…"
    direct_prompt: str = "Name:"
    #: checks an account's settings; returns the problem or None
    validate: Callable[[dict], str | None] = lambda settings: None
    #: handle_request(panel, client, request) -> bool: shows a request of
    #: the client (a verification, a trust decision); False leaves it to the
    #: panel's generic handling
    handle_request: Callable | None = None
    #: show_security(panel, client, conversation_key): the encryption
    #: details of a conversation (keys, devices, fingerprints)
    show_security: Callable | None = None
    #: extra actions on a conversation: ((label, callback(panel, client, key)), ...)
    conversation_actions: tuple = ()
    #: the account field that offers the public servers (core.chat_servers)
    #: in an editable drop-down; "" for none
    server_field: str = ""
    #: apply_server(entry, values) -> {field: value}: what choosing a public
    #: server fills in (values: the form's current settings)
    apply_server: Callable | None = None
    #: label of the public room list ("Channel List", "Room Directory")
    room_list_label: str = "Room List"


# --- connections ------------------------------------------------------------------

PROXY_CHOICES = (("default", "axross default proxy (Tools > Network & Proxy)"),
                 ("none", "Direct, no proxy"))


async def open_stream(host: str, port: int, *, ssl_context=None, server_hostname: str | None = None,
                      proxy_mode: str = "default", protocol: str = "", timeout: float = 20.0,
                      limit: int = 1 << 16):
    """A TCP (optionally TLS) stream to *host*:*port*, through axross's
    default proxy when one applies (*proxy_mode* "default") - a proxy that
    cannot be resolved is an error, never a direct connection."""
    config = None
    if proxy_mode != "none":
        from core import proxy_settings

        config = await asyncio.to_thread(
            lambda: proxy_settings.resolve("default", None, host, port, protocol).config)
    if config is None:
        return await asyncio.wait_for(asyncio.open_connection(
            host, port, ssl=ssl_context, server_hostname=server_hostname if ssl_context else None,
            limit=limit), timeout)
    from core.proxy import create_proxy_socket

    sock = await asyncio.to_thread(create_proxy_socket, config, host, port, timeout)
    sock.setblocking(False)
    return await asyncio.wait_for(asyncio.open_connection(
        sock=sock, ssl=ssl_context, server_hostname=(server_hostname or host) if ssl_context else None,
        limit=limit), timeout)
