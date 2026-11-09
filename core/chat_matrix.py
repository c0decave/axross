"""Matrix for the chat panel (resources/extensions/matrix.py), on matrix-nio
with its end-to-end encryption (Olm/Megolm through vodozemac).

* Login with the account's password once; the access token and the device
  are kept (token in the keyring, the device's keys in an encrypted store
  under ``~/.local/state/axross/chat/matrix-<id>/`` whose key is in the
  keyring), so the next start is the same device with the same keys.
* Rooms and direct chats; a new direct chat is created encrypted.
  Messages, emotes and notices; attachments are named, never fetched.
* End-to-end encryption: messages in an encrypted room are encrypted for
  every device of its members; a message that cannot be decrypted says so
  and its key is requested from our other devices.
* Device trust: every device of a room's members with its fingerprint;
  verify it interactively (SAS: compare emoji or numbers - with Element and
  other clients, which start with ``m.key.verification.request``, as well
  as the older direct start) or by comparing the fingerprint, blacklist it
  (it gets no keys) or ignore it. Whether messages go to devices nobody
  verified is the account's choice: *warn* (like Element; the room shows
  "not every key is verified") or *block* (nothing is sent until each
  device is verified, blacklisted or ignored).
* Room keys exported to and imported from a passphrase-protected file
  (the format Element uses).

Message text is shown as plain text: ``formatted_body`` (HTML) is not
rendered.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass, field

from core import chat as C

log = logging.getLogger(__name__)

UNVERIFIED_WARN = "warn"
UNVERIFIED_BLOCK = "block"
SYNC_TIMEOUT_MS = 30_000
#: Pause before a sync that failed is tried again (the last repeats).
RETRY_DELAYS = (2, 5, 15, 30, 60)
MAX_ROOMS = 1000
#: How long an interactive verification may take.
VERIFY_TIMEOUT = 600
#: Rooms asked for per page of the public room directory, pages at most,
#: and the largest page read (bytes).
ROOM_PAGE = 500
ROOM_PAGES = 40
MAX_DIRECTORY_PAGE = 4 * 1024 * 1024
_USER_ID = re.compile(r"@[a-z0-9._=\-/+]+:[A-Za-z0-9.\-:\[\]]+")
_ROOM_REF = re.compile(r"[#!][^\s:]+:[A-Za-z0-9.\-:\[\]]+")


def nio_missing(*, load: bool = True) -> str | None:
    """Why the Matrix client cannot run here, or None.

    *load* False only looks whether the packages are installed, without
    importing them: the panel asks when the extension is switched on, and
    importing nio takes about half a second and 100 MB - the connect
    imports it (in the chat runner's thread)."""
    if not load:
        return None if C.modules_installed("nio", "vodozemac") else _NIO_MISSING
    try:
        import nio  # noqa: F401
        import vodozemac  # noqa: F401
    except ImportError:
        return _NIO_MISSING
    return None


# Help > Features… installs it (or names the axross-full build), as for
# every other extra - not a pip command to type.
_NIO_MISSING = "Matrix needs matrix-nio with encryption: install it in Help → Features… (Matrix and XMPP chat)"


def full_user_id(user: str, homeserver: str) -> str:
    """"@alice:example.org" of "alice" and "https://example.org"."""
    user = user.strip()
    if user.startswith("@"):
        return user
    host = re.sub(r"^https?://", "", homeserver.strip()).split("/", 1)[0]
    return f"@{user}:{host}"


def loopback_http(url: str) -> bool:
    """An http:// address of this machine (a homeserver for tests or a
    local bridge) - the only place Matrix may go without TLS."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    return parts.scheme == "http" and (parts.hostname or "") in ("localhost", "127.0.0.1", "::1")


def fingerprint_text(key: str) -> str:
    """An Ed25519 key in groups of four, as Element shows it."""
    key = key or ""
    return " ".join(key[i:i + 4] for i in range(0, len(key), 4))


def parse_public_rooms(data) -> tuple[list, str]:
    """The rooms of one page of ``/publicRooms`` (untrusted JSON) and the
    token of the next page ("" for the last). A room is joined by its alias
    when it has one, else by its id."""
    if not isinstance(data, dict):
        raise C.ChatError("The room directory sent something that is not a room list.")
    rooms = []
    chunk = data.get("chunk")
    for item in (chunk if isinstance(chunk, list) else [])[:ROOM_PAGE * 2]:
        if not isinstance(item, dict):
            continue
        alias, room_id = item.get("canonical_alias"), item.get("room_id")
        target = next((t for t in (alias, room_id) if isinstance(t, str) and _ROOM_REF.fullmatch(t)), "")
        if not target:
            continue
        name = item.get("name")
        topic = item.get("topic")
        users = item.get("num_joined_members")
        rooms.append(C.RoomInfo(name=target, title=name if isinstance(name, str) else "",
                                users=users if isinstance(users, int) and not isinstance(users, bool) else -1,
                                topic=topic if isinstance(topic, str) else ""))
    token = data.get("next_batch")
    return rooms, token if isinstance(token, str) and 0 < len(token) <= 1000 else ""


# --- what the user is asked --------------------------------------------------------------

@dataclass
class InviteRequest:
    room_id: str
    room_name: str
    inviter: str
    kind: str = "invite"


@dataclass
class VerificationRequest:
    """Another device wants to verify with us (or answered our request)."""
    user_id: str
    device_id: str
    transaction_id: str
    device_name: str = ""
    kind: str = "verification-request"


@dataclass
class SasRequest:
    """Compare these with the other device; do they match?"""
    user_id: str
    device_id: str
    transaction_id: str
    emoji: list = field(default_factory=list)       # [(symbol, name), ...]
    decimals: tuple = ()
    kind: str = "sas"


@dataclass
class VerificationResult:
    user_id: str
    device_id: str
    transaction_id: str
    ok: bool
    reason: str = ""
    kind: str = "verification-result"


@dataclass
class DeviceInfo:
    user_id: str
    device_id: str
    name: str
    fingerprint: str
    trust: str            # "verified" | "blacklisted" | "ignored" | "unset"
    own: bool = False


# --- the client -------------------------------------------------------------------------

# nio's key store (peewee on SQLite) binds its models to a database for the
# length of each call, process-wide: two accounts on two threads would
# switch each other's database in the middle of a call ("database attribute
# does not appear to be set on the model"). All Matrix accounts therefore
# share one loop thread, where the store's synchronous calls never overlap.
_SHARED = {"runner": None, "users": 0}


def _shared_runner() -> C.AsyncRunner:
    if _SHARED["runner"] is None:
        _SHARED["runner"] = C.AsyncRunner("chat-matrix")
    _SHARED["users"] += 1
    return _SHARED["runner"]


def _release_runner() -> None:
    _SHARED["users"] = max(0, _SHARED["users"] - 1)
    if _SHARED["users"] == 0 and _SHARED["runner"] is not None:
        _SHARED["runner"].stop()
        _SHARED["runner"] = None


class MatrixClient(C.ChatClient):
    protocol = "matrix"
    supports_room_list = True
    e2e_scheme = "Olm/Megolm"
    commands = ("join", "leave", "invite", "topic", "nick", "me", "notice", "encrypt", "verify",
                "devices", "trust", "untrust", "blacklist", "ignore", "export-keys", "import-keys", "help")
    extra_secrets = ("access_token", "store_key")

    def __init__(self, account: C.Account, parent=None) -> None:
        super().__init__(account, parent)
        self.runner = _shared_runner()
        self._released = False
        s = account.settings
        self.homeserver = str(s.get("homeserver", "")).strip().rstrip("/")
        if self.homeserver and "://" not in self.homeserver:
            self.homeserver = "https://" + self.homeserver
        self.user_id = full_user_id(str(s.get("user", "")), self.homeserver) if s.get("user") else ""
        self.unverified = s.get("unverified") if s.get("unverified") in (UNVERIFIED_WARN, UNVERIFIED_BLOCK) \
            else UNVERIFIED_WARN
        self.nio = None
        self._sync_task: asyncio.Task | None = None
        self._want_online = False
        #: transaction ids of verifications the user agreed to
        self._accepted: set[str] = set()
        #: our outgoing requests: txid -> (user, device ids)
        self._requested: dict[str, tuple[str, tuple[str, ...]]] = {}
        self._sas_shown: set[str] = set()
        self._room_keys_asked: set[str] = set()
        self._invites_asked: set[str] = set()
        self._update_conversation(self.server_key, title=account.name or self.user_id or "Matrix")

    def configured_link_security(self):
        """HTTPS to the homeserver (aiohttp checks the certificate); the
        TLS version is not kept by nio, so this stays "configured"."""
        from core import conn_security as CS

        if loopback_http(self.homeserver):
            return CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "http:// to a homeserver on this machine - "
                                   "not encrypted (it never leaves the computer)")
        return CS.url_info(self.homeserver, what="Matrix homeserver")

    async def _room_list(self, rid: int, search: str) -> None:
        """The homeserver's public room directory, page by page."""
        nio = self._require_online()
        since, count = "", 0
        for _page in range(ROOM_PAGES):
            rooms, since = parse_public_rooms(await self._public_rooms_page(nio, since, search))
            rooms = rooms[:C.MAX_ROOM_LIST - count]
            count += len(rooms)
            self._emit_rooms(rid, rooms)
            if not since or count >= C.MAX_ROOM_LIST:
                break
        capped = bool(since)
        self.room_list_done.emit(rid, f"Only the first {count} rooms are shown." if capped else "")

    async def _public_rooms_page(self, nio, since: str, search: str) -> dict:
        if getattr(nio, "client_session", None) is None or not getattr(nio, "access_token", ""):
            raise C.ChatError("Not connected.")
        body: dict = {"limit": ROOM_PAGE}
        if since:
            body["since"] = since
        if search:
            body["filter"] = {"generic_search_term": search[:200]}
        response = await nio.send("POST", "/_matrix/client/v3/publicRooms", data=json.dumps(body),
                                  headers={"Authorization": f"Bearer {nio.access_token}",
                                           "Content-Type": "application/json"})
        try:
            if response.status != 200:
                raise C.ChatError(f"The room directory answered HTTP {response.status}.")
            raw = bytearray()
            while True:  # aiohttp's read(n) gives what is there, up to n
                chunk = await response.content.read(65536)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > MAX_DIRECTORY_PAGE:
                    raise C.ChatError("The room directory's answer is too large.")
        finally:
            response.release()
        try:
            return json.loads(raw)
        except (ValueError, RecursionError):
            raise C.ChatError("The room directory sent something that is not JSON.") from None

    def shutdown(self) -> None:
        try:
            self.disconnect_account()
        finally:
            if not self._released:
                self._released = True
                _release_runner()

    # -- connect ------------------------------------------------------------------------
    def _store_key(self) -> str:
        key = C.account_secret(self.account, "store_key")
        if not key:
            key = secrets.token_urlsafe(32)
            if not C.store_account_secret(self.account, "store_key", key):
                self._note(self.server_key, "The keyring cannot keep the key of the encryption store: "
                           "this device's keys are lost when axross closes.", C.KIND_ERROR)
        return key

    def _proxy_url(self) -> str | None:
        if self.account.settings.get("proxy") == "none":
            return None
        from urllib.parse import quote, urlsplit

        from core import proxy_settings

        parts = urlsplit(self.homeserver)
        config = proxy_settings.resolve("default", None, parts.hostname or "", parts.port or 443, "matrix").config
        if config is None:
            return None
        transport = config.transport
        if transport not in ("socks5", "socks4", "http"):
            raise C.ChatError(f"Matrix cannot go through a {transport} proxy; choose Direct or another proxy.")
        auth = ""
        if config.username:
            auth = quote(config.username, safe="") + (":" + quote(config.password, safe="") if config.password else "") + "@"
        return f"{transport}://{auth}{config.host}:{config.port}"

    def _make_nio(self, device_id: str):
        from nio import AsyncClient, AsyncClientConfig

        path = str(C.state_dir(self.account))
        config = AsyncClientConfig(store_sync_tokens=True, encryption_enabled=True,
                                   pickle_key=self._store_key(), store_name="axross.db",
                                   max_timeouts=None, request_timeout=90)
        client = AsyncClient(self.homeserver, self.user_id, device_id=device_id or "", store_path=path,
                             config=config, proxy=self._proxy_url())
        return client

    async def _connect(self) -> None:
        missing = nio_missing()
        if missing:
            raise C.ChatError(missing)
        if not self.homeserver.startswith("https://") and not loopback_http(self.homeserver):
            raise C.ChatError("The homeserver address must start with https://.")
        if not _USER_ID.fullmatch(self.user_id):
            raise C.ChatError(f"{self.user_id!r} is not a Matrix user id (@name:server).")
        from nio import LoginResponse

        self._want_online = True
        device_id = str(self.account.settings.get("device_id", "") or "")
        token = C.account_secret(self.account, "access_token")
        self.nio = self._make_nio(device_id)
        if device_id and token:
            self.nio.restore_login(self.user_id, device_id, token)
            self.nio.load_store()
            self._note(self.server_key, f"Signed in as {self.user_id}, device {device_id}.")
        else:
            password = C.account_secret(self.account, "password")
            if not password:
                raise C.ChatError("The account has no password stored.")
            name = str(self.account.settings.get("device_name", "") or "axross")[:100]
            response = await self.nio.login(password=password, device_name=name)
            if not isinstance(response, LoginResponse):
                await self.nio.close()
                self.nio = None
                raise C.ChatError(f"Login failed: {getattr(response, 'message', response)}")
            self.account.settings["device_id"] = response.device_id
            self.user_id = response.user_id
            if not C.store_account_secret(self.account, "access_token", response.access_token):
                self._note(self.server_key, "The keyring cannot keep the login: you sign in again "
                           "next time (as a new device).", C.KIND_ERROR)
            self._account_changed()
            self._note(self.server_key, f"Signed in as {self.user_id}; this is a new device, "
                       f"{response.device_id}. Verify it from another of your sessions.")
        self._register_callbacks()
        self._set_state(C.STATE_CONNECTING, "first sync…")
        self._sync_task = asyncio.create_task(self._sync_loop())

    def _account_changed(self) -> None:
        callback = getattr(self, "on_account_changed", None)
        if callback is not None:
            callback(self.account)

    async def _sync_loop(self) -> None:
        from nio import SyncError, SyncResponse

        attempt = 0
        first = True
        while self._want_online and self.nio is not None:
            try:
                response = await self.nio.sync(timeout=SYNC_TIMEOUT_MS if not first else 0, full_state=first)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - network: try again
                response = exc
            if isinstance(response, SyncResponse):
                attempt = 0
                first = False
                if self.state != C.STATE_ONLINE:
                    # The first sync, and every one after a failed one: a
                    # failure set "connecting", which refuses every send.
                    self._set_state(C.STATE_ONLINE, self.user_id)
                await self._after_sync()
                continue
            if isinstance(response, SyncError) and getattr(response, "status_code", "") == "M_UNKNOWN_TOKEN":
                self._want_online = False
                C.store_account_secret(self.account, "access_token", None)
                self.account.settings.pop("device_id", None)
                self._account_changed()
                self._set_state(C.STATE_ERROR, "signed out by the server")
                self._note(self.server_key, "The server ended this login (signed out elsewhere?). "
                           "Connect again to sign in as a new device.", C.KIND_ERROR)
                return
            delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
            attempt += 1
            text = getattr(response, "message", None) or C.error_text(response) if isinstance(
                response, BaseException) else getattr(response, "message", str(response))
            self._set_state(C.STATE_CONNECTING if not first else C.STATE_CONNECTING, f"retry in {delay} s")
            self._note(self.server_key, f"Sync failed ({text}); trying again in {delay} s.", C.KIND_ERROR)
            await asyncio.sleep(delay)

    async def _after_sync(self) -> None:
        nio = self.nio
        if nio is None:
            return
        if nio.should_upload_keys:
            await nio.keys_upload()
        if nio.should_query_keys:
            await nio.keys_query()
        if nio.should_claim_keys:
            await nio.keys_claim(nio.get_users_for_key_claiming())
        await nio.send_to_device_messages()
        self._refresh_rooms()

    async def _disconnect(self) -> None:
        self._want_online = False
        task, self._sync_task = self._sync_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self.nio is not None:
            try:
                await self.nio.close()
            except Exception:  # noqa: BLE001
                pass
        self.nio = None

    # -- rooms ------------------------------------------------------------------------------
    def _room_encryption(self, room) -> str:
        if not room.encrypted:
            return C.ENC_TRANSPORT
        for device in self._room_devices(room):
            if not (device.verified or device.blacklisted or device.ignored):
                return C.ENC_E2E_UNTRUSTED
        return C.ENC_E2E

    def _room_devices(self, room):
        nio = self.nio
        if nio is None or nio.olm is None:
            return []
        out = []
        for user_id in list(room.users)[:2000]:
            for device in nio.device_store.active_user_devices(user_id):
                if user_id == self.user_id and device.id == nio.device_id:
                    continue
                out.append(device)
        return out

    def _room_kind(self, room) -> str:
        if room.member_count <= 2 and not room.name and not room.canonical_alias:
            return C.CONV_DIRECT
        return C.CONV_CHANNEL

    def _members(self, room) -> dict[str, C.Member]:
        members = {}
        levels = getattr(room, "power_levels", None)
        for user_id, user in list(room.users.items())[:5000]:
            level = 0
            if levels is not None:
                try:
                    level = levels.get_user_level(user_id)
                except Exception:  # noqa: BLE001
                    level = 0
            role = "@" if level >= 100 else ("+" if level >= 50 else "")
            members[user_id] = C.Member(name=user_id, display=C.clean_name(user.display_name or user_id), role=role)
        return members

    def _refresh_rooms(self) -> None:
        nio = self.nio
        if nio is None:
            return
        for room_id, room in list(nio.rooms.items())[:MAX_ROOMS]:
            title = room.display_name or room_id
            fields = dict(topic=room.topic or "", encryption=self._room_encryption(room),
                          members=self._members(room))
            if self.conversation(room_id) is None:
                self._add_conversation(room_id, self._room_kind(room), title, **fields)
            else:
                self._update_conversation(room_id, title=title, **fields)
        for room_id, room in list(nio.invited_rooms.items())[:100]:
            if room_id in self._invites_asked:
                continue
            self._invites_asked.add(room_id)
            inviter = getattr(room, "inviter", "") or ""
            self.request.emit(InviteRequest(room_id, C.clean_name(room.display_name or room_id), C.clean_name(inviter)))

    # -- events ------------------------------------------------------------------------------
    def _register_callbacks(self) -> None:
        from nio import (
            KeyVerificationCancel,
            KeyVerificationKey,
            KeyVerificationMac,
            KeyVerificationStart,
            MegolmEvent,
            RoomEncryptionEvent,
            RoomMemberEvent,
            RoomMessageEmote,
            RoomMessageFile,
            RoomMessageImage,
            RoomMessageNotice,
            RoomMessageText,
            UnknownToDeviceEvent,
        )

        nio = self.nio
        guard = self._guarded
        nio.add_event_callback(guard(self._on_text), (RoomMessageText, RoomMessageEmote, RoomMessageNotice))
        nio.add_event_callback(guard(self._on_file), (RoomMessageFile, RoomMessageImage))
        nio.add_event_callback(guard(self._on_undecryptable), MegolmEvent)
        nio.add_event_callback(guard(self._on_member), RoomMemberEvent)
        nio.add_event_callback(guard(self._on_encryption), RoomEncryptionEvent)
        nio.add_to_device_callback(guard(self._on_verification),
                                   (KeyVerificationStart, KeyVerificationKey, KeyVerificationMac,
                                    KeyVerificationCancel))
        nio.add_to_device_callback(guard(self._on_unknown_to_device), UnknownToDeviceEvent)

    @staticmethod
    def _guarded(callback):
        """*callback* for nio, never raising: nio does not catch a
        callback's exception, and one escaping sync() after nio stored the
        batch token loses every message and room key of that batch. The
        events are other users' (to-device ones from anyone)."""
        import functools
        import inspect

        @functools.wraps(callback)
        async def guarded(*args):
            try:
                result = callback(*args)
                if inspect.isawaitable(result):
                    await result
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - logged, the sync goes on
                log.exception("Matrix: handling an event failed")

        return guarded

    def _ensure_room(self, room) -> str:
        if self.conversation(room.room_id) is None:
            self._add_conversation(room.room_id, self._room_kind(room), room.display_name or room.room_id,
                                   topic=room.topic or "", encryption=self._room_encryption(room),
                                   members=self._members(room))
        return room.room_id

    def _message_encryption(self, room, event) -> str:
        if getattr(event, "decrypted", False):
            return C.ENC_E2E if getattr(event, "verified", False) else C.ENC_E2E_UNTRUSTED
        return C.ENC_TRANSPORT

    async def _on_text(self, room, event) -> None:
        from nio import RoomMessageEmote, RoomMessageNotice

        key = self._ensure_room(room)
        kind = C.KIND_ACTION if isinstance(event, RoomMessageEmote) else (
            C.KIND_NOTICE if isinstance(event, RoomMessageNotice) else C.KIND_MESSAGE)
        sender = room.user_name(event.sender) or event.sender
        self._add_message(C.ChatMessage(
            conversation=key, sender=sender, text=event.body or "", kind=kind,
            timestamp=(event.server_timestamp or time.time() * 1000) / 1000,
            outgoing=event.sender == self.user_id, encryption=self._message_encryption(room, event),
            message_id=event.event_id or ""), highlight_words=[self.user_id, room.user_name(self.user_id) or ""])

    async def _on_file(self, room, event) -> None:
        key = self._ensure_room(room)
        sender = room.user_name(event.sender) or event.sender
        self._add_message(C.ChatMessage(
            conversation=key, sender=sender, kind=C.KIND_SYSTEM,
            text=f"{sender} sent a file: {event.body or 'attachment'} (not downloaded)",
            timestamp=(event.server_timestamp or 0) / 1000 or time.time(),
            encryption=self._message_encryption(room, event), message_id=event.event_id or ""))

    async def _on_undecryptable(self, room, event) -> None:
        key = self._ensure_room(room)
        sender = room.user_name(event.sender) or event.sender
        self._add_message(C.ChatMessage(
            conversation=key, sender=sender, text="(this message could not be decrypted - its key "
            "was not shared with this device; asking your other devices for it)",
            timestamp=(event.server_timestamp or 0) / 1000 or time.time(), encryption=C.ENC_FAILED,
            message_id=event.event_id or ""))
        session = getattr(event, "session_id", "")
        if session and session not in self._room_keys_asked and len(self._room_keys_asked) < 10_000:
            self._room_keys_asked.add(session)
            try:
                await self.nio.request_room_key(event)
            except Exception:  # noqa: BLE001 - a request already pending
                pass

    async def _on_member(self, room, event) -> None:
        if room.room_id not in self.nio.rooms:
            return
        key = self._ensure_room(room)
        self._update_conversation(key, members=self._members(room), encryption=self._room_encryption(room))
        name = C.clean_name(event.content.get("displayname") or event.state_key or "")
        membership = event.membership
        prev = event.prev_membership
        if membership == "join" and prev != "join":
            self._note(key, f"{name} joined")
        elif membership == "leave" and prev == "join":
            self._note(key, f"{name} left")
        elif membership == "invite":
            self._note(key, f"{name} was invited")
        elif membership == "ban":
            self._note(key, f"{name} was banned")

    async def _on_encryption(self, room, event) -> None:
        key = self._ensure_room(room)
        self._update_conversation(key, encryption=self._room_encryption(room))
        self._note(key, "End-to-end encryption is on in this room.")

    # -- sending ------------------------------------------------------------------------------
    def _require_online(self):
        if self.nio is None or self.state != C.STATE_ONLINE:
            raise C.ChatError("Not connected.")
        return self.nio

    async def _send_content(self, key: str, content: dict) -> None:
        from nio import OlmUnverifiedDeviceError, RoomSendResponse

        nio = self._require_online()
        room = nio.rooms.get(key)
        if room is None:
            raise C.ChatError("Not in this room.")
        ignore = self.unverified == UNVERIFIED_WARN
        try:
            response = await nio.room_send(key, "m.room.message", content, ignore_unverified_devices=ignore)
        except OlmUnverifiedDeviceError as exc:
            device = getattr(exc, "device", None)
            who = f"{device.user_id} ({device.id})" if device is not None else "a member"
            raise C.ChatError(f"Not sent: {who} has a device nobody verified. Verify, ignore or "
                              "blacklist it (Encryption…), or allow unverified devices in the account.")
        if not isinstance(response, RoomSendResponse):
            raise C.ChatError(f"Not sent: {getattr(response, 'message', response)}")

    async def _send_text(self, key: str, text: str) -> None:
        if self.conversation(key) is None or key == self.server_key:
            raise C.ChatError("This is the account's window - choose a room.")
        await self._send_content(key, {"msgtype": "m.text", "body": text})

    async def _join(self, target: str) -> None:
        from nio import JoinResponse

        nio = self._require_online()
        target = target.split()[0] if target.split() else ""
        if not _ROOM_REF.fullmatch(target):
            raise C.ChatError(f"{target!r} is not a room address (#room:server or !id:server).")
        response = await nio.join(target)
        if not isinstance(response, JoinResponse):
            raise C.ChatError(f"Could not join {target}: {getattr(response, 'message', response)}")
        self._note(self.server_key, f"Joined {target}.")

    async def _open_direct(self, target: str) -> None:
        from nio import RoomCreateResponse, RoomPreset

        nio = self._require_online()
        user = target.split()[0] if target.split() else ""
        if not _USER_ID.fullmatch(user):
            raise C.ChatError(f"{user!r} is not a Matrix user id (@name:server).")
        for room_id, room in nio.rooms.items():
            if self._room_kind(room) == C.CONV_DIRECT and user in room.users:
                self._ensure_room(room)
                return
        response = await nio.room_create(
            is_direct=True, invite=[user], preset=RoomPreset.trusted_private_chat,
            initial_state=[{"type": "m.room.encryption", "state_key": "",
                            "content": {"algorithm": "m.megolm.v1.aes-sha2"}}])
        if not isinstance(response, RoomCreateResponse):
            raise C.ChatError(f"Could not start a chat with {user}: {getattr(response, 'message', response)}")
        self._note(self.server_key, f"Started an encrypted chat with {user}.")

    async def _leave(self, key: str) -> None:
        nio = self._require_online()
        await nio.room_leave(key)
        await nio.room_forget(key)
        self._remove_conversation(key)

    # -- devices and trust --------------------------------------------------------------------
    def own_device(self) -> DeviceInfo | None:
        nio = self.nio
        if nio is None or nio.olm is None:
            return None
        return DeviceInfo(self.user_id, nio.device_id, "this device",
                          nio.olm.account.identity_keys["ed25519"], "verified", own=True)

    def devices(self, user_id: str) -> list[DeviceInfo]:
        nio = self.nio
        if nio is None or nio.olm is None:
            return []
        out = []
        for device in nio.device_store.active_user_devices(user_id):
            if user_id == self.user_id and device.id == nio.device_id:
                continue
            trust = ("verified" if device.verified else "blacklisted" if device.blacklisted
                     else "ignored" if device.ignored else "unset")
            out.append(DeviceInfo(user_id, device.id, C.clean_name(device.display_name or ""),
                                  device.ed25519, trust))
        return out

    def room_devices(self, key: str) -> list[DeviceInfo]:
        nio = self.nio
        room = nio.rooms.get(key) if nio is not None else None
        if room is None:
            return []
        out = []
        for user_id in sorted(room.users)[:500]:
            out.extend(self.devices(user_id))
        return out

    def _device(self, user_id: str, device_id: str):
        nio = self.nio
        if nio is None:
            raise C.ChatError("Not connected.")
        device = nio.device_store[user_id].get(device_id) if user_id in nio.device_store.users else None
        if device is None:
            raise C.ChatError(f"{user_id} has no device {device_id}.")
        return device

    def set_trust(self, user_id: str, device_id: str, trust: str) -> None:
        """"verified" (the user compared the fingerprint), "blacklisted",
        "ignored" or "unset"."""
        self.runner.submit(self._set_trust(user_id, device_id, trust),
                           on_error=lambda e: self._error_in(self.server_key, e))

    async def _set_trust(self, user_id: str, device_id: str, trust: str) -> None:
        nio = self._require_online()
        device = self._device(user_id, device_id)
        if trust == "verified":
            nio.verify_device(device)
        elif trust == "blacklisted":
            nio.blacklist_device(device)
        elif trust == "ignored":
            nio.ignore_device(device)
        else:
            nio.unverify_device(device)
            nio.unblacklist_device(device)
            nio.unignore_device(device)
        self._refresh_rooms()
        self._note(self.server_key, f"{user_id} {device_id}: {trust}.")

    # -- interactive verification (SAS) ---------------------------------------------------------
    def verify(self, user_id: str, device_id: str = "") -> None:
        """Ask *user_id*'s device (all of them without *device_id*) to verify."""
        self.runner.submit(self._request_verification(user_id, device_id),
                           on_error=lambda e: self._error_in(self.server_key, e))

    async def _request_verification(self, user_id: str, device_id: str) -> None:
        from nio import ToDeviceMessage

        nio = self._require_online()
        if user_id not in nio.device_store.users:
            await nio.keys_query()
        devices = [d for d in nio.device_store.active_user_devices(user_id)
                   if not (user_id == self.user_id and d.id == nio.device_id)]
        if device_id:
            devices = [d for d in devices if d.id == device_id]
        if not devices:
            raise C.ChatError(f"{user_id} has no device to verify" + (f" called {device_id}." if device_id else "."))
        txid = secrets.token_hex(16)
        self._requested[txid] = (user_id, tuple(d.id for d in devices))
        self._accepted.add(txid)
        content = {"from_device": nio.device_id, "methods": ["m.sas.v1"], "transaction_id": txid,
                   "timestamp": int(time.time() * 1000)}
        for device in devices:
            await nio.to_device(ToDeviceMessage("m.key.verification.request", user_id, device.id, content))
        self._note(self.server_key, f"Asked {user_id} to verify - accept it on the other device.")
        asyncio.get_running_loop().call_later(VERIFY_TIMEOUT, self._requested.pop, txid, None)

    async def _on_unknown_to_device(self, event) -> None:
        source = getattr(event, "source", {}) or {}
        kind = source.get("type", "")
        content = source.get("content", {}) or {}
        txid = str(content.get("transaction_id", ""))[:100]
        if not txid:
            return
        if kind == "m.key.verification.request":
            methods = content.get("methods", [])
            if not isinstance(methods, list) or "m.sas.v1" not in methods:
                return
            sent = content.get("timestamp", 0)
            if isinstance(sent, (int, float)) and abs(time.time() * 1000 - sent) > VERIFY_TIMEOUT * 1000:
                return  # an old request, delivered late
            device_id = str(content.get("from_device", ""))[:100]
            name = ""
            try:
                name = self._device(event.sender, device_id).display_name or ""
            except C.ChatError:
                if self.nio.should_query_keys:
                    await self.nio.keys_query()
            self.request.emit(VerificationRequest(event.sender, device_id, txid, C.clean_name(name)))
        elif kind == "m.key.verification.ready":
            await self._on_ready(event.sender, str(content.get("from_device", "")), txid)
        elif kind == "m.key.verification.done":
            return

    async def _on_ready(self, user_id: str, device_id: str, txid: str) -> None:
        """The other device accepted our request: start the SAS on it, and
        tell our other target devices the request is taken."""
        from nio import ToDeviceMessage
        from nio.crypto import Sas

        asked = self._requested.pop(txid, None)
        if asked is None or asked[0] != user_id or device_id not in asked[1]:
            return
        nio = self.nio
        for other in asked[1]:
            if other != device_id:
                await nio.to_device(ToDeviceMessage("m.key.verification.cancel", user_id, other, {
                    "transaction_id": txid, "code": "m.accepted", "reason": "Verified on another device"}))
        device = self._device(user_id, device_id)
        sas = Sas(self.user_id, nio.device_id, nio.olm.account.identity_keys["ed25519"], device,
                  transaction_id=txid)
        nio.olm.key_verifications[txid] = sas
        await nio.to_device(sas.start_verification())

    async def _on_verification(self, event) -> None:
        from nio import KeyVerificationCancel, KeyVerificationKey, KeyVerificationMac, KeyVerificationStart

        nio = self.nio
        txid = event.transaction_id
        sas = nio.key_verifications.get(txid)
        if isinstance(event, KeyVerificationStart):
            if sas is None or "emoji" not in event.short_authentication_string:
                return
            if txid in self._accepted:
                await nio.accept_key_verification(txid)
            else:
                # the older direct start, without a request first: ask
                self.request.emit(VerificationRequest(event.sender, event.from_device, txid))
        elif isinstance(event, KeyVerificationKey):
            if sas is None or txid in self._sas_shown:
                return
            self._sas_shown.add(txid)
            self.request.emit(SasRequest(sas.other_olm_device.user_id, sas.other_olm_device.id, txid,
                                         sas.get_emoji(), sas.get_decimals()))
        elif isinstance(event, KeyVerificationMac):
            if sas is not None and sas.verified:
                await self._done(sas)
        elif isinstance(event, KeyVerificationCancel):
            if sas is None and txid not in self._accepted and txid not in self._requested:
                return  # not a verification of ours: anyone could send it
            self._accepted.discard(txid)
            self.request.emit(VerificationResult(event.sender, "", txid, False, C.clean_text(event.reason or "", 200)))

    async def _done(self, sas) -> None:
        from nio import ToDeviceMessage

        device = sas.other_olm_device
        await self.nio.to_device(ToDeviceMessage("m.key.verification.done", device.user_id, device.id,
                                                 {"transaction_id": sas.transaction_id}))
        self._accepted.discard(sas.transaction_id)
        self._refresh_rooms()
        self.request.emit(VerificationResult(device.user_id, device.id, sas.transaction_id, True))
        self._note(self.server_key, f"Verified {device.user_id}'s device {device.id}.")

    async def _answer(self, request, answer) -> None:
        from nio import ToDeviceMessage

        nio = self._require_online()
        if isinstance(request, InviteRequest):
            if answer:
                await nio.join(request.room_id)
            else:
                await nio.room_leave(request.room_id)
            return
        if isinstance(request, VerificationRequest):
            txid = request.transaction_id
            sas = nio.key_verifications.get(txid)
            if not answer:
                if sas is not None:
                    await nio.cancel_key_verification(txid, reject=True)
                else:
                    await nio.to_device(ToDeviceMessage("m.key.verification.cancel", request.user_id,
                                                        request.device_id, {"transaction_id": txid,
                                                                            "code": "m.user", "reason": "Declined"}))
                return
            self._accepted.add(txid)
            if sas is not None:            # older flow: the start is already here
                await nio.accept_key_verification(txid)
            else:
                await nio.to_device(ToDeviceMessage("m.key.verification.ready", request.user_id, request.device_id, {
                    "from_device": nio.device_id, "methods": ["m.sas.v1"], "transaction_id": txid}))
            return
        if isinstance(request, SasRequest):
            txid = request.transaction_id
            if answer:
                await nio.confirm_short_auth_string(txid)
                sas = nio.key_verifications.get(txid)
                if sas is not None and sas.verified:
                    await self._done(sas)
            else:
                await nio.cancel_key_verification(txid, reject=False)
                self._accepted.discard(txid)

    # -- keys ---------------------------------------------------------------------------------
    def export_keys(self, path: str, passphrase: str) -> None:
        self.runner.submit(self._export(path, passphrase), on_error=lambda e: self._error_in(self.server_key, e))

    async def _export(self, path: str, passphrase: str) -> None:
        nio = self._require_online()
        if len(passphrase) < 8:
            raise C.ChatError("The passphrase needs at least 8 characters.")
        await nio.export_keys(path, passphrase)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self._note(self.server_key, f"Room keys exported to {path}.")

    def import_keys(self, path: str, passphrase: str) -> None:
        self.runner.submit(self._import(path, passphrase), on_error=lambda e: self._error_in(self.server_key, e))

    async def _import(self, path: str, passphrase: str) -> None:
        nio = self._require_online()
        if os.path.getsize(path) > 200 * 1024 * 1024:
            raise C.ChatError("That key file is too large.")
        try:
            await nio.import_keys(path, passphrase)
        except Exception as exc:  # noqa: BLE001 - nio raises EncryptionError on a wrong passphrase
            raise C.ChatError(f"Could not import the keys (wrong passphrase?): {C.error_text(exc)}")
        self._note(self.server_key, f"Room keys imported from {path}.")

    # -- commands ------------------------------------------------------------------------------
    HELP = (
        "/join #room:server - join a room",
        "/leave - leave this room",
        "/invite @user:server - invite to this room",
        "/topic text, /nick name (your display name), /me text, /notice text",
        "/encrypt - turn on end-to-end encryption in this room (cannot be undone)",
        "/devices [@user] - the devices and their trust",
        "/verify @user [device] - verify interactively (compare emoji)",
        "/trust @user device, /untrust, /blacklist, /ignore - set a device's trust",
        "/export-keys FILE PASSPHRASE, /import-keys FILE PASSPHRASE - room keys",
    )

    async def _command(self, key: str, name: str, args: str) -> None:
        from nio import RoomPutStateResponse

        if name == "help":
            for line in self.HELP:
                self._note(key, line)
            return
        nio = self._require_online()
        in_room = key != self.server_key and key in nio.rooms
        parts = args.split()
        if name == "join":
            await self._join(args)
        elif name == "leave":
            if not in_room:
                raise C.ChatError("/leave works in a room.")
            await self._leave(key)
        elif name == "invite":
            if not in_room or not parts or not _USER_ID.fullmatch(parts[0]):
                raise C.ChatError("/invite @user:server, in a room.")
            await nio.room_invite(key, parts[0])
        elif name == "topic":
            if not in_room:
                raise C.ChatError("/topic works in a room.")
            await nio.room_put_state(key, "m.room.topic", {"topic": args})
        elif name == "nick":
            if not args:
                raise C.ChatError("/nick needs a name.")
            await nio.set_displayname(args[:100])
        elif name in ("me", "notice"):
            if not in_room or not args:
                raise C.ChatError(f"/{name} text, in a room.")
            await self._send_content(key, {"msgtype": "m.emote" if name == "me" else "m.notice", "body": args})
        elif name == "encrypt":
            if not in_room:
                raise C.ChatError("/encrypt works in a room.")
            if nio.rooms[key].encrypted:
                self._note(key, "This room is already encrypted.")
                return
            response = await nio.room_put_state(key, "m.room.encryption", {"algorithm": "m.megolm.v1.aes-sha2"})
            if not isinstance(response, RoomPutStateResponse):
                raise C.ChatError(f"Could not turn on encryption: {getattr(response, 'message', response)}")
        elif name == "devices":
            users = [parts[0]] if parts else (sorted(nio.rooms[key].users) if in_room else [self.user_id])
            own = self.own_device()
            if own is not None:
                self._note(key, f"This device {own.device_id}: {fingerprint_text(own.fingerprint)}")
            for user in users[:100]:
                for d in self.devices(user):
                    self._note(key, f"{d.user_id} {d.device_id} {d.name!r}: {d.trust} - {fingerprint_text(d.fingerprint)}")
        elif name == "verify":
            if not parts or not _USER_ID.fullmatch(parts[0]):
                raise C.ChatError("/verify @user:server [device]")
            await self._request_verification(parts[0], parts[1] if len(parts) > 1 else "")
        elif name in ("trust", "untrust", "blacklist", "ignore"):
            if len(parts) != 2 or not _USER_ID.fullmatch(parts[0]):
                raise C.ChatError(f"/{name} @user:server DEVICE")
            trust = {"trust": "verified", "untrust": "unset", "blacklist": "blacklisted", "ignore": "ignored"}[name]
            await self._set_trust(parts[0], parts[1], trust)
        elif name in ("export-keys", "import-keys"):
            path, _, passphrase = args.partition(" ")
            if not path or not passphrase:
                raise C.ChatError(f"/{name} FILE PASSPHRASE")
            path = os.path.expanduser(path)
            await (self._export(path, passphrase) if name == "export-keys" else self._import(path, passphrase))
        else:
            self._note(key, f"Unknown command: /{name} (/help lists them)", C.KIND_ERROR)


# --- the account form ----------------------------------------------------------------------

FIELDS = (
    C.FieldSpec("homeserver", "Homeserver", required=True, help="https://matrix.org"),
    C.FieldSpec("user", "User", required=True, help="@name:server or name"),
    C.FieldSpec("password", "Password", "password", secret=True,
                help="Needed for the first sign-in; kept in the keyring"),
    C.FieldSpec("device_name", "Device name", default="axross"),
    C.FieldSpec("unverified", "Devices nobody verified", "choice", UNVERIFIED_WARN,
                ((UNVERIFIED_WARN, "Send to them, but warn"),
                 (UNVERIFIED_BLOCK, "Send nothing until each is verified, blacklisted or ignored"))),
    C.FieldSpec("proxy", "Proxy", "choice", "default", C.PROXY_CHOICES),
)


def validate(settings: dict) -> str | None:
    homeserver = str(settings.get("homeserver", "")).strip()
    if not homeserver:
        return "The homeserver is missing."
    if homeserver.startswith("http://") and not loopback_http(homeserver):
        return "The homeserver must be reached over https://."
    user = full_user_id(str(settings.get("user", "")), homeserver if "://" in homeserver else "https://" + homeserver)
    if not _USER_ID.fullmatch(user):
        return f"{user!r} is not a Matrix user id (@name:server)."
    return None


def apply_server(entry, values: dict) -> dict:
    """What choosing a public homeserver (core.chat_servers.ServerEntry)
    fills in: its client address and, when a user name is typed, the user
    id on the server's name (``@name:example.org`` even when the client
    address is ``matrix.example.org``)."""
    port = f":{entry.port}" if entry.port and entry.port != 443 else ""
    out = {"homeserver": f"https://{entry.host}{port}"}
    user = str(values.get("user", "") or "").strip()
    local = user[1:].split(":", 1)[0] if user.startswith("@") else user.split(":", 1)[0]
    if local:
        out["user"] = f"@{local}:{entry.domain or entry.host}"
    return out


PROTOCOL = C.Protocol(
    name="matrix", title="Matrix", fields=FIELDS, make_client=MatrixClient,
    join_label="Join Room…", join_prompt="Room (#room:server or !id:server):",
    direct_label="Direct Chat…", direct_prompt="User (@name:server):", validate=validate,
    server_field="homeserver", apply_server=apply_server, room_list_label="Room Directory",
)
