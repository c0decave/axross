"""IRC for the chat panel (resources/extensions/irc.py): RFC 1459/2812 with
the IRCv3 parts that matter for a client.

* TLS by default, certificate checked; a self-signed server is trusted only
  by its pinned SHA-256 fingerprint (asked once, kept in the account).
  Plain TCP only when chosen.
* Login: SASL PLAIN, SCRAM-SHA-256 (RFC 7677, the server proves it knows
  the password too) or EXTERNAL (a client certificate, CertFP); a server
  password; NickServ IDENTIFY as a fallback for networks without SASL.
  A required SASL login that fails ends the connection - the password is
  never sent another way.
* IRCv3 capabilities: sasl, server-time, message-tags, multi-prefix,
  away-notify, account-notify, extended-join, chghost, cap-notify.
* Channels with topic, members and their status (op, voice ...), modes,
  kicks; private queries; /me; notices; nick changes; MOTD and server
  replies in the server conversation.
* Lines split by bytes to fit the 512-byte limit (UTF-8 safe), sent with a
  flood limit; CR/LF in a parameter can never start a second command.
* Keep-alive PING and a reconnect with a growing pause; channels rejoined.

IRC itself has no end-to-end encryption: what is sent in a channel or a
query is readable by the servers of the network. The panel says so.

CTCP requests (VERSION, TIME, PING ...) are not answered - they tell other
users which program and time zone you use.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import ssl
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime

from core import chat as C

log = logging.getLogger(__name__)

#: Longest line read from the server (512 + 8191 bytes of tags); longer
#: lines are dropped.
MAX_LINE = 512 + 8191
#: Bytes of one line we send, CR LF included.
LINE_LIMIT = 512
#: Flood limit: this many lines at once, then one per FLOOD_INTERVAL seconds.
FLOOD_BURST = 5
FLOOD_INTERVAL = 0.7
#: Seconds without anything from the server before we PING, and then
#: before the connection counts as dead.
PING_AFTER = 120.0
PING_TIMEOUT = 60.0
#: Pauses before reconnect attempts (the last one repeats).
RECONNECT_DELAYS = (5, 15, 30, 60, 120, 300)
#: The longest SASL challenge accepted (base64, sent in 400-byte pieces).
MAX_SASL_CHALLENGE = 64 * 1024
#: NAMES lists open at once (353 without 366).
MAX_NAMES_PENDING = 200
#: NICK attempts during the login before giving up (433 / 432 each time).
MAX_NICK_TRIES = 10
#: Lines a user may paste as one message.
MAX_PASTE_LINES = 20
#: Seconds a channel list may pause before it counts as broken off.
LIST_TIMEOUT = 120.0
WANTED_CAPS = ("sasl", "server-time", "message-tags", "multi-prefix", "away-notify",
               "account-notify", "extended-join", "chghost", "cap-notify")

TLS_VERIFY = "verify"
TLS_PINNED = "pinned"
TLS_OFF = "off"
SASL_NONE = "none"
SASL_PLAIN = "PLAIN"
SASL_SCRAM = "SCRAM-SHA-256"
SASL_EXTERNAL = "EXTERNAL"


# --- lines --------------------------------------------------------------------------

@dataclass
class Line:
    command: str
    params: list[str] = field(default_factory=list)
    prefix: str = ""
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def nick(self) -> str:
        return self.prefix.split("!", 1)[0].split("@", 1)[0]

    def param(self, index: int, default: str = "") -> str:
        return self.params[index] if index < len(self.params) else default


_TAG_UNESCAPE = {":": ";", "s": " ", "\\": "\\", "r": "\r", "n": "\n"}


def _unescape_tag(value: str) -> str:
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            out.append(_TAG_UNESCAPE.get(value[i + 1], value[i + 1]))
            i += 2
            continue
        if ch != "\\":
            out.append(ch)
        i += 1
    return "".join(out)


def parse_line(raw: str) -> Line | None:
    """One line from the server (without CR LF), or None if it is not one."""
    raw = raw.rstrip("\r\n")
    if not raw or "\x00" in raw:
        return None
    tags: dict[str, str] = {}
    if raw.startswith("@"):
        tag_part, _, raw = raw[1:].partition(" ")
        for item in tag_part.split(";")[:64]:
            if not item:
                continue
            key, _, value = item.partition("=")
            tags[key[:256]] = _unescape_tag(value)[:4096]
        raw = raw.lstrip(" ")
    prefix = ""
    if raw.startswith(":"):
        prefix, _, raw = raw[1:].partition(" ")
        raw = raw.lstrip(" ")
    trailing = None
    if " :" in raw:
        raw, trailing = raw.split(" :", 1)
    elif raw.startswith(":"):
        raw, trailing = "", raw[1:]
    parts = [p for p in raw.split(" ") if p]
    if not parts:
        return None
    command = parts[0].upper()
    if not re.fullmatch(r"[A-Z]{1,32}|\d{3}", command):
        return None
    params = parts[1:]
    if trailing is not None:
        params.append(trailing)
    return Line(command=command, params=params[:32], prefix=prefix, tags=tags)


class LineError(ValueError):
    pass


def format_line(command: str, *params: str) -> str:
    """A line to send. Only the last parameter may contain spaces or start
    with ":"; no parameter may contain CR, LF or NUL."""
    for p in params:
        if any(c in p for c in "\r\n\x00"):
            raise LineError("a line break in an IRC parameter")
    for p in params[:-1]:
        if not p or " " in p or p.startswith(":"):
            raise LineError(f"invalid IRC parameter {p!r}")
    if params:
        last = params[-1]
        if not last or " " in last or last.startswith(":"):
            return " ".join((command,) + params[:-1] + (":" + last,))
    return " ".join((command,) + params)


def split_text(text: str, budget: int) -> list[str]:
    """*text* cut into pieces of at most *budget* UTF-8 bytes, at spaces
    where possible, never inside a character."""
    budget = max(budget, 16)
    out = []
    while text:
        data = text.encode("utf-8")
        if len(data) <= budget:
            out.append(text)
            break
        cut = data[:budget]
        piece = cut.decode("utf-8", errors="ignore")
        space = piece.rfind(" ")
        if space > len(piece) // 2:
            piece = piece[:space]
        out.append(piece)
        text = text[len(piece):].lstrip(" ")
    return out


# --- case mapping -------------------------------------------------------------------

def casefold(name: str, mapping: str = "rfc1459") -> str:
    name = name.lower() if mapping == "ascii" else name.lower()
    if mapping == "rfc1459":
        name = name.translate(str.maketrans("[]\\~", "{}|^"))
    elif mapping == "strict-rfc1459":
        name = name.translate(str.maketrans("[]\\", "{}|"))
    return name


_NICK = re.compile(r"[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]{0,63}")


def valid_nick(nick: str) -> bool:
    return bool(_NICK.fullmatch(nick))


# --- SCRAM-SHA-256 (RFC 5802 / 7677) ------------------------------------------------------

class ScramError(Exception):
    pass


def _saslname(name: str) -> str:
    return name.replace("=", "=3D").replace(",", "=2C")


class Scram:
    """The client side of one SCRAM-SHA-256 exchange."""

    def __init__(self, username: str, password: str, nonce: str | None = None) -> None:
        self.username = unicodedata.normalize("NFKC", username)
        self.password = unicodedata.normalize("NFKC", password).encode("utf-8")
        self.nonce = nonce or base64.b64encode(secrets.token_bytes(24)).decode()
        self.first_bare = f"n={_saslname(self.username)},r={self.nonce}"
        self.server_signature = b""
        #: verify() accepted the server's signature: the server knows the password.
        self.verified = False

    def first(self) -> bytes:
        return ("n,," + self.first_bare).encode()

    def final(self, server_first: bytes) -> bytes:
        text = server_first.decode("utf-8")
        attrs = dict(item.split("=", 1) for item in text.split(",") if "=" in item)
        nonce, salt, iterations = attrs.get("r", ""), attrs.get("s", ""), attrs.get("i", "")
        if not nonce.startswith(self.nonce) or len(nonce) <= len(self.nonce):
            raise ScramError("the server's SCRAM nonce does not continue ours")
        try:
            iterations_n = int(iterations)
            salt_bytes = base64.b64decode(salt, validate=True)
        except (ValueError, TypeError) as exc:
            raise ScramError("the server's SCRAM challenge is malformed") from exc
        if not 4096 <= iterations_n <= 1_000_000:
            raise ScramError(f"the server asks for {iterations_n} SCRAM iterations")
        salted = hashlib.pbkdf2_hmac("sha256", self.password, salt_bytes, iterations_n)
        client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        stored_key = hashlib.sha256(client_key).digest()
        without_proof = f"c=biws,r={nonce}"
        auth_message = f"{self.first_bare},{text},{without_proof}".encode()
        signature = hmac.new(stored_key, auth_message, hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, signature))
        server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        self.server_signature = hmac.new(server_key, auth_message, hashlib.sha256).digest()
        return f"{without_proof},p={base64.b64encode(proof).decode()}".encode()

    def verify(self, server_final: bytes) -> None:
        text = server_final.decode("utf-8", errors="replace")
        attrs = dict(item.split("=", 1) for item in text.split(",") if "=" in item)
        if "e" in attrs:
            raise ScramError(f"the server refused the login ({attrs['e']})")
        try:
            got = base64.b64decode(attrs.get("v", ""), validate=True)
        except ValueError as exc:
            raise ScramError("the server's SCRAM signature is malformed") from exc
        if not self.server_signature or not hmac.compare_digest(got, self.server_signature):
            raise ScramError("the server could not prove it knows the password")
        self.verified = True


# --- requests to the user -------------------------------------------------------------

@dataclass
class CertificateRequest:
    """The server's certificate is not trusted: trust it by its fingerprint?"""
    host: str
    port: int
    fingerprint: str   # "AB:CD:..." SHA-256
    reason: str
    kind: str = "certificate"


def fingerprint_of(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def normalise_fingerprint(text: str) -> str:
    hexdigits = re.sub(r"[^0-9A-Fa-f]", "", text or "").upper()
    if len(hexdigits) != 64:
        return ""
    return ":".join(hexdigits[i:i + 2] for i in range(0, 64, 2))


# --- the client ----------------------------------------------------------------------

def _settings_int(settings: dict, key: str, default: int, low: int, high: int) -> int:
    try:
        value = int(settings.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if low <= value <= high else default


def autojoin_list(settings: dict) -> list[tuple[str, str]]:
    """(channel, key) of the account's "Join at start" lines."""
    out = []
    raw = settings.get("autojoin", "")
    lines = raw if isinstance(raw, list) else str(raw).splitlines()
    for line in lines[:200]:
        parts = str(line).split()
        if parts and parts[0][:1] in "#&+!":
            out.append((parts[0][:200], parts[1][:100] if len(parts) > 1 else ""))
    return out


class IrcClient(C.ChatClient):
    protocol = "irc"
    supports_room_list = True
    commands = ("join", "part", "msg", "query", "me", "notice", "nick", "topic", "away", "back",
                "whois", "names", "mode", "kick", "invite", "quote", "close", "help")

    def __init__(self, account: C.Account, parent=None) -> None:
        super().__init__(account, parent)
        s = account.settings
        self.host = str(s.get("server", "")).strip()
        self.tls_mode = s.get("tls", TLS_VERIFY) if s.get("tls") in (TLS_VERIFY, TLS_PINNED, TLS_OFF) else TLS_VERIFY
        self.port = _settings_int(s, "port", 6667 if self.tls_mode == TLS_OFF else 6697, 1, 65535)
        self.wanted_nick = str(s.get("nick", "")).strip() or "axross"
        self.nick = self.wanted_nick
        self.casemapping = "rfc1459"
        self.chantypes = "#&"
        self.prefix_modes = "ov"
        self.prefix_chars = "@+"
        self.chanmodes = ("beI", "k", "l", "imnpst")
        self.linelen = LINE_LIMIT
        self.caps: set[str] = set()
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._tasks: list[asyncio.Task] = []
        self._send_queue: asyncio.Queue | None = None
        self._want_online = False
        self._registered: asyncio.Event | None = None
        self._sasl_done: asyncio.Future | None = None
        self._scram: Scram | None = None
        self._names_pending: dict[str, dict[str, C.Member]] = {}
        self._last_heard = time.monotonic()
        self._attempt = 0
        self._channels_wanted: dict[str, str] = {}  # folded name -> key
        self._channel_names: dict[str, str] = {}    # folded name -> as typed
        self._cap_offer: set[str] = set()
        self._sasl_mechs: set[str] | None = None
        self._sasl_buffer = ""
        #: the LIST being read: (request id, entries not yet handed on, count)
        self._listing: list | None = None
        self._list_timeout: asyncio.TimerHandle | None = None
        self.highlight_words: list[str] = []
        raw_words = s.get("highlight", "")
        for word in (raw_words if isinstance(raw_words, list) else str(raw_words).splitlines()):
            if str(word).strip():
                self.highlight_words.append(str(word).strip()[:100])
        self._update_conversation(self.server_key, title=account.name or self.host,
                                  encryption=C.ENC_NONE if self.tls_mode == TLS_OFF else C.ENC_TRANSPORT)

    # -- helpers ------------------------------------------------------------------------
    def fold(self, name: str) -> str:
        return casefold(name, self.casemapping)

    def is_channel(self, name: str) -> bool:
        return bool(name) and name[0] in self.chantypes

    @property
    def link_encryption(self) -> str:
        return C.ENC_NONE if self.tls_mode == TLS_OFF else C.ENC_TRANSPORT

    def _ssl_context(self) -> ssl.SSLContext | None:
        if self.tls_mode == TLS_OFF:
            return None
        from core.tls_context import client_tls_context

        if self.tls_mode == TLS_PINNED:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # the pin below is the check
        else:
            ctx = client_tls_context(True, label="IRC")
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        cert = str(self.account.settings.get("client_cert", "")).strip()
        if cert:
            key = str(self.account.settings.get("client_key", "")).strip() or None
            ctx.load_cert_chain(os.path.expanduser(cert), os.path.expanduser(key) if key else None)
        return ctx

    # -- connect / disconnect -----------------------------------------------------------
    async def _connect(self) -> None:
        if not self.host:
            raise C.ChatError("The account has no server.")
        self._want_online = True
        self._attempt = 0
        self._cancel_reconnect()
        await self._open()

    async def _open(self) -> None:
        if self._writer is not None or self._tasks:
            await self._close()  # never two connections feeding one client
        self._set_state(C.STATE_CONNECTING, f"{self.host}:{self.port}")
        self._note(self.server_key, f"Connecting to {self.host}:{self.port}"
                   + (" (TLS)" if self.tls_mode != TLS_OFF else " (not encrypted)") + "…")
        ctx = self._ssl_context()
        proxy_mode = "none" if self.account.settings.get("proxy") == "none" else "default"
        try:
            reader, writer = await C.open_stream(self.host, self.port, ssl_context=ctx,
                                                 server_hostname=self.host, proxy_mode=proxy_mode,
                                                 protocol="irc", limit=MAX_LINE + 2)
        except ssl.SSLCertVerificationError as exc:
            await self._offer_certificate(str(exc.verify_message or exc))
            raise C.ChatError(f"The server's certificate is not trusted: {exc.verify_message or exc}")
        if ctx is not None:
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True) or b""
            got = fingerprint_of(der)
            if self.tls_mode == TLS_PINNED:
                pinned = normalise_fingerprint(str(self.account.settings.get("fingerprint", "")))
                if not pinned or not hmac.compare_digest(got, pinned):
                    writer.close()
                    self.request.emit(CertificateRequest(
                        self.host, self.port, got,
                        "The certificate is not the pinned one." if pinned else "No fingerprint is pinned."))
                    raise C.ChatError("The server's certificate does not match the pinned fingerprint "
                                      f"(it is {got}).")
            version = writer.get_extra_info("ssl_object").version()
            self._note(self.server_key, f"TLS {version}, certificate SHA-256 {got}")
            self._link_info = self._tls_link_info(writer.get_extra_info("ssl_object"), got)
        else:
            from core import conn_security as CS

            self._link_info = CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "IRC without TLS - cleartext - anyone "
                                              "on the network can read it, the password too", True)
        self._reader, self._writer = reader, writer
        self._cap_offer: set[str] = set()
        self._sasl_mechs: set[str] | None = None
        self._sasl_buffer = ""
        self._scram = None
        self._send_queue = asyncio.Queue(maxsize=10_000)
        self._registered = asyncio.Event()
        self.caps = set()
        self.nick = self.wanted_nick
        self._nick_tries = 0
        self._last_heard = time.monotonic()
        loop = asyncio.get_running_loop()
        self._sasl_done = loop.create_future()
        self._tasks = [asyncio.create_task(self._read_loop()), asyncio.create_task(self._write_loop()),
                       asyncio.create_task(self._keepalive())]
        try:
            await self._register()
        except BaseException:
            # A login that failed or timed out leaves no socket and no
            # loop behind (a late 001 would turn it "online" again).
            await self._close()
            raise

    def _tls_link_info(self, ssl_object, fingerprint: str):
        """The negotiated TLS of the connection for the security badge."""
        from core import conn_security as CS

        info = CS.tls_socket(ssl_object, verified=True, what="IRC",
                             extra=(f"Certificate SHA-256: {fingerprint}",))
        if info is not None and self.tls_mode == TLS_PINNED and info.level == CS.LEVEL_TLS:
            info = CS.SecurityInfo(info.level, info.summary.replace("certificate verified",
                                                                    "certificate pinned by its fingerprint"),
                                   True, info.details)
        return info

    def configured_link_security(self):
        from core import conn_security as CS

        if self.tls_mode == TLS_OFF:
            return CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "IRC without TLS - cleartext - anyone on the "
                                   "network can read it, the password too")
        how = "certificate pinned by its fingerprint" if self.tls_mode == TLS_PINNED else "certificate verified"
        return CS.SecurityInfo(CS.LEVEL_TLS, f"IRC over TLS, {how}")

    async def _offer_certificate(self, reason: str) -> None:
        """Fetch the untrusted certificate's fingerprint and ask the user."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            proxy_mode = "none" if self.account.settings.get("proxy") == "none" else "default"
            _, writer = await C.open_stream(self.host, self.port, ssl_context=ctx, server_hostname=self.host,
                                            proxy_mode=proxy_mode, protocol="irc")
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True) or b""
            writer.close()
        except Exception:  # noqa: BLE001 - the error is reported anyway
            return
        self.request.emit(CertificateRequest(self.host, self.port, fingerprint_of(der), reason))

    async def _register(self) -> None:
        s = self.account.settings
        server_password = C.account_secret(self.account, "server_password")
        self._raw("CAP", "LS", "302")
        if server_password:
            self._raw("PASS", server_password)
        self._raw("NICK", self.nick)
        user = str(s.get("username", "")).strip() or self.nick
        user = re.sub(r"[^A-Za-z0-9_.-]", "", user)[:16] or "axross"
        realname = str(s.get("realname", "")).strip() or self.nick
        self._raw("USER", user, "0", "*", realname)
        try:
            await asyncio.wait_for(self._registered.wait(), 60)
        except asyncio.TimeoutError:
            raise C.ChatError("The server did not finish the login within 60 s.")

    async def _disconnect(self) -> None:
        self._want_online = False
        self._cancel_reconnect()
        if self._writer is not None and not self._writer.is_closing():
            try:
                self._writer.write(b"QUIT :Leaving\r\n")
                await asyncio.wait_for(self._writer.drain(), 2)
            except Exception:  # noqa: BLE001 - closing anyway
                pass
        await self._close()
        self._mark_channels_left()

    def _spawn_lost(self, reason) -> None:
        """Start the reconnect after a lost connection - once: the read
        loop, the keepalive and a failed retry may all report the loss."""
        task = getattr(self, "_reconnect_task", None)
        if task is not None and not task.done() and task is not asyncio.current_task():
            return
        self._reconnect_task = asyncio.get_running_loop().create_task(self._lost(reason))

    def _cancel_reconnect(self) -> None:
        task = getattr(self, "_reconnect_task", None)
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()
        self._reconnect_task = None

    async def _close(self) -> None:
        current = asyncio.current_task()
        for task in self._tasks:
            if task is not current:
                task.cancel()
        self._tasks = []
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:  # noqa: BLE001
                pass
        self._reader = self._writer = None
        self._link_info = None
        if self._listing is not None:
            self._finish_list("The connection was closed.")

    def _mark_channels_left(self) -> None:
        for conv in self.conversations():
            if conv.kind == C.CONV_CHANNEL and conv.joined:
                self._update_conversation(conv.key, joined=False, members={})

    async def _lost(self, reason: str) -> None:
        await self._close()
        self._mark_channels_left()
        if not self._want_online:
            return
        delay = RECONNECT_DELAYS[min(self._attempt, len(RECONNECT_DELAYS) - 1)]
        self._attempt += 1
        self._note(self.server_key, f"Connection lost ({reason}). Reconnecting in {delay} s…", C.KIND_ERROR)
        self._set_state(C.STATE_CONNECTING, f"reconnecting in {delay} s")
        await asyncio.sleep(delay)
        if not self._want_online:
            return
        try:
            await self._open()
            self._attempt = 0
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - try again
            self._spawn_lost((C.error_text(exc)))

    # -- I/O ------------------------------------------------------------------------------
    def _raw(self, command: str, *params: str) -> None:
        """Queue one line (validated: a parameter cannot smuggle a second command)."""
        line = format_line(command, *params)
        data = line.encode("utf-8")
        if len(data) > LINE_LIMIT - 2:
            data = data[:LINE_LIMIT - 2].decode("utf-8", errors="ignore").encode("utf-8")
        if self._send_queue is None:
            raise C.ChatError("Not connected.")
        try:
            self._send_queue.put_nowait(data + b"\r\n")
        except asyncio.QueueFull:
            raise C.ChatError("Too much is waiting to be sent.")

    async def _write_loop(self) -> None:
        tokens = float(FLOOD_BURST)
        last = time.monotonic()
        assert self._send_queue is not None
        while True:
            data = await self._send_queue.get()
            now = time.monotonic()
            tokens = min(FLOOD_BURST, tokens + (now - last) / FLOOD_INTERVAL)
            last = now
            if tokens < 1:
                await asyncio.sleep((1 - tokens) * FLOOD_INTERVAL)
                tokens = 1
                last = time.monotonic()
            tokens -= 1
            writer = self._writer
            if writer is None:
                return
            writer.write(data)
            try:
                await writer.drain()
            except (ConnectionError, OSError) as exc:
                self._spawn_lost((C.error_text(exc)))
                return

    async def _read_loop(self) -> None:
        reader = self._reader
        assert reader is not None
        while True:
            try:
                data = await reader.readuntil(b"\n")
            except asyncio.LimitOverrunError as exc:
                # an over-long line: skip it to its end
                await reader.read(exc.consumed)
                try:
                    await reader.readuntil(b"\n")
                except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
                    pass
                continue
            except asyncio.IncompleteReadError:
                self._spawn_lost(("closed by the server"))
                return
            except (ConnectionError, OSError, ssl.SSLError) as exc:
                self._spawn_lost((C.error_text(exc)))
                return
            self._last_heard = time.monotonic()
            line = parse_line(data.decode("utf-8", errors="replace"))
            if line is None:
                continue
            try:
                await self._handle(line)
            except C.ChatError as exc:
                self._note(self.server_key, str(exc), C.KIND_ERROR)
                if isinstance(exc, _Fatal):
                    self._want_online = False
                    await self._close()
                    self._set_state(C.STATE_ERROR, str(exc))
                    return
            except Exception:  # noqa: BLE001 - one bad line must not end the session
                log.exception("IRC: handling %s failed", line.command)

    async def _keepalive(self) -> None:
        while True:
            await asyncio.sleep(15)
            idle = time.monotonic() - self._last_heard
            if idle > PING_AFTER + PING_TIMEOUT:
                self._spawn_lost(("no answer from the server"))
                return
            if idle > PING_AFTER:
                try:
                    self._raw("PING", f"axross-{int(time.time())}")
                except C.ChatError:
                    pass

    # -- what the server says ---------------------------------------------------------
    def _timestamp(self, line: Line) -> float:
        value = line.tags.get("time")
        if value:
            try:
                ts = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
                if abs(ts - time.time()) < 10 * 365 * 86400:
                    return ts
            except ValueError:
                pass
        return time.time()

    async def _handle(self, line: Line) -> None:
        handler = getattr(self, f"_on_{line.command.lower()}", None)
        if handler is not None:
            await handler(line)
        elif line.command.isdigit():
            self._numeric(line)

    async def _on_ping(self, line: Line) -> None:
        self._raw("PONG", line.param(0) or "axross")

    async def _on_pong(self, line: Line) -> None:
        return None

    async def _on_error(self, line: Line) -> None:
        self._note(self.server_key, f"Server: {line.param(0)}", C.KIND_ERROR)

    async def _on_cap(self, line: Line) -> None:
        sub = line.param(1).upper()
        if sub == "LS":
            more = line.param(2) == "*"
            offered = line.params[-1].split()
            for item in offered:
                self._cap_offer.add(item.split("=", 1)[0])
                if item.startswith("sasl="):
                    self._sasl_mechs = set(item.split("=", 1)[1].split(","))
            if more:
                return
            want = [c for c in WANTED_CAPS if c in self._cap_offer]
            if self._sasl_mechanism() == SASL_NONE and "sasl" in want:
                want.remove("sasl")
            if want:
                self._raw("CAP", "REQ", " ".join(want))
            else:
                await self._cap_end_or_fail()
        elif sub == "ACK":
            self.caps.update(c.lstrip("-~=") for c in line.params[-1].split())
            if "sasl" in self.caps and self._sasl_mechanism() != SASL_NONE:
                self._start_sasl()
            else:
                await self._cap_end_or_fail()
        elif sub == "NAK":
            await self._cap_end_or_fail()
        elif sub == "NEW":
            want = [c for c in line.params[-1].split() if c in WANTED_CAPS and c != "sasl"]
            if want:
                self._raw("CAP", "REQ", " ".join(want))
        elif sub == "DEL":
            for c in line.params[-1].split():
                self.caps.discard(c)

    def _sasl_mechanism(self) -> str:
        mech = self.account.settings.get("sasl", SASL_NONE)
        return mech if mech in (SASL_PLAIN, SASL_SCRAM, SASL_EXTERNAL) else SASL_NONE

    async def _cap_end_or_fail(self) -> None:
        if self._sasl_mechanism() != SASL_NONE and "sasl" not in self.caps:
            raise _Fatal("The server does not offer SASL login, which the account requires - "
                         "not logging in another way.")
        self._raw("CAP", "END")

    def _start_sasl(self) -> None:
        mech = self._sasl_mechanism()
        offered = self._sasl_mechs
        if offered and mech not in offered:
            raise _Fatal(f"The server does not offer SASL {mech} (it offers {', '.join(sorted(offered))}).")
        self._raw("AUTHENTICATE", mech)

    def _sasl_send(self, payload: bytes) -> None:
        encoded = base64.b64encode(payload).decode() if payload else "+"
        for i in range(0, len(encoded), 400):
            self._raw("AUTHENTICATE", encoded[i:i + 400])
        if encoded != "+" and len(encoded) % 400 == 0:
            self._raw("AUTHENTICATE", "+")

    async def _on_authenticate(self, line: Line) -> None:
        mech = self._sasl_mechanism()
        data = line.param(0)
        challenge = b""
        if data and data != "+":
            self._sasl_buffer += data
            if len(self._sasl_buffer) > MAX_SASL_CHALLENGE:
                self._sasl_buffer = ""
                raise _Fatal("The server's SASL challenge is too long.")
            if len(data) == 400:
                return
            try:
                challenge = base64.b64decode(self._sasl_buffer, validate=True)
            except ValueError:
                raise _Fatal("The server sent a malformed SASL challenge.")
            finally:
                self._sasl_buffer = ""
        user = str(self.account.settings.get("sasl_user", "")).strip() or self.wanted_nick
        if mech == SASL_EXTERNAL:
            self._sasl_send(b"")
            return
        password = C.account_secret(self.account, "password") or ""
        if not password:
            raise _Fatal("SASL login needs the account's password, which is not stored.")
        if mech == SASL_PLAIN:
            if self.tls_mode == TLS_OFF:
                raise _Fatal("Refusing to send the password in plain text over a connection "
                             "without TLS (choose SCRAM-SHA-256 or TLS).")
            self._sasl_send(f"{user}\x00{user}\x00{password}".encode())
            return
        try:
            if self._scram is None:
                self._scram = Scram(user, password)
                self._sasl_send(self._scram.first())
            elif not self._scram.server_signature:
                self._sasl_send(self._scram.final(challenge))
            else:
                self._scram.verify(challenge)
                self._sasl_send(b"")
        except ScramError as exc:
            self._raw("AUTHENTICATE", "*")
            raise _Fatal(f"SCRAM login failed: {exc}")

    def _numeric(self, line: Line) -> None:
        code = line.command
        rest = [p for p in line.params[1:]]
        text = " ".join(rest)
        if code in ("900",):
            self._note(self.server_key, f"Logged in as {line.param(2)}.")
        elif code == "903":
            if self._scram is not None and not self._scram.verified:
                # SCRAM's point is that the server proves it knows the
                # password too; a 903 without that proof is an impostor's.
                self._scram = None
                raise _Fatal("SASL login: the server did not prove it knows the password (SCRAM).")
            self._scram = None
            self._raw("CAP", "END")
        elif code in ("902", "904", "905", "906", "908"):
            self._scram = None
            if code == "908":
                return
            raise _Fatal(f"SASL login failed: {line.params[-1]}")
        elif code in ("372", "375", "376"):
            self._note(self.server_key, line.params[-1])
        elif code in ("311", "312", "313", "317", "318", "319", "330", "671", "378", "338"):
            self._note(self.server_key, "WHOIS " + " ".join(rest))
        elif code == "324":
            key = self.fold(line.param(1))
            self._note(key, f"Modes: {' '.join(line.params[2:])}")
        elif code in ("401", "403", "404", "405", "471", "473", "474", "475", "477", "482", "442", "441"):
            target = line.param(1)
            key = self.fold(target)
            self._note(key if self.conversation(key) else self.server_key,
                       f"{target}: {line.params[-1]}", C.KIND_ERROR)
        else:
            self._note(self.server_key, text)

    async def _on_001(self, line: Line) -> None:
        self.nick = line.param(0) or self.nick
        self._registered.set()
        self._set_state(C.STATE_ONLINE, f"{self.host} as {self.nick}")
        self._note(self.server_key, line.params[-1])
        s = self.account.settings
        if s.get("nickserv") is True and self._sasl_mechanism() == SASL_NONE:
            password = C.account_secret(self.account, "password")
            if password:
                if self.tls_mode == TLS_OFF:
                    self._note(self.server_key, "Not identifying to NickServ without TLS.", C.KIND_ERROR)
                else:
                    self._raw("PRIVMSG", "NickServ", f"IDENTIFY {password}")
        wanted = dict(self._channels_wanted)
        for name, key in autojoin_list(s):
            wanted.setdefault(self.fold(name), key)
            self._channel_names.setdefault(self.fold(name), name)
        names = self._channel_names
        for folded, key in wanted.items():
            self._join_line(names.get(folded, folded), key)

    async def _on_005(self, line: Line) -> None:
        for token in line.params[1:-1]:
            name, _, value = token.partition("=")
            name = name.upper()
            if name == "CASEMAPPING" and value in ("ascii", "rfc1459", "strict-rfc1459"):
                self.casemapping = value
            elif name == "CHANTYPES" and value:
                self.chantypes = value[:8]
            elif name == "PREFIX":
                m = re.fullmatch(r"\(([A-Za-z]+)\)(\S+)", value)
                if m and len(m.group(1)) == len(m.group(2)):
                    self.prefix_modes, self.prefix_chars = m.group(1), m.group(2)
            elif name == "CHANMODES":
                parts = value.split(",")
                if len(parts) >= 4:
                    self.chanmodes = tuple(parts[:4])
            elif name == "LINELEN" and value.isdigit():
                self.linelen = max(LINE_LIMIT, min(int(value), 4096))
        self._note(self.server_key, " ".join(line.params[1:]))

    # -- the channel list (LIST) ------------------------------------------------------
    async def _room_list(self, rid: int, search: str) -> None:
        self._require_online()
        if self._listing is not None:
            self._finish_list("")  # the newer request replaces it
        self._listing = [rid, [], 0]
        self._arm_list_timeout()
        # a mask is passed on (ELIST); the panel filters what arrives anyway
        if search and " " not in search and "," not in search:
            self._raw("LIST", f"*{search.strip('*')}*")
        else:
            self._raw("LIST")

    def _arm_list_timeout(self) -> None:
        if self._list_timeout is not None:
            self._list_timeout.cancel()
        self._list_timeout = asyncio.get_running_loop().call_later(
            LIST_TIMEOUT, lambda: self._finish_list("The server did not finish the channel list in time."))

    def _finish_list(self, problem: str) -> None:
        listing, self._listing = self._listing, None
        if self._list_timeout is not None:
            self._list_timeout.cancel()
            self._list_timeout = None
        if listing is None:
            return
        rid, pending, _count = listing
        if pending:
            self._emit_rooms(rid, pending)
        self.room_list_done.emit(rid, problem)

    async def _on_321(self, line: Line) -> None:
        return None  # RPL_LISTSTART

    async def _on_322(self, line: Line) -> None:
        """RPL_LIST: <me> <channel> <visible> :<topic> - batched, capped."""
        if self._listing is None:
            # a LIST typed by hand: it feeds the panel as well
            self._room_list_id += 1
            self._listing = [self._room_list_id, [], 0]
            self._arm_list_timeout()
        listing = self._listing
        if listing[2] >= C.MAX_ROOM_LIST:
            return
        channel = line.param(1)
        if not self.is_channel(channel):
            return
        try:
            users = int(line.param(2, "-1"))
        except ValueError:
            users = -1
        listing[1].append(C.RoomInfo(name=channel, users=users, topic=line.param(3)))
        listing[2] += 1
        if len(listing[1]) >= C.ROOM_BATCH:
            batch, listing[1] = listing[1], []
            self._emit_rooms(listing[0], batch)
            self._arm_list_timeout()

    async def _on_323(self, line: Line) -> None:
        listing = self._listing
        capped = listing is not None and listing[2] >= C.MAX_ROOM_LIST
        self._finish_list(f"Only the first {C.MAX_ROOM_LIST} channels are shown." if capped else "")

    async def _on_433(self, line: Line) -> None:
        if self._registered.is_set():
            self._note(self.server_key, f"Nick {line.param(1)} is already in use.", C.KIND_ERROR)
            return
        self._nick_tries = getattr(self, "_nick_tries", 0) + 1
        if self._nick_tries > MAX_NICK_TRIES:
            raise _Fatal(f"No free nick after {MAX_NICK_TRIES} tries - choose another one.")
        alt = str(self.account.settings.get("alt_nick", "")).strip()
        if alt and self.nick != alt:
            self.nick = alt
        else:
            # Append "_", or - at the length limit - change the end: cutting
            # an appended "_" off again would ask for the same nick forever.
            limit = 30
            candidate = self.nick + "_"
            if len(candidate) > limit:
                candidate = self.nick[:limit - 1] + str(self._nick_tries % 10)
            self.nick = candidate
        self._raw("NICK", self.nick)

    _on_432 = _on_433

    def _set_members(self, key: str, members: dict) -> None:
        """Every member shown by its nick made safe to show (as Matrix shows
        display names): a server's NAMES / JOIN / NICK can carry bidi and
        control characters (``\u202enimda``). The nick itself is kept: it is
        what commands address."""
        for member in members.values():
            member.display = C.clean_name(member.name)
        super()._set_members(key, members)

    async def _on_nick(self, line: Line) -> None:
        old, new = line.nick, line.param(0)
        if self.fold(old) == self.fold(self.nick):
            self.nick = new
            self._set_state(C.STATE_ONLINE, f"{self.host} as {new}")
            self._note(self.server_key, f"You are now {new}.")
        for conv in self.conversations():
            folded = self.fold(old)
            if folded in conv.members:
                members = dict(conv.members)
                member = members.pop(folded)
                member.name = new
                members[self.fold(new)] = member
                self._set_members(conv.key, members)
                self._note(conv.key, f"{old} is now {new}")
        query = self.conversation(self.fold(old))
        if query is not None and query.kind == C.CONV_DIRECT and self.fold(old) != self.fold(new) \
                and self.conversation(self.fold(new)) is None:
            history = list(query.history)
            self._remove_conversation(self.fold(old))
            moved = self._add_conversation(self.fold(new), C.CONV_DIRECT, new, encryption=self.link_encryption)
            with self._lock:
                for message in history:
                    message.conversation = moved.key
                    moved.history.append(message)
            self.conversation_changed.emit(moved.key)
            self._note(moved.key, f"{old} is now {new}")

    async def _on_join(self, line: Line) -> None:
        channel = line.param(0)
        key = self.fold(channel)
        nick = line.nick
        if self.fold(nick) == self.fold(self.nick):
            self._channel_names[key] = channel
            self._channels_wanted.setdefault(key, "")
            self._add_conversation(key, C.CONV_CHANNEL, channel, joined=True, members={},
                                   encryption=self.link_encryption)
            self._note(key, f"You joined {channel}. Messages here are readable by the network's "
                            "servers (IRC has no end-to-end encryption).")
            return
        conv = self.conversation(key)
        if conv is None:
            return
        members = dict(conv.members)
        members[self.fold(nick)] = C.Member(name=nick)
        self._set_members(key, members)
        self._note(key, f"{nick} joined")

    async def _on_part(self, line: Line) -> None:
        key = self.fold(line.param(0))
        nick = line.nick
        reason = line.param(1)
        if self.fold(nick) == self.fold(self.nick):
            self._channels_wanted.pop(key, None)
            self._update_conversation(key, joined=False, members={})
            self._note(key, "You left the channel.")
            return
        self._drop_member(key, nick, f"{nick} left" + (f" ({reason})" if reason else ""))

    async def _on_kick(self, line: Line) -> None:
        key = self.fold(line.param(0))
        victim, reason = line.param(1), line.param(2)
        if self.fold(victim) == self.fold(self.nick):
            self._channels_wanted.pop(key, None)
            self._update_conversation(key, joined=False, members={})
            self._note(key, f"{line.nick} kicked you" + (f": {reason}" if reason else ""), C.KIND_ERROR)
            return
        self._drop_member(key, victim, f"{line.nick} kicked {victim}" + (f": {reason}" if reason else ""))

    async def _on_quit(self, line: Line) -> None:
        nick, folded = line.nick, self.fold(line.nick)
        for conv in self.conversations():
            if folded in conv.members:
                self._drop_member(conv.key, nick, f"{nick} quit" + (f" ({line.param(0)})" if line.param(0) else ""))

    def _drop_member(self, key: str, nick: str, note: str) -> None:
        conv = self.conversation(key)
        if conv is None:
            return
        members = dict(conv.members)
        members.pop(self.fold(nick), None)
        self._set_members(key, members)
        self._note(key, note)

    async def _on_topic(self, line: Line) -> None:
        key = self.fold(line.param(0))
        self._update_conversation(key, topic=line.param(1))
        self._note(key, f"{line.nick} set the topic: {line.param(1)}")

    async def _on_332(self, line: Line) -> None:
        self._update_conversation(self.fold(line.param(1)), topic=line.params[-1])

    async def _on_333(self, line: Line) -> None:
        return None

    async def _on_331(self, line: Line) -> None:
        self._update_conversation(self.fold(line.param(1)), topic="")

    async def _on_353(self, line: Line) -> None:
        key = self.fold(line.params[-2] if len(line.params) >= 3 else "")
        if key not in self._names_pending and len(self._names_pending) >= MAX_NAMES_PENDING:
            # 353 replies without their 366: a server could open lists forever.
            self._names_pending.pop(next(iter(self._names_pending)))
        pending = self._names_pending.setdefault(key, {})
        for entry in line.params[-1].split()[:5000]:
            role = ""
            while entry and entry[0] in self.prefix_chars:
                role += entry[0]
                entry = entry[1:]
            nick = entry.split("!", 1)[0]
            if nick:
                pending[self.fold(nick)] = C.Member(name=nick, role=role)
        if len(pending) > 50_000:
            pending.clear()

    async def _on_366(self, line: Line) -> None:
        key = self.fold(line.param(1))
        members = self._names_pending.pop(key, {})
        if self.conversation(key) is not None:
            self._set_members(key, members)
            self._note(key, f"{len(members)} in the channel")

    async def _on_mode(self, line: Line) -> None:
        target = line.param(0)
        if not self.is_channel(target):
            return
        key = self.fold(target)
        conv = self.conversation(key)
        modes, args = line.param(1), list(line.params[2:])
        self._note(key, f"{line.nick or line.prefix} sets mode {' '.join(line.params[1:])}")
        if conv is None:
            return
        members = dict(conv.members)
        adding = True
        a_modes, b_modes, c_modes, _ = self.chanmodes
        for ch in modes:
            if ch in "+-":
                adding = ch == "+"
                continue
            if ch in self.prefix_modes:
                nick = args.pop(0) if args else ""
                member = members.get(self.fold(nick))
                if member is not None:
                    symbol = self.prefix_chars[self.prefix_modes.index(ch)]
                    role = member.role.replace(symbol, "")
                    if adding:
                        role = "".join(sorted(role + symbol, key=self.prefix_chars.index))
                    member.role = role
            elif ch in a_modes or ch in b_modes or (ch in c_modes and adding):
                if args:
                    args.pop(0)
        self._set_members(key, members)

    async def _on_away(self, line: Line) -> None:
        folded = self.fold(line.nick)
        for conv in self.conversations():
            member = conv.members.get(folded)
            if member is not None:
                member.away = bool(line.params)
                self.conversation_changed.emit(conv.key)

    async def _on_chghost(self, line: Line) -> None:
        return None

    async def _on_account(self, line: Line) -> None:
        return None

    async def _on_privmsg(self, line: Line) -> None:
        await self._message(line, C.KIND_MESSAGE)

    async def _on_notice(self, line: Line) -> None:
        await self._message(line, C.KIND_NOTICE)

    async def _message(self, line: Line, kind: str) -> None:
        target, text = line.param(0), line.param(1)
        sender = line.nick or line.prefix
        own = self.fold(sender) == self.fold(self.nick)
        if text.startswith("\x01"):
            body = text.strip("\x01")
            verb, _, rest = body.partition(" ")
            if verb.upper() == "ACTION":
                kind, text = C.KIND_ACTION, rest
            else:
                if kind == C.KIND_MESSAGE and not own:
                    self._note(self.server_key, f"CTCP {verb.upper()[:20]} from {sender} (not answered)")
                return
        if self.is_channel(target):
            key = self.fold(target)
            if self.conversation(key) is None:
                return
        elif not self._registered.is_set() or "." in sender and "!" not in line.prefix:
            key = self.server_key          # the server itself talking
        elif kind == C.KIND_NOTICE and self.conversation(self.fold(sender)) is None:
            key = self.server_key          # services, server notices
        else:
            key = self.fold(target if own else sender)
            if self.conversation(key) is None:
                self._add_conversation(key, C.CONV_DIRECT, target if own else sender,
                                       encryption=self.link_encryption)
        self._add_message(C.ChatMessage(conversation=key, sender=sender, text=text,
                                        timestamp=self._timestamp(line), kind=kind, outgoing=own,
                                        encryption=self.link_encryption, message_id=line.tags.get("msgid", "")),
                          highlight_words=[self.nick] + self.highlight_words)

    # -- what the user does ---------------------------------------------------------
    def _require_online(self) -> None:
        if self._writer is None or self._registered is None or not self._registered.is_set():
            raise C.ChatError("Not connected.")

    def _budget(self, command: str, target: str) -> int:
        # ":nick!user@host " is added by the server for the others
        overhead = len(f":{self.nick}!{'x' * 10}@{'h' * 63} {command} {target} :".encode()) + 2
        return self.linelen - overhead

    def _say(self, key: str, target: str, text: str, kind: str = C.KIND_MESSAGE) -> None:
        self._require_online()
        lines = [l for l in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
        lines = [l for l in lines if l.strip()]
        if len(lines) > MAX_PASTE_LINES:
            raise C.ChatError(f"{len(lines)} lines at once - at most {MAX_PASTE_LINES} are sent as a message.")
        command = "NOTICE" if kind == C.KIND_NOTICE else "PRIVMSG"
        for one in lines:
            if kind == C.KIND_ACTION:
                pieces = split_text(one, self._budget(command, target) - 9)
                for piece in pieces:
                    self._raw(command, target, f"\x01ACTION {piece}\x01")
            else:
                pieces = split_text(one, self._budget(command, target))
                for piece in pieces:
                    self._raw(command, target, piece)
            for piece in pieces:
                self._add_message(C.ChatMessage(conversation=key, sender=self.nick, text=piece, kind=kind,
                                                outgoing=True, encryption=self.link_encryption))

    def _target_of(self, key: str) -> str:
        conv = self.conversation(key)
        if conv is None or conv.kind == C.CONV_SERVER:
            raise C.ChatError("This is the server's window - join a channel or open a query.")
        return conv.title

    async def _send_text(self, key: str, text: str) -> None:
        self._say(key, self._target_of(key), text)

    def _join_line(self, channel: str, key: str = "") -> None:
        if key:
            self._raw("JOIN", channel, key)
        else:
            self._raw("JOIN", channel)

    async def _join(self, target: str) -> None:
        self._require_online()
        parts = target.split()
        if not parts:
            return
        channel = parts[0]
        if not self.is_channel(channel):
            channel = "#" + channel
        if len(channel) > 200 or any(c in channel for c in " ,\x07"):
            raise C.ChatError(f"{channel!r} is not a channel name.")
        key = parts[1] if len(parts) > 1 else ""
        self._channels_wanted[self.fold(channel)] = key
        self._channel_names[self.fold(channel)] = channel
        self._join_line(channel, key)

    async def _open_direct(self, target: str) -> None:
        nick = target.split()[0] if target.split() else ""
        if not valid_nick(nick):
            raise C.ChatError(f"{nick!r} is not a nick name.")
        self._add_conversation(self.fold(nick), C.CONV_DIRECT, nick, encryption=self.link_encryption)

    async def _leave(self, key: str) -> None:
        conv = self.conversation(key)
        if conv is None:
            return
        if conv.kind == C.CONV_CHANNEL and conv.joined and self._writer is not None:
            self._channels_wanted.pop(key, None)
            self._raw("PART", conv.title, "Leaving")
        self._remove_conversation(key)

    async def _answer(self, request: object, answer: object) -> None:
        if isinstance(request, CertificateRequest) and answer is True:
            self.account.settings["tls"] = TLS_PINNED
            self.account.settings["fingerprint"] = request.fingerprint
            self.tls_mode = TLS_PINNED
            self._note(self.server_key, f"Trusting the certificate {request.fingerprint}.")
            self.account_changed()
            if self.state != C.STATE_ONLINE:
                self._want_online = True
                await self._open()

    def account_changed(self) -> None:
        """Hook: the panel saves the account (set by the panel)."""
        callback = getattr(self, "on_account_changed", None)
        if callback is not None:
            callback(self.account)

    HELP = (
        "/join #channel [key] - join a channel",
        "/part [reason] - leave this channel",
        "/msg nick text - a private message",
        "/query nick - open a private conversation",
        "/me text - an action",
        "/notice target text - a notice",
        "/nick name - change your nick",
        "/topic [text] - show or set the topic",
        "/away [text], /back - set or clear away",
        "/whois nick, /names, /mode [modes], /kick nick [reason], /invite nick",
        "/quote LINE - send a raw IRC line",
        "/close - close this conversation",
    )

    async def _command(self, key: str, name: str, args: str) -> None:
        if name == "help":
            for line in self.HELP:
                self._note(key, line)
            return
        if name == "close":
            await self._leave(key)
            return
        if name == "query":
            await self._open_direct(args)
            return
        if name == "join":
            await self._join(args)
            return
        self._require_online()
        conv = self.conversation(key)
        here = conv.title if conv is not None and conv.kind != C.CONV_SERVER else ""
        if name == "me":
            self._say(key, self._target_of(key), args, C.KIND_ACTION)
        elif name in ("msg", "notice"):
            target, _, text = args.partition(" ")
            if not target or not text:
                raise C.ChatError(f"/{name} needs a target and a text.")
            folded = self.fold(target)
            if not self.is_channel(target) and name == "msg":
                self._add_conversation(folded, C.CONV_DIRECT, target, encryption=self.link_encryption)
                self._say(folded, target, text)
            else:
                show = folded if self.conversation(folded) else key
                self._say(show, target, text, C.KIND_NOTICE if name == "notice" else C.KIND_MESSAGE)
        elif name == "part":
            if not here or conv.kind != C.CONV_CHANNEL:
                raise C.ChatError("/part works in a channel.")
            self._channels_wanted.pop(key, None)
            self._raw("PART", here, args or "Leaving")
        elif name == "nick":
            if not valid_nick(args):
                raise C.ChatError(f"{args!r} is not a nick name.")
            self.wanted_nick = args
            self._raw("NICK", args)
        elif name == "topic":
            if not here or conv.kind != C.CONV_CHANNEL:
                raise C.ChatError("/topic works in a channel.")
            if args:
                self._raw("TOPIC", here, args)
            else:
                self._raw("TOPIC", here)
        elif name == "away":
            self._raw("AWAY", args or "away")
        elif name == "back":
            self._raw("AWAY")
        elif name == "whois":
            if not args:
                raise C.ChatError("/whois needs a nick.")
            self._raw("WHOIS", args.split()[0])
        elif name == "names":
            if here:
                self._raw("NAMES", here)
        elif name == "mode":
            target = here or self.nick
            params = args.split()
            self._raw("MODE", target, *params) if params else self._raw("MODE", target)
        elif name == "kick":
            nick, _, reason = args.partition(" ")
            if not here or not nick:
                raise C.ChatError("/kick works in a channel and needs a nick.")
            self._raw("KICK", here, nick, reason or nick)
        elif name == "invite":
            if not here or not args:
                raise C.ChatError("/invite works in a channel and needs a nick.")
            self._raw("INVITE", args.split()[0], here)
        elif name in ("quote", "raw"):
            line = parse_line(args)
            if line is None:
                raise C.ChatError("That is not an IRC line.")
            if line.command in ("PASS", "AUTHENTICATE"):
                raise C.ChatError(f"{line.command} is not sent by hand.")
            self._raw(line.command, *line.params)
        else:
            self._note(key, f"Unknown command: /{name} (/help lists them)", C.KIND_ERROR)


class _Fatal(C.ChatError):
    """Ends the connection without reconnecting (a login that must not be retried)."""


# --- the account form ----------------------------------------------------------------

FIELDS = (
    C.FieldSpec("server", "Server", required=True, help="irc.libera.chat"),
    C.FieldSpec("tls", "Encryption", "choice", TLS_VERIFY,
                ((TLS_VERIFY, "TLS, certificate checked"), (TLS_PINNED, "TLS, pinned certificate"),
                 (TLS_OFF, "None (plain text - not recommended)"))),
    C.FieldSpec("port", "Port", "int", 6697),
    C.FieldSpec("fingerprint", "Pinned SHA-256", help="Only for a pinned certificate"),
    C.FieldSpec("nick", "Nick", required=True),
    C.FieldSpec("alt_nick", "Alternative nick"),
    C.FieldSpec("username", "User name"),
    C.FieldSpec("realname", "Real name"),
    C.FieldSpec("sasl", "Login", "choice", SASL_NONE,
                ((SASL_NONE, "None"), (SASL_SCRAM, "SASL SCRAM-SHA-256"), (SASL_PLAIN, "SASL PLAIN"),
                 (SASL_EXTERNAL, "SASL EXTERNAL (client certificate)"))),
    C.FieldSpec("sasl_user", "Account name", help="Defaults to the nick"),
    C.FieldSpec("password", "Password", "password", secret=True,
                help="SASL or NickServ password (kept in the keyring)"),
    C.FieldSpec("nickserv", "Identify with NickServ (without SASL)", "bool", False),
    C.FieldSpec("server_password", "Server password", "password", secret=True),
    C.FieldSpec("client_cert", "Client certificate (PEM)", "file"),
    C.FieldSpec("client_key", "Client key (PEM)", "file"),
    C.FieldSpec("autojoin", "Join at start", "lines", "", help="One channel per line, optionally a key"),
    C.FieldSpec("highlight", "Highlight words", "lines", ""),
    C.FieldSpec("proxy", "Proxy", "choice", "default", C.PROXY_CHOICES),
)


def validate(settings: dict) -> str | None:
    if not str(settings.get("server", "")).strip():
        return "The server is missing."
    if not valid_nick(str(settings.get("nick", "")).strip()):
        return "The nick is missing or not valid (letters, digits and [ ] \\ ` _ ^ { | } -)."
    if settings.get("tls") == TLS_PINNED and not normalise_fingerprint(str(settings.get("fingerprint", ""))):
        return "A pinned certificate needs its SHA-256 fingerprint (64 hex digits)."
    if settings.get("sasl") == SASL_EXTERNAL and not str(settings.get("client_cert", "")).strip():
        return "SASL EXTERNAL needs a client certificate."
    if settings.get("sasl") == SASL_PLAIN and settings.get("tls") == TLS_OFF:
        return "SASL PLAIN would send the password in plain text - choose TLS or SCRAM-SHA-256."
    return None


def apply_server(entry, values: dict) -> dict:
    """What choosing a public IRC network (core.chat_servers.ServerEntry)
    fills in: the server, its port and TLS (a plain-text entry switches
    TLS off only because the list names no TLS port - the user sees it)."""
    return {"server": entry.host, "port": entry.port or (6697 if entry.tls else 6667),
            "tls": TLS_VERIFY if entry.tls else TLS_OFF}


PROTOCOL = C.Protocol(
    name="irc", title="IRC", fields=FIELDS, make_client=IrcClient,
    join_label="Join Channel…", join_prompt="Channel (and key):",
    direct_label="Private Message…", direct_prompt="Nick:", validate=validate,
    server_field="server", apply_server=apply_server, room_list_label="Channel List",
)
