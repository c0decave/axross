"""POP3 read-only backend implementing the FileBackend protocol.

POP3 is fundamentally a *retrieve* protocol — it cannot store new
messages on the server. Axross exposes POP3 mailboxes as a flat
read-only filesystem so users on legacy hosts (some ISPs, some
appliance MTAs) that don't offer IMAP can still browse mail
through the same UI.

Layout::

    /                       — flat list of messages
    /<msgno>_<subject>.eml  — raw RFC 822 of message N

Surface:

* ``list_dir("/")`` — LIST + TOP for subjects.
* ``stat(path)``   — size from LIST, name parsed from the path.
* ``open_read``    — RETR.
* ``remove``       — DELE flag (POP3 only commits on QUIT, see
                      docstring).
* ``open_write`` / ``mkdir`` / ``rename`` / ``chmod`` — refused.

A message is named ``<msgno>_<subject>.eml``, the whole name at most
core.mail_names.MAX_NAME_BYTES UTF-8 bytes. POP3 numbers messages per
connection; after a reconnect a listed path is found again by its UIDL
id, or - on a server without UIDL - by a fingerprint of its headers
(TOP n 0) and size; when that matches more than one message, a delete
is refused. A dropped connection is reconnected on the next call; DELEs
it carried were never committed (only QUIT commits them), and that is
raised as :class:`Pop3DeletesLost` - also by ``disconnect()`` when QUIT
fails - so the caller can tell the user the messages are still there.

Uses only Python stdlib (``poplib``, ``email``).
"""

from __future__ import annotations

import contextlib
import email
import functools
import hashlib
import errno
import email.errors
import email.header
import email.policy
import io
import logging
import poplib
import re
from datetime import datetime
from typing import IO

from core.backend import SessionLifecycle
from core.mail_names import message_file_name, message_subject_part
from core.session_lock import io_lock, liveness_check, serialized
from models.file_item import FileItem

log = logging.getLogger(__name__)


# Cap on a single read_file call. Mailboxes occasionally hold absurd
# attachments (gigabyte logs); refusing >32 MiB keeps the UI snappy
# without rejecting any reasonable mail.
MAX_MESSAGE_BYTES = 32 * 1024 * 1024
#: LIST / UIDL answers: ~30 bytes a message - room for some 500 000.
MAX_LISTING_BYTES = 16 * 1024 * 1024
#: TOP n 0 (the headers the listing shows the subject from).
MAX_HEADER_BYTES = 1024 * 1024
#: TOP with body lines (the scripting API): as much as a whole message.
MAX_TOP_BYTES = MAX_MESSAGE_BYTES

# Reused filename-character allow-list. Mirrors imap_client._sanitize_filename.
_FILENAME_BAD_CHARS = re.compile(r'[/\\:*?"<>|\x00-\x1f]')


def _sanitize_filename(name: str, max_len: int = 120) -> str:
    name = _FILENAME_BAD_CHARS.sub("_", name)
    name = name.strip(". ")
    if not name:
        name = "untitled"
    if len(name) > max_len:
        name = name[:max_len]
    return name


class Pop3DeletesLost(OSError):
    """DELEs were sent on a connection that ended without a working QUIT:
    the server never committed them and still has the messages."""


def _connection_lost(exc: BaseException) -> bool:
    """Whether *exc* (or what it was raised from) says the connection is
    gone - not a "-ERR" the server answered."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, poplib.error_proto):
            if "EOF" in str(cur):  # poplib: the server closed the connection
                return True
        elif isinstance(cur, (ConnectionError, TimeoutError, EOFError)):
            return True
        elif isinstance(cur, OSError) and cur.errno in (errno.EBADF, errno.ENOTCONN, errno.EPIPE):
            return True
        cur = cur.__cause__
    return False


def _reconnecting(method):
    """Run *method*; when it failed because the connection is gone, drop
    the connection and run it once more on a new one (POP3 numbers
    messages per connection: the path resolution handles that). DELEs
    sent on the lost connection were not committed: that is raised as
    Pop3DeletesLost instead of retrying."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with io_lock(self):
            try:
                return method(self, *args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - re-raised unless the link is gone
                if not _connection_lost(exc) or self._closed_by_user:
                    raise
                self._drop_connection(exc)
                log.info("POP3: the connection to %s was lost (%s); reconnecting", self._host, exc)
                return method(self, *args, **kwargs)

    return wrapper


def _decode_header(raw: str | bytes | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    parts: list[str] = []
    try:
        pieces = email.header.decode_header(raw)
    except email.errors.HeaderParseError:
        # A B-encoded word that is not base64: show it as the server sent it.
        return raw.strip()
    for piece, charset in pieces:
        if isinstance(piece, bytes):
            try:
                parts.append(piece.decode(charset or "utf-8", errors="replace"))
            except (LookupError, ValueError):  # unknown charset, NUL in its name
                parts.append(piece.decode("utf-8", errors="replace"))
        else:
            parts.append(piece)
    return "".join(parts).strip()


# ---------------------------------------------------------------------------
# Proxy-aware POP3 subclasses
#
# poplib's POP3 / POP3_SSL use ``socket.create_connection`` internally
# (Python 3.4+). We override the same hook used by the IMAP path:
# ``_create_socket(self, timeout)``. For POP3_SSL we wrap the proxied
# socket in TLS via the SDK's pre-built context.
# ---------------------------------------------------------------------------


class _ProxyPOP3(poplib.POP3):
    """POP3 subclass that builds its TCP socket through a SOCKS / HTTP
    proxy via :func:`core.proxy.create_proxy_socket`.
    """

    def __init__(self, host: str, port: int, proxy_config, timeout: float = 30.0):
        self._axross_proxy = proxy_config
        self._axross_timeout = float(timeout)
        super().__init__(host, port, timeout=timeout)

    def _create_socket(self, timeout=None):
        from core.proxy import create_proxy_socket

        t = float(timeout) if timeout is not None else self._axross_timeout
        return create_proxy_socket(
            self._axross_proxy,
            self.host,
            int(self.port),
            timeout=t,
        )


class _ProxyPOP3_SSL(poplib.POP3_SSL):
    """POP3_SSL counterpart. Same hook plus a TLS wrap on the
    proxied socket using poplib's built-in SSL context."""

    def __init__(self, host: str, port: int, proxy_config, timeout: float = 30.0, context=None):
        self._axross_proxy = proxy_config
        self._axross_timeout = float(timeout)
        super().__init__(host, port, timeout=timeout, context=context)

    def _create_socket(self, timeout=None):
        from core.proxy import create_proxy_socket

        t = float(timeout) if timeout is not None else self._axross_timeout
        raw = create_proxy_socket(
            self._axross_proxy,
            self.host,
            int(self.port),
            timeout=t,
        )
        # poplib stores the ssl.SSLContext on self.context. We wrap
        # the proxied socket in TLS using it, matching what stdlib's
        # POP3_SSL._create_socket does internally.
        return self.context.wrap_socket(raw, server_hostname=self.host)


# ---------------------------------------------------------------------------
# Message-path conventions
# ---------------------------------------------------------------------------

# Filename pattern: ``<msgno>_<safe-subject>.eml`` — same shape as the
# IMAP backend so paths look consistent across the two mail backends.
_MSG_PATH_RE = re.compile(r"^/(?P<msgno>\d+)_[^/]*\.eml$")


def _listing(lines) -> list[tuple[int, int]]:
    """``(msgno, size)`` of each line of a LIST answer."""
    out: list[tuple[int, int]] = []
    for raw in lines:
        text = raw.decode("ascii", errors="replace") if isinstance(raw, bytes) else raw
        parts = text.strip().split()
        if len(parts) < 2:
            continue
        try:
            out.append((int(parts[0]), int(parts[1])))
        except ValueError:
            continue
    return out


def _subject_of(headers: bytes | None) -> str:
    """The decoded Subject of a TOP n 0 header block ("" without one)."""
    if not headers:
        return ""
    try:
        msg = email.message_from_bytes(headers, policy=email.policy.compat32)
        return _decode_header(msg.get("Subject", ""))
    except Exception as exc:  # noqa: BLE001 - a header the parser chokes on
        log.debug("POP3: unparseable headers: %s", exc)
        return ""


def _fingerprint(headers: bytes | None, size: int) -> str:
    """A message's identity on a server without UIDL: its headers (with
    Message-ID, Date, Received - one message's own) and size. "" when the
    headers could not be read."""
    if headers is None:
        return ""
    return hashlib.sha256(headers + b"\0" + str(int(size)).encode()).hexdigest()


def _names_subject(path: str, safe_subject: str) -> bool:
    """Whether *path* (``/<n>_<subject>.eml``) names a message with the
    sanitised subject *safe_subject*: as list_dir() names it now (cut at
    MAX_NAME_BYTES bytes for the path's number), or as it named it
    before names were capped in bytes (a bookmark, a mail dock's
    seen-state)."""
    match = _MSG_PATH_RE.fullmatch(path)
    if not match:
        return False
    named = path.rsplit("/", 1)[-1].split("_", 1)[1][: -len(".eml")]
    return named in (message_subject_part(match.group("msgno"), safe_subject), safe_subject)


def _msgno_from_path(path: str) -> int:
    """The message number in *path*. A path that names no message is
    FileNotFoundError: the mailbox is flat and only holds messages, so
    nothing can be there."""
    m = _MSG_PATH_RE.fullmatch(path)
    if not m:
        raise FileNotFoundError(
            errno.ENOENT, "POP3 path does not look like a message", path
        )
    return int(m.group("msgno"))


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class Pop3Session(SessionLifecycle):
    """POP3 read-only backend implementing the FileBackend protocol."""

    # POP3 has no folder hierarchy and no mutable surface — these flags
    # let the UI hide context-menu entries that would otherwise raise.
    supports_symlinks = False
    supports_hardlinks = False
    #: One flat list of messages at "/" - no INBOX nor any other folder.
    #: Mail docks and the Mail Project read "/" whatever folder is named.
    FLAT_MAILBOX = True

    def __init__(
        self,
        host: str,
        port: int = 995,
        username: str = "",
        password: str = "",
        use_ssl: bool = True,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
        verify_tls: bool = True,
    ):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_ssl = use_ssl
        self._verify_tls = bool(verify_tls)
        from core.proxy import ProxyConfig

        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )
        self._pop: poplib.POP3 | poplib.POP3_SSL | None = None
        self._connect()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        try:
            if self._use_ssl:
                from core.tls_context import client_tls_context

                tls_ctx = client_tls_context(getattr(self, "_verify_tls", True), label="POP3")
                if self._proxy.enabled:
                    self._pop = _ProxyPOP3_SSL(
                        self._host,
                        self._port,
                        self._proxy,
                        timeout=30.0,
                        context=tls_ctx,
                    )
                else:
                    self._pop = poplib.POP3_SSL(
                        self._host, self._port, timeout=30.0, context=tls_ctx
                    )
            else:
                # Plaintext POP3 — credentials traverse the wire in
                # the clear via USER/PASS. Loud warning so a misconfig
                # doesn't slip past silently.
                log.warning(
                    "POP3 connecting to %s:%d WITHOUT TLS — credentials will be sent in plaintext",
                    self._host,
                    self._port,
                )
                if self._proxy.enabled:
                    self._pop = _ProxyPOP3(
                        self._host,
                        self._port,
                        self._proxy,
                        timeout=30.0,
                    )
                else:
                    self._pop = poplib.POP3(self._host, self._port, timeout=30.0)

            self._pop.user(self._username)
            self._pop.pass_(self._password)
            # POP3 numbers messages per connection: a new one may number
            # them differently (_resolve).
            self._generation = getattr(self, "_generation", 0) + 1
            self._pending_deletes = 0
            log.info(
                "POP3%s connected: %s@%s:%d",
                "S" if self._use_ssl else "",
                self._username,
                self._host,
                self._port,
            )
        except poplib.error_proto as exc:
            self._pop = None
            raise OSError(f"POP3 LOGIN failed: {exc}") from exc
        except Exception:
            self._pop = None
            raise

    #: Set by disconnect(): a later call through this object (a queued or
    #: retried transfer, a scheduled job) raises instead of logging in
    #: again by itself with the stored password.
    _closed_by_user = False

    def _ensure_connected(self) -> "poplib.POP3 | poplib.POP3_SSL":
        if self._closed_by_user:
            raise ConnectionError(errno.ENOTCONN,
                                  f"POP3 {getattr(self, '_host', '')}: disconnected")
        if self._pop is None:
            self._connect()
        # poplib has no NOOP probe — we trust the most-recent stat call
        # was authoritative; reconnect happens on the next exception.
        assert self._pop is not None
        return self._pop

    @property
    def name(self) -> str:
        return f"POP3{'S' if self._use_ssl else ''}: {self._username}@{self._host}:{self._port}"

    def security_info(self):
        """The negotiated TLS of the POP3 connection for the security badge
        (None when not connected - the profile tells then)."""
        from core import conn_security as CS

        sock = getattr(self._pop, "sock", None) if self._pop is not None else None
        if sock is None:
            return None
        if not self._use_ssl:
            return CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "POP3 without TLS - cleartext - anyone on the "
                                   "network can read it, the password too", True)
        return CS.tls_socket(sock, verified=self._verify_tls, what="POP3")

    @property
    @liveness_check
    def connected(self) -> bool:
        if self._pop is None:
            return False
        try:
            # NOOP exists in POP3 — sends "NOOP\r\n", expects "+OK".
            self._pop.noop()
            return True
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("POP3 liveness check failed: %s", exc)
            return False

    @serialized
    def disconnect(self) -> None:
        """Issue QUIT to commit any DELE flags and close the socket.
        Idempotent; safe to call when not connected.

        Pop3DeletesLost when QUIT fails after DELEs were sent: the server
        commits deletions only on a QUIT it answers +OK, so the messages
        are still there - swallowed, the user was told they were gone."""
        self._closed_by_user = True
        if self._pop is None:
            return
        pending = getattr(self, "_pending_deletes", 0)
        try:
            self._pop.quit()
        except Exception as exc:  # noqa: BLE001
            if pending:
                log.warning("POP3 QUIT failed with %d deletion(s) pending: %s", pending, exc)
                raise Pop3DeletesLost(
                    errno.EIO,
                    f"POP3: {pending} deletion(s) were not committed - QUIT to {self._host} "
                    f"failed ({exc}); those messages are still on the server",
                ) from exc
            log.debug("POP3 quit raised: %s", exc)
        finally:
            self._pop = None
            self._pending_deletes = 0

    def _lost_deletes_note(self) -> str:
        """For an error that drops the connection: the DELEs sent on it,
        which go uncommitted with it ("" when there were none)."""
        pending = getattr(self, "_pending_deletes", 0)
        self._pending_deletes = 0
        if not pending:
            return ""
        log.warning("POP3: %d deletion(s) on this connection are lost with it (no QUIT)", pending)
        return (f" The connection was dropped: {pending} deletion(s) sent on it were not "
                f"committed - those messages are still on the server.")

    def _drop_connection(self, exc: BaseException) -> None:
        """Forget a connection that is gone. DELEs sent on it were never
        committed: Pop3DeletesLost (the next call connects anew)."""
        pop, self._pop = self._pop, None
        if pop is not None:
            with contextlib.suppress(Exception):
                pop.close()
        pending = getattr(self, "_pending_deletes", 0)
        self._pending_deletes = 0
        if pending:
            raise Pop3DeletesLost(
                errno.EIO,
                f"POP3: the connection to {self._host} was lost; {pending} deletion(s) sent on "
                f"it were not committed - those messages are still on the server",
            ) from exc

    def close(self) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        # Strip first, then drop the empty ones: join("/", "1_x.eml") gave
        # "//1_x.eml", which no message path matches.
        cleaned = [c for c in (p.strip("/") for p in parts if p) if c]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return path

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    @_reconnecting
    @serialized
    def list_dir(self, path: str) -> list[FileItem]:
        """List all messages in the mailbox.

        POP3 has no folder hierarchy: any non-root path is empty.
        Items have name ``<msgno>_<subject>.eml`` (at most
        core.mail_names.MAX_NAME_BYTES UTF-8 bytes) and the size from
        the server's LIST response. Subjects are best-effort: TOP
        (read first 0 lines, headers only) is queried per message;
        on TOP failure the item still appears with subject "(no
        subject)" so the user can still browse the mailbox. The same
        headers give each message its fingerprint (see _resolve).
        """
        path = self.normalize(path)
        if path != "/":
            return []

        pop = self._ensure_connected()
        # LIST returns lines like ``b"1 1234"`` — message-number + octets.
        try:
            _resp, lines, _octets = self._long_capped(pop, "list", (), "LIST", MAX_LISTING_BYTES)
        except poplib.error_proto as exc:
            raise OSError(f"POP3 LIST failed: {exc}") from exc

        items: list[FileItem] = []
        uids = self._uid_map(pop)
        listed: dict[int, tuple[str, str, int, str]] = {}
        for msgno, size in _listing(lines):
            headers = self._fetch_headers(msgno)
            subject = _subject_of(headers)
            safe_subj = _sanitize_filename(subject) if subject else "untitled"
            name = message_file_name(str(msgno), safe_subj)
            listed[msgno] = (uids.get(msgno, ""), safe_subj, size, _fingerprint(headers, size))
            items.append(
                FileItem(
                    name=name,
                    is_dir=False,
                    is_link=False,
                    size=size,
                    modified=datetime.now(),  # POP3 has no per-message mtime
                    permissions=0o400,
                )
            )
        self._listed = listed
        self._listing_generation = self._generation
        return items

    def _uid_map(self, pop) -> dict[int, str]:
        """``UIDL``: message number -> unique id; {} without UIDL."""
        try:
            _resp, lines, _octets = self._long_capped(pop, "uidl", (), "UIDL", MAX_LISTING_BYTES)
        except (poplib.error_proto, OSError) as exc:
            if _connection_lost(exc):
                raise
            log.debug("POP3 UIDL failed: %s", exc)
            return {}
        out: dict[int, str] = {}
        for raw in lines:
            text = raw.decode("ascii", "replace") if isinstance(raw, bytes) else raw
            parts = text.split()
            if len(parts) >= 2 and parts[0].isdigit():
                out[int(parts[0])] = parts[1]
        return out

    def _resolve(self, path: str, *, strict: bool = False) -> int:
        """The number of the message *path* names ON THIS CONNECTION.

        POP3 numbers per connection: after a reconnect the number in a
        listed path may name another message - removing the listed
        "world" deleted "salary-letter" (review B4, 2026-10-17). On the
        listing's connection the number holds; otherwise the message is
        found by its UIDL id, or - without UIDL - by the fingerprint of
        its headers and size the listing took. Two messages with the
        same subject were told apart by neither the number nor the
        subject: the wrong "Daily report" was deleted. *strict* (a
        delete) refuses when the fingerprint does not name one message.
        A path the listing does not carry is used by its number when the
        subject still matches."""
        msgno = _msgno_from_path(path)
        pop = self._ensure_connected()
        listing = getattr(self, "_listing_generation", -1)
        if listing < 0 or listing == getattr(self, "_generation", 0):
            # Never listed (a path from elsewhere: its number is all there
            # is), or still the listing's connection: the number holds.
            return msgno
        entry = getattr(self, "_listed", {}).get(msgno)
        if entry is None or not _names_subject(path, entry[1]):
            if not _names_subject(path, self._safe_subject(msgno)):
                raise OSError(
                    f"POP3 {path}: message numbers changed since the listing (the connection "
                    "was renewed); list the mailbox again"
                )
            return msgno
        uid, _subject, size, fingerprint = entry
        if uid:
            current = self._uid_map(pop)
            if current:
                found = next((n for n, u in current.items() if u == uid), None)
                if found is None:
                    raise FileNotFoundError(
                        errno.ENOENT, "POP3: the message is no longer in the mailbox", path
                    )
                return found
        return self._find_by_fingerprint(pop, path, size, fingerprint, strict=strict)

    def _find_by_fingerprint(self, pop, path: str, size: int, fingerprint: str, *,
                             strict: bool) -> int:
        """The number of the message whose headers and size the listing
        fingerprinted as *fingerprint* (a server without UIDL)."""
        if not fingerprint:
            raise OSError(
                f"POP3 {path}: message numbers changed since the listing (the connection "
                "was renewed) and the server has no UIDL; list the mailbox again"
            )
        try:
            _resp, lines, _octets = self._long_capped(pop, "list", (), "LIST", MAX_LISTING_BYTES)
        except poplib.error_proto as exc:
            raise OSError(f"POP3 LIST failed: {exc}") from exc
        matches = [
            n for n, sz in _listing(lines)
            if sz == size and _fingerprint(self._fetch_headers(n), sz) == fingerprint
        ]
        if not matches:
            raise FileNotFoundError(
                errno.ENOENT, "POP3: the message is no longer in the mailbox", path
            )
        twins = sum(1 for e in getattr(self, "_listed", {}).values() if e[3] == fingerprint)
        if strict and (len(matches) > 1 or twins > 1):
            raise OSError(
                f"POP3 {path}: the server has no UIDL and {max(len(matches), twins)} messages "
                "have the same headers and size, so axross cannot tell which one the path "
                "names after the reconnect; nothing deleted (use a mail client)"
            )
        return matches[0]

    def _check_identity(self, path: str, msgno: int) -> None:
        """FileNotFoundError unless message *msgno* is the one *path*
        names: ``<n>_<subject>.eml`` with the subject the listing gives it
        (TOP n 0). DELE by the number alone deleted another message when
        the path came from elsewhere - a fresh session's "1_salary-letter.eml"
        was message 1 "hello". Nothing is deleted on a mismatch."""
        listed = getattr(self, "_listed", {}).get(msgno)
        if listed and getattr(self, "_listing_generation", -1) == getattr(self, "_generation", 0):
            now = listed[1]  # the listing of this very connection named it
        else:
            now = self._safe_subject(msgno)  # named as list_dir() names it
        if not _names_subject(path, now):
            raise FileNotFoundError(
                errno.ENOENT,
                f"POP3: message {msgno} is {now!r}, not the one the path names; "
                "nothing deleted (list the mailbox again)",
                path,
            )

    def _safe_subject(self, msgno: int) -> str:
        """Message *msgno*'s subject as list_dir() puts it in the name."""
        subject = self._fetch_subject(msgno)
        return _sanitize_filename(subject) if subject else "untitled"

    def _fetch_headers(self, msgno: int) -> bytes | None:
        """TOP <msgno> 0: the message's headers; None when the server
        refuses (a lost connection is raised)."""
        try:
            pop = self._ensure_connected()
            _resp, lines, _octets = self._long_capped(pop, "top", (msgno, 0), f"TOP {int(msgno)} 0",
                                                      MAX_HEADER_BYTES)
        except Exception as exc:  # noqa: BLE001
            if _connection_lost(exc):
                raise
            log.debug("POP3 TOP %d failed: %s", msgno, exc)
            return None
        return b"\r\n".join(
            line if isinstance(line, bytes) else line.encode("utf-8", "replace") for line in lines
        )

    def _fetch_subject(self, msgno: int) -> str:
        """Best-effort: TOP <msgno> 0 returns headers only; parse
        Subject. Failure → empty string (a lost connection is raised)."""
        return _subject_of(self._fetch_headers(msgno))

    @_reconnecting
    @serialized
    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/",
                is_dir=True,
                is_link=False,
                size=0,
                modified=datetime.now(),
                permissions=0o500,
            )
        msgno = _msgno_from_path(path)
        pop = self._ensure_connected()
        try:
            # ``LIST n`` is a single-line reply: ``+OK <msgno> <octets>``.
            resp = pop.list(msgno)
            text = resp.decode("ascii", errors="replace") if isinstance(resp, bytes) else resp
            parts = text.strip().split()
            size = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0
        except poplib.error_proto as exc:
            if not self._listed_now(pop, msgno):
                raise FileNotFoundError(errno.ENOENT, "POP3: no such message", path) from exc
            raise OSError(f"POP3 stat({path}): {exc}") from exc
        return FileItem(
            name=path.lstrip("/"),
            is_dir=False,
            is_link=False,
            size=size,
            modified=datetime.now(),
            permissions=0o400,
        )

    def _listed_now(self, pop, msgno: int) -> bool:
        """Whether the mailbox listing carries *msgno*.

        ``-ERR`` to ``LIST n`` has no standard wording, and a dropped
        connection reaches poplib as ``-ERR EOF`` too. Only the listing
        (which leaves out what this session deleted) tells "no such
        message" apart; a listing that fails is an OSError."""
        try:
            _resp, lines, _octets = self._long_capped(pop, "list", (), "LIST", MAX_LISTING_BYTES)
        except poplib.error_proto as exc:
            raise OSError(f"POP3 LIST failed: {exc}") from exc
        for raw in lines:
            text = raw.decode("ascii", errors="replace") if isinstance(raw, bytes) else raw
            parts = text.split()
            if parts and parts[0] == str(msgno):
                return True
        return False

    def is_dir(self, path: str) -> bool:
        return self.normalize(path) == "/"

    def exists(self, path: str) -> bool:
        """False only when the message is not in the mailbox. A refused,
        dropped or timed-out request is an OSError: the transfer worker
        and server_side_copy(overwrite=False) take False as the go-ahead
        to write."""
        try:
            self.stat(path)
            return True
        except FileNotFoundError:
            return False

    @_reconnecting
    @serialized
    def open_read(self, path: str, mode: str = "rb") -> IO:
        path = self.normalize(path)
        msgno = self._resolve(path)
        pop = self._ensure_connected()
        # The size LIST reports first: over the cap, RETR would have to
        # drop the connection mid-answer - and with it every DELE sent on
        # it (review B4). The cap inside the read stays for a server whose
        # LIST does not tell the truth.
        if self._known_size(msgno) > MAX_MESSAGE_BYTES:
            raise OSError(
                f"POP3 message {msgno} exceeds the {MAX_MESSAGE_BYTES} byte cap. "
                "Use a mail client to fetch.",
            )
        try:
            lines = self._retr_capped(pop, msgno, MAX_MESSAGE_BYTES)
        except poplib.error_proto as exc:
            raise OSError(f"POP3 RETR({path}): {exc}") from exc
        # Every line ends in CRLF, the last one too: the bytes LIST counts
        # (2 were missing, review B20).
        blob = b"".join(
            (line if isinstance(line, bytes) else line.encode("utf-8", "replace")) + b"\r\n"
            for line in lines
        )
        return io.BytesIO(blob)

    def _known_size(self, msgno: int) -> int:
        """The size the listing on THIS connection gave message *msgno*; 0
        when there is none (the cap inside the read still holds)."""
        if getattr(self, "_listing_generation", -1) != getattr(self, "_generation", 0):
            return 0
        return getattr(self, "_listed", {}).get(msgno, ("", "", 0, ""))[2]

    def _long_capped(self, pop, method: str, args: tuple, command: str, cap: int):
        """poplib's *method* (list / uidl / top) as ``(resp, lines,
        octets)``, with *cap* bytes as the most its multi-line answer may
        hold: poplib's _getlongresp() buffers without a limit, and a server
        that never ends the answer grows memory until the process dies.
        Over the cap the connection is dropped (the rest is still on the
        wire) and OSError raised. A stand-in object without poplib's
        internals (tests) is simply asked."""
        if not isinstance(pop, poplib.POP3):
            return getattr(pop, method)(*args)
        pop._putcmd(command)
        resp = pop._getresp()
        lines: list[bytes] = []
        octets = 0
        line, o = pop._getline()
        while line != b".":
            if line.startswith(b".."):
                o -= 1
                line = line[1:]
            octets += o
            if octets > cap:
                with contextlib.suppress(Exception):
                    pop.close()
                self._pop = None
                raise OSError(
                    f"POP3 {command.split()[0]} answer exceeds {cap} bytes{self._lost_deletes_note()}"
                )
            lines.append(line)
            line, o = pop._getline()
        return resp, lines, octets

    def _retr_capped(self, pop, msgno: int, cap: int) -> list[bytes]:
        """``RETR msgno`` with the size cap applied while reading.

        poplib's retr() buffers the whole multi-line answer before
        returning, so checking the cap afterwards let a server that never
        ends a message grow memory without bound. This is poplib's
        _getlongresp() loop with the cap inside it; a message over the cap
        drops the connection (the rest of the answer is still on the wire)
        and the next call reconnects.
        """
        pop._putcmd(f"RETR {msgno}")
        pop._getresp()
        lines: list[bytes] = []
        octets = 0
        line, o = pop._getline()
        while line != b".":
            if line.startswith(b".."):
                o -= 1
                line = line[1:]
            octets += o
            if octets > cap:
                log.warning(
                    "POP3 message %d exceeds the %d byte cap; dropping the connection", msgno, cap
                )
                with contextlib.suppress(Exception):
                    pop.close()
                self._pop = None
                raise OSError(
                    f"POP3 message {msgno} exceeds the {cap} byte cap. Use a mail client to "
                    f"fetch.{self._lost_deletes_note()}",
                )
            lines.append(line)
            line, o = pop._getline()
        return lines

    # ------------------------------------------------------------------
    # FileBackend — write surface (refused; POP3 is read-only)
    # ------------------------------------------------------------------

    @_reconnecting
    @serialized
    def remove(self, path: str, recursive: bool = False) -> None:
        """DELE the message. POP3 only *flags* the message for
        deletion; the actual removal happens on QUIT (when the
        session disconnects). The flag is reset if the session
        ends without QUIT (e.g. RST).

        Document this clearly: a user clicking "delete" sees the
        item disappear from list_dir for the remainder of THIS
        session, and the deletion is committed when they
        disconnect. Re-connecting before disconnect would still
        show the message.
        """
        path = self.normalize(path)
        msgno = self._resolve(path, strict=True)
        self._check_identity(path, msgno)
        pop = self._ensure_connected()
        try:
            pop.dele(msgno)
        except poplib.error_proto as exc:
            raise OSError(f"POP3 DELE({path}): {exc}") from exc
        self._pending_deletes = getattr(self, "_pending_deletes", 0) + 1

    def open_write(self, path: str, append: bool = False) -> IO:
        raise OSError(
            "POP3 has no write surface. Use IMAP for storing messages.",
        )

    def mkdir(self, path: str, parents: bool = False, exist_ok: bool = False) -> None:
        raise OSError(
            "POP3 has no directory hierarchy — mkdir is not supported.",
        )

    def rename(self, src: str, dst: str) -> None:
        raise OSError("POP3 does not support rename.")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("POP3 does not carry POSIX permissions.")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("POP3 does not support copy on the server.")

    # ------------------------------------------------------------------
    # POP3-specific verbs (slice 4 of API_GAPS)
    # ------------------------------------------------------------------

    @serialized
    def stat_mailbox(self) -> tuple[int, int]:
        """``STAT`` — returns ``(message_count, total_octets)``. Cheap;
        every POP3 server supports it."""
        pop = self._ensure_connected()
        count, octets = pop.stat()
        return (int(count), int(octets))

    @serialized
    def uidl(self, msgno: int | None = None) -> dict[int, str] | str:
        """Server-assigned unique-ID listing. Without ``msgno``,
        returns a dict ``{msgno: uid}`` covering every message in the
        maildrop. With ``msgno``, returns just that one UID string.
        Useful for cross-session message identity (POP3 sequence
        numbers shift after RETR + QUIT)."""
        pop = self._ensure_connected()
        if msgno is not None:
            resp = pop.uidl(int(msgno))
            # b"+OK 1 abc..."  → split off the trailing UID
            text = resp.decode("ascii", errors="replace") if isinstance(resp, bytes) else str(resp)
            parts = text.split()
            return parts[-1]
        resp, lines, _ = self._long_capped(pop, "uidl", (), "UIDL", MAX_LISTING_BYTES)
        out: dict[int, str] = {}
        for line in lines:
            text = line.decode("ascii", errors="replace") if isinstance(line, bytes) else str(line)
            tok = text.split()
            if len(tok) >= 2 and tok[0].isdigit():
                out[int(tok[0])] = tok[1]
        return out

    @serialized
    def top(self, msgno: int, n_lines: int = 10) -> bytes:
        """``TOP`` — returns headers + first ``n_lines`` of body.
        Useful for triage without pulling whole messages."""
        pop = self._ensure_connected()
        resp, lines, octets = self._long_capped(pop, "top", (int(msgno), int(n_lines)),
                                                f"TOP {int(msgno)} {int(n_lines)}", MAX_TOP_BYTES)
        # poplib returns lines as bytes; reassemble with CRLF.
        return b"\r\n".join(line if isinstance(line, bytes) else line.encode() for line in lines)

    @serialized
    def dele(self, msgno: int) -> None:
        """Mark a message for deletion. Actual delete happens on
        clean QUIT (``self.disconnect()``)."""
        pop = self._ensure_connected()
        pop.dele(int(msgno))
        self._pending_deletes = getattr(self, "_pending_deletes", 0) + 1

    @serialized
    def rset(self) -> None:
        """``RSET`` — undo all DELE marks issued in this session."""
        pop = self._ensure_connected()
        pop.rset()
        self._pending_deletes = 0

    @serialized
    def noop(self) -> None:
        """``NOOP`` keep-alive."""
        pop = self._ensure_connected()
        pop.noop()
