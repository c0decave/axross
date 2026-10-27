"""IMAP4 backend implementing the FileBackend protocol.

Maps email mailboxes and messages to a filesystem-like interface:

    /                       — root, lists all mailboxes
    /INBOX/                 — lists emails in INBOX as files
    /INBOX/1234_subject.eml — raw email (RFC 822) for message UID 1234
    /INBOX/1234/            — list attachments of message UID 1234
    /INBOX/1234/report.pdf  — download attachment from message 1234

Uses only Python stdlib (imaplib, email).
"""

from __future__ import annotations

import email
import email.errors
import email.header
import email.policy
import contextlib
import errno
import email.utils
import functools
import imaplib
import io
import logging
import posixpath
import re
import tempfile
from datetime import datetime, timedelta, timezone
from typing import IO

from core.backend import SessionLifecycle
from core.session_lock import io_lock, liveness_check, serialized
from models.file_item import FileItem

log = logging.getLogger(__name__)

# Characters not allowed in filenames — replaced with underscore
_FILENAME_BAD_CHARS = re.compile(r'[/\\:*?"<>|\x00-\x1f]')

# The announcement of an IMAP literal: {<octets>} CRLF (RFC 3501 4.3).
_LITERAL_RE = re.compile(rb"\{(\d{1,10})\+?\}\r\n")
_IMAP_SPACE = b" \t\r\n"
_ATOM_END = b" \t\r\n()"

# Matches quota response values like (STORAGE 1234 5678)
_QUOTA_RE = re.compile(r"\(STORAGE\s+(\d+)\s+(\d+)\)", re.IGNORECASE)


def _sanitize_filename(name: str, max_len: int = 120) -> str:
    """Sanitize a string for use as a filename component."""
    name = _FILENAME_BAD_CHARS.sub("_", name)
    name = name.strip(". ")
    if not name:
        name = "untitled"
    if len(name) > max_len:
        name = name[:max_len]
    return name


def _internaldate(text: str) -> datetime:
    """``INTERNALDATE`` ("01-Jul-2026 11:00:00 +0200") as an aware datetime.

    The zone is part of the value: dropping it left the server's wall
    clock reading, which FileItem reads as THIS machine's local time.
    Raises on an unparseable value, like the call it replaces."""
    parts = email.utils.parsedate_tz(text)
    if parts is None:
        raise ValueError(f"unparseable INTERNALDATE: {text!r}")
    when = datetime(*parts[:6])
    if parts[9] is None:
        return when
    return when.replace(tzinfo=timezone(timedelta(seconds=parts[9])))


# Socket timeout for every IMAP connection; the proxied ones get the
# same value from _create_socket below.
IMAP_TIMEOUT = 30.0


class _ProxyIMAP4(imaplib.IMAP4):
    """IMAP4 subclass that builds its TCP socket through a SOCKS /
    HTTP proxy via :func:`core.proxy.create_proxy_socket`.

    ``imaplib`` itself has no proxy hook, but it cleanly delegates
    socket creation to ``_create_socket(self, timeout)``. Overriding
    that one method routes every byte of the IMAP session through
    the proxy without touching the rest of imaplib's state machine.
    """

    def __init__(self, host: str, port: int, proxy_config):
        self._axross_proxy = proxy_config
        super().__init__(host, port)

    def _create_socket(self, timeout=None):
        from core.proxy import create_proxy_socket

        timeout = float(timeout) if timeout is not None else IMAP_TIMEOUT
        return create_proxy_socket(
            self._axross_proxy,
            self.host,
            int(self.port),
            timeout=timeout,
        )


class _ProxyIMAP4_SSL(imaplib.IMAP4_SSL):
    """IMAP4_SSL counterpart. Re-uses the proxy socket-builder, then
    wraps the result in TLS via the SSL context imaplib already
    constructs internally."""

    def __init__(self, host: str, port: int, proxy_config, ssl_context=None):
        self._axross_proxy = proxy_config
        super().__init__(host, port, ssl_context=ssl_context)

    def _create_socket(self, timeout=None):
        from core.proxy import create_proxy_socket

        timeout = float(timeout) if timeout is not None else IMAP_TIMEOUT
        raw = create_proxy_socket(
            self._axross_proxy,
            self.host,
            int(self.port),
            timeout=timeout,
        )
        # ssl_context is populated by IMAP4_SSL.__init__ (defaults to
        # ssl._create_stdlib_context() when None was passed in).
        return self.ssl_context.wrap_socket(raw, server_hostname=self.host)


def _search_uids(raw: bytes | str) -> list[bytes]:
    """The UIDs of a SEARCH answer, as ASCII digit tokens.

    The tokens go back to the server in a FETCH command and into int();
    anything else the server put there (non-ASCII bytes, words) is
    skipped instead of raising UnicodeDecodeError / ValueError.
    """
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return [tok for tok in raw.split() if tok.isdigit()]  # bytes.isdigit(): ASCII only


def _as_bytes(value) -> bytes:
    return value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")


def _imap_responses(data) -> list[bytes]:
    """imaplib's reply *data* as one bytes value per untagged response.

    imaplib splits a response at every literal: ``(line ending in {n},
    literal)``, then the rest of the line as the next element (another
    tuple when it ends in a literal again). The parts are joined back
    into wire form, ``line CRLF literal rest``, so one parser reads the
    whole response.
    """
    out: list[bytes] = []
    pending: bytes | None = None
    for item in data or ():
        if isinstance(item, tuple):
            head = _as_bytes(item[0]) if item else b""
            literal = _as_bytes(item[1]) if len(item) > 1 else b""
            pending = (pending or b"") + head + b"\r\n" + literal
        elif item is not None:
            out.append((pending or b"") + _as_bytes(item))
            pending = None
    if pending is not None:
        out.append(pending)
    return out


def _imap_scalar(raw: bytes, i: int) -> tuple[bytes | None, int]:
    """The string or atom at ``raw[i]``: quoted, literal, NIL (None) or atom."""
    if raw[i : i + 1] == b'"':
        out = bytearray()
        i += 1
        while i < len(raw):
            ch = raw[i]
            if ch == 0x5C and i + 1 < len(raw):  # backslash escapes the next octet
                out.append(raw[i + 1])
                i += 2
                continue
            if ch == 0x22:
                return bytes(out), i + 1
            out.append(ch)
            i += 1
        return bytes(out), i  # unterminated: what arrived
    literal = _LITERAL_RE.match(raw, i)
    if literal:
        start = literal.end()
        end = min(len(raw), start + int(literal.group(1)))
        return raw[start:end], end
    j = i + 1
    while j < len(raw) and raw[j] not in _ATOM_END:
        j += 1
    token = raw[i:j]
    return (None if token.upper() == b"NIL" else token), j


def _imap_value(raw: bytes, i: int = 0):
    """Read one IMAP value from ``raw[i:]``; return ``(value, end)``.

    A parenthesised list is a Python list, NIL is None, a quoted string,
    literal or atom is bytes. Malformed or truncated input yields what was
    readable - a hostile server must not raise anything here. Iterative,
    so deep nesting cannot exhaust the stack.
    """
    stack: list[list] = []
    while True:
        while i < len(raw) and raw[i] in _IMAP_SPACE:
            i += 1
        if i >= len(raw):
            return (stack[0] if stack else None), i
        ch = raw[i]
        if ch == 0x28:  # "("
            new: list = []
            if stack:
                stack[-1].append(new)
            stack.append(new)
            i += 1
            continue
        if ch == 0x29:  # ")"
            if not stack:
                return None, i  # a stray ")": nothing to read here
            done = stack.pop()
            i += 1
            if not stack:
                return done, i
            continue
        value, i = _imap_scalar(raw, i)
        if not stack:
            return value, i
        stack[-1].append(value)


def _parse_list_entry(raw: bytes) -> tuple[str, str, bytes] | None:
    """``(flags, separator, name)`` of one LIST / LSUB response, or None.

    The name is still modified UTF-7; the separator is "" for NIL.
    """
    flags, i = _imap_value(raw)
    if not isinstance(flags, list):
        return None
    sep, i = _imap_value(raw, i)
    name, _ = _imap_value(raw, i)
    if isinstance(sep, list) or not isinstance(name, bytes):
        return None
    flag_text = " ".join(f.decode("ascii", "replace") for f in flags if isinstance(f, bytes))
    return flag_text, (sep or b"").decode("ascii", "replace"), name


def _fetch_attributes(raw: bytes) -> dict[bytes, object]:
    """The ``KEY value`` pairs of one FETCH response (``n (KEY value ...)``).

    Keys are upper-cased; values as :func:`_imap_value` reads them, so a
    string that merely contains ``RFC822.SIZE 1`` is never read as one.
    """
    start = raw.find(b"(")
    if start < 0:
        return {}
    items, _ = _imap_value(raw, start)
    if not isinstance(items, list):
        return {}
    out: dict[bytes, object] = {}
    for k in range(0, len(items) - 1, 2):
        key = items[k]
        if isinstance(key, bytes):
            out.setdefault(key.upper(), items[k + 1])
    return out


def _fetch_number(attrs: dict, key: bytes) -> int | None:
    value = attrs.get(key)
    return int(value) if isinstance(value, bytes) and value.isdigit() else None


def _fetch_date(attrs: dict) -> datetime:
    value = attrs.get(b"INTERNALDATE")
    if isinstance(value, bytes):
        try:
            return _internaldate(value.decode("ascii", "replace"))
        except Exception:  # noqa: BLE001 - the server's date, any shape
            pass
    return datetime.fromtimestamp(0)


def _envelope_subject(envelope) -> str:
    """The decoded subject of a parsed ENVELOPE list (its second field)."""
    if isinstance(envelope, list) and len(envelope) > 1 and isinstance(envelope[1], bytes):
        return _decode_header(envelope[1]) or "no_subject"
    return "no_subject"


def _imap_errors_as_oserror(fn):
    """Re-raise imaplib's protocol errors from ``fn`` as ``OSError``.

    imaplib raises ``IMAP4.error`` for a tagged NO/BAD it does not expect
    and ``IMAP4.abort`` for BYE, a dropped connection or a reply it cannot
    parse - plain Exception subclasses. The backend contract is OSError,
    which is what the pane, transfers and compare handle.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except imaplib.IMAP4.error as exc:
            raise OSError(f"IMAP {fn.__name__}: {exc}") from exc

    return wrapper


def _expunge_one(imap, uid) -> tuple[str, list]:
    """Expunge only message *uid*, never the mailbox's other \\Deleted mail.

    A bare ``EXPUNGE`` permanently removes every message flagged
    ``\\Deleted`` in the selected mailbox, including ones the user
    flagged in another client. Prefer ``UID EXPUNGE`` (UIDPLUS); without
    it, expunge only when ours is the sole flagged message and otherwise
    leave the flag in place - answered as "NO", since the message is still
    there.
    """
    uid = str(uid)
    caps = getattr(imap, "capabilities", ()) or ()
    if any(str(c).upper() == "UIDPLUS" for c in caps):
        return imap.uid("EXPUNGE", uid)
    typ, data = imap.uid("SEARCH", None, "DELETED")
    flagged = b" ".join(data or []).split() if typ == "OK" else None
    if flagged is not None and all(f.decode("ascii", "ignore") == uid for f in flagged):
        return imap.expunge()
    log.warning(
        "IMAP: UID %s flagged \\Deleted but not expunged — server lacks UIDPLUS "
        "and other messages are flagged too",
        uid,
    )
    return "NO", [
        f"UID {uid} is flagged \\Deleted but not expunged: the server lacks UIDPLUS "
        "and an EXPUNGE would also remove the other messages flagged \\Deleted".encode()
    ]


def _decode_header(raw: str | bytes | None) -> str:
    """Decode an RFC 2047 encoded header value into a plain string."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        parts = email.header.decode_header(raw)
    except email.errors.HeaderParseError:
        # A B-encoded word that is not base64 ("=?utf-8?B?S?="): show it
        # as the server sent it.
        return raw
    decoded: list[str] = []
    for fragment, charset in parts:
        if isinstance(fragment, bytes):
            try:
                decoded.append(fragment.decode(charset or "utf-8", errors="replace"))
            except (LookupError, ValueError):  # unknown charset, NUL in its name
                # A charset Python does not know ("=?x-bogus?Q?...?=") is
                # the server's word, not ours: show the bytes as UTF-8,
                # as pop3_client._decode_header does.
                decoded.append(fragment.decode("utf-8", errors="replace"))
        else:
            decoded.append(fragment)
    return " ".join(decoded)


def _imap_utf7_encode(text: str) -> bytes:
    """Encode a mailbox name using modified UTF-7 (IMAP convention).

    ASCII printable characters (0x20-0x7E) except '&' pass through unchanged.
    Non-ASCII characters are encoded as modified BASE64 wrapped in & ... -.
    Literal '&' is encoded as '&-'.
    """
    result = bytearray()
    buf = ""
    for ch in text:
        if 0x20 <= ord(ch) <= 0x7E:
            if buf:
                import base64

                encoded = base64.b64encode(buf.encode("utf-16-be")).rstrip(b"=")
                result.extend(b"&" + encoded.replace(b"/", b",") + b"-")
                buf = ""
            if ch == "&":
                result.extend(b"&-")
            else:
                result.append(ord(ch))
        else:
            buf += ch
    if buf:
        import base64

        encoded = base64.b64encode(buf.encode("utf-16-be")).rstrip(b"=")
        result.extend(b"&" + encoded.replace(b"/", b",") + b"-")
    return bytes(result)


def _imap_utf7_decode(data: bytes) -> str:
    """Decode a modified UTF-7 (IMAP) mailbox name to a Python string."""
    import base64

    result: list[str] = []
    i = 0
    while i < len(data):
        if data[i : i + 1] == b"&":
            # Find the closing '-'
            j = data.find(b"-", i + 1)
            if j == -1:
                # Malformed: no closing '-', treat '&' as literal
                result.append("&")
                i += 1
                continue
            if j == i + 1:
                # "&-" is a literal "&"
                result.append("&")
            else:
                encoded = data[i + 1 : j].replace(b",", b"/")
                # Add padding
                pad = 4 - len(encoded) % 4
                if pad < 4:
                    encoded += b"=" * pad
                try:
                    decoded_bytes = base64.b64decode(encoded, validate=True)
                    result.append(decoded_bytes.decode("utf-16-be"))
                except ValueError:
                    # binascii.Error / UnicodeDecodeError (both ValueError):
                    # the server sent a shift sequence that is not modified
                    # BASE64 of UTF-16. Keep it literally, like the
                    # unterminated "&" above.
                    result.append(data[i : j + 1].decode("ascii", "replace"))
            i = j + 1
        else:
            result.append(chr(data[i]))
            i += 1
    return "".join(result)


class _SpooledWriter:
    """Write to a temp buffer, then IMAP APPEND on close.

    If ``filename`` is set, the written bytes are wrapped in a minimal
    RFC 822 message with the data as an attachment before appending.
    If ``filename`` is None, the bytes are assumed to be a complete
    RFC 822 message already (e.g. when copying .eml files).
    """

    def __init__(
        self,
        imap: imaplib.IMAP4 | imaplib.IMAP4_SSL,
        mailbox: str,
        filename: str | None = None,
        lock=None,
    ):
        self._imap = imap
        self._mailbox = mailbox
        self._filename = filename
        # The session's I/O lock: APPEND runs on the shared handle.
        self._lock = lock if lock is not None else contextlib.nullcontext()
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)
        self._closed = False

    def write(self, data: bytes) -> int:
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    @_imap_errors_as_oserror
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.seek(0)
            raw_bytes = self._buf.read()
        finally:
            self._buf.close()

        if self._filename and not self._filename.lower().endswith(".eml"):
            # Wrap arbitrary file data in a minimal RFC 822 message
            message_bytes = self._wrap_as_email(raw_bytes, self._filename)
        else:
            message_bytes = raw_bytes

        mailbox_encoded = _imap_utf7_encode(self._mailbox).decode("ascii")
        with self._lock:
            typ, data = self._imap.append(mailbox_encoded, None, None, message_bytes)
        if typ != "OK":
            raise OSError(f"IMAP APPEND to {self._mailbox} failed: {data}")
        log.info("Appended %d bytes to mailbox %s", len(message_bytes), self._mailbox)

    def discard(self) -> None:
        """Drop buffered bytes without APPENDing to the mailbox
        (transfer cancel path)."""
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.close()
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _wrap_as_email(data: bytes, filename: str) -> bytes:
        """Wrap raw file data in an RFC 822 message with the file as attachment."""
        import email.mime.base
        import email.mime.multipart
        import email.mime.text
        from email.utils import formatdate

        msg = email.mime.multipart.MIMEMultipart()
        msg["Subject"] = f"File: {filename}"
        msg["From"] = "axross@localhost"
        msg["Date"] = formatdate(localtime=True)
        msg.attach(email.mime.text.MIMEText(f"File '{filename}' uploaded via axross.", "plain"))

        attachment = email.mime.base.MIMEBase("application", "octet-stream")
        attachment.set_payload(data)
        import email.encoders

        email.encoders.encode_base64(attachment)
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=filename,
        )
        msg.attach(attachment)
        return msg.as_bytes()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


class ImapSession(SessionLifecycle):
    """IMAP4 backend implementing the FileBackend protocol.

    Maps IMAP mailboxes to directories and email messages to files,
    providing a filesystem-like view of an IMAP account.
    """

    def __init__(
        self,
        host: str,
        port: int = 993,
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
        self._imap: imaplib.IMAP4 | imaplib.IMAP4_SSL | None = None
        self._hierarchy_sep: str = "/"
        self._selected_mailbox: str | None = None
        self._mailbox_cache: set[str] | None = None

        self._connect()

    def _connect(self) -> None:
        """Establish IMAP connection and authenticate."""
        # ``_proxy`` is set by ``__init__``; defensively tolerate the
        # __new__-bypass pattern some unit tests use.
        proxy = getattr(self, "_proxy", None)
        proxy_active = proxy is not None and proxy.enabled
        # A new connection starts in AUTH state: nothing is selected,
        # whatever the previous connection had open.
        self._selected_mailbox = None
        self._selected_readonly = True
        try:
            if self._use_ssl:
                from core.tls_context import client_tls_context

                tls_ctx = client_tls_context(getattr(self, "_verify_tls", True), label="IMAP")
                if proxy_active:
                    self._imap = _ProxyIMAP4_SSL(
                        self._host, self._port, proxy, ssl_context=tls_ctx
                    )
                else:
                    self._imap = imaplib.IMAP4_SSL(
                        self._host, self._port, ssl_context=tls_ctx, timeout=IMAP_TIMEOUT
                    )
            else:
                # Credentials will traverse the wire in plaintext — this is
                # occasionally legitimate (localhost, overlay VPN), but it
                # is almost always a misconfiguration the user wants to know
                # about.
                log.warning(
                    "IMAP connecting to %s:%d WITHOUT TLS — credentials will be sent in plaintext",
                    self._host,
                    self._port,
                )
                if proxy_active:
                    self._imap = _ProxyIMAP4(self._host, self._port, proxy)
                else:
                    self._imap = imaplib.IMAP4(self._host, self._port, timeout=IMAP_TIMEOUT)

            typ, data = self._imap.login(self._username, self._password)
            if typ != "OK":
                raise ConnectionError(f"IMAP LOGIN failed: {data}")

            # Detect hierarchy separator from LIST
            try:
                typ, data = self._imap.list('""', '""')
                responses = _imap_responses(data) if typ == "OK" else []
                entry = _parse_list_entry(responses[0]) if responses else None
                if entry is not None:
                    sep = entry[1].strip()
                    if sep:
                        self._hierarchy_sep = sep
            except Exception as exc:
                log.debug("Could not detect hierarchy separator: %s", exc)

            log.info(
                "IMAP%s connected: %s@%s:%d (sep=%r)",
                "S" if self._use_ssl else "",
                self._username,
                self._host,
                self._port,
                self._hierarchy_sep,
            )
        except Exception:
            self._imap = None
            raise

    def _ensure_connected(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        """Return the IMAP connection, reconnecting if needed."""
        if self._imap is None:
            self._connect()
        assert self._imap is not None
        try:
            self._imap.noop()
        except Exception:
            self._connect()
        assert self._imap is not None
        return self._imap

    def _select_mailbox(self, mailbox: str, readonly: bool = True) -> None:
        """Select a mailbox if not already selected.

        Tracks the writable/read-only mode in the cache so that a
        subsequent call asking for write access re-selects when
        the previous selection was read-only (otherwise STOREs
        would silently no-op against an EXAMINE'd mailbox).
        """
        imap = self._ensure_connected()
        encoded = _imap_utf7_encode(mailbox).decode("ascii")
        if (
            self._selected_mailbox == mailbox
            and getattr(self, "_selected_readonly", True) == readonly
        ):
            return
        # A failed SELECT deselects whatever was selected (RFC 3501
        # 6.3.1): forget it first, so the next call selects again instead
        # of sending FETCH in the authenticated state.
        self._selected_mailbox = None
        typ, data = imap.select(encoded, readonly=readonly)
        if typ != "OK":
            raise OSError(f"Cannot select mailbox {mailbox!r}: {data}")
        self._selected_mailbox = mailbox
        self._selected_readonly = readonly

    def _list_entries(self) -> list[tuple[str, bool]]:
        """``(name, selectable)`` of every mailbox LIST returns; refreshes
        the name cache. \\Noselect and \\NonExistent (RFC 5258, implies
        \\Noselect - Dovecot's deleted parent of living sub-mailboxes)
        mark a name that cannot be opened."""
        imap = self._ensure_connected()
        typ, data = imap.list()
        if typ != "OK":
            raise OSError(f"IMAP LIST failed: {data}")

        entries: list[tuple[str, bool]] = []
        for raw in _imap_responses(data):
            entry = _parse_list_entry(raw)
            if entry is None:
                log.debug("Unparseable LIST entry: %r", raw)
                continue
            flags = entry[0].lower()
            selectable = "\\noselect" not in flags and "\\nonexistent" not in flags
            entries.append((_imap_utf7_decode(entry[2]), selectable))

        self._mailbox_cache = {name for name, _ in entries}
        return entries

    def _mailbox_names(self) -> set[str]:
        """Return known mailbox names, refreshing from IMAP when needed."""
        if self._mailbox_cache is None:
            self._list_entries()
        return set(self._mailbox_cache or ())

    def _mailbox_nodes(self) -> set[str]:
        """Known mailbox names plus every parent level above them.

        A server need not list the parent of a nested mailbox (or lists
        it \\Noselect); its path is still a folder on the way down.
        """
        sep = self._hierarchy_sep
        nodes = self._mailbox_names()
        for name in list(nodes):
            pieces = name.split(sep)
            for depth in range(1, len(pieces)):
                nodes.add(sep.join(pieces[:depth]))
        return nodes

    @property
    def _tree_view(self) -> bool:
        """Whether nested mailboxes are listed level by level.

        With "/" as the hierarchy separator a full name ("Work/2025") is
        no single path component, so each directory lists only its
        first-level sub-mailboxes. Any other separator keeps the flat
        listing: "box.sub" is a valid name at the root.
        """
        return self._hierarchy_sep == "/"

    @staticmethod
    def _sub_mailboxes(entries: list[tuple[str, bool]], parent: str) -> list[FileItem]:
        """The first-level folders below *parent* ("" for the root).

        One per child name, shown when it, or a mailbox below it, can be
        opened. A name with an empty level ("a//b") is unreachable by any
        normalised path and is left out.
        """
        prefix = f"{parent}/" if parent else ""
        children: dict[str, None] = {}
        for name, selectable in entries:
            if not selectable or not name.startswith(prefix):
                continue
            levels = name[len(prefix) :].split("/")
            if "" in levels:
                log.debug("Skipping mailbox with an empty level: %r", name)
                continue
            children.setdefault(levels[0])
        return [FileItem(name=child, is_dir=True) for child in children]

    def _split_mailbox(self, parts: list[str]) -> tuple[str | None, list[str]]:
        """The longest leading run of *parts* that names a known mailbox
        (or a parent level of one), and the parts after it."""
        nodes = self._mailbox_nodes()
        for index in range(len(parts), 0, -1):
            candidate = self._hierarchy_sep.join(parts[:index])
            if candidate in nodes:
                return candidate, parts[index:]
        return None, parts

    def _virtual_path_to_mailbox(self, path: str) -> str:
        """Map a virtual path like ``/Inbox/Sub`` to an IMAP mailbox name."""
        normalized = self.normalize(path)
        parts = [p for p in normalized.split("/") if p]
        if not parts:
            raise OSError("Root is not a mailbox")
        return self._hierarchy_sep.join(parts)

    @staticmethod
    def _attachment_name(part) -> str | None:
        filename = part.get_filename()
        if filename:
            return _sanitize_filename(filename)

        content_disp = part.get("Content-Disposition", "")
        if "attachment" not in content_disp.lower():
            return None

        content_type = part.get_content_type()
        ext = content_type.split("/")[-1] if "/" in content_type else "bin"
        return f"attachment.{ext}"

    @classmethod
    def _named_attachments(cls, msg) -> list[tuple[str, object]]:
        """``(name, part)`` for every attachment of *msg*, names unique.

        Two attachments may carry the same file name (or sanitise to it).
        Later ones get ``.1``, ``.2`` ... before the extension, skipping
        any name another attachment really carries, so listing, stat and
        open_read address each part by one name of its own.
        """
        parts = [(cls._attachment_name(part), part) for part in msg.walk()]
        parts = [(name, part) for name, part in parts if name is not None]
        carried = {name for name, _ in parts}
        used: set[str] = set()
        out: list[tuple[str, object]] = []
        for base, part in parts:
            name = base
            if name in used:
                root, dot, ext = base.rpartition(".")
                n = 0
                while name in used or name in carried:
                    n += 1
                    name = f"{root}.{n}.{ext}" if dot and root else f"{base}.{n}"
            used.add(name)
            out.append((name, part))
        return out

    @classmethod
    def _find_attachment(cls, msg, att_name: str):
        """The part listed as *att_name*, or None."""
        for name, part in cls._named_attachments(msg):
            if name == att_name:
                return part
        return None

    # ------------------------------------------------------------------
    # Path parsing
    # ------------------------------------------------------------------

    def _parse_path(self, path: str) -> tuple:
        """Parse a virtual path into components.

        Returns:
            (None,)                         — root (list mailboxes)
            (mailbox,)                      — list messages in mailbox
            (mailbox, uid)                  — specific message (.eml)
            (mailbox, uid, attachment_name) — specific attachment
        """
        path = self.normalize(path)
        parts = [p for p in path.split("/") if p]

        if not parts:
            return (None,)

        mailbox, remainder = self._split_mailbox(parts)
        if mailbox is None:
            mailbox = parts[0]
            remainder = parts[1:]

        if not remainder:
            return (mailbox,)

        # Second part is either "uid.eml" or "uid" (directory for attachments)
        name_part = remainder[0]
        uid_str = name_part
        # Strip .eml extension if present
        if uid_str.lower().endswith(".eml"):
            uid_str = uid_str[:-4]
        # Extract UID: it's the part before the first underscore
        uid_match = re.match(r"^(\d+)", uid_str)
        if not uid_match:
            # Non-UID filename (e.g. transfer temp file ".readme.txt.part-xxx"
            # or an arbitrary file being written).  Return mailbox + raw name
            # so callers can handle it gracefully.
            if len(remainder) == 1:
                return (mailbox, None)
            # A message is named by its UID: nothing can be below this name.
            raise FileNotFoundError(
                errno.ENOENT, f"Invalid message identifier in path: {name_part!r}", path
            )
        uid = uid_match.group(1)

        if len(remainder) == 1:
            if name_part.lower().endswith(".eml"):
                # Explicit .eml reference — this is the raw message
                return (mailbox, uid)
            # Could be a directory (listing attachments) or a message file
            # Treat as message if it looks like "uid_subject.eml", directory otherwise
            return (mailbox, uid)

        if len(remainder) == 2:
            attachment_name = remainder[1]
            return (mailbox, uid, attachment_name)

        raise FileNotFoundError(errno.ENOENT, "Path too deep", path)

    # ------------------------------------------------------------------
    # FileBackend interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        proto = "IMAPS" if self._use_ssl else "IMAP"
        return f"{self._username}@{self._host} ({proto})"

    @property
    @liveness_check
    def connected(self) -> bool:
        if self._imap is None:
            return False
        try:
            self._imap.noop()
            return True
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("IMAP liveness check failed: %s", exc)
            return False

    def close(self) -> None:
        self.disconnect()

    @serialized
    def disconnect(self) -> None:
        """Close the IMAP connection."""
        if self._imap is not None:
            try:
                if self._selected_mailbox is not None:
                    self._imap.close()
            except Exception:
                pass
            try:
                self._imap.logout()
            except Exception:
                pass
            self._imap = None
            self._selected_mailbox = None
            self._mailbox_cache = None
        log.info("Disconnected from %s", self._host)

    @_imap_errors_as_oserror
    @serialized
    def list_dir(self, path: str) -> list[FileItem]:
        """List directory contents at the given virtual path."""
        parsed = self._parse_path(path)

        if parsed == (None,):
            return self._list_mailboxes()
        if len(parsed) == 1:
            mailbox = parsed[0]
            folders: list[FileItem] = []
            if self._tree_view:
                entries = self._list_entries()
                folders = self._sub_mailboxes(entries, mailbox)
                if folders and (mailbox, True) not in entries:
                    # \Noselect or not listed: a folder of folders only.
                    return folders
            try:
                return folders + self._list_messages(mailbox)
            except OSError:
                if self._is_hierarchy_only(mailbox):
                    return folders
                raise
        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                raise FileNotFoundError(f"Path not found: {path}")
            return self._list_attachments(mailbox, uid)

        raise OSError(f"Cannot list: {path!r} is a file, not a directory")

    def _list_mailboxes(self) -> list[FileItem]:
        """List the mailboxes at the root as directory entries.

        Names that cannot be opened (\\Noselect, \\NonExistent) are left
        out - in the tree view unless a mailbox below them can be opened.
        """
        entries = self._list_entries()
        if self._tree_view:
            return self._sub_mailboxes(entries, "")
        return [FileItem(name=name, is_dir=True) for name, selectable in entries if selectable]

    def _list_messages(self, mailbox: str) -> list[FileItem]:
        """List messages in a mailbox as file entries."""
        self._select_mailbox(mailbox, readonly=True)
        imap = self._ensure_connected()

        typ, data = imap.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise OSError(f"IMAP UID SEARCH failed in {mailbox!r}: {data}")

        uids_raw = data[0]
        if not uids_raw or not uids_raw.strip():
            return []

        uid_list = _search_uids(uids_raw)
        items: list[FileItem] = []

        # Fetch envelopes in batches to avoid overly long commands
        batch_size = 100
        for i in range(0, len(uid_list), batch_size):
            batch = b",".join(uid_list[i : i + batch_size])
            typ, fetch_data = imap.uid(
                "FETCH", batch.decode("ascii"), "(ENVELOPE RFC822.SIZE INTERNALDATE)"
            )
            if typ != "OK":
                log.warning("FETCH failed for UIDs %s: %s", batch, fetch_data)
                continue

            for response in _imap_responses(fetch_data):
                attrs = _fetch_attributes(response)
                uid = attrs.get(b"UID")
                if not isinstance(uid, bytes) or not uid.isdigit():
                    continue
                uid = uid.decode("ascii")
                subject = _envelope_subject(attrs.get(b"ENVELOPE"))
                sanitized_subject = _sanitize_filename(subject, max_len=80)
                items.append(
                    FileItem(
                        name=f"{uid}_{sanitized_subject}.eml",
                        size=_fetch_number(attrs, b"RFC822.SIZE") or 0,
                        modified=_fetch_date(attrs),
                    )
                )

        return items

    def _extract_envelope_subject(self, envelope_str: str) -> str:
        """The decoded subject of an ``ENVELOPE (...)`` text.

        The ENVELOPE is ``(date subject from sender reply-to to cc bcc
        in-reply-to message-id)``; the subject is a quoted string, a
        literal or NIL.
        """
        raw = envelope_str.encode("utf-8", "replace")
        start = raw.find(b"(")
        if start < 0:
            return "no_subject"
        return _envelope_subject(_imap_value(raw, start)[0])

    def _list_attachments(self, mailbox: str, uid: str) -> list[FileItem]:
        """List MIME attachments of a specific message as file entries."""
        raw = self._fetch_raw_message(mailbox, uid)
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        items: list[FileItem] = []

        for attachment_name, part in self._named_attachments(msg):
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            items.append(
                FileItem(
                    name=attachment_name,
                    size=size,
                )
            )

        return items

    def _select_existing(self, mailbox: str, path: str) -> None:
        """``_select_mailbox`` (read-only), with a mailbox that is not
        there as FileNotFoundError.

        A refused SELECT says nothing by itself - its wording is free, and
        a locked or busy mailbox is refused too. A fresh LIST decides: a
        mailbox it does not carry as selectable holds no message. A LIST
        that fails, or one that carries the mailbox, leaves the OSError."""
        try:
            self._select_mailbox(mailbox, readonly=True)
        except OSError as exc:
            if (mailbox, True) not in self._list_entries():
                raise FileNotFoundError(
                    errno.ENOENT, f"No such mailbox: {mailbox}", path
                ) from exc
            raise

    def _fetch_raw_message(self, mailbox: str, uid: str) -> bytes:
        """Fetch the full RFC822 body of a message by UID."""
        where = f"/{mailbox}/{uid}"
        self._select_existing(mailbox, where)
        imap = self._ensure_connected()
        typ, data = imap.uid("FETCH", uid, "(RFC822)")
        if typ != "OK":
            raise OSError(f"Cannot fetch message UID {uid} from {mailbox!r}: {data}")
        for response_part in data:
            if isinstance(response_part, tuple):
                return response_part[1]
        if not any(part for part in data or ()):
            # UID FETCH of a UID that is not there answers OK, no data.
            raise FileNotFoundError(errno.ENOENT, "No such message", where)
        raise OSError(f"No RFC822 body returned for UID {uid} in {mailbox!r}")

    @_imap_errors_as_oserror
    @serialized
    def stat(self, path: str) -> FileItem:
        """Return a FileItem for the given virtual path."""
        parsed = self._parse_path(path)

        if parsed == (None,):
            return FileItem(name="/", is_dir=True)

        if len(parsed) == 1:
            # Mailbox, or a parent level of one
            mailbox = parsed[0]
            if mailbox not in self._mailbox_nodes():
                raise FileNotFoundError(f"Mailbox not found: {mailbox}")
            return FileItem(name=posixpath.basename(self.normalize(path)), is_dir=True)

        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                raise FileNotFoundError(f"Path not found: {path}")
            # Check if path ends with .eml
            normalized = self.normalize(path)
            parts = [p for p in normalized.split("/") if p]
            leaf_name = parts[-1] if parts else path
            if leaf_name.lower().endswith(".eml"):
                # It's a message file
                self._select_existing(mailbox, path)
                imap = self._ensure_connected()
                typ, data = imap.uid("FETCH", uid, "(RFC822.SIZE INTERNALDATE)")
                if typ != "OK":
                    raise OSError(f"Cannot stat message UID {uid}: {data}")
                size = 0
                modified = datetime.fromtimestamp(0)
                if not any(part for part in data or ()):
                    # UID FETCH of a UID that is not there answers OK, no data.
                    raise FileNotFoundError(errno.ENOENT, "No such message", path)
                for response in _imap_responses(data):
                    # A reply with a literal arrives split into a (line,
                    # literal) tuple and the rest of the line; joined here.
                    attrs = _fetch_attributes(response)
                    found = _fetch_number(attrs, b"RFC822.SIZE")
                    if found is not None:
                        size = found
                    if b"INTERNALDATE" in attrs:
                        modified = _fetch_date(attrs)
                return FileItem(name=leaf_name, size=size, modified=modified)
            else:
                # It's the attachment directory for this UID
                return FileItem(name=uid, is_dir=True)

        if len(parsed) == 3:
            mailbox, uid, att_name = parsed
            # Stat an attachment
            raw = self._fetch_raw_message(mailbox, uid)
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            part = self._find_attachment(msg, att_name)
            if part is not None:
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
                return FileItem(name=att_name, size=size)
            raise FileNotFoundError(
                errno.ENOENT, f"Attachment {att_name!r} not found in UID {uid}", path
            )

        raise OSError(f"Invalid path: {path!r}")

    @_imap_errors_as_oserror
    def is_dir(self, path: str) -> bool:
        """Check if the path refers to a directory-like entity."""
        parsed = self._parse_path(path)
        if parsed == (None,):
            return True
        if len(parsed) == 1:
            return parsed[0] in self._mailbox_nodes()
        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                return False  # Non-UID filename — treat as file
            # Check if it's a .eml file reference or attachment dir
            normalized = self.normalize(path)
            parts = [p for p in normalized.split("/") if p]
            if parts and parts[-1].lower().endswith(".eml"):
                return False
            return True  # Attachment listing directory
        return False  # Attachment file

    def exists(self, path: str) -> bool:
        """False only when the mailbox, message or attachment is not there.
        A refused, dropped or timed-out request is an OSError: the transfer
        worker takes False as the go-ahead to write."""
        try:
            self.stat(path)
            return True
        except FileNotFoundError:
            return False

    @_imap_errors_as_oserror
    @serialized
    def mkdir(self, path: str) -> None:
        """Create a new mailbox."""
        mailbox = self._virtual_path_to_mailbox(path)
        imap = self._ensure_connected()
        encoded = _imap_utf7_encode(mailbox).decode("ascii")
        typ, data = imap.create(encoded)
        if typ != "OK":
            raise OSError(f"Cannot create mailbox {mailbox!r}: {data}")
        self._mailbox_cache = None
        log.info("Created mailbox: %s", mailbox)

    @_imap_errors_as_oserror
    @serialized
    def remove(self, path: str, recursive: bool = False) -> None:
        """Delete a message or mailbox.

        For messages: mark \\Deleted and expunge.
        For mailboxes: delete the mailbox via IMAP DELETE.
        """
        parsed = self._parse_path(path)

        if parsed == (None,):
            raise OSError("Cannot remove root")

        if len(parsed) == 1:
            self._remove_mailbox_tree(parsed[0], path, recursive)
            return

        if len(parsed) >= 3:
            # An attachment is part of its message: deleting it would
            # mean rewriting the mail, and acting on the UID would
            # delete the whole message.
            raise OSError(f"Cannot remove a single attachment: {path!r}")

        if len(parsed) == 2:
            mailbox, uid = parsed[0], parsed[1]
            if uid is None:
                log.debug("Ignoring remove for non-UID path: %s", path)
                return  # Non-UID path (temp file etc.) — nothing to delete
            self._select_mailbox(mailbox, readonly=False)
            imap = self._ensure_connected()
            typ, data = imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
            if typ != "OK":
                raise OSError(f"Cannot mark UID {uid} as deleted in {mailbox!r}: {data}")
            typ, data = _expunge_one(imap, uid)
            self._selected_mailbox = None  # State may have changed
            if typ != "OK":
                # The message is still in the mailbox (flagged \Deleted):
                # reporting success would make it reappear on the next
                # listing. An expunge from any client completes it.
                raise OSError(
                    f"Cannot remove message UID {uid} from {mailbox!r}: "
                    + b" ".join(_as_bytes(d) for d in data or ()).decode("utf-8", "replace")
                )
            log.info("Deleted message UID %s from %s", uid, mailbox)
            return

        raise OSError(f"Cannot remove: {path!r}")

    def _is_hierarchy_only(self, mailbox: str) -> bool:
        """A name that only holds sub-mailboxes and cannot be opened.

        Another client's single DELETE of a parent leaves one behind; the
        lab Dovecot lists it as plain \\HasChildren and refuses SELECT.
        """
        prefix = mailbox + self._hierarchy_sep
        if not any(name.startswith(prefix) for name in self._mailbox_names()):
            return False
        encoded = _imap_utf7_encode(mailbox).decode("ascii")
        typ, _ = self._ensure_connected().status(encoded, "(MESSAGES)")
        return typ != "OK"

    def _message_count(self, mailbox: str) -> int:
        """Messages in *mailbox* by STATUS; 0 for a name that cannot hold any."""
        imap = self._ensure_connected()
        encoded = _imap_utf7_encode(mailbox).decode("ascii")
        typ, data = imap.status(encoded, "(MESSAGES)")
        if typ != "OK":
            return 0
        raw = b" ".join(d if isinstance(d, bytes) else str(d).encode() for d in data if d)
        match = re.search(rb"MESSAGES\s+(\d+)", raw, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    def _delete_mailbox(self, mailbox: str) -> tuple[str, list]:
        imap = self._ensure_connected()
        # Unselect current mailbox if it's the one being deleted
        if self._selected_mailbox == mailbox:
            try:
                imap.close()
            except Exception:
                pass
            self._selected_mailbox = None
        encoded = _imap_utf7_encode(mailbox).decode("ascii")
        return imap.delete(encoded)

    def _remove_mailbox_tree(self, mailbox: str, path: str, recursive: bool) -> None:
        """Delete *mailbox*; with *recursive* its sub-mailboxes first.

        A single DELETE leaves the sub-mailboxes behind (RFC 3501 6.3.4),
        and Dovecot then lists the deleted parent as \\NonExistent.
        """
        prefix = mailbox + self._hierarchy_sep
        children = sorted(
            (name for name in self._mailbox_names() if name.startswith(prefix)),
            key=lambda name: name.count(self._hierarchy_sep),
            reverse=True,
        )
        if not recursive and (children or self._message_count(mailbox)):
            raise OSError(
                errno.ENOTEMPTY,
                f"Mailbox {mailbox!r} has messages or sub-mailboxes; remove it recursively",
                path,
            )
        try:
            for child in children:
                typ, data = self._delete_mailbox(child)
                if typ != "OK":
                    raise OSError(f"Cannot delete mailbox {child!r}: {data}")
                log.info("Deleted mailbox: %s", child)
            typ, data = self._delete_mailbox(mailbox)
        finally:
            self._mailbox_cache = None
        if typ != "OK":
            # A parent that only held the deleted sub-mailboxes is gone
            # with the last of them.
            if children and mailbox not in self._mailbox_names():
                return
            raise OSError(f"Cannot delete mailbox {mailbox!r}: {data}")
        log.info("Deleted mailbox: %s", mailbox)

    @_imap_errors_as_oserror
    @serialized
    def rename(self, src: str, dst: str) -> None:
        """Rename a mailbox or move a message.

        For mailboxes: IMAP RENAME.
        For messages: COPY to new mailbox + DELETE from old.
        """
        src_parsed = self._parse_path(src)
        dst_parsed = self._parse_path(dst)

        # Rename mailbox
        if (
            len(src_parsed) == 1
            and src_parsed[0] is not None
            and src_parsed[0] in self._mailbox_names()
        ):
            old_name = src_parsed[0]
            new_name = self._virtual_path_to_mailbox(dst)
            imap = self._ensure_connected()
            if self._selected_mailbox == old_name:
                try:
                    imap.close()
                except Exception:
                    pass
                self._selected_mailbox = None
            old_enc = _imap_utf7_encode(old_name).decode("ascii")
            new_enc = _imap_utf7_encode(new_name).decode("ascii")
            typ, data = imap.rename(old_enc, new_enc)
            if typ != "OK":
                raise OSError(f"Cannot rename mailbox {old_name!r} to {new_name!r}: {data}")
            self._mailbox_cache = None
            log.info("Renamed mailbox %s -> %s", old_name, new_name)
            return

        if len(src_parsed) >= 3:
            raise OSError(f"Cannot rename or move a single attachment: {src!r}")

        # Move message: copy to new mailbox, then delete from old
        if len(src_parsed) == 2 and len(dst_parsed) >= 1:
            src_mailbox, src_uid = src_parsed[0], src_parsed[1]
            if src_uid is None:
                raise OSError(f"Cannot rename non-message path: {src!r}")
            dst_mailbox = dst_parsed[0]
            if dst_mailbox is None:
                raise OSError("Cannot move message to root")

            self._select_mailbox(src_mailbox, readonly=False)
            imap = self._ensure_connected()

            dst_enc = _imap_utf7_encode(dst_mailbox).decode("ascii")
            typ, data = imap.uid("COPY", src_uid, dst_enc)
            if typ != "OK":
                raise OSError(f"Cannot copy UID {src_uid} to {dst_mailbox!r}: {data}")

            # Delete from source
            typ, data = imap.uid("STORE", src_uid, "+FLAGS", "(\\Deleted)")
            if typ != "OK":
                log.warning(
                    "Could not mark UID %s as deleted after copy: %s",
                    src_uid,
                    data,
                )
            _expunge_one(imap, src_uid)
            self._selected_mailbox = None
            log.info(
                "Moved message UID %s from %s to %s",
                src_uid,
                src_mailbox,
                dst_mailbox,
            )
            return

        raise OSError(f"Cannot rename {src!r} to {dst!r}")

    @_imap_errors_as_oserror
    @serialized
    def open_read(self, path: str) -> IO[bytes]:
        """Download an email (.eml) or an attachment."""
        parsed = self._parse_path(path)

        if len(parsed) == 2:
            mailbox, uid = parsed
            if uid is None:
                raise OSError(f"Cannot read non-message path: {path!r}")
            raw = self._fetch_raw_message(mailbox, uid)
            return io.BytesIO(raw)

        if len(parsed) == 3:
            # Specific attachment
            mailbox, uid, att_name = parsed
            raw = self._fetch_raw_message(mailbox, uid)
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            part = self._find_attachment(msg, att_name)
            if part is not None:
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = b""
                return io.BytesIO(payload)
            raise OSError(f"Attachment {att_name!r} not found in UID {uid} of {mailbox!r}")

        raise OSError(f"Cannot read: {path!r} is a directory")

    @_imap_errors_as_oserror
    @serialized
    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        """Upload / append a message to a mailbox (IMAP APPEND).

        Accepts paths like:
            /INBOX              — write raw RFC 822 bytes directly
            /INBOX/readme.txt   — wrap arbitrary file in an RFC 822 email
            /INBOX/5_sub.eml    — write raw RFC 822 bytes directly
            /Work/2025/note.eml — the same into a nested mailbox

        The transfer worker may create temp paths like
        ``/INBOX/.readme.txt.part-<id>`` which are not valid UID references.
        So the mailbox is resolved like ``_parse_path()`` does it, but the
        rest is kept as a file name instead of being read as a UID.
        """
        normalized = self.normalize(path)
        parts = [p for p in normalized.split("/") if p]

        if not parts:
            raise OSError(f"Cannot write to root: {path!r}")

        imap = self._ensure_connected()
        # The mailbox is the longest leading run of the path that names one,
        # as for every other path ("/Work/2025/note.eml" -> "Work/2025").
        mailbox, rest = self._split_mailbox(parts)

        if mailbox is None and len(parts) == 1:
            # Single unknown component — could be a write to root like
            # "/bigfile.bin" or a mailbox the cached LIST does not know yet.
            # Check whether it exists; if not, treat it as a filename and
            # write to INBOX.
            # The probe goes through _select_mailbox so the session's idea of
            # what is selected, and how, stays the server's: a successful
            # EXAMINE is read-only, a failed one deselects (RFC 3501 6.3.1).
            # A mailbox that is selected already exists; no probe needed.
            mailbox = parts[0]
            if self._selected_mailbox == mailbox:
                return _SpooledWriter(imap, mailbox, lock=io_lock(self))
            try:
                self._select_mailbox(mailbox, readonly=True)
                return _SpooledWriter(imap, mailbox, lock=io_lock(self))
            except (OSError, imaplib.IMAP4.error):
                pass
            # Mailbox doesn't exist — treat as filename, write to INBOX
            filename = mailbox
            mailbox = "INBOX"
            log.info("IMAP write to root-level file %r — using mailbox INBOX", filename)
            return _SpooledWriter(imap, mailbox, filename=filename, lock=io_lock(self))

        if mailbox is None:
            mailbox, rest = parts[0], parts[1:]

        if not rest:
            # The mailbox itself: raw RFC 822 bytes
            return _SpooledWriter(imap, mailbox, lock=io_lock(self))

        if len(rest) == 1:
            # Pass filename so _SpooledWriter can wrap non-.eml data
            return _SpooledWriter(imap, mailbox, filename=rest[0], lock=io_lock(self))

        raise OSError(f"Cannot write to {path!r}: only message-level writes are supported")

    def normalize(self, path: str) -> str:
        """Normalize a virtual path."""
        path = (path or "/").replace("\\", "/")
        result = posixpath.normpath(path)
        if result == ".":
            return "/"
        if not result.startswith("/"):
            return f"/{result}"
        return result

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(self.normalize(path)) or "/"

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("IMAP does not support Unix permissions")

    def readlink(self, path: str) -> str:
        raise OSError("IMAP does not support symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """IMAP has COPY for messages between mailboxes but the
        FileBackend abstraction doesn't map cleanly to that; raise
        for fallback so callers stay protocol-agnostic."""
        raise OSError("IMAP copy between mailboxes not exposed as FS primitive")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """IMAP doesn't checksum messages — FETCH BODY[] returns the
        full RFC822 which callers can stream-hash themselves."""
        return ""

    # ------------------------------------------------------------------
    # IMAP-specific verbs (slice 4 of API_GAPS)
    # ------------------------------------------------------------------

    @_imap_errors_as_oserror
    @serialized
    def search(self, criteria: str = "ALL", *, mailbox: str = "INBOX") -> list[int]:
        """Run an IMAP SEARCH against ``mailbox`` and return the
        matching UIDs (NOT the message-sequence numbers — UIDs are
        stable across sessions; sequence numbers shift after expunge).

        ``criteria`` is the raw IMAP search string (RFC 3501 §6.4.4),
        e.g.::

            sess.search('FROM "boss@x.com" SINCE 1-Jan-2026')
            sess.search('UNSEEN SUBJECT "invoice"')
            sess.search('LARGER 1048576')   # > 1 MiB

        F32: refuse CR/LF in ``criteria`` and ``mailbox``. imaplib
        sends each command as ``<tag> <verb> <args>\\r\\n`` without
        re-escaping embedded CR/LF in the args, so a tainted
        criterion would smuggle a second IMAP command on the same
        connection. We block this BEFORE the wire frame is built.

        Caller is still responsible for escaping ``"`` characters
        inside quoted-string criteria — that's an IMAP-syntax issue
        rather than a smuggling one.
        """
        if "\r" in criteria or "\n" in criteria:
            raise ValueError(
                "IMAP search: criteria must not contain CR/LF (would "
                "smuggle a second IMAP command). F32."
            )
        if "\r" in mailbox or "\n" in mailbox:
            raise ValueError("IMAP search: mailbox must not contain CR/LF. F32.")
        imap = self._ensure_connected()
        self._select_mailbox(mailbox, readonly=True)
        typ, data = imap.uid("SEARCH", None, criteria)
        if typ != "OK":
            raise OSError(f"IMAP SEARCH failed: {data}")
        if not data or data[0] is None:
            return []
        return [int(u) for u in _search_uids(data[0])]

    @_imap_errors_as_oserror
    @serialized
    def fetch_flags(self, uid: int, *, mailbox: str = "INBOX") -> list[str]:
        """Return the flags currently set on a message (e.g.
        ``["\\Seen", "\\Answered"]``)."""
        imap = self._ensure_connected()
        self._select_mailbox(mailbox, readonly=True)
        typ, data = imap.uid("FETCH", str(int(uid)), "(FLAGS)")
        if typ != "OK" or not data:
            raise OSError(f"IMAP FETCH FLAGS failed: {data}")
        raw = data[0].decode() if isinstance(data[0], bytes) else str(data[0])
        m = re.search(r"FLAGS\s*\(([^)]*)\)", raw)
        if not m:
            return []
        return [f for f in m.group(1).split() if f]

    @_imap_errors_as_oserror
    @serialized
    def set_flags(
        self,
        uid: int,
        flags: list[str] | tuple[str, ...],
        *,
        mailbox: str = "INBOX",
        mode: str = "set",
    ) -> None:
        """STORE flags on a message. ``mode`` is ``"set"`` (replace),
        ``"add"`` (``+FLAGS``), or ``"remove"`` (``-FLAGS``).

        ``flags`` are raw IMAP flag strings like ``"\\Seen"``,
        ``"\\Flagged"``, ``"\\Deleted"``, or any custom keyword the
        server allows.
        """
        if mode == "set":
            verb = "FLAGS"
        elif mode == "add":
            verb = "+FLAGS"
        elif mode == "remove":
            verb = "-FLAGS"
        else:
            raise ValueError(f"set_flags mode must be set/add/remove, got {mode!r}")
        # Validate flags shape — imaplib will happily smuggle a CR/LF
        # into the wire if we don't.
        for f in flags:
            if "\r" in f or "\n" in f or " " in f:
                raise ValueError(f"set_flags flag {f!r} must not contain CR/LF/space")
        imap = self._ensure_connected()
        self._select_mailbox(mailbox, readonly=False)
        typ, data = imap.uid(
            "STORE",
            str(int(uid)),
            verb,
            "(" + " ".join(flags) + ")",
        )
        if typ != "OK":
            raise OSError(f"IMAP STORE {verb} failed: {data}")

    @_imap_errors_as_oserror
    @serialized
    def move(self, uid: int, src_mailbox: str, dst_mailbox: str) -> None:
        """Move a message from ``src_mailbox`` to ``dst_mailbox`` by
        UID. Uses the IMAP MOVE extension (RFC 6851) when the server
        announces it; falls back to COPY + STORE \\Deleted + EXPUNGE
        for pre-MOVE servers.

        F32: mailbox names with CR/LF are refused before any wire
        byte is sent."""
        for label, val in (("src_mailbox", src_mailbox), ("dst_mailbox", dst_mailbox)):
            if "\r" in val or "\n" in val:
                raise ValueError(f"IMAP move: {label} must not contain CR/LF. F32.")
        imap = self._ensure_connected()
        self._select_mailbox(src_mailbox, readonly=False)
        # capability() ASKs the server; cache locally to avoid spam.
        try:
            typ, caps = imap.capability()
            cap_str = (
                b" ".join(caps).decode("ascii", errors="replace")
                if isinstance(caps, list)
                else str(caps)
            )
        except Exception:  # noqa: BLE001
            cap_str = ""
        dst_enc = _imap_utf7_encode(dst_mailbox).decode("ascii")
        if "MOVE" in cap_str.upper():
            typ, data = imap.uid("MOVE", str(int(uid)), dst_enc)
            if typ != "OK":
                raise OSError(f"IMAP MOVE failed: {data}")
            return
        # Fallback: COPY then STORE \\Deleted + EXPUNGE.
        typ, data = imap.uid("COPY", str(int(uid)), dst_enc)
        if typ != "OK":
            raise OSError(f"IMAP COPY (move-fallback) failed: {data}")
        self.set_flags(uid, ["\\Deleted"], mailbox=src_mailbox, mode="add")
        _expunge_one(imap, str(int(uid)))

    @_imap_errors_as_oserror
    @serialized
    def disk_usage(self, path: str) -> tuple[int, int, int]:
        """Return quota usage if the server supports IMAP QUOTA.

        Returns (total_bytes, used_bytes, free_bytes).
        """
        imap = self._ensure_connected()
        try:
            typ, data = imap.getquotaroot("INBOX")
            if typ != "OK":
                raise OSError("QUOTA not supported by server")

            # data is a list; the quota response may span multiple entries
            for entry in data:
                if entry is None:
                    continue
                text = (
                    entry.decode("ascii", errors="replace")
                    if isinstance(entry, bytes)
                    else str(entry)
                )
                m = _QUOTA_RE.search(text)
                if m:
                    used_kb = int(m.group(1))
                    total_kb = int(m.group(2))
                    used = used_kb * 1024
                    total = total_kb * 1024
                    free = max(0, total - used)
                    return (total, used, free)

            raise OSError("No STORAGE quota found in server response")
        except (imaplib.IMAP4.error, AttributeError) as exc:
            raise OSError(f"IMAP QUOTA not supported: {exc}") from exc
