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


#: Bytes one read of a literal asks for at a time.
_LITERAL_CHUNK = 1024 * 1024

#: What one command's answer may total when it carries no message body:
#: the greeting, LOGIN, LIST, SELECT, SEARCH, STATUS, FETCH of ENVELOPE /
#: RFC822.SIZE / FLAGS. imaplib refuses a single line over 1,000,000 bytes
#: already, so a SEARCH of about 120,000 UIDs is the most any one line can
#: carry; 8 MiB leaves room for eight such lines, for a 100-message ENVELOPE
#: batch (_list_messages) at 80 KB per envelope - a long recipient list - or
#: a LIST of some 80,000 mailboxes, and is still nothing to hold in memory.
_ANSWER_CAP = 8 * 1024 * 1024

#: The one SEARCH line of a mailbox listing may be this long: imaplib's
#: 1,000,000-byte line limit refused the ``UID SEARCH ALL`` answer of a
#: mailbox of about 125,000 messages (an archive, Gmail's All Mail) and
#: the mailbox could not be opened at all. 24 MiB carries some three
#: million 7-digit UIDs; every other command keeps imaplib's limit.
_SEARCH_LINE_CAP = 24 * 1024 * 1024

#: What the answer to a message FETCH may carry besides the message itself
#: (the FETCH framing, untagged EXISTS / FLAGS updates in between).
_BODY_SLACK = 64 * 1024


class ImapAnswerTooLarge(OSError):
    """A server's answer to one command went over its byte budget.

    The connection is dropped when this is raised: the rest of the answer
    is still on the wire, and the stream is out of step with any command
    sent after it."""

    def __init__(self, command: str, budget: int, seen: int) -> None:
        self.command, self.budget, self.seen = command, budget, seen
        super().__init__(
            errno.EFBIG,
            f"the IMAP server's answer to {command} is larger than {_human(budget)} "
            f"({_human(seen)} announced or read); the connection was dropped",
        )


def _human(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.0f} MiB"
    return f"{n // 1024} KiB" if n >= 1024 else f"{n} bytes"


class _LiteralInSteps:
    """A byte budget per command, and literals read in steps.

    Nothing in imaplib caps an answer: a literal is read as long as the
    server says, and untagged lines are collected until the tagged one
    comes. A broken or hostile server that announces a huge literal and
    then sends gigabytes - or sends untagged lines for ever - filled the
    memory through list_dir / open_read / the attachment listing.

    Every command now gets a budget (:data:`_ANSWER_CAP`, or what
    :func:`_expect_large_answer` set for the next command); each byte that
    read() and readline() take from the server counts against it, and a
    literal announced larger than what is left is refused before anything
    of it is read. Over budget the connection is shut and
    :class:`ImapAnswerTooLarge` (an OSError naming the size) raised.

    The literal is read in :data:`_LITERAL_CHUNK` steps into one bytearray:
    imaplib's single ``file.read(n)`` makes Python 3.11.2 (Debian 12's)
    allocate the announced size at once. One whose size lies ends short at
    EOF or the socket timeout, as with a newer Python."""

    _axross_budget = _ANSWER_CAP
    _axross_used = 0
    _axross_command = "the greeting"
    _axross_next_budget: int | None = None
    _axross_maxline: int | None = None
    _axross_next_maxline: int | None = None

    def _command(self, name, *args):
        self._axross_budget = self._axross_next_budget or _ANSWER_CAP
        self._axross_next_budget = None
        self._axross_maxline = self._axross_next_maxline
        self._axross_next_maxline = None
        self._axross_used = 0
        # "UID FETCH", not "UID"; never an argument (LOGIN's is the user).
        self._axross_command = f"{name} {args[0]}" if name == "UID" and args else name
        return super()._command(name, *args)

    def _axross_over(self, seen: int):
        budget, command = self._axross_budget, self._axross_command
        log.warning("IMAP: answer to %s over its %d-byte budget (%d); dropping the connection",
                    command, budget, seen)
        try:
            self.shutdown()
        except Exception:  # noqa: BLE001 - the socket may be gone already
            pass
        # Any further command fails at once (imaplib's state check), so
        # ImapSession._ensure_connected reconnects instead of reading the
        # rest of this answer as the reply to the next one.
        self.state = "LOGOUT"
        raise ImapAnswerTooLarge(command, budget, seen)

    def read(self, size):
        if self._axross_used + size > self._axross_budget:
            self._axross_over(self._axross_used + size)
        buf = bytearray()
        while len(buf) < size:
            step = min(size - len(buf), _LITERAL_CHUNK)
            chunk = self.file.read(step)
            buf += chunk
            if len(chunk) < step:
                break
        self._axross_used += len(buf)
        return bytes(buf)

    def readline(self):
        left = self._axross_budget - self._axross_used
        maxline = self._axross_maxline or imaplib._MAXLINE
        line = self.file.readline(min(maxline, left) + 1)
        self._axross_used += len(line)
        if self._axross_used > self._axross_budget:
            self._axross_over(self._axross_used)
        if len(line) > maxline:
            raise self.error("got more than %d bytes" % maxline)
        return line


def _expect_large_answer(imap, budget: int) -> None:
    """Give the NEXT command sent on ``imap`` a budget of ``budget`` bytes
    (a message FETCH); every later one gets :data:`_ANSWER_CAP` again."""
    if isinstance(imap, _LiteralInSteps):
        imap._axross_next_budget = budget


def _expect_long_line(imap, maxline: int) -> None:
    """Let one line of the answer to the NEXT command sent on ``imap`` be
    up to ``maxline`` bytes (and the answer that much more), instead of
    imaplib's 1,000,000: the one-line answer to a ``UID SEARCH``. Every
    later command gets imaplib's limit again."""
    if isinstance(imap, _LiteralInSteps):
        imap._axross_next_maxline = maxline
        imap._axross_next_budget = _ANSWER_CAP + maxline


def _has_capability(imap, name: str) -> bool:
    """Whether the server announced capability *name* (e.g. ``UIDPLUS``).

    Matched as a whole word: ``"MOVE" in caps`` took ``XMOVE`` for MOVE."""
    name = name.upper()
    return any(str(c).upper() == name for c in getattr(imap, "capabilities", ()) or ())


class _IMAP4(_LiteralInSteps, imaplib.IMAP4):
    pass


class _IMAP4_SSL(_LiteralInSteps, imaplib.IMAP4_SSL):
    pass


class _ProxyIMAP4(_IMAP4):
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


class _ProxyIMAP4_SSL(_IMAP4_SSL):
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
    if _has_capability(imap, "UIDPLUS"):
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


def _mailbox_arg(name: str) -> str:
    """*name* as an IMAP mailbox argument: modified UTF-7 in a quoted
    string (RFC 3501 4.3). Python 3's imaplib quotes nothing, and a bare
    ``Sent Items`` or ``[Gmail]/Sent Mail`` is a syntax error to Dovecot,
    Exchange and Gmail."""
    encoded = _imap_utf7_encode(name).decode("ascii")
    return '"' + encoded.replace("\\", "\\\\").replace('"', '\\"') + '"'


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

        mailbox_encoded = _mailbox_arg(self._mailbox)
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


    def _login(self):
        """LOGIN - or, for a user name or password beyond ASCII, SASL PLAIN:
        imaplib's LOGIN encodes as ASCII, and a password with "ä" or "€"
        raised UnicodeEncodeError at every connect. PLAIN carries UTF-8
        (RFC 4616). ``(typ, data)`` as imaplib answers."""
        if (self._username + self._password).isascii():
            return self._imap.login(self._username, self._password)
        caps = {str(c).upper() for c in getattr(self._imap, "capabilities", ())}
        if "AUTH=PLAIN" not in caps:
            raise ConnectionError("IMAP: the user name or password has characters beyond "
                                  "ASCII, and the server offers no AUTH=PLAIN to send them")
        credentials = f"\0{self._username}\0{self._password}".encode("utf-8")
        return self._imap.authenticate("PLAIN", lambda _challenge: credentials)

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
                    self._imap = _IMAP4_SSL(
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
                    self._imap = _IMAP4(self._host, self._port, timeout=IMAP_TIMEOUT)

            typ, data = self._login()
            if typ != "OK":
                raise ConnectionError(f"IMAP LOGIN failed: {data}")
            self._refresh_capabilities()

            # Detect hierarchy separator from LIST
            try:
                typ, data = self._imap.list('""', '""')
                responses = _imap_responses(data) if typ == "OK" else []
                entry = _parse_list_entry(responses[0]) if responses else None
                if entry is not None:
                    sep = entry[1].strip()
                    if sep:
                        self._hierarchy_sep = sep
            except ImapAnswerTooLarge:
                raise  # the connection is dropped; nothing to go on with
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

    def _refresh_capabilities(self) -> None:
        """Ask for the capabilities again after login.

        imaplib keeps the list the server gave before login, and many
        servers (Dovecot among them) announce UIDPLUS, MOVE and UNSELECT
        only to an authenticated client - every check for them answered
        "not offered". A failed or empty answer keeps the old list."""
        try:
            typ, data = self._imap.capability()
        except ImapAnswerTooLarge:
            raise
        except Exception as exc:  # noqa: BLE001 - the old list still serves
            log.debug("IMAP CAPABILITY after login failed: %s", exc)
            return
        if typ != "OK" or not isinstance(data, list):
            return
        words = b" ".join(_as_bytes(d) for d in data if d).decode("ascii", "replace").upper().split()
        if words:
            self._imap.capabilities = tuple(dict.fromkeys(words))

    def _leave_selected(self, imap) -> None:
        """Leave the selected mailbox without expunging anything.

        CLOSE on a mailbox selected read-write expunges every message
        flagged \\Deleted (RFC 3501 6.4.2): ones another client only
        flagged (Outlook's "mark as deleted"), and the very messages
        :func:`_expunge_one` refused to expunge on purpose. UNSELECT
        (RFC 3691) leaves without an expunge; without it the mailbox is
        EXAMINEd first - a CLOSE of a read-only mailbox removes nothing.
        Best effort: a failure leaves the session to select again."""
        mailbox = self._selected_mailbox
        readonly = getattr(self, "_selected_readonly", True)
        self._selected_mailbox = None
        self._selected_readonly = True
        if mailbox is None:
            return
        try:
            if _has_capability(imap, "UNSELECT"):
                imap.unselect()
                return
            if not readonly:
                typ, _data = imap.select(_mailbox_arg(mailbox), readonly=True)
                if typ != "OK":
                    return  # a failed EXAMINE deselects (RFC 3501 6.3.1)
            imap.close()
        except ImapAnswerTooLarge:
            raise
        except Exception as exc:  # noqa: BLE001 - the next SELECT replaces it
            log.debug("IMAP: leaving mailbox %r failed: %s", mailbox, exc)

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
        encoded = _mailbox_arg(mailbox)
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

        # Second part is either "uid.eml" / "uid_subject.eml" (the message)
        # or "uid" (the folder of its attachments)
        name_part = remainder[0]
        if name_part.lower().endswith(".eml"):
            # The UID is the part before the first underscore
            uid_match = re.match(r"^(\d+)", name_part[:-4])
        else:
            # Only the bare UID names the attachments' folder: a file such
            # as "2024_report.pdf" was taken for message 2024's folder and
            # "existed" without a question to the server.
            uid_match = re.fullmatch(r"(\d+)", name_part)
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

    def security_info(self):
        """The negotiated TLS of the IMAP connection for the security badge
        (None when not connected - the profile tells then)."""
        from core import conn_security as CS

        sock = getattr(self._imap, "sock", None) if self._imap is not None else None
        if sock is None:
            return None
        if not self._use_ssl:
            return CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "IMAP without TLS - cleartext - anyone on the "
                                   "network can read it, the password too", True)
        return CS.tls_socket(sock, verified=self._verify_tls, what="IMAP")

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
        """Close the IMAP connection.

        LOGOUT alone: it leaves the selected mailbox without an expunge
        (RFC 3501 6.4.2). The CLOSE sent before it expunged every message
        flagged \\Deleted in a mailbox left selected read-write - by a
        refused remove, a set_flags or a move - including ones another
        client had only flagged."""
        if self._imap is not None:
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

        # The answer is one line of all UIDs: over imaplib's line limit
        # from about 125,000 messages on.
        _expect_long_line(imap, _SEARCH_LINE_CAP)
        typ, data = imap.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise OSError(f"IMAP UID SEARCH failed in {mailbox!r}: {data}")

        uid_list = [uid for part in data or () if part for uid in _search_uids(part)]
        if not uid_list:
            return []
        items: list[FileItem] = []

        # Fetch envelopes in batches to avoid overly long commands
        batch_size = 100
        for i in range(0, len(uid_list), batch_size):
            batch = b",".join(uid_list[i : i + batch_size])
            typ, fetch_data = imap.uid(
                "FETCH", batch.decode("ascii"), "(ENVELOPE RFC822.SIZE INTERNALDATE)"
            )
            if typ != "OK":
                # Skipped, the listing looked complete without these
                # messages - and a sync or a compare took them for gone.
                raise OSError(
                    f"IMAP FETCH of {mailbox!r} failed for messages "
                    f"{i + 1}-{min(i + batch_size, len(uid_list))}: {fetch_data}"
                )

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
        # The whole message is held in memory (and handed on as BytesIO):
        # the open size limit of the viewers caps it, as it caps a file
        # opened from any other pane.
        from core import open_limits

        limit = open_limits.max_open_bytes()
        too_large = OSError(
            errno.EFBIG,
            f"Message UID {uid} in {mailbox!r} is larger than {open_limits.describe_limit()}, "
            "the open size limit (Edit → Settings… → Files & Panes → Open Size Limit)",
        )
        _expect_large_answer(imap, limit + _BODY_SLACK)
        try:
            typ, data = imap.uid("FETCH", uid, "(RFC822)")
        except ImapAnswerTooLarge as exc:
            self._imap = None
            self._selected_mailbox = None
            raise too_large from exc
        if typ != "OK":
            raise OSError(f"Cannot fetch message UID {uid} from {mailbox!r}: {data}")
        for response_part in data:
            if isinstance(response_part, tuple):
                if len(response_part[1]) > limit:
                    raise too_large
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
            self._select_existing(mailbox, path)
            return self._selected_message_item(uid, leaf_name, path)

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

    def _selected_message_item(self, uid: str, leaf_name: str, path: str) -> FileItem:
        """The item *leaf_name* names in the SELECTED mailbox: the message
        file ``<uid>[_<subject>].eml`` (checked against the message's
        subject) or the attachment folder ``<uid>``. FileNotFoundError when
        the UID is not there or is another message."""
        imap = self._ensure_connected()
        if not leaf_name.lower().endswith(".eml"):
            # The attachment directory for this UID - when the message is there.
            typ, data = imap.uid("FETCH", uid, "(UID)")
            if typ != "OK":
                raise OSError(f"Cannot stat message UID {uid}: {data}")
            if not any(part for part in data or ()):
                raise FileNotFoundError(errno.ENOENT, "No such message", path)
            return FileItem(name=uid, is_dir=True)
        typ, data = imap.uid("FETCH", uid, "(RFC822.SIZE INTERNALDATE ENVELOPE)")
        if typ != "OK":
            raise OSError(f"Cannot stat message UID {uid}: {data}")
        size = 0
        modified = datetime.fromtimestamp(0)
        if not any(part for part in data or ()):
            # UID FETCH of a UID that is not there answers OK, no data.
            raise FileNotFoundError(errno.ENOENT, "No such message", path)
        envelope = None
        for response in _imap_responses(data):
            # A reply with a literal arrives split into a (line,
            # literal) tuple and the rest of the line; joined here.
            attrs = _fetch_attributes(response)
            found = _fetch_number(attrs, b"RFC822.SIZE")
            if found is not None:
                size = found
            if b"INTERNALDATE" in attrs:
                modified = _fetch_date(attrs)
            if b"ENVELOPE" in attrs:
                envelope = attrs[b"ENVELOPE"]
        if not self._names_message(leaf_name, uid, envelope):
            # "5_invoice.eml" copied in from another mailbox is not
            # this mailbox's message 5: it "existed", and a copy
            # there was refused or prompted for nothing.
            raise FileNotFoundError(
                errno.ENOENT, f"No message {leaf_name!r} (UID {uid} is another one)", path
            )
        return FileItem(name=leaf_name, size=size, modified=modified)

    @staticmethod
    def _names_message(leaf: str, uid: str, envelope) -> bool:
        """Whether the file name *leaf* is message *uid*'s: ``<uid>.eml``,
        or the name the listing gives it (``<uid>_<subject>.eml``). A reply
        without the envelope cannot tell another message apart: it passes."""
        if leaf.lower() == f"{uid}.eml" or envelope is None:
            return True
        listed = f"{uid}_{_sanitize_filename(_envelope_subject(envelope), max_len=80)}.eml"
        return leaf.casefold() == listed.casefold()

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
        encoded = _mailbox_arg(mailbox)
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
                # Only "<uid>[_subject].eml" names a message: no other name
                # is there, and "removed" it was not. (A failed APPEND is
                # never rolled back by name: the store only adds.)
                raise FileNotFoundError(errno.ENOENT, "No such message", path)
            self._select_mailbox(mailbox, readonly=False)
            # stat()'s identity check, in this selection: "5_invoice.eml"
            # from a stale listing (or another mailbox) is not this
            # mailbox's UID 5 when its subject differs - deleting by the
            # number alone removed another message. FileNotFoundError then,
            # nothing deleted.
            leaf_name = [p for p in self.normalize(path).split("/") if p][-1]
            self._selected_message_item(uid, leaf_name, path)
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
        encoded = _mailbox_arg(mailbox)
        typ, _ = self._ensure_connected().status(encoded, "(MESSAGES)")
        return typ != "OK"

    def _message_count(self, mailbox: str) -> int | None:
        """Messages in *mailbox* by STATUS; 0 for a name that cannot hold any
        (listed \\Noselect); None when STATUS fails otherwise - unknown,
        which a non-recursive delete took for empty."""
        imap = self._ensure_connected()
        encoded = _mailbox_arg(mailbox)
        typ, data = imap.status(encoded, "(MESSAGES)")
        if typ != "OK":
            if (mailbox, False) in self._list_entries():
                return 0
            return None
        raw = b" ".join(d if isinstance(d, bytes) else str(d).encode() for d in data if d)
        match = re.search(rb"MESSAGES\s+(\d+)", raw, re.IGNORECASE)
        return int(match.group(1)) if match else 0

    def _delete_mailbox(self, mailbox: str) -> tuple[str, list]:
        imap = self._ensure_connected()
        # Leave the mailbox if it is the one being deleted - without the
        # expunge of a CLOSE: a DELETE the server refuses keeps it whole.
        if self._selected_mailbox == mailbox:
            self._leave_selected(imap)
        encoded = _mailbox_arg(mailbox)
        return imap.delete(encoded)

    def _remove_mailbox_tree(self, mailbox: str, path: str, recursive: bool) -> None:
        """Delete *mailbox*; with *recursive* its sub-mailboxes first.

        A single DELETE leaves the sub-mailboxes behind (RFC 3501 6.3.4),
        and Dovecot then lists the deleted parent as \\NonExistent.
        """
        if mailbox not in self._mailbox_nodes():
            self._mailbox_cache = None  # a mailbox made since the last LIST
            if mailbox not in self._mailbox_nodes():
                raise FileNotFoundError(errno.ENOENT, f"No such mailbox: {mailbox}", path)
        prefix = mailbox + self._hierarchy_sep
        children = sorted(
            (name for name in self._mailbox_names() if name.startswith(prefix)),
            key=lambda name: name.count(self._hierarchy_sep),
            reverse=True,
        )
        if not recursive:
            count = None if children else self._message_count(mailbox)
            if count is None and not children:
                raise OSError(
                    f"Cannot tell whether mailbox {mailbox!r} is empty (STATUS failed); "
                    "nothing was deleted",
                )
            if children or count:
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
                self._leave_selected(imap)
            old_enc = _mailbox_arg(old_name)
            new_enc = _mailbox_arg(new_name)
            typ, data = imap.rename(old_enc, new_enc)
            if typ != "OK":
                raise OSError(f"Cannot rename mailbox {old_name!r} to {new_name!r}: {data}")
            self._mailbox_cache = None
            log.info("Renamed mailbox %s -> %s", old_name, new_name)
            return

        if len(src_parsed) >= 3:
            raise OSError(f"Cannot rename or move a single attachment: {src!r}")

        # Move a message to another mailbox
        if len(src_parsed) == 2 and len(dst_parsed) >= 1:
            src_mailbox, src_uid = src_parsed[0], src_parsed[1]
            if src_uid is None:
                raise OSError(f"Cannot rename non-message path: {src!r}")
            dst_mailbox = dst_parsed[0]
            if dst_mailbox is None:
                raise OSError("Cannot move message to root")
            if dst_mailbox == src_mailbox:
                # The name is the UID and the subject: neither changes,
                # and a copy within the mailbox only made a new UID.
                raise OSError(
                    errno.ENOTSUP,
                    f"A message cannot be renamed within its mailbox {src_mailbox!r}: "
                    "its name is its UID and subject",
                    src,
                )
            self._select_mailbox(src_mailbox, readonly=False)
            # remove()'s identity check: "2_invoice.eml" from a stale
            # listing is not this mailbox's UID 2 when the subject differs,
            # and a UID that is gone is FileNotFoundError - UID COPY of it
            # answers OK with nothing copied.
            leaf_name = [p for p in self.normalize(src).split("/") if p][-1]
            self._selected_message_item(src_uid, leaf_name, src)
            self._move_selected_message(src_uid, src_mailbox, dst_mailbox)
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
    def append_message(self, mailbox: str, message: bytes, flags: tuple[str, ...] = ()) -> None:
        """IMAP APPEND a complete RFC 5322 message with *flags* (e.g.
        ``("\\Draft",)`` for a draft, ``("\\Seen",)`` for a sent copy)."""
        if "\r" in mailbox or "\n" in mailbox:
            raise ValueError("IMAP append: the mailbox must not contain CR/LF")
        for f in flags:
            if not f or any(c in f for c in "\r\n ()"):
                raise ValueError(f"IMAP append: flag {f!r} must be one word")
        imap = self._ensure_connected()
        encoded = _mailbox_arg(mailbox)
        typ, data = imap.append(encoded, "(" + " ".join(flags) + ")" if flags else None, None, message)
        if typ != "OK":
            raise OSError(f"IMAP APPEND to {mailbox} failed: {data}")

    @_imap_errors_as_oserror
    @serialized
    def special_mailbox(self, use: str) -> str:
        """The mailbox the server marks with the special-use flag *use*
        (RFC 6154: ``drafts``, ``sent``, ``junk``, ``trash``, ``archive``),
        else one with the usual name; '' when there is none."""
        imap = self._ensure_connected()
        typ, data = imap.list()
        if typ != "OK":
            raise OSError(f"IMAP LIST failed: {data}")
        names = []
        for raw in _imap_responses(data):
            entry = _parse_list_entry(raw)
            if entry is None:
                continue
            name = _imap_utf7_decode(entry[2])
            if f"\\{use}".lower() in entry[0].lower():
                return name
            names.append(name)
        usual = {"drafts": ("Drafts", "Draft", "Entw\u00fcrfe", "INBOX.Drafts"),
                 "sent": ("Sent", "Sent Items", "Sent Messages", "Gesendet", "INBOX.Sent"),
                 "junk": ("Junk", "Spam"), "trash": ("Trash", "Deleted Items", "Papierkorb"),
                 "archive": ("Archive", "Archiv")}.get(use.lower(), ())
        for candidate in usual:
            for name in names:
                if name.lower() == candidate.lower():
                    return name
        return ""

    @_imap_errors_as_oserror
    @serialized
    def move(self, uid: int, src_mailbox: str, dst_mailbox: str) -> None:
        """Move a message from ``src_mailbox`` to ``dst_mailbox`` by
        UID - see :meth:`_move_selected_message` for how. A UID that is
        not there is FileNotFoundError, not a move of nothing.

        F32: mailbox names with CR/LF are refused before any wire
        byte is sent."""
        for label, val in (("src_mailbox", src_mailbox), ("dst_mailbox", dst_mailbox)):
            if "\r" in val or "\n" in val:
                raise ValueError(f"IMAP move: {label} must not contain CR/LF. F32.")
        uid = str(int(uid))
        self._select_mailbox(src_mailbox, readonly=False)
        typ, data = self._ensure_connected().uid("FETCH", uid, "(UID)")
        if typ != "OK":
            raise OSError(f"Cannot look up message UID {uid} in {src_mailbox!r}: {data}")
        if not any(part for part in data or ()):
            # UID MOVE / COPY of a UID that is not there answers OK.
            raise FileNotFoundError(errno.ENOENT, f"No message UID {uid} in {src_mailbox!r}")
        self._move_selected_message(uid, src_mailbox, dst_mailbox)

    def _move_selected_message(self, uid: str, src_mailbox: str, dst_mailbox: str) -> None:
        """Move message *uid* of the mailbox selected read-write,
        *src_mailbox*, to *dst_mailbox*; the caller checked that it is
        there.

        MOVE (RFC 6851) when offered. Otherwise COPY, flag the original
        \\Deleted and expunge only it (:func:`_expunge_one`): UID EXPUNGE
        with UIDPLUS. A server with neither expunges by mailbox only, which
        removes every message flagged \\Deleted - also ones another
        client only flagged: the move is refused before anything is copied
        when another message is flagged, and when one gets flagged in
        between, the original is unflagged again and the OSError says the
        copy is made but the original kept. It never reports a move that
        left the message in both mailboxes."""
        imap = self._ensure_connected()
        dst_enc = _mailbox_arg(dst_mailbox)
        if _has_capability(imap, "MOVE"):
            typ, data = imap.uid("MOVE", uid, dst_enc)
            if typ != "OK":
                raise OSError(f"Cannot move message UID {uid} to {dst_mailbox!r}: {data}")
            log.info("Moved message UID %s from %s to %s", uid, src_mailbox, dst_mailbox)
            return
        if not _has_capability(imap, "UIDPLUS"):
            typ, data = imap.uid("SEARCH", None, "DELETED")
            flagged = b" ".join(_as_bytes(d) for d in data or () if d).split() if typ == "OK" else None
            if flagged is None or any(f.decode("ascii", "ignore") != uid for f in flagged):
                raise OSError(
                    errno.ENOTSUP,
                    f"Cannot move message UID {uid} from {src_mailbox!r}: the server offers "
                    "neither MOVE nor UIDPLUS, and other messages there are flagged deleted - "
                    "removing the original would expunge them too. Nothing was moved.",
                )
        typ, data = imap.uid("COPY", uid, dst_enc)
        if typ != "OK":
            raise OSError(f"Cannot copy message UID {uid} to {dst_mailbox!r}: {data}")
        kept = f"message UID {uid} was copied to {dst_mailbox!r} but stays in {src_mailbox!r}"
        typ, data = imap.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        if typ != "OK":
            raise OSError(f"Move incomplete: {kept} (flagging it deleted failed: {data})")
        typ, data = _expunge_one(imap, uid)
        if typ != "OK":
            try:
                imap.uid("STORE", uid, "-FLAGS", "(\\Deleted)")
            except ImapAnswerTooLarge:
                raise
            except Exception as exc:  # noqa: BLE001 - the error below says what is left
                log.warning("IMAP: could not unflag UID %s again: %s", uid, exc)
            raise OSError(
                f"Move incomplete: {kept}: "
                + b" ".join(_as_bytes(d) for d in data or ()).decode("utf-8", "replace")
            )
        log.info("Moved message UID %s from %s to %s", uid, src_mailbox, dst_mailbox)

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
