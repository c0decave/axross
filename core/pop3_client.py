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

Uses only Python stdlib (``poplib``, ``email``).
"""
from __future__ import annotations

import email
import email.header
import email.policy
import io
import logging
import poplib
import re
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


# Cap on a single read_file call. Mailboxes occasionally hold absurd
# attachments (gigabyte logs); refusing >32 MiB keeps the UI snappy
# without rejecting any reasonable mail.
MAX_MESSAGE_BYTES = 32 * 1024 * 1024

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


def _decode_header(raw: str | bytes | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    parts: list[str] = []
    for piece, charset in email.header.decode_header(raw):
        if isinstance(piece, bytes):
            try:
                parts.append(piece.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
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
            self._axross_proxy, self.host, int(self.port), timeout=t,
        )


class _ProxyPOP3_SSL(poplib.POP3_SSL):
    """POP3_SSL counterpart. Same hook plus a TLS wrap on the
    proxied socket using poplib's built-in SSL context."""

    def __init__(self, host: str, port: int, proxy_config, timeout: float = 30.0,
                 context=None):
        self._axross_proxy = proxy_config
        self._axross_timeout = float(timeout)
        super().__init__(host, port, timeout=timeout, context=context)

    def _create_socket(self, timeout=None):
        from core.proxy import create_proxy_socket
        t = float(timeout) if timeout is not None else self._axross_timeout
        raw = create_proxy_socket(
            self._axross_proxy, self.host, int(self.port), timeout=t,
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


def _msgno_from_path(path: str) -> int:
    m = _MSG_PATH_RE.match(path)
    if not m:
        raise OSError(f"POP3 path does not look like a message: {path!r}")
    return int(m.group("msgno"))


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Pop3Session:
    """POP3 read-only backend implementing the FileBackend protocol."""

    # POP3 has no folder hierarchy and no mutable surface — these flags
    # let the UI hide context-menu entries that would otherwise raise.
    supports_symlinks = False
    supports_hardlinks = False

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
    ):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_ssl = use_ssl
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
                if self._proxy.enabled:
                    self._pop = _ProxyPOP3_SSL(
                        self._host, self._port, self._proxy, timeout=30.0,
                    )
                else:
                    self._pop = poplib.POP3_SSL(self._host, self._port, timeout=30.0)
            else:
                # Plaintext POP3 — credentials traverse the wire in
                # the clear via USER/PASS. Loud warning so a misconfig
                # doesn't slip past silently.
                log.warning(
                    "POP3 connecting to %s:%d WITHOUT TLS — credentials "
                    "will be sent in plaintext",
                    self._host, self._port,
                )
                if self._proxy.enabled:
                    self._pop = _ProxyPOP3(
                        self._host, self._port, self._proxy, timeout=30.0,
                    )
                else:
                    self._pop = poplib.POP3(self._host, self._port, timeout=30.0)

            self._pop.user(self._username)
            self._pop.pass_(self._password)
            log.info(
                "POP3%s connected: %s@%s:%d",
                "S" if self._use_ssl else "",
                self._username, self._host, self._port,
            )
        except poplib.error_proto as exc:
            self._pop = None
            raise OSError(f"POP3 LOGIN failed: {exc}") from exc
        except Exception:
            self._pop = None
            raise

    def _ensure_connected(self) -> "poplib.POP3 | poplib.POP3_SSL":
        if self._pop is None:
            self._connect()
        # poplib has no NOOP probe — we trust the most-recent stat call
        # was authoritative; reconnect happens on the next exception.
        assert self._pop is not None
        return self._pop

    @property
    def name(self) -> str:
        return f"POP3{'S' if self._use_ssl else ''}: {self._username}@{self._host}:{self._port}"

    @property
    def connected(self) -> bool:
        if self._pop is None:
            return False
        try:
            # NOOP exists in POP3 — sends "NOOP\r\n", expects "+OK".
            self._pop.noop()
            return True
        except Exception:
            return False

    def disconnect(self) -> None:
        """Issue QUIT to commit any DELE flags and close the socket.
        Idempotent; safe to call when not connected."""
        if self._pop is None:
            return
        try:
            self._pop.quit()
        except Exception as exc:  # noqa: BLE001
            log.debug("POP3 quit raised: %s", exc)
        finally:
            self._pop = None

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
        cleaned = [p.strip("/") for p in parts if p]
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

    def list_dir(self, path: str) -> list[FileItem]:
        """List all messages in the mailbox.

        POP3 has no folder hierarchy: any non-root path is empty.
        Items have name ``<msgno>_<subject>.eml`` and the size from
        the server's LIST response. Subjects are best-effort: TOP
        (read first 0 lines, headers only) is queried per message;
        on TOP failure the item still appears with subject "(no
        subject)" so the user can still browse the mailbox.
        """
        path = self.normalize(path)
        if path != "/":
            return []

        pop = self._ensure_connected()
        # LIST returns lines like ``b"1 1234"`` — message-number + octets.
        try:
            _resp, lines, _octets = pop.list()
        except poplib.error_proto as exc:
            raise OSError(f"POP3 LIST failed: {exc}") from exc

        items: list[FileItem] = []
        for raw in lines:
            text = raw.decode("ascii", errors="replace") if isinstance(raw, bytes) else raw
            parts = text.strip().split()
            if len(parts) < 2:
                continue
            try:
                msgno = int(parts[0])
                size = int(parts[1])
            except ValueError:
                continue
            subject = self._fetch_subject(msgno)
            safe_subj = _sanitize_filename(subject) if subject else "untitled"
            name = f"{msgno}_{safe_subj}.eml"
            items.append(FileItem(
                name=name,
                is_dir=False,
                is_link=False,
                size=size,
                modified=datetime.now(),  # POP3 has no per-message mtime
                permissions=0o400,
            ))
        return items

    def _fetch_subject(self, msgno: int) -> str:
        """Best-effort: TOP <msgno> 0 returns headers only; parse
        Subject. Failure → empty string (never raises)."""
        try:
            pop = self._ensure_connected()
            _resp, lines, _octets = pop.top(msgno, 0)
            blob = b"\r\n".join(
                line if isinstance(line, bytes) else line.encode("utf-8", "replace")
                for line in lines
            )
            msg = email.message_from_bytes(blob, policy=email.policy.compat32)
            return _decode_header(msg.get("Subject", ""))
        except Exception as exc:  # noqa: BLE001
            log.debug("POP3 TOP %d failed: %s", msgno, exc)
            return ""

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False,
                size=0, modified=datetime.now(), permissions=0o500,
            )
        msgno = _msgno_from_path(path)
        pop = self._ensure_connected()
        try:
            _resp, lines, _octets = pop.list(msgno)
            text = lines.decode("ascii", errors="replace") if isinstance(lines, bytes) else lines
            parts = text.strip().split()
            size = int(parts[1]) if len(parts) >= 2 else 0
        except poplib.error_proto as exc:
            raise OSError(f"POP3 stat({path}): {exc}") from exc
        return FileItem(
            name=path.lstrip("/"), is_dir=False, is_link=False,
            size=size, modified=datetime.now(), permissions=0o400,
        )

    def is_dir(self, path: str) -> bool:
        return self.normalize(path) == "/"

    def open_read(self, path: str, mode: str = "rb") -> IO:
        path = self.normalize(path)
        msgno = _msgno_from_path(path)
        pop = self._ensure_connected()
        try:
            _resp, lines, octets = pop.retr(msgno)
        except poplib.error_proto as exc:
            raise OSError(f"POP3 RETR({path}): {exc}") from exc
        if octets and octets > MAX_MESSAGE_BYTES:
            raise OSError(
                f"POP3 message {msgno} is {octets} bytes — exceeds the "
                f"{MAX_MESSAGE_BYTES} byte cap. Use a mail client to fetch.",
            )
        blob = b"\r\n".join(
            line if isinstance(line, bytes) else line.encode("utf-8", "replace")
            for line in lines
        )
        return io.BytesIO(blob)

    # ------------------------------------------------------------------
    # FileBackend — write surface (refused; POP3 is read-only)
    # ------------------------------------------------------------------

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
        msgno = _msgno_from_path(path)
        pop = self._ensure_connected()
        try:
            pop.dele(msgno)
        except poplib.error_proto as exc:
            raise OSError(f"POP3 DELE({path}): {exc}") from exc

    def open_write(self, path: str, mode: str = "wb") -> IO:
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

    def stat_mailbox(self) -> tuple[int, int]:
        """``STAT`` — returns ``(message_count, total_octets)``. Cheap;
        every POP3 server supports it."""
        pop = self._ensure_connected()
        count, octets = pop.stat()
        return (int(count), int(octets))

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
            text = resp.decode("ascii", errors="replace") \
                if isinstance(resp, bytes) else str(resp)
            parts = text.split()
            return parts[-1]
        resp, lines, _ = pop.uidl()
        out: dict[int, str] = {}
        for line in lines:
            text = line.decode("ascii", errors="replace") \
                if isinstance(line, bytes) else str(line)
            tok = text.split()
            if len(tok) >= 2 and tok[0].isdigit():
                out[int(tok[0])] = tok[1]
        return out

    def top(self, msgno: int, n_lines: int = 10) -> bytes:
        """``TOP`` — returns headers + first ``n_lines`` of body.
        Useful for triage without pulling whole messages."""
        pop = self._ensure_connected()
        resp, lines, octets = pop.top(int(msgno), int(n_lines))
        # poplib returns lines as bytes; reassemble with CRLF.
        return b"\r\n".join(
            line if isinstance(line, bytes) else line.encode()
            for line in lines
        )

    def dele(self, msgno: int) -> None:
        """Mark a message for deletion. Actual delete happens on
        clean QUIT (``self.disconnect()``)."""
        pop = self._ensure_connected()
        pop.dele(int(msgno))

    def rset(self) -> None:
        """``RSET`` — undo all DELE marks issued in this session."""
        pop = self._ensure_connected()
        pop.rset()

    def noop(self) -> None:
        """``NOOP`` keep-alive."""
        pop = self._ensure_connected()
        pop.noop()
