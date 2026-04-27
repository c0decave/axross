"""Self-contained NNTP client.

Replacement for stdlib :mod:`nntplib` (removed in Python 3.13). Covers
the modern NNTP feature surface so axross can talk to real Usenet
servers and private NNTP (Eternal-September, news.aioe.org, news
peers, internal corp news mirrors, …):

* RFC 3977 — Network News Transfer Protocol (modern)
* RFC 4642 — TLS upgrade (``STARTTLS``) + implicit-TLS port 563
* RFC 4643 — AUTHINFO USER / PASS (and AUTHINFO SASL via PLAIN / EXTERNAL — fall through)
* RFC 4644 — Streaming (CHECK / TAKETHIS) — out of scope for v1
* RFC 6048 — additional commands (LIST COUNTS, LIST DISTRIB-PATS) —
  transparent passthrough via :meth:`raw_command`

Every method returns parsed values rather than the raw protocol so
callers don't need to grok NNTP's response codes. Unknown commands
go through :meth:`raw_command` for forward-compat.

Why our own: stdlib ``nntplib`` is gone in 3.13, vendor wrappers are
underspecified, and Usenet is small enough to implement cleanly.
About 350 LOC including TLS, auth, parsing, and dot-unstuffing.
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
from datetime import datetime
from typing import Iterator

log = logging.getLogger(__name__)


DEFAULT_PORT = 119
DEFAULT_TLS_PORT = 563

# Per-response cap. A hostile / runaway server could otherwise fill
# memory by streaming an unbounded multi-line block.
MAX_MULTILINE_BYTES = 64 * 1024 * 1024

DEFAULT_TIMEOUT = 30.0


class NntpError(OSError):
    """Generic NNTP protocol failure."""


class NntpResponseError(NntpError):
    """Server returned an error response (4xx / 5xx).

    Carries the response ``code`` (3-digit int) and ``message``."""

    def __init__(self, code: int, message: str):
        super().__init__(f"NNTP {code} {message}")
        self.code = code
        self.message = message


class NntpAuthRequired(NntpResponseError):
    """480 Authentication required — caller should call ``authinfo()``."""


# ---------------------------------------------------------------------------
# Wire-level helpers
# ---------------------------------------------------------------------------

_RESPONSE_RE = re.compile(rb"^(\d{3})(?:[ \-](.*))?\r?\n?$")


class _LineReader:
    """Buffered line reader on top of a socket — yields one CRLF-terminated
    line at a time. Mirrors the small interface stdlib ``nntplib`` had."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = b""

    def readline(self) -> bytes:
        while b"\n" not in self._buf:
            chunk = self._sock.recv(64 * 1024)
            if not chunk:
                if not self._buf:
                    raise NntpError("connection closed by server")
                line = self._buf
                self._buf = b""
                return line
            self._buf += chunk
        line, _, rest = self._buf.partition(b"\n")
        self._buf = rest
        return line + b"\n"

    def write(self, data: bytes) -> None:
        self._sock.sendall(data)

    def replace_socket(self, sock: socket.socket) -> None:
        # Used after STARTTLS handshake — discard the buffer (the
        # next bytes will be encrypted) and swap in the wrapped sock.
        self._sock = sock
        self._buf = b""


def _parse_status_line(line: bytes) -> tuple[int, str]:
    m = _RESPONSE_RE.match(line)
    if not m:
        raise NntpError(f"malformed NNTP status line: {line!r}")
    code = int(m.group(1))
    rest = (m.group(2) or b"").decode("utf-8", "replace").rstrip("\r\n")
    return code, rest


# ---------------------------------------------------------------------------
# NNTP client
# ---------------------------------------------------------------------------

class NntpClient:
    """Stateful NNTP client. One instance per server connection."""

    def __init__(
        self,
        host: str,
        port: int | None = None,
        use_tls: bool = False,
        starttls: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        proxy_config=None,
    ):
        if port is None:
            port = DEFAULT_TLS_PORT if use_tls and not starttls else DEFAULT_PORT
        self._host = host
        self._port = int(port)
        self._use_tls = bool(use_tls)
        self._timeout = float(timeout)
        self._proxy = proxy_config
        self._sock = self._open_socket()
        if self._use_tls and not starttls:
            self._sock = self._tls_wrap(self._sock)
        self._reader = _LineReader(self._sock)
        self._greeting_code, self._greeting = self._read_status()
        if self._greeting_code not in (200, 201):
            raise NntpError(f"bad NNTP greeting: {self._greeting_code} {self._greeting}")
        self._posting_allowed = (self._greeting_code == 200)
        if starttls:
            # Server must advertise STARTTLS before we send it. Skip
            # capability check for compatibility with servers that
            # don't honour CAPABILITIES — STARTTLS itself either
            # succeeds (382) or fails (580 / 502).
            self._do_starttls()
        log.info(
            "NNTP%s connected to %s:%d (posting=%s)",
            "S" if self._use_tls else "",
            host, port, self._posting_allowed,
        )

    # ------------------------------------------------------------------
    # Socket / TLS
    # ------------------------------------------------------------------

    def _open_socket(self) -> socket.socket:
        if self._proxy is not None and getattr(self._proxy, "enabled", False):
            from core.proxy import create_proxy_socket
            sock = create_proxy_socket(
                self._proxy, self._host, self._port, timeout=self._timeout,
            )
        else:
            sock = socket.create_connection(
                (self._host, self._port), timeout=self._timeout,
            )
        sock.settimeout(self._timeout)
        return sock

    def _tls_wrap(self, sock: socket.socket) -> socket.socket:
        ctx = ssl.create_default_context()
        return ctx.wrap_socket(sock, server_hostname=self._host)

    def _do_starttls(self) -> None:
        code, msg = self._command("STARTTLS")
        if code != 382:
            raise NntpError(f"STARTTLS refused: {code} {msg}")
        self._sock = self._tls_wrap(self._sock)
        self._reader.replace_socket(self._sock)
        self._use_tls = True
        log.info("NNTP STARTTLS upgrade complete with %s", self._host)

    # ------------------------------------------------------------------
    # I/O primitives
    # ------------------------------------------------------------------

    def _send_line(self, line: str) -> None:
        if "\r" in line or "\n" in line:
            raise NntpError("command must not contain CR/LF")
        log.debug("NNTP > %s", line)
        self._reader.write(line.encode("utf-8") + b"\r\n")

    def _read_status(self) -> tuple[int, str]:
        line = self._reader.readline()
        if not line:
            raise NntpError("connection closed unexpectedly")
        code, msg = _parse_status_line(line)
        log.debug("NNTP < %d %s", code, msg)
        return code, msg

    def _command(self, line: str) -> tuple[int, str]:
        self._send_line(line)
        return self._read_status()

    def _read_multiline(self) -> Iterator[str]:
        """Yield each line of a multi-line response. Strips the
        trailing ``.`` terminator and dot-unstuffs lines that begin
        with two dots. Caps total bytes at MAX_MULTILINE_BYTES."""
        received = 0
        while True:
            raw = self._reader.readline()
            received += len(raw)
            if received > MAX_MULTILINE_BYTES:
                raise NntpError(
                    f"multi-line response exceeds {MAX_MULTILINE_BYTES} byte cap",
                )
            line = raw.rstrip(b"\r\n")
            if line == b".":
                return
            if line.startswith(b".."):
                line = line[1:]
            yield line.decode("utf-8", "replace")

    # ------------------------------------------------------------------
    # Authentication (RFC 4643 — AUTHINFO USER / PASS)
    # ------------------------------------------------------------------

    def authinfo(self, username: str, password: str = "") -> None:
        """RFC 4643 plaintext auth. After STARTTLS / on port 563 this
        is the standard path; on plain 119 it leaks credentials and
        we log a warning so a misconfigured profile doesn't slip past.

        Validates username + password upfront so a CR/LF in either
        field can't put the connection into an indeterminate state
        (USER accepted, PASS never sent / silently truncated).
        """
        for label, value in (("username", username), ("password", password)):
            if "\r" in value or "\n" in value:
                raise NntpError(
                    f"AUTHINFO {label} must not contain CR/LF — refusing "
                    "to send to avoid leaving auth in an indeterminate state"
                )
        if not self._use_tls:
            log.warning(
                "NNTP AUTHINFO USER on plaintext socket — credentials "
                "are sent in the clear (host=%s)",
                self._host,
            )
        code, msg = self._command(f"AUTHINFO USER {username}")
        if code == 281:
            return  # 281 = no password needed
        if code == 381:
            code, msg = self._command(f"AUTHINFO PASS {password}")
        if code not in (281,):
            raise NntpResponseError(code, msg)

    # ------------------------------------------------------------------
    # CAPABILITIES (RFC 3977 §5.2)
    # ------------------------------------------------------------------

    def capabilities(self) -> list[str]:
        code, msg = self._command("CAPABILITIES")
        if code != 101:
            return []
        return list(self._read_multiline())

    # ------------------------------------------------------------------
    # Group / article ops
    # ------------------------------------------------------------------

    def mode_reader(self) -> None:
        """Many transit servers default to TRANSIT; we want READER."""
        code, msg = self._command("MODE READER")
        if code not in (200, 201):
            log.debug("MODE READER returned %d %s — proceeding anyway", code, msg)

    def list_groups(self, prefix: str = "") -> Iterator[tuple[str, int, int, str]]:
        """Yield ``(group, high, low, status)`` tuples.

        ``prefix`` filters via ``LIST ACTIVE <prefix>*`` so we don't
        round-trip 100 000 groups when the user only wants ``de.*``.
        Status is ``y`` (open), ``n`` (no posting), ``m`` (moderated).
        """
        if prefix:
            cmd = f"LIST ACTIVE {prefix}*"
        else:
            cmd = "LIST ACTIVE"
        code, msg = self._command(cmd)
        if code != 215:
            raise NntpResponseError(code, msg)
        for line in self._read_multiline():
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                yield parts[0], int(parts[1]), int(parts[2]), parts[3]
            except ValueError:
                continue

    def select_group(self, group: str) -> tuple[int, int, int]:
        """Switch to ``group``. Returns ``(estimated_count, low, high)``."""
        code, msg = self._command(f"GROUP {group}")
        if code == 480:
            raise NntpAuthRequired(code, msg)
        if code != 211:
            raise NntpResponseError(code, msg)
        # 211 <count> <first> <last> <group>
        parts = msg.split()
        try:
            return int(parts[0]), int(parts[1]), int(parts[2])
        except (ValueError, IndexError) as exc:
            raise NntpError(f"malformed GROUP response: {msg!r}") from exc

    def over(self, low: int, high: int) -> Iterator[dict]:
        """OVER (RFC 3977 §8.3) — yields per-article overview records.

        Falls back to legacy XOVER when the server replies 500 to OVER.
        Each record is a dict with keys: ``msgno``, ``subject``,
        ``from``, ``date``, ``message_id``, ``references``, ``bytes``,
        ``lines``.
        """
        cmd = f"OVER {low}-{high}"
        code, msg = self._command(cmd)
        if code == 500:
            code, msg = self._command(f"XOVER {low}-{high}")
        if code != 224:
            raise NntpResponseError(code, msg)
        for line in self._read_multiline():
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            yield {
                "msgno": _safe_int(parts[0]),
                "subject": parts[1],
                "from": parts[2],
                "date": parts[3],
                "message_id": parts[4],
                "references": parts[5],
                "bytes": _safe_int(parts[6]),
                "lines": _safe_int(parts[7]) if len(parts) > 7 else 0,
            }

    def article(self, ident: int | str) -> bytes:
        """ARTICLE <number>|<message-id> — full RFC 5322 / Usenet
        article (headers + body). Returns the bytes."""
        cmd = f"ARTICLE {ident}"
        code, msg = self._command(cmd)
        if code == 480:
            raise NntpAuthRequired(code, msg)
        if code != 220:
            raise NntpResponseError(code, msg)
        chunks: list[bytes] = []
        for line in self._read_multiline():
            chunks.append(line.encode("utf-8", "replace"))
        return b"\r\n".join(chunks) + b"\r\n"

    def head(self, ident: int | str) -> bytes:
        cmd = f"HEAD {ident}"
        code, msg = self._command(cmd)
        if code != 221:
            raise NntpResponseError(code, msg)
        chunks: list[bytes] = []
        for line in self._read_multiline():
            chunks.append(line.encode("utf-8", "replace"))
        return b"\r\n".join(chunks) + b"\r\n"

    def body(self, ident: int | str) -> bytes:
        cmd = f"BODY {ident}"
        code, msg = self._command(cmd)
        if code != 222:
            raise NntpResponseError(code, msg)
        chunks: list[bytes] = []
        for line in self._read_multiline():
            chunks.append(line.encode("utf-8", "replace"))
        return b"\r\n".join(chunks) + b"\r\n"

    def post(self, raw_article: bytes) -> None:
        """POST a fully formed Usenet article. The body must already
        contain headers + blank-line + body. Dot-stuffing is applied
        on the wire automatically."""
        if not self._posting_allowed:
            raise NntpError("posting is not allowed on this connection")
        code, msg = self._command("POST")
        if code != 340:
            raise NntpResponseError(code, msg)
        # Dot-stuff each line that begins with a dot.
        out = bytearray()
        for line in raw_article.splitlines():
            if line.startswith(b"."):
                out.extend(b"." + line)
            else:
                out.extend(line)
            out.extend(b"\r\n")
        out.extend(b".\r\n")
        self._reader.write(bytes(out))
        code, msg = self._read_status()
        if code != 240:
            raise NntpResponseError(code, msg)

    # ------------------------------------------------------------------
    # Forward-compat escape hatch
    # ------------------------------------------------------------------

    def raw_command(self, line: str, multiline: bool = False) -> tuple[int, str, list[str] | None]:
        """Send an arbitrary command and return ``(code, message,
        body)`` where body is the multi-line block (or None)."""
        code, msg = self._command(line)
        body = list(self._read_multiline()) if multiline else None
        return code, msg, body

    def quit(self) -> None:
        try:
            self._command("QUIT")
        except Exception:  # noqa: BLE001
            pass
        try:
            self._sock.close()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.quit()


def _safe_int(s: str) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def parse_overview_date(s: str) -> datetime:
    """Best-effort parse of an NNTP overview ``Date`` header.
    Returns epoch on failure (empty input, malformed string, or any
    of the half-dozen exception types the stdlib parser raises in
    different Python versions)."""
    if not s:
        return datetime.fromtimestamp(0)
    from email.utils import parsedate_to_datetime
    try:
        result = parsedate_to_datetime(s)
    except (TypeError, ValueError, AttributeError, IndexError):
        return datetime.fromtimestamp(0)
    if result is None:
        return datetime.fromtimestamp(0)
    return result
