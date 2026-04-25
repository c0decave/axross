"""Telnet backend implementing the FileBackend protocol.

Uses raw shell commands over a custom telnet transport to provide
filesystem operations.  No external dependencies — pure stdlib sockets.
"""
from __future__ import annotations

import base64
import io
import logging
import posixpath
import re
import select
import shlex
import socket
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import IO, TYPE_CHECKING

from models.file_item import FileItem

if TYPE_CHECKING:  # pragma: no cover — type-hint only, no runtime cost
    from core.proxy import ProxyConfig

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Telnet protocol constants (RFC 854 / 855)
# ---------------------------------------------------------------------------
IAC = 0xFF  # Interpret As Command
DONT = 0xFE
DO = 0xFD
WONT = 0xFC
WILL = 0xFB
SB = 0xFA  # Sub-negotiation Begin
SE = 0xF0  # Sub-negotiation End
NOP = 0xF1
GA = 0xF9  # Go Ahead

# Common option codes
OPT_ECHO = 1
OPT_SGA = 3  # Suppress Go-Ahead
OPT_TTYPE = 24  # Terminal Type
OPT_NAWS = 31  # Negotiate About Window Size
OPT_LINEMODE = 34

_PROMPT_MARKER = "__AXX_PROMPT__"
_CMD_START_PREFIX = "__AXX_CMD_START_"
_CMD_EXIT_PREFIX = "__AXX_CMD_EXIT_"

# Login prompt patterns (case-insensitive)
_LOGIN_RE = re.compile(r"(login|username)\s*:", re.IGNORECASE)
_PASSWORD_RE = re.compile(r"password\s*:", re.IGNORECASE)
_SHELL_PROMPT_RE = re.compile(r"[$#%>]\s*$")

# Strip ANSI escape sequences (colors, cursor movements, etc.)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\([AB0-2]")

# ls -la line parser
_LS_LINE_RE = re.compile(
    r"^([dlcbps-])"           # type char
    r"([rwxsStT-]{9})\s+"     # permissions
    r"(\d+)\s+"               # nlinks
    r"(\S+)\s+"               # owner
    r"(\S+)\s+"               # group
    r"(\d+)\s+"               # size
    r"(.{12})\s+"             # date (fixed width)
    r"(.+)$"                  # name (may contain -> for symlinks)
)

CONNECT_TIMEOUT = 15.0
CMD_TIMEOUT = 30.0
TRANSFER_TIMEOUT = 300.0
_READ_SLICE = 0.1  # select() poll interval


# ---------------------------------------------------------------------------
# Layer 1: Raw Telnet Transport
# ---------------------------------------------------------------------------
def _validate_telnet_host(host: str) -> None:
    """Reject control characters and whitespace in telnet host strings."""
    if not host:
        raise OSError("Telnet host must not be empty")
    if any(ch in host for ch in ("\r", "\n", "\x00")):
        raise OSError("Telnet host contains invalid control characters")
    if any(ch.isspace() for ch in host):
        raise OSError("Telnet host must not contain whitespace")


class _TelnetTransport:
    """Raw TCP socket with telnet IAC negotiation (IPv4 + IPv6).

    Accepts an optional :class:`core.proxy.ProxyConfig` — when set,
    the underlying socket is created through the proxy instead of a
    direct TCP connect. Telnet is plain-text TCP, so any
    SOCKS4/SOCKS5/HTTP-CONNECT proxy can tunnel it.
    """

    def __init__(self, host: str, port: int, timeout: float = CONNECT_TIMEOUT,
                 proxy: "ProxyConfig | None" = None,
                 naws_width: int = 0, naws_height: int = 0):
        _validate_telnet_host(host)
        if not 0 < int(port) < 65536:
            raise OSError(f"Telnet port out of range: {port}")

        self._host = host
        self._port = port
        # NAWS geometry: 0 means "use module default" — see
        # core.client_identity.TELNET_NAWS_{WIDTH,HEIGHT}.
        from core.client_identity import TELNET_NAWS_HEIGHT, TELNET_NAWS_WIDTH
        self._naws_width = naws_width if naws_width > 0 else TELNET_NAWS_WIDTH
        self._naws_height = naws_height if naws_height > 0 else TELNET_NAWS_HEIGHT
        try:
            if proxy is not None and proxy.enabled:
                # SSRF guard + deny-listed-range check live inside
                # create_proxy_socket.
                from core.proxy import create_proxy_socket
                self._sock = create_proxy_socket(
                    proxy, host, int(port), timeout=timeout,
                )
                log.info(
                    "Telnet via %s proxy %s:%d → %s:%d",
                    proxy.proxy_type, proxy.host, proxy.port, host, port,
                )
            else:
                # create_connection transparently handles IPv4/IPv6 via
                # getaddrinfo and tries each resolved address until one
                # succeeds.
                self._sock = socket.create_connection(
                    (host, port), timeout=timeout,
                )
        except (socket.gaierror, OSError, ConnectionError) as e:
            log.warning("Telnet connect to %s:%d failed: %s", host, port, e)
            raise OSError(f"Cannot connect to {host}:{port}: {e}") from e
        self._sock.setblocking(False)
        self._buffer = b""
        self._closed = False
        log.debug("Telnet transport connected to %s:%d", host, port)

    def send(self, data: str) -> None:
        """Send text data with proper telnet line endings (CR/LF).

        All newlines are converted to CR/LF for the telnet protocol.
        For large data (e.g. heredocs), the data is sent in chunks to
        avoid overwhelming the remote line buffer.
        """
        if self._closed:
            raise OSError("Transport closed")
        # Normalize line endings: \r\n → \n → \r\n
        raw = data.replace("\r\n", "\n").replace("\r", "\n")
        lines = raw.split("\n")
        # Reassemble with CR/LF and ensure trailing CR/LF
        raw_bytes = b"\r\n".join(l.encode("utf-8") for l in lines)
        if not raw_bytes.endswith(b"\r\n"):
            raw_bytes += b"\r\n"
        try:
            # Send in chunks to avoid telnet server buffer issues
            chunk_size = 4096
            for i in range(0, len(raw_bytes), chunk_size):
                self._sock.sendall(raw_bytes[i : i + chunk_size])
                if len(raw_bytes) > chunk_size:
                    time.sleep(0.01)  # pace large sends
        except OSError as e:
            self._closed = True
            raise OSError(f"Send failed: {e}") from e

    def send_raw(self, data: bytes) -> None:
        """Send raw bytes without newline appending."""
        if self._closed:
            raise OSError("Transport closed")
        try:
            self._sock.sendall(data)
        except OSError as e:
            self._closed = True
            raise OSError(f"Send failed: {e}") from e

    def read_until(
        self, match: str, timeout: float = CMD_TIMEOUT
    ) -> str:
        """Read until *match* appears in the accumulated text.

        Returns all text up to and including the match.
        Raises TimeoutError if *timeout* seconds elapse.
        """
        deadline = time.monotonic() + timeout
        text = ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timeout waiting for {match!r} "
                    f"(got so far: {text[-200:]!r})"
                )
            chunk = self._read_chunk(min(remaining, _READ_SLICE))
            if chunk:
                text += chunk
                if match in text:
                    return text
        # unreachable

    def read_until_re(
        self, pattern: re.Pattern, timeout: float = CMD_TIMEOUT
    ) -> tuple[str, re.Match]:
        """Read until regex *pattern* matches somewhere in the accumulated text."""
        deadline = time.monotonic() + timeout
        text = ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timeout waiting for pattern {pattern.pattern!r} "
                    f"(got so far: {text[-200:]!r})"
                )
            chunk = self._read_chunk(min(remaining, _READ_SLICE))
            if chunk:
                text += chunk
                m = pattern.search(text)
                if m:
                    return text, m

    def read_some(self, timeout: float = 1.0) -> str:
        """Read whatever is available within timeout."""
        text = ""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = self._read_chunk(min(remaining, _READ_SLICE))
            if chunk:
                text += chunk
            elif text:
                break  # Got some data, nothing more coming
        return text

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._sock.close()
            except OSError:
                pass
            log.debug("Telnet transport closed")

    @property
    def closed(self) -> bool:
        return self._closed

    def _read_chunk(self, timeout: float) -> str:
        """Read available data from socket, process IAC sequences."""
        try:
            ready, _, _ = select.select([self._sock], [], [], max(timeout, 0))
        except (ValueError, OSError):
            self._closed = True
            return ""
        if not ready:
            return ""
        try:
            raw = self._sock.recv(4096)
        except BlockingIOError:
            return ""
        except OSError as e:
            self._closed = True
            raise OSError(f"Read failed: {e}") from e
        if not raw:
            self._closed = True
            return ""
        # Prepend any leftover bytes from previous incomplete IAC sequence
        data = self._buffer + raw
        self._buffer = b""
        data, leftover = self._negotiate(data)
        self._buffer = leftover
        # Strip carriage returns
        text = data.decode("utf-8", errors="replace").replace("\r", "")
        return text

    def _negotiate(self, data: bytes) -> tuple[bytes, bytes]:
        """Process IAC sequences, respond to option negotiations.

        Returns (clean_data, leftover) where leftover contains any
        incomplete IAC sequence at the end that needs more data.
        """
        clean = bytearray()
        i = 0
        while i < len(data):
            if data[i] != IAC:
                clean.append(data[i])
                i += 1
                continue
            if i + 1 >= len(data):
                # Incomplete IAC at end — save for next read
                return bytes(clean), data[i:]
            cmd = data[i + 1]
            if cmd == IAC:
                clean.append(IAC)  # Escaped 0xFF
                i += 2
                continue
            if cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= len(data):
                    return bytes(clean), data[i:]
                opt = data[i + 2]
                self._handle_option(cmd, opt)
                i += 3
                continue
            if cmd == SB:
                # Sub-negotiation: find SE
                se_idx = data.find(bytes([IAC, SE]), i + 2)
                if se_idx == -1:
                    return bytes(clean), data[i:]
                self._handle_subneg(data[i + 2 : se_idx])
                i = se_idx + 2
                continue
            # Other commands (NOP, GA, etc.) — skip
            i += 2
        return bytes(clean), b""

    def _handle_option(self, cmd: int, opt: int) -> None:
        """Respond to DO/DONT/WILL/WONT option negotiations."""
        if cmd == DO:
            if opt == OPT_SGA:
                self.send_raw(bytes([IAC, WILL, OPT_SGA]))
            elif opt == OPT_TTYPE:
                self.send_raw(bytes([IAC, WILL, OPT_TTYPE]))
            elif opt == OPT_NAWS:
                # Window size — default 80×24 (VT100), overridable per
                # profile via ``telnet_naws_{width,height}``. Real
                # terminals rarely change size mid-session, so a fixed
                # plausible default blends better than randomisation.
                w, h = int(self._naws_width), int(self._naws_height)
                self.send_raw(bytes([IAC, WILL, OPT_NAWS]))
                self.send_raw(bytes([
                    IAC, SB, OPT_NAWS,
                    (w >> 8) & 0xFF, w & 0xFF,
                    (h >> 8) & 0xFF, h & 0xFF,
                    IAC, SE,
                ]))
            else:
                self.send_raw(bytes([IAC, WONT, opt]))
        elif cmd == WILL:
            if opt == OPT_SGA:
                self.send_raw(bytes([IAC, DO, OPT_SGA]))
            elif opt == OPT_ECHO:
                self.send_raw(bytes([IAC, DO, OPT_ECHO]))
            else:
                self.send_raw(bytes([IAC, DONT, opt]))
        elif cmd in (DONT, WONT):
            pass  # Acknowledge silently

    def _handle_subneg(self, data: bytes) -> None:
        """Handle sub-negotiation requests."""
        if not data:
            return
        opt = data[0]
        if opt == OPT_TTYPE and len(data) >= 2 and data[1] == 1:
            # SEND request for terminal type
            ttype = b"xterm"
            self.send_raw(bytes([IAC, SB, OPT_TTYPE, 0]) + ttype + bytes([IAC, SE]))


# ---------------------------------------------------------------------------
# Layer 2: Shell Session
# ---------------------------------------------------------------------------
class _ShellSession:
    """Manages shell interaction over a telnet transport."""

    def __init__(
        self,
        transport: _TelnetTransport,
        username: str,
        password: str,
        timeout: float = CONNECT_TIMEOUT,
    ):
        self._transport = transport
        self._username = username
        self._password = password
        self._prompt_ready = False
        # Per-session unpredictable suffix so remote file content cannot
        # forge our exit-code sentinel. 64-bit hex from secrets.token_hex
        # (~16 chars) collapses the collision / forgery probability to
        # something negligible even on long-running shells.
        import secrets
        self._marker_id = secrets.token_hex(8)
        self._cmd_start = f"{_CMD_START_PREFIX}{self._marker_id}__"
        self._cmd_exit_re = re.compile(
            rf"{re.escape(_CMD_EXIT_PREFIX)}{self._marker_id}_(\d+)__"
        )
        self._login(timeout)
        self._setup_prompt()

    def _login(self, timeout: float) -> None:
        """Perform username/password authentication."""
        deadline = time.monotonic() + timeout
        text = ""

        # Read until we see a login prompt or shell prompt (no-auth systems)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Timeout waiting for login prompt (got: {text[-200:]!r})")
            chunk = self._transport.read_some(min(remaining, 2.0))
            text += chunk
            if _LOGIN_RE.search(text):
                break
            if _PASSWORD_RE.search(text):
                # Some systems skip username, go straight to password
                self._transport.send(self._password)
                try:
                    result = self._transport.read_some(timeout=5.0)
                    text += result
                except TimeoutError:
                    pass
                if _SHELL_PROMPT_RE.search(text):
                    log.info("Telnet login successful (password-only)")
                    return
                raise PermissionError("Telnet login failed")
            if _SHELL_PROMPT_RE.search(text):
                log.info("Telnet: no-auth shell detected")
                return

        # Send username
        self._transport.send(self._username)

        # Wait for password prompt
        try:
            text2 = self._transport.read_until_re(_PASSWORD_RE, timeout=10.0)[0]
        except TimeoutError:
            # Maybe no password required
            text2 = self._transport.read_some(timeout=2.0)
            if _SHELL_PROMPT_RE.search(text2):
                log.info("Telnet login successful (no password)")
                return
            raise PermissionError("Telnet login failed: no password prompt received")

        # Send password
        self._transport.send(self._password)

        # Wait for shell prompt or error
        try:
            result = self._transport.read_some(timeout=10.0)
        except TimeoutError:
            raise PermissionError("Telnet login timed out after password")

        if any(kw in result.lower() for kw in ("incorrect", "denied", "failed", "invalid", "bad")):
            raise PermissionError("Telnet login failed: invalid credentials")

        # Check for shell prompt
        if _SHELL_PROMPT_RE.search(result):
            log.info("Telnet login successful")
            return

        # Try reading a bit more
        try:
            more = self._transport.read_some(timeout=5.0)
            result += more
        except TimeoutError:
            pass
        if _SHELL_PROMPT_RE.search(result):
            log.info("Telnet login successful")
            return

        raise PermissionError(f"Telnet login failed: unexpected response: {result[-200:]!r}")

    def _setup_prompt(self) -> None:
        """Set a unique, parseable prompt and configure shell for automation."""
        # Use printf to emit a real newline in PS1 (works in sh/dash/ash/bash)
        commands = [
            f"PS1=$(printf '{_PROMPT_MARKER}\\n'); export PS1",
            "export PS2=''",
            "export LANG=C LC_ALL=C TERM=dumb",
            "unalias ls 2>/dev/null; true",
            "stty -echo 2>/dev/null; true",
            f"echo '{_PROMPT_MARKER}'",
        ]
        for cmd in commands:
            self._transport.send(cmd)
            time.sleep(0.05)

        # Synchronize: read until we see the prompt marker
        try:
            self._transport.read_until(_PROMPT_MARKER, timeout=10.0)
            # Consume any trailing prompt markers from the setup
            self._transport.read_some(timeout=0.5)
            self._prompt_ready = True
            log.debug("Shell prompt configured")
        except TimeoutError:
            log.warning("Could not set custom prompt, continuing anyway")
            self._prompt_ready = True

    def execute(self, cmd: str, timeout: float = CMD_TIMEOUT) -> tuple[str, int]:
        """Execute a shell command and return (stdout, exit_code).

        Uses per-session randomized markers to reliably delimit command output.
        For multi-line commands (heredocs), the exit marker is placed on its
        own line after the command to avoid breaking heredoc delimiters.
        """
        mid = self._marker_id
        exit_marker_echo = f'"{_CMD_EXIT_PREFIX}{mid}_$?__"'
        if "\n" in cmd:
            # Multi-line command (heredoc): exit echo must be on its own line
            wrapped = f"echo '{self._cmd_start}'\n{cmd}\necho {exit_marker_echo}"
        else:
            wrapped = f"echo '{self._cmd_start}'; {cmd} 2>&1; echo {exit_marker_echo}"
        self._transport.send(wrapped)

        # Read until exit marker
        try:
            text, m = self._transport.read_until_re(self._cmd_exit_re, timeout=timeout)
        except TimeoutError:
            raise TimeoutError(f"Command timed out: {cmd[:80]!r}")

        exit_code = int(m.group(1))

        # Extract output between start marker and exit marker
        start_idx = text.find(self._cmd_start)
        if start_idx != -1:
            output = text[start_idx + len(self._cmd_start) : m.start()]
        else:
            output = text[: m.start()]

        # Clean up: strip leading/trailing whitespace, remove prompt markers
        output = output.replace(_PROMPT_MARKER, "").strip()

        return output, exit_code

    def execute_checked(self, cmd: str, timeout: float = CMD_TIMEOUT) -> str:
        """Execute and raise OSError if exit code is non-zero."""
        output, code = self.execute(cmd, timeout=timeout)
        if code != 0:
            raise OSError(f"Command failed (exit {code}): {cmd[:80]}\n{output[:500]}")
        return output

    def execute_streaming(
        self, cmd: str, timeout: float = TRANSFER_TIMEOUT
    ) -> tuple[str, int]:
        """Execute a command that may produce large output (e.g. base64 dump).

        Same as execute() but with a longer default timeout.
        """
        return self.execute(cmd, timeout=timeout)

    @property
    def transport(self) -> _TelnetTransport:
        return self._transport


# ---------------------------------------------------------------------------
# Layer 3: Capability Probe
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Capabilities:
    """Available shell tools detected after login."""

    has_base64: bool = False
    has_uuencode: bool = False
    has_xxd: bool = False
    has_stat_gnu: bool = False
    has_stat_bsd: bool = False
    has_md5sum: bool = False
    has_dd: bool = False
    has_tar: bool = False
    has_chmod: bool = False
    has_readlink: bool = False
    has_df: bool = False
    has_wc: bool = False
    has_test: bool = True  # Assume shell built-in
    shell_type: str = "sh"
    os_name: str = "unknown"
    transfer_method: str = "raw"  # "base64", "uuencode", "xxd", "raw"


def _probe_capabilities(shell: _ShellSession) -> _Capabilities:
    """Detect available commands and determine best transfer method."""
    tools: dict[str, bool] = {}
    probes = [
        "base64", "uuencode", "xxd", "stat", "md5sum", "dd",
        "tar", "chmod", "readlink", "df", "wc", "mkdir", "rm", "mv",
        "cat", "test", "ls",
    ]

    # Batch check: command -v for each tool
    # Some shells don't have command -v, fallback to which
    check_cmd = "command -v"
    _, code = shell.execute(f"{check_cmd} ls", timeout=5.0)
    if code != 0:
        check_cmd = "which"

    for tool in probes:
        _, code = shell.execute(f"{check_cmd} {tool}", timeout=5.0)
        tools[tool] = code == 0

    # Detect GNU stat vs BSD stat
    has_stat_gnu = False
    has_stat_bsd = False
    if tools.get("stat"):
        _, code = shell.execute("stat --format='%s' / 2>/dev/null", timeout=5.0)
        if code == 0:
            has_stat_gnu = True
        else:
            _, code = shell.execute("stat -f '%z' / 2>/dev/null", timeout=5.0)
            if code == 0:
                has_stat_bsd = True

    # Detect OS
    os_output, _ = shell.execute("uname -s 2>/dev/null", timeout=5.0)
    os_name = os_output.strip() or "unknown"

    # Detect shell
    shell_output, _ = shell.execute("echo $0 2>/dev/null || echo $SHELL", timeout=5.0)
    shell_type = posixpath.basename(shell_output.strip().lstrip("-")) or "sh"

    # Determine best transfer method
    if tools.get("base64"):
        transfer_method = "base64"
    elif tools.get("uuencode"):
        transfer_method = "uuencode"
    elif tools.get("xxd"):
        transfer_method = "xxd"
    else:
        transfer_method = "raw"

    caps = _Capabilities(
        has_base64=tools.get("base64", False),
        has_uuencode=tools.get("uuencode", False),
        has_xxd=tools.get("xxd", False),
        has_stat_gnu=has_stat_gnu,
        has_stat_bsd=has_stat_bsd,
        has_md5sum=tools.get("md5sum", False),
        has_dd=tools.get("dd", False),
        has_tar=tools.get("tar", False),
        has_chmod=tools.get("chmod", False),
        has_readlink=tools.get("readlink", False),
        has_df=tools.get("df", False),
        has_wc=tools.get("wc", False),
        shell_type=shell_type,
        os_name=os_name,
        transfer_method=transfer_method,
    )
    log.info(
        "Telnet capabilities: transfer=%s, stat_gnu=%s, stat_bsd=%s, os=%s, shell=%s",
        caps.transfer_method, caps.has_stat_gnu, caps.has_stat_bsd,
        caps.os_name, caps.shell_type,
    )
    return caps


# ---------------------------------------------------------------------------
# Layer 4: Output Parsers
# ---------------------------------------------------------------------------
def _parse_ls_la(output: str) -> list[FileItem]:
    """Parse `ls -la` output into FileItem list."""
    # Strip ANSI escape sequences that some shells/aliases inject
    output = _ANSI_RE.sub("", output)
    items: list[FileItem] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("total "):
            continue
        m = _LS_LINE_RE.match(line)
        if not m:
            continue
        type_char = m.group(1)
        perm_str = m.group(2)
        owner = m.group(4)
        group = m.group(5)
        size = int(m.group(6))
        date_str = m.group(7).strip()
        name_field = m.group(8)

        is_dir = type_char == "d"
        is_link = type_char == "l"
        link_target = ""
        name = name_field

        if is_link and " -> " in name_field:
            name, link_target = name_field.split(" -> ", 1)

        # Skip . and ..
        if name in (".", ".."):
            continue

        permissions = _parse_permissions(perm_str)
        modified = _parse_ls_date(date_str)

        items.append(FileItem(
            name=name,
            size=size,
            modified=modified,
            permissions=permissions,
            is_dir=is_dir,
            is_link=is_link,
            link_target=link_target,
            owner=owner,
            group=group,
        ))
    return items


def _parse_permissions(perm_str: str) -> int:
    """Convert 'rwxrwxrwx' string to octal permission int."""
    mode = 0
    bits = [
        0o400, 0o200, 0o100,  # owner rwx
        0o040, 0o020, 0o010,  # group rwx
        0o004, 0o002, 0o001,  # other rwx
    ]
    for i, char in enumerate(perm_str[:9]):
        if char == "-":
            continue
        # Handle setuid/setgid/sticky at execute positions
        if i == 2 and char in ("s", "S"):
            mode |= 0o4000
            if char == "s":  # setuid WITH execute
                mode |= bits[i]
            # 'S' = setuid WITHOUT execute — don't set execute bit
            continue
        if i == 5 and char in ("s", "S"):
            mode |= 0o2000
            if char == "s":
                mode |= bits[i]
            continue
        if i == 8 and char in ("t", "T"):
            mode |= 0o1000
            if char == "t":  # sticky WITH execute
                mode |= bits[i]
            continue
        # Normal rwx bits
        if i < len(bits):
            mode |= bits[i]
    return mode


def _parse_ls_date(date_str: str) -> datetime:
    """Parse ls -la date field.

    Formats: 'Mar 16 14:30' (recent) or 'Mar 16  2025' (old).
    """
    now = datetime.now()
    for fmt in ("%b %d %H:%M", "%b %d  %Y", "%b %d %Y"):
        try:
            dt = datetime.strptime(date_str, fmt)
            # If no year in format, use current year
            if dt.year == 1900:
                dt = dt.replace(year=now.year)
                # If date is in the future, it's probably last year
                if dt > now:
                    dt = dt.replace(year=now.year - 1)
            return dt
        except ValueError:
            continue
    return datetime.fromtimestamp(0)


def _parse_stat_gnu(output: str) -> FileItem:
    """Parse GNU stat output with format '%n|%s|%Y|%f|%U|%G|%F'."""
    parts = output.strip().split("|")
    if len(parts) < 7:
        raise ValueError(f"Cannot parse stat output: {output!r}")
    name = posixpath.basename(parts[0])
    size = int(parts[1])
    mtime = datetime.fromtimestamp(int(parts[2]))
    mode = int(parts[3], 16) & 0o7777
    owner = parts[4]
    group = parts[5]
    ftype = parts[6].lower()
    is_dir = "directory" in ftype
    is_link = "link" in ftype

    return FileItem(
        name=name,
        size=size,
        modified=mtime,
        permissions=mode,
        is_dir=is_dir,
        is_link=is_link,
        owner=owner,
        group=group,
    )


def _parse_df(output: str) -> tuple[int, int, int]:
    """Parse `df -B1` or `df -k` output.

    Returns (total, used, free) in bytes.
    """
    lines = output.strip().splitlines()
    if len(lines) < 2:
        return (0, 0, 0)
    # Header line, then data (may wrap to second line)
    data_lines = lines[1:]
    data = " ".join(data_lines)
    parts = data.split()
    # Typical: filesystem total used available use% mountpoint
    # We need: parts[1]=total, parts[2]=used, parts[3]=available
    try:
        if len(parts) >= 4:
            total = int(parts[1])
            used = int(parts[2])
            free = int(parts[3])
            return (total, used, free)
    except (ValueError, IndexError):
        pass
    return (0, 0, 0)


# ---------------------------------------------------------------------------
# Layer 5: SpooledWriter
# ---------------------------------------------------------------------------
class _SpooledWriter:
    """Buffer writes in memory, upload via shell on close()."""

    def __init__(
        self,
        shell: _ShellSession,
        remote_path: str,
        caps: _Capabilities,
        append: bool = False,
    ):
        self._shell = shell
        self._remote_path = remote_path
        self._caps = caps
        self._append = append
        self._buf = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)

    def write(self, data: bytes) -> int:
        return self._buf.write(data)

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self._buf.seek(pos, whence)

    def tell(self) -> int:
        return self._buf.tell()

    def close(self) -> None:
        self._buf.seek(0)
        data = self._buf.read()
        self._buf.close()
        qpath = shlex.quote(self._remote_path)

        if self._caps.transfer_method == "base64":
            self._upload_base64(data, qpath)
        elif self._caps.transfer_method == "uuencode":
            self._upload_uuencode(data, qpath)
        elif self._caps.transfer_method == "xxd":
            self._upload_xxd(data, qpath)
        else:
            self._upload_raw(data, qpath)

    @staticmethod
    def _safe_eof(payload: str) -> str:
        """Return an EOF marker that does not appear in *payload*."""
        eof = "__AXX_EOF__"
        while eof in payload:
            eof += "_"
        return eof

    def _upload_base64(self, data: bytes, qpath: str) -> None:
        encoded = base64.b64encode(data).decode("ascii")
        redirect = ">>" if self._append else ">"
        eof = self._safe_eof(encoded)
        cmd = f"base64 -d {redirect} {qpath} << '{eof}'\n{encoded}\n{eof}"
        self._shell.execute_checked(cmd, timeout=TRANSFER_TIMEOUT)

    def _upload_uuencode(self, data: bytes, qpath: str) -> None:
        import uu
        # ``uudecode -o`` writes/overwrites the output file — there's
        # no in-tool append flag. ``open_write(append=True)`` handles
        # append at the backend layer by pre-concatenating the
        # existing content and calling the writer with append=False,
        # so in the normal flow ``self._append`` is always False
        # here. A direct ``_SpooledWriter(append=True)`` caller that
        # lands in this path would silently drop the append semantic,
        # so refuse it explicitly rather than hide the bug behind a
        # dead ``redirect`` variable.
        if self._append:
            raise OSError(
                "Telnet uuencode upload path does not support append; "
                "go through open_write(append=True) or use xxd/raw.",
            )
        buf_in = io.BytesIO(data)
        buf_out = io.BytesIO()
        uu.encode(buf_in, buf_out, name="-")
        uu_data = buf_out.getvalue().decode("ascii")
        eof = self._safe_eof(uu_data)
        cmd = f"uudecode -o {qpath} << '{eof}'\n{uu_data}\n{eof}"
        self._shell.execute_checked(cmd, timeout=TRANSFER_TIMEOUT)

    def _upload_xxd(self, data: bytes, qpath: str) -> None:
        hex_data = data.hex()
        redirect = ">>" if self._append else ">"
        eof = self._safe_eof(hex_data)
        cmd = f"xxd -r -p {redirect} {qpath} << '{eof}'\n{hex_data}\n{eof}"
        self._shell.execute_checked(cmd, timeout=TRANSFER_TIMEOUT)

    def _upload_raw(self, data: bytes, qpath: str) -> None:
        """Text-only fallback via cat heredoc. Only works for text data."""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise OSError(
                "Cannot upload binary file: no base64/uuencode/xxd available "
                "on remote system. Only text files are supported."
            )
        redirect = ">>" if self._append else ">"
        eof = self._safe_eof(text)
        cmd = f"cat {redirect} {qpath} << '{eof}'\n{text}\n{eof}"
        self._shell.execute_checked(cmd, timeout=TRANSFER_TIMEOUT)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ---------------------------------------------------------------------------
# Main Backend: TelnetSession (FileBackend implementation)
# ---------------------------------------------------------------------------
class TelnetSession:
    """Telnet filesystem backend using shell commands.

    Connects via raw telnet, authenticates, then uses standard Unix commands
    (ls, stat, cat, base64, etc.) to implement the FileBackend interface.
    """

    def __init__(
        self,
        host: str,
        port: int = 23,
        username: str = "",
        password: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
        naws_width: int = 0,
        naws_height: int = 0,
    ):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._naws_width = naws_width
        self._naws_height = naws_height
        # Build an optional ProxyConfig from the kwargs. ProxyConfig's
        # ``enabled`` property decides whether we go through a proxy
        # or direct.
        from core.proxy import ProxyConfig
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )
        self._transport: _TelnetTransport | None = None
        self._shell: _ShellSession | None = None
        self._caps: _Capabilities = _Capabilities()
        self._home_dir: str = "/"
        self._connected = False
        self._connect()

    def _connect(self) -> None:
        """Establish telnet connection, login, probe capabilities."""
        self._transport = _TelnetTransport(
            self._host, self._port, proxy=self._proxy,
            naws_width=self._naws_width, naws_height=self._naws_height,
        )
        self._shell = _ShellSession(
            self._transport, self._username, self._password
        )
        self._caps = _probe_capabilities(self._shell)
        # Determine home directory
        output, code = self._shell.execute("echo $HOME", timeout=5.0)
        self._home_dir = output.strip() or "/"
        self._connected = True
        log.info(
            "Telnet session established: %s@%s:%d (home=%s, transfer=%s)",
            self._username, self._host, self._port,
            self._home_dir, self._caps.transfer_method,
        )

    def _ensure_connected(self) -> _ShellSession:
        """Reconnect if the connection has dropped."""
        if self._connected and self._shell and not self._transport.closed:
            return self._shell
        log.info("Telnet: reconnecting to %s:%d", self._host, self._port)
        if self._transport and not self._transport.closed:
            self._transport.close()
        self._connect()
        return self._shell

    def _force_reconnect(self) -> _ShellSession:
        """Force a full reconnect (close + reconnect)."""
        self._connected = False
        if self._transport and not self._transport.closed:
            self._transport.close()
        self._connect()
        return self._shell

    def _exec(self, cmd: str, timeout: float = CMD_TIMEOUT) -> str:
        """Execute command, auto-reconnect once on failure."""
        shell = self._ensure_connected()
        try:
            return shell.execute_checked(cmd, timeout=timeout)
        except (OSError, TimeoutError):
            # Force reconnect and retry once
            log.debug("Telnet: command failed, reconnecting and retrying")
            shell = self._force_reconnect()
            return shell.execute_checked(cmd, timeout=timeout)

    def _exec_raw(self, cmd: str, timeout: float = CMD_TIMEOUT) -> tuple[str, int]:
        """Execute command returning (output, exit_code) without checking."""
        shell = self._ensure_connected()
        try:
            return shell.execute(cmd, timeout=timeout)
        except (OSError, TimeoutError):
            shell = self._force_reconnect()
            return shell.execute(cmd, timeout=timeout)

    # --- FileBackend interface ---

    @property
    def name(self) -> str:
        return f"{self._username}@{self._host} (Telnet)"

    @property
    def connected(self) -> bool:
        if not self._connected or not self._shell:
            return False
        try:
            _, code = self._shell.execute("echo ok", timeout=5.0)
            return code == 0
        except Exception:
            return False

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        output = self._exec(f"ls -la {shlex.quote(path)}")
        return _parse_ls_la(output)

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        qpath = shlex.quote(path)
        if self._caps.has_stat_gnu:
            output = self._exec(
                f"stat --format='%n|%s|%Y|%f|%U|%G|%F' {qpath}"
            )
            return _parse_stat_gnu(output)
        # Fallback: ls -ld
        output = self._exec(f"ls -ld {qpath}")
        items = _parse_ls_la(output)
        if not items:
            raise OSError(f"Cannot stat {path}: no output from ls -ld")
        item = items[0]
        # ls -la gives us the directory's own name, but we want the basename
        return FileItem(
            name=posixpath.basename(path.rstrip("/")) or path,
            size=item.size,
            modified=item.modified,
            permissions=item.permissions,
            is_dir=item.is_dir,
            is_link=item.is_link,
            link_target=item.link_target,
            owner=item.owner,
            group=item.group,
        )

    def is_dir(self, path: str) -> bool:
        _, code = self._exec_raw(f"test -d {shlex.quote(self.normalize(path))}")
        return code == 0

    def exists(self, path: str) -> bool:
        _, code = self._exec_raw(f"test -e {shlex.quote(self.normalize(path))}")
        return code == 0

    def mkdir(self, path: str) -> None:
        self._exec(f"mkdir -p {shlex.quote(self.normalize(path))}")

    def remove(self, path: str, recursive: bool = False) -> None:
        path = self.normalize(path)
        qpath = shlex.quote(path)
        if recursive:
            self._exec(f"rm -rf {qpath}")
        else:
            # Check if directory
            if self.is_dir(path):
                self._exec(f"rmdir {qpath}")
            else:
                self._exec(f"rm -f {qpath}")

    def rename(self, src: str, dst: str) -> None:
        self._exec(
            f"mv {shlex.quote(self.normalize(src))} {shlex.quote(self.normalize(dst))}"
        )

    def open_read(self, path: str) -> IO[bytes]:
        path = self.normalize(path)
        qpath = shlex.quote(path)
        shell = self._ensure_connected()

        if self._caps.transfer_method == "base64":
            output, code = shell.execute(
                f"base64 < {qpath}", timeout=TRANSFER_TIMEOUT
            )
            if code != 0:
                raise OSError(f"Cannot read {path}: base64 failed (exit {code})")
            # Decode base64 — output may have whitespace/newlines
            try:
                data = base64.b64decode(output.replace("\n", "").replace(" ", ""))
            except Exception as e:
                raise OSError(f"Cannot decode {path}: {e}") from e
        elif self._caps.transfer_method == "xxd":
            output, code = shell.execute(
                f"xxd -p < {qpath}", timeout=TRANSFER_TIMEOUT
            )
            if code != 0:
                raise OSError(f"Cannot read {path}: xxd failed (exit {code})")
            try:
                data = bytes.fromhex(output.replace("\n", "").replace(" ", ""))
            except Exception as e:
                raise OSError(f"Cannot decode {path}: {e}") from e
        elif self._caps.transfer_method == "uuencode":
            output, code = shell.execute(
                f"uuencode - - < {qpath}", timeout=TRANSFER_TIMEOUT
            )
            if code != 0:
                raise OSError(f"Cannot read {path}: uuencode failed (exit {code})")
            import uu
            buf_in = io.BytesIO(output.encode("ascii"))
            buf_out = io.BytesIO()
            try:
                uu.decode(buf_in, buf_out)
            except Exception as e:
                raise OSError(f"Cannot decode {path}: {e}") from e
            data = buf_out.getvalue()
        else:
            # Raw cat — text only
            output, code = shell.execute(
                f"cat {qpath}", timeout=TRANSFER_TIMEOUT
            )
            if code != 0:
                raise OSError(f"Cannot read {path}: cat failed (exit {code})")
            data = output.encode("utf-8")

        buf = io.BytesIO(data)
        buf.seek(0)
        return buf

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = self.normalize(path)
        if append:
            try:
                with self.open_read(path) as f:
                    existing = f.read()
            except OSError:
                existing = b""
            writer = _SpooledWriter(
                self._ensure_connected(), path, self._caps, append=False
            )
            writer.write(existing)
            return writer
        return _SpooledWriter(self._ensure_connected(), path, self._caps)

    def normalize(self, path: str) -> str:
        return posixpath.normpath(path) or "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def home(self) -> str:
        return self._home_dir

    def chmod(self, path: str, mode: int) -> None:
        if not self._caps.has_chmod:
            raise OSError("chmod not available on remote system")
        self._exec(f"chmod {oct(mode)[2:]} {shlex.quote(self.normalize(path))}")

    def readlink(self, path: str) -> str:
        if not self._caps.has_readlink:
            raise OSError("readlink not available on remote system")
        output = self._exec(f"readlink {shlex.quote(self.normalize(path))}")
        result = output.strip()
        if not result:
            raise OSError(f"Not a symlink: {path}")
        return result

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """Shell ``cp -p`` on the remote — server-side."""
        src = self.normalize(src)
        dst = self.normalize(dst)
        output, code = self._exec_raw(
            f"cp -p -- {shlex.quote(src)} {shlex.quote(dst)} 2>&1"
        )
        if code != 0:
            raise OSError(f"cp {src} -> {dst} failed: {output.strip()!r}")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Run the remote ``sha256sum`` / ``md5sum`` over the shell."""
        tool = {
            "sha256": "sha256sum",
            "sha1": "sha1sum",
            "md5": "md5sum",
        }.get(algorithm)
        if not tool:
            return ""
        path = self.normalize(path)
        output, code = self._exec_raw(
            f"{tool} {shlex.quote(path)} 2>/dev/null"
        )
        if code != 0 or not output:
            return ""
        first_line = output.strip().splitlines()[0] if output.strip() else ""
        digest = first_line.split()[0] if first_line else ""
        if digest and all(c in "0123456789abcdef" for c in digest.lower()):
            return f"{algorithm}:{digest.lower()}"
        return ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        if not self._caps.has_df:
            return (0, 0, 0)
        path = self.normalize(path)
        # Try df -B1 (GNU) first
        output, code = self._exec_raw(
            f"df -B1 {shlex.quote(path)} 2>/dev/null"
        )
        if code == 0:
            result = _parse_df(output)
            if result != (0, 0, 0):
                return result
        # Fallback: df -k (POSIX) → multiply by 1024
        output, code = self._exec_raw(f"df -k {shlex.quote(path)}")
        if code == 0:
            total, used, free = _parse_df(output)
            return (total * 1024, used * 1024, free * 1024)
        return (0, 0, 0)

    def close(self) -> None:
        self._connected = False
        if self._transport and not self._transport.closed:
            try:
                self._transport.send("exit")
            except OSError:
                pass
            self._transport.close()
        self._shell = None
        self._transport = None

    def disconnect(self) -> None:
        self.close()
