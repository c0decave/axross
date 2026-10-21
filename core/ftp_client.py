"""FTP/FTPS backend implementing the FileBackend protocol."""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import functools
import io
import logging
import posixpath
import re
import select
import socket
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from ftplib import FTP, FTP_TLS, error_perm  # nosec B402
from ftplib import Error as _FtpLibError  # nosec B402
from typing import IO, NoReturn

from core.backend import SessionLifecycle
from core.path_policy import MAX_RECURSIVE_DELETE_DEPTH, check_tree_depth, safe_join
from core.read_spool import READ_CHUNK, new_read_spool
from core.session_lock import io_lock, liveness_check, serialized
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

log = logging.getLogger(__name__)

# FTP/FTPS protocol support is intentional; Bandit B402/B321 is suppressed
# only at the exact import/call sites that need ftplib.


# A control connection verified (NOOP or login) this recently is used
# without another NOOP, unless its socket is readable - a server-side
# close ("421" + FIN) makes it readable and sends us down the NOOP path.
LIVENESS_WINDOW = 10.0

# A framing line of a multi-line reply: three digits, then '-' or ' '.
_FTP_REPLY_LINE = re.compile(r"^\d{3}[ -]")

# ftplib's own exceptions - error_temp (4xx), error_perm (5xx), error_reply,
# error_proto - and the EOFError it raises when the server hangs up are not
# OSError. The backend contract is OSError, which is what every caller
# (compare, pane, transfers, recursive delete) handles.
_FTP_PROTOCOL_ERRORS = (_FtpLibError, EOFError)

# One ``ls -l`` style LIST line: type and mode, link count, owner,
# optional group, size, date, then one space and the name. The date
# anchors the name, which may itself contain spaces; a symlink's name is
# followed by " -> target".
_UNIX_LIST_LINE = re.compile(
    r"^(?P<type>[-bcdlps])(?P<mode>[-rwxsStTl]{9})\S*\s+\d+\s+(?P<owner>\S+)\s+"
    r"(?:(?P<group>\S+)\s+)?(?P<size>\d+)\s+(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<when>\d{1,2}:\d{2}|\d{4}) (?P<rest>.*)$"
)

_LIST_MONTHS = {
    m: i
    for i, m in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
    )
}


@dataclasses.dataclass(frozen=True)
class _ListEntry:
    """One parsed Unix-style LIST line."""

    kind: str  # "-", "d", "l", ...
    mode: int  # permission bits, 0o7777 at most
    owner: str
    group: str
    size: int
    modified: datetime | None  # UTC; None when the date cannot be read
    rest: str  # the name, for a link "name -> target"


def _list_mode(chars: str) -> int:
    """Permission bits of the nine ``rwx`` characters of an ``ls -l`` line."""
    mode = 0
    for i, (special, exec_bit) in enumerate(((0o4000, 0o100), (0o2000, 0o010), (0o1000, 0o001))):
        r, w, x = chars[3 * i : 3 * i + 3]
        if r == "r":
            mode |= exec_bit << 2
        if w == "w":
            mode |= exec_bit << 1
        if x in "xst":
            mode |= exec_bit
        if x in "sStT":
            mode |= special
    return mode


def _list_date(month: str, day: str, when: str, now: datetime) -> datetime | None:
    """The date of a LIST line, read as UTC like MDTM.

    ``Mon DD HH:MM`` leaves out the year of a date within the last six
    months; one that would lie ahead of ``now`` is from last year.
    """
    number = _LIST_MONTHS.get(month.lower())
    if number is None:
        return None
    try:
        if ":" in when:
            hour, minute = (int(x) for x in when.split(":"))
            value = datetime(now.year, number, int(day), hour, minute, tzinfo=timezone.utc)
            if value > now + timedelta(days=1):
                value = value.replace(year=now.year - 1)
            return value
        return datetime(int(when), number, int(day), tzinfo=timezone.utc)
    except ValueError:  # Feb 30, 25:61, Feb 29 moved into a common year
        return None


def _parse_unix_list_details(
    lines: list[str], now: datetime | None = None
) -> list[_ListEntry] | None:
    """Every entry of a Unix-style LIST with its mode, owner, size and date.

    None when a line is neither a ``total`` line nor Unix-style (a DOS
    or other listing that cannot say what is a symbolic link).
    """
    now = now or datetime.now(timezone.utc)
    entries: list[_ListEntry] = []
    for line in lines:
        line = line.rstrip("\r")
        if not line.strip() or line.startswith("total "):
            continue
        m = _UNIX_LIST_LINE.match(line)
        if m is None:
            return None
        entries.append(
            _ListEntry(
                kind=m.group("type"),
                mode=_list_mode(m.group("mode")),
                owner=m.group("owner"),
                group=m.group("group") or "",
                size=int(m.group("size")),
                modified=_list_date(m.group("month"), m.group("day"), m.group("when"), now),
                rest=m.group("rest"),
            )
        )
    return entries


def _parse_unix_list(lines: list[str]) -> list[tuple[str, str]] | None:
    """``(type char, name[ -> target])`` per entry of a Unix-style LIST.

    None when a line is neither a ``total`` line nor Unix-style (a DOS
    or other listing that cannot say what is a symbolic link).
    """
    details = _parse_unix_list_details(lines)
    return None if details is None else [(e.kind, e.rest) for e in details]


def _entry_detail(details: list[_ListEntry] | None, name: str) -> _ListEntry | None:
    """The LIST entry of ``name``, or None when it is missing or ambiguous."""
    if details is None:
        return None
    found = [
        e
        for e in details
        if (e.rest.startswith(name + " -> ") if e.kind == "l" else e.rest == name)
    ]
    return found[0] if len(found) == 1 else None


def _unix_entry(
    entries: list[_ListEntry] | list[tuple[str, str]] | None, name: str
) -> tuple[str, str] | None:
    """``(type char, link target)`` of ``name`` in a parsed LIST, or None.

    None also when the listing is missing or names the entry ambiguously
    (a name that itself contains " -> ").
    """
    if entries is None:
        return None
    found: set[tuple[str, str]] = set()
    for kind, rest in ((e.kind, e.rest) if isinstance(e, _ListEntry) else e for e in entries):
        if kind == "l":
            if rest.startswith(name + " -> "):
                found.add(("l", rest[len(name) + 4 :]))
        elif rest == name:
            found.add((kind, ""))
    return found.pop() if len(found) == 1 else None


def _is_not_found_reply(exc: BaseException) -> bool:
    """True for 550, the reply FTP gives for a path that is not there
    ("file unavailable"; RFC 959). Every other 5xx - 530 not logged in,
    500 / 502 not understood, 534 policy - says nothing about the path."""
    return str(exc)[:3] == "550"


def _ftp_errors_as_oserror(fn):
    """Re-raise ftplib protocol errors from ``fn`` as ``OSError``."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except _FTP_PROTOCOL_ERRORS as exc:
            detail = str(exc) or "connection closed by server"
            raise OSError(f"FTP {fn.__name__}: {detail}") from exc
        except UnicodeEncodeError as exc:
            # ftplib encodes each command in the session encoding (latin-1
            # when the server refused OPTS UTF8): a name it cannot carry is
            # a failed operation, not a crash.
            raise OSError(
                f"FTP {fn.__name__}: name cannot be encoded as {exc.encoding} "
                f"for this server: {exc.object[exc.start : exc.end]!r}"
            ) from exc

    return wrapper


def _quit_quietly(ftp) -> None:
    """QUIT a control connection; close it when QUIT fails."""
    try:
        ftp.quit()
    except Exception:  # noqa: BLE001 - a dead connection is closed anyway
        _close_quietly(ftp)


def _close_quietly(ftp) -> None:
    """Close a control connection without a QUIT round trip."""
    try:
        ftp.close()
    except Exception:  # noqa: BLE001 - nothing left to report it to
        pass


class _SpooledWriter:
    """Write to a temp file, then upload on close."""

    def __init__(self, ftp: FTP, remote_path: str, append: bool = False, lock=None):
        self._ftp = ftp
        self._remote_path = remote_path
        self._append = append
        # The session's I/O lock: the upload runs on the shared handle.
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

    @_ftp_errors_as_oserror
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._buf.seek(0)
            cmd = "APPE" if self._append else "STOR"
            with self._lock:
                self._ftp.storbinary(f"{cmd} {self._remote_path}", self._buf)
        finally:
            self._buf.close()

    def discard(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._buf.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


class _StreamedDownload(io.RawIOBase):
    """``open_read``'s handle when the session could open a second control
    connection for it: the RETR runs while the caller reads.

    The whole download used to run inside ``open_read`` on the shared
    connection, under the session lock - Cancel and the progress bar of a
    transfer only ran once it was over, and every other call on the
    session waited for it. Here a transfer reads block by block, checking
    cancel and reporting progress in between, while the shared connection
    stays free.

    Received bytes go to a spool, so seek() back works as on the spool of
    old; a read past them receives up to there. ``read(n)`` returns ``n``
    bytes unless the file ends first (FUSE passes it to the kernel, which
    takes a short read for the end of the file). Not bound to a thread:
    FUSE opens, reads and releases on different ones.
    """

    _BLOCK = 64 * 1024

    def __init__(self, ftp: FTP, conn, path: str, done) -> None:
        super().__init__()
        self._ftp = ftp
        self._conn = conn
        self._path = path
        # Called with the control connection after a complete transfer.
        self._done = done
        self._spool = new_read_spool()
        self._received = 0
        self._pos = 0
        self._failed: OSError | None = None
        self._lock = threading.Lock()

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, pos: int, whence: int = 0) -> int:
        with self._lock:
            self._checked()
            if whence == io.SEEK_SET:
                target = pos
            elif whence == io.SEEK_CUR:
                target = self._pos + pos
            elif whence == io.SEEK_END:
                self._receive(None)
                target = self._received + pos
            else:
                raise ValueError(f"invalid whence ({whence})")
            if target < 0:
                raise ValueError(f"negative seek position {target}")
            self._pos = target
            return target

    def readinto(self, buffer) -> int:
        with self._lock:
            self._checked()
            view = memoryview(buffer).cast("B")
            self._receive(self._pos + len(view))
            if self._pos >= self._received:
                return 0
            self._spool.seek(self._pos)
            data = self._spool.read(min(len(view), self._received - self._pos))
            view[: len(data)] = data
            self._pos += len(data)
            return len(data)

    def readall(self) -> bytes:
        chunks = []
        while chunk := self.read(READ_CHUNK):
            chunks.append(chunk)
        return b"".join(chunks)

    def _checked(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if self._failed is not None:
            raise OSError(f"FTP read {self._path}: download failed: {self._failed}")

    def _receive(self, upto: int | None) -> None:
        """Receive until ``upto`` bytes are in the spool (None: all)."""
        while self._conn is not None and (upto is None or self._received < upto):
            try:
                data = self._conn.recv(self._BLOCK)
                if not data:
                    self._finish()
                    return
            except _FTP_PROTOCOL_ERRORS as exc:
                detail = str(exc) or "connection closed by server"
                self._fail(OSError(f"FTP read {self._path}: {detail}"))
            except OSError as exc:
                self._fail(exc)
            self._spool.seek(self._received)
            self._spool.write(data)
            self._received += len(data)

    def _finish(self) -> None:
        """The data connection ended: the server's reply says whether the
        file did. A 4xx/5xx there is a failed download, not a short file."""
        conn, self._conn = self._conn, None
        unwrap = getattr(conn, "unwrap", None)  # TLS: close as retrbinary does
        try:
            if unwrap is not None:
                unwrap()
        finally:
            conn.close()
        self._ftp.voidresp()
        ftp, self._ftp = self._ftp, None
        self._done(ftp)

    def _fail(self, exc: OSError) -> NoReturn:
        self._failed = exc
        self._drop()
        raise exc

    def _drop(self) -> None:
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
        ftp, self._ftp = self._ftp, None
        if ftp is not None:
            # Mid-transfer or failed: its control channel is not in a
            # state to send the next command on.
            _close_quietly(ftp)

    def close(self) -> None:
        if self.closed:
            return
        with self._lock:
            try:
                self._drop()
            finally:
                self._spool.close()
                super().close()


class _FtpProxyMixin:
    """Mixin for ftplib.FTP / FTP_TLS that routes BOTH the control
    channel and PASV data channels through a SOCKS / HTTP proxy.

    Why both: many production FTP servers (vsftpd, pure-ftpd) enable
    anti-hijack-check and reject a data connection whose source IP
    differs from the control channel's source. With the control
    channel coming from the proxy IP and the data channel coming
    direct from the client, the server refuses → the client hangs
    waiting for the ``150 Opening data connection`` reply that
    never arrives. Routing the data channel through the proxy too
    keeps the source IPs identical.

    Use the helper :func:`_ftp_connect_via_proxy` to bring an
    instance up; ``ntransfercmd`` is replaced below so each PASV
    transfer also dials through the proxy.
    """

    _axross_proxy: object = None
    _axross_timeout: float = 15.0

    def ntransfercmd(self, cmd, rest=None):
        """Override: open the data socket through the proxy, then
        delegate to the standard control-channel sequence.

        ftplib's stock implementation is structurally:
            host, port = self.makepasv()
            conn = socket.create_connection((host, port), self.timeout, ...)
            resp = self.sendcmd(cmd)
            (if TLS/PROT P) conn = self.context.wrap_socket(...)
            ...
        We rebuild that here, swapping the data-socket constructor.

        ftplib's ``makepasv`` defends against FTP-bounce by replacing
        the PASV-announced host with ``self.sock.getpeername()[0]``
        unless ``trust_server_pasv_ipv4_address`` is set. Under a
        proxy, ``getpeername()`` returns the *proxy's* IP — using
        that would route the data connection to the proxy host
        instead of the FTP server. Force-trust the announced host
        for the proxy path; the proxy + the SSRF guard already
        enforce a stricter invariant than the bounce check would.
        """
        from core.proxy import create_proxy_socket

        size = None
        if self.passiveserver:
            self.trust_server_pasv_ipv4_address = True
            host, port = self.makepasv()
            # Belt + braces: when the announced host happens to be
            # the proxy's own IP (mis-configured server), override it
            # with the original ftp.host the user typed.
            if host == self.sock.getpeername()[0]:
                host = self.host
            conn = create_proxy_socket(
                self._axross_proxy,
                host,
                int(port),
                timeout=float(self._axross_timeout),
            )
            try:
                if rest is not None:
                    self.sendcmd(f"REST {rest}")
                resp = self.sendcmd(cmd)
                if resp[0] == "2":
                    resp = self.getresp()
                if resp[0] != "1":
                    from ftplib import error_reply  # nosec B402

                    raise error_reply(resp)
                # Match ftplib.FTP_TLS.ntransfercmd(): after the server
                # accepts the transfer (1xx), protect the PASV data socket
                # when PROT P is active. Without this, FTPS via proxy opens
                # a clear data channel while the server waits for TLS.
                if getattr(self, "_prot_p", False) and hasattr(self, "context"):
                    conn = self.context.wrap_socket(  # type: ignore[attr-defined]
                        conn,
                        server_hostname=self.host,
                        session=_control_session(self),
                    )
            except Exception:
                conn.close()
                raise
        else:
            # Active mode is incompatible with outbound-only proxies
            # (server would dial back to the client). The session
            # ctor flips passive_server=True when a proxy is set, so
            # we should never land here — but be loud if we do.
            raise OSError(
                "FTP active mode is incompatible with a proxy. Use passive=True (the default).",
            )

        # Parse 'size=...' if present in the 1xx reply (used by REST).
        if resp[:3] == "150":
            try:
                size = parse150(resp)  # type: ignore[name-defined]
            except Exception:
                size = None
        return conn, size


class _LenientListingMixin:
    """``retrlines`` that decodes the data channel with ``errors="replace"``.

    ftplib decodes LIST / NLST / MLSD data strictly in ``self.encoding``
    (ftplib.FTP.retrlines: ``conn.makefile('r', encoding=self.encoding)``),
    so one name in another encoding - a server that accepted OPTS UTF8 ON
    but lists latin-1 names - raised UnicodeDecodeError out of list_dir,
    which no caller catches, and left the reply of the aborted transfer
    unread on the control channel. The control channel is already read
    with ``errors="replace"`` (see FtpSession._connect); listings now
    follow the same rule. Otherwise this is ftplib's own retrlines.
    """

    def retrlines(self, cmd, callback=None):
        import ssl

        if callback is None:
            callback = print
        self.sendcmd("TYPE A")
        with (
            self.transfercmd(cmd) as conn,
            conn.makefile("r", encoding=self.encoding, errors="replace") as fp,
        ):
            while True:
                line = fp.readline(self.maxline + 1)
                if len(line) > self.maxline:
                    raise _FtpLibError(f"got more than {self.maxline} bytes")
                if not line:
                    break
                if line[-2:] == "\r\n":
                    line = line[:-2]
                elif line[-1:] == "\n":
                    line = line[:-1]
                callback(line)
            if isinstance(conn, ssl.SSLSocket):
                conn.unwrap()
        return self.voidresp()


class _FTP(_LenientListingMixin, FTP):
    """Plain FTP with lenient listing decoding."""


def _control_session(ftp) -> object | None:
    """The control connection's TLS session, for the data socket to resume.

    Servers that require session reuse (vsftpd's require_ssl_reuse=YES by
    default, test.rebex.net) refuse a data connection that negotiates a
    session of its own: "425 ... TLS session resumption required"."""
    return getattr(getattr(ftp, "sock", None), "session", None)


class _FTP_TLS(_LenientListingMixin, FTP_TLS):
    """FTPS with lenient listing decoding and TLS session reuse on data."""

    def ntransfercmd(self, cmd, rest=None):
        # ftplib's FTP_TLS.ntransfercmd wraps without session=.
        conn, size = FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(
                conn, server_hostname=self.host, session=_control_session(self)
            )
        return conn, size


class _ProxyFTP(_FtpProxyMixin, _LenientListingMixin, FTP):
    """FTP subclass with proxy-aware control + data channels."""


class _ProxyFTP_TLS(_FtpProxyMixin, _LenientListingMixin, FTP_TLS):
    """FTPS subclass with proxy-aware control + data channels."""


# Imported lazily inside the override above; expose for parse150 hook.
try:
    from ftplib import parse150  # type: ignore[attr-defined]  # nosec B402
except ImportError:  # pragma: no cover — Python<3.x
    parse150 = None  # type: ignore[assignment]


def _ftp_connect_via_proxy(ftp, host: str, port: int, proxy_config, timeout: float):
    """Connect a proxy-aware ``ftplib.FTP`` (or ``FTP_TLS``) through a
    SOCKS / HTTP proxy.

    ``ftplib.FTP.connect`` opens its own TCP socket via
    ``socket.create_connection``. We bypass it: pre-build a
    socksified socket via :func:`core.proxy.create_proxy_socket`,
    assign it onto ``ftp.sock``, and run the server-greeting read
    that ``ftp.connect`` would have done.

    The caller is expected to have constructed *ftp* as a
    :class:`_ProxyFTP` / :class:`_ProxyFTP_TLS` instance so subsequent
    PASV data channels also tunnel through the proxy.
    """
    from core.proxy import create_proxy_socket

    sock = create_proxy_socket(
        proxy_config,
        host,
        int(port),
        timeout=float(timeout),
    )
    ftp.host = host
    ftp.port = int(port)
    ftp.sock = sock
    ftp.af = sock.family
    # Propagate the timeout onto ``ftp.timeout`` too. Without this,
    # ftplib's data-channel sockets (PASV ``ntransfercmd``) inherit
    # ``None`` and block indefinitely if the data port is unreachable.
    ftp.timeout = float(timeout)
    # Stash the proxy + timeout where the mixin can find them.
    ftp._axross_proxy = proxy_config  # type: ignore[attr-defined]
    ftp._axross_timeout = float(timeout)  # type: ignore[attr-defined]
    ftp.file = sock.makefile("r", encoding=ftp.encoding)
    # Read the 220 server greeting — same shape as ftplib.FTP.connect.
    ftp.welcome = ftp.getresp()
    return ftp.welcome


class FtpSession(SessionLifecycle):
    """FTP/FTPS backend implementing the FileBackend protocol.

    Uses ftplib (stdlib). Supports both plain FTP and explicit FTPS.
    """

    #: False for a session built without ``__init__``: no login parameters.
    _separate_downloads = False

    def __init__(
        self,
        host: str,
        port: int = 21,
        username: str = "",
        password: str = "",
        tls: bool = False,
        passive: bool = True,
        verify_tls: bool = True,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        """Create an FTP / FTPS session.

        ``verify_tls`` (default ``True``): when ``tls=True``, require
        the server's certificate to chain to a trusted CA AND have a
        subject that matches the connected host. Set to ``False`` to
        accept self-signed / hostname-mismatched certs — useful for
        internal lab servers, never for production.

        Background: Python's ``ftplib.FTP_TLS()`` with no ``context=``
        argument uses ``ssl._create_stdlib_context()`` which defaults
        to ``CERT_NONE`` + ``check_hostname=False``, i.e. NO
        verification at all. That is indistinguishable from a MITM
        attacker. We default to a verifying context and only fall back
        when the caller explicitly opts in.
        """
        self._host = host
        self._port = port
        self._username = username or "anonymous"
        self._password = password
        self._tls = tls
        self._passive = passive
        self._verify_tls = verify_tls
        from core.proxy import ProxyConfig

        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host,
            port=int(proxy_port or 0),
            username=proxy_username,
            password=proxy_password,
        )
        self._ftp: FTP | None = None
        self._has_mlsd = False
        # Downloads run on a control connection of their own (see
        # _StreamedDownload); the last finished one is kept for the next.
        self._separate_downloads = True
        self._spare_ftp: FTP | None = None
        self._spare_lock = threading.Lock()

        if self._proxy.enabled and not self._passive:
            log.warning(
                "FTP proxy + active mode is not supported (the server "
                "would dial back to the client directly). Forcing PASV.",
            )
            self._passive = True

        self._connect()

    def _connect(self) -> None:
        """Establish FTP connection."""
        ftp = self._login()

        # Probe MLSD support. _ProxyFTP/_ProxyFTP_TLS override
        # ntransfercmd(), so PASV data channels used by MLSD are
        # proxied the same way RETR/STOR/NLST data channels are.
        try:
            list(ftp.mlsd("/", facts=["type"]))
            self._has_mlsd = True
        except Exception:
            self._has_mlsd = False

        self._ftp = ftp
        log.info(
            "FTP%s connected: %s@%s:%d (MLSD=%s)",
            "S" if self._tls else "",
            self._username,
            self._host,
            self._port,
            self._has_mlsd,
        )

    def _login(self, *, announce: bool = True) -> FTP:
        """A new control connection, logged in and set up. ``announce``
        False keeps the TLS opt-out warning of a download's own
        connection at debug level: the session's login already warned."""
        if self._tls:
            import ssl

            if self._verify_tls:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True
                context.load_default_certs()
            else:
                # Explicit opt-out: used for self-signed / lab servers.
                (log.warning if announce else log.debug)(
                    "FTPS connection to %s:%d with TLS verification DISABLED "
                    "— subject to MITM attacks",
                    self._host,
                    self._port,
                )
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            ftp = (
                _ProxyFTP_TLS(context=context) if self._proxy.enabled else _FTP_TLS(context=context)
            )
        else:
            ftp = _ProxyFTP() if self._proxy.enabled else _FTP()  # nosec B321

        try:
            if self._proxy.enabled:
                _ftp_connect_via_proxy(
                    ftp,
                    self._host,
                    self._port,
                    self._proxy,
                    timeout=15.0,
                )
            else:
                ftp.connect(self._host, self._port, timeout=15)
            ftp.login(self._username, self._password)

            if self._tls and isinstance(ftp, FTP_TLS):
                ftp.prot_p()  # Protect data channel

            ftp.set_pasv(self._passive)

            # Try UTF-8
            try:
                ftp.sendcmd("OPTS UTF8 ON")
                ftp.encoding = "utf-8"
            except error_perm:
                ftp.encoding = "latin-1"

            # Harden the response reader against encoding mismatches: even
            # when the server accepts OPTS UTF8 ON it may still echo paths
            # back in latin-1 (vsftpd/pure-ftpd both do this for non-ASCII
            # names on certain builds). A raw UnicodeDecodeError inside
            # ftplib.getline() aborts the control session; switching the
            # decoder to errors='replace' keeps the channel alive while
            # logging what happened.
            try:
                raw = ftp.sock.makefile(
                    "r",
                    encoding=ftp.encoding,
                    errors="replace",
                )
                ftp.file = raw
            except Exception as exc:
                log.debug("Could not harden FTP response decoder: %s", exc)
        except BaseException:
            # A refused login must not leave its socket open.
            _close_quietly(ftp)
            raise
        return ftp

    @property
    @liveness_check
    def connected(self) -> bool:
        if self._ftp is None:
            return False
        try:
            self._ftp.voidcmd("NOOP")
            return True
        except Exception:
            return False

    @serialized
    def disconnect(self) -> None:
        spare = self._take_spare()
        if spare is not None:
            _quit_quietly(spare)
        if self._ftp:
            log.info("FTP disconnecting from %s@%s", self._username, self._host)
            try:
                self._ftp.quit()
            except Exception:
                try:
                    self._ftp.close()
                except Exception:
                    pass
            self._ftp = None

    def close(self) -> None:
        self.disconnect()

    @property
    def name(self) -> str:
        proto = "FTPS" if self._tls else "FTP"
        return f"{self._username}@{self._host} ({proto})"

    def _ensure_connected(self) -> FTP:
        if self._ftp is not None and self._recently_verified():
            return self._ftp
        if self._ftp is None or not self.connected:
            self._connect()
        assert self._ftp is not None
        self._verified_at = time.monotonic()
        return self._ftp

    def _recently_verified(self) -> bool:
        """True when the last NOOP/login is recent and nothing is waiting
        on the control socket. Anything unexpected answers False, so the
        NOOP check runs as it always did."""
        verified_at = getattr(self, "_verified_at", None)
        if verified_at is None or time.monotonic() - verified_at > LIVENESS_WINDOW:
            return False
        sock = getattr(self._ftp, "sock", None)
        if not isinstance(sock, socket.socket):
            return False
        try:
            if getattr(sock, "pending", lambda: 0)():  # TLS bytes already buffered
                return False
            readable, _, _ = select.select([sock], [], [], 0)
        except (OSError, ValueError):
            return False
        return not readable

    @_ftp_errors_as_oserror
    @serialized
    def list_dir(self, path: str) -> list[FileItem]:
        ftp = self._ensure_connected()
        items: list[FileItem] = []

        if self._has_mlsd:
            try:
                for name, facts in ftp.mlsd(path, facts=["type", "size", "modify", "perm"]):
                    if name in (".", ".."):
                        continue
                    # RFC 3659 7.5.1: cdir is the listed directory itself
                    # and pdir a parent; their pathname may be "tmp" or
                    # "/tmp" rather than "." / "..", so the type decides.
                    if facts.get("type", "").lower() in ("cdir", "pdir"):
                        continue
                    items.append(self._mlsd_to_item(name, facts))
                return items
            except error_perm:
                pass

        # Fallback: NLST + individual stat
        try:
            names = ftp.nlst(path)
        except error_perm as e:
            raise OSError(f"Cannot list {path}: {e}") from e
        # vsftpd answers NLST of a missing folder with an empty listing,
        # not 550: an empty answer counts only when CWD reaches the folder.
        if not names and not self._cwd_reaches(ftp, path):
            raise FileNotFoundError(errno.ENOENT, "No such directory", path)

        # A Unix-style LIST line carries type, mode, owner, size and date,
        # so an entry it names needs no probe of its own; only a regular
        # file asks MDTM for its exact UTC time. Without a readable LIST
        # every entry is probed with stat(), whose CWD follows a symbolic
        # link - LIST is also the only source that says which are links.
        details = self._unix_listing(ftp, path) if names else None
        for full_path in names:
            entry_name = posixpath.basename(full_path) or full_path
            if entry_name in (".", ".."):
                continue
            stat_path = (
                posixpath.join(path, entry_name) if not full_path.startswith("/") else full_path
            )
            detail = _entry_detail(details, entry_name)
            if detail is not None and detail.kind in ("-", "d"):
                modified = self._mdtm(ftp, stat_path) if detail.kind == "-" else None
                items.append(
                    FileItem(
                        name=entry_name,
                        size=detail.size,
                        modified=modified or detail.modified or datetime.fromtimestamp(0),
                        permissions=detail.mode,
                        is_dir=detail.kind == "d",
                        owner=detail.owner,
                        group=detail.group,
                    )
                )
                continue
            is_link = detail is not None and detail.kind == "l"
            extra = (
                {"permissions": detail.mode, "owner": detail.owner, "group": detail.group}
                if detail is not None
                else {}
            )
            try:
                item = self.stat(stat_path)
                items.append(
                    FileItem(
                        name=entry_name,
                        size=item.size,
                        modified=item.modified,
                        is_dir=item.is_dir and not is_link,
                        is_link=is_link,
                        link_target=detail.rest[len(entry_name) + 4 :] if is_link else "",
                        **extra,
                    )
                )
            except OSError:
                items.append(FileItem(name=entry_name, is_link=is_link, **extra))

        return items

    def _unix_listing(self, ftp: FTP, path: str) -> list[_ListEntry] | None:
        """Parsed Unix-style ``LIST`` of directory ``path``, or None when
        the server refuses it or answers in a format without link types.

        ``LIST -a`` first: pure-ftpd (measured 2026-10-21) leaves dot
        entries out of a plain LIST, and NLST still names them, so each
        one fell back to the per-entry probe and lost mode, owner and
        group. A server that refuses the option, or takes ``-a`` for a
        path and answers with nothing usable, gets the plain LIST."""
        details: list[_ListEntry] | None = None
        for command in (f"LIST -a {path}", f"LIST {path}"):
            lines: list[str] = []
            try:
                ftp.retrlines(command, lines.append)
            except error_perm:
                continue
            details = _parse_unix_list_details(lines)
            if details:
                return details
        return details

    @staticmethod
    def _mdtm(ftp: FTP, path: str) -> datetime | None:
        """``MDTM`` of ``path`` as an aware UTC datetime, None when refused."""
        try:
            ts = ftp.sendcmd(f"MDTM {path}").split(None, 1)[-1]
            # RFC 3659 2.3 / 3: MDTM times are UTC.
            return datetime.strptime(ts[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except Exception:  # noqa: BLE001 - a refused or malformed reply is "no time"
            return None

    def _entry_kind(self, ftp: FTP, path: str) -> str | None:
        """``"link"``, ``"dir"`` or None (unknown) for an entry that CWD
        accepts as a directory.

        CWD follows symbolic links, and some MLSD servers report a link
        with its target's type, so the parent's LIST decides. When LIST
        is not Unix-style, an MLSD server's own type is trusted; without
        MLSD the type stays unknown.
        """
        norm = posixpath.normpath(path)
        parent, leaf = posixpath.split(norm)
        if not leaf:
            return "dir"  # the root has no parent that could link to it
        listing = self._unix_listing(ftp, parent or ".")
        entry = _unix_entry(listing, leaf)
        if entry is not None:
            return {"l": "link", "d": "dir"}.get(entry[0])
        if listing is None and self._has_mlsd:
            try:
                facts = self._mlst_reply_facts(ftp.sendcmd(f"MLST {path}"))
            except error_perm:
                return None
            if facts is not None:
                item = self._mlsd_to_item(leaf, facts)
                if item.is_link:
                    return "link"
                if item.is_dir:
                    return "dir"
        return None

    @_ftp_errors_as_oserror
    @serialized
    def stat(self, path: str) -> FileItem:
        ftp = self._ensure_connected()
        name = posixpath.basename(path) or path
        size = 0
        modified = datetime.fromtimestamp(0)
        is_dir = False

        # Try MLST first
        if self._has_mlsd:
            try:
                resp = ftp.sendcmd(f"MLST {path}")
                facts = self._mlst_reply_facts(resp)
                if facts is not None:
                    return self._mlsd_to_item(name, facts)
            except error_perm:
                pass

        # Fallback: SIZE + MDTM + CWD probe
        size_known = False
        try:
            size = ftp.size(path) or 0
            size_known = True
        except UnicodeEncodeError:
            raise  # a name the session encoding cannot carry: not "found"
        except ValueError:
            size_known = True  # a 213 reply ftplib cannot parse: the file is there
        except Exception:
            pass

        mdtm = self._mdtm(ftp, path)
        modified = mdtm or modified
        is_dir = self._cwd_reaches(ftp, path)

        # Every probe refused: the path is missing - unless the parent's
        # listing names it (a server that allows SIZE in binary mode only
        # and has no MDTM refuses both for an existing file).
        if not (size_known or mdtm or is_dir) and not self._parent_lists(ftp, path):
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", path)

        return FileItem(name=name, size=size, modified=modified, is_dir=is_dir)


    @staticmethod
    def _parent_lists(ftp: FTP, path: str) -> bool:
        """True when the NLST of *path*'s parent names it."""
        trimmed = path.rstrip("/")
        name = posixpath.basename(trimmed)
        if not name:
            return True  # the root
        try:
            names = ftp.nlst(posixpath.dirname(trimmed) or "/")
        except error_perm as e:
            if _is_not_found_reply(e):
                return False  # no parent folder
            raise
        return any(posixpath.basename(n.rstrip("/")) == name for n in names)

    @staticmethod
    def _cwd_reaches(ftp: FTP, path: str) -> bool:
        """True when CWD into *path* succeeds (the working folder is
        restored), False for 550. Any other refusal is raised: it says
        nothing about the path."""
        try:
            old_cwd = ftp.pwd()
            ftp.cwd(path)
            ftp.cwd(old_cwd)
            return True
        except error_perm as e:
            if _is_not_found_reply(e):
                return False
            raise
        except UnicodeDecodeError as e:
            # A reply in another encoding than the negotiated one; the
            # control channel normally reads with errors="replace"
            # (_connect), so this is a reader that could not be
            # hardened. Its code is unknown: no answer, not "no".
            raise OSError(f"FTP CWD {path}: reply could not be decoded: {e}") from e

    @_ftp_errors_as_oserror
    @serialized
    def is_dir(self, path: str) -> bool:
        """False only for 550; any other refusal is an OSError - remove()
        and the transfer manager pick folder or file from this answer."""
        return self._cwd_reaches(self._ensure_connected(), path)

    @_ftp_errors_as_oserror
    @serialized
    def exists(self, path: str) -> bool:
        """False only when SIZE is refused, CWD answers 550 and the parent
        listing lacks the name; any other refusal is an OSError -
        server_side_copy(overwrite=False) takes False as its go-ahead to
        write."""
        ftp = self._ensure_connected()
        try:
            ftp.size(path)
            return True
        except error_perm:
            pass  # SIZE is optional and refused for a folder: CWD decides
        except UnicodeEncodeError:
            raise  # UnicodeEncodeError is a ValueError, but not a 213 reply
        except ValueError:
            # ftplib's size() int()s the reply text: "213 abc" is a success
            # reply (the file is there) with a size it cannot parse.
            return True
        if self._cwd_reaches(ftp, path):
            return True
        # CWD answers 550 for a file too, and a refused SIZE may be the
        # same 550 (vsftpd in ASCII mode): the parent listing decides.
        return self._parent_lists(ftp, path)

    @_ftp_errors_as_oserror
    @serialized
    def mkdir(self, path: str) -> None:
        ftp = self._ensure_connected()
        try:
            ftp.mkd(path)
        except error_perm as e:
            raise OSError(f"Cannot create directory {path}: {e}") from e

    @_ftp_errors_as_oserror
    @serialized
    def remove(self, path: str, recursive: bool = False) -> None:
        ftp = self._ensure_connected()
        if self.is_dir(path):
            # CWD also accepts a symbolic link to a directory: such an
            # entry is unlinked, never emptied.
            kind = self._entry_kind(ftp, path)
            if kind == "link":
                try:
                    ftp.delete(path)
                except error_perm as e:
                    raise OSError(f"Cannot delete link {path}: {e}") from e
            elif recursive:
                if kind != "dir":
                    raise OSError(
                        f"Refusing to recursively delete {path}: the server does not "
                        "say whether it is a directory or a symbolic link"
                    )
                self._rmdir_recursive(path)
            else:
                try:
                    ftp.rmd(path)
                except error_perm as e:
                    raise OSError(f"Cannot remove directory {path}: {e}") from e
        else:
            try:
                ftp.delete(path)
            except error_perm as e:
                raise OSError(f"Cannot delete {path}: {e}") from e

    _MAX_TREE_DEPTH = MAX_RECURSIVE_DELETE_DEPTH

    def _rmdir_recursive(self, path: str, depth: int = 0) -> None:
        check_tree_depth(path, depth, self._MAX_TREE_DEPTH)
        ftp = self._ensure_connected()
        # A child is descended into only when LIST confirms a directory
        # (or, when LIST cannot tell, an MLSD server says so); a link is
        # unlinked. Every child is classified before anything is deleted.
        listing = self._unix_listing(ftp, path)
        children = []
        for item in self.list_dir(path):
            try:
                child = safe_join(self, path, item.name)
            except ValueError as exc:
                raise OSError(
                    f"Cannot recursively remove {path}: unsafe child name {item.name!r}: {exc}"
                ) from exc
            entry = _unix_entry(listing, item.name)
            if item.is_link or (entry is not None and entry[0] == "l"):
                descend = False
            elif not item.is_dir:
                descend = False
            elif entry is not None and entry[0] == "d":
                descend = True
            elif entry is None and listing is None and self._has_mlsd:
                descend = True
            else:
                raise OSError(
                    f"Refusing to recursively delete {path}: the server does not say "
                    f"whether {item.name!r} is a directory or a symbolic link"
                )
            children.append((descend, child))
        for descend, child in children:
            if descend:
                self._rmdir_recursive(child, depth + 1)
            else:
                ftp.delete(child)
        ftp.rmd(path)

    @_ftp_errors_as_oserror
    @serialized
    def rename(self, src: str, dst: str) -> None:
        ftp = self._ensure_connected()
        try:
            ftp.rename(src, dst)
        except error_perm as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    @_ftp_errors_as_oserror
    def open_read(self, path: str) -> IO[bytes]:
        ftp = self._download_connection()
        if ftp is None:
            return self._open_read_shared(path)
        try:
            ftp.voidcmd("TYPE I")
            conn = ftp.transfercmd(f"RETR {path}")
        except error_perm as e:
            # "550 No such file": answered, the connection is fine.
            self._keep_spare(ftp)
            raise OSError(f"Cannot read {path}: {e}") from e
        except BaseException:
            _close_quietly(ftp)
            raise
        return _StreamedDownload(ftp, conn, path, self._keep_spare)

    def _download_connection(self) -> FTP | None:
        """A logged-in control connection of its own for one download, or
        None to download on the shared one: a session built without its
        ``__init__`` has nothing to log in with, and a server that refused
        a second connection is not asked again."""
        if not self._separate_downloads:
            return None
        ftp = self._take_spare()
        if ftp is not None:
            try:
                ftp.voidcmd("NOOP")
                return ftp
            except (*_FTP_PROTOCOL_ERRORS, OSError):
                _close_quietly(ftp)
        try:
            return self._login(announce=False)
        except _FtpLibError as exc:
            # "421 Too many connections", "530 ... maximum number of
            # clients": the server allows this user one connection.
            log.info(
                "FTP %s refused a second connection (%s); downloads use the session's",
                self._host,
                exc,
            )
            self._separate_downloads = False
        except (OSError, EOFError) as exc:
            log.debug("FTP %s: no second connection for a download: %s", self._host, exc)
        return None

    def _take_spare(self) -> FTP | None:
        lock = self.__dict__.get("_spare_lock")
        if lock is None:
            return None
        with lock:
            ftp, self._spare_ftp = self._spare_ftp, None
        return ftp

    def _keep_spare(self, ftp: FTP) -> None:
        """Keep a finished download's connection for the next download,
        so a run of them logs in once; one spare is enough."""
        with self._spare_lock:
            if self._spare_ftp is None and self._ftp is not None:
                self._spare_ftp, ftp = ftp, None
        if ftp is not None:
            _quit_quietly(ftp)

    @serialized
    def _open_read_shared(self, path: str) -> IO[bytes]:
        """The whole download on the shared connection, under the session
        lock: for a server that allows one connection per user."""
        ftp = self._ensure_connected()
        # Spooled, not a BytesIO: the whole file used to sit in RAM.
        buf = new_read_spool()
        try:
            ftp.retrbinary(f"RETR {path}", buf.write)
        except error_perm as e:
            buf.close()
            raise OSError(f"Cannot read {path}: {e}") from e
        except BaseException:
            buf.close()
            raise
        buf.seek(0)
        return buf

    @_ftp_errors_as_oserror
    @serialized
    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        ftp = self._ensure_connected()
        return _SpooledWriter(ftp, path, append=append, lock=io_lock(self))

    def normalize(self, path: str) -> str:
        return posixpath.normpath(path) or "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path) or "/"

    @_ftp_errors_as_oserror
    @serialized
    def home(self) -> str:
        ftp = self._ensure_connected()
        return ftp.pwd()

    @_ftp_errors_as_oserror
    @serialized
    def chmod(self, path: str, mode: int) -> None:
        ftp = self._ensure_connected()
        octal = format(mode, "o")
        try:
            ftp.sendcmd(f"SITE CHMOD {octal} {path}")
        except error_perm as e:
            log.warning("SITE CHMOD failed for %s (server may not support it): %s", path, e)
            raise OSError(f"chmod not supported by this FTP server: {e}") from e
        except Exception as e:
            log.warning("Unexpected error during SITE CHMOD for %s: %s", path, e)
            raise OSError(f"chmod failed: {e}") from e

    def readlink(self, path: str) -> str:
        raise OSError("FTP does not support symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """FTP has no native server-side copy. Raises so server_ops
        falls back to stream copy."""
        raise OSError("FTP has no server-side copy primitive")

    # ------------------------------------------------------------------
    # FTP-specific verbs (round 2 of API_GAPS)
    # ------------------------------------------------------------------

    @_ftp_errors_as_oserror
    @serialized
    def features(self) -> list[str]:
        """``FEAT`` — list every server-advertised feature
        (``MLSD``, ``UTF8``, ``HASH``, ``EPSV``, ``SIZE``, …). Returns
        each feature line stripped of leading whitespace."""
        ftp = self._ensure_connected()
        try:
            resp = ftp.sendcmd("FEAT")
        except error_perm as exc:
            raise OSError(f"FTP FEAT not supported: {exc}") from exc
        # Response shape:
        #   211-Features:
        #    UTF8
        #    MLST type*;size*;modify*;
        #    ...
        #   211 End
        out: list[str] = []
        # PATTERN-001: ftplib emits `\n`-joined responses; avoid splitlines().
        for line in split_lf_only_stream(resp):
            stripped = line.strip().rstrip("\r")
            # Skip the framing 211 line(s).
            if not stripped or stripped.startswith("211"):
                continue
            if stripped.startswith("Features:") or stripped.lower() == "end":
                continue
            out.append(stripped)
        return out

    @_ftp_errors_as_oserror
    @serialized
    def site(self, command: str) -> str:
        """Send a raw ``SITE <command>`` and return the textual
        response. ``SITE`` is the universal extension verb — most
        servers accept ``SITE CHMOD``, ``SITE UMASK``, ``SITE IDLE``,
        ``SITE HELP`` etc.

        Refuses CR/LF in ``command`` so a tainted argument can't smuggle
        a second wire command (FTP commands are CRLF-delimited).
        """
        if "\r" in command or "\n" in command:
            raise ValueError(
                "FTP site() command must not contain CR/LF (would smuggle a second wire command)"
            )
        ftp = self._ensure_connected()
        try:
            return ftp.sendcmd(f"SITE {command}")
        except error_perm as exc:
            raise OSError(f"FTP SITE {command!r}: {exc}") from exc

    @_ftp_errors_as_oserror
    @serialized
    def mlst(self, path: str) -> dict[str, str]:
        """``MLST <path>`` — RFC 3659 facts for one entry. Returns the
        facts as a dict (e.g. ``{"size": "4096", "type": "dir",
        "modify": "20260426170000"}``).

        Server may not support MLST (it's still optional in many
        deployments — ``vsftpd`` enables it, others don't); falls
        through to ``error_perm`` -> OSError.

        F38: refuse CR/LF in ``path`` (FTP wire-frame is CRLF-
        delimited; symmetry with ``site()``).
        """
        if "\r" in path or "\n" in path:
            raise ValueError(
                "FTP mlst() path must not contain CR/LF (would smuggle a second wire command). F38."
            )
        ftp = self._ensure_connected()
        try:
            resp = ftp.sendcmd(f"MLST {path}")
        except error_perm as exc:
            raise OSError(f"FTP MLST {path}: {exc}") from exc
        facts = self._mlst_reply_facts(resp)
        return facts if facts is not None else {}

    @_ftp_errors_as_oserror
    @serialized
    def cwd(self, path: str) -> None:
        """Raw ``CWD`` — change the server-side working directory.
        Useful when a script wants to run a sequence of relative-path
        operations; most callers should keep using absolute paths.

        F38: refuse CR/LF in ``path`` (FTP wire-frame is CRLF-delim;
        symmetry with ``site()`` / ``mlst()``).
        """
        if "\r" in path or "\n" in path:
            raise ValueError("FTP cwd() path must not contain CR/LF. F38.")
        ftp = self._ensure_connected()
        try:
            ftp.cwd(path)
        except error_perm as exc:
            raise OSError(f"FTP CWD {path}: {exc}") from exc

    @_ftp_errors_as_oserror
    @serialized
    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """FTP has no native checksum command. Some servers advertise
        ``HASH`` (RFC draft) or ``XMD5`` / ``XSHA256`` extensions; we
        try them on a best-effort basis and return "" otherwise.
        Callers should fall back to client-side streaming."""
        ftp = self._ensure_connected()
        cmd_map = {
            "sha256": ("HASH SHA-256", "XSHA256"),
            "sha1": ("HASH SHA-1", "XSHA1"),
            "md5": ("HASH MD5", "XMD5"),
        }
        for cmd_text in cmd_map.get(algorithm, ()):
            cmd, _, _ = cmd_text.partition(" ")
            try:
                resp = ftp.sendcmd(f"{cmd_text} {path}")
            except error_perm:
                continue
            except Exception:
                continue
            # Typical response: "213 0-12345 abc123deadbeef..."
            parts = resp.split()
            if parts:
                candidate = parts[-1].strip().lower()
                if all(c in "0123456789abcdef" for c in candidate) and len(candidate) >= 32:
                    return f"{algorithm}:{candidate}"
        return ""

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        log.debug("disk_usage not available for FTP (no standard command); returning zeros")
        return (0, 0, 0)

    # --- MLSD helpers ---

    @staticmethod
    def _mlst_reply_facts(resp: str) -> dict[str, str] | None:
        """Facts of the one entry line in an ``MLST`` reply, or None.

        RFC 3659 7.2: the reply is ``250-<text>``, then the entry line
        ``" facts SP pathname"``, then ``250 <text>``. The framing lines
        usually echo the requested path, which may itself contain ``=``
        or ``; ``, so they are recognised by their reply code and never
        parsed as facts. Facts contain no space, so the pathname is
        everything after the first space of the entry line.
        """
        # PATTERN-001: ftplib joins multi-line responses with `\n`
        # (see ftplib.getmultiline). Split on the actual emitter
        # delimiter, not splitlines(), so a server-supplied entry
        # name carrying \v / \f / U+0085 / U+2028 / U+2029 cannot
        # forge a fake `type=...; name` line.
        for line in split_lf_only_stream(resp):
            line = line.rstrip("\r")
            if _FTP_REPLY_LINE.match(line):
                continue
            entry = line.lstrip(" ")
            if not entry:
                continue
            facts_str, _, _pathname = entry.partition(" ")
            if "=" not in facts_str:
                continue
            return FtpSession._parse_mlsd_facts(facts_str)
        return None

    @staticmethod
    def _parse_mlsd_facts(facts_str: str) -> dict[str, str]:
        facts: dict[str, str] = {}
        for part in facts_str.split(";"):
            part = part.strip()
            if "=" in part:
                key, _, val = part.partition("=")
                facts[key.lower()] = val
        return facts

    @staticmethod
    def _mlsd_to_item(name: str, facts: dict[str, str]) -> FileItem:
        entry_type = facts.get("type", "file").lower()
        is_dir = entry_type in ("dir", "cdir", "pdir")
        # "OS.unix=slink:<target>" is the IANA-registered form (ProFTPD).
        is_link = entry_type == "os.unix=symlink" or entry_type.startswith("os.unix=slink")

        size = 0
        if "size" in facts:
            try:
                size = int(facts["size"])
            except ValueError:
                pass

        modified = datetime.fromtimestamp(0)
        if "modify" in facts:
            try:
                ts = facts["modify"][:14]
                # RFC 3659 2.3 / 7.5.3: the modify fact is UTC.
                modified = datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
            except (ValueError, IndexError):
                pass

        return FileItem(
            name=name,
            size=size,
            modified=modified,
            is_dir=is_dir,
            is_link=is_link,
        )
