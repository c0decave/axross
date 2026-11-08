"""FTP/FTPS backend implementing the FileBackend protocol."""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import functools
import inspect
import io
import logging
import posixpath
import re
import select
import socket
import tempfile
import threading
import time
import weakref
from datetime import datetime, timedelta, timezone
from ftplib import FTP, FTP_TLS, error_perm, error_temp  # nosec B402
from ftplib import Error as _FtpLibError  # nosec B402
from typing import IO, NoReturn

from core import removal_cancel
from core.backend import SessionLifecycle
from core.path_policy import (
    MAX_RECURSIVE_DELETE_DEPTH,
    check_tree_depth,
    refuse_control_chars,
    refuse_folder_path,
    safe_join,
)
from core.read_spool import READ_CHUNK, new_read_spool
from core.session_lock import io_lock, liveness_check, serialized
from core.transfer_pool import MAX_PARALLEL
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

log = logging.getLogger(__name__)

# FTP/FTPS protocol support is intentional; Bandit B402/B321 is suppressed
# only at the exact import/call sites that need ftplib.


# A control connection verified (NOOP or login) this recently is used
# without another NOOP, unless its socket is readable - a server-side
# close ("421" + FIN) makes it readable and sends us down the NOOP path.
LIVENESS_WINDOW = 10.0

# Idle control connections a session keeps for its transfers (each
# download and upload runs on one of its own): as many as transfer jobs
# may run at once, so a run of them logs in once per job, not per file.
IDLE_CONNECTIONS = MAX_PARALLEL

# Seconds a connect, the login or any later reply on a control
# connection may take (ftplib keeps it as the socket's timeout).
SOCKET_TIMEOUT = 15.0

# A refusal (421 / 530) within this many seconds after a login of ours
# timed out or broke may be caused by that login: the server can still
# count it (it was busy hashing the password when we gave up). Such a
# refusal does not turn the session to one connection for good.
LOGIN_FAILURE_GRACE = 60.0

# How often a data connection is asked for when PASV / EPSV answers 425
# (the server found no free passive port), and the pause before the next
# ask, times the attempt.
PASV_ATTEMPTS = 3
PASV_RETRY_DELAY = 0.05

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
    #: The line names an hour and minute (a date within the last six
    #: months); an older one names the year only.
    has_time: bool = False


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


# What a server says on a 2xx that ends a listing it could not make:
# vsftpd's "226 Transfer done (but failed to open directory)." and the
# like. A successful 226 says none of these.
_LIST_FAILED_REPLY = re.compile(
    r"fail|denied|permission|not permitted|cannot|can't|unable", re.IGNORECASE
)


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
                has_time=":" in m.group("when"),
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


def _nlst_all(ftp, path: str) -> list[str]:
    """``NLST`` of *path* including its dot entries.

    vsftpd (force_dot_files=NO, its default) and pure-ftpd leave names
    that start with a dot out of a plain NLST / LIST unless the client
    passes ``-a``: a folder copy left .htaccess / .env / .git behind and a
    recursive delete failed on RMD with them still there. ``NLST -a``
    first; a server that refuses the option, answers with nothing (it may
    have looked for a path "-a ..."), or names entries that begin with
    "-a" (it took the option for part of the path) gets the plain NLST,
    whose answer - or refusal - stands."""
    try:
        names = ftp.nlst(f"-a {path}")
    except error_perm:
        names = []
    if names and not any(n.startswith("-a") for n in names):
        return names
    return ftp.nlst(path)


def _list_lines_all(ftp, path: str) -> tuple[str | None, list[str]]:
    """``(final reply, lines)`` of ``LIST -a`` of *path*, as
    :func:`_nlst_all` does for NLST: the plain ``LIST`` answers when the
    option is refused or the answer is empty. A refusal of the plain LIST
    is raised (error_perm)."""
    lines: list[str] = []
    try:
        reply = ftp.retrlines(f"LIST -a {path}", lines.append)
    except error_perm:
        lines = []
    else:
        if any(line.strip() and not line.startswith("total ") for line in lines):
            return reply, lines
        lines = []
    reply = ftp.retrlines(f"LIST {path}", lines.append)
    return reply, lines


#: The largest offset of a server's LIST clock from UTC that is taken
#: for one (UTC-12 .. UTC+14).
_MAX_ZONE_OFFSET = timedelta(hours=14)


def _list_zone_offset(pairs: list[tuple[datetime, datetime]]) -> timedelta | None:
    """How far a server's LIST dates are off UTC, from ``(MDTM, LIST
    date)`` pairs of the same files: MDTM is UTC (RFC 3659 3), LIST
    prints the server's wall clock (proftpd, pure-ftpd, IIS, vsftpd with
    use_localtime=YES). Rounded to the quarter hour (LIST drops the
    seconds); the offset most files agree on, None without one."""
    votes: dict[int, int] = {}
    for mdtm, listed in pairs:
        quarters = round((mdtm - listed).total_seconds() / 900)
        if abs(quarters) * 900 <= _MAX_ZONE_OFFSET.total_seconds():
            votes[quarters] = votes.get(quarters, 0) + 1
    if not votes:
        return None
    best = max(votes.items(), key=lambda kv: kv[1])[0]
    return timedelta(seconds=best * 900)


def _is_not_found_reply(exc: BaseException) -> bool:
    """True for 550, the reply FTP gives for a path that is not there
    ("file unavailable"; RFC 959). Every other 5xx - 530 not logged in,
    500 / 502 not understood, 534 policy - says nothing about the path."""
    return str(exc)[:3] == "550"


# A 550 worded as a refusal ("Access is denied." - IIS, "Permission denied")
# may answer for an entry that is there: no answer about the path.
_REFUSAL_WORDING = re.compile(r"denied|permission|not allowed|forbidden", re.IGNORECASE)


def _features(ftp) -> frozenset[str]:
    """The keywords *ftp*'s server names in its ``FEAT`` reply (RFC 2389),
    upper case, asked once per control connection. A refused FEAT
    (5xx: an old server) names nothing; a 4xx reply is raised."""
    cached = getattr(ftp, "_axross_features", None)
    if isinstance(cached, frozenset):
        return cached
    try:
        resp = ftp.sendcmd("FEAT")
    except error_perm:
        found: frozenset[str] = frozenset()
    else:
        found = frozenset(
            line.split(None, 1)[0].upper()
            for line in resp.split("\n")
            if line.strip() and not _FTP_REPLY_LINE.match(line)
        )
    ftp._axross_features = found
    return found


def _mlst_exists(ftp, path: str) -> bool | None:
    """Whether *path* is there by one ``MLST`` on the control connection
    (RFC 3659 7): 250 is there, 550 is not. None when the server does not
    offer MLST or its answer says nothing about the path (500 / 502 / 504:
    not implemented after all - not asked again on this connection; 501;
    a 550 worded as a refusal). Any other refusal is raised."""
    if getattr(ftp, "_axross_mlst_refused", False) or "MLST" not in _features(ftp):
        return None
    try:
        resp = ftp.sendcmd(f"MLST {path}")
    except error_perm as exc:
        code = str(exc)[:3]
        if code in ("500", "502", "504"):
            ftp._axross_mlst_refused = True
            return None
        if code == "501":
            return None
        if code == "550":
            return None if _REFUSAL_WORDING.search(str(exc)) else False
        raise
    if resp[:3] == "250":
        return True
    if resp[:1] in ("1", "3"):
        # Another reply is still to come: every later command would read
        # the one before it. Closed, the next call logs in again.
        _close_quietly(ftp)
    raise OSError(f"FTP exists: unexpected reply to MLST {path}: {resp[:80]!r}")


def _binary_mode(ftp) -> None:
    """Put *ftp* in ``TYPE I`` unless it is known to be there: vsftpd
    answers SIZE in ASCII mode with "550 Could not get file size", the
    reply a missing file gets. A server that refuses TYPE I is not asked
    again on this connection; SIZE then goes out as before."""
    if getattr(ftp, "_axross_type", None) == "I" or getattr(ftp, "_axross_type_i_refused", False):
        return
    try:
        ftp.voidcmd("TYPE I")
    except error_perm:
        ftp._axross_type_i_refused = True
        return
    ftp._axross_type = "I"  # also for a connection without _ControlChannelMixin


# Parameters of the wrapped FtpSession methods that carry a remote path.
_PATH_PARAMS = frozenset({"path", "src", "dst"})


def _ftp_errors_as_oserror(fn):
    """Re-raise ftplib protocol errors from ``fn`` as ``OSError``.

    Every path argument (``path`` / ``src`` / ``dst``) is checked first
    with :func:`core.path_policy.refuse_control_chars`: FTP commands are
    CRLF-framed, so a line break in a name either smuggled a second
    command or made ftplib raise a ValueError (no OSError: the pane and
    the transfer engine did not catch it); other C0 characters reach the
    server's command parser as they are."""
    checked = [
        (index, name)
        for index, name in enumerate(inspect.signature(fn).parameters)
        if name in _PATH_PARAMS
    ]

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        for index, name in checked:
            value = args[index] if index < len(args) else kwargs.get(name)
            if isinstance(value, str):
                refuse_control_chars(value, f"FTP {fn.__name__}")
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


_DIGEST_HEX_LEN = {"md5": 32, "sha1": 40, "sha256": 64}


def _is_digest(token: str, algorithm: str) -> bool:
    want = _DIGEST_HEX_LEN.get(algorithm)
    token = token.lower()
    return len(token) == want and all(c in "0123456789abcdef" for c in token)


def _hash_reply_digest(resp: str, algorithm: str, *, draft: bool) -> str:
    """The hex digest in a checksum reply, or "".

    ``HASH`` answers ``213 <algo> <range> <hash> <name>``
    (draft-bryan-ftpext-hash): the last token is the FILE NAME, which was
    returned as the hash - also when the name itself is hex. The name may
    hold blanks, so the fields are taken from the left. ``XMD5`` /
    ``XSHA*`` answer ``2xx <hash>`` (some servers add the name after it):
    the first token after the code that is a digest of the right length.
    """
    parts = resp.split(None, 4)
    if len(parts) < 2 or not parts[0].startswith("2"):
        return ""
    if draft:
        if len(parts) >= 4 and _is_digest(parts[3], algorithm):
            return parts[3].lower()
        return ""
    for token in parts[1:]:
        if _is_digest(token, algorithm):
            return token.lower()
    return ""


def _quit_quietly(ftp) -> None:
    """QUIT a control connection; close it when QUIT fails."""
    try:
        ftp.quit()
    except Exception:  # noqa: BLE001 - a dead connection is closed anyway
        _close_quietly(ftp)


def _socket_quiet(ftp) -> bool:
    """True when nothing waits on *ftp*'s control socket: a server-side
    close ("421" + FIN) makes it readable. Anything unexpected answers
    False, so the caller checks the connection with a NOOP."""
    sock = getattr(ftp, "sock", None)
    if not isinstance(sock, socket.socket):
        return False
    try:
        if getattr(sock, "pending", lambda: 0)():  # TLS bytes already buffered
            return False
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return False
    return not readable


def _close_quietly(ftp) -> None:
    """Close a control connection without a QUIT round trip."""
    try:
        ftp.close()
    except Exception:  # noqa: BLE001 - nothing left to report it to
        pass


class _SpooledWriter:
    """Write to a temp file, then upload on close.

    ``store(command, fileobj)`` runs the upload (FtpSession._store: on a
    control connection of its own, or on the shared one); without it the
    upload runs on ``ftp`` under ``lock``."""

    def __init__(self, ftp: FTP | None, remote_path: str, append: bool = False, lock=None,
                 store=None):
        self._ftp = ftp
        self._remote_path = remote_path
        self._append = append
        self._lock = lock if lock is not None else contextlib.nullcontext()
        self._store = store
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
            if self._store is not None:
                self._store(f"{cmd} {self._remote_path}", self._buf)
            else:
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
        the PASV-announced host with ``self.sock.getpeername()[0]``.
        Under a proxy, ``getpeername()`` is the *proxy's* address, so
        the control connection's host (``self.host``, which the proxy
        dialled) takes its place - never the host the reply names.
        """
        from core.proxy import create_proxy_socket

        size = None
        if self.passiveserver:
            # Only the port of the PASV / EPSV reply is used: the data
            # connection goes to the host the control connection goes
            # to, through the proxy. The host a 227 reply names may be a
            # NAT'ed server's private address, or - from a hostile server
            # or a MITM on cleartext FTP - any host the proxy can reach
            # (169.254.169.254, intranet hosts): the proxy would fetch it
            # as the download, or receive the upload.
            self.trust_server_pasv_ipv4_address = False
            _announced, port = self.makepasv()
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


class _ControlChannelMixin:
    """Remembers the transfer type (``TYPE A`` / ``TYPE I``) the server
    last accepted on this control connection, as ``_axross_type``; None
    while unknown (a new connection, or a TYPE command whose reply is not
    in yet or was a refusal). ftplib switches the type inside retrlines /
    retrbinary / storbinary without telling anyone.

    Also asks again for a passive data port the server answered with 425:
    pure-ftpd (passive ports 30000-30010 in the lab) answered PASV with
    "425 Unable to identify the local data socket: Address already in use"
    for 1 of 300 uploads in 2 of 10 rounds with four jobs at a time
    (measured 2026-10-26). 425 is transient (RFC 959 4.2.1) and no
    transfer command has gone out yet."""

    _axross_type: str | None = None

    def makepasv(self):
        for attempt in range(1, PASV_ATTEMPTS + 1):
            try:
                return super().makepasv()  # type: ignore[misc]
            except error_temp as exc:
                if str(exc)[:3] != "425" or attempt == PASV_ATTEMPTS:
                    raise
                log.debug("FTP passive port refused (%s); asking again", exc)
                time.sleep(PASV_RETRY_DELAY * attempt)
        raise AssertionError("unreachable")  # pragma: no cover

    def putcmd(self, line):
        if line[:5].upper() == "TYPE ":
            self._axross_type = None  # unknown until the server says yes
        super().putcmd(line)  # type: ignore[misc]

    def _note_type(self, cmd: str) -> None:
        if cmd[:5].upper() == "TYPE ":
            self._axross_type = cmd[5:].strip().upper()

    def sendcmd(self, cmd):
        resp = super().sendcmd(cmd)  # type: ignore[misc]
        if resp[:1] == "2":
            self._note_type(cmd)
        return resp

    def voidcmd(self, cmd):
        resp = super().voidcmd(cmd)  # type: ignore[misc]  # raises unless 2xx
        self._note_type(cmd)
        return resp


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


class _FTP(_ControlChannelMixin, _LenientListingMixin, FTP):
    """Plain FTP with lenient listing decoding."""


def _control_session(ftp) -> object | None:
    """The control connection's TLS session, for the data socket to resume.

    Servers that require session reuse (vsftpd's require_ssl_reuse=YES by
    default, test.rebex.net) refuse a data connection that negotiates a
    session of its own: "425 ... TLS session resumption required"."""
    return getattr(getattr(ftp, "sock", None), "session", None)


class _FTP_TLS(_ControlChannelMixin, _LenientListingMixin, FTP_TLS):
    """FTPS with lenient listing decoding and TLS session reuse on data."""

    def ntransfercmd(self, cmd, rest=None):
        # ftplib's FTP_TLS.ntransfercmd wraps without session=.
        conn, size = FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(
                conn, server_hostname=self.host, session=_control_session(self)
            )
        return conn, size


class _ProxyFTP(_FtpProxyMixin, _ControlChannelMixin, _LenientListingMixin, FTP):
    """FTP subclass with proxy-aware control + data channels."""


class _ProxyFTP_TLS(
    _FtpProxyMixin, _ControlChannelMixin, _LenientListingMixin, FTP_TLS
):
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
    _separate_transfers = False

    @property
    def parallel_transfers_safe(self) -> bool:
        """Two transfer jobs may share this session while every transfer
        runs on a control connection of its own; once the server refused
        a second one, the session carries one job at a time (asked again
        by core.transfer_pool before every job). Metadata calls share the
        session's connection under its lock either way."""
        return self._separate_transfers is True

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
        # Downloads (_StreamedDownload) and uploads (_store) run on control
        # connections of their own; finished ones wait in _idle for the
        # next transfer, IDLE_CONNECTIONS at most, newest last. _pool_generation counts
        # disconnects: a connection handed out before one is not kept.
        # _separate_cap: how many of ours the server allows beside the
        # session's, once it refused one more.
        self._separate_transfers = True
        self._idle: list[tuple[FTP, float]] = []  # (connection, released at)
        self._pool_lock = threading.Lock()
        self._pool_changed = threading.Condition(self._pool_lock)
        self._logins_in_flight = 0
        self._pool_generation = 0
        self._separate_cap: int | None = None
        self._separate_open: weakref.WeakSet = weakref.WeakSet()

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
                    timeout=SOCKET_TIMEOUT,
                )
            else:
                ftp.connect(self._host, self._port, timeout=SOCKET_TIMEOUT)
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
        except Exception as exc:  # noqa: BLE001 - any failure means not connected
            log.debug("FTP liveness check of %s failed: %s", getattr(self, "_host", "?"), exc)
            return False

    @serialized
    def disconnect(self) -> None:
        for idle in self._drain_pool():
            _quit_quietly(idle)
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

    def security_info(self):
        """The negotiated protection of the control connection (TLS version,
        cipher, whether the certificate was checked) and whether the data
        channel is protected too (PROT P); None when not connected."""
        from core import conn_security as CS

        ftp = self._ftp
        sock = getattr(ftp, "sock", None) if ftp is not None else None
        if sock is None:
            return None
        if not self._tls:
            return CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "FTP - cleartext - anyone on the network can "
                                   "read it, the password too", True)
        data = "data channel protected (PROT P)" if getattr(ftp, "_prot_p", False) \
            else "data channel NOT protected"
        info = CS.tls_socket(sock, verified=self._verify_tls, what="FTPS", extra=(data,))
        if info is not None and not getattr(ftp, "_prot_p", False):
            return CS.SecurityInfo(CS.LEVEL_TLS_WEAK, info.summary + "; " + data, True, info.details)
        return info

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
        return _socket_quiet(self._ftp)

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
            names = _nlst_all(ftp, path)
        except error_perm as e:
            refused = self._read_refused(path, e)
            if isinstance(refused, FileNotFoundError):
                raise FileNotFoundError(errno.ENOENT, f"Cannot list {path}: {e}", path) from e
            raise OSError(f"Cannot list {path}: {e}") from e
        names = [n for n in names if (posixpath.basename(n.rstrip("/")) or n) not in (".", "..")]
        # NLST (and LIST) of a FILE answers with that file - vsftpd,
        # pure-ftpd and proftpd run ls on the argument; MLSD of a file is
        # 501 / 550 and lands here too. One name that is the path's own
        # is a folder only when CWD enters it (a folder "a" in "a" is).
        leaf = posixpath.basename(path.rstrip("/"))
        if (
            len(names) == 1
            and leaf
            and posixpath.basename(names[0].rstrip("/")) == leaf
            and not self._cwd_reaches(ftp, path)
        ):
            raise NotADirectoryError(errno.ENOTDIR, "Not a directory", path)
        # vsftpd answers NLST of a missing folder with an empty listing,
        # not 550: an empty answer counts only when CWD reaches the folder.
        if not names and not self._cwd_reaches(ftp, path):
            raise FileNotFoundError(errno.ENOENT, "No such directory", path)
        if not names:
            # CWD reaching a folder says it may be entered, not read: a
            # 0711 folder lets vsftpd in and answers NLST with no names
            # and "226 ... (but failed to open directory)". Taken as
            # empty, a tree copy or move would skip everything inside.
            self._confirm_empty(ftp, path)

        # A Unix-style LIST line carries type, mode, owner, size and date,
        # so an entry it names needs no probe of its own; only a regular
        # file asks MDTM for its exact UTC time. Without a readable LIST
        # every entry is probed with stat(), whose CWD follows a symbolic
        # link - LIST is also the only source that says which are links.
        details = self._unix_listing(ftp, path) if names else None
        # Dates LIST alone gives (folders; files without MDTM) are put on
        # the server's clock offset that MDTM and LIST of its files show.
        list_dated: list[int] = []
        clock_pairs: list[tuple[datetime, datetime]] = []
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
                if detail.modified is not None and detail.has_time:
                    if modified is not None:
                        clock_pairs.append((modified, detail.modified))
                    else:
                        list_dated.append(len(items))
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

        offset = _list_zone_offset(clock_pairs) if list_dated else None
        if offset:
            for index in list_dated:
                items[index] = dataclasses.replace(
                    items[index], modified=items[index].modified + offset
                )
        return items

    @staticmethod
    def _confirm_empty(ftp: FTP, path: str) -> None:
        """Ask ``LIST`` whether the folder an empty NLST named is empty.

        ftplib's ``nlst`` drops the final reply, so LIST is asked again and
        its reply read: wording such as vsftpd's "(but failed to open
        directory)" on a 226, or a refusal, is a PermissionError; entries
        LIST shows that NLST left out are an OSError. Neither is read as
        an empty folder."""
        try:
            # LIST -a: a folder that holds only dot entries is not empty.
            reply, lines = _list_lines_all(ftp, path)
        except error_perm as e:
            raise PermissionError(errno.EACCES, f"Cannot list {path}: {e}", path) from e
        if isinstance(reply, str) and _LIST_FAILED_REPLY.search(reply):
            raise PermissionError(
                errno.EACCES,
                f"Cannot list {path}: the server could not read the folder "
                f"({reply.strip()[:200]})",
                path,
            )
        shown = []
        for line in lines:
            line = line.rstrip("\r")
            if not line.strip() or line.startswith("total "):
                continue
            m = _UNIX_LIST_LINE.match(line)
            name = m.group("rest").split(" -> ", 1)[0] if m is not None else line
            if name not in (".", ".."):
                shown.append(name)
        if shown:
            raise OSError(
                errno.EIO,
                f"Cannot list {path}: NLST names nothing, but LIST shows "
                f"{len(shown)} entries",
                path,
            )

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
        item = self._stat(path)
        # The server resolves "g/" to the file g (MLST, SIZE, MDTM): a
        # path ending in "/" names a folder, as stat(2) has it.
        if path.endswith("/") and path.strip("/") and not item.is_dir:
            raise NotADirectoryError(errno.ENOTDIR, f"Cannot stat {path}: not a folder", path)
        return item

    def _stat(self, path: str) -> FileItem:
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
        _binary_mode(ftp)
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
            names = _nlst_all(ftp, posixpath.dirname(trimmed) or "/")
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
        """Whether the entry itself is there (a dangling link is).

        False only on a definitive "not there": 550 to MLST on a server
        that names MLST in FEAT, or else SIZE refused, CWD 550 and a parent
        listing without the name. Any other refusal is an OSError -
        server_side_copy(overwrite=False) and the transfer engine take
        False as their go-ahead to write.

        MLST needs no data connection and no failed CWD: pure-ftpd delays
        every failed CWD by 100 ms times the failed CWDs so far on the
        connection and drops it after the 50th (measured 2026-10-26), so
        an upload of 300 new files lost every 51st one. Where a 550 to
        MLST is not about the name itself, nothing can be overwritten: a
        server whose MLST follows links answers it for a dangling link (no
        data behind it), and for an entry in a folder without search
        permission, where a write fails as well."""
        # A line break in *path* is refused by the decorator: ftplib's
        # ValueError was taken below for "a 213 reply it cannot parse".
        ftp = self._ensure_connected()
        answer = _mlst_exists(ftp, path)
        if answer is not None:
            return answer
        _binary_mode(ftp)
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
        # same 550 for a file that is there (a server that will not size
        # an unreadable file, or SIZE in ASCII mode where TYPE I was
        # refused): the parent listing decides.
        return self._parent_lists(ftp, path)

    @_ftp_errors_as_oserror
    @serialized
    def mkdir(self, path: str) -> None:
        ftp = self._ensure_connected()
        try:
            ftp.mkd(path)
        except error_perm as e:
            # MKD of a taken name is a 550 like any other refusal.
            if str(e).startswith("550") and self.exists(path):
                raise FileExistsError(
                    errno.EEXIST, f"Cannot create directory {path}: it exists", path
                ) from e
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
                # 550 says "not there" and "may not" alike: only exists()
                # tells a typo (FileNotFoundError, as on LocalFS) apart.
                if str(e).startswith("550") and not self.exists(path):
                    raise FileNotFoundError(
                        errno.ENOENT, f"Cannot delete {path}: not found", path
                    ) from e
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
            removal_cancel.checkpoint(child)  # the pane's Cancel stops here
            if descend:
                self._rmdir_recursive(child, depth + 1)
            else:
                ftp.delete(child)
            removal_cancel.removed(child)
        ftp.rmd(path)

    @_ftp_errors_as_oserror
    @serialized
    def rename(self, src: str, dst: str) -> None:
        ftp = self._ensure_connected()
        # The server canonicalizes the name: a file renamed to "x/" became
        # a file "x". A folder may be named so; a source that is not there
        # goes on to RNFR, which says so.
        refuse_folder_path(dst, "rename to",
                           source_is_file=lambda: self.exists(src) and not self.is_dir(src))
        try:
            ftp.rename(src, dst)
        except error_perm as e:
            raise OSError(f"Cannot rename {src} -> {dst}: {e}") from e

    @_ftp_errors_as_oserror
    @serialized
    def set_modified(self, path: str, mtime: float) -> None:
        """Set *path*'s modification time with ``MFMT`` (whole seconds,
        UTC), so a copy keeps its source's time. Only a server that names
        MFMT in its FEAT reply is asked: NotImplementedError otherwise (the
        copy then keeps the upload time, which "Overwrite if Newer" and
        Compare read as the newer one)."""
        ftp = self._ensure_connected()
        if "MFMT" not in _features(ftp):
            raise NotImplementedError("the FTP server does not offer MFMT")
        stamp = datetime.fromtimestamp(int(mtime), tz=timezone.utc).strftime("%Y%m%d%H%M%S")
        try:
            ftp.sendcmd(f"MFMT {stamp} {path}")
        except error_perm as e:
            raise OSError(f"Cannot set the modification time of {path}: {e}") from e

    @_ftp_errors_as_oserror
    def open_read(self, path: str) -> IO[bytes]:
        got = self._transfer_connection()
        if got is None:
            return self._open_read_shared(path)
        ftp, generation = got
        done = functools.partial(self._release_connection, generation=generation)
        try:
            ftp.voidcmd("TYPE I")
            conn = ftp.transfercmd(f"RETR {path}")
        except error_perm as e:
            # "550 No such file": answered, the connection is fine.
            done(ftp)
            raise self._read_refused(path, e) from e
        except BaseException:
            _close_quietly(ftp)
            raise
        return _StreamedDownload(ftp, conn, path, done)

    def _store(self, command: str, fileobj) -> None:
        """Upload *fileobj* with *command* (STOR / APPE): on a control
        connection of its own, so that the session's connection and lock
        stay free for other jobs; on the shared one, under the session
        lock for the whole transfer, when the server allows no more."""
        got = self._transfer_connection()
        if got is None:
            with io_lock(self):
                self._ensure_connected().storbinary(command, fileobj)
            return
        ftp, generation = got
        try:
            ftp.storbinary(command, fileobj)
        except error_perm:
            # "553 Could not create file": answered, the connection is fine.
            self._release_connection(ftp, generation=generation)
            raise
        except BaseException:
            _close_quietly(ftp)
            raise
        self._release_connection(ftp, generation=generation)

    def _transfer_connection(self) -> tuple[FTP, int] | None:
        """A logged-in control connection of its own for one transfer and
        the pool generation it belongs to, or None to transfer on the
        shared one: a session built without its ``__init__`` has nothing
        to log in with, a server that refused a second connection is not
        asked again, and one that refused a further one is not asked for
        more than it allowed."""
        if not self._separate_transfers:
            return None
        while True:
            with self._pool_lock:
                generation = self._pool_generation
                entry = self._idle.pop() if self._idle else None
                if entry is None and self._separate_cap is not None:
                    if self._open_separate() >= self._separate_cap:
                        return None
            if entry is None:
                break
            ftp, released_at = entry
            # Used a moment ago and nothing waiting on it: no NOOP round
            # trip, as for the session's connection (_recently_verified).
            if time.monotonic() - released_at <= LIVENESS_WINDOW and _socket_quiet(ftp):
                return ftp, generation
            try:
                ftp.voidcmd("NOOP")
                return ftp, generation
            except (*_FTP_PROTOCOL_ERRORS, OSError):
                _close_quietly(ftp)
        with self._pool_lock:
            self._logins_in_flight += 1
        ftp = None
        try:
            ftp = self._login(announce=False)
        except _FtpLibError as exc:
            # "421 Too many connections", "530 ... maximum number of
            # clients": the server allows this user no more connections.
            refused = exc
        except (OSError, EOFError) as exc:
            log.debug("FTP %s: no connection of its own for a transfer: %s", self._host, exc)
            self._login_failed_at = time.monotonic()
            refused = None
        else:
            refused = None
        finally:
            with self._pool_changed:
                if ftp is not None:
                    self._separate_open.add(ftp)
                self._logins_in_flight -= 1
                self._pool_changed.notify_all()
        if ftp is not None:
            return ftp, generation
        if refused is not None:
            self._refused(refused)
        return None

    def _refused(self, exc: Exception) -> None:
        """The server refused one more connection.

        * Right after a login of ours timed out or broke, the server may
          still count that one: nothing is concluded, this transfer uses
          the session's connection and the next one asks again.
        * With some of ours open beside the session's, those are what it
          allows: they go on carrying transfers side by side, and no more
          are asked for until the session disconnects.
        * With none open, it allows this user one connection: every
          transfer uses the session's from now on, one job at a time.
        """
        with self._pool_changed:
            # Logins started at the same time may still succeed: they are
            # what the server allows, so wait for their outcome first.
            self._pool_changed.wait_for(lambda: self._logins_in_flight == 0, timeout=60)
            allowed = self._open_separate()
            failed_at = getattr(self, "_login_failed_at", None)
            ours = failed_at is not None and time.monotonic() - failed_at < LOGIN_FAILURE_GRACE
            if ours:
                pass
            elif allowed:
                self._separate_cap = allowed
            else:
                self._separate_transfers = False
        if ours:
            log.info(
                "FTP %s refused another connection (%s) right after a login of ours "
                "failed; this transfer uses the session's, the next one asks again",
                self._host,
                exc,
            )
        elif allowed:
            log.info(
                "FTP %s refused another connection (%s); transfers use the %d it allowed",
                self._host,
                exc,
                allowed,
            )
        else:
            log.info(
                "FTP %s refused a second connection (%s); transfers use the session's",
                self._host,
                exc,
            )

    def _open_separate(self) -> int:
        """Connections of ours open beside the session's, idle or in use
        (called with _pool_lock held). ftplib's close() drops ``sock``."""
        return sum(1 for ftp in list(self._separate_open) if getattr(ftp, "sock", None))

    def _release_connection(self, ftp: FTP, *, generation: int) -> None:
        """A transfer is through with *ftp* and left it ready for the next
        command: keep it for the next transfer, unless the session was
        disconnected since it was handed out or IDLE_CONNECTIONS wait
        already."""
        with self._pool_lock:
            if (
                generation == self._pool_generation
                and self._ftp is not None
                and len(self._idle) < IDLE_CONNECTIONS
            ):
                self._idle.append((ftp, time.monotonic()))
                ftp = None
        if ftp is not None:
            _quit_quietly(ftp)

    def _drain_pool(self) -> list[FTP]:
        """Take every idle connection; one in use is quit when its
        transfer ends (the generation moves on)."""
        lock = self.__dict__.get("_pool_lock")
        if lock is None:
            return []
        with lock:
            idle, self._idle = self._idle, []
            self._pool_generation += 1
            self._separate_cap = None
        return [ftp for ftp, _released_at in idle]

    def _read_refused(self, path: str, exc: error_perm) -> OSError:
        """The OSError for a refused RETR: 550 says "not there" and "may
        not" alike, so only exists() names a FileNotFoundError."""
        if _is_not_found_reply(exc):
            try:
                there = self.exists(path)
            except Exception:  # noqa: BLE001 - no answer: not "missing"
                there = None
            if there is False:
                return FileNotFoundError(errno.ENOENT, f"Cannot read {path}: {exc}", path)
        return OSError(f"Cannot read {path}: {exc}")

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
            raise self._read_refused(path, e) from e
        except BaseException:
            buf.close()
            raise
        buf.seek(0)
        return buf

    @_ftp_errors_as_oserror
    @serialized
    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        # Connected now, so a dead server fails here and not after the
        # caller spooled the whole file; the upload picks its connection
        # when the writer closes (_store).
        if path.endswith("/") and path.strip("/"):
            # STOR "x/" stored a FILE "x" on servers that drop the slash.
            raise IsADirectoryError(
                errno.EISDIR, f"Cannot write {path}: a path ending in '/' names a folder", path
            )
        ftp = self._ensure_connected()
        return _SpooledWriter(ftp, path, append=append, store=self._store)

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
        refuse_control_chars(path, "FTP mlst")  # F38: no second wire command
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
        refuse_control_chars(path, "FTP cwd")  # F38
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
            except Exception as exc:  # noqa: BLE001 - best effort: try the next command
                log.debug("FTP %s of %s failed: %s", cmd, path, exc)
                continue
            digest = _hash_reply_digest(resp, algorithm, draft=(cmd == "HASH"))
            if digest:
                return f"{algorithm}:{digest}"
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
