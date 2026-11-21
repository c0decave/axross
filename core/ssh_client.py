"""SSH/SFTP session implementing the FileBackend protocol."""

from __future__ import annotations

import errno
import functools
import hashlib
import logging
import os
import posixpath
import shlex
import socket
import stat as stat_module
import struct
import subprocess
import threading
import time
import weakref
from collections.abc import Callable
from contextlib import contextmanager
from contextlib import suppress as contextlib_suppress
from datetime import datetime
from pathlib import Path
from typing import IO, TYPE_CHECKING

import paramiko

from core import removal_cancel, transfer_hooks
from core.backend import SessionLifecycle
from core.client_identity import SSH_LOCAL_VERSION, apply_paramiko_banner_override
from core.exec_util import command_missing, digest_from_sum_output
from core.path_policy import MAX_RECURSIVE_DELETE_DEPTH, check_tree_depth, safe_join
from core.profiles import ConnectionProfile
from core.proxy import (
    ProxyConfig,
    create_direct_socket,
    create_proxy_socket,
    enable_quick_ack,
    enable_tcp_nodelay,
)
from core.redaction import redact_text
from core.ssh_config import expand_proxy_command, require_confirmed_proxy_command
from core.subprocess_env import clean_child_env
from models.file_item import FileItem
from security.protocol_line_split import split_lf_only_stream

if TYPE_CHECKING:
    from models.exec_result import ExecResult
    from models.interactive_shell import InteractiveShell

# Apply the class-level banner patch defensively on import, so a
# standalone invocation of this module (tests, scripts) doesn't depend
# on main.py having run first.
apply_paramiko_banner_override()

log = logging.getLogger(__name__)

HELPER_STDOUT_CAP = 4 * 1024 * 1024
#: Seconds the SSH key exchange may take before a connect gives up (a
#: server that sends its banner and then stalls).
SSH_HANDSHAKE_TIMEOUT = 10.0
HELPER_STDERR_CAP = 256 * 1024
# hardlink(): the shell's answer when the link path is already taken.
_HARDLINK_TAKEN = "axross-hardlink-target-exists"


def _read_limited_stream(stream, cap: int, label: str) -> bytes:
    data = stream.read(cap + 1)
    if isinstance(data, str):
        raw = data.encode("utf-8", errors="replace")
    else:
        raw = bytes(data)
    if len(raw) > cap:
        raise OSError(f"{label} exceeds {cap} byte cap")
    return raw


# What paramiko raises when the SFTP channel or the transport under it is
# gone: SFTPClient turns EOF into SSHException("Server connection dropped")
# (sftp_client._read_response); neither is an OSError.
_SFTP_CONNECTION_ERRORS = (paramiko.SSHException, EOFError)

#: Seconds an SFTP channel waits for the server's next bytes (an answer,
#: window space for a write) before the request fails with
#: ``TimeoutError`` (ETIMEDOUT). Without it a request on a connection
#: that went silent (Wi-Fi gone, a NAT entry dropped, a VPN down: no RST
#: arrives) waited for ever - the pane, the transfer and Cancel with it.
#: It bounds silence, not the length of a transfer: a large download
#: gets its bytes long before this. Also the longest wait for the server
#: to open a channel.
SFTP_IO_TIMEOUT = 60.0

#: The longest an SFTP request waits for its answer while the SSH
#: connection itself still answers (see :func:`transport_answers`): a
#: server that is alive but slow - a tape or HSM recall, a cloud-tiered
#: file brought back on open, the unlink of a huge file - is waited for,
#: up to this many seconds of silence on the one request.
SFTP_SLOW_SERVER_CAP = 30 * 60.0

#: The keepalive request :func:`transport_answers` sends: OpenSSH's own
#: (ServerAliveInterval). Only after :data:`SFTP_IO_TIMEOUT` of silence
#: on a waiting request - no fixed cadence (docs/OPSEC.md #2). A server
#: that drops it unanswered gets a channel open of this type half-way.
_KEEPALIVE_REQUEST = "keepalive@openssh.com"


def _sftp_errors_as_oserror(fn):
    """Re-raise what paramiko raises for a bad answer from ``fn`` as
    ``OSError``, the backend contract every caller (pane, transfers,
    compare) handles: a lost connection, a protocol violation
    (paramiko.SFTPError) and a name or link target that is not UTF-8
    (paramiko decodes those strictly)."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except TimeoutError as exc:
            if exc.errno is not None:
                raise  # already a sentence (core.sftp_io.timeout_error)
            from core.sftp_io import timeout_error

            session = args[0] if args else None
            client = getattr(getattr(session, "_thread_local", None), "sftp", None)
            raise timeout_error(fn.__name__, client) from exc
        except _SFTP_CONNECTION_ERRORS as exc:
            detail = str(exc) or type(exc).__name__
            raise OSError(f"SFTP {fn.__name__}: connection to the server failed: {detail}") from exc
        except (paramiko.SFTPError, UnicodeError) as exc:
            raise OSError(f"SFTP {fn.__name__}: unusable answer from the server: {exc}") from exc

    return wrapper


#: READDIR requests kept on the wire while a folder is listed.
LISTING_READDIRS_IN_FLIGHT = 16
#: Most entries one folder listing collects: a server that answers READDIR
#: without end (or a folder of millions) grew the client's memory without
#: bound - past 1 GB inside one MCP call. Over it the listing fails.
MAX_LISTING_ENTRIES = 300_000
#: Most bytes the answers of one folder listing may carry - names,
#: longnames, attributes, extended ones too: 4000-character names took a
#: client to 1.5 GB in 8 s well below the entry cap, 900 KiB of extended
#: attributes per entry past 2.5 GB. Over it the listing fails.
MAX_LISTING_BYTES = 64 << 20
#: A longer name is no name any file system here holds (NAME_MAX is 255
#: bytes): such an entry is left out of the listing.
MAX_NAME_BYTES = 4096

#: REMOVE requests a recursive delete keeps on the wire (one batch); the
#: pane's Cancel is asked between batches.
RMTREE_REMOVES_IN_FLIGHT = 16


def wire_path(path: str | bytes) -> bytes:
    """*path* as the bytes an SFTP request carries: UTF-8, with the lone
    surrogates of a name that is not UTF-8 (``surrogateescape``, how
    listings and local file names decode them) back as the raw bytes."""
    if isinstance(path, bytes):
        return path
    return path.encode("utf-8", errors="surrogateescape")


def command_bytes(cmd: str | bytes) -> bytes:
    """*cmd* as the bytes of an SSH exec request: UTF-8, with the lone
    surrogates of a name that is not UTF-8 (see :func:`wire_path`) back
    as the raw bytes - paramiko encodes a str command strictly as UTF-8,
    so a command naming such a file raised UnicodeEncodeError (not an
    OSError). ``shlex.quote`` quotes such a str like any other, so the
    quoting survives the encoding. A surrogate that stands for no byte
    is an OSError (EILSEQ)."""
    if isinstance(cmd, bytes):
        return cmd
    try:
        return cmd.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError as exc:
        raise OSError(errno.EILSEQ, f"SSH command cannot be sent: {exc}") from exc


def _duration(seconds: float) -> str:
    if seconds >= 60:
        return f"{seconds / 60:g} minutes"
    return f"{seconds:g} s"


def _slow_requests() -> frozenset:
    from paramiko.sftp import CMD_CLOSE, CMD_EXTENDED, CMD_REMOVE, CMD_RENAME, CMD_RMDIR

    return frozenset({CMD_CLOSE, CMD_REMOVE, CMD_RMDIR, CMD_RENAME, CMD_EXTENDED})


#: SFTP requests a healthy server may answer slowly (see
#: _SurrogateSftpClient._request).
_SLOW_BY_NATURE = _slow_requests()


class _SurrogateSftpClient(paramiko.SFTPClient):
    """paramiko's SFTP client with paths encoded by :func:`wire_path`.

    paramiko encodes every path strictly as UTF-8 (util.b, in
    ``_adjust_cwd``, which every request with a path passes through), so
    a name listed from a latin-1 folder could be seen but not used: stat,
    open, rename and remove raised UnicodeEncodeError - or, decoded with
    replacement characters, asked for a name that is not there."""

    #: The longest a request waits for its answer while the SSH connection
    #: answers keepalives (:meth:`_still_waiting`); an MCP profile sets its
    #: own, much shorter one (:meth:`SSHSession.bound_requests`).
    slow_server_cap: float | None = None
    #: Numbers of the requests slow by nature still unanswered (see
    #: _async_request).
    _slow_nums: frozenset | set = frozenset()

    def _adjust_cwd(self, path):
        return super()._adjust_cwd(wire_path(path))

    def _async_request(self, fileobj, t, *args):
        """paramiko's (its ``_request`` sends through here too); a request a
        healthy server may take long to answer - the CLOSE that flushes an
        upload (a NAS), the REMOVE of a huge file, a rename, fsync - is
        noted: while one is unanswered, a wait lasts up to
        :data:`SFTP_SLOW_SERVER_CAP` as long as the connection answers
        keepalives, not the short deadline an MCP profile sets for the rest
        (a 70 s CLOSE failed and the finished upload was removed)."""
        num = super()._async_request(fileobj, t, *args)
        if t in _SLOW_BY_NATURE:
            if not isinstance(self._slow_nums, set):
                self._slow_nums = set()
            self._slow_nums.add(num)
        return num

    def _slow_pending(self) -> bool:
        nums = self._slow_nums
        if not nums:
            return False
        expecting = getattr(self, "_expecting", {})
        nums.intersection_update(expecting)
        return bool(nums)

    #: Bytes taken from the channel and not handed out yet (_read_all).
    _rbuf: bytearray | None = None
    _rpos = 0
    #: What one read from the channel asks for at most (_read_all).
    READ_CHUNK = 64 * 1024

    def _read_all(self, n):
        """paramiko's, but a request whose answer is late is not failed
        while the SSH connection still answers (:meth:`_still_waiting`) -
        and the channel is read in chunks: paramiko read every answer with
        two reads (its length, then the rest), each a lock and a wait on
        the channel - for the answers of a batch of small files, more time
        than everything else. What is read beyond *n* stays here for the
        next answer (only this client reads its channel)."""
        buf = self._rbuf
        if buf is None:
            buf = self._rbuf = bytearray()
        silent_since = None
        while len(buf) - self._rpos < n:
            try:
                x = self.sock.recv(max(n - (len(buf) - self._rpos), self.READ_CHUNK))
            except TimeoutError:
                silent_since = self._still_waiting(silent_since)
                continue
            if len(x) == 0:
                raise EOFError()
            silent_since = None
            if self._rpos:
                del buf[:self._rpos]
                self._rpos = 0
            buf += x
        start = self._rpos
        self._rpos = start + n
        out = bytes(buf[start:start + n])
        if self._rpos == len(buf):
            buf.clear()
            self._rpos = 0
        return out

    def answer_pending(self) -> bool:
        """An answer can be read without waiting: a whole one is in this
        client's buffer, or the channel has bytes already."""
        buf = self._rbuf
        if buf is not None and len(buf) - self._rpos >= 4:
            size = int.from_bytes(buf[self._rpos:self._rpos + 4], "big")
            if len(buf) - self._rpos - 4 >= size:
                return True
        ready = getattr(self.sock, "recv_ready", None)
        return bool(ready()) if callable(ready) else False

    #: Requests held back by :meth:`holding_requests`, as bytes on the wire.
    _held_out: list | None = None

    def _send_packet(self, t, packet):
        held = self._held_out
        if held is None:
            return super()._send_packet(t, packet)
        packet = packet.asbytes()
        held.append(struct.pack(">I", len(packet) + 1) + bytes((t,)) + packet)
        return None

    @contextmanager
    def holding_requests(self):
        """Requests sent in the ``with`` body go out together at the next
        :meth:`flush_requests` (and at its end): one write to the channel,
        one SSH packet for many small SFTP requests, instead of one each
        (a send() each, 0.1 - 0.3 ms of system time per request)."""
        if self._held_out is not None:
            yield
            return
        self._held_out = []
        try:
            yield
        finally:
            try:
                self.flush_requests()
            finally:
                self._held_out = None

    def flush_requests(self) -> None:
        held = self._held_out
        if held:
            data = b"".join(held)
            held.clear()
            self._write_all(data)

    def _write_all(self, out):
        """paramiko's, with the same patience as :meth:`_read_all` for a
        server that is slow to take more (a full channel window)."""
        silent_since = None
        while len(out) > 0:
            try:
                n = self.sock.send(out)
            except TimeoutError:
                silent_since = self._still_waiting(silent_since)
                continue
            if n <= 0:
                raise EOFError()
            silent_since = None
            if n == len(out):
                return
            out = out[n:]

    def _still_waiting(self, silent_since: float | None) -> float:
        """The channel's time-out (:data:`SFTP_IO_TIMEOUT` or the
        profile's) passed without a byte. A server that is alive but
        slow (a tape or HSM recall, a cloud-tiered file, the unlink of a
        huge file) is not a lost network: the SSH connection is asked
        (:func:`transport_answers`); it answers - wait on, up to
        :data:`SFTP_SLOW_SERVER_CAP` of silence; it does not - re-raise
        the time-out (ETIMEDOUT for the caller, see
        core.sftp_io.timeout_error). Cancel closes the channel, which
        ends the wait."""
        chan = self.sock
        now = time.monotonic()
        if silent_since is None:
            silent_since = now - (chan.gettimeout() or 0.0)
        if chan.closed:
            raise EOFError()
        try:
            # A cancelled call (an MCP tool past its time-out, Cancel in a
            # pane) stops waiting: the channel is this thread's own, so
            # closing it ends nothing else.
            transfer_hooks.check()
        except InterruptedError:
            chan.close()
            raise
        cap = self.slow_server_cap if self.slow_server_cap is not None else SFTP_SLOW_SERVER_CAP
        if self._slow_pending():
            cap = max(cap, SFTP_SLOW_SERVER_CAP)
        if now - silent_since >= cap:
            chan.close()
            raise SlowServerTimeout(
                errno.ETIMEDOUT,
                f"SFTP: the server is connected but did not answer a request for "
                f"{_duration(cap)}; it may be stuck. Try again later.",
            )
        limit = chan.gettimeout() or SFTP_IO_TIMEOUT
        if not transport_answers(chan.get_transport(), limit, lambda: chan.closed):
            if chan.closed:
                raise EOFError()
            raise TimeoutError()  # silent and no answer to a keepalive
        log.info(
            "SFTP: no answer for %.0f s, but the SSH connection answers; waiting on "
            "(a slow server)", time.monotonic() - silent_since,
        )
        return silent_since

    @classmethod
    def from_transport(cls, t, window_size=None, max_packet_size=None, timeout=None):
        """paramiko's, with the channel time-out (*timeout*, default
        :data:`SFTP_IO_TIMEOUT`) set before the SFTP version exchange - a
        server gone silent then fails the open too, instead of hanging
        it."""
        limit = timeout if timeout else SFTP_IO_TIMEOUT

        def silent() -> TimeoutError:
            return TimeoutError(
                errno.ETIMEDOUT,
                f"SFTP: the server did not open a channel within {limit:g} s; the "
                f"network connection is probably lost. Reconnect and try again.",
            )

        try:
            chan = t.open_session(
                window_size=window_size, max_packet_size=max_packet_size, timeout=limit
            )
        except paramiko.SSHException as exc:
            if str(exc).startswith("Timeout opening channel"):
                raise silent() from exc
            raise
        if chan is None:
            return None
        chan.settimeout(limit)
        # paramiko waits for the subsystem's answer without a time-out;
        # closing the channel ends that wait.
        timed_out: list[bool] = []

        def give_up() -> None:
            timed_out.append(True)
            chan.close()

        timer = threading.Timer(limit, give_up)
        timer.daemon = True
        timer.start()
        try:
            chan.invoke_subsystem("sftp")
        except (paramiko.SSHException, EOFError) as exc:
            if timed_out:
                raise silent() from exc
            raise
        finally:
            timer.cancel()
        return cls(chan)


class _HostileAnswer(paramiko.SFTPError):
    """An answer that cannot be what it claims (a count its bytes cannot
    carry): its channel is closed, not read on."""


def _over_budget(path: str) -> OSError:
    """The error of a listing past MAX_LISTING_BYTES: an OSError (EFBIG),
    marked so its channel is closed, not read on (see _HostileAnswer)."""
    exc = OSError(errno.EFBIG, f"{path}: more than {MAX_LISTING_BYTES} bytes in the listing's "
                  "answers; not listed")
    exc.axross_hostile = True
    return exc


def _bytes_left(msg) -> int:
    """Bytes of *msg* (a paramiko Message) not read yet."""
    packet = msg.packet
    return len(packet.getbuffer()) - packet.tell()


#: Most extended attributes one attribute block may carry (none is kept;
#: OpenSSH sends none). More - or more than the packet can hold - is a
#: malformed answer: a count of 0xFFFFFFFF spun a worker in paramiko.
MAX_EXTENDED_ATTRIBUTES = 1024


def _bounded_unpack(self, msg) -> None:
    """paramiko's SFTPAttributes._unpack with every count bounded by the
    bytes that carry it; the extended attributes are read past, not kept."""
    self._flags = msg.get_int()
    if self._flags & self.FLAG_SIZE:
        self.st_size = msg.get_int64()
    if self._flags & self.FLAG_UIDGID:
        self.st_uid = msg.get_int()
        self.st_gid = msg.get_int()
    if self._flags & self.FLAG_PERMISSIONS:
        self.st_mode = msg.get_int()
    if self._flags & self.FLAG_AMTIME:
        self.st_atime = msg.get_int()
        self.st_mtime = msg.get_int()
    if self._flags & self.FLAG_EXTENDED:
        count = msg.get_int()
        if count > MAX_EXTENDED_ATTRIBUTES or count * 8 > _bytes_left(msg):
            raise _HostileAnswer(
                f"malformed attributes ({count} extended attributes in "
                f"{_bytes_left(msg)} bytes)")
        for _ in range(count):
            msg.get_string()
            msg.get_string()
        self.attr = {}


def _install_bounded_attribute_parser() -> None:
    """Every attribute block paramiko unpacks here - stat, lstat, fstat, a
    listing - goes through :func:`_bounded_unpack`."""
    paramiko.SFTPAttributes._unpack = _bounded_unpack


_install_bounded_attribute_parser()


class _AnswersByNumber:
    """Receives the answers to pipelined requests (registered as their
    owner, so paramiko hands each one over, whoever reads it) and keeps
    them by request number."""

    #: Called with the request number of every answer kept (or None).
    on_answer = None

    def __init__(self) -> None:
        self.answers: dict[int, tuple[int, paramiko.Message]] = {}
        #: Bytes of every answer received so far (names, longnames,
        #: attributes - extended ones too) and the size of the last one.
        self.received = 0
        self.last_size = 0
        #: Set once the listing is over: late answers are only counted.
        self.discard = False

    def _async_response(self, t, msg, num) -> None:
        size = len(msg.asbytes())
        self.received += size
        self.last_size = size
        if not self.discard:
            self.answers[num] = (t, msg)
            if self.on_answer is not None:
                self.on_answer(num)


def _listdir_attr(sftp: paramiko.SFTPClient, path: str) -> list[paramiko.SFTPAttributes]:
    """``sftp.listdir_attr(path)`` with pipelined READDIRs and names decoded
    leniently.

    paramiko sends one READDIR and waits for its answer before the next;
    each answer is a slice of the folder (OpenSSH about 100 names), so a big
    folder cost a round trip per slice and every folder one more for the
    answer that says "end". Here :data:`LISTING_READDIRS_IN_FLIGHT` stay on
    the wire; answers are used in request order, and those after the end
    of the folder are ignored.

    SFTP v3 names are bytes and OpenSSH sends them as stored, so a latin-1
    name is ordinary; paramiko decodes each strictly as UTF-8
    (Message.get_text) and one such name made the whole folder unlistable
    with UnicodeDecodeError. Names are decoded with ``surrogateescape``,
    as Python decodes a local file name: ``caf\\xe9.txt`` lists as
    ``"caf\\udce9.txt"``, and :class:`_SurrogateSftpClient` encodes it back
    to the same bytes, so the entry can be opened, renamed and removed.
    """
    from collections import deque

    from paramiko.sftp import CMD_CLOSE, CMD_HANDLE, CMD_NAME, CMD_OPENDIR, CMD_READDIR, CMD_STATUS

    def text(raw: bytes) -> str:
        return raw.decode("utf-8", errors="surrogateescape")

    t, msg = sftp._request(CMD_OPENDIR, sftp._adjust_cwd(path))
    if t != CMD_HANDLE:
        raise paramiko.SFTPError("Expected handle")
    handle = msg.get_binary()
    receiver = _AnswersByNumber()
    in_flight: deque[int] = deque()
    entries: list[paramiko.SFTPAttributes] = []
    overlong = 0

    def over_budget() -> None:
        # Everything the answers carried counts - an entry's extended
        # attributes too (900 KiB each took a listing past 2.5 GB while
        # only the names were counted).
        if receiver.received > MAX_LISTING_BYTES:
            raise _over_budget(path)

    def send() -> None:
        in_flight.append(sftp._async_request(receiver, CMD_READDIR, handle))

    hostile = False
    try:
        for _ in range(LISTING_READDIRS_IN_FLIGHT):
            send()
        while in_flight:
            num = in_flight.popleft()
            while num not in receiver.answers:
                sftp._read_response()
                over_budget()
            t, msg = receiver.answers.pop(num)
            if t == CMD_STATUS:
                try:
                    sftp._convert_status(msg)  # OSError for a failure
                except EOFError:  # the end of the folder
                    break
            if t != CMD_NAME:
                raise paramiko.SFTPError("Expected name response")
            count = msg.get_int()
            # An entry is at least 12 bytes (two string lengths and the
            # attribute flags): a count the packet cannot carry is a lie -
            # paramiko reads zeros past its end, and 0xFFFFFFFF of them grew
            # a worker to gigabytes.
            if count * 12 > _bytes_left(msg):
                raise _HostileAnswer(
                    f"{path}: malformed listing answer ({count} entries in "
                    f"{_bytes_left(msg)} bytes)")
            for index in range(count):
                if index % 1024 == 1023:
                    # A long answer: a cancelled call or a closed connection
                    # (remote_close) stops it here too.
                    transfer_hooks.check()
                    if getattr(getattr(sftp, "sock", None), "closed", False):
                        raise EOFError("the SFTP channel was closed")
                if len(entries) > MAX_LISTING_ENTRIES:
                    raise OSError(errno.EFBIG,
                                  f"{path}: more than {MAX_LISTING_ENTRIES} entries; not listed")
                raw_name = msg.get_string()
                msg.get_string()  # the ls -l longname: never kept (it doubled each entry)
                if len(raw_name) > MAX_NAME_BYTES:
                    paramiko.SFTPAttributes._from_msg(msg)  # its attributes, skipped
                    overlong += 1
                    continue
                filename = text(raw_name)
                attr = paramiko.SFTPAttributes._from_msg(msg, filename, "")
                attr.attr = {}  # extended attributes: nothing here reads them
                if filename not in (".", ".."):
                    entries.append(attr)
            if len(entries) > MAX_LISTING_ENTRIES:
                raise OSError(errno.EFBIG,
                              f"{path}: more than {MAX_LISTING_ENTRIES} entries; not listed")
            over_budget()
            # A cancelled transfer or MCP call (core.transfer_hooks) stops
            # a long listing between two answers, so does a closed channel.
            transfer_hooks.check()
            if getattr(getattr(sftp, "sock", None), "closed", False):
                raise EOFError("the SFTP channel was closed")
            # Big answers (a MiB and more): one READDIR on the wire at a
            # time, so the answers held at once stay few.
            if receiver.last_size <= (1 << 20) or not in_flight:
                send()
    except _HostileAnswer:
        hostile = True
        raise
    except OSError as exc:
        hostile = bool(getattr(exc, "axross_hostile", False))
        raise
    finally:
        receiver.discard = True
        if hostile:
            # A malformed or oversized answer: the READDIRs still out are
            # not read (16 of 15 MB each), the channel is closed instead -
            # this thread opens a new one for its next request.
            try:
                sftp.sock.close()
            except Exception:  # noqa: BLE001 - closing is all that is left
                pass
            receiver.answers.clear()
            # (no CLOSE of the handle either: the channel is gone)
        else:
            # The READDIRs still out are answered before CLOSE (end of
            # folder, or whatever a failing server says): nothing is left
            # for another request to read. A dead connection raises its
            # own error here.
            try:
                while any(owner is receiver for owner in list(sftp._expecting.values())):
                    sftp._read_response()
            finally:
                receiver.answers.clear()
    sftp._request(CMD_CLOSE, handle)
    if overlong:
        log.warning("SFTP %s: %d entries with names over %d bytes left out", path, overlong,
                    MAX_NAME_BYTES)
    return entries


#: known_hosts key type -> the host key algorithms that verify such a key.
#: An "ssh-rsa" entry is negotiated as rsa-sha2-512/256 (same key, SHA-2
#: signatures); paramiko no longer offers SHA-1 "ssh-rsa" by default.
_HOST_KEY_ALGORITHMS = {
    "ssh-rsa": ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"),
}


def _wait_readable(chan, timeout: float) -> bool:
    """Wait up to *timeout* s for *chan* to signal data (paramiko's pipe
    behind ``fileno``). Only a wait: that pipe can miss a wake-up."""
    from core.posix_compat import wait_io

    rlist, _ = wait_io([chan], timeout=timeout)
    return chan in rlist


#: Channel ids of the probe's channel opens: above paramiko's own (24
#: bits), so an answer to one is never taken for a channel of paramiko's.
_PROBE_CHANNEL_BASE = 0x7F000000
_PROBE_CHANNEL_SPAN = 0x00FFFFFF


class _TransportWatch:
    """The receive side of one transport, as the probes need it - hooked
    per instance (paramiko keeps its handler table per transport for
    this); paramiko's own events and fields are never replaced:

    * every packet the transport reads wakes the probes waiting: ANY
      packet - output of another channel, a window adjust, an answer -
      proves the connection carries traffic both ways;
    * the answers to the probes' own keepalive requests and channel
      opens are taken here, before paramiko's handlers: its
      ``completion_event``, ``global_response`` and ``saved_exception``
      belong to whoever else waits on them.
    """

    def __init__(self, transport) -> None:
        self.lock = threading.Lock()
        self.waiters: set[threading.Event] = set()
        #: Keepalive requests (want-reply) sent and not answered yet:
        #: answers come in order (RFC 4254 4), so that many are ours.
        #: axross itself sends no other global request that wants one.
        self.pending_requests = 0
        #: A probe went unanswered and nothing has arrived since
        #: (transport_suspect); the next packet read clears it.
        self.unanswered = False
        self._next_channel = 0
        ref = weakref.ref(transport)
        packetizer = transport.packetizer
        read = packetizer.read_message

        def read_message():
            result = read()
            self.unanswered = False
            if self.waiters:
                self._wake()
            return result

        common = paramiko.common
        table = transport._handler_table
        hooks = {
            common.MSG_REQUEST_SUCCESS: self._global_answer,
            common.MSG_REQUEST_FAILURE: self._global_answer,
            common.MSG_CHANNEL_OPEN_SUCCESS: lambda orig: self._open_answer(orig, ref, True),
            common.MSG_CHANNEL_OPEN_FAILURE: lambda orig: self._open_answer(orig, ref, False),
        }
        wrapped = {ptype: hook(table[ptype]) for ptype, hook in hooks.items()}
        table.update(wrapped)
        packetizer.read_message = read_message

    def _wake(self) -> None:
        with self.lock:
            waiters, self.waiters = self.waiters, set()
        for event in waiters:
            event.set()

    def wait_for_traffic(self, event: threading.Event) -> None:
        with self.lock:
            self.waiters.add(event)

    def _global_answer(self, original):
        # The handlers wake the probes too: the table is looked up per
        # packet, while a read_message already running when the watch
        # was installed still returns its packet past the hook.
        def handler(m):
            if self.waiters:
                self._wake()
            with self.lock:
                ours = self.pending_requests > 0
                if ours:
                    self.pending_requests -= 1
            if not ours:
                return original(m)
            return None

        return handler

    def _open_answer(self, original, ref, success: bool):
        def handler(m):
            if self.waiters:
                self._wake()
            pos = m.packet.tell()
            chanid = m.get_int()
            if not _PROBE_CHANNEL_BASE <= chanid <= _PROBE_CHANNEL_BASE + _PROBE_CHANNEL_SPAN:
                m.packet.seek(pos)
                return original(m)
            if success:
                # A server that opened the unknown channel all the same:
                # closed again (its later messages for it are ignored,
                # the id is in channels_seen).
                remote = m.get_int()
                transport = ref()
                if transport is not None:
                    close = paramiko.Message()
                    close.add_byte(paramiko.common.cMSG_CHANNEL_CLOSE)
                    close.add_int(remote)
                    try:
                        transport._send_message(close)
                    except Exception as exc:  # noqa: BLE001 - the transport decides
                        log.debug("SSH probe channel not closed: %s", exc)
            return None

        return handler

    def send_request(self, transport) -> None:
        m = paramiko.Message()
        m.add_byte(paramiko.common.cMSG_GLOBAL_REQUEST)
        m.add_string(_KEEPALIVE_REQUEST)
        m.add_boolean(True)
        with self.lock:
            self.pending_requests += 1
        transport._send_user_message(m)

    def send_channel_open(self, transport) -> None:
        """A channel open of a type no server offers: RFC 4254 5.1 says
        every server answers it (OPEN_FAILURE) - also one that drops
        global requests without the answer RFC 4254 4 asks for."""
        with transport.lock:
            chanid = _PROBE_CHANNEL_BASE + self._next_channel
            self._next_channel = (self._next_channel + 1) % _PROBE_CHANNEL_SPAN
            # Whatever comes later for it is "a dead channel" to paramiko
            # (ignored), never "an unknown channel" (which ends the transport).
            transport.channels_seen[chanid] = True
        m = paramiko.Message()
        m.add_byte(paramiko.common.cMSG_CHANNEL_OPEN)
        m.add_string(_KEEPALIVE_REQUEST)
        m.add_int(chanid)
        m.add_int(0)
        m.add_int(32768)
        transport._send_user_message(m)


#: The receive hooks per transport (weak: a closed transport goes).
_WATCHES: "weakref.WeakKeyDictionary[object, _TransportWatch]" = weakref.WeakKeyDictionary()


def _transport_watch(transport) -> _TransportWatch | None:
    """The :class:`_TransportWatch` of *transport*, installed on first
    use; None for something that is no paramiko transport (a stand-in)."""
    with _PROBES_LOCK:
        try:
            watch = _WATCHES.get(transport)
        except TypeError:
            return None
        if watch is not None:
            return watch
        if not isinstance(getattr(transport, "_handler_table", None), dict) or \
                getattr(transport, "packetizer", None) is None:
            return None
        try:
            watch = _TransportWatch(transport)
        except Exception as exc:  # noqa: BLE001 - another paramiko: no probe
            log.debug("SSH keepalive probe not available: %s", exc)
            return None
        _WATCHES[transport] = watch
        return watch


class _Probe:
    """One keepalive probe on a transport and whether anything came back."""

    def __init__(self) -> None:
        self.answered = threading.Event()

    def start(self, transport, watch: _TransportWatch | None, timeout: float) -> None:
        if watch is not None:
            watch.wait_for_traffic(self.answered)
        # Sent from a thread of its own: a send waits behind a write stuck
        # in the socket buffer of a dead link (paramiko retries for ever).
        threading.Thread(
            target=self._send, args=(transport, watch, timeout),
            name="axross-ssh-probe", daemon=True,
        ).start()

    def _send(self, transport, watch: _TransportWatch | None, timeout: float) -> None:
        if watch is None:
            return
        try:
            # OpenSSH's own keepalive (ServerAliveInterval) first. Any
            # answer counts - OpenSSH and paramiko servers refuse it
            # (REQUEST_FAILURE), which proves traffic both ways as well.
            watch.send_request(transport)
            # A server that drops global requests unanswered (some
            # appliances) gets a channel open half-way through the wait.
            if self.answered.wait(max(timeout, 0.0) / 2) or not transport.is_active():
                return
            watch.send_channel_open(transport)
        except Exception as exc:  # noqa: BLE001 - a dead transport does not answer
            log.debug("SSH keepalive probe not sent: %s", exc)


#: The probe in flight per transport (weak: a closed transport goes).
_PROBES: "weakref.WeakKeyDictionary[object, _Probe]" = weakref.WeakKeyDictionary()
_PROBES_LOCK = threading.RLock()


def transport_answers(transport, timeout: float, stop: Callable[[], bool] | None = None) -> bool:
    """Whether the SSH connection *transport* still carries traffic both
    ways: anything arrives within *timeout* seconds of a keepalive
    request (``keepalive@openssh.com``, want-reply) - its answer, or any
    other packet; for a server that drops the request unanswered, the
    answer to a channel open sent half-way. A request whose answer is
    slow then waits on (the server is alive, only busy) instead of
    failing as a lost network. Probes of one transport share the probe
    in flight. *stop* (polled) ends the wait early - Cancel - with False."""
    if transport is None or not transport.is_active():
        return False
    watch = _transport_watch(transport)
    with _PROBES_LOCK:
        try:
            probe = _PROBES.get(transport)
        except TypeError:  # not weakly referenceable (a stand-in)
            probe = None
        if probe is None or probe.answered.is_set():
            probe = _Probe()
            try:
                _PROBES[transport] = probe
            except TypeError:
                pass
            probe.start(transport, watch, timeout)
    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        left = deadline - time.monotonic()
        if probe.answered.wait(min(0.1, max(left, 0.0))):
            return transport.is_active()
        if not transport.is_active() or (stop is not None and stop()):
            return False
        if left <= 0:
            if watch is not None:
                watch.unanswered = True
            log.warning("SSH connection did not answer a keepalive for %.0f s", timeout)
            return False


def transport_suspect(transport) -> bool:
    """Whether *transport*'s last keepalive probe went unanswered and
    nothing has arrived since: the connection is most likely gone. A
    network gone silent sends no FIN or RST, so paramiko keeps the
    transport "active" for as long as TCP takes to give up (minutes); the
    sessions' ``connected`` asks this too, so the connection manager
    opens a new session on a reconnect instead of handing out the dead
    one again. Any packet that arrives clears it: a network that comes
    back keeps the session working for whoever still holds it."""
    try:
        watch = _WATCHES.get(transport)
    except TypeError:
        return False
    return watch is not None and watch.unanswered


class _ExecWatch:
    """Watches one exec channel (a checksum, a server-side copy, df, ln)
    from a thread of its own while the command runs:

    * Cancel of the running transfer (core.transfer_hooks) closes the
      channel at once - a read blocked on it wakes - and :attr:`cancelled`
      tells the caller to raise InterruptedError;
    * no output for *idle* seconds: the SSH connection is asked whether
      it is alive (:func:`transport_answers`). Alive, the command just
      takes long (a big file hashed, copied on the server) and is waited
      for; dead, the channel is closed and :attr:`timed_out` set. A
      fixed read time-out would fail a long legitimate command; none at
      all hung for ever on a network gone silent (keepalive is off by
      default, docs/OPSEC.md #2).
    """

    POLL = 0.2

    def __init__(self, chan, transport, idle: float, hooks=None) -> None:
        from core import transfer_hooks

        self.cancelled = False
        self.timed_out = False
        self._chan = chan
        self._transport = transport
        self._idle = max(float(idle), 0.5)
        hooks = hooks if hooks is not None else transfer_hooks.current()
        self._cancel = getattr(hooks, "cancel_event", None)
        if self._cancel is not None and self._cancel.is_set():
            raise InterruptedError(transfer_hooks.CANCELLED)
        self._last = time.monotonic()
        self._stopped = threading.Event()
        threading.Thread(target=self._run, name="axross-exec-watch", daemon=True).start()

    def touch(self) -> None:
        """Output arrived: the command is alive."""
        self._last = time.monotonic()

    def _should_stop(self) -> bool:
        return self._stopped.is_set() or (self._cancel is not None and self._cancel.is_set())

    def _run(self) -> None:
        while not self._stopped.is_set():
            if self._cancel is not None:
                fired = self._cancel.wait(self.POLL)
            else:
                fired = False
                self._stopped.wait(self.POLL)
            if self._stopped.is_set():
                return
            if fired:
                self.cancelled = True
                self._close()
                return
            if time.monotonic() - self._last < self._idle:
                continue
            if transport_answers(self._transport, self._idle, self._should_stop):
                self.touch()  # alive: the command takes its time
                continue
            if self._stopped.is_set():
                return
            if self._cancel is not None and self._cancel.is_set():
                self.cancelled = True
            else:
                self.timed_out = True
            self._close()
            return

    def _close(self) -> None:
        # In a thread of its own: closing sends a message, which can wait
        # behind a write stuck on a dead link.
        threading.Thread(target=self._close_now, daemon=True).start()

    def _close_now(self) -> None:
        try:
            self._chan.close()
        except Exception:  # noqa: BLE001 - closing a dead channel may fail
            pass

    def stop(self) -> None:
        self._stopped.set()


def drain_exec_channel(
    chan,
    *,
    timeout: float | None,
    stdout_cap: int,
    stderr_cap: int,
    label: str,
    on_output: Callable[[], object] | None = None,
) -> "ExecResult":
    """Read an exec channel's stdout and stderr to the end, each clipped
    at its cap, and return the :class:`~models.exec_result.ExecResult`.

    Both streams are drained together: reading one to its end while the
    other is unread deadlocks once the remote fills the channel window.
    Bytes above a cap are read and discarded so the remote can finish.
    Raises ``TimeoutError`` (an OSError) when the command has not exited
    after *timeout* seconds - the channel timeout only bounds a blocking
    recv, which this loop never makes. *on_output* is called whenever
    bytes arrived (an :class:`_ExecWatch` learns the command is alive).
    A channel closed under the loop (Cancel, a dead connection) ends it.
    """
    from models.exec_result import ExecResult

    stdout_buf = bytearray()
    stderr_buf = bytearray()
    stdout_truncated = False
    stderr_truncated = False
    deadline = time.monotonic() + timeout if timeout is not None else None
    while True:
        if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
            break
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"{label}: the command did not finish within {timeout:g} s")
        # Readiness is asked of the channel itself; the wait is only a
        # wait. paramiko's pipe behind fileno() can miss a wake-up (measured
        # under load: not readable 97 times in a row with data pending), and
        # a loop that read only after a wake-up never read again.
        if not (chan.recv_ready() or chan.recv_stderr_ready()):
            if chan.closed:
                break
            _wait_readable(chan, 0.1)
        if on_output is not None and (chan.recv_ready() or chan.recv_stderr_ready()):
            on_output()
        if chan.recv_ready():
            room = stdout_cap - len(stdout_buf)
            if room > 0:
                chunk = chan.recv(min(65536, room))
                if chunk:
                    stdout_buf.extend(chunk)
            else:
                # Cap reached — drain to keep the remote
                # from blocking on a full pipe, but discard.
                chan.recv(65536)
                stdout_truncated = True
        if chan.recv_stderr_ready():
            room = stderr_cap - len(stderr_buf)
            if room > 0:
                chunk = chan.recv_stderr(min(65536, room))
                if chunk:
                    stderr_buf.extend(chunk)
            else:
                chan.recv_stderr(65536)
                stderr_truncated = True
    # Final drain after exit-status arrives.
    while chan.recv_ready():
        room = stdout_cap - len(stdout_buf)
        if room <= 0:
            chan.recv(65536)
            stdout_truncated = True
            continue
        stdout_buf.extend(chan.recv(min(65536, room)))
    while chan.recv_stderr_ready():
        room = stderr_cap - len(stderr_buf)
        if room <= 0:
            chan.recv_stderr(65536)
            stderr_truncated = True
            continue
        stderr_buf.extend(chan.recv_stderr(min(65536, room)))
    return ExecResult(
        returncode=chan.recv_exit_status(),
        stdout=bytes(stdout_buf),
        stderr=bytes(stderr_buf),
        truncated_stdout=stdout_truncated,
        truncated_stderr=stderr_truncated,
    )


class CleanEnvProxyCommand(paramiko.ProxyCommand):
    """paramiko's ProxyCommand, but the command gets a clean environment.

    paramiko starts it with ``subprocess.Popen`` and no ``env``, so it
    inherits this process's - in a frozen one-file build that includes
    LD_LIBRARY_PATH pointing at the extraction folder, and a ``bash -c``,
    ``nc`` or ``ssh -W`` jump resolves its libraries against the bundled
    ones (dist/axross-full 0.13.22: ``bash -c true`` "symbol lookup
    error"). paramiko's ``__init__`` takes no environment, so this one
    sets the same three attributes its send/recv/close use (a test holds
    them equal to paramiko's) and starts the process itself."""

    def __init__(self, command_line: str) -> None:
        # Deliberately not super().__init__(): it would start the command
        # with the inherited environment.
        self.cmd = shlex.split(command_line)
        self.process = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=clean_child_env(),
        )
        self.timeout = None


def dropped_connection(name: str) -> ConnectionAbortedError:
    """The error for a request on an SSH connection the other side or the
    network has closed: ConnectionAbortedError, which
    core.user_errors.describe turns into "closed by the other side,
    reconnect". The bare "Not connected" (SFTP) and "SSH session not
    active" (SCP) gave no hint what to do."""
    return ConnectionAbortedError(
        errno.ECONNABORTED, f"Not connected: the SSH connection {name} was closed"
    )


class SlowServerTimeout(TimeoutError):
    """An SFTP request the server left unanswered for
    :data:`SFTP_SLOW_SERVER_CAP` while the SSH connection kept answering:
    the server is there, but busy or stuck - not a lost network."""


class _ExecRefused(OSError):
    """The server turned an exec request down while the connection stands
    (it runs no commands, or not this one)."""


class HostKeyVerificationError(paramiko.SSHException):
    """Base class for SSH host key verification errors."""


class UnknownHostKeyError(HostKeyVerificationError):
    """Raised when a server host key is not present in known_hosts."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(f"Unknown host key for {host} ({key_type}, SHA256:{fingerprint_sha256})")
        self.host = host
        self.key_type = key_type
        self.fingerprint_sha256 = fingerprint_sha256


class HostKeyMismatchError(HostKeyVerificationError):
    """Raised when a server host key does not match known_hosts."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(f"Host key mismatch for {host} ({key_type}, SHA256:{fingerprint_sha256})")
        self.host = host
        self.key_type = key_type
        self.fingerprint_sha256 = fingerprint_sha256


class RevokedHostKeyError(HostKeyMismatchError):
    """Raised when known_hosts marks the server host key ``@revoked``."""

    def __init__(self, host: str, key_type: str, fingerprint_sha256: str):
        super().__init__(host, key_type, fingerprint_sha256)
        self.args = (f"Host key for {host} is revoked ({key_type}, SHA256:{fingerprint_sha256})",)


class KnownHosts(paramiko.HostKeys):
    """An OpenSSH known_hosts file, read line by line.

    paramiko's HostKeys.load raises InvalidHostKey for a line with a
    marker (``@cert-authority``, ``@revoked``) or a broken key, which
    failed every connect. Here a broken line is skipped, a
    ``@cert-authority`` line too (paramiko cannot check host
    certificates), and a ``@revoked`` key is remembered and refused for
    every host, never loaded as a trusted key. Lookup semantics stay
    paramiko's: the first key of a type listed for a host wins.
    """

    def __init__(self) -> None:
        super().__init__()
        self._revoked: set[bytes] = set()

    def load(self, filename) -> None:
        trusted: list[paramiko.hostkeys.HostKeyEntry] = []
        with open(filename, encoding="utf-8", errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                marker = None
                if line.startswith("@"):
                    marker, _, line = line.partition(" ")
                    line = line.strip()
                entry = self._parse(line, lineno)
                if entry is None:
                    continue
                if marker == "@revoked":
                    self._revoked.add(entry.key.asbytes())
                elif marker is None:
                    trusted.append(entry)
                else:
                    log.debug("known_hosts line %d: %s line skipped", lineno, marker)
        for entry in trusted:
            if self.is_revoked(entry.key):
                continue
            key_type = entry.key.get_name()
            for host in entry.hostnames:
                known = self.lookup(host)
                if known is None or key_type not in known:
                    self.add(host, key_type, entry.key)

    @staticmethod
    def _parse(line: str, lineno: int):
        try:
            entry = paramiko.hostkeys.HostKeyEntry.from_line(line, lineno)
        except Exception as exc:  # noqa: BLE001 - one bad line must not void the file
            log.debug("known_hosts line %d skipped: %s", lineno, exc)
            return None
        if entry is None or entry.key is None:
            return None
        return entry

    def is_revoked(self, key: paramiko.PKey) -> bool:
        return key.asbytes() in self._revoked

    def save(self, filename) -> None:
        # Rewriting would drop comments, marker lines and key types
        # paramiko does not know; append_known_host adds a line instead.
        raise NotImplementedError("known_hosts is only appended to")


def load_known_hosts(path: Path) -> KnownHosts:
    """The known_hosts at *path*; empty when it is missing or unreadable."""
    host_keys = KnownHosts()
    if not path.exists():
        return host_keys
    try:
        host_keys.load(str(path))
        log.debug("Loaded known_hosts from %s", path)
    except OSError as e:
        log.warning("Could not load known_hosts: %s", e)
    return host_keys


def _hashes_host_names(path: Path) -> bool:
    """True when known_hosts already stores hashed host names (HashKnownHosts)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                fields = raw.split()
                if fields and fields[0].startswith("@"):
                    fields = fields[1:]
                if fields and fields[0].startswith("|1|"):
                    return True
    except OSError:
        pass
    return False


def append_known_host(path: Path, alias: str, key: paramiko.PKey) -> None:
    """Add one ``alias keytype base64`` line at the end of known_hosts.

    The rest of the file and its mode stay as they are; a new file is
    created 0600 (a new parent folder 0700). The host name is hashed
    when the file already hashes its host names.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = paramiko.HostKeys.hash_host(alias) if _hashes_host_names(path) else alias
    line = f"{name} {key.get_name()} {key.get_base64()}\n".encode()
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            line = b"\n" + line
        os.write(fd, line)
    finally:
        os.close(fd)


class NoAgentKeysError(OSError):
    """No SSH agent answered, or it holds no key: nothing was offered to
    the server, so "the server refused the login" would be wrong."""


def agent_with_keys() -> tuple[paramiko.Agent, list]:
    """The running SSH agent (SSH_AUTH_SOCK) and its keys; the caller
    closes the agent. NoAgentKeysError when there is none or it is empty:
    paramiko then raised "No keys available from SSH agent" as an
    AuthenticationException (SFTP) or "No authentication methods
    available" (SCP), both read as a refused login."""
    from core.i18n import tr

    agent = paramiko.Agent()
    keys = list(agent.get_keys())
    if not keys:
        agent.close()
        raise NoAgentKeysError(tr(
            "No SSH agent answered, or it holds no keys. Start ssh-agent and add your "
            "key with ssh-add, or choose a key file for this connection."))
    return agent, keys


def host_key_aliases(host: str, port: int) -> list[str]:
    """The known_hosts names of *host*:*port*, the one to store first.

    OpenSSH lower-cases the host name before it reads or writes
    known_hosts (``ssh Server.Example`` stores ``server.example``); a
    profile host typed with a capital letter was "a new host key" for a
    host already known, and the user was asked to trust it again. The
    name as typed follows, for entries axross stored that way before."""
    names = []
    for name in (host.lower(), host):
        alias = name if port == 22 else f"[{name}]:{port}"
        if alias not in names:
            names.append(alias)
    return names


def _private_key_classes() -> list[type[paramiko.PKey]]:
    classes = [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey]
    # DSSKey was removed in paramiko 4.x
    if hasattr(paramiko, "DSSKey"):
        classes.append(paramiko.DSSKey)
    return classes


def load_private_key(path: str, passphrase: str) -> paramiko.PKey:
    """Load the private key at *path*, trying every key format.

    An encrypted key without its passphrase, or with a wrong one, raises
    PasswordRequiredException (naming the file), so a caller can ask for
    the passphrase; any other unreadable key raises SSHException. Both
    used to end in one "Cannot load key", and Quick Connect never knew a
    passphrase was what was missing."""
    passphrase_arg = passphrase or None
    encrypted = False
    for cls in _private_key_classes():
        try:
            return cls.from_private_key_file(path, password=passphrase_arg)
        except paramiko.PasswordRequiredException:
            encrypted = True
        except paramiko.SSHException:
            continue
    if passphrase_arg is not None and not encrypted:
        # A wrong passphrase fails like a damaged file ("Bad password or
        # corrupt", "checkints do not match"); without one, an encrypted
        # key says so.
        for cls in _private_key_classes():
            try:
                cls.from_private_key_file(path, password=None)
            except paramiko.PasswordRequiredException:
                encrypted = True
                break
            except paramiko.SSHException:
                continue
            break  # it loads without a passphrase: not an encrypted key
    if encrypted:
        if passphrase_arg is None:
            raise paramiko.PasswordRequiredException(
                f"The key {path} is encrypted: it needs its passphrase"
            )
        raise paramiko.PasswordRequiredException(f"Wrong passphrase for the key {path}")
    raise paramiko.SSHException(f"Cannot load key from {path}")


class SSHSession(SessionLifecycle):
    """SFTP file backend over SSH, implementing the FileBackend protocol."""

    def __init__(self, profile: ConnectionProfile):
        self._profile = profile
        self._transport: paramiko.Transport | None = None
        self._home_dir: str = "/"
        self._thread_local = threading.local()
        self._thread_sftp: dict[int, paramiko.SFTPClient] = {}
        self._sftp_lock = threading.Lock()
        #: Set by :meth:`bound_requests` (the MCP server): the longest one
        #: SFTP request may go unanswered, keepalives or not, and how often
        #: a waiting request looks at its call's cancel.
        self.sftp_request_deadline: float | None = None
        self.sftp_poll_seconds: float | None = None
        self._known_hosts_path = Path.home() / ".ssh" / "known_hosts"
        #: Why checksum() cannot work on this session, once the server said
        #: so for good: the hash tool is not installed, or the server
        #: refuses to run commands. Every later call answers at once
        #: instead of opening a channel per file to hear it again.
        self._checksum_unavailable: dict[str, str] = {}

    @property
    def name(self) -> str:
        return f"{self._profile.username}@{self._profile.host}"

    @property
    def connected(self) -> bool:
        """False also while the connection did not answer its last
        keepalive (transport_suspect): a reconnect then opens a new one."""
        transport = self._transport
        return (
            transport is not None and transport.is_active() and not transport_suspect(transport)
        )

    @property
    def transport(self) -> paramiko.Transport | None:
        return self._transport

    def security_info(self):
        """The negotiated SSH protection (cipher, key exchange, host key) for
        the security badge; None when not connected (the profile tells)."""
        from core.conn_security import ssh_transport

        return ssh_transport(self._transport, "SFTP over SSH")

    @property
    def sftp(self) -> paramiko.SFTPClient:
        sftp = self._get_sftp_client()
        if sftp is None:
            if self._transport is not None:
                # The server or the network dropped it (not a disconnect()):
                # core.user_errors says to reconnect.
                raise dropped_connection(self.name)
            raise ConnectionError("Not connected")
        return sftp

    def connect(
        self,
        password: str = "",
        key_passphrase: str = "",
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None = None,
        resolve_profile: object | None = None,
    ) -> None:
        """Establish SSH connection and open SFTP channel."""
        profile = self._profile
        family = self._socket_family()

        try:
            # Create socket (ProxyCommand, SOCKS/HTTP proxy, or direct)
            if profile.proxy_command:
                require_confirmed_proxy_command(profile)
                cmd = expand_proxy_command(
                    profile.proxy_command,
                    host=profile.host,
                    port=profile.port,
                    username=profile.username,
                    resolve_profile=resolve_profile,
                )
                log.info("Using ProxyCommand for %s: %s", profile.host, redact_text(cmd))
                sock = CleanEnvProxyCommand(cmd)
            elif (profile.proxy_type or "none").lower() != "none":
                if not profile.proxy_host:
                    raise OSError(
                        f"SFTP proxy_type={profile.proxy_type!r} requires "
                        "proxy_host; refusing direct traffic."
                    )
                proxy_pw = profile.get_proxy_password() or ""
                proxy_config = ProxyConfig(
                    proxy_type=profile.proxy_type,
                    host=profile.proxy_host,
                    port=profile.proxy_port,
                    username=profile.proxy_username,
                    password=proxy_pw,
                )
                sock = create_proxy_socket(
                    proxy_config,
                    profile.host,
                    profile.port,
                    family=family,
                )
            else:
                sock = create_direct_socket(profile.host, profile.port, family=family)
            # Without it every request after an exec channel waited ~40 ms
            # for a delayed ACK (Nagle); see core.proxy.enable_tcp_nodelay.
            enable_tcp_nodelay(sock)
            # And acknowledge at once: a server's Nagle held its second
            # small answer ~40 ms for our delayed ACK (core.proxy).
            sock = enable_quick_ack(sock)

            log.info("Creating SSH transport to %s:%d", profile.host, profile.port)
            self._transport = paramiko.Transport(sock)
            self._transport.local_version = SSH_LOCAL_VERSION
            # Before the transport reads: every packet counts for a probe.
            _transport_watch(self._transport)
            self._prefer_known_host_key_types()
            self._transport.start_client(timeout=SSH_HANDSHAKE_TIMEOUT)
            # paramiko waits an hour for the server to open a channel.
            self._transport.channel_timeout = self._io_timeout()
            self._verify_host_key(on_unknown_host=on_unknown_host)
            # Keepalive off by default — a fixed 30-s cadence is a
            # cross-session fingerprint. Opt-in per profile. See
            # docs/OPSEC.md #2.
            if profile.ssh_keepalive_interval > 0:
                self._transport.set_keepalive(profile.ssh_keepalive_interval)

            # Authenticate
            self._authenticate(password, key_passphrase)

            # Open one default SFTP channel for the current thread
            self._get_sftp_client()

            # Determine home directory
            try:
                self._home_dir = self.sftp.normalize(".")
            except Exception as e:
                log.warning("Could not determine home directory, defaulting to /: %s", e)
                self._home_dir = "/"

            log.info("SFTP session established. Home: %s", self._home_dir)
        except Exception:
            self.disconnect()
            raise

    def _socket_family(self) -> int:
        return {
            "auto": socket.AF_UNSPEC,
            "ipv4": socket.AF_INET,
            "ipv6": socket.AF_INET6,
        }.get(self._profile.address_family, socket.AF_UNSPEC)

    def _load_host_keys(self) -> KnownHosts:
        return load_known_hosts(self._known_hosts_path)

    def _host_key_aliases(self) -> list[str]:
        return host_key_aliases(self._profile.host, self._profile.port)

    def _prefer_known_host_key_types(self) -> None:
        """Offer the host key types known_hosts holds for this host first.

        A server has several host keys; paramiko's default order picks
        ECDSA/Ed25519 before RSA. With only the (correct) RSA key on
        record the negotiated ECDSA key then failed the check as a false
        mismatch. OpenSSH (HostKeyAlgorithms) and paramiko's SSHClient do
        the same reordering. Only the ORDER changes: a server without
        the known type still negotiates another one, and the check after
        start_client still refuses it.
        """
        if not self._transport:
            return
        host_keys = self._load_host_keys()
        known: set[str] = set()
        for alias in self._host_key_aliases():
            entry = host_keys.lookup(alias)
            if entry is None:
                continue
            for key_type in entry.keys():
                known.update(_HOST_KEY_ALGORITHMS.get(key_type, (key_type,)))
            # _verify_host_key decides on the first alias with an entry.
            break
        if not known:
            return
        options = self._transport.get_security_options()
        offered = list(options.key_types)
        first = [k for k in offered if k in known]
        if first:
            options.key_types = first + [k for k in offered if k not in known]

    @staticmethod
    def _fingerprint_sha256(key: paramiko.PKey) -> str:
        digest = hashlib.sha256(key.asbytes()).digest()
        import base64

        return base64.b64encode(digest).decode("ascii").rstrip("=")

    def _verify_host_key(
        self,
        on_unknown_host: Callable[[UnknownHostKeyError], bool] | None = None,
    ) -> None:
        """Verify the negotiated remote host key against known_hosts."""
        if not self._transport:
            raise ConnectionError("Transport not initialized")

        remote_key = self._transport.get_remote_server_key()
        key_type = remote_key.get_name()
        fingerprint = self._fingerprint_sha256(remote_key)
        host_keys = self._load_host_keys()
        if host_keys.is_revoked(remote_key):
            raise RevokedHostKeyError(self._host_key_aliases()[0], key_type, fingerprint)

        for alias in self._host_key_aliases():
            known = host_keys.lookup(alias)
            if known is None:
                continue
            if host_keys.check(alias, remote_key):
                log.info("Verified host key for %s", alias)
                return
            raise HostKeyMismatchError(alias, key_type, fingerprint)

        error = UnknownHostKeyError(self._host_key_aliases()[0], key_type, fingerprint)
        if on_unknown_host and on_unknown_host(error):
            self.trust_current_host_key()
            # Log type + full SHA256 fingerprint so future forensics can
            # detect a MITM flip that the user may have blindly accepted.
            log.info(
                "Trusted new host key for %s (%s, SHA256:%s)",
                error.host,
                key_type,
                fingerprint,
            )
            return
        raise error

    def trust_current_host_key(self) -> None:
        """Persist the currently negotiated host key to known_hosts."""
        if not self._transport:
            raise ConnectionError("Transport not initialized")

        remote_key = self._transport.get_remote_server_key()
        append_known_host(self._known_hosts_path, self._host_key_aliases()[0], remote_key)

    def _authenticate(self, password: str, key_passphrase: str) -> None:
        """Authenticate using the method specified in the profile."""
        profile = self._profile

        if profile.auth_type == "agent":
            log.info("Authenticating via SSH agent")
            agent, agent_keys = agent_with_keys()
            try:
                for key in agent_keys:
                    try:
                        self._transport.auth_publickey(profile.username, key)
                        log.info("Authenticated with agent key: %s", key.get_name())
                        return
                    except paramiko.AuthenticationException:
                        continue
            finally:
                # Its socket to the agent: one more open per connect.
                agent.close()
            raise paramiko.AuthenticationException("All SSH agent keys rejected")

        elif profile.auth_type == "key":
            key_path = profile.key_file
            if not key_path:
                raise ValueError("No key file specified")

            log.info("Authenticating with key file: %s", key_path)
            pkey = self._load_private_key(key_path, key_passphrase)
            self._transport.auth_publickey(profile.username, pkey)

        else:  # password
            pw = password or profile.get_password() or ""
            # Username is PII — keep at DEBUG so it doesn't ship to
            # centralised log aggregators by default, matching the
            # convention WinRM uses (see commit 9385438).
            log.info("Authenticating with password")
            log.debug("Auth-as user: %s", profile.username)
            self._transport.auth_password(profile.username, pw)

    def _load_private_key(self, path: str, passphrase: str) -> paramiko.PKey:
        """Load a private key, trying multiple formats."""
        return load_private_key(path, passphrase)

    def disconnect(self) -> None:
        """Close SFTP channel and SSH transport."""
        with self._sftp_lock:
            channels = list({id(client): client for client in self._thread_sftp.values()}.values())
            self._thread_sftp.clear()
            self._thread_local = threading.local()

        for channel in channels:
            try:
                channel.close()
            except Exception as exc:
                log.debug("SFTP channel close raised: %s", exc, exc_info=True)

        if self._transport:
            try:
                self._transport.close()
            except Exception as exc:
                log.debug("SSH transport close raised: %s", exc, exc_info=True)
            self._transport = None
            log.info("SSH session disconnected: %s", self.name)

        log.info("Disconnected from %s", self._profile.host)

    def open_sftp_channel(self) -> paramiko.SFTPClient:
        """Open an additional SFTP channel on the same transport.

        Useful for parallel operations (e.g., transfers while browsing).
        """
        if not self._transport or not self._transport.is_active():
            raise ConnectionError("Transport is not active")
        return self._open_sftp_client()

    @staticmethod
    def _channel_open(client: paramiko.SFTPClient | None) -> bool:
        """Whether *client*'s channel can still carry requests. A channel
        the server or this side closed stays dead; the transport (and the
        session's other channels) can be fine."""
        if client is None:
            return False
        try:
            channel = client.get_channel()
        except Exception:  # noqa: BLE001 - a broken client is a closed one
            return False
        return channel is not None and not channel.closed and not channel.eof_received

    def _get_sftp_client(self) -> paramiko.SFTPClient | None:
        """This thread's SFTP client on the session's transport. A client
        whose channel died is replaced: the connection manager shares a
        session whose transport is alive with every pane on the host, so
        a dead cached channel failed each of them until the last pane
        closed the session."""
        if not self._transport or not self._transport.is_active():
            return None

        thread_id = threading.get_ident()
        existing = getattr(self._thread_local, "sftp", None)
        if self._channel_open(existing):
            return existing

        with self._sftp_lock:
            existing = self._thread_sftp.get(thread_id)
            if not self._channel_open(existing):
                if existing is not None:
                    log.info("SFTP channel to %s was closed; opening a new one", self.name)
                    try:
                        existing.close()
                    except Exception as exc:  # noqa: BLE001 - it is dead already
                        log.debug("Closing the dead SFTP client raised: %s", exc)
                self._close_channels_of_ended_threads(thread_id)
                existing = self._open_sftp_client()
                self._thread_sftp[thread_id] = existing
            self._thread_local.sftp = existing
            return existing

    def _close_channels_of_ended_threads(self, current: int) -> None:
        """Let go of the channels of threads that have ended (the caller
        holds _sftp_lock). Transfer workers and MCP calls come and go:
        their channels stayed open for the life of the session, and after
        ten OpenSSH (MaxSessions) refused every new pane, terminal and
        transfer on the host.

        Not closed here: a file the thread opened may still be read by
        another one (a preview opened off the GUI thread). paramiko closes
        a channel nothing refers to any more (Channel.__del__; the
        transport holds its channels weakly)."""
        alive = {t.ident for t in threading.enumerate()}
        alive.add(current)
        ended = [ident for ident in self._thread_sftp if ident not in alive]
        for ident in ended:
            del self._thread_sftp[ident]
        if ended:
            log.debug("%s: let go of %d SFTP channel(s) of ended threads", self.name, len(ended))

    def bound_requests(self, deadline: float, poll: float = 5.0) -> None:
        """Every SFTP request of this session - on every thread's channel,
        open now or later - fails after *deadline* seconds without an
        answer, even while the server answers keepalives (a server that
        stalls a READDIR held an MCP worker for 30 minutes), and a waiting
        request notices its call's cancel within *poll* seconds."""
        self.sftp_request_deadline = float(deadline)
        self.sftp_poll_seconds = float(poll)
        with self._sftp_lock:
            clients = list(self._thread_sftp.values())
        for client in clients:
            self._apply_request_bounds(client)

    def _apply_request_bounds(self, client) -> None:
        if client is None or self.sftp_request_deadline is None:
            return
        try:
            client.slow_server_cap = self.sftp_request_deadline
            client.get_channel().settimeout(
                min(self.sftp_poll_seconds or 5.0, self.sftp_request_deadline))
        except Exception as exc:  # noqa: BLE001 - a stand-in or a closed channel
            log.debug("SFTP request bounds not applied: %s", exc)

    def _open_sftp_client(self) -> paramiko.SFTPClient:
        """A new SFTP channel. A server that refuses the SFTP subsystem
        (SSH and SCP working, SFTP switched off - common on NAS boxes)
        answers by closing the channel; paramiko then says only
        "Channel closed.", which reads like a dropped connection."""
        from core.sftp_io import ReadAheadRaw

        try:
            # Room for two read-ahead windows: with paramiko's 2 MiB default
            # the server could send only 2 MiB of the 8 MiB a window asks
            # for per round trip (a download at 20 ms: ~52 MB/s, not ~90).
            client = _SurrogateSftpClient.from_transport(
                self._transport, window_size=2 * ReadAheadRaw.MAX_WINDOW,
                timeout=self._io_timeout(),
            )
            self._apply_request_bounds(client)
            return client
        except paramiko.ChannelException as exc:
            # The server would not open one more channel at all - not an
            # SFTP question (ChannelException is an SSHException, so it
            # must come first).
            raise OSError(
                f"{self.name}: the server refused to open another channel"
                f" ({exc.code}: {exc.text or 'no reason given'})."
                " SSH servers limit the channels per connection (OpenSSH"
                " MaxSessions, 10 by default); every pane, terminal and transfer"
                " on this host uses one. Close some of them, or raise the limit"
                " on the server."
            ) from exc
        except (paramiko.SSHException, EOFError) as exc:
            if self._transport is not None and self._transport.is_active():
                raise OSError(
                    f"{self.name}: the server refused the SFTP subsystem"
                    f" ({exc or 'channel closed'})."
                    " SSH works, so SFTP is probably switched off on the server (on a"
                    " Synology NAS: Control Panel > File Services > FTP > Enable SFTP"
                    " service). Use the SCP protocol for this host, or enable SFTP."
                ) from exc
            raise

    # --- FileBackend implementation ---

    def _list_attrs(self, path: str) -> list[paramiko.SFTPAttributes]:
        """The folder's entries; a name that is not UTF-8 does not make the
        whole folder unlistable (see :func:`_listdir_attr`)."""
        sftp = self.sftp
        if isinstance(sftp, paramiko.SFTPClient):
            return _listdir_attr(sftp, path)
        return sftp.listdir_attr(path)  # a stand-in client (tests)

    @_sftp_errors_as_oserror
    def list_dir(self, path: str) -> list[FileItem]:
        items: list[FileItem] = []
        try:
            attrs = self._list_attrs(path)
        except OSError as exc:
            # OpenSSH answers OPENDIR of a file with SSH_FX_NO_SUCH_FILE
            # (its errno_to_portable maps ENOTDIR there), others with a
            # bare failure: the entry itself says whether it is a file.
            # A time-out is no answer at all: asking again waits as long.
            if not isinstance(exc, PermissionError | TimeoutError) and self._is_non_folder(path):
                raise NotADirectoryError(
                    errno.ENOTDIR, f"Cannot list {path}: not a folder", path
                ) from exc
            raise
        for attr in attrs:
            items.append(self._attr_to_item(attr))
        # Only names no POSIX folder can hold go. A backslash, control
        # character or bidi override is kept: a listing without the entry
        # made a folder copy incomplete without an error, while the
        # transfer list refuses such a name visibly ("name not usable
        # here") and the pane shows it escaped.
        from core.path_policy import drop_impossible_names

        return drop_impossible_names(items, origin=f"SFTP {path}")

    def _is_non_folder(self, path: str) -> bool:
        """True when *path* is there and is no folder (by stat, so a link
        to a folder is one). Any failure answers False."""
        try:
            mode = self.sftp.stat(path.rstrip("/") or "/").st_mode
        except Exception:  # noqa: BLE001 - no answer is not "a file"
            return False
        return mode is not None and not stat_module.S_ISDIR(mode)

    @_sftp_errors_as_oserror
    def stat(self, path: str) -> FileItem:
        attr = self.sftp.lstat(path)
        name = posixpath.basename(path) or path
        return self._attr_to_item(attr, name_override=name)

    #: ``is_dir(path)`` is the type of the LSTAT ``stat(path)`` makes (False
    #: for not found): a caller holding a ``stat_many`` answer can take it
    #: from there instead of asking again.
    is_dir_from_stat = True

    #: LSTAT requests kept on the wire by :meth:`stat_many`.
    STAT_MANY_IN_FLIGHT = 64

    @_sftp_errors_as_oserror
    def stat_many(self, paths: list[str]) -> list[FileItem | OSError]:
        """``stat`` of every path with pipelined LSTATs: per path the
        FileItem ``stat`` returns, or the OSError it raises. A lost
        connection raises for the whole batch.

        ``stat`` one path after the other is a waited-for round trip each;
        copying a selection of N files asked 3 N of them before the first
        byte moved.
        """
        from collections import deque

        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient):  # a stand-in client (tests)
            return [self._stat_or_error(path) for path in paths]
        from paramiko.sftp import CMD_LSTAT

        receiver = _AnswersByNumber()
        results: list[FileItem | OSError | None] = [None] * len(paths)
        pending: deque[tuple[int, int]] = deque()
        upcoming = iter(enumerate(paths))
        try:
            while True:
                while len(pending) < self.STAT_MANY_IN_FLIGHT:
                    nxt = next(upcoming, None)
                    if nxt is None:
                        break
                    index, path = nxt
                    num = sftp._async_request(receiver, CMD_LSTAT, sftp._adjust_cwd(path))
                    pending.append((index, num))
                if not pending:
                    break
                index, num = pending.popleft()
                while num not in receiver.answers:
                    sftp._read_response()
                t, msg = receiver.answers.pop(num)
                results[index] = self._stat_answer(sftp, paths[index], t, msg)
        finally:
            try:
                while any(owner is receiver for owner in list(sftp._expecting.values())):
                    sftp._read_response()
            finally:
                receiver.answers.clear()
        return results  # type: ignore[return-value]

    def _stat_or_error(self, path: str) -> FileItem | OSError:
        try:
            return self.stat(path)
        except OSError as exc:
            return exc

    #: Files in progress at the same time in :meth:`_pipelined`.
    SMALL_FILES_IN_FLIGHT = 64

    def _pipelined(self, sftp, steps: list) -> list:
        """Run *steps* - one generator per file, each yielding the requests
        of its next stage (``(command, *arguments)`` tuples) and getting
        their answers (``(type, message)`` pairs) back, its return value
        its result - with up to :data:`SMALL_FILES_IN_FLIGHT` of them on
        the wire at once. The answers of a stage come back together; the
        stages of one file run in order. Every request sent is answered
        before this returns or raises (nothing is left for another call to
        read)."""
        receiver = _AnswersByNumber()
        results: list = [None] * len(steps)
        waiting: dict[int, list] = {}  # file -> [its generator, request numbers, unanswered]
        owner_of: dict[int, int] = {}  # request number -> file
        ready: list[int] = []  # files whose stage is all answered
        upcoming = iter(range(len(steps)))
        hold = getattr(sftp, "holding_requests", None)
        flush = getattr(sftp, "flush_requests", lambda: None)
        pending = getattr(sftp, "answer_pending", lambda: False)

        def answered(num: int) -> None:
            index = owner_of.pop(num, None)
            if index is not None:
                entry = waiting[index]
                entry[2] -= 1
                if not entry[2]:
                    ready.append(index)

        receiver.on_answer = answered

        def advance(index: int, step, answers) -> None:
            try:
                wanted = step.send(answers) if answers is not None else next(step)
            except StopIteration as stop:
                results[index] = stop.value
                return
            nums = [sftp._async_request(receiver, command, *args) for command, *args in wanted]
            waiting[index] = [step, nums, len(nums)]
            for num in nums:
                owner_of[num] = index

        try:
            with hold() if callable(hold) else contextlib_suppress():
                while True:
                    while len(waiting) < self.SMALL_FILES_IN_FLIGHT:
                        index = next(upcoming, None)
                        if index is None:
                            break
                        advance(index, steps[index], None)
                    if not waiting:
                        break
                    # Every request out in one write; then the next answer
                    # and those already here; each file whose stage is all
                    # answered goes on.
                    flush()
                    sftp._read_response()
                    while pending():
                        sftp._read_response()
                    done, ready[:] = list(ready), []
                    for index in done:
                        step, nums, _left = waiting.pop(index)
                        advance(index, step, [receiver.answers.pop(num) for num in nums])
        finally:
            try:
                while any(owner is receiver for owner in list(sftp._expecting.values())):
                    sftp._read_response()
            finally:
                receiver.answers.clear()
        return results

    @staticmethod
    def _status_error(sftp, answer, what: str, path: str) -> OSError | None:
        """The OSError a STATUS *answer* stands for, None for "OK"."""
        from paramiko.sftp import CMD_STATUS

        t, msg = answer
        if t != CMD_STATUS:
            return OSError(errno.EIO, f"SFTP {what}: unexpected answer from the server", path)
        try:
            sftp._convert_status(msg)
        except EOFError as exc:
            return OSError(errno.EIO, f"SFTP {what}: {exc or 'end of file'}", path)
        except OSError as exc:
            if exc.filename is None:
                exc.filename = path
            return exc
        return None

    @_sftp_errors_as_oserror
    def upload_small_files(self, items: list[dict]) -> list[dict]:
        """Write small files to their temp names, pipelined across files:
        per item ``{"temp", "data", "mode"}`` an OPEN that creates (or
        truncates) *temp* with *mode* in its attributes, the WRITEs of
        *data* (32 KiB each) and the CLOSE, then an LSTAT of *temp*.

        Per item ``{"error", "temp"}``: the OSError that stopped it (None)
        and the temp file's stat. Nothing is renamed: the caller checks
        each file and commits with :meth:`commit_small_files`.

        One by one, an upload of a 10-byte file was an OPEN, a WRITE, a
        CLOSE, two LSTATs and a SETSTAT with the RENAME - five round trips
        each, waited for one after the other."""
        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient):  # a stand-in client (tests)
            raise NotImplementedError("pipelined uploads need a paramiko SFTP client")
        from paramiko.sftp import (
            CMD_CLOSE,
            CMD_HANDLE,
            CMD_LSTAT,
            CMD_OPEN,
            CMD_WRITE,
            SFTP_FLAG_CREATE,
            SFTP_FLAG_TRUNC,
            SFTP_FLAG_WRITE,
            int64,
        )

        flags = SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_TRUNC
        chunk = 32 * 1024

        def upload(item: dict):
            temp, data = item["temp"], item["data"]
            attrs = paramiko.SFTPAttributes()
            attrs.st_mode = int(item["mode"]) & 0o7777
            (answer,) = yield [(CMD_OPEN, sftp._adjust_cwd(temp), flags, attrs)]
            if answer[0] != CMD_HANDLE:
                return {"error": self._status_error(sftp, answer, "open", temp)
                        or OSError(errno.EIO, "SFTP open: the server sent no handle", temp),
                        "temp": None, "dest": None}
            handle = answer[1].get_binary()
            writes = [(CMD_WRITE, handle, int64(offset), data[offset:offset + chunk])
                      for offset in range(0, len(data), chunk)]
            answers = yield writes + [(CMD_CLOSE, handle)]
            for answer in answers:
                error = self._status_error(sftp, answer, "write", temp)
                if error is not None:
                    return {"error": error, "temp": None, "dest": None}
            (answer,) = yield [(CMD_LSTAT, sftp._adjust_cwd(temp))]
            temp_stat = self._stat_answer(sftp, temp, *answer)
            if isinstance(temp_stat, OSError):
                return {"error": temp_stat, "temp": None}
            return {"error": None, "temp": temp_stat}

        return self._pipelined(sftp, [upload(item) for item in items])

    @_sftp_errors_as_oserror
    def commit_small_files(self, items: list[dict]) -> list[dict]:
        """For each ``{"temp", "dest", "mode", "mtime", "no_replace",
        "decide"}``: :meth:`rename_with_attributes` - a SETSTAT of mode and
        time and the RENAME onto *dest* (posix-rename, which replaces; the
        plain RENAME with *no_replace*, which refuses a *dest* that is
        there) - for all files pipelined. With *decide* an LSTAT of *dest*
        comes first, in the same pipeline: ``decide(its stat or OSError)``
        returns *no_replace*, or an exception that stops this file (in the
        result as "refused"). Per item ``{"attributes_set", "error",
        "refused"}``; a rename the server refused is tried again on its own
        as rename_with_attributes does (FileExistsError for a taken name)."""
        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient):  # a stand-in client (tests)
            raise NotImplementedError("pipelined renames need a paramiko SFTP client")
        from paramiko.sftp import CMD_EXTENDED, CMD_RENAME, CMD_SETSTAT

        from paramiko.sftp import CMD_LSTAT

        def commit(item: dict):
            no_replace = bool(item.get("no_replace"))
            decide = item.get("decide")
            if decide is not None:
                # The last look at the destination, one round trip before
                # the rename (the conflict answers: "fail", "newer").
                (answer,) = yield [(CMD_LSTAT, sftp._adjust_cwd(item["dest"]))]
                verdict = decide(self._stat_answer(sftp, item["dest"], *answer))
                if isinstance(verdict, BaseException):
                    return {"attributes_set": False, "renamed": False, "error": None,
                            "refused": verdict}
                no_replace = bool(verdict)
            item["no_replace"] = no_replace
            attr = paramiko.SFTPAttributes()
            if item.get("mode") is not None:
                attr.st_mode = item["mode"]
            if item.get("mtime") is not None:
                attr.st_atime, attr.st_mtime = time.time(), item["mtime"]
            old, new = sftp._adjust_cwd(item["temp"]), sftp._adjust_cwd(item["dest"])
            rename = ((CMD_RENAME, old, new) if no_replace
                      else (CMD_EXTENDED, "posix-rename@openssh.com", old, new))
            set_answer, rename_answer = yield [(CMD_SETSTAT, old, attr), rename]
            set_error = self._status_error(sftp, set_answer, "setstat", item["temp"])
            renamed = self._status_error(sftp, rename_answer, "rename", item["dest"]) is None
            return {"attributes_set": set_error is None, "renamed": renamed, "error": None}

        results = self._pipelined(sftp, [commit(item) for item in items])
        for item, result in zip(items, results):
            if not result["renamed"] and result.get("refused") is None:
                # As _rename_with_attributes: the plain RENAME on its own,
                # which names a target that is there.
                try:
                    self._plain_rename(item["temp"], item["dest"])
                except Exception as exc:  # noqa: BLE001 - this file's error
                    result["error"] = exc if isinstance(exc, OSError) else OSError(str(exc))
        return results

    @_sftp_errors_as_oserror
    def discard_small_files(self, paths: list[str]) -> None:
        """REMOVE of each temp file of a batch that is not committed, the
        requests pipelined; one that is not there (any more) is no error."""
        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient) or not paths:
            for path in paths:
                with contextlib_suppress(OSError):
                    self.remove(path)
            return
        from paramiko.sftp import CMD_REMOVE

        def remove(path: str):
            (answer,) = yield [(CMD_REMOVE, sftp._adjust_cwd(path))]
            error = self._status_error(sftp, answer, "remove", path)
            if error is not None and not isinstance(error, FileNotFoundError):
                log.warning("Could not remove the partial upload %s: %s", path, error)

        self._pipelined(sftp, [remove(path) for path in paths])

    @_sftp_errors_as_oserror
    def read_small_files(self, entries: list[tuple[str, int]]) -> dict[str, bytes]:
        """The contents of small files, read with pipelined requests:
        *entries* are ``(path, listed size)`` pairs; per file an OPEN, then
        one READ of the listed size and one byte more together with the
        CLOSE - up to :data:`SMALL_FILES_IN_FLIGHT` files at once
        (:meth:`_pipelined`).

        Copying a folder of many small files read them one after the other,
        each an OPEN, a READ and a second READ that said "end of file":
        three round trips per 10-byte file. A file whose answer ends at its
        listed size is in the result (for a regular file SFTP v3 returns
        all a READ asks for, or up to the end of the file); one that could
        not be opened or read, or that holds more or less than listed, is
        not - the transfer reads that one on its own, and reports what
        goes wrong there."""
        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient):  # a stand-in client (tests)
            return {}
        from paramiko.sftp import (
            CMD_CLOSE,
            CMD_DATA,
            CMD_HANDLE,
            CMD_OPEN,
            CMD_READ,
            CMD_STATUS,
            SFTP_EOF,
            SFTP_FLAG_READ,
            int64,
        )

        from core.sftp_io import _close_transport

        # Cancel of the running transfer closes the channel: a batch waiting
        # on a silent network ends at once, not after the I/O time-out.
        watch = transfer_hooks.watch_cancel(sftp.close, escalate=lambda: _close_transport(sftp))

        def read(path: str, size: int):
            (answer,) = yield [(CMD_OPEN, sftp._adjust_cwd(path), SFTP_FLAG_READ,
                                paramiko.SFTPAttributes())]
            if answer[0] != CMD_HANDLE:
                return None  # not readable: the job opens it itself
            handle = answer[1].get_binary()
            (t, msg), _closed = yield [(CMD_READ, handle, int64(0), int(size) + 1),
                                       (CMD_CLOSE, handle)]
            if t == CMD_DATA:
                data = msg.get_string()
                return data if len(data) == size else None
            if t == CMD_STATUS and size == 0 and msg.get_int() == SFTP_EOF:
                return b""
            return None

        try:
            contents = self._pipelined(sftp, [read(path, size) for path, size in entries])
        except BaseException as exc:
            if watch is not None and watch.fired:
                raise InterruptedError(transfer_hooks.CANCELLED) from exc
            raise
        finally:
            if watch is not None:
                watch.stop()
        return {path: data for (path, _size), data in zip(entries, contents) if data is not None}

    def _stat_answer(self, sftp, path: str, t: int, msg) -> FileItem | OSError:
        """What ``stat(path)`` returns or raises for LSTAT answer *t*/*msg*
        (``sftp.lstat`` and the ``_sftp_errors_as_oserror`` mapping)."""
        from paramiko.sftp import CMD_ATTRS, CMD_STATUS

        try:
            if t == CMD_STATUS:
                sftp._convert_status(msg)  # the OSError lstat raises
            if t != CMD_ATTRS:
                raise paramiko.SFTPError("Expected attributes")
            attr = paramiko.SFTPAttributes._from_msg(msg)
            return self._attr_to_item(attr, name_override=posixpath.basename(path) or path)
        except EOFError as exc:
            detail = str(exc) or type(exc).__name__
            return OSError(f"SFTP stat: connection to the server failed: {detail}")
        except (paramiko.SFTPError, UnicodeError) as exc:
            return OSError(f"SFTP stat: unusable answer from the server: {exc}")
        except OSError as exc:
            return exc

    @_sftp_errors_as_oserror
    def is_dir(self, path: str) -> bool:
        """False only for "not found" (or a file on the way); a refused,
        failed or timed-out lstat is an OSError - the transfer manager
        and remove() pick folder or file from this answer."""
        try:
            attr = self.sftp.lstat(path)
        except (FileNotFoundError, NotADirectoryError):
            return False
        return stat_module.S_ISDIR(attr.st_mode or 0)

    @_sftp_errors_as_oserror
    def exists(self, path: str) -> bool:
        try:
            self.sftp.lstat(path)
            return True
        except FileNotFoundError:
            return False

    @_sftp_errors_as_oserror
    def mkdir(self, path: str) -> None:
        """FileExistsError when *path* is taken, as mkdir(2): SFTP v3 has
        no status for it, so OpenSSH answers SSH_FX_FAILURE ("Failure") -
        an OSError nobody could tell from a refused permission."""
        try:
            self.sftp.mkdir(path)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            try:
                self.sftp.lstat(path)
            except OSError:
                raise exc from None
            raise FileExistsError(errno.EEXIST, f"Cannot create {path}: it exists", path) from exc

    @_sftp_errors_as_oserror
    def remove(self, path: str, recursive: bool = False) -> None:
        if self.is_dir(path):
            if recursive:
                self._rmtree(path)
            else:
                self.sftp.rmdir(path)
        else:
            self.sftp.remove(path)

    _MAX_TREE_DEPTH = MAX_RECURSIVE_DELETE_DEPTH

    def _rmtree(self, path: str, depth: int = 0) -> None:
        """Recursively remove a directory tree via SFTP.

        The folder's files go first, in batches of
        :data:`RMTREE_REMOVES_IN_FLIGHT` pipelined REMOVEs
        (:meth:`_remove_files`), then each sub-folder recurses. The pane's
        Cancel is asked before every batch and every sub-folder, so it
        stops the walk after the running batch.
        """
        check_tree_depth(path, depth, self._MAX_TREE_DEPTH)
        files: list[str] = []
        folders: list[str] = []
        for attr in self._list_attrs(path):
            try:
                child = safe_join(self, path, attr.filename)
            except ValueError as exc:
                raise OSError(
                    f"Cannot recursively remove {path}: unsafe child name {attr.filename!r}: {exc}"
                ) from exc
            (folders if stat_module.S_ISDIR(attr.st_mode or 0) else files).append(child)
        for start in range(0, len(files), RMTREE_REMOVES_IN_FLIGHT):
            batch = files[start : start + RMTREE_REMOVES_IN_FLIGHT]
            removal_cancel.checkpoint(batch[0])  # the pane's Cancel stops here
            self._remove_files(batch)
        for child in folders:
            removal_cancel.checkpoint(child)
            self._rmtree(child, depth + 1)
            removal_cancel.removed(child)
        self.sftp.rmdir(path)

    def _remove_files(self, paths: list[str]) -> None:
        """``sftp.remove`` of every path, the REMOVEs pipelined: all go out,
        then the answers are read in request order, each removed file
        reported to :func:`removal_cancel.removed`.

        A failing answer raises what ``sftp.remove`` raised for it (the
        first one in request order), but only after every answer still on
        the wire was read: no request is left for another call to read.
        The other files of the batch are removed by then.
        """
        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient):  # a stand-in client (tests)
            for path in paths:
                sftp.remove(path)
                removal_cancel.removed(path)
            return
        from paramiko.sftp import CMD_REMOVE, CMD_STATUS

        receiver = _AnswersByNumber()
        first_error: Exception | None = None
        try:
            sent = [
                (path, sftp._async_request(receiver, CMD_REMOVE, sftp._adjust_cwd(path)))
                for path in paths
            ]
            for path, num in sent:
                while num not in receiver.answers:
                    sftp._read_response()
                t, msg = receiver.answers.pop(num)
                if t == CMD_STATUS:  # paramiko's remove() looks at nothing else
                    try:
                        sftp._convert_status(msg)  # what sftp.remove raises
                    except (OSError, EOFError, UnicodeError) as exc:
                        if first_error is None:
                            first_error = exc
                        continue
                removal_cancel.removed(path)
        finally:
            # Whatever stopped the loop, the answers still out are read
            # before anything else is sent. A dead connection raises its
            # own error here.
            try:
                while any(owner is receiver for owner in list(sftp._expecting.values())):
                    sftp._read_response()
            finally:
                receiver.answers.clear()
        if first_error is not None:
            raise first_error

    @_sftp_errors_as_oserror
    def rename(self, src: str, dst: str) -> None:
        posix_rename = getattr(self.sftp, "posix_rename", None)
        if posix_rename is not None:
            try:
                posix_rename(src, dst)
                return
            except OSError as e:
                log.debug("posix-rename %s -> %s failed, falling back: %s", src, dst, e)
        self._plain_rename(src, dst)

    def _plain_rename(self, src: str, dst: str) -> None:
        """SSH_FXP_RENAME. OpenSSH refuses an existing *dst* with a bare
        SSH_FX_FAILURE ("Failure"): named FileExistsError when *dst* is
        there, as rename_no_replace promises."""
        try:
            self.sftp.rename(src, dst)
        except OSError as exc:
            if isinstance(exc, FileNotFoundError):
                raise
            try:
                self.sftp.lstat(dst)
            except Exception:  # noqa: BLE001 - not there, or no answer: the original error
                raise exc from None
            raise FileExistsError(
                errno.EEXIST, f"Cannot rename {src} -> {dst}: the target exists ({exc})", dst
            ) from exc

    @_sftp_errors_as_oserror
    def rename_no_replace(self, src: str, dst: str) -> None:
        """The plain SSH_FXP_RENAME, which the server refuses when *dst*
        exists (``rename`` tries posix-rename first, which replaces it):
        a move within the server that must not overwrite a file that
        appeared after the check (core.transfer_worker)."""
        self._plain_rename(src, dst)

    @_sftp_errors_as_oserror
    def set_attributes(self, path: str, *, mode: int | None = None,
                       mtime: float | None = None) -> None:
        """Set *path*'s permission bits and/or modification time with ONE
        SETSTAT (chmod and set_modified are a round trip each). As
        set_modified, the access time becomes now."""
        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient):  # a stand-in client (tests)
            if mode is not None:
                sftp.chmod(path, mode)
            if mtime is not None:
                sftp.utime(path, (time.time(), mtime))
            return
        from paramiko.sftp import CMD_SETSTAT

        attr = paramiko.SFTPAttributes()
        if mode is not None:
            attr.st_mode = mode
        if mtime is not None:
            attr.st_atime, attr.st_mtime = time.time(), mtime
        sftp._request(CMD_SETSTAT, sftp._adjust_cwd(path), attr)

    def rename_with_attributes(self, src: str, dst: str, *, mode: int | None = None,
                               mtime: float | None = None, no_replace: bool = False) -> bool:
        """:meth:`set_attributes` of *src*, then :meth:`rename` of *src* to
        *dst*, in ONE round trip: both requests go out together and the
        server handles them in order (a transfer's temp file gets the
        source's mode and time, then its name). Returns whether the
        attributes were set; raises what :meth:`rename` raises - a refused
        posix-rename is tried again as a plain RENAME, as there.
        *no_replace*: the plain RENAME only, as :meth:`rename_no_replace` -
        FileExistsError for a *dst* that is there."""
        sftp = self.sftp
        if not isinstance(sftp, paramiko.SFTPClient):  # a stand-in client (tests)
            try:
                self.set_attributes(src, mode=mode, mtime=mtime)
                attributes_set = True
            except OSError:
                attributes_set = False
            if no_replace:
                self.rename_no_replace(src, dst)
            else:
                self.rename(src, dst)
            return attributes_set
        return self._rename_with_attributes(sftp, src, dst, mode, mtime, no_replace)

    @_sftp_errors_as_oserror
    def _rename_with_attributes(self, sftp, src, dst, mode, mtime, no_replace=False) -> bool:
        from paramiko.sftp import CMD_EXTENDED, CMD_RENAME, CMD_SETSTAT

        attr = paramiko.SFTPAttributes()
        if mode is not None:
            attr.st_mode = mode
        if mtime is not None:
            attr.st_atime, attr.st_mtime = time.time(), mtime
        receiver = _AnswersByNumber()
        old, new = sftp._adjust_cwd(src), sftp._adjust_cwd(dst)
        try:
            setstat = sftp._async_request(receiver, CMD_SETSTAT, old, attr)
            if no_replace:
                rename = sftp._async_request(receiver, CMD_RENAME, old, new)
            else:
                rename = sftp._async_request(receiver, CMD_EXTENDED,
                                             "posix-rename@openssh.com", old, new)
            while setstat not in receiver.answers or rename not in receiver.answers:
                sftp._read_response()
        finally:
            try:
                while any(owner is receiver for owner in list(sftp._expecting.values())):
                    sftp._read_response()
            finally:
                answers = dict(receiver.answers)
                receiver.answers.clear()

        def ok(num: int) -> bool:
            t, msg = answers[num]
            try:
                sftp._convert_status(msg)
            except OSError:
                return False
            return True

        attributes_set = ok(setstat)
        if not ok(rename):
            # posix-rename refused: the plain RENAME. A refused plain RENAME
            # (no_replace) is sent again on its own, which names a target
            # that is there (FileExistsError) or raises the server's error.
            log.debug("rename %s -> %s refused, falling back", src, dst)
            self._plain_rename(src, dst)
        return attributes_set

    @_sftp_errors_as_oserror
    def set_modified(self, path: str, mtime: float) -> None:
        """Set *path*'s modification time (epoch seconds) by SETSTAT, so a
        copy keeps its source's time. SFTP v3 keeps whole seconds and sets
        both times or neither: the access time becomes now (the file was
        just written)."""
        self.sftp.utime(path, (time.time(), mtime))

    @_sftp_errors_as_oserror
    def open_read(self, path: str) -> IO[bytes]:
        # Pipelined, bounded read-ahead: see core.sftp_io.
        from core.sftp_io import open_read_ahead

        return open_read_ahead(lambda: self.sftp.open(path, "rb"))

    @_sftp_errors_as_oserror
    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        # WRITEs go out without waiting for each answer (one round trip per
        # 32 KiB otherwise); every answer is still checked: core.sftp_io.
        from core.sftp_io import PipelinedWriter

        if path.endswith("/") and path.strip("/"):
            # A server that canonicalizes the path first wrote a FILE "x".
            raise IsADirectoryError(
                errno.EISDIR, f"Cannot write {path}: a path ending in '/' names a folder", path
            )
        return PipelinedWriter(self.sftp.open(path, "ab" if append else "wb"), append=append)

    @_sftp_errors_as_oserror
    def open_write_new(self, path: str, mode: int) -> IO[bytes]:
        """*path* created (or truncated) for writing with *mode* in the OPEN
        request's attributes: a server creates the file with it (OpenSSH:
        less its umask) - private from its first byte, not created in the
        default mode and chmod-ed after (core.atomic_io._open_new_with_mode).
        An existing file keeps its mode, as with any open."""
        from paramiko.sftp import (
            CMD_HANDLE,
            CMD_OPEN,
            SFTP_FLAG_CREATE,
            SFTP_FLAG_TRUNC,
            SFTP_FLAG_WRITE,
        )
        from paramiko.sftp_attr import SFTPAttributes
        from paramiko.sftp_file import SFTPFile

        from core.sftp_io import PipelinedWriter

        if path.endswith("/") and path.strip("/"):
            raise IsADirectoryError(
                errno.EISDIR, f"Cannot write {path}: a path ending in '/' names a folder", path
            )
        sftp = self.sftp
        attrs = SFTPAttributes()
        attrs.st_mode = mode & 0o7777
        kind, msg = sftp._request(
            CMD_OPEN, sftp._adjust_cwd(path),
            SFTP_FLAG_WRITE | SFTP_FLAG_CREATE | SFTP_FLAG_TRUNC, attrs,
        )
        if kind != CMD_HANDLE:
            raise OSError(errno.EIO, f"open {path}: the server sent no handle", path)
        return PipelinedWriter(SFTPFile(sftp, msg.get_binary(), "wb"), append=False)

    def normalize(self, path: str) -> str:
        try:
            return self.sftp.normalize(path)
        except (OSError, UnicodeError, paramiko.SFTPError, *_SFTP_CONNECTION_ERRORS):
            return posixpath.normpath(path)

    def realpath(self, path: str) -> str:
        """The server's canonical form of *path* (REALPATH): OpenSSH's
        sftp-server answers with realpath(3), every symlink resolved.
        OSError when the server cannot (a missing path on most)."""
        try:
            return self.sftp.normalize(path)
        except (OSError, UnicodeError, paramiko.SFTPError, *_SFTP_CONNECTION_ERRORS) as exc:
            if isinstance(exc, OSError):
                raise
            raise OSError(f"realpath {path}: {exc}") from exc

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return posixpath.join(*parts)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path) or "/"

    def home(self) -> str:
        return self._home_dir

    @_sftp_errors_as_oserror
    def chmod(self, path: str, mode: int) -> None:
        self.sftp.chmod(path, mode)

    @_sftp_errors_as_oserror
    def owner_ids(self, path: str) -> tuple[int, int] | None:
        """(uid, gid) of *path* itself (a link is not followed); None
        when the server does not say."""
        st = self.sftp.lstat(path)
        uid, gid = getattr(st, "st_uid", None), getattr(st, "st_gid", None)
        return None if uid is None or gid is None else (int(uid), int(gid))

    @_sftp_errors_as_oserror
    def chown(self, path: str, uid: int, gid: int) -> None:
        self.sftp.chown(path, uid, gid)

    @_sftp_errors_as_oserror
    def readlink(self, path: str) -> str:
        target = self.sftp.readlink(path) or ""
        if isinstance(target, bytes):
            # paramiko hands back the raw bytes of a target that is not
            # UTF-8 (sftp_client._to_unicode); decoded as listed names are.
            target = target.decode("utf-8", errors="surrogateescape")
        return target

    # SFTP speaks symlinks natively (paramiko's sftp.symlink); hardlinks
    # aren't in the SFTP v3 spec, so we fall back to a shell ``ln``
    # invocation and flag only symlinks as supported-without-caveats.
    supports_symlinks = True
    supports_hardlinks = True

    def symlink(self, target: str, link_path: str) -> None:
        """Create a symlink on the remote host. paramiko's argument
        order is ``(source, dest)`` — ``source`` is where the link
        POINTS TO, ``dest`` is where the link is created. We mirror
        os.symlink's order (target, link_path)."""
        try:
            # The target is sent as given, not through _adjust_cwd.
            self.sftp.symlink(wire_path(target), link_path)
        except OSError:
            raise
        except Exception as exc:  # noqa: BLE001 — paramiko IOError etc.
            raise OSError(
                f"SFTP symlink({target!r} → {link_path!r}): {exc}",
            ) from exc

    def _io_timeout(self) -> float:
        """Seconds of silence after which a waiting SFTP request or exec
        command asks the SSH connection whether it is alive: the
        profile's SFTP time-out, else :data:`SFTP_IO_TIMEOUT`."""
        value = getattr(getattr(self, "_profile", None), "sftp_timeout", 0) or 0
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = 0.0
        return value if value > 0 else SFTP_IO_TIMEOUT

    def _run_on_channel(
        self,
        label: str,
        start: Callable[[paramiko.Channel], object],
        *,
        timeout: float | None = None,
        stdout_cap: int = HELPER_STDOUT_CAP,
        stderr_cap: int = HELPER_STDERR_CAP,
    ) -> "ExecResult":
        """Open an exec channel, ``start(chan)`` (sends the exec request),
        read the command's output to its end and return the
        :class:`~models.exec_result.ExecResult`.

        Watched by an :class:`_ExecWatch`: Cancel of the running transfer
        closes the channel (InterruptedError), and a connection that goes
        silent and does not answer a keepalive fails it (TimeoutError,
        ETIMEDOUT) - a command that only takes long (a hash of a big file)
        is waited for. *timeout*: a hard limit on top (exec()). An exec
        request the server turns down while the connection stands raises
        :class:`_ExecRefused`."""
        transport = self._transport
        if not transport or not transport.is_active():
            raise ConnectionError(errno.ENOTCONN, f"{label}: SSH transport not active")
        idle = self._io_timeout()
        try:
            chan = transport.open_session(timeout=idle)
        except paramiko.SSHException as exc:
            if str(exc).startswith("Timeout opening channel"):
                raise TimeoutError(
                    errno.ETIMEDOUT,
                    f"{label}: the server did not open a channel within {idle:g} s; the "
                    f"network connection is probably lost. Reconnect and try again.",
                ) from exc
            raise
        watch: _ExecWatch | None = None
        try:
            watch = _ExecWatch(chan, transport, idle)
            try:
                start(chan)
            except paramiko.SSHException as exc:
                if not (watch.cancelled or watch.timed_out) and transport.is_active():
                    raise _ExecRefused(f"{label}: the server refused the command ({exc})") from exc
                raise
            result = drain_exec_channel(
                chan,
                timeout=timeout,
                stdout_cap=stdout_cap,
                stderr_cap=stderr_cap,
                label=label,
                on_output=watch.touch,
            )
        except BaseException as exc:
            if isinstance(exc, InterruptedError) and watch is None:
                raise  # Cancel was pressed before the command was sent
            if watch is not None and watch.cancelled:
                from core import transfer_hooks

                raise InterruptedError(transfer_hooks.CANCELLED) from exc
            if watch is not None and watch.timed_out:
                raise self._silent_exec(label, idle) from exc
            raise
        finally:
            if watch is not None:
                watch.stop()
            try:
                chan.close()
            except Exception:  # noqa: BLE001 - closing a dead channel may fail
                pass
        if watch.cancelled:
            from core import transfer_hooks

            raise InterruptedError(transfer_hooks.CANCELLED)
        if watch.timed_out:
            raise self._silent_exec(label, idle)
        return result

    @staticmethod
    def _silent_exec(label: str, idle: float) -> TimeoutError:
        return TimeoutError(
            errno.ETIMEDOUT,
            f"{label}: the server sent nothing for {idle:g} s and the SSH connection "
            f"did not answer a keepalive either; the network connection is probably "
            f"lost. Reconnect and try again.",
        )

    def hardlink(self, target: str, link_path: str) -> None:
        """Hardlink via a remote ``ln`` shell call — SFTP v3 has no
        native hardlink operation. Fails cleanly when the remote
        host lacks ``ln`` or the two paths live on different
        filesystems (errors bubble up as OSError from the shell).

        An existing *link_path* is FileExistsError, as link(2): plain
        ``ln`` onto a folder made the link INSIDE it and reported success
        (``ln -T`` refuses that, but is GNU only), so the shell tests
        first - a dangling symlink counts as taken too."""
        if not self._transport or not self._transport.is_active():
            raise OSError("SSH hardlink: transport not active")
        qlink = shlex.quote(link_path)
        command = command_bytes(
            f"if test -e {qlink} || test -L {qlink}; then "
            f"echo {_HARDLINK_TAKEN} >&2; exit 1; fi; "
            f"ln -- {shlex.quote(target)} {qlink}",
        )
        try:
            result = self._run_on_channel("SSH hardlink", lambda chan: chan.exec_command(command))
        except paramiko.SSHException as exc:
            raise OSError(f"SSH hardlink: {exc}") from exc
        rc, err = result.returncode, result.stderr
        if rc != 0 and _HARDLINK_TAKEN.encode() in err:
            raise FileExistsError(
                errno.EEXIST, f"SSH hardlink: {link_path} already exists", link_path
            )
        if rc != 0:
            raise OSError(
                f"SSH hardlink({target!r} → {link_path!r}) rc={rc}: "
                f"{err.decode('utf-8', errors='replace').strip()}"
            )

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        try:
            stats = self.sftp.statvfs(path)
            block_size = stats.f_frsize or stats.f_bsize or 0
            if block_size > 0:
                total = stats.f_blocks * block_size
                free = stats.f_bavail * block_size
                used = total - (stats.f_bfree * block_size)
                return (total, used, free)
        except Exception as e:
            log.debug("statvfs unavailable for %s: %s", path, e)

        # df: "not supported" - (0, 0, 0) - only when the server has no
        # df or runs no commands. A failure (no such path, a dropped
        # connection, a name that cannot be sent) is an OSError, not an
        # empty disk.
        if not self._transport or not self._transport.is_active():
            raise ConnectionError(errno.ENOTCONN, "SSH transport not active")
        command = command_bytes(f"df -Pk -- {shlex.quote(path)}")
        try:
            result = self._run_on_channel("SSH df", lambda chan: chan.exec_command(command))
        except _ExecRefused as exc:
            log.debug("df fallback unavailable for %s: %s", path, exc)
            return (0, 0, 0)
        except paramiko.SSHException as exc:
            raise OSError(f"SSH disk usage of {path}: {exc}") from exc
        if result.truncated_stdout:
            raise OSError(f"SSH df stdout exceeds {HELPER_STDOUT_CAP} byte cap")
        output = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        rc = result.returncode
        if command_missing(rc, stderr, "df"):
            log.debug("df unavailable on %s: %s", self._profile.host, stderr.strip())
            return (0, 0, 0)
        if rc != 0:
            raise OSError(f"SSH disk usage of {path}: df rc={rc}: {stderr.strip()}")
        lines = [line.strip() for line in split_lf_only_stream(output) if line.strip()]
        parts = lines[-1].split() if len(lines) >= 2 else []
        try:
            if len(parts) >= 4:
                return (int(parts[1]) * 1024, int(parts[2]) * 1024, int(parts[3]) * 1024)
        except ValueError:
            pass
        log.debug("df output for %s not understood: %r", path, output[:200])
        return (0, 0, 0)

    def exec(
        self,
        cmd: str,
        *,
        timeout: float | None = 30.0,
        stdin: bytes | None = None,
        stdout_cap: int = 1024 * 1024,
        stderr_cap: int = 64 * 1024,
        env: dict[str, str] | None = None,
    ) -> "ExecResult":
        """Run a shell command on the remote host, return an
        :class:`~models.exec_result.ExecResult`.

        ``cmd`` is sent verbatim to the remote ``/bin/sh`` (or whatever
        the user's login shell is). Caller is responsible for escaping
        substituted arguments — use ``shlex.quote()`` for any path or
        user-supplied value spliced into the command string.

        ``stdin`` is fed to the remote process before its stdout/stderr
        are read. Pass ``None`` to skip stdin entirely.

        ``stdout_cap`` / ``stderr_cap`` clip each stream after that many
        bytes; the corresponding ``truncated_*`` flag on the result
        tells the caller a clip happened. Defaults are generous (1 MiB
        / 64 KiB) so most ``show``-style output round-trips intact.

        ``env`` keys are validated against ``[A-Za-z_][A-Za-z0-9_]*`` so
        a tainted key can't smuggle a second ``export`` line. Values
        are sent through paramiko's ``update_environment`` channel call
        — most sshd configs ignore client-set env unless ``AcceptEnv``
        whitelists the key, so don't rely on env propagation as a
        security boundary.

        Raises ``OSError`` on transport failure, NOT on a non-zero
        remote exit code; use ``.check()`` on the result for the latter.
        A command that outlives *timeout* raises ``TimeoutError``.
        """
        if not self._transport or not self._transport.is_active():
            raise OSError("SSH exec: transport not active")
        from core.redaction import command_summary

        # Never the command's text: it carries passwords (mysql -pSECRET,
        # a token in a URL) that no redaction pattern finds.
        log.info(
            "SSH exec on %s@%s: %s",
            self._profile.username,
            self._profile.host,
            command_summary(cmd),
        )
        if env:
            import re as _re

            for k, v in env.items():
                if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                    raise OSError(
                        f"SSH exec: env key {k!r} must match "
                        "[A-Za-z_][A-Za-z0-9_]* (refusing to send)"
                    )
                # F39: a tainted VALUE with embedded NUL would terminate
                # the C-string the SSH agent forwards; CR/LF would land
                # in some sshd logs as a forged log line. Symmetry with
                # the key allow-list — both halves of the env tuple are
                # equally adversary-controllable in practice.
                if "\x00" in v or "\r" in v or "\n" in v:
                    raise OSError(
                        f"SSH exec: env value for {k!r} must not contain "
                        "NUL/CR/LF (refusing to send). F39."
                    )
        def start(chan) -> None:
            if timeout is not None:
                chan.settimeout(timeout)
            if env:
                # paramiko's update_environment is best-effort; sshd
                # silently drops unwhitelisted keys.
                for k, v in env.items():
                    try:
                        chan.update_environment({k: v})
                    except paramiko.SSHException:
                        pass
            chan.exec_command(command_bytes(cmd))
            if stdin:
                try:
                    chan.sendall(stdin)
                except OSError as exc:
                    log.debug("SSH exec stdin sendall failed: %s", exc)
                try:
                    chan.shutdown_write()
                except OSError:
                    pass

        # Cancel (in a transfer) and a connection gone silent end it too.
        return self._run_on_channel(
            "SSH exec",
            start,
            timeout=timeout,
            stdout_cap=stdout_cap,
            stderr_cap=stderr_cap,
        )

    def interactive_shell(
        self,
        *,
        term: str = "xterm-256color",
        cols: int = 80,
        rows: int = 24,
        env: dict[str, str] | None = None,
    ) -> "InteractiveShell":
        """Open a NEW interactive-shell channel on the existing SSH
        transport — multiplexing.

        The transport stays the same one used for SFTP and the
        FileBackend ops; we just open a second SSH channel on it,
        request a PTY, and invoke the user's login shell. File ops
        and the shell run concurrently against the same TCP
        connection + the same auth handshake.

        Use it like this::

            sess = SSHSession(profile)
            sess.connect(...)
            with sess.interactive_shell() as shell:
                shell.write(b"uname -a\\n")
                print(shell.read_until(b"$ ", timeout=5).decode())
            # File ops on ``sess`` continue to work — only the
            # shell channel was closed.

        ``env`` honours the same NUL/CR/LF guards as ``exec()``;
        most sshd configs ignore client-set env unless
        ``AcceptEnv`` whitelists the key.
        """
        from models.interactive_shell import InteractiveShell

        if not self._transport or not self._transport.is_active():
            raise OSError("SSH interactive_shell: transport not active")
        if env:
            import re as _re

            for k, v in env.items():
                if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                    raise OSError(
                        f"SSH interactive_shell: env key {k!r} must match [A-Za-z_][A-Za-z0-9_]*"
                    )
                if "\x00" in v or "\r" in v or "\n" in v:
                    raise OSError(
                        f"SSH interactive_shell: env value for {k!r} must not contain NUL/CR/LF"
                    )
        if "\r" in term or "\n" in term or "\x00" in term:
            raise ValueError("SSH interactive_shell: term must not contain NUL/CR/LF")
        chan = self._transport.open_session()
        try:
            chan.get_pty(term=term, width=int(cols), height=int(rows))
            if env:
                for k, v in env.items():
                    try:
                        chan.update_environment({k: v})
                    except paramiko.SSHException:
                        log.debug(
                            "SSH interactive_shell: env key %s rejected by sshd (likely AcceptEnv)",
                            k,
                        )
            chan.invoke_shell()
        except Exception:
            try:
                chan.close()
            except Exception:  # noqa: BLE001
                pass
            raise
        label = f"{self._profile.username}@{self._profile.host}:{self._profile.port}"
        log.info(
            "SSH interactive shell opened on %s (%dx%d %s) — multiplexed "
            "alongside %d existing channel(s) on the transport",
            label,
            cols,
            rows,
            term,
            len(self._transport._channels.values()) - 1
            if hasattr(self._transport, "_channels")
            else 0,
        )
        return InteractiveShell(chan, label=label)

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(f"{type(self).__name__} does not expose file version history")

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy via ``cp -p``. O(0) client bytes."""
        if not self._transport or not self._transport.is_active():
            raise ConnectionError("SSH transport not active")
        # Plain cp copies INTO an existing folder dst (review B6 twin).
        from core.telnet_client import copy_command

        command = command_bytes(copy_command(src, dst, preserve=True))
        # A copy of a big file on the server takes as long as it takes: no
        # fixed time-out, but a silent connection that does not answer a
        # keepalive fails it, and Cancel closes it (_run_on_channel).
        try:
            result = self._run_on_channel("SSH copy", lambda chan: chan.exec_command(command))
        except paramiko.SSHException as exc:
            raise OSError(f"copy failed: {exc}") from exc
        rc = result.returncode
        if rc != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")
            raise OSError(f"cp {src} -> {dst} failed: rc={rc} stderr={stderr!r}")

    def checksum_kinds(self, path: str = "", *, written: bool = False) -> frozenset[str] | None:
        """The algorithms :meth:`checksum` can answer with here: none once
        the server said it cannot hash (see ``_checksum_unavailable``),
        otherwise unknown (None) - the transfer engine then asks."""
        if "sha256" in self._checksum_unavailable:
            return frozenset()
        return None

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Exec ``sha256sum`` / ``md5sum`` on the remote and parse the
        output. Cheap compared to SFTP streaming the whole file to us.

        Falls back to returning ``""`` when the requested algorithm
        lacks a CLI tool on the remote — caller then has the option to
        do a client-side streaming hash via :meth:`open_read`.

        A missing tool, and a server that refuses to run commands at all
        (an exec request turned down - not a channel it would not open,
        which can be a passing channel limit), are remembered for the
        session: a copy of 500 files asked 500 times.
        """
        tool = {
            "sha256": "sha256sum",
            "sha1": "sha1sum",
            "md5": "md5sum",
        }.get(algorithm)
        if not tool:
            return ""
        known = self._checksum_unavailable.get(algorithm)
        if known == "missing":
            return ""
        if known is not None:
            raise OSError(f"checksum failed: {known}")
        if not self._transport or not self._transport.is_active():
            raise ConnectionError("SSH transport not active")
        command = command_bytes(f"{tool} -- {shlex.quote(path)}")
        # After every upload the transfer engine asks for this: Cancel
        # closes the channel, and a connection gone silent fails it - a
        # big file hashed slowly is waited for (_run_on_channel).
        try:
            result = self._run_on_channel(f"SSH {tool}", lambda chan: chan.exec_command(command))
        except _ExecRefused as exc:
            # The channel opened, the command was turned down (the
            # connection still stands): this server runs no commands.
            reason = exc.__cause__ or exc
            for name in ("sha256", "sha1", "md5"):
                self._checksum_unavailable[name] = (
                    f"the server refuses to run commands ({reason})")
            raise OSError(f"checksum failed: {reason}") from exc
        except paramiko.SSHException as exc:
            raise OSError(f"checksum failed: {exc}") from exc
        if result.truncated_stdout:
            raise OSError(f"SSH checksum stdout exceeds {HELPER_STDOUT_CAP} byte cap")
        output = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        rc = result.returncode
        if command_missing(rc, stderr, tool):
            # No such tool on this host (exit 126/127, or the words of
            # cmd.exe / PowerShell on Windows OpenSSH, which exit 1): ""
            # lets the caller hash the stream, as documented above.
            log.debug("%s unavailable on %s: %s", tool, self._profile.host, stderr.strip())
            self._checksum_unavailable[algorithm] = "missing"
            return ""
        if rc != 0:
            raise OSError(f"{tool} failed on {path}: rc={rc} stderr={stderr!r}")
        hex_digest = digest_from_sum_output(output, algorithm)
        if not hex_digest:
            return ""
        return f"{algorithm}:{hex_digest}"

    #: Bytes of one batch hash command line, and files in it, at most:
    #: far below any server's ARG_MAX (Linux 2 MiB, older systems 64 KiB).
    CHECKSUM_COMMAND_MAX = 32 * 1024
    CHECKSUM_FILES_MAX = 64

    def checksum_many(self, paths: list[str], algorithm: str = "sha256") -> dict[str, str]:
        """:meth:`checksum` of many files with one remote command per chunk
        (``sha256sum -- 'p1' 'p2' ...``, every name quoted, the command line
        at most :data:`CHECKSUM_COMMAND_MAX` bytes and
        :data:`CHECKSUM_FILES_MAX` files): a batch of uploads asked one
        command per file - an SSH channel, an exec and its output each.

        ``{path: "sha256:<hex>"}`` for the files whose line in the output
        could be told apart (core.exec_util.digests_from_sum_output); a file
        with no line, or a line that is not clear, is left out - the caller
        asks :meth:`checksum` for that one. Empty when the server has no
        such tool or runs no commands (remembered as :meth:`checksum`
        does) or the connection is gone; never raises for that."""
        from core.exec_util import digests_from_sum_output

        tool = {"sha256": "sha256sum", "sha1": "sha1sum", "md5": "md5sum"}.get(algorithm)
        if not tool or not paths or algorithm in self._checksum_unavailable:
            return {}
        result: dict[str, str] = {}
        chunk: list[str] = []
        size = 0
        prefix = len(tool) + 4
        for path in paths:
            try:
                quoted = len(command_bytes(shlex.quote(path))) + 1
            except OSError:
                continue  # no command can name it: checksum() says so for it
            if chunk and (size + quoted > self.CHECKSUM_COMMAND_MAX - prefix
                          or len(chunk) >= self.CHECKSUM_FILES_MAX):
                if not self._checksum_chunk(tool, algorithm, chunk, result,
                                            digests_from_sum_output):
                    return result
                chunk, size = [], 0
            chunk.append(path)
            size += quoted
        if chunk:
            self._checksum_chunk(tool, algorithm, chunk, result, digests_from_sum_output)
        return result

    def _checksum_chunk(self, tool: str, algorithm: str, chunk: list[str], result: dict,
                        parse) -> bool:
        """One command of :meth:`checksum_many`; False when no further one
        is worth sending (no tool, no commands, no connection)."""
        command = command_bytes(f"{tool} -- " + " ".join(shlex.quote(p) for p in chunk))
        try:
            ran = self._run_on_channel(f"SSH {tool}", lambda chan: chan.exec_command(command))
        except _ExecRefused as exc:
            reason = exc.__cause__ or exc
            for name in ("sha256", "sha1", "md5"):
                self._checksum_unavailable[name] = (
                    f"the server refuses to run commands ({reason})")
            return False
        except InterruptedError:
            raise
        except (OSError, paramiko.SSHException) as exc:
            log.debug("batch %s of %d files failed: %s", tool, len(chunk), exc)
            return False
        stderr = ran.stderr.decode("utf-8", errors="replace")
        if command_missing(ran.returncode, stderr, tool):
            log.debug("%s unavailable on %s: %s", tool, self._profile.host, stderr.strip())
            self._checksum_unavailable[algorithm] = "missing"
            return False
        if ran.truncated_stdout:
            return True  # each file is asked on its own then
        # A file the tool could not read has no line, the others count
        # (a non-zero exit then says only that one failed).
        names = {wire_path(path): path for path in chunk}
        for name, digest in parse(ran.stdout, list(names), algorithm).items():
            result[names[name]] = f"{algorithm}:{digest}"
        return True

    def _attr_to_item(self, attr: paramiko.SFTPAttributes, name_override: str = "") -> FileItem:
        mode = attr.st_mode or 0
        is_link = stat_module.S_ISLNK(mode)
        is_dir = stat_module.S_ISDIR(mode)

        mtime = attr.st_mtime or 0
        modified = datetime.fromtimestamp(mtime) if mtime else datetime.fromtimestamp(0)
        atime = attr.st_atime or 0
        accessed = datetime.fromtimestamp(atime) if atime else None

        return FileItem(
            name=name_override or attr.filename,
            size=attr.st_size or 0,
            modified=modified,
            permissions=mode & 0o7777,
            is_dir=is_dir,
            is_link=is_link,
            owner=str(attr.st_uid) if attr.st_uid is not None else "",
            group=str(attr.st_gid) if attr.st_gid is not None else "",
            accessed=accessed,
        )
