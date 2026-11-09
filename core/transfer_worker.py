"""Transfer worker — runs file transfers on a QThread."""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import re
import stat as stat_module
import string
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from queue import Queue
from threading import Event
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, pyqtSignal

from core import read_spool, transfer_hooks
from core.local_fs import create_private_file, open_own_partial, same_entry
from core.posix_compat import fchmod_private
from core.path_policy import hidden_sibling_name, safe_join

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

PROGRESS_INTERVAL = 0.1  # Minimum seconds between progress signals
SPEED_WINDOW = 3.0  # Seconds for rolling speed average
# 1 MiB per read/write: protocols that do one synchronous request per call
# (SMB via smbclient, ...) paid a round trip per 64 KiB before.
CHUNK_SIZE = 1024 * 1024
#: rename / link answers that mean "not this way here": another file system
#: (EXDEV), no hard links on it (EPERM / ENOTSUP / EOPNOTSUPP on vfat, exFAT,
#: some FUSE file systems), too many links (EMLINK). The copy takes over.
_RENAME_FALLBACK_ERRNOS = frozenset(
    {errno.EXDEV, errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EMLINK}
)
# Bytes compared at each end of a partial before a resume appends to it.
RESUME_VERIFY_WINDOW = 64 * 1024


# A partial is named ``.<name>.part-<job id>-<source fingerprint>``. The
# fingerprint records which version of the source its bytes came from, so
# a resume never appends a changed source to an older version's head.
PARTIAL_MARK = ".part-"
FINGERPRINT_LEN = 8
JOB_ID_LEN = 8
_PARTIAL_TAIL_BYTES = JOB_ID_LEN + 1 + FINGERPRINT_LEN


def source_fingerprint(item) -> str:
    """Short digest of a source's size and modification time, or "" when
    the backend reports no modification time (then nothing is resumed).

    A symlink's own time does not change with its target's content, so a
    link has no fingerprint either."""
    if item is None or getattr(item, "is_link", False):
        return ""
    size = int(getattr(item, "size", 0) or 0)
    modified = getattr(item, "modified", None)
    try:
        stamp = float(modified.timestamp()) if modified is not None else 0.0
    except (AttributeError, OSError, OverflowError, ValueError):
        stamp = 0.0
    if stamp <= 0:
        return ""
    text = f"{size}:{round(stamp * 1_000_000)}"
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:FINGERPRINT_LEN]


def partial_prefix(filename: str) -> str:
    """``.<filename>.part-``; for a name near the 255-byte limit the name
    is cut and a digest of the whole name keeps it unique."""
    return hidden_sibling_name(filename, PARTIAL_MARK, reserve=_PARTIAL_TAIL_BYTES)


def partial_name(filename: str, job_id: str, fingerprint: str) -> str:
    """The temp file name a transfer of *filename* writes to."""
    tail = f"{job_id}-{fingerprint}" if fingerprint else job_id
    return partial_prefix(filename) + tail


def partial_fingerprint(name: str, filename: str) -> str:
    """The source fingerprint recorded in partial *name*, "" when none."""
    prefix = partial_prefix(filename)
    if not name.startswith(prefix):
        return ""
    _, sep, fingerprint = name[len(prefix):].rpartition("-")
    if (
        sep
        and len(fingerprint) == FINGERPRINT_LEN
        and all(c in string.hexdigits for c in fingerprint)
    ):
        return fingerprint.lower()
    return ""


_PARTIAL_TAIL_RE = re.compile(r"[0-9a-f]{%d}-[0-9a-f]{%d}" % (JOB_ID_LEN, FINGERPRINT_LEN))


def is_partial_name(name: str, filename: str | None = None) -> bool:
    """True when *name* has exactly the shape of a partial axross writes
    and may resume or remove: ``.<filename>.part-<job id>-<fingerprint>``
    (eight hex digits each). A user's ``.video.mp4.part-1-notes`` is not
    one: it was adopted as a partial, then removed (review round 8).
    Without *filename*, any ``.<something>.part-<hex8>-<hex8>``."""
    if filename is not None:
        prefix = partial_prefix(filename)
        return name.startswith(prefix) and bool(_PARTIAL_TAIL_RE.fullmatch(name[len(prefix):]))
    head, mark, tail = name.rpartition(PARTIAL_MARK)
    return bool(mark and head.startswith(".") and len(head) > 1
                and _PARTIAL_TAIL_RE.fullmatch(tail))


#: Partial files a worker of this process is writing now: no other job may
#: adopt one (two copies of one file appended into one partial, and both
#: committed it - review round 8).
_LIVE_PARTIALS: set[str] = set()
_LIVE_PARTIALS_LOCK = threading.Lock()


def partial_in_use(path: str) -> bool:
    """A job of this process is writing the partial *path* now."""
    with _LIVE_PARTIALS_LOCK:
        return path in _LIVE_PARTIALS


def _claim_live_partial(path: str) -> bool:
    """Mark *path* as written by the calling job; False when another job
    of this process has it."""
    with _LIVE_PARTIALS_LOCK:
        if path in _LIVE_PARTIALS:
            return False
        _LIVE_PARTIALS.add(path)
        return True


def _release_live_partials(paths) -> None:
    with _LIVE_PARTIALS_LOCK:
        for path in paths:
            _LIVE_PARTIALS.discard(path)


_FALLBACK_UMASK: int | None = None


def process_umask() -> int:
    """This process's umask, read without changing it where possible.

    os.umask() can only be read by setting it, which for a moment lets
    another thread create a file with the wrong mode; /proc avoids that.

    Read anew on every call - the umask can change while axross runs (a
    bracket such as adb's key generation, a script) - but as raw bytes:
    a text-mode read of the ~60 lines cost ~80 µs, twice per copied file.
    """
    global _FALLBACK_UMASK
    try:
        fd = os.open("/proc/self/status", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            data = os.read(fd, 16384)
        finally:
            os.close(fd)
        at = data.find(b"\nUmask:")
        if at >= 0:
            return int(data[at + 7 : data.index(b"\n", at + 7)].strip(), 8)
    except (OSError, ValueError, IndexError):
        pass
    if _FALLBACK_UMASK is None:
        current = os.umask(0o022)
        os.umask(current)
        _FALLBACK_UMASK = current
    return _FALLBACK_UMASK


def copy_mode(source_mode: int | None) -> int | None:
    """The permission bits a copy of a *source_mode* file gets, like cp:
    the source's rwx bits less the umask, never set-id or sticky bits.
    ``None`` when the source's mode is unknown (the backend default)."""
    if not source_mode:
        return None
    return source_mode & 0o777 & ~process_umask()


def _read_exact(handle, size: int) -> bytes:
    """Up to *size* bytes, across short reads; fewer only at EOF."""
    parts: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = handle.read(remaining)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8", errors="replace")
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


#: errno values that say the destination has no room: its file system or
#: the user's quota is full, or the file is larger than it allows.
_OUT_OF_SPACE_ERRNOS = frozenset(
    code for code in (getattr(errno, name, None) for name in ("ENOSPC", "EDQUOT", "EFBIG"))
    if code is not None
)
#: NT status codes (an SMB server's answer, as smbprotocol carries it in
#: ``.status`` of its own, non-OSError exceptions) for the same: the disk
#: or the quota is full.
_OUT_OF_SPACE_NT_STATUS = frozenset({0xC000007F, 0xC0000044})


def is_out_of_space(exc: BaseException) -> bool:
    """True when *exc*, or an error it was raised from, says the
    destination ran out of space (ENOSPC, EDQUOT, EFBIG, a RamFS cap, an
    SMB STATUS_DISK_FULL or STATUS_QUOTA_EXCEEDED)."""
    from core.ram_fs import RamFsCapacityError

    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, RamFsCapacityError):
            return True
        if isinstance(current, OSError) and current.errno in _OUT_OF_SPACE_ERRNOS:
            return True
        status = getattr(current, "status", None)
        if isinstance(status, int) and status in _OUT_OF_SPACE_NT_STATUS:
            return True
        # The error it was raised from, as a traceback shows it.
        current = current.__cause__ or (
            None if current.__suppress_context__ else current.__context__
        )
    return False


def _backend_label(backend) -> str:
    """The label the operation journal records for *backend*."""
    if backend is None:
        return ""
    return getattr(backend, "name", type(backend).__name__)


def _backend_can_rename(backend) -> bool:
    """Whether the registry lets *backend*'s class rename (TFTP and other
    write-once protocols do not); a class it does not know is asked."""
    try:
        from core import backend_registry

        class_name = type(backend).__name__
        for info in backend_registry.all_backends():
            if info.class_name == class_name:
                return bool(info.capabilities.can_rename)
    except Exception as exc:  # noqa: BLE001 - no registry: try the rename
        log.debug("backend registry lookup failed: %s", exc)
    return True


class TransferDirection(Enum):
    UPLOAD = auto()
    DOWNLOAD = auto()
    RELAY = auto()  # Remote A -> local buffer -> Remote B


class TransferStatus(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


#: Checksum prefixes that fingerprint one stored copy, not its content:
#: the same bytes stored twice can carry different values (an S3
#: multipart / SSE-KMS / SSE-C ETag, a WebDAV getetag). Comparing them
#: after a copy reported identical files as corrupt, so they are never
#: compared; forced verification streams both sides instead.
_STORAGE_FINGERPRINTS = frozenset({"s3-etag", "etag"})


def _hashes_whole_local_file(backend) -> bool:
    """True when *backend*'s checksum is LocalFS's: SHA-256 of a full read."""
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS) and type(backend).checksum is LocalFS.checksum


def _could_match(value, other_backend) -> bool:
    """Whether native checksum *value* can be compared with the other side's
    at all: not empty, no storage fingerprint, and SHA-256 when the other
    side is a local file (LocalFS returns nothing else)."""
    if not value:
        return False
    algo = value.partition(":")[0]
    if algo in _STORAGE_FINGERPRINTS:
        return False
    return algo == "sha256" or not _hashes_whole_local_file(other_backend)


def _local_stamp(path: str) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size


class _StreamedHash:
    """SHA-256 of a local source while it is copied from its first byte:
    a copy from a local file then reads it once, not twice more for the
    check (before: one read to copy, one for each side's checksum)."""

    def __init__(self, job: "TransferJob", offset: int) -> None:
        self._job = job
        local = offset == 0 and _hashes_whole_local_file(job.source_backend)
        self._stamp = _local_stamp(job.source_path) if local else None
        self._hash = hashlib.sha256() if self._stamp is not None else None

    def update(self, chunk: bytes) -> None:
        if self._hash is not None:
            self._hash.update(chunk)

    def finish(self) -> None:
        if self._hash is not None:
            self._job.streamed_source_checksum = f"sha256:{self._hash.hexdigest()}"
            self._job.streamed_source_stamp = self._stamp


def _streamed_source_checksum(job: "TransferJob") -> str | None:
    """The hash read while copying, while the source is unchanged since the
    read began (mtime and size: a rewrite of the same size moves the mtime).
    Otherwise None, and the source is read again as before."""
    checksum = getattr(job, "streamed_source_checksum", "")
    stamp = getattr(job, "streamed_source_stamp", None)
    if not checksum or stamp is None:
        return None
    if _local_stamp(job.source_path) != stamp:
        log.debug("Source %s changed since it was read; hashing it again", job.source_path)
        return None
    return checksum


def _may_compare(backend, path: str, other_backend, *, written: bool, against=None) -> bool:
    """False when *backend* says (``checksum_kinds``) that its checksum of
    *path* can only be of a kind :func:`_could_match` rejects against
    *other_backend* - a storage fingerprint, an MD5 against a local file:
    asking would be a request per file for a value that is never compared
    (S3: a HEAD, WebDAV: a PROPFIND). The verdict is the same as with the
    answer: the default check skips, a forced one streams both sides.
    *written*: the file was just written by this transfer. *against*: the
    other side's checksum when it is known already - only its algorithm
    can be compared. A backend without the method, or one that does not
    know, is asked."""
    kinds_of = getattr(backend, "checksum_kinds", None)
    if not callable(kinds_of):
        return True
    try:
        kinds = kinds_of(path, written=written)
    except Exception as exc:  # noqa: BLE001 - unknown: ask
        log.debug("checksum_kinds of %s failed: %s", path, exc)
        return True
    if kinds is None:
        return True
    if against:
        return against.partition(":")[0] in kinds
    return any(_could_match(f"{kind}:", other_backend) for kind in kinds)


def _native_checksum(backend, path: str, side: str):
    """``backend.checksum(path)``, or None when it fails."""
    try:
        return backend.checksum(path)
    except Exception as exc:
        hooks = transfer_hooks.current()
        if isinstance(exc, InterruptedError) and hooks is not None and hooks.cancelled():
            raise  # Cancel during the checksum (an SSH exec): the job is cancelled
        log.debug("%s checksum unavailable: %s", side, exc)
        return None


class _ChecksumMismatch(Exception):
    """Raised by _verify_integrity when source and destination
    checksums disagree after a completed transfer. Caught by the
    worker loop and surfaced as a regular TransferStatus.ERROR with
    a specific error message so the UI can distinguish data-corruption
    from other failure modes."""


class _SameEntry(OSError):
    """Source and destination turned out to be one file under two paths.

    Raised before the temp file replaces the destination; a move would
    otherwise delete "the source", which is the only copy."""


#: Kernel file systems whose files list a size (4096, 0) that a read does
#: not yield: sysfs attributes, procfs, device nodes.
_PSEUDO_ROOTS = ("/sys", "/proc", "/dev")
#: The sizes such a file lists: a page (sysfs) or nothing (procfs, a
#: device node). Any other size under those folders is a real one.
_PSEUDO_SIZES = (0, 4096)


def _is_pseudo_file(path: str) -> bool:
    """*path* lies under /sys, /proc or /dev (a POSIX path)."""
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    import posixpath

    clean = posixpath.normpath(path)
    if clean.startswith("//"):
        clean = "/" + clean.lstrip("/")
    return any(clean == root or clean.startswith(root + "/") for root in _PSEUDO_ROOTS)


def _is_pseudo_source(backend, path: str, listed: int) -> bool:
    """A kernel pseudo file, whose short read is no lost data: under
    /sys, /proc or /dev on a backend whose "/" is a whole machine's root
    (``machine_root``: local, SFTP, SCP, the shells, ADB) AND listed with
    such a file's size (:data:`_PSEUDO_SIZES`). On an FTP, WebDAV or any
    other server "/dev" is an ordinary folder, and a 3 MB file under it
    that delivered half was saved as the copy."""
    if listed not in _PSEUDO_SIZES or not _is_pseudo_file(path):
        return False
    from core.capability_contracts import caps_for_backend

    try:
        return bool(getattr(caps_for_backend(backend), "machine_root", False))
    except Exception:  # noqa: BLE001 - unknown: no exemption
        return False


class _PartialChanged(OSError):
    """The temp file holds other bytes than the job wrote into it (another
    transfer wrote to it too): it is not committed, nor kept."""


class _ShortRead(OSError):
    """The source's read ended (without an error) before its size: the
    copy is refused, the destination left as it was."""


def _source_reads_at_offset(backend) -> bool:
    """Whether a resume could read *backend*'s file from where a partial
    ends (its caps' seekable_reads): a source read whole (POP3, a mail
    store, a spooled download) yields the same short bytes again."""
    from core.server_ops import _known_backend_capabilities

    caps = _known_backend_capabilities(backend)
    return caps is None or bool(getattr(caps, "seekable_reads", True))


class _DestinationKept(Exception):
    """``if_exists="newer"`` found a destination at least as new as the
    source: the job ends without writing, and a move keeps its source."""


@dataclass
class TransferJob:
    """Represents a single file transfer."""

    job_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    source_path: str = ""
    dest_path: str = ""
    direction: TransferDirection = TransferDirection.DOWNLOAD
    total_bytes: int = 0
    transferred_bytes: int = 0
    speed: float = 0.0
    status: TransferStatus = TransferStatus.PENDING
    error_message: str = ""
    #: The exception behind ``error_message`` (traceback dropped): the
    #: Transfers panel shows core.user_errors.describe() of it, in the
    #: interface language; the raw text stays in the log and the tooltip.
    error: BaseException | None = field(default=None, repr=False, compare=False)
    cancel_event: Event = field(default_factory=Event)
    filename: str = ""
    source_backend: object = field(default=None, repr=False)
    dest_backend: object = field(default=None, repr=False)
    resume: bool = False  # If True, attempt to resume from partial transfer
    temp_path: str = ""
    move: bool = False  # If True, delete source file after successful transfer
    use_temp_file: bool = True  # If False, write directly to dest (skip temp+rename)
    # When True, _verify_integrity forces a full client-side stream-
    # sha256 of both source and dest if native checksums are missing,
    # empty, or use incompatible algorithms. Useful for security-
    # sensitive moves where "backend had no cheap hash so we skipped"
    # is not an acceptable outcome. Costs a re-read of the file on
    # each side; off by default because most backends already carry
    # a cheap native fingerprint.
    verify_checksum: bool = False
    operation_id: str = ""
    # The user operation this job is part of (core.operation_journal
    # new_batch_id): one F5 / F6 / drop is undone as one.
    batch_id: str = ""
    # What to do with an existing destination (core.transfer_conflicts):
    # "overwrite" (the default), "fail" or "newer". Checked right before
    # the first write and again right before the temp file is renamed.
    if_exists: str = "overwrite"
    # True when "newer" found a destination at least as new: nothing was
    # written and a move kept its source.
    skipped: bool = False
    # "sha256:<hex>" of the bytes this run read from a local source, with
    # the source's (mtime_ns, size) when the read began: the integrity check
    # takes it instead of reading the whole source again while that stamp
    # still holds (_StreamedHash).
    streamed_source_checksum: str = ""
    streamed_source_stamp: tuple[int, int] | None = None
    # source_fingerprint() of the source when the job was queued; named in
    # the temp file so a later resume can tell whether the source changed.
    source_fingerprint: str = ""
    # The source's permission bits and modification time (epoch seconds)
    # when queued, None when unknown: the copy gets them (see copy_mode).
    source_mode: int | None = None
    source_mtime: float | None = None
    # False for a failed row that no retry can fix (a name that cannot be
    # joined safely); retry_job refuses it.
    retryable: bool = True
    # True once retry_job queued a new job for this failed one: "Retry
    # Failed" walks every failed row, and a second press must not queue
    # the same transfer again.
    retried: bool = False
    # The destination's folder was made by the walk that queued this job
    # (its mkdir succeeded: it was not there, so it held nothing). With
    # if_exists "overwrite" a direct write then takes the destination as
    # absent instead of asking the server per file whether there is one
    # to snapshot (WebDAV: a PROPFIND, S3: a HEAD and a LIST). Never used
    # for "fail" / "newer": a file that appeared since must still be
    # found, and those modes look right before writing as before.
    dest_folder_new: bool = False
    # Set by the worker while it runs: the source's size before a move
    # copied it, or a copy read a local file (None for other copies or
    # when unknown) - a copy that comes out shorter is not committed (see
    # _refuse_short_move, _refuse_short_local_copy) - and whether the
    # integrity check compared the bytes (then the temp file's size needs
    # no second look before the rename).
    move_source_size: int | None = field(default=None, repr=False, compare=False)
    integrity_compared: bool = field(default=False, repr=False, compare=False)

    @property
    def eta_seconds(self) -> float:
        if self.speed <= 0 or self.total_bytes <= 0:
            return 0.0
        remaining = self.total_bytes - self.transferred_bytes
        return remaining / self.speed

    @property
    def progress_percent(self) -> float:
        if self.total_bytes <= 0:
            return 0.0
        return min(100.0, (self.transferred_bytes / self.total_bytes) * 100.0)


def _local_partial_problem(path: str) -> str:
    """Why the local partial *path* is not resumed ("" = it may be): not a
    regular file of this user with one name (looked at without following
    a link) - a file system that shows another owner (a CIFS or vfat mount
    with uid=) restarts the copy instead of failing it."""
    from core.local_fs import own_file_problem

    try:
        return own_file_problem(os.lstat(path))
    except OSError as exc:
        return str(exc)


def _set_mode_through(fh, mode: int) -> None:
    """*mode* onto the open file *fh*; best effort, as a chmod by name was
    (vfat, a FUSE mount may refuse it - the file then stays as created)."""
    try:
        fchmod_private(fh.fileno(), mode)
    except OSError as exc:
        log.debug("could not set mode %04o on %s: %s", mode, getattr(fh, "name", "?"), exc)


def _private_local(backend) -> bool:
    """Whether *backend* is the local file system whose temp files are
    written through one checked descriptor (core.local_fs.open_own_partial,
    create_private_file): LocalFS with its own open_write, not a subclass
    that confines or redirects writes, nor a test's stand-in."""
    check = getattr(backend, "private_writes", None)
    try:
        return bool(callable(check) and check())
    except Exception:  # noqa: BLE001 - a stand-in without the method's state
        return False


def _is_local(backend) -> bool:
    """A backend on this machine's disk: copying from or to it runs at
    disk speed, it is no network leg of a job."""
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


class _JobProgress:
    """The progress callback of one job, counting the network phases.

    A job may move its bytes over the network more than once: a reader
    that downloads in ``open_read`` (Drive, S3 ...), the copy loop, a
    writer that uploads in ``close()`` (OneDrive, FTP ...). Each phase
    reports 0..total bytes of its own (core.transfer_hooks); the bar
    shows their sum over the number of network phases, so it reaches 100 %
    when the last byte is on the destination - not when a spooling writer
    has buffered everything at disk speed. A copy loop between a local or
    already downloaded source and a local or spooling destination is no
    network leg and moves the bar not at all (it still checks Cancel).
    Speed and ETA follow the bar, i.e. the job's own throughput.

    Called as ``progress(transferred, total)`` by the copy loop; ``hooks``
    is what the backends see.
    """

    def __init__(self, job: "TransferJob", report) -> None:
        self._job = job
        self._report = report  # report(done, total): the bar, the speed
        self.hooks = transfer_hooks.TransferHooks(job.cancel_event, self._network)
        if _is_local(job.dest_backend) and job.dest_path:
            # A download spools next to its local destination, not in /tmp.
            self.hooks.spool_dir = os.path.dirname(os.path.abspath(job.dest_path))
        self._finished = 0  # network phases done
        self._phases = 1  # network phases in all (known once both ends are open)
        self._copy_weight = 1
        self._copy_started = False
        self._shown = 0
        self._shown_total = -1

    def _show(self, current: int, total: int) -> None:
        total = max(int(total or 0), 0)
        phases = max(self._phases, 1)
        done = (self._finished * total + min(max(current, 0), total)) // phases \
            if total else 0
        # Never backwards inside a job: a phase that starts over (an
        # upload resumed where the server says it stands) shows no dip.
        if total == self._shown_total:
            done = max(done, self._shown)
        self._shown, self._shown_total = done, total
        self._report(done, total)

    def _network(self, kind: str, done: int, total: int | None) -> None:
        job_total = self._job.total_bytes
        if kind == "download" and not self._copy_started:
            # open_read downloads before the copy loop: one leg, and one
            # more after it unless the destination is this machine.
            self._phases = 1 + (0 if _is_local(self._job.dest_backend) else 1)
        if total and job_total <= 0:
            job_total = total
        if total and total != job_total and job_total > 0:
            done = done * job_total // total
        try:
            self._show(done, job_total)
        except InterruptedError:
            # The bar only: whether a Cancel stops the backend is decided by
            # the hooks (TransferHooks.sent checks it unless the upload is
            # already committed).
            pass

    def copy_starts(self) -> None:
        """Both ends are open: how many network legs the job has is known."""
        if self._copy_started:
            return
        self._copy_started = True
        job, hooks = self._job, self.hooks
        if hooks.downloaded:
            self._finished = 1
        source_done = hooks.downloaded or _is_local(job.source_backend)
        dest_done = hooks.upload_expected or _is_local(job.dest_backend)
        upload = 1 if hooks.upload_expected else 0
        self._copy_weight = 0 if source_done and dest_done and (self._finished or upload) else 1
        self._phases = max(self._finished + self._copy_weight + upload, 1)

    def copy_ends(self) -> None:
        """The copy loop is through; what follows is the writer's upload."""
        if self._copy_started:
            self._finished += self._copy_weight
            self._copy_weight = 0

    def __call__(self, transferred: int, total: int) -> None:
        if self._copy_weight or not self._copy_started:
            self._show(transferred, total)
        else:
            self.hooks.check()
            self._show(0, total)


def _hooks_of(job: "TransferJob", progress_callback) -> transfer_hooks.TransferHooks:
    """The hooks the backends get for *job*: those of its _JobProgress, or
    Cancel alone for a caller that passed a plain callback."""
    hooks = getattr(progress_callback, "hooks", None)
    if isinstance(hooks, transfer_hooks.TransferHooks):
        return hooks
    return transfer_hooks.TransferHooks(job.cancel_event)


def _open_sequential(backend, path: str):
    """``backend.open_read(path)`` for the copy loop, which reads front to
    back once: a download may stream instead of spooling
    (core.read_spool.sequential_reads)."""
    with read_spool.sequential_reads():
        return backend.open_read(path)


def _copy_starts(progress_callback) -> None:
    starts = getattr(progress_callback, "copy_starts", None)
    if starts is not None:
        starts()


def _copy_ends(progress_callback) -> None:
    ends = getattr(progress_callback, "copy_ends", None)
    if ends is not None:
        ends()


def _was_cancelled(job: "TransferJob", exc: BaseException) -> bool:
    """*exc* is the Cancel of *job*, re-raised under another type by a
    library on the way out (requests wraps an InterruptedError raised in
    the middle of a request body as ConnectionError)."""
    if not job.cancel_event.is_set():
        return False
    seen = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, InterruptedError):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


def _without_traceback(exc: BaseException) -> BaseException:
    """*exc* (and the exceptions it was raised from) without their
    tracebacks: a failed job keeps its exception for the Transfers panel,
    not the frames - and with them the backends - of the worker."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        current.__traceback__ = None
        current = current.__cause__ or current.__context__
    return exc

class TransferWorker(QObject):
    """Processes transfer jobs from a queue, emitting progress signals.

    Designed to run on a QThread.
    """

    # object, not int: a Qt int is 32 bits, and 3 GiB would arrive as -1 GiB.
    progress = pyqtSignal(str, object, object)  # job_id, bytes_done, bytes_total
    speed_update = pyqtSignal(str, float)  # job_id, bytes_per_second
    job_finished = pyqtSignal(str)  # job_id
    job_error = pyqtSignal(str, str)  # job_id, error_message
    job_started = pyqtSignal(str)  # job_id

    def __init__(self, parent=None, *, scheduler=None, index: int = 0):
        super().__init__(parent)
        self._queue: Queue[TransferJob | None] = Queue()
        self._running = True
        # A core.transfer_pool.JobScheduler shared with the other workers
        # of a TransferManager; None: this worker's own queue.
        self._scheduler = scheduler
        self._index = index

    def enqueue(self, job: TransferJob) -> None:
        if self._scheduler is not None:
            self._scheduler.put(job)
            return
        self._queue.put(job)

    def enqueue_many(self, jobs) -> None:
        """:meth:`enqueue` of each of *jobs*, in order (one lock for all)."""
        if self._scheduler is not None:
            self._scheduler.put_many(jobs)
            return
        for job in jobs:
            self._queue.put(job)

    def stop(self) -> None:
        self._running = False
        if self._scheduler is not None:
            self._scheduler.wake()
        else:
            self._queue.put(None)  # Sentinel to unblock

    @staticmethod
    def _journal_identity(job: TransferJob) -> dict:
        """Backend label and direction for every journal event of *job*.

        Undo reads the FINISH event, so it has to carry them too: without
        the direction a cross-backend move looks like a same-backend
        rename, and without the labels undo cannot tell which host it is
        on or which host the data came from.
        """
        details = {
            "direction": job.direction.name,
            "source_backend": _backend_label(job.source_backend),
        }
        if job.batch_id:
            details["batch"] = job.batch_id
        return {"backend": _backend_label(job.dest_backend), "details": details}

    @staticmethod
    def _record_journal_phase(job: TransferJob, phase: str) -> None:
        if not job.operation_id:
            return
        try:
            from core.operation_journal import record_phase

            record_phase(
                job.operation_id,
                phase,
                "move" if job.move else "transfer",
                source=job.source_path,
                dest=job.dest_path,
                bytes_total=job.total_bytes,
                bytes_done=job.transferred_bytes,
                **TransferWorker._journal_identity(job),
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("transfer journal phase %s failed: %s", phase, exc)

    @staticmethod
    def _finish_journal(
        job: TransferJob,
        *,
        status: str,
        error: str = "",
    ) -> None:
        if not job.operation_id:
            return
        try:
            from core.operation_journal import finish_operation

            fields = TransferWorker._journal_identity(job)
            if job.move and status == "done" and job.dest_backend is not None:
                # What the move put there: undo moves it back only while the
                # entry under that name is still this one (core.undo).
                from core.undo import entry_identity

                identity = entry_identity(job.dest_backend, job.dest_path)
                if identity:
                    fields["details"]["dest_identity"] = identity
            finish_operation(
                job.operation_id,
                "move" if job.move else "transfer",
                status=status,
                source=job.source_path,
                dest=job.dest_path,
                bytes_total=job.total_bytes,
                bytes_done=job.transferred_bytes,
                error=error,
                **fields,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("transfer journal finish failed: %s", exc)

    def run(self) -> None:
        """Main loop — processes jobs from the queue."""
        log.info("Transfer worker started")
        if self._scheduler is not None:
            self._run_shared()
        else:
            while self._running:
                job = self._queue.get()
                if job is None:
                    break
                self._process_job(job)
        log.info("Transfer worker stopped")

    def _run_shared(self) -> None:
        """Take jobs from the shared scheduler until :meth:`stop`."""
        scheduler = self._scheduler
        while self._running:
            taken = scheduler.take(self._index, lambda: not self._running)
            if taken is None:
                break
            job, claimed = taken
            try:
                if claimed:
                    self._process_job(job)
                else:
                    self._report_cancelled(job)
            finally:
                scheduler.done(job)

    def _report_cancelled(self, job: TransferJob) -> None:
        """A job cancelled while it waited for a busy session or path: the
        signals and journal entries _process_job gives a cancelled job,
        without a single backend call (the session belongs to another job)."""
        job.status = TransferStatus.ACTIVE
        self.job_started.emit(job.job_id)
        self._record_journal_phase(job, "worker_start")
        job.error_message = "Cancelled"
        self._finish_journal(job, status="cancelled", error="Cancelled")
        job.status = TransferStatus.CANCELLED
        self.job_error.emit(job.job_id, "Cancelled")
        log.info("Transfer cancelled: %s", job.filename)

    def _process_job(self, job: TransferJob) -> None:
        job.status = TransferStatus.ACTIVE
        job.streamed_source_checksum, job.streamed_source_stamp = "", None
        self.job_started.emit(job.job_id)
        self._record_journal_phase(job, "worker_start")
        log.debug("Transfer started: %s -> %s (%s, %d bytes%s)", job.source_path, job.dest_path,
                  job.direction.name.lower(), job.total_bytes, ", move" if job.move else "")

        speed_samples: deque[tuple[float, int]] = deque()
        last_progress_time = 0.0
        # What the GUI was last told: the same (done, total) or speed again
        # is not sent (a small file sent 6 signals, 3 of them repeats).
        last_sent: list = [None, job.speed]

        def send_progress(done: int, total: int) -> None:
            if last_sent[0] != (done, total):
                last_sent[0] = (done, total)
                self.progress.emit(job.job_id, done, total)

        def report_progress(transferred: int, total: int) -> None:
            nonlocal last_progress_time

            if job.cancel_event.is_set():
                raise InterruptedError("Transfer cancelled")

            job.transferred_bytes = transferred
            job.total_bytes = total

            now = time.monotonic()
            speed_samples.append((now, transferred))

            # Trim old samples
            while speed_samples and (now - speed_samples[0][0]) > SPEED_WINDOW:
                speed_samples.popleft()

            # Calculate speed
            if len(speed_samples) >= 2:
                dt = speed_samples[-1][0] - speed_samples[0][0]
                db = speed_samples[-1][1] - speed_samples[0][1]
                if dt > 0:
                    job.speed = db / dt

            # Rate-limit signal emission
            if now - last_progress_time >= PROGRESS_INTERVAL:
                last_progress_time = now
                send_progress(transferred, total)
                if job.speed != last_sent[1]:
                    last_sent[1] = job.speed
                    self.speed_update.emit(job.job_id, job.speed)

        # The copy loop calls it; the backends see its hooks (network
        # phases of spooling readers and writers, Cancel during them).
        progress_callback = _JobProgress(job, report_progress)

        try:
            # A source the backend will not let go out by a move (a Google
            # Doc: only its export would arrive) is refused before any copy.
            refuse_move_out = getattr(job.source_backend, "refuse_move_out", None)
            if job.move and callable(refuse_move_out):
                refuse_move_out(job.source_path, job.dest_backend)
            renamed = self._move_by_rename(job)
            if renamed is None:
                renamed = self._move_on_server(job)
            if renamed is not None:
                # One rename on the same file system: no byte copied, nothing
                # to verify (it is the same file), no source left to remove.
                job.transferred_bytes = job.total_bytes = renamed
                self._finish_journal(job, status="done")
                job.status = TransferStatus.DONE
                send_progress(renamed, renamed)
                self.job_finished.emit(job.job_id)
                log.info("Transfer complete: %s (renamed)", job.filename)
                return
            # A move compares the source's size after the copy with this, so
            # it never deletes data written to the source meanwhile.
            size_before = self._move_source_size(job)
            job.move_source_size, job.integrity_compared = size_before, False
            written = self._do_transfer(job, progress_callback)
            if written is not None:
                # What was written, not what the listing said when the job
                # was queued: a symlink is listed with the length of its
                # target path, and a source may have grown since.
                job.transferred_bytes = job.total_bytes = written
                # Now, not only after DONE: progress signals queued before
                # still carry the listing's size, and the GUI thread applies
                # them to this job; the written size must come after them.
                send_progress(written, written)

            # The integrity check ran inside _do_transfer, before the copy
            # replaced the destination: the temp file is checked before the
            # rename, a direct write before its rollback snapshot is let go.
            # After the rename a mismatch left the corrupt copy in place of
            # the original destination.

            # Move mode: delete source after successful transfer
            if job.move and job.source_backend:
                from core.server_ops import refuse_changed_source, refuse_short_copy

                refuse_short_copy(job.source_path, size_before, written, job.dest_path)
                refuse_changed_source(
                    job.source_backend, job.source_path, size_before, job.dest_path
                )
                self._refuse_wrong_destination_size(job, size_before, written)
                try:
                    job.source_backend.remove(job.source_path)
                    log.info("Move: deleted source %s", job.source_path)
                except Exception as e:
                    raise OSError(
                        f"move partially completed: copied {job.source_path} "
                        f"to {job.dest_path}, but removing the source failed: {e}"
                    ) from e

            # The journal first, in every branch below: whoever waits for
            # the final status (or job_finished) reads the journal next.
            self._finish_journal(job, status="done")
            job.status = TransferStatus.DONE
            # Final progress update
            send_progress(job.total_bytes, job.total_bytes)
            self.job_finished.emit(job.job_id)
            log.info("Transfer complete: %s", job.filename)

        except _DestinationKept as exc:
            job.skipped = True
            self._finish_journal(job, status="skipped", error=str(exc))
            job.status = TransferStatus.DONE
            self.job_finished.emit(job.job_id)
            log.info("Transfer skipped: %s", exc)
            return

        except _ChecksumMismatch as exc:
            job.error_message = str(exc)
            self._finish_journal(job, status="error", error=str(exc))
            job.status = TransferStatus.ERROR
            self.job_error.emit(job.job_id, str(exc))
            log.error("Transfer integrity check FAILED: %s", exc)
            return

        except InterruptedError:
            self._report_job_cancelled(job)

        except Exception as e:
            if _was_cancelled(job, e):
                self._report_job_cancelled(job)
                return
            job.error_message = str(e)
            job.error = _without_traceback(e)
            self._finish_journal(job, status="error", error=str(e))
            job.status = TransferStatus.ERROR
            self.job_error.emit(job.job_id, str(e))
            log.error("Transfer error for %s: %s", job.filename, e)

    def _report_job_cancelled(self, job: TransferJob) -> None:
        job.error_message = "Cancelled"
        self._finish_journal(job, status="cancelled", error="Cancelled")
        job.status = TransferStatus.CANCELLED
        self.job_error.emit(job.job_id, "Cancelled")
        log.info("Transfer cancelled: %s", job.filename)

    @staticmethod
    def _move_by_rename(job: TransferJob) -> int | None:
        """Move a local file to a folder on the same file system by renaming
        it, as ``mv`` does: no copy, no hash, the times, mode and owner
        stay. Returns the size moved, or None when this move needs the copy
        (another backend, another file system, no hard links there, a
        resume).

        The rules of the copy hold: ``if_exists`` is checked as the copy
        checks it, and without "overwrite" the new name is made by
        ``link()``, which fails rather than replace a file that appeared
        meanwhile. A source that cannot be removed (no write permission on
        its folder) leaves everything as it was and fails the job - the copy
        would have left a second copy behind for the same error.
        """
        from core.local_fs import LocalFS

        if not job.move or job.resume:
            return None
        src, dst = job.source_backend, job.dest_backend
        if type(src) is not LocalFS or type(dst) is not LocalFS:
            return None
        if job.cancel_event.is_set():
            raise InterruptedError("Transfer cancelled")
        from core.storage_identity import same_entry

        if same_entry(src, job.source_path, dst, job.dest_path):
            raise OSError(f"source and destination are the same: {job.dest_path}")
        try:
            st = os.lstat(job.source_path)
            if os.stat(os.path.dirname(job.dest_path) or ".").st_dev != st.st_dev:
                return None
        except OSError:
            return None  # the copy reports what is wrong
        if not stat_module.S_ISREG(st.st_mode):
            # Regular files only: the copy refuses a FIFO or device and follows
            # a file link to its content - a rename would move them as they are.
            return None
        present = TransferWorker._check_existing_destination(job)
        if job.if_exists == "overwrite" or present:
            try:
                os.rename(job.source_path, job.dest_path)
            except OSError as exc:
                if exc.errno in _RENAME_FALLBACK_ERRNOS:
                    return None
                raise OSError(f"cannot move {job.source_path} to {job.dest_path}: {exc}") from exc
            return st.st_size
        try:
            os.link(job.source_path, job.dest_path, follow_symlinks=False)
        except FileExistsError as exc:
            raise FileExistsError(f"{job.dest_path} already exists; not overwritten") from exc
        except OSError as exc:
            if exc.errno in _RENAME_FALLBACK_ERRNOS:
                return None
            raise OSError(f"cannot move {job.source_path} to {job.dest_path}: {exc}") from exc
        try:
            os.unlink(job.source_path)
        except OSError as exc:
            try:
                os.unlink(job.dest_path)
            except OSError as undo_exc:
                log.error("Move: could not take back the new name %s: %s",
                          job.dest_path, undo_exc)
            raise OSError(
                f"cannot move {job.source_path}: removing it from its folder failed: {exc}"
            ) from exc
        return st.st_size

    @staticmethod
    def _move_on_server(job: TransferJob) -> int | None:
        """Move a file within ONE remote session by renaming it on the
        server (SFTP RENAME, FTP RNFR/RNTO, WebDAV MOVE, SMB, S3 copy on the
        server): no byte passes through this machine. Returns the size
        moved, or None when this move needs the copy (two sessions, a
        backend without rename, a folder or link, a destination that is
        there and may be replaced, a rename the server refused).

        A move inside one SFTP server used to download and upload every
        byte (40 MiB: 5.7 s against 4 ms for the rename).

        The rules of the copy hold: ``if_exists`` is checked as the copy
        checks it, and only a destination that is not there is renamed
        onto - where the backend can, through ``rename_no_replace``, which
        the server refuses rather than replace a file that appeared
        meanwhile. A planned overwrite takes the copy, with its temp file
        and rollback. A refused rename that left both ends as they were
        falls back to the copy; one that left the file at both ends fails
        the job as a move whose source could not be removed does.
        """
        from core.local_fs import LocalFS

        if not job.move or job.resume:
            return None
        src, dst = job.source_backend, job.dest_backend
        if src is None or src is not dst or isinstance(src, LocalFS):
            return None
        rename = getattr(src, "rename_no_replace", None) or getattr(src, "rename", None)
        if not callable(rename) or not _backend_can_rename(src):
            return None
        if job.cancel_event.is_set():
            raise InterruptedError("Transfer cancelled")
        try:
            item = src.stat(job.source_path)
        except Exception as exc:  # noqa: BLE001 - the copy reports what is wrong
            log.debug("server-side move: cannot stat %s: %s", job.source_path, exc)
            return None
        if getattr(item, "is_dir", False) or getattr(item, "is_link", False):
            # The copy follows a file link to its content and refuses a
            # folder here; a rename would move them as they are.
            return None
        if TransferWorker._check_existing_destination(job) is not False:
            if job.if_exists != "overwrite":
                return None  # there, and the answers allow replacing it: the copy
            try:
                if dst.exists(job.dest_path):
                    return None
            except Exception as exc:  # noqa: BLE001 - unknown: the copy decides
                log.debug("server-side move: cannot check %s: %s", job.dest_path, exc)
                return None
        try:
            rename(job.source_path, job.dest_path)
        except Exception as exc:  # noqa: BLE001 - the state decides what follows
            source_there = TransferWorker._exists_or_none(src, job.source_path)
            dest_there = TransferWorker._exists_or_none(dst, job.dest_path)
            if source_there and dest_there is False:
                log.info("Server-side rename of %s refused (%s); copying instead",
                         job.source_path, exc)
                return None
            if source_there is False and dest_there:
                log.info("Server-side rename of %s reported %s but completed",
                         job.source_path, exc)
                return int(getattr(item, "size", 0) or 0)
            raise OSError(f"cannot move {job.source_path} to {job.dest_path} "
                          f"on the server: {exc}") from exc
        if TransferWorker._exists_or_none(dst, job.dest_path) is False:
            # A server that answered OK and renamed nothing: the copy.
            if TransferWorker._exists_or_none(src, job.source_path):
                log.warning("Server-side rename of %s changed nothing; copying instead",
                            job.source_path)
                return None
            raise OSError(f"moving {job.source_path} on the server lost track of it: "
                          f"{job.dest_path} is not there")
        return int(getattr(item, "size", 0) or 0)

    @staticmethod
    def _exists_or_none(backend, path: str) -> bool | None:
        try:
            return bool(backend.exists(path))
        except Exception as exc:  # noqa: BLE001 - unknown
            log.debug("cannot check whether %s exists: %s", path, exc)
            return None

    @staticmethod
    def _refuse_wrong_destination_size(job: TransferJob, size_before: int | None,
                                       written: int | None) -> None:
        """Raise :class:`OSError` when the committed destination of a move
        is not as long as the source (*size_before*; what the copy
        *written* where the source's backend lists 0): the source is then
        kept. Another job appending to the same partial gave a 4.9 MB
        "copy" of a 4 MB file, and the move deleted the source (review
        round 8). Not checked when a size is unknown."""
        if size_before is None or job.dest_backend is None:
            return
        expected = written if not size_before and written else size_before
        from core.server_ops import source_size

        size_now = source_size(job.dest_backend, job.dest_path)
        if size_now is None or size_now == expected:
            return
        raise OSError(
            f"{job.dest_path} holds {size_now} bytes after the copy, {job.source_path} "
            f"{expected}; the source was kept"
        )

    @staticmethod
    def _move_source_size(job: TransferJob) -> int | None:
        """The source's size before a move copies it, or a copy reads a
        file on this machine's disk (None for other copies): a copy of a
        local file cut while it was read is not committed either
        (:meth:`_refuse_short_local_copy`)."""
        if job.source_backend is None or not (job.move or _is_local(job.source_backend)):
            return None
        from core.server_ops import source_size

        return source_size(job.source_backend, job.source_path)

    def _verify_integrity(self, job: TransferJob, dest_path: str | None = None) -> None:
        """:meth:`_verify_integrity_now` under the job's Cancel: a backend
        that hashes on the server (SFTP runs ``sha256sum`` over an SSH
        exec channel) watches it, so Cancel ends a slow hash at once."""
        hooks = transfer_hooks.current()
        if hooks is None:
            hooks = transfer_hooks.TransferHooks(getattr(job, "cancel_event", None))
        with transfer_hooks.active(hooks):
            # By the class: tests call it with a stand-in for self.
            TransferWorker._verify_integrity_now(self, job, dest_path)

    def _verify_integrity_now(self, job: TransferJob, dest_path: str | None = None) -> None:
        """Compare source + dest checksum after a successful transfer.

        *dest_path*: the file to check on the destination backend, by
        default ``job.dest_path``; the temp-file route passes its temp file,
        so a mismatch is found while the original destination still exists.

        Default mode (``job.verify_checksum == False``):
          Opportunistic — if either side's native checksum is empty
          or the two sides report different algorithms, skip silently.
          A mismatch still raises :class:`_ChecksumMismatch`.

        Forced mode (``job.verify_checksum == True``):
          If native checksums aren't both present with a matching
          algorithm, stream-sha256 both sides through ``open_read``
          and compare. A failure to open either side — plus an
          honest mismatch — raises :class:`_ChecksumMismatch` so a
          caller who asked for verification never walks away with
          "backend had no cheap hash so we skipped".

        Compatible mismatch cases (native mode only):
        - Different algorithms (sha256 vs md5) on the two sides — we
          can't compare, so skip.
        - Composite S3 multipart ETag (``s3-etag:...``) against a
          plain ``md5:`` from a non-multipart source — incomparable,
          skip.
        - Two storage fingerprints (``s3-etag:`` / ``etag:``, see
          :data:`_STORAGE_FINGERPRINTS`) — they differ for identical
          bytes, so they are not compared either.

        Cancel: the streaming fallback honours ``job.cancel_event``;
        setting it between chunks raises :class:`InterruptedError`
        which the outer loop maps to TransferStatus.CANCELLED.
        """
        src = job.source_backend
        dst = job.dest_backend
        if src is None or dst is None:
            return
        if dest_path is None:
            dest_path = job.dest_path
        src_cs = dst_cs = None
        # The second value is asked for only when the first could match it:
        # the verdict is the same, and a local file's "checksum" (a read of
        # the whole file) is not computed for a comparison that cannot
        # happen - so the other side goes first when only the source is
        # local.
        streamed = _streamed_source_checksum(job)
        if _hashes_whole_local_file(src) and not _hashes_whole_local_file(dst):
            if _may_compare(dst, dest_path, src, written=True):
                dst_cs = _native_checksum(dst, dest_path, "Dest")
            if _could_match(dst_cs, src):
                src_cs = streamed or _native_checksum(src, job.source_path, "Source")
        else:
            if streamed:
                src_cs = streamed
            elif _may_compare(src, job.source_path, dst, written=False):
                src_cs = _native_checksum(src, job.source_path, "Source")
            if _could_match(src_cs, dst) and _may_compare(dst, dest_path, src, written=True,
                                                          against=src_cs):
                dst_cs = _native_checksum(dst, dest_path, "Dest")
        # Native fast path: both sides returned non-empty values with
        # the same algo prefix. Use what the backend gave us.
        if src_cs and dst_cs:
            src_algo, _, src_hex = src_cs.partition(":")
            dst_algo, _, dst_hex = dst_cs.partition(":")
            if src_algo == dst_algo and src_algo not in _STORAGE_FINGERPRINTS:
                if src_hex != dst_hex:
                    raise _ChecksumMismatch(
                        f"Integrity FAIL for {job.filename}: source {src_cs} != dest {dst_cs}"
                    )
                job.integrity_compared = True
                log.info(
                    "Integrity OK for %s (%s, native)",
                    job.filename,
                    src_algo,
                )
                return
            # Algo mismatch (e.g. md5 vs sha256) or a storage fingerprint
            # that is no content hash. Fall through to the streaming path
            # iff forced; otherwise skip as before.
            log.debug(
                "Native checksums not comparable for %s: src=%s dst=%s",
                job.filename,
                src_algo,
                dst_algo,
            )
        # Opportunistic skip when not forcing.
        if not job.verify_checksum:
            return
        # Forced verification — stream both sides. Any error reading
        # from either side during forced mode is itself an integrity
        # failure (the user asked for verification; we can't deliver).
        log.info(
            "Integrity stream-sha256 for %s (forced)",
            job.filename,
        )
        try:
            src_sha = self._stream_sha256(
                src,
                job.source_path,
                job.cancel_event,
            )
        except InterruptedError:
            raise
        except Exception as exc:
            raise _ChecksumMismatch(
                f"Integrity FAIL for {job.filename}: cannot read source for verification: {exc}"
            ) from exc
        try:
            dst_sha = self._stream_sha256(
                dst,
                dest_path,
                job.cancel_event,
            )
        except InterruptedError:
            raise
        except Exception as exc:
            raise _ChecksumMismatch(
                f"Integrity FAIL for {job.filename}: cannot read dest for verification: {exc}"
            ) from exc
        if src_sha != dst_sha:
            raise _ChecksumMismatch(
                f"Integrity FAIL for {job.filename}: "
                f"source sha256:{src_sha} != dest sha256:{dst_sha}"
            )
        job.integrity_compared = True
        log.info(
            "Integrity OK for %s (sha256, stream)",
            job.filename,
        )

    @staticmethod
    def _stream_sha256(backend, path: str, cancel_event: Event) -> str:
        """Return hex sha256 of ``path`` read through ``backend`` in
        1 MiB chunks. Honours ``cancel_event`` — raises
        :class:`InterruptedError` between chunks when set.

        Separate from the UI's file-pane stream-hash because this one
        runs on the worker thread with no Qt dependencies; the two
        paths happen to use the same chunk size so the hash values
        would compare-equal if the same file were re-hashed in either
        place."""
        import hashlib

        chunk_size = 1 << 20  # 1 MiB
        hasher = hashlib.sha256()
        # A reader that downloads in open_read checks Cancel meanwhile.
        with transfer_hooks.active(transfer_hooks.TransferHooks(cancel_event)), \
                read_spool.sequential_reads():
            handle = backend.open_read(path)
        with handle as fh:
            while True:
                if cancel_event.is_set():
                    raise InterruptedError("transfer cancelled")
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                hasher.update(chunk)
        return hasher.hexdigest()

    def _do_transfer(
        self,
        job: TransferJob,
        progress_callback,
    ) -> int:
        """Perform the actual file copy using backend open_read/open_write.
        Returns the size of the destination file written."""
        source_backend = job.source_backend
        dest_backend = job.dest_backend

        if not source_backend or not dest_backend:
            raise ValueError("Job missing source/dest backends")
        if job.cancel_event.is_set():
            # Cancelled while queued: the loops below would only notice
            # after opening (and on a direct writer truncating) the
            # destination, then write it back from a snapshot.
            raise InterruptedError("Transfer cancelled")
        from core.storage_identity import same_entry

        if same_entry(source_backend, job.source_path, dest_backend, job.dest_path):
            # Copying a file over itself, and for a move then deleting
            # "the source", would remove the only copy.
            raise OSError(f"source and destination are the same: {job.dest_path}")

        present = None
        if not (job.use_temp_file and job.if_exists == "fail" and not job.resume):
            # Through a fresh temp file nothing is replaced before the
            # rename, and "fail" is checked again right before it: this
            # second round trip per file (every F5 onto a free name) would
            # only spare the write in a rare race. "newer" must decide
            # before reading; a resume must not touch its partial.
            present = self._check_existing_destination(job)
        if job.use_temp_file:
            return self._do_transfer_with_temp(job, progress_callback)
        known_absent = present is False or (
            job.dest_folder_new and job.if_exists == "overwrite" and not job.resume
        )
        return self._do_transfer_direct(job, progress_callback, known_absent=known_absent)

    @staticmethod
    def _check_existing_destination(job: TransferJob) -> bool | None:
        """Enforce ``job.if_exists`` against the destination as it is NOW.

        The conflict prompt looked at the destination earlier; a file that
        appeared since must not be replaced on the strength of an answer
        about another state. ``"fail"`` raises :class:`FileExistsError`,
        ``"newer"`` raises :class:`_DestinationKept` unless the source is
        strictly newer. A destination that cannot be checked counts as
        present: guessing "absent" is how a file gets overwritten. Returns
        whether it was there (None for "overwrite": not asked).
        """
        mode = job.if_exists
        if mode == "overwrite":
            return None
        dest_backend = job.dest_backend
        try:
            present = dest_backend.exists(job.dest_path)
        except Exception as exc:  # noqa: BLE001 - unknown means do not write
            raise OSError(
                f"cannot check whether {job.dest_path} already exists: {exc}"
            ) from exc
        if not present:
            return False
        if mode == "newer":
            src_mtime = TransferWorker._mtime_of(job.source_backend, job.source_path)
            dst_mtime = TransferWorker._mtime_of(dest_backend, job.dest_path)
            # Whole seconds: SFTP and FTP keep no fraction, so a copy that
            # was given its source's time (10.6 s) reads back as 10 s and
            # looked older than its unchanged source - every "Overwrite if
            # Newer" copied it again.
            if (src_mtime is not None and dst_mtime is not None
                    and int(src_mtime) > int(dst_mtime)):
                return True
            raise _DestinationKept(
                f"{job.dest_path} is not older than {job.source_path}; kept"
            )
        raise FileExistsError(f"{job.dest_path} already exists; not overwritten")

    @staticmethod
    def _mtime_of(backend, path: str) -> float | None:
        try:
            modified = getattr(backend.stat(path), "modified", None)
            value = modified.timestamp() if modified is not None else 0.0
        except Exception as exc:  # noqa: BLE001 - unknown age: never "newer"
            log.debug("cannot read the modification time of %s: %s", path, exc)
            return None
        return value if value > 0 else None

    def _do_transfer_direct(
        self,
        job: TransferJob,
        progress_callback,
        *,
        known_absent: bool = False,
    ) -> int:
        """Write directly to dest_path (no temp file + rename).

        Used for backends where temp-file rename is unsupported (IMAP),
        extremely expensive (rsync), or pointless because the backend
        already buffers internally via SpooledWriter (FTP, WebDAV, S3,
        Azure Blob, cloud backends). *known_absent*: the no-overwrite check
        just found no destination, so the rollback snapshot need not ask
        again (on FTP a missing file is several refused commands).

        A destination that already exists under the source's name may be
        the source itself, reached over another protocol (axross's own
        WebDAV reverse-serve, FTP or SCP to localhost, sshfs plus SCP):
        a move or a copy probes for that before it writes
        (:meth:`_refuse_aliased_direct`) - a move would delete the only
        copy, a copy through a writer that truncates at open empties it.
        Should the probe prove nothing, a copy that reads back a short
        source restores the snapshot (see below). The integrity check runs
        while the snapshot is still held, so a mismatch puts the old
        destination back instead of leaving the corrupt copy. S3 and Azure
        Blob keep no snapshot (they replace the object only at close): with
        ``verify_checksum`` a server-side copy of the old object stands in
        for it (:meth:`_back_up_committed_destination`).
        """
        source_backend = job.source_backend
        dest_backend = job.dest_backend
        transferred = 0
        completed = False

        from core.server_ops import (
            _discard_or_close_writer,
            _rollback_direct_destination,
            _snapshot_direct_destination,
            source_size,
            write_traits,
        )

        traits = write_traits(dest_backend)
        # A writer that spools and sends everything in close() (FTP, WebDAV,
        # SCP, Telnet, ADB, a DB row): the destination is untouched until
        # then. Its safety copy is taken right before that close(), so a
        # copy cancelled or failed before it neither reads back the old
        # file nor uploads it again (400 MiB: 1.2 s read + 2.3 s rollback
        # after a Cancel 0.3 s in).
        spools = traits.spools_until_close

        def check_cancel() -> None:
            if job.cancel_event.is_set():
                raise InterruptedError("Transfer cancelled")

        # Outside the rollback: until the snapshot exists nothing has been
        # written, and a failed read-back of an existing destination
        # must not reach the rollback, which would take it for a partial
        # file of ours and remove it.
        if known_absent:
            destination_existed = False
        else:
            destination_existed, _ = _snapshot_direct_destination(
                dest_backend, job.dest_path, defer=True)
        needs_copy = destination_existed and not (traits.commits_on_close or traits.append_only)
        destination_snapshot = None
        #: A server-side copy of the old destination (cp, WebDAV COPY, a DB
        #: row): no byte through this machine, put back on failure.
        server_copy = None
        if needs_copy and not spools:
            server_copy, destination_snapshot = self._safety_copy(job, check_cancel)
        backup = None
        #: The writer was opened: before that nothing of the destination
        #: was touched, and a rollback could only do harm - on Google Drive
        #: it wrote the snapshot of the file listed over the one the
        #: refused open_write had just found under the name (ESTALE).
        opened = False
        #: A spooling writer's close() was called: from then on the
        #: destination may have changed.
        sent = False
        # The size known when the copy starts: a read that ends short of it
        # is checked against the source before the copy counts as done.
        expected = int(job.total_bytes or 0)
        try:
            size_before = None
            if destination_existed and not traits.append_only:
                # Only an existing destination can be the source itself - not
                # on a store that only adds (IMAP, Exchange: the probe would be
                # one more message, which remove() cannot take back). A copy
                # needs the probe only where a write can empty the source: S3
                # and Azure Blob (they commit at close) have read it whole by then.
                if job.move or not traits.commits_on_close:
                    self._refuse_aliased_direct(job)
                if traits.commits_on_close and job.verify_checksum:
                    # Committed at close, the new object has replaced the old
                    # one before the check runs: a mismatch left the corrupt
                    # copy in its place, with nothing to put back.
                    backup = self._back_up_committed_destination(job)
                if (destination_snapshot is not None or server_copy is not None) \
                        and self._same_leaf_name(job):
                    # A writer that truncates at open, aimed at the source
                    # under another path, empties it before it is read: the
                    # copy then comes out short and "succeeds". The snapshot
                    # holds the bytes; a short copy restores them.
                    size_before = source_size(source_backend, job.source_path)
            try:
                # The hooks for the backends: a reader that downloads in
                # open_read and a writer that uploads in close() check
                # Cancel and report their network bytes. Not around the
                # rollback below: that must not be cancelled itself.
                with transfer_hooks.active(_hooks_of(job, progress_callback)), \
                        _open_sequential(source_backend, job.source_path) as src:
                    dst = dest_backend.open_write(job.dest_path, append=False)
                    opened = True
                    _copy_starts(progress_callback)
                    streamed = _StreamedHash(job, 0)
                    try:
                        while True:
                            if job.cancel_event.is_set():
                                raise InterruptedError("Transfer cancelled")
                            chunk = src.read(CHUNK_SIZE)
                            if not chunk:
                                break
                            dst.write(chunk)
                            streamed.update(chunk)
                            transferred += len(chunk)
                            progress_callback(transferred, job.total_bytes)
                        # Before a spooling writer sends anything: a short
                        # read then costs no upload and no rollback.
                        self._refuse_short_read(job, transferred, expected)
                        self._refuse_short_move(job, transferred)
                        if needs_copy and spools:
                            # Not under the hooks: the read-back is no part
                            # of the job's progress (Cancel still stops it).
                            with transfer_hooks.active(None):
                                server_copy, destination_snapshot = self._safety_copy(
                                    job, check_cancel)
                        completed = True
                        streamed.finish()
                        _copy_ends(progress_callback)
                    finally:
                        sent = completed
                        try:
                            _discard_or_close_writer(dst, completed=completed)
                        except transfer_hooks.UploadCancelled:
                            # Cancelled before the writer committed a byte:
                            # the destination is as it was, nothing to roll
                            # back (a snapshot restore would upload the old
                            # file again).
                            completed, opened = False, False
                            raise
                if size_before is not None and transferred < size_before:
                    raise OSError(
                        f"only {transferred} of {size_before} bytes of {job.source_path} "
                        f"were copied to {job.dest_path}; {job.dest_path} was put back "
                        "as it was (it may be the source under another path)"
                    )
                self._verify_integrity(job)
            except BaseException as exc:
                if backup is not None:
                    kept, backup = backup, None
                    if not self._put_back_committed_destination(job, kept, written=completed):
                        if isinstance(exc, _ChecksumMismatch):
                            raise _ChecksumMismatch(
                                f"{exc}; the previous {job.dest_path} could not be put back "
                                f"and is kept as {kept}"
                            ) from exc
                        raise
                # A writer that spools and was discarded before its close()
                # sent anything left the destination as it was.
                touched = opened and (sent or not spools)
                if touched and server_copy is not None:
                    kept, server_copy = server_copy, None
                    if not self._put_back_server_copy(job, kept):
                        note = (f"{exc}; the previous {job.dest_path} could not be put back "
                                f"and is kept as {kept}")
                        if isinstance(exc, _ChecksumMismatch):
                            raise _ChecksumMismatch(note) from exc
                        if isinstance(exc, OSError) and exc.errno is not None:
                            raise OSError(exc.errno, note) from exc
                        raise OSError(note) from exc
                # A writer that commits only at close and never got there
                # (S3, Azure Blob) left nothing of this transfer behind: a
                # file now under the name is someone else's, not a partial
                # to remove.
                elif touched and (completed or not traits.commits_on_close):
                    _rollback_direct_destination(
                        dest_backend,
                        job.dest_path,
                        destination_existed=destination_existed,
                        destination_snapshot=destination_snapshot,
                    )
                raise
        finally:
            if destination_snapshot is not None:
                destination_snapshot.close()
            if backup is not None:  # the check passed (or never ran: nothing written)
                self._drop_destination_backup(job, backup)
            if server_copy is not None:  # done, or nothing was touched
                self._drop_destination_backup(job, server_copy)
        # FTP (MFMT) is written directly: the temp-file route was the only
        # one that kept the source's time.
        self._apply_source_mtime(job)
        return transferred

    @staticmethod
    def _server_copy_usable(backend) -> bool:
        """Whether *backend* copies on the server (WriteTraits.server_copy:
        cp, WebDAV COPY, an SQLite row): a safety copy there moves no byte
        through this machine."""
        from core.server_ops import write_traits

        return write_traits(backend).server_copy and callable(getattr(backend, "copy", None))

    def _safety_copy(self, job: TransferJob, check_cancel):
        """What restores the existing destination should the write fail:
        ``(server-side copy path, None)`` where the backend copies on the
        server, else ``(None, local snapshot)`` - read back with Cancel
        checked per chunk, spooled in the spool folder after a free-space
        check (core.server_ops.read_destination_snapshot)."""
        from core.server_ops import read_destination_snapshot

        check_cancel()
        if self._server_copy_usable(job.dest_backend):
            try:
                return self._back_up_committed_destination(job), None
            except OSError as exc:
                log.info("No server-side copy of %s (%s); reading it back instead",
                         job.dest_path, exc)
                check_cancel()
        return None, read_destination_snapshot(job.dest_backend, job.dest_path,
                                               check=check_cancel)

    @staticmethod
    def _put_back_server_copy(job: TransferJob, backup: str) -> bool:
        """The failed write is undone from the server-side copy *backup*:
        copied back over the destination in place (its mode and links
        stay), or - a backend whose copy refuses an existing target -
        the destination removed and the copy renamed to it. False (the
        copy kept, logged) when neither worked."""
        dest_backend = job.dest_backend
        try:
            dest_backend.copy(backup, job.dest_path)
        except Exception as exc:  # noqa: BLE001 - try the rename next
            try:
                if dest_backend.exists(job.dest_path):
                    dest_backend.remove(job.dest_path)
                dest_backend.rename(backup, job.dest_path)
            except Exception as exc2:  # noqa: BLE001 - the caller names the kept copy
                log.error("Could not put %s back from %s: %s; %s",
                          job.dest_path, backup, exc, exc2)
                return False
            log.info("Put %s back as it was before the transfer", job.dest_path)
            return True
        log.info("Put %s back as it was before the transfer", job.dest_path)
        TransferWorker._drop_destination_backup(job, backup)
        return True

    @staticmethod
    def _refuse_short_move(job: TransferJob, transferred: int) -> None:
        """A move whose copy came out shorter than the source was before it
        is not committed - a local source too (_refuse_short_read leaves
        those to the size check after the copy): a local file truncated
        while it was moved left the short copy under the destination's
        name, the move failed and kept the source (review round 8)."""
        size_before = job.move_source_size
        if not job.move or size_before is None or transferred >= size_before:
            return
        if _is_pseudo_source(job.source_backend, job.source_path, size_before):
            return
        raise _ShortRead(
            errno.EIO,
            f"only {transferred} of {size_before} bytes of {job.source_path} were copied; "
            f"the source was kept and {job.dest_path} was left as it was",
        )

    @staticmethod
    def _refuse_short_read(job: TransferJob, transferred: int, expected: int) -> None:
        """Raise :class:`OSError` when the copy read fewer bytes than the
        source holds: a stream that ended early without an error (an FTP
        data connection cut, then "226" all the same) gave a short file
        that was committed as the copy - for every transfer, not only a
        move. *expected* is the size the job knew at open (the listing's,
        or the live size of a resume); only a copy short of it costs one
        stat of the source, which decides: a source that shrank meanwhile
        was copied as it is now. A source whose size cannot be read (a
        symlink, a mail store's estimate, a failed stat) is not refused;
        a local one is compared with its size from before the copy
        (:meth:`_refuse_short_local_copy`), not stat-ed again - and sysfs
        lists 4096 bytes for attributes that read a few - on a remote
        machine too (SFTP, SCP, a shell): /sys, /proc and /dev are not
        refused there - only under those folders, only on a backend whose
        "/" is a machine's root and only for a file listed with such a
        file's size (:func:`_is_pseudo_source`). Called before the copy
        replaces the destination, so the destination stays as it was."""
        if _is_local(job.source_backend):
            TransferWorker._refuse_short_local_copy(job, transferred)
            return
        if expected <= 0 or transferred >= expected:
            return
        if _is_pseudo_source(job.source_backend, job.source_path, expected):
            return
        from core.server_ops import source_size

        live = source_size(job.source_backend, job.source_path)
        if live is None or transferred >= live:
            return
        raise _ShortRead(
            errno.EIO,
            f"only {transferred} of {live} bytes of {job.source_path} were read; "
            f"the copy is incomplete and {job.dest_path} was left as it was",
        )

    @staticmethod
    def _refuse_short_local_copy(job: TransferJob, transferred: int) -> None:
        """Fail a copy of a file on this machine's disk that came out
        shorter than the file was before the copy (``move_source_size``):
        the file was cut while it was read, and the short copy was
        committed as DONE - over an existing destination too (review round
        9). Reported as a failed transfer; Retry or a new copy takes the
        file as it is then. A move is left to :meth:`_refuse_short_move`,
        a kernel pseudo file (sysfs lists 4096 bytes) is not failed."""
        before = job.move_source_size
        if job.move or before is None or transferred >= before:
            return
        if _is_pseudo_source(job.source_backend, job.source_path, before):
            return
        from core.i18n import tr

        raise _ShortRead(
            errno.EIO,
            tr("only {copied} of {size} bytes of {source} could be read: the file got "
               "shorter while it was copied. The copy is incomplete and was not saved; "
               "{dest} was left as it was").format(
                copied=transferred, size=before, source=job.source_path, dest=job.dest_path),
        )

    @staticmethod
    def _destination_backup_path(job: TransferJob) -> str:
        dest_backend = job.dest_backend
        dest_name = job.dest_path.rsplit(dest_backend.separator() or "/", 1)[-1]
        return safe_join(
            dest_backend,
            dest_backend.parent(job.dest_path),
            hidden_sibling_name(dest_name, f".previous-{job.job_id}",
                                reserve=_PARTIAL_TAIL_BYTES),
        )

    @staticmethod
    def _back_up_committed_destination(job: TransferJob) -> str:
        """A server-side copy of the destination object (S3 CopyObject,
        Azure Copy Blob - no byte through this machine) beside it, before
        an upload that is checked afterwards replaces it; its path. One
        that cannot be made refuses the transfer before anything is
        written: the check was asked for, and without the copy its
        failure would leave the corrupt upload in place of the original."""
        dest_backend = job.dest_backend
        backup = None
        try:
            backup = TransferWorker._destination_backup_path(job)
            copy = getattr(dest_backend, "copy", None)
            if not callable(copy):
                raise OSError("the backend has no server-side copy")
            copy(job.dest_path, backup)
        except Exception as exc:  # noqa: BLE001 - nothing was written yet
            if backup is not None:
                # A copy that failed half-way (the disk full) left its
                # partial under our own name: it would stay hidden.
                TransferWorker._remove_failed_backup(dest_backend, backup)
            raise OSError(
                f"cannot keep a copy of {job.dest_path} before it is replaced and checked "
                f"({exc}); nothing was replaced"
            ) from exc
        log.debug("Kept %s as %s until the integrity check passes", job.dest_path, backup)
        return backup

    @staticmethod
    def _remove_failed_backup(dest_backend, backup: str) -> None:
        try:
            if dest_backend.exists(backup):
                dest_backend.remove(backup)
        except Exception as exc:  # noqa: BLE001 - a leftover copy loses nothing
            log.warning("Could not remove the partial copy %s: %s", backup, exc)

    @staticmethod
    def _put_back_committed_destination(job: TransferJob, backup: str, *, written: bool) -> bool:
        """The transfer failed: the object *backup* holds goes back to the
        destination (when the upload may have replaced it) and the copy is
        removed. False when it could not be put back - the copy is kept."""
        dest_backend = job.dest_backend
        if written:
            try:
                dest_backend.copy(backup, job.dest_path)
            except Exception as exc:  # noqa: BLE001 - the caller names the kept copy
                log.error("Could not put %s back from %s: %s", job.dest_path, backup, exc)
                return False
            log.info("Put %s back as it was before the transfer", job.dest_path)
        TransferWorker._drop_destination_backup(job, backup)
        return True

    @staticmethod
    def _drop_destination_backup(job: TransferJob, backup: str) -> None:
        try:
            job.dest_backend.remove(backup)
        except Exception as exc:  # noqa: BLE001 - a leftover copy loses nothing
            log.warning("Could not remove the copy %s of the previous %s: %s",
                        backup, job.dest_path, exc)

    def _do_transfer_with_temp(
        self,
        job: TransferJob,
        progress_callback,
    ) -> int:
        """Write to a temp file, then rename to final destination.

        Used for backends with real filesystem semantics (local, SFTP,
        SMB, NFS, iSCSI, Azure Files) where rename is atomic and cheap.
        """
        source_backend = job.source_backend
        dest_backend = job.dest_backend

        from core.server_ops import _discard_or_close_writer, write_traits

        # A temp name made now carries this job's id, which nothing has
        # written yet: there is no leftover under it to look for (one
        # round trip per file on a remote destination). A name the job
        # brought along (a retry, an auto-resume) may have one.
        fresh_temp = not job.temp_path and not job.resume
        temp_path = self._temp_destination_path(job)
        # The source's mode less the umask, read once per job (it is
        # needed before the write and again before the rename).
        mode = copy_mode(job.source_mode)
        cleanup_temp = True
        keep_partial = False
        transferred = 0
        # A partial is worth keeping only where open_write(append=True)
        # really appends: Azure Files downloads it and uploads it whole
        # again, and refuses one over 256 MiB - kept "for a resume", such a
        # partial failed every later copy of the file.
        real_append = write_traits(dest_backend).real_append
        #: Partials this job writes: no other job of this process adopts them.
        live: list[str] = []
        # A local destination is written through ONE descriptor, opened
        # without following a link and checked (review round 9): in a
        # folder others may write to, the claimed partial's name could be
        # swapped for a symlink to ~/.bashrc between the claim and an open
        # by path, which then wrote the download into it.
        private_local = _private_local(dest_backend)
        #: The temp file written (its fstat), compared before the rename.
        written = None

        try:
            if not fresh_temp:
                brought = temp_path
                temp_path = self._claim_brought_partial(job, temp_path, real_append)
                # A fresh name of this job's own: nothing to look for there.
                fresh_temp = temp_path != brought and not job.resume
            if _claim_live_partial(temp_path):
                live.append(temp_path)
            resume_offset = 0
            live_size = 0
            if job.resume and real_append and dest_backend.exists(temp_path):
                live_source = self._live_source_item(job)
                live_size = int(getattr(live_source, "size", 0) or 0) if live_source else 0
                if live_size:
                    # The size the job carries can be stale: a retry copies
                    # it from the failed job.
                    job.total_bytes = live_size
                if not self._partial_is_of_this_source(job, temp_path, live_source):
                    # A partial is adopted by its name; only the fingerprint
                    # in that name says it was written from the source as it
                    # is now. Another version (or no record) means restart.
                    log.warning(
                        "Partial %s was not written from %s as it is now; "
                        "restarting transfer",
                        temp_path,
                        job.source_path,
                    )
                    dest_backend.remove(temp_path)
                    job.temp_path = ""
                    job.source_fingerprint = source_fingerprint(live_source)
                    temp_path = self._temp_destination_path(job)
                    if _claim_live_partial(temp_path):
                        live.append(temp_path)
                    if dest_backend.exists(temp_path):
                        dest_backend.remove(temp_path)
                else:
                    try:
                        partial_stat = dest_backend.stat(temp_path)
                        resume_offset = partial_stat.size
                        log.info(
                            "Resuming transfer at offset %d for %s", resume_offset, job.filename
                        )
                    except OSError:
                        resume_offset = 0
            elif not fresh_temp and dest_backend.exists(temp_path):
                dest_backend.remove(temp_path)

            if resume_offset > live_size:
                # Only a partial with the live source's fingerprint gets an
                # offset, so live_size is the source's size right now.
                # Resuming past its end would read nothing and finalize the
                # old partial as the file.
                log.warning(
                    "Discarding oversized partial %s (%d > %d bytes) "
                    "for %s; restarting transfer",
                    temp_path,
                    resume_offset,
                    live_size,
                    job.filename,
                )
                dest_backend.remove(temp_path)
                resume_offset = 0

            hooks = _hooks_of(job, progress_callback)
            # From the start the copy reads front to back once: a download
            # streams instead of spooling beside its local copy. A resume
            # seeks (and compares the partial), so it keeps the spool.
            with transfer_hooks.active(hooks), read_spool.sequential_reads(resume_offset == 0):
                source_handle = source_backend.open_read(job.source_path)
            with source_handle as src:
                if resume_offset > 0 and not self._partial_matches_source(
                    src, dest_backend, temp_path, resume_offset
                ):
                    # The probe adopts a partial by file name alone: it may
                    # hold another file's bytes (a cancelled download of a
                    # namesake) or an older version of this one.
                    log.warning(
                        "Partial %s does not match %s; restarting transfer",
                        temp_path,
                        job.source_path,
                    )
                    resume_offset = 0
                    # Under a fresh name, as for another fingerprint: the
                    # stalled writer of another process may still hold this
                    # partial open, and a restart into the same file let
                    # both write it - a torn copy, committed (review round 9).
                    temp_path = self._restart_under_fresh_partial(job, temp_path, live)
                if private_local and resume_offset > 0:
                    problem = _local_partial_problem(temp_path)
                    if problem:
                        # Never appended to (core.local_fs.open_own_partial
                        # refuses it again at the open, should it change).
                        log.warning("Not resuming %s: %s; restarting transfer",
                                    temp_path, problem)
                        resume_offset = 0
                # Decide the offset BEFORE seeking: a source left seeked to a
                # discarded partial's size copies only the tail.
                if job.total_bytes > 0 and resume_offset == job.total_bytes:
                    progress_callback(resume_offset, job.total_bytes)
                    transferred = resume_offset
                    log.info(
                        "Resume partial already complete for %s; finalizing %s",
                        job.filename,
                        temp_path,
                    )
                    self._refuse_aliased_source(job, temp_path)
                    self._verify_integrity(job, temp_path)
                    self._refuse_changed_partial(job, temp_path, transferred)
                    free = self._check_existing_destination(job) is False
                    if private_local:
                        # The mode through a checked descriptor: a chmod by
                        # name follows a link put there (~/.ssh/id_rsa 0644).
                        with self._open_local_temp(temp_path, resume_offset, mode) as fh:
                            written = os.fstat(fh.fileno())
                        self._refuse_swapped_partial(job, temp_path, written)
                    else:
                        self._apply_source_mode(job, temp_path)
                    self._finalize_temp_destination(dest_backend, temp_path, job.dest_path,
                                                    no_replace=free)
                    self._apply_source_mtime(job)
                    cleanup_temp = False
                    return transferred
                if resume_offset > 0:
                    # Seek source to resume position
                    try:
                        src.seek(resume_offset)
                    except (OSError, IOError) as exc:
                        log.warning(
                            "Resume disabled for %s: source cannot seek to "
                            "offset %d (%s); restarting transfer",
                            job.filename,
                            resume_offset,
                            exc,
                        )
                        resume_offset = 0
                mode_set = False
                if private_local:
                    dst = self._open_local_temp(temp_path, resume_offset, mode)
                    written = os.fstat(dst.fileno())
                    mode_set = mode is not None
                else:
                    if resume_offset == 0:
                        mode_set = self._precreate_private_temp(job, temp_path, mode)
                    with transfer_hooks.active(hooks):
                        dst = dest_backend.open_write(temp_path, append=resume_offset > 0)
                _copy_starts(progress_callback)

                streamed = _StreamedHash(job, resume_offset)
                completed = False
                expected = int(job.total_bytes or 0)
                try:
                    transferred = resume_offset
                    if transferred > 0 and transferred < job.total_bytes:
                        progress_callback(transferred, job.total_bytes)
                    while True:
                        if job.cancel_event.is_set():
                            raise InterruptedError("Transfer cancelled")
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        dst.write(chunk)
                        streamed.update(chunk)
                        transferred += len(chunk)
                        progress_callback(transferred, job.total_bytes)
                    streamed.finish()
                    completed = True
                    _copy_ends(progress_callback)
                finally:
                    if completed or real_append:
                        # An unfinished partial stays for a resume. A
                        # spooling writer uploads now, under the hooks.
                        with transfer_hooks.active(hooks):
                            dst.close()
                    else:
                        # A spooling writer (Azure Files) uploads at close:
                        # a cancelled transfer uploaded its partial, for
                        # nothing - no resume appends to it.
                        _discard_or_close_writer(dst, completed=False)

            # A short read is not committed: the temp file never replaces
            # the destination (a resume can continue it where it is real).
            self._refuse_short_read(job, transferred, expected)
            self._refuse_short_move(job, transferred)
            self._refuse_aliased_source(job, temp_path)
            # The temp file, before it replaces the destination: checked
            # after the rename, a mismatch left the corrupt copy where the
            # original had been.
            self._verify_integrity(job, temp_path)
            # Another job appending to the same partial is found here.
            self._refuse_changed_partial(job, temp_path, transferred)
            if written is not None:
                self._refuse_swapped_partial(job, temp_path, written)
            # "fail" / "newer" onto a free name: the rename must not replace
            # a file that appears after this look (a check and then rename()
            # replaced it on LocalFS and SFTP).
            free = self._check_existing_destination(job) is False
            # Mode and time in one request where the backend can (SFTP: one
            # SETSTAT on the temp file, whose time the rename keeps) - sent
            # together with the rename where it can do that too.
            timed, renamed = self._rename_with_attributes(
                job, temp_path, None if mode_set else mode, no_replace=free)
            if not timed and not renamed:
                timed = self._apply_source_attributes(job, temp_path, None if mode_set else mode)
            if not timed and not mode_set:
                self._apply_source_mode(job, temp_path if not renamed else job.dest_path, mode)
            if not renamed:
                self._finalize_temp_destination(dest_backend, temp_path, job.dest_path,
                                                no_replace=free)
            if not timed:
                self._apply_source_mtime(job)

            cleanup_temp = False
            return transferred
        except (_DestinationKept, FileExistsError, _SameEntry, _ChecksumMismatch,
                _PartialChanged):
            # Refused to replace the destination: the partial is of no
            # use to a retry, which would be refused the same way - or,
            # after a failed integrity check, holds the wrong bytes.
            raise
        except InterruptedError:
            # Not for a source a resume cannot read from an offset (a
            # download streamed from S3, OneDrive, FTP ...): the resume
            # fetches it whole again, the partial would only stay hidden.
            keep_partial = (real_append and (transferred > 0 or resume_offset > 0)
                            and _source_reads_at_offset(job.source_backend)
                            and self._partial_resumable(job, temp_path))
            raise
        except Exception as exc:
            # Kept for a resume - unless the destination is full: the
            # hidden partial is what fills it, and a resume needs the
            # room as well.
            # Nor for a source a resume cannot read from an offset (POP3,
            # a streamed download): it reads the whole file again - after
            # a refused short read just as short - and the partial would
            # only stay behind, hidden.
            keep_partial = (real_append and (transferred > 0 or resume_offset > 0)
                            and not is_out_of_space(exc)
                            and _source_reads_at_offset(job.source_backend)
                            and self._partial_resumable(job, temp_path))
            raise
        finally:
            if cleanup_temp and not keep_partial:
                try:
                    if dest_backend.exists(temp_path):
                        dest_backend.remove(temp_path)
                except OSError:
                    log.warning("Could not remove partial transfer %s", temp_path)
            _release_live_partials(live)

    @staticmethod
    def _claim_brought_partial(job: TransferJob, temp_path: str, real_append: bool) -> str:
        """The temp path a job brought along (a retry, an auto-resume):
        made its own before anything is written to it, or a fresh one.

        A partial another job may still be writing is never resumed: one
        this process writes is left alone, and one a resume would append
        to is first renamed to this job's own name without replacing
        anything - a job of another process (a second axross) that still
        writes it then fails at its rename instead of committing both
        jobs' bytes (review round 8). When the rename fails the copy starts
        afresh under this job's own name and the partial stays as it was."""
        dest_backend = job.dest_backend

        def fresh(reason: str) -> str:
            log.info("Not resuming %s (%s); starting afresh", temp_path, reason)
            job.temp_path = ""
            job.resume = False
            return TransferWorker._temp_destination_path(job)

        if partial_in_use(temp_path):
            return fresh("another transfer is writing it")
        if not (job.resume and real_append):
            return temp_path
        sep = dest_backend.separator() or "/"
        dest_name = job.dest_path.rsplit(sep, 1)[-1]
        temp_name = temp_path.rsplit(sep, 1)[-1]
        own_name = partial_name(dest_name, job.job_id, partial_fingerprint(temp_name, dest_name))
        if temp_name == own_name:
            return temp_path
        try:
            own_path = safe_join(dest_backend, dest_backend.parent(job.dest_path), own_name)
        except ValueError as exc:
            return fresh(str(exc))
        if partial_in_use(own_path):
            return fresh("another transfer is writing it")
        from core.server_ops import rename_no_replace

        try:
            rename_no_replace(dest_backend, temp_path, own_path)
        except Exception as exc:  # noqa: BLE001 - gone, taken or refused: start afresh
            return fresh(f"it could not be claimed: {exc}")
        log.debug("Claimed partial %s as %s", temp_path, own_path)
        job.temp_path = own_path
        return own_path

    @staticmethod
    def _restart_under_fresh_partial(job: TransferJob, temp_path: str, live: list) -> str:
        """Remove the partial *temp_path* whose bytes are not the source's
        and return a new temp path no one else has: a name of the same shape
        with a random id in the job id's place (this job's own name may be
        the very one just claimed). Added to *live*, set on the job."""
        dest_backend = job.dest_backend
        try:
            dest_backend.remove(temp_path)
        except Exception as exc:  # noqa: BLE001 - left behind; the copy goes on elsewhere
            log.warning("Could not remove the mismatched partial %s: %s", temp_path, exc)
        sep = dest_backend.separator() or "/"
        dest_name = job.dest_path.rsplit(sep, 1)[-1]
        fingerprint = (partial_fingerprint(temp_path.rsplit(sep, 1)[-1], dest_name)
                       or job.source_fingerprint)
        parent = dest_backend.parent(job.dest_path)
        while True:
            fresh = safe_join(dest_backend, parent,
                              partial_name(dest_name, uuid.uuid4().hex[:JOB_ID_LEN], fingerprint))
            if fresh != temp_path and _claim_live_partial(fresh):
                break
        live.append(fresh)
        job.temp_path = fresh
        return fresh

    @staticmethod
    def _open_local_temp(temp_path: str, resume_offset: int, mode: int | None):
        """The local temp file, open through one descriptor: a resume
        appends to the partial only while it is a regular file of this
        user with one name, as long as compared (never through a link put
        in its place); a copy from the start removes whatever is under the
        name (a link goes, not what it points to) and creates the file anew,
        exclusively, never readable by more than *mode* allows (review
        round 9: created 0644 and chmod-ed later, a 0600 key could be
        opened by others meanwhile). The resumed file gets *mode* too."""
        if resume_offset > 0:
            try:
                fh = open_own_partial(temp_path, expect_size=resume_offset)
            except PermissionError as exc:
                from core.i18n import tr

                raise _PartialChanged(errno.EIO, tr(
                    "The partial file {path} was changed or replaced by a link before it "
                    "could be continued; nothing was written to it.").format(path=temp_path)
                ) from exc
            if mode is not None:
                _set_mode_through(fh, mode)
            return fh
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        return create_private_file(temp_path, mode)

    @staticmethod
    def _refuse_swapped_partial(job: TransferJob, temp_path: str, written) -> None:
        """Raise :class:`_PartialChanged` when *temp_path* no longer names
        the file written through its descriptor (*written*, its fstat):
        the rename would put whatever was put there (a link to a file of
        the user's) in the destination's place."""
        if same_entry(temp_path, written):
            return
        from core.i18n import tr

        raise _PartialChanged(errno.EIO, tr(
            "The partial file {path} was replaced while it was written; {dest} was left "
            "as it was.").format(path=temp_path, dest=job.dest_path))

    @staticmethod
    def _refuse_changed_partial(job: TransferJob, temp_path: str, transferred: int) -> None:
        """Raise :class:`_PartialChanged` when the temp file is not as long
        as what this job put into it (the resumed part and the bytes it
        wrote): another transfer wrote to it as well. Two copies of one
        file appending into one partial committed a 4.9 MB "copy" of a
        4 MB file (review round 8). Not asked when the integrity check
        already compared the temp file's bytes, nor when its size is
        unknown."""
        if job.integrity_compared or job.dest_backend is None:
            return
        from core.server_ops import source_size

        size = source_size(job.dest_backend, temp_path)
        if size is None or size == transferred:
            return
        raise _PartialChanged(
            errno.EIO,
            f"the partial file {temp_path} holds {size} bytes, this copy wrote "
            f"{transferred}: another transfer wrote to it as well; {job.dest_path} "
            "was left as it was",
        )

    @staticmethod
    def _precreate_private_temp(job: TransferJob, temp_path: str, mode=-1) -> bool:
        """Give a fresh temp file the source's mode BEFORE any data lands
        when that mode is narrower than a default file's (a 0600 key):
        written first and chmod-ed after, the bytes would sit group- or
        world-readable for the whole transfer. True when the mode is set.

        The owner gets write permission while the data goes in, as
        atomic_io gives its temp files (``_OWNER_WRITE``): created 0400
        (an AWS ``key.pem``) the temp file refused the write that follows
        for every user but root. Such a mode is set after the write (False).
        *mode*: copy_mode() of the source's mode when the caller has it."""
        if mode == -1:
            mode = copy_mode(job.source_mode)
        if mode is None or mode & 0o044 == 0o044:
            return False
        from core.atomic_io import _OWNER_WRITE, _precreate_with_mode

        _precreate_with_mode(job.dest_backend, temp_path, mode | _OWNER_WRITE)
        return bool(mode & _OWNER_WRITE)

    @staticmethod
    def _apply_source_mode(job: TransferJob, temp_path: str, mode=-1) -> None:
        """Best effort: a backend without chmod keeps its own default."""
        if mode == -1:
            mode = copy_mode(job.source_mode)
        if mode is None:
            return
        from core.atomic_io import _restore_mode

        _restore_mode(job.dest_backend, temp_path, mode)

    @staticmethod
    def _rename_with_attributes(job: TransferJob, temp_path: str,
                                mode: int | None, *,
                                no_replace: bool = False) -> tuple[bool, bool]:
        """Mode, time and the rename onto the destination in one round trip
        where the backend offers ``rename_with_attributes`` (SFTP); called
        after the integrity check and the last look at the destination,
        exactly where the rename was. ``(attributes set, renamed)``; a
        rename that failed leaves both to the steps that follow (the
        finalize with its fallbacks, the attributes one by one).
        """
        combined = getattr(job.dest_backend, "rename_with_attributes", None)
        if not job.source_mtime or not callable(combined):
            return False, False
        try:
            if no_replace:
                timed = bool(combined(temp_path, job.dest_path, mode=mode,
                                      mtime=job.source_mtime, no_replace=True))
            else:
                timed = bool(combined(temp_path, job.dest_path, mode=mode,
                                      mtime=job.source_mtime))
        except (OSError, NotImplementedError, ValueError, TypeError) as exc:
            log.debug("rename of %s with its attributes failed: %s", temp_path, exc)
            return False, False
        return timed, True

    @staticmethod
    def _apply_source_attributes(job: TransferJob, temp_path: str, mode: int | None) -> bool:
        """Give the temp file *mode* (None: leave it) and the source's time
        in ONE call, before the rename, where the backend offers
        ``set_attributes(path, mode=, mtime=)`` (SFTP: a SETSTAT, a round
        trip less per file than a chmod and a time set after the rename).
        True when the time was set (and the mode, if one was given); False
        when the caller sets them one by one, as before: no such call, no
        source time, or a server that refused the pair (one that refuses
        a mode change may still take the time on its own)."""
        setter = getattr(job.dest_backend, "set_attributes", None)
        if not job.source_mtime or not callable(setter):
            return False
        try:
            setter(temp_path, mode=mode, mtime=job.source_mtime)
        except (OSError, NotImplementedError, ValueError) as exc:
            log.debug("cannot set mode and time of %s at once: %s", temp_path, exc)
            return False
        return True

    @staticmethod
    def _apply_source_mtime(job: TransferJob) -> None:
        """Give the copy the source's modification time where the backend
        can set one, so a later compare sees "same size and time"."""
        setter = getattr(job.dest_backend, "set_modified", None)
        if not job.source_mtime or not callable(setter):
            return
        try:
            setter(job.dest_path, job.source_mtime)
        except (OSError, NotImplementedError, ValueError) as exc:
            log.debug("cannot set the modification time of %s: %s", job.dest_path, exc)

    @staticmethod
    def _refuse_aliased_source(job: TransferJob, temp_path: str) -> None:
        """Raise :class:`_SameEntry` when a move's source folder shows the
        temp file just written into the destination folder.

        The temp name carries this job's id, so seeing it next to the
        source proves both folders are one folder under two paths (sshfs
        of localhost, one share over two protocols, a bind mount), which
        no path or inode comparison can always tell. With the same name
        (case-insensitively) the destination then IS the source, and the
        move's final delete would remove the only copy. A probe that
        fails proves nothing either way, so it refuses too: a kept source
        costs a second copy, a wrong delete costs the file.
        """
        if not job.move or not TransferWorker._same_leaf_name(job):
            return
        TransferWorker._refuse_if_seen_from_source(job, temp_path)

    @staticmethod
    def _same_leaf_name(job: TransferJob) -> bool:
        """Whether source and destination have one name (case-insensitively):
        only then can the destination be the source under another path."""
        dest_name = job.dest_path.rsplit(job.dest_backend.separator() or "/", 1)[-1]
        src_name = job.source_path.rsplit(job.source_backend.separator() or "/", 1)[-1]
        return dest_name.casefold() == src_name.casefold()

    @staticmethod
    def _refuse_aliased_direct(job: TransferJob) -> None:
        """:meth:`_refuse_aliased_source` for a transfer that writes straight
        to an existing destination of the source's name (WebDAV, FTP, SCP,
        Telnet, ADB, rsync, the cloud stores): no temp file is written
        there, so an empty probe file named with this job's id is written
        next to the destination BEFORE that is touched, and looked for next
        to the source. Without it a move onto the source's own folder under
        another path uploaded the same bytes, passed the size checks and
        deleted the only copy; a copy through a writer that truncates at
        open emptied the source, and only a short copy with a size read
        beforehand put it back (not for a symlink, or a source without a
        stat). A probe that cannot be written or looked for proves nothing:
        a move is refused then, a copy goes on (the rollback snapshot still
        catches a short copy). The probe is removed again.
        """
        if not TransferWorker._same_leaf_name(job):
            return
        dest_backend = job.dest_backend
        dest_name = job.dest_path.rsplit(dest_backend.separator() or "/", 1)[-1]
        try:
            probe = safe_join(
                dest_backend,
                dest_backend.parent(job.dest_path),
                partial_name(dest_name, f"{job.job_id}-probe", ""),
            )
            dest_backend.open_write(probe).close()
        except Exception as exc:  # noqa: BLE001 - unprovable means keep the source
            if not job.move:
                log.debug("No probe file next to %s (%s); copying without it",
                          job.dest_path, exc)
                return
            raise _SameEntry(
                f"cannot rule out that {job.source_path} and {job.dest_path} are one "
                f"file (no probe file could be written: {exc}); nothing was replaced"
            ) from exc
        try:
            TransferWorker._refuse_if_seen_from_source(job, probe, unprovable_refuses=job.move)
        finally:
            try:
                dest_backend.remove(probe)
            except Exception as exc:  # noqa: BLE001 - a leftover probe is empty
                log.warning("Could not remove the probe file %s: %s", probe, exc)

    @staticmethod
    def _refuse_if_seen_from_source(
        job: TransferJob, probe_path: str, *, unprovable_refuses: bool = True
    ) -> None:
        """Raise :class:`_SameEntry` when the file *probe_path*, just
        written next to the destination, shows up next to the source too,
        or (*unprovable_refuses*) when that cannot be checked."""
        src_backend = job.source_backend
        temp_name = probe_path.rsplit(job.dest_backend.separator() or "/", 1)[-1]
        try:
            probe = safe_join(src_backend, src_backend.parent(job.source_path), temp_name)
            visible = src_backend.exists(probe)
        except Exception as exc:  # noqa: BLE001 - unprovable means keep the source
            if not unprovable_refuses:
                log.debug("Cannot look for the probe next to %s (%s)", job.source_path, exc)
                return
            raise _SameEntry(
                f"cannot rule out that {job.source_path} and {job.dest_path} "
                f"are one file ({exc}); nothing was replaced"
            ) from exc
        if visible:
            raise _SameEntry(
                f"source and destination are the same: {job.dest_path} "
                f"(the source folder is the destination folder under another path)"
            )

    @staticmethod
    def _partial_matches_source(src, dest_backend, temp_path: str, offset: int) -> bool:
        """True when the partial's bytes agree with the source's.

        A partial of up to two windows is compared whole; a longer one by
        its first and its last window, so a resume reads at most
        ``2 * RESUME_VERIFY_WINDOW`` extra source bytes. Anything that
        prevents the comparison (no seek, no read-back) counts as a
        mismatch: restarting costs time, a wrong splice costs the file.
        """
        window = RESUME_VERIFY_WINDOW
        if offset <= 2 * window:
            spans = [(0, offset)]
        else:
            spans = [(0, window), (offset - window, window)]
        read_source = False
        try:
            with dest_backend.open_read(temp_path) as partial:
                for start, length in spans:
                    partial.seek(start)
                    src.seek(start)
                    read_source = True
                    if _read_exact(src, length) != _read_exact(partial, length):
                        break
                else:
                    return True
        except Exception as exc:  # noqa: BLE001 - unverifiable means restart
            log.info("Resume: cannot verify partial %s: %s", temp_path, exc)
        if read_source:
            # Seek worked to get here, so it brings the restart back to 0.
            src.seek(0)
        return False

    @staticmethod
    def _live_source_item(job: TransferJob):
        """The source's stat right now, or ``None`` when it cannot be read."""
        try:
            return job.source_backend.stat(job.source_path)
        except (OSError, TypeError, ValueError) as exc:
            log.debug("Resume: cannot stat source %s: %s", job.source_path, exc)
            return None

    @staticmethod
    def _partial_resumable(job: TransferJob, temp_path: str) -> bool:
        """Whether a resume could ever adopt the partial *temp_path*: only
        one whose name records the source's fingerprint. A source without
        a modification time (rsh, a shell listing without one) has none:
        its hidden partial was kept after Cancel and never resumed."""
        sep = job.dest_backend.separator() or "/"
        dest_name = job.dest_path.rsplit(sep, 1)[-1]
        temp_name = temp_path.rsplit(sep, 1)[-1]
        return bool(partial_fingerprint(temp_name, dest_name))

    @staticmethod
    def _partial_is_of_this_source(job: TransferJob, temp_path: str, live_source) -> bool:
        """True when the fingerprint in the partial's name is the live
        source's: same size and modification time as when it was written."""
        live = source_fingerprint(live_source)
        if not live:
            return False
        sep = job.dest_backend.separator() or "/"
        dest_name = job.dest_path.rsplit(sep, 1)[-1]
        temp_name = temp_path.rsplit(sep, 1)[-1]
        return partial_fingerprint(temp_name, dest_name) == live

    @staticmethod
    def _temp_destination_path(job: TransferJob) -> str:
        dest_backend = job.dest_backend
        if dest_backend is None:
            raise ValueError("Job missing destination backend")
        if job.temp_path:
            return job.temp_path

        parent = dest_backend.parent(job.dest_path)
        separator = dest_backend.separator()
        filename = (
            job.dest_path.rsplit(separator, 1)[-1] if separator in job.dest_path else job.dest_path
        )
        if not job.source_fingerprint and job.source_backend is not None:
            job.source_fingerprint = source_fingerprint(TransferWorker._live_source_item(job))
        temp_name = partial_name(filename, job.job_id, job.source_fingerprint)
        job.temp_path = safe_join(dest_backend, parent, temp_name)
        return job.temp_path

    @staticmethod
    def _finalize_temp_destination(dest_backend, temp_path: str, dest_path: str, *,
                                   no_replace: bool = False) -> None:
        from core.server_ops import _finalize_temp_destination

        _finalize_temp_destination(dest_backend, temp_path, dest_path, no_replace=no_replace)
