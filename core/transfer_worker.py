"""Transfer worker — runs file transfers on a QThread."""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import stat as stat_module
import string
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from queue import Queue
from threading import Event
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, pyqtSignal

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


_FALLBACK_UMASK: int | None = None


def process_umask() -> int:
    """This process's umask, read without changing it where possible.

    os.umask() can only be read by setting it, which for a moment lets
    another thread create a file with the wrong mode; /proc avoids that.
    """
    global _FALLBACK_UMASK
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("Umask:"):
                    return int(line.split()[1], 8)
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


def _native_checksum(backend, path: str, side: str):
    """``backend.checksum(path)``, or None when it fails."""
    try:
        return backend.checksum(path)
    except Exception as exc:
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

            finish_operation(
                job.operation_id,
                "move" if job.move else "transfer",
                status=status,
                source=job.source_path,
                dest=job.dest_path,
                bytes_total=job.total_bytes,
                bytes_done=job.transferred_bytes,
                error=error,
                **TransferWorker._journal_identity(job),
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

        def progress_callback(transferred: int, total: int) -> None:
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
                self.progress.emit(job.job_id, transferred, total)
                self.speed_update.emit(job.job_id, job.speed)

        try:
            renamed = self._move_by_rename(job)
            if renamed is None:
                renamed = self._move_on_server(job)
            if renamed is not None:
                # One rename on the same file system: no byte copied, nothing
                # to verify (it is the same file), no source left to remove.
                job.transferred_bytes = job.total_bytes = renamed
                self._finish_journal(job, status="done")
                job.status = TransferStatus.DONE
                self.progress.emit(job.job_id, renamed, renamed)
                self.job_finished.emit(job.job_id)
                log.info("Transfer complete: %s (renamed)", job.filename)
                return
            # A move compares the source's size after the copy with this, so
            # it never deletes data written to the source meanwhile.
            size_before = self._move_source_size(job)
            written = self._do_transfer(job, progress_callback)
            if written is not None:
                # What was written, not what the listing said when the job
                # was queued: a symlink is listed with the length of its
                # target path, and a source may have grown since.
                job.transferred_bytes = job.total_bytes = written
                # Now, not only after DONE: progress signals queued before
                # still carry the listing's size, and the GUI thread applies
                # them to this job; the written size must come after them.
                self.progress.emit(job.job_id, written, written)

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
            self.progress.emit(job.job_id, job.total_bytes, job.total_bytes)
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
            job.error_message = "Cancelled"
            self._finish_journal(job, status="cancelled", error="Cancelled")
            job.status = TransferStatus.CANCELLED
            self.job_error.emit(job.job_id, "Cancelled")
            log.info("Transfer cancelled: %s", job.filename)

        except Exception as e:
            job.error_message = str(e)
            self._finish_journal(job, status="error", error=str(e))
            job.status = TransferStatus.ERROR
            self.job_error.emit(job.job_id, str(e))
            log.error("Transfer error for %s: %s", job.filename, e)

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
    def _move_source_size(job: TransferJob) -> int | None:
        """The source's size before a move copies it (None for a copy)."""
        if not job.move or job.source_backend is None:
            return None
        from core.server_ops import source_size

        return source_size(job.source_backend, job.source_path)

    def _verify_integrity(self, job: TransferJob, dest_path: str | None = None) -> None:
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
            dst_cs = _native_checksum(dst, dest_path, "Dest")
            if _could_match(dst_cs, src):
                src_cs = streamed or _native_checksum(src, job.source_path, "Source")
        else:
            src_cs = streamed or _native_checksum(src, job.source_path, "Source")
            if _could_match(src_cs, dst):
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
        with backend.open_read(path) as fh:
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
        return self._do_transfer_direct(job, progress_callback, known_absent=present is False)

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

        # Outside the rollback: until the snapshot exists nothing has been
        # written, and a failed read-back of an existing destination
        # must not reach the rollback, which would take it for a partial
        # file of ours and remove it.
        if known_absent:
            destination_existed, destination_snapshot = False, None
        else:
            destination_existed, destination_snapshot = _snapshot_direct_destination(
                dest_backend,
                job.dest_path,
            )
        backup = None
        #: The writer was opened: before that nothing of the destination
        #: was touched, and a rollback could only do harm - on Google Drive
        #: it wrote the snapshot of the file listed over the one the
        #: refused open_write had just found under the name (ESTALE).
        opened = False
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
                if destination_snapshot is not None and self._same_leaf_name(job):
                    # A writer that truncates at open, aimed at the source
                    # under another path, empties it before it is read: the
                    # copy then comes out short and "succeeds". The snapshot
                    # holds the bytes; a short copy restores them.
                    size_before = source_size(source_backend, job.source_path)
            try:
                with source_backend.open_read(job.source_path) as src:
                    dst = dest_backend.open_write(job.dest_path, append=False)
                    opened = True
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
                        completed = True
                        streamed.finish()
                    finally:
                        _discard_or_close_writer(dst, completed=completed)
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
                if opened:
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
        # FTP (MFMT) is written directly: the temp-file route was the only
        # one that kept the source's time.
        self._apply_source_mtime(job)
        return transferred

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
        try:
            backup = TransferWorker._destination_backup_path(job)
            copy = getattr(dest_backend, "copy", None)
            if not callable(copy):
                raise OSError("the backend has no server-side copy")
            copy(job.dest_path, backup)
        except Exception as exc:  # noqa: BLE001 - nothing was written yet
            raise OSError(
                f"cannot keep a copy of {job.dest_path} before it is replaced and checked "
                f"({exc}); nothing was replaced"
            ) from exc
        log.debug("Kept %s as %s until the integrity check passes", job.dest_path, backup)
        return backup

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

        temp_path = self._temp_destination_path(job)
        cleanup_temp = True
        keep_partial = False
        transferred = 0
        # A partial is worth keeping only where open_write(append=True)
        # really appends: Azure Files downloads it and uploads it whole
        # again, and refuses one over 256 MiB - kept "for a resume", such a
        # partial failed every later copy of the file.
        real_append = write_traits(dest_backend).real_append

        try:
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
            elif dest_backend.exists(temp_path):
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

            with source_backend.open_read(job.source_path) as src:
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
                    self._check_existing_destination(job)
                    self._apply_source_mode(job, temp_path)
                    self._finalize_temp_destination(dest_backend, temp_path, job.dest_path)
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
                if resume_offset == 0:
                    mode_set = self._precreate_private_temp(job, temp_path)
                dst = dest_backend.open_write(temp_path, append=resume_offset > 0)

                streamed = _StreamedHash(job, resume_offset)
                completed = False
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
                finally:
                    if completed or real_append:
                        dst.close()  # an unfinished partial stays for a resume
                    else:
                        # A spooling writer (Azure Files) uploads at close:
                        # a cancelled transfer uploaded its partial, for
                        # nothing - no resume appends to it.
                        _discard_or_close_writer(dst, completed=False)

            self._refuse_aliased_source(job, temp_path)
            # The temp file, before it replaces the destination: checked
            # after the rename, a mismatch left the corrupt copy where the
            # original had been.
            self._verify_integrity(job, temp_path)
            self._check_existing_destination(job)
            if not mode_set:
                self._apply_source_mode(job, temp_path)
            self._finalize_temp_destination(dest_backend, temp_path, job.dest_path)
            self._apply_source_mtime(job)

            cleanup_temp = False
            return transferred
        except (_DestinationKept, FileExistsError, _SameEntry, _ChecksumMismatch):
            # Refused to replace the destination: the partial is of no
            # use to a retry, which would be refused the same way - or,
            # after a failed integrity check, holds the wrong bytes.
            raise
        except InterruptedError:
            keep_partial = real_append and (transferred > 0 or resume_offset > 0)
            raise
        except Exception as exc:
            # Kept for a resume - unless the destination is full: the
            # hidden partial is what fills it, and a resume needs the
            # room as well.
            keep_partial = (real_append and (transferred > 0 or resume_offset > 0)
                            and not is_out_of_space(exc))
            raise
        finally:
            if cleanup_temp and not keep_partial:
                try:
                    if dest_backend.exists(temp_path):
                        dest_backend.remove(temp_path)
                except OSError:
                    log.warning("Could not remove partial transfer %s", temp_path)

    @staticmethod
    def _precreate_private_temp(job: TransferJob, temp_path: str) -> bool:
        """Give a fresh temp file the source's mode BEFORE any data lands
        when that mode is narrower than a default file's (a 0600 key):
        written first and chmod-ed after, the bytes would sit group- or
        world-readable for the whole transfer. True when the mode is set.

        The owner gets write permission while the data goes in, as
        atomic_io gives its temp files (``_OWNER_WRITE``): created 0400
        (an AWS ``key.pem``) the temp file refused the write that follows
        for every user but root. Such a mode is set after the write (False)."""
        mode = copy_mode(job.source_mode)
        if mode is None or mode & 0o044 == 0o044:
            return False
        from core.atomic_io import _OWNER_WRITE, _precreate_with_mode

        _precreate_with_mode(job.dest_backend, temp_path, mode | _OWNER_WRITE)
        return bool(mode & _OWNER_WRITE)

    @staticmethod
    def _apply_source_mode(job: TransferJob, temp_path: str) -> None:
        """Best effort: a backend without chmod keeps its own default."""
        mode = copy_mode(job.source_mode)
        if mode is None:
            return
        from core.atomic_io import _restore_mode

        _restore_mode(job.dest_backend, temp_path, mode)

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
    def _finalize_temp_destination(dest_backend, temp_path: str, dest_path: str) -> None:
        from core.server_ops import _finalize_temp_destination

        _finalize_temp_destination(dest_backend, temp_path, dest_path)
