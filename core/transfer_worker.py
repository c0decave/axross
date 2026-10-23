"""Transfer worker — runs file transfers on a QThread."""

from __future__ import annotations

import errno
import hashlib
import logging
import os
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
    # What to do with an existing destination (core.transfer_conflicts):
    # "overwrite" (the default), "fail" or "newer". Checked right before
    # the first write and again right before the temp file is renamed.
    if_exists: str = "overwrite"
    # True when "newer" found a destination at least as new: nothing was
    # written and a move kept its source.
    skipped: bool = False
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

    def __init__(self, parent=None):
        super().__init__(parent)
        self._queue: Queue[TransferJob | None] = Queue()
        self._running = True

    def enqueue(self, job: TransferJob) -> None:
        self._queue.put(job)

    def stop(self) -> None:
        self._running = False
        self._queue.put(None)  # Sentinel to unblock

    @staticmethod
    def _journal_identity(job: TransferJob) -> dict:
        """Backend label and direction for every journal event of *job*.

        Undo reads the FINISH event, so it has to carry them too: without
        the direction a cross-backend move looks like a same-backend
        rename, and without the labels undo cannot tell which host it is
        on or which host the data came from.
        """
        return {
            "backend": _backend_label(job.dest_backend),
            "details": {
                "direction": job.direction.name,
                "source_backend": _backend_label(job.source_backend),
            },
        }

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
        while self._running:
            job = self._queue.get()
            if job is None:
                break
            self._process_job(job)
        log.info("Transfer worker stopped")

    def _process_job(self, job: TransferJob) -> None:
        job.status = TransferStatus.ACTIVE
        self.job_started.emit(job.job_id)
        self._record_journal_phase(job, "worker_start")

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

            # Post-transfer integrity check: native compare when both
            # backends produce matching-algorithm hashes cheaply. When
            # ``job.verify_checksum`` is True and native is missing /
            # empty / algo-mismatched, fall back to streaming sha256
            # of both sides.
            self._verify_integrity(job)

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

            job.status = TransferStatus.DONE
            # Final progress update
            self.progress.emit(job.job_id, job.total_bytes, job.total_bytes)
            self.job_finished.emit(job.job_id)
            log.info("Transfer complete: %s", job.filename)
            self._finish_journal(job, status="done")

        except _DestinationKept as exc:
            job.skipped = True
            job.status = TransferStatus.DONE
            self.job_finished.emit(job.job_id)
            log.info("Transfer skipped: %s", exc)
            self._finish_journal(job, status="skipped", error=str(exc))
            return

        except _ChecksumMismatch as exc:
            job.status = TransferStatus.ERROR
            job.error_message = str(exc)
            self.job_error.emit(job.job_id, str(exc))
            log.error("Transfer integrity check FAILED: %s", exc)
            self._finish_journal(job, status="error", error=str(exc))
            return

        except InterruptedError:
            job.status = TransferStatus.CANCELLED
            job.error_message = "Cancelled"
            self.job_error.emit(job.job_id, "Cancelled")
            log.info("Transfer cancelled: %s", job.filename)
            self._finish_journal(job, status="cancelled", error="Cancelled")

        except Exception as e:
            job.status = TransferStatus.ERROR
            job.error_message = str(e)
            self.job_error.emit(job.job_id, str(e))
            log.error("Transfer error for %s: %s", job.filename, e)
            self._finish_journal(job, status="error", error=str(e))

    @staticmethod
    def _move_source_size(job: TransferJob) -> int | None:
        """The source's size before a move copies it (None for a copy)."""
        if not job.move or job.source_backend is None:
            return None
        from core.server_ops import source_size

        return source_size(job.source_backend, job.source_path)

    def _verify_integrity(self, job: TransferJob) -> None:
        """Compare source + dest checksum after a successful transfer.

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
        try:
            src_cs = src.checksum(job.source_path)
        except Exception as exc:
            src_cs = None
            log.debug("Source checksum unavailable: %s", exc)
        try:
            dst_cs = dst.checksum(job.dest_path)
        except Exception as exc:
            dst_cs = None
            log.debug("Dest checksum unavailable: %s", exc)
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
                job.dest_path,
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

        self._check_existing_destination(job)
        if job.use_temp_file:
            return self._do_transfer_with_temp(job, progress_callback)
        return self._do_transfer_direct(job, progress_callback)

    @staticmethod
    def _check_existing_destination(job: TransferJob) -> None:
        """Enforce ``job.if_exists`` against the destination as it is NOW.

        The conflict prompt looked at the destination earlier; a file that
        appeared since must not be replaced on the strength of an answer
        about another state. ``"fail"`` raises :class:`FileExistsError`,
        ``"newer"`` raises :class:`_DestinationKept` unless the source is
        strictly newer. A destination that cannot be checked counts as
        present: guessing "absent" is how a file gets overwritten.
        """
        mode = job.if_exists
        if mode == "overwrite":
            return
        dest_backend = job.dest_backend
        try:
            present = dest_backend.exists(job.dest_path)
        except Exception as exc:  # noqa: BLE001 - unknown means do not write
            raise OSError(
                f"cannot check whether {job.dest_path} already exists: {exc}"
            ) from exc
        if not present:
            return
        if mode == "newer":
            src_mtime = TransferWorker._mtime_of(job.source_backend, job.source_path)
            dst_mtime = TransferWorker._mtime_of(dest_backend, job.dest_path)
            if src_mtime is not None and dst_mtime is not None and src_mtime > dst_mtime:
                return
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
    ) -> int:
        """Write directly to dest_path (no temp file + rename).

        Used for backends where temp-file rename is unsupported (IMAP),
        extremely expensive (rsync), or pointless because the backend
        already buffers internally via SpooledWriter (FTP, WebDAV, S3,
        Azure Blob, cloud backends).
        """
        source_backend = job.source_backend
        dest_backend = job.dest_backend
        transferred = 0
        completed = False

        from core.server_ops import (
            _discard_or_close_writer,
            _rollback_direct_destination,
            _snapshot_direct_destination,
        )

        # Outside the try: until the snapshot exists nothing has been
        # written, and a failed read-back of an existing destination
        # must not reach the rollback, which would take it for a partial
        # file of ours and remove it.
        destination_existed, destination_snapshot = _snapshot_direct_destination(
            dest_backend,
            job.dest_path,
        )
        try:
            with source_backend.open_read(job.source_path) as src:
                dst = dest_backend.open_write(job.dest_path, append=False)
                try:
                    while True:
                        if job.cancel_event.is_set():
                            raise InterruptedError("Transfer cancelled")
                        chunk = src.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        dst.write(chunk)
                        transferred += len(chunk)
                        progress_callback(transferred, job.total_bytes)
                    completed = True
                finally:
                    _discard_or_close_writer(dst, completed=completed)
        except BaseException:
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
        return transferred

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

        temp_path = self._temp_destination_path(job)
        cleanup_temp = True
        keep_partial = False
        transferred = 0

        try:
            resume_offset = 0
            live_size = 0
            if job.resume and dest_backend.exists(temp_path):
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
                        transferred += len(chunk)
                        progress_callback(transferred, job.total_bytes)
                finally:
                    dst.close()

            self._refuse_aliased_source(job, temp_path)
            self._check_existing_destination(job)
            if not mode_set:
                self._apply_source_mode(job, temp_path)
            self._finalize_temp_destination(dest_backend, temp_path, job.dest_path)
            self._apply_source_mtime(job)

            cleanup_temp = False
            return transferred
        except (_DestinationKept, FileExistsError, _SameEntry):
            # Refused to replace the destination: the partial is of no
            # use to a retry, which would be refused the same way.
            raise
        except InterruptedError:
            keep_partial = transferred > 0 or resume_offset > 0
            raise
        except Exception as exc:
            # Kept for a resume - unless the destination is full: the
            # hidden partial is what fills it, and a resume needs the
            # room as well.
            keep_partial = (transferred > 0 or resume_offset > 0) and not is_out_of_space(exc)
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
        world-readable for the whole transfer. True when the mode is set."""
        mode = copy_mode(job.source_mode)
        if mode is None or mode & 0o044 == 0o044:
            return False
        from core.atomic_io import _precreate_with_mode

        _precreate_with_mode(job.dest_backend, temp_path, mode)
        return True

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
        if not job.move:
            return
        src_backend, dest_backend = job.source_backend, job.dest_backend
        dest_sep = dest_backend.separator() or "/"
        src_sep = src_backend.separator() or "/"
        dest_name = job.dest_path.rsplit(dest_sep, 1)[-1]
        src_name = job.source_path.rsplit(src_sep, 1)[-1]
        if dest_name.casefold() != src_name.casefold():
            return
        temp_name = temp_path.rsplit(dest_sep, 1)[-1]
        try:
            probe = safe_join(src_backend, src_backend.parent(job.source_path), temp_name)
            visible = src_backend.exists(probe)
        except Exception as exc:  # noqa: BLE001 - unprovable means keep the source
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
