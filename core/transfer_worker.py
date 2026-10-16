"""Transfer worker — runs file transfers on a QThread."""

from __future__ import annotations

import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from queue import Queue
from threading import Event
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, pyqtSignal

from core.path_policy import safe_join

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


class _ChecksumMismatch(Exception):
    """Raised by _verify_integrity when source and destination
    checksums disagree after a completed transfer. Caught by the
    worker loop and surfaced as a regular TransferStatus.ERROR with
    a specific error message so the UI can distinguish data-corruption
    from other failure modes."""


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

    progress = pyqtSignal(str, int, int)  # job_id, bytes_done, bytes_total
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
            self._do_transfer(job, progress_callback)

            # Post-transfer integrity check: native compare when both
            # backends produce matching-algorithm hashes cheaply. When
            # ``job.verify_checksum`` is True and native is missing /
            # empty / algo-mismatched, fall back to streaming sha256
            # of both sides.
            self._verify_integrity(job)

            # Move mode: delete source after successful transfer
            if job.move and job.source_backend:
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
            if src_algo == dst_algo:
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
            # Algo mismatch (e.g. md5 vs sha256). Fall through to the
            # streaming path iff forced; otherwise skip as before.
            log.debug(
                "Native algo mismatch for %s: src=%s dst=%s",
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
    ) -> None:
        """Perform the actual file copy using backend open_read/open_write."""
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
            self._do_transfer_with_temp(job, progress_callback)
        else:
            self._do_transfer_direct(job, progress_callback)

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
    ) -> None:
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

    def _do_transfer_with_temp(
        self,
        job: TransferJob,
        progress_callback,
    ) -> None:
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
            if job.resume and dest_backend.exists(temp_path):
                # Resume from existing partial file
                try:
                    partial_stat = dest_backend.stat(temp_path)
                    resume_offset = partial_stat.size
                    log.info("Resuming transfer at offset %d for %s", resume_offset, job.filename)
                except OSError:
                    resume_offset = 0
            elif dest_backend.exists(temp_path):
                dest_backend.remove(temp_path)

            if resume_offset > 0:
                # The size the job carries can be stale: a retry copies it
                # from the failed job, and the source may have been rewritten
                # since. Resuming past the live end would read nothing and
                # finalize the old partial as the file.
                source_size = self._live_source_size(job)
                if source_size:
                    job.total_bytes = source_size
                limit = source_size if source_size is not None else job.total_bytes
                if (source_size is not None or limit > 0) and resume_offset > limit:
                    log.warning(
                        "Discarding oversized partial %s (%d > %d bytes) "
                        "for %s; restarting transfer",
                        temp_path,
                        resume_offset,
                        limit,
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
                    self._check_existing_destination(job)
                    self._finalize_temp_destination(dest_backend, temp_path, job.dest_path)
                    cleanup_temp = False
                    return
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

            self._check_existing_destination(job)
            self._finalize_temp_destination(dest_backend, temp_path, job.dest_path)

            cleanup_temp = False
        except (_DestinationKept, FileExistsError):
            # Refused to replace the destination: the partial is of no
            # use to a retry, which would be refused the same way.
            raise
        except InterruptedError:
            keep_partial = transferred > 0 or resume_offset > 0
            raise
        except Exception:
            keep_partial = transferred > 0 or resume_offset > 0
            raise
        finally:
            if cleanup_temp and not keep_partial:
                try:
                    if dest_backend.exists(temp_path):
                        dest_backend.remove(temp_path)
                except OSError:
                    log.warning("Could not remove partial transfer %s", temp_path)

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
    def _live_source_size(job: TransferJob) -> int | None:
        """The source's size right now, or ``None`` when it cannot be read."""
        try:
            return int(getattr(job.source_backend.stat(job.source_path), "size", 0) or 0)
        except (OSError, TypeError, ValueError) as exc:
            log.debug("Resume: cannot stat source %s: %s", job.source_path, exc)
            return None

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
        temp_name = f".{filename}.part-{job.job_id}"
        job.temp_path = safe_join(dest_backend, parent, temp_name)
        return job.temp_path

    @staticmethod
    def _finalize_temp_destination(dest_backend, temp_path: str, dest_path: str) -> None:
        from core.server_ops import _finalize_temp_destination

        _finalize_temp_destination(dest_backend, temp_path, dest_path)
