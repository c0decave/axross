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

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)

PROGRESS_INTERVAL = 0.1  # Minimum seconds between progress signals
SPEED_WINDOW = 3.0  # Seconds for rolling speed average
CHUNK_SIZE = 64 * 1024  # 64KB read/write chunks


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
                    log.warning("Move: could not delete source %s: %s", job.source_path, e)

            job.status = TransferStatus.DONE
            # Final progress update
            self.progress.emit(job.job_id, job.total_bytes, job.total_bytes)
            self.job_finished.emit(job.job_id)
            log.info("Transfer complete: %s", job.filename)

        except _ChecksumMismatch as exc:
            job.status = TransferStatus.ERROR
            job.error_message = str(exc)
            self.job_error.emit(job.job_id, str(exc))
            log.error("Transfer integrity check FAILED: %s", exc)
            return

        except InterruptedError:
            job.status = TransferStatus.CANCELLED
            job.error_message = "Cancelled"
            self.job_error.emit(job.job_id, "Cancelled")
            log.info("Transfer cancelled: %s", job.filename)

        except Exception as e:
            job.status = TransferStatus.ERROR
            job.error_message = str(e)
            self.job_error.emit(job.job_id, str(e))
            log.error("Transfer error for %s: %s", job.filename, e)

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
            src_err = exc
            log.debug("Source checksum unavailable: %s", exc)
        else:
            src_err = None
        try:
            dst_cs = dst.checksum(job.dest_path)
        except Exception as exc:
            dst_cs = None
            dst_err = exc
            log.debug("Dest checksum unavailable: %s", exc)
        else:
            dst_err = None
        # Native fast path: both sides returned non-empty values with
        # the same algo prefix. Use what the backend gave us.
        if src_cs and dst_cs:
            src_algo, _, src_hex = src_cs.partition(":")
            dst_algo, _, dst_hex = dst_cs.partition(":")
            if src_algo == dst_algo:
                if src_hex != dst_hex:
                    raise _ChecksumMismatch(
                        f"Integrity FAIL for {job.filename}: "
                        f"source {src_cs} != dest {dst_cs}"
                    )
                log.info(
                    "Integrity OK for %s (%s, native)",
                    job.filename, src_algo,
                )
                return
            # Algo mismatch (e.g. md5 vs sha256). Fall through to the
            # streaming path iff forced; otherwise skip as before.
            log.debug(
                "Native algo mismatch for %s: src=%s dst=%s",
                job.filename, src_algo, dst_algo,
            )
        # Opportunistic skip when not forcing.
        if not job.verify_checksum:
            return
        # Forced verification — stream both sides. Any error reading
        # from either side during forced mode is itself an integrity
        # failure (the user asked for verification; we can't deliver).
        log.info(
            "Integrity stream-sha256 for %s (forced)", job.filename,
        )
        try:
            src_sha = self._stream_sha256(
                src, job.source_path, job.cancel_event,
            )
        except InterruptedError:
            raise
        except Exception as exc:
            raise _ChecksumMismatch(
                f"Integrity FAIL for {job.filename}: "
                f"cannot read source for verification: {exc}"
            ) from exc
        try:
            dst_sha = self._stream_sha256(
                dst, job.dest_path, job.cancel_event,
            )
        except InterruptedError:
            raise
        except Exception as exc:
            raise _ChecksumMismatch(
                f"Integrity FAIL for {job.filename}: "
                f"cannot read dest for verification: {exc}"
            ) from exc
        if src_sha != dst_sha:
            raise _ChecksumMismatch(
                f"Integrity FAIL for {job.filename}: "
                f"source sha256:{src_sha} != dest sha256:{dst_sha}"
            )
        log.info(
            "Integrity OK for %s (sha256, stream)", job.filename,
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

        if job.use_temp_file:
            self._do_transfer_with_temp(job, progress_callback)
        else:
            self._do_transfer_direct(job, progress_callback)

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
                if completed:
                    # Only flush/upload if all data was written successfully
                    dst.close()
                else:
                    # Error or cancel — discard buffered data without uploading.
                    # SpooledWriter backends upload on close(), so we must NOT
                    # call close() on them. Preferred path: the writer exposes
                    # a ``discard()`` method. Second-best: we know the
                    # ``_buf`` convention from the existing SpooledWriters and
                    # close the internal buffer. Worst: a writer with neither
                    # — we log a WARNING (not debug) because that means the
                    # cancellation may have uploaded partial data to the
                    # destination, which the user DOES need to know about.
                    try:
                        if hasattr(dst, 'discard'):
                            dst.discard()
                        elif hasattr(dst, '_buf'):
                            dst._buf.close()
                        else:
                            log.warning(
                                "Transfer cancel: writer %s lacks discard() "
                                "and _buf — falling back to close(), which "
                                "may upload partial data to the destination.",
                                type(dst).__name__,
                            )
                            dst.close()
                    except Exception:
                        log.debug("Failed to discard cancelled transfer output", exc_info=True)

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

            with source_backend.open_read(job.source_path) as src:
                if resume_offset > 0:
                    # Seek source to resume position
                    try:
                        src.seek(resume_offset)
                    except (OSError, IOError):
                        resume_offset = 0
                        src.seek(0)

                if job.total_bytes > 0 and resume_offset >= job.total_bytes:
                    progress_callback(resume_offset, job.total_bytes)
                    return
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

            try:
                dest_backend.rename(temp_path, job.dest_path)
            except OSError:
                if dest_backend.exists(job.dest_path) and not dest_backend.is_dir(job.dest_path):
                    dest_backend.remove(job.dest_path)
                    dest_backend.rename(temp_path, job.dest_path)
                else:
                    raise

            cleanup_temp = False
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
    def _temp_destination_path(job: TransferJob) -> str:
        dest_backend = job.dest_backend
        if dest_backend is None:
            raise ValueError("Job missing destination backend")
        if job.temp_path:
            return job.temp_path

        parent = dest_backend.parent(job.dest_path)
        separator = dest_backend.separator()
        filename = (
            job.dest_path.rsplit(separator, 1)[-1]
            if separator in job.dest_path
            else job.dest_path
        )
        temp_name = f".{filename}.part-{job.job_id}"
        job.temp_path = dest_backend.join(parent, temp_name)
        return job.temp_path
