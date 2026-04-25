"""Transfer manager — coordinates transfer workers and job queue."""
from __future__ import annotations

import logging
import os
import posixpath
from typing import TYPE_CHECKING, Callable

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from core.transfer_worker import (
    TransferDirection,
    TransferJob,
    TransferStatus,
    TransferWorker,
)
from core import backend_registry

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)


def _safe_basename(name: str) -> str:
    """Return *name* only if it is a single path component that cannot
    escape its parent directory; otherwise raise :class:`ValueError`.

    Reject values the OS would interpret as navigation rather than a
    filename: ``.``, ``..``, anything containing a path separator
    (``/``, ``\\``) or a NUL byte. Without this guard a malicious remote
    server listing an entry named ``..`` could have axross compute
    ``<user_dir>/..`` as the destination path and overwrite files
    above the user's chosen target directory.
    """
    if not name or name in (".", ".."):
        raise ValueError(f"Unsafe remote filename: {name!r}")
    if "/" in name or "\\" in name or "\x00" in name:
        raise ValueError(f"Unsafe remote filename: {name!r}")
    return name


def _probe_resumable_temp(
    backend: FileBackend, dest_path: str,
) -> tuple[str, int] | None:
    """Look for an existing partial ``.axross-tmp.*`` sibling of
    *dest_path* on the backend. Returns ``(temp_path, size)`` if a
    non-empty partial exists, else ``None``.

    This is best-effort: any backend error while probing disables
    auto-resume (we restart from scratch) rather than surfacing the
    error to the user. Resume is an optimisation, not a correctness
    requirement.
    """
    try:
        sep = backend.separator()
        parent = backend.parent(dest_path)
        filename = (
            dest_path.rsplit(sep, 1)[-1] if sep in dest_path else dest_path
        )
        # Match ``_temp_destination_path`` in transfer_worker.py:
        # ``.{filename}.part-{job_id}``. The job_id differs on each
        # run; we match by prefix so any prior partial counts.
        temp_prefix = f".{filename}.part-"
        for item in backend.list_dir(parent):
            name = getattr(item, "name", "") or ""
            if not name.startswith(temp_prefix):
                continue
            tmp_path = backend.join(parent, name)
            size = int(getattr(item, "size", 0) or 0)
            if size > 0:
                return tmp_path, size
    except Exception as exc:  # noqa: BLE001
        log.debug(
            "auto-resume probe of %s failed (%s) — will start fresh",
            dest_path, exc,
        )
    return None


def _should_use_temp_file(backend: FileBackend) -> bool:
    """Check if a backend benefits from the temp-file-then-rename pattern.

    Backends that buffer writes internally (SpooledWriter) gain nothing
    from an extra rename step.  Backends without efficient rename (S3,
    rsync, IMAP) actually break or suffer badly from it.

    Only true filesystem-like backends (local, SFTP, SMB, NFS, iSCSI,
    Azure Files) benefit from atomic temp-file + rename.
    """
    class_name = type(backend).__name__
    for info in backend_registry.all_backends():
        if info.class_name == class_name:
            caps = info.capabilities
            # Use temp files only when the backend can stream writes AND
            # has efficient (native) rename support.
            return caps.can_stream_write and caps.can_rename
    # Unknown backend — default to safe temp-file mode
    return True


class TransferManager(QObject):
    """Manages file transfers between backends.

    Provides a high-level API for enqueueing transfers,
    tracking progress, and handling cancellation.
    """

    job_added = pyqtSignal(object)  # TransferJob
    job_updated = pyqtSignal(str)  # job_id
    job_finished = pyqtSignal(str)  # job_id
    job_error = pyqtSignal(str, str)  # job_id, error_message
    # Emitted when a recursive directory transfer cannot create or list a
    # remote directory. Payload is (absolute_path, reason). The UI can
    # surface this to the user; prior to this signal the failure was only
    # visible in the log.
    directory_error = pyqtSignal(str, str)
    all_finished = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._jobs: dict[str, TransferJob] = {}
        self._queued_count = 0
        self._active_count = 0
        self._dirs_to_remove_after_move: list[tuple] = []  # (backend, dir_path)

        # Worker thread
        self._worker = TransferWorker()
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)

        # Connect worker signals
        self._worker.progress.connect(self._on_progress)
        self._worker.speed_update.connect(self._on_speed)
        self._worker.job_started.connect(self._on_job_started)
        self._worker.job_finished.connect(self._on_job_finished)
        self._worker.job_error.connect(self._on_job_error)

        self._thread.start()

    def transfer_file(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_path: str,
        dest_path: str,
        direction: TransferDirection = TransferDirection.DOWNLOAD,
        move: bool = False,
    ) -> TransferJob:
        """Enqueue a single file transfer."""
        # Get file size for progress
        try:
            stat = source_backend.stat(source_path)
            total_bytes = stat.size
        except OSError:
            total_bytes = 0

        # Determine filename
        sep = source_backend.separator()
        filename = source_path.rsplit(sep, 1)[-1] if sep in source_path else source_path

        use_temp = _should_use_temp_file(dest_backend)
        # Auto-resume: if a previous interrupted run left an
        # ``.axross-tmp.*`` file in the destination directory for
        # this filename, and the dest backend supports the
        # open_read + seek idiom, pick up where we left off instead
        # of restarting at offset 0. Saves hours on 10 GiB transfers
        # over slow links. Resume semantics only apply to the
        # temp-file path (direct writes have no partial state).
        auto_resume = False
        resume_temp_path = ""
        if use_temp:
            probe = _probe_resumable_temp(dest_backend, dest_path)
            if probe is not None:
                tmp_path, tmp_size = probe
                # Only treat as resumable if the partial is non-empty
                # and SMALLER than the source (otherwise the previous
                # transfer likely finished and something else is
                # going on — start fresh to avoid silent corruption).
                if 0 < tmp_size < (total_bytes or float("inf")):
                    auto_resume = True
                    # Pin the temp path on the job so the worker picks
                    # up THIS specific partial — otherwise
                    # ``_temp_destination_path`` generates a fresh
                    # ``.filename.part-<new-job-id>`` path that won't
                    # match the leftover.
                    resume_temp_path = tmp_path
                    log.info(
                        "Auto-resume: found partial %s (%d bytes); "
                        "will continue from offset %d",
                        tmp_path, tmp_size, tmp_size,
                    )

        job = TransferJob(
            source_path=source_path,
            dest_path=dest_path,
            direction=direction,
            total_bytes=total_bytes,
            filename=filename,
            move=move,
            use_temp_file=use_temp,
            resume=auto_resume,
            temp_path=resume_temp_path,
        )

        job.source_backend = source_backend
        job.dest_backend = dest_backend

        self._jobs[job.job_id] = job
        self._queued_count += 1
        self.job_added.emit(job)
        self._worker.enqueue(job)

        log.info(
            "Enqueued transfer: %s -> %s (%s bytes)",
            source_path,
            dest_path,
            total_bytes,
        )
        return job

    def transfer_files(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_paths: list[str],
        dest_dir: str,
        direction: TransferDirection = TransferDirection.DOWNLOAD,
        move: bool = False,
    ) -> list[TransferJob]:
        """Enqueue multiple file transfers to a destination directory."""
        jobs = []
        for src_path in source_paths:
            sep = source_backend.separator()
            filename = src_path.rsplit(sep, 1)[-1] if sep in src_path else src_path
            try:
                filename = _safe_basename(filename)
            except ValueError as exc:
                log.warning(
                    "Skipping transfer with unsafe source filename: %s",
                    exc,
                )
                continue
            dest_path = dest_backend.join(dest_dir, filename)

            # Check if source is a directory — if so, recurse
            try:
                if source_backend.is_dir(src_path):
                    sub_jobs = self._transfer_directory(
                        source_backend, dest_backend, src_path, dest_path, direction,
                        move=move,
                    )
                    jobs.extend(sub_jobs)
                    continue
            except OSError as e:
                log.warning("Could not stat %s, transferring as file: %s", src_path, e)

            job = self.transfer_file(
                source_backend, dest_backend, src_path, dest_path, direction,
                move=move,
            )
            jobs.append(job)

        return jobs

    def _transfer_directory(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_dir: str,
        dest_dir: str,
        direction: TransferDirection,
        move: bool = False,
    ) -> list[TransferJob]:
        """Recursively transfer a directory."""
        jobs = []

        # Create destination directory
        try:
            if not dest_backend.exists(dest_dir):
                dest_backend.mkdir(dest_dir)
        except OSError as e:
            log.error("Failed to create directory %s: %s", dest_dir, e)
            self.directory_error.emit(dest_dir, f"mkdir failed: {e}")
            return jobs

        # List source directory
        try:
            items = source_backend.list_dir(source_dir)
        except OSError as e:
            log.error("Failed to list %s: %s", source_dir, e)
            self.directory_error.emit(source_dir, f"list failed: {e}")
            return jobs

        for item in items:
            try:
                safe_name = _safe_basename(item.name)
            except ValueError as exc:
                log.warning(
                    "Skipping remote entry with unsafe name in %s: %s",
                    source_dir, exc,
                )
                continue
            src_path = source_backend.join(source_dir, safe_name)
            dst_path = dest_backend.join(dest_dir, safe_name)

            if item.is_dir:
                sub_jobs = self._transfer_directory(
                    source_backend, dest_backend, src_path, dst_path, direction,
                    move=move,
                )
                jobs.extend(sub_jobs)
            else:
                job = self.transfer_file(
                    source_backend, dest_backend, src_path, dst_path, direction,
                    move=move,
                )
                jobs.append(job)

        # For move: schedule source dir removal after all files transferred
        if move:
            self._dirs_to_remove_after_move.append((source_backend, source_dir))

        return jobs

    def cancel_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if job:
            job.cancel_event.set()
            log.info("Cancel requested for %s", job_id)

    def cancel_all(self) -> None:
        for job in self._jobs.values():
            if job.status in (TransferStatus.PENDING, TransferStatus.ACTIVE):
                job.cancel_event.set()

    def get_job(self, job_id: str) -> TransferJob | None:
        return self._jobs.get(job_id)

    def all_jobs(self) -> list[TransferJob]:
        return list(self._jobs.values())

    def retry_job(self, job_id: str) -> TransferJob | None:
        """Retry a failed or cancelled job, resuming from partial data if possible."""
        old_job = self._jobs.get(job_id)
        if not old_job:
            return None
        if old_job.status not in (TransferStatus.ERROR, TransferStatus.CANCELLED):
            return None

        new_job = TransferJob(
            source_path=old_job.source_path,
            dest_path=old_job.dest_path,
            direction=old_job.direction,
            total_bytes=old_job.total_bytes,
            filename=old_job.filename,
            resume=True,
            temp_path=old_job.temp_path,
            move=old_job.move,
            use_temp_file=old_job.use_temp_file,
        )
        new_job.source_backend = old_job.source_backend
        new_job.dest_backend = old_job.dest_backend

        self._jobs[new_job.job_id] = new_job
        self._queued_count += 1
        self.job_added.emit(new_job)
        self._worker.enqueue(new_job)

        log.info("Retrying transfer (resume): %s -> %s", old_job.source_path, old_job.dest_path)
        return new_job

    def clear_finished(self) -> None:
        """Remove completed/errored/cancelled jobs."""
        to_remove = [
            jid
            for jid, j in self._jobs.items()
            if j.status in (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)
        ]
        for jid in to_remove:
            del self._jobs[jid]

    def shutdown(self) -> None:
        self.cancel_all()
        self._worker.stop()
        self._thread.quit()
        self._thread.wait(5000)

    # --- Slots for worker signals ---

    def _on_progress(self, job_id: str, transferred: int, total: int) -> None:
        job = self._jobs.get(job_id)
        if job:
            job.transferred_bytes = transferred
            job.total_bytes = total
            self.job_updated.emit(job_id)

    def _on_speed(self, job_id: str, speed: float) -> None:
        job = self._jobs.get(job_id)
        if job:
            job.speed = speed

    def _on_job_started(self, job_id: str) -> None:
        self._queued_count = max(0, self._queued_count - 1)
        self._active_count += 1
        job = self._jobs.get(job_id)
        if job:
            log.info("Transfer started: %s (%s)", job.filename, job_id)
        self.job_updated.emit(job_id)

    def _on_job_finished(self, job_id: str) -> None:
        self._active_count = max(0, self._active_count - 1)
        job = self._jobs.get(job_id)
        if job:
            job.status = TransferStatus.DONE
            log.info("Transfer finished: %s (%s)", job.filename, job_id)
        self.job_finished.emit(job_id)
        if self._active_count == 0 and self._queued_count == 0:
            self._cleanup_move_dirs()
            self.all_finished.emit()

    def _on_job_error(self, job_id: str, error: str) -> None:
        self._active_count = max(0, self._active_count - 1)
        job = self._jobs.get(job_id)
        if job:
            job.error_message = error
            log.error("Transfer failed: %s (%s): %s", job.filename, job_id, error)
        self.job_error.emit(job_id, error)
        if self._active_count == 0 and self._queued_count == 0:
            self._cleanup_move_dirs()
            self.all_finished.emit()

    def _cleanup_move_dirs(self) -> None:
        """Remove empty source directories after a move operation (deepest first)."""
        if not self._dirs_to_remove_after_move:
            return
        # Process in reverse order so deepest dirs are removed first
        for backend, dir_path in reversed(self._dirs_to_remove_after_move):
            try:
                remaining = backend.list_dir(dir_path)
                if not remaining:
                    backend.remove(dir_path)
                    log.info("Move: removed empty source directory %s", dir_path)
                else:
                    log.debug("Move: source directory %s not empty, keeping", dir_path)
            except OSError as e:
                log.warning("Move: could not remove source directory %s: %s", dir_path, e)
        self._dirs_to_remove_after_move.clear()
