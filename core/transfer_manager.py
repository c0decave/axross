"""Transfer manager — coordinates transfer workers and job queue."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from core import backend_registry
from core.capability_contracts import contract_for_backend
from core.path_policy import safe_join, safe_leaf, transfer_leaf
from core.transfer_conflicts import IF_EXISTS_OVERWRITE, prefetch_stats
from core.transfer_pool import MAX_PARALLEL, JobScheduler, parallel_transfers, valid_parallel
from core.transfer_worker import (
    TransferDirection,
    TransferJob,
    TransferStatus,
    TransferWorker,
    _backend_label,
    partial_fingerprint,
    partial_prefix,
    source_fingerprint,
)

if TYPE_CHECKING:
    from core.backend import FileBackend
    from core.transfer_conflicts import ConflictPlan

log = logging.getLogger(__name__)


def _safe_basename(name: str, source_backend=None, dest_backend=None) -> str:
    """Return *name* only if it is a single path component that cannot
    escape its parent directory; otherwise raise :class:`ValueError`.
    With both backends, their own name rules apply (core.path_policy:
    a backslash is a plain character only where both say so).

    Reject values the OS would interpret as navigation rather than a
    filename: ``.``, ``..``, anything containing a path separator
    (``/``, ``\\``) or a NUL byte. Without this guard a malicious remote
    server listing an entry named ``..`` could have axross compute
    ``<user_dir>/..`` as the destination path and overwrite files
    above the user's chosen target directory.
    """
    try:
        if source_backend is not None and dest_backend is not None:
            return transfer_leaf(source_backend, dest_backend, name)
        return safe_leaf(name)
    except ValueError as exc:
        raise ValueError(f"Unsafe remote filename: {name!r}") from exc


class _DestListings:
    """Destination folder listings for one enqueue batch.

    The auto-resume probe looks for leftover partials next to each target
    file; listing the folder once per *file* made a 1 000-file folder copy
    list it 1 001 times. Each folder is listed at most once here, and not
    at all when this batch just created it. A failed listing counts as "no
    partials", which is what the per-file probe concluded from it too.
    """

    def __init__(self, backend: FileBackend) -> None:
        self._backend = backend
        self._listings: dict[str, list] = {}

    def created(self, folder: str) -> None:
        self._listings[folder] = []

    def entries(self, folder: str) -> list:
        if folder not in self._listings:
            try:
                self._listings[folder] = list(self._backend.list_dir(folder))
            except Exception as exc:  # noqa: BLE001 - same as the probe's catch-all
                log.debug("auto-resume probe of %s failed (%s) — will start fresh", folder, exc)
                self._listings[folder] = []
        return self._listings[folder]


def _probe_resumable_temp(
    backend: FileBackend,
    dest_path: str,
    listings: _DestListings | None = None,
    fingerprint: str = "",
) -> tuple[str, int] | None:
    """Look for an existing partial ``.<name>.part-*`` sibling of
    *dest_path* on the backend. Returns ``(temp_path, size)`` if a
    non-empty partial exists, else ``None``. A partial whose name records
    *fingerprint* (the source as it is now) is preferred; the worker
    discards any other before it writes.

    This is best-effort: any backend error while probing disables
    auto-resume (we restart from scratch) rather than surfacing the
    error to the user. Resume is an optimisation, not a correctness
    requirement.
    """
    try:
        sep = backend.separator()
        parent = backend.parent(dest_path)
        filename = dest_path.rsplit(sep, 1)[-1] if sep in dest_path else dest_path
        # Match ``_temp_destination_path`` in transfer_worker.py:
        # ``.{filename}.part-{job_id}-{fingerprint}``. The job_id differs on
        # each run; we match by prefix so any prior partial counts.
        temp_prefix = partial_prefix(filename)
        entries = listings.entries(parent) if listings is not None else backend.list_dir(parent)
        fallback: tuple[str, int] | None = None
        for item in entries:
            name = getattr(item, "name", "") or ""
            if not name.startswith(temp_prefix):
                continue
            try:
                tmp_path = safe_join(backend, parent, name)
            except ValueError as exc:
                log.warning(
                    "Ignoring unsafe partial-transfer candidate %r in %s: %s",
                    name,
                    parent,
                    exc,
                )
                continue
            # Only a real regular file may be resumed: a symlink's
            # "size" is its target-string length, and appending through
            # it writes into whatever it points at.
            if getattr(item, "is_link", False) or getattr(item, "is_dir", False):
                continue
            size = int(getattr(item, "size", 0) or 0)
            if size <= 0:
                continue
            if fingerprint and partial_fingerprint(name, filename) == fingerprint:
                return tmp_path, size
            if fallback is None:
                fallback = tmp_path, size
        return fallback
    except Exception as exc:  # noqa: BLE001
        log.debug(
            "auto-resume probe of %s failed (%s) — will start fresh",
            dest_path,
            exc,
        )
    return None


def _source_metadata(item) -> tuple[int | None, float | None]:
    """(permission bits, modification time) a copy of *item* should get,
    None for what the listing does not tell. A symlink's own mode (0777)
    and time say nothing about the file it points to."""
    if item is None or getattr(item, "is_link", False):
        return None, None
    mode = int(getattr(item, "permissions", 0) or 0) or None
    modified = getattr(item, "modified", None)
    try:
        mtime = float(modified.timestamp()) if modified is not None else None
    except (AttributeError, OSError, OverflowError, ValueError):
        mtime = None
    return mode, (mtime if mtime and mtime > 0 else None)


def _self_target_refusal(
    source_backend: FileBackend,
    source_path: str,
    dest_backend: FileBackend,
    dest_path: str,
    *,
    is_dir: bool,
) -> str:
    """Why copying *source_path* to *dest_path* must not start, or ``""``.

    Onto itself, a move deletes the only copy once the copy "succeeded";
    a folder copied into itself lists its own copy while making it and
    recurses until the stack or the path length gives out.
    """
    from core.storage_identity import is_within, same_entry

    if is_dir:
        if is_within(source_backend, source_path, dest_backend, dest_path):
            return f"cannot copy or move a folder into itself: {dest_path}"
    elif same_entry(source_backend, source_path, dest_backend, dest_path):
        return f"source and destination are the same: {dest_path}"
    return ""


def _is_dir_from_stat(answer) -> bool:
    """``is_dir`` from a ``stat_many`` answer, for a backend whose is_dir is
    its stat's type: False for not found, the error for anything else."""
    if isinstance(answer, (FileNotFoundError, NotADirectoryError)):
        return False
    if isinstance(answer, OSError):
        raise answer
    return bool(getattr(answer, "is_dir", False))


def _should_use_temp_file(backend: FileBackend) -> bool:
    """Check if a backend benefits from the temp-file-then-rename pattern.

    Backends that buffer writes internally (SpooledWriter) gain nothing
    from an extra rename step.  Backends without efficient rename (S3,
    rsync, IMAP) actually break or suffer badly from it.

    Only true filesystem-like backends (local, SFTP, SMB, NFS, iSCSI,
    Azure Files) benefit from atomic temp-file + rename.
    """
    try:
        from core.local_fs import LocalFS

        if isinstance(backend, LocalFS) and type(backend).rename is not LocalFS.rename:
            return False
    except Exception:
        pass
    try:
        from core.db_fs_base import DbFsBackend

        if isinstance(backend, DbFsBackend):
            return False
    except Exception:
        pass
    contract = contract_for_backend(backend)
    if contract.can_stream_write and contract.can_rename and contract.rename_atomic:
        return True
    class_name = type(backend).__name__
    for info in backend_registry.all_backends():
        if info.class_name == class_name:
            caps = info.capabilities
            # Use temp files only when the backend can stream writes AND
            # has efficient (native) rename support.
            return bool(caps.can_stream_write and caps.can_rename and caps.rename_atomic)
    # Unknown backend: don't assume POSIX-style atomic rename. Direct
    # transfers still use guarded rollback in TransferWorker.
    return False


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
    # A background walk (transfer_files_in_background) registered its jobs.
    walk_finished = pyqtSignal()
    # Internal: a walk thread hands its result to the GUI thread.
    _walk_done = pyqtSignal(object)

    def __init__(self, parent=None, *, max_parallel: int | None = None):
        """*max_parallel*: jobs that may run at the same time (1..MAX_PARALLEL); None
        reads the "Parallel transfers" setting (core.transfer_pool)."""
        super().__init__(parent)
        if max_parallel is None:
            max_parallel = parallel_transfers()
        elif not valid_parallel(max_parallel):
            raise ValueError(f"max_parallel must be 1..{MAX_PARALLEL}, not {max_parallel!r}")
        self._jobs: dict[str, TransferJob] = {}
        self._queued_count = 0
        self._active_count = 0
        self._dirs_to_remove_after_move: list[tuple] = []  # (backend, dir_path)
        # Move source folders the cleanup kept because something was still
        # in them (a file whose move failed), deepest first. Retrying such
        # a file puts the folders above it back on the cleanup list.
        self._kept_move_dirs: list[tuple] = []  # (backend, dir_path)
        # A walk thread collects its jobs here instead of registering them;
        # the GUI thread registers them when the walk is done.
        self._local = threading.local()
        # Walks in flight: [source_backend, dest_backend, cancel event] per
        # walk. cancel_all sets the event: the walk stops and queues nothing.
        self._walks: list[list] = []
        self._shut_down = False
        # Cancel All presses so far: work that starts before it queues its
        # jobs (the conflict check of F5 / F6) compares and drops them.
        self._cancel_epoch = 0
        self._walk_done.connect(self._finish_walk)

        # Worker threads. They share one queue (core.transfer_pool); with
        # max_parallel 1 the first worker is the only one and runs the jobs
        # one after the other, in queue order, as the single worker did.
        # _worker / _thread are that first worker: every job is queued
        # through _worker.enqueue.
        self._scheduler = JobScheduler(max_parallel)
        self._pool: list[tuple[TransferWorker, QThread]] = []
        self._worker, self._thread = self._add_worker()
        self._ensure_workers(max_parallel)

    def _add_worker(self) -> tuple[TransferWorker, QThread]:
        worker = TransferWorker(scheduler=self._scheduler, index=len(self._pool))
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)

        worker.progress.connect(self._on_progress)
        worker.speed_update.connect(self._on_speed)
        worker.job_started.connect(self._on_job_started)
        worker.job_finished.connect(self._on_job_finished)
        worker.job_error.connect(self._on_job_error)

        self._pool.append((worker, thread))
        thread.start()
        return worker, thread

    def _ensure_workers(self, count: int) -> None:
        while len(self._pool) < count:
            self._add_worker()

    @property
    def max_parallel(self) -> int:
        """Jobs that may run at the same time."""
        return self._scheduler.limit

    def set_max_parallel(self, count: int) -> None:
        """Let up to *count* (1..MAX_PARALLEL) jobs run at once. Jobs that start from
        now on obey it; running jobs finish. Workers are only added, never
        taken away while the manager lives: one above the limit idles (a
        worker thread keeps its SFTP channel, so a later raise reuses it)."""
        if not valid_parallel(count):
            raise ValueError(f"parallel transfers must be 1..{MAX_PARALLEL}, not {count!r}")
        if self._shut_down:
            return
        self._ensure_workers(count)
        self._scheduler.set_limit(count)

    def transfer_file(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_path: str,
        dest_path: str,
        direction: TransferDirection = TransferDirection.DOWNLOAD,
        move: bool = False,
        *,
        size: int | None = None,
        dest_listing: _DestListings | None = None,
        if_exists: str = IF_EXISTS_OVERWRITE,
        source_item=None,
        stat_answer=None,
    ) -> TransferJob:
        """Enqueue a single file transfer.

        *size* is the source size when the caller already has it from a
        listing (0 or None: ask the backend); *source_item* is that
        listing entry. *stat_answer* is what ``source_backend.stat`` just
        returned for the path (a batched stat): it stands for that call.
        *dest_listing* shares destination listings across one batch (see
        _DestListings). *if_exists* is what the worker does
        with an existing destination (see ``core.transfer_conflicts``).
        """
        # Get file size for progress
        if size:
            total_bytes = size
        elif stat_answer is not None:
            source_item = stat_answer
            total_bytes = stat_answer.size
        else:
            try:
                source_item = source_backend.stat(source_path)
                total_bytes = source_item.size
            except OSError:
                total_bytes = 0
        fingerprint = source_fingerprint(source_item)
        source_mode, source_mtime = _source_metadata(source_item)

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
            probe = _probe_resumable_temp(dest_backend, dest_path, dest_listing, fingerprint)
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
                        "Auto-resume: found partial %s (%d bytes); will continue from offset %d",
                        tmp_path,
                        tmp_size,
                        tmp_size,
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
            if_exists=if_exists,
            source_fingerprint=fingerprint,
            source_mode=source_mode,
            source_mtime=source_mtime,
        )

        job.source_backend = source_backend
        job.dest_backend = dest_backend
        try:
            from core.operation_journal import start_operation

            job.operation_id = start_operation(
                "move" if move else "transfer",
                source=source_path,
                dest=dest_path,
                backend=getattr(dest_backend, "name", type(dest_backend).__name__),
                bytes_total=total_bytes,
                details={
                    "direction": direction.name,
                    "temp_file": use_temp,
                    "source_backend": _backend_label(source_backend),
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("operation journal start failed: %s", exc)

        self._register(job)

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
        *,
        conflict_plan: ConflictPlan | None = None,
    ) -> list[TransferJob]:
        """Enqueue multiple file transfers to a destination directory.

        Without *conflict_plan* an existing destination file is replaced
        (the scripting semantics, and a sync's confirmed overwrites). With one, every name follows
        the user's answer and every job refuses to replace a file the plan
        did not allow it to replace.
        """
        jobs = []
        dest_listing = _DestListings(dest_backend)
        # One batch instead of an is_dir and a stat round trip per selected
        # path (where the backend can, see prefetch_stats).
        known = prefetch_stats(source_backend, list(source_paths))
        for src_path in source_paths:
            if self._walk_cancelled():
                break
            sep = source_backend.separator()
            filename = src_path.rsplit(sep, 1)[-1] if sep in src_path else src_path
            try:
                filename = _safe_basename(filename, source_backend, dest_backend)
            except ValueError as exc:
                jobs.append(self._unsafe_name_job(source_backend, dest_backend, src_path,
                                                  direction, move, exc))
                continue
            dest_path = safe_join(dest_backend, dest_dir, filename)
            if_exists = IF_EXISTS_OVERWRITE
            if conflict_plan is not None:
                resolved = conflict_plan.resolve(dest_path)
                if resolved is None:
                    log.info("Transfer skipped (destination kept): %s", dest_path)
                    continue
                dest_path, if_exists = resolved

            # Check if source is a directory — if so, recurse
            source_item = known.get(src_path)
            try:
                if source_item is not None and getattr(source_backend, "is_dir_from_stat", False):
                    src_is_dir = _is_dir_from_stat(source_item)
                else:
                    src_is_dir = source_backend.is_dir(src_path)
                refusal = _self_target_refusal(
                    source_backend, src_path, dest_backend, dest_path, is_dir=src_is_dir
                )
                if refusal:
                    jobs.append(
                        self._refused_job(
                            source_backend, dest_backend, src_path, dest_path,
                            direction, move, refusal,
                        )
                    )
                    continue
                if src_is_dir:
                    sub_jobs = self._transfer_directory(
                        source_backend,
                        dest_backend,
                        src_path,
                        dest_path,
                        direction,
                        move=move,
                        dest_listing=dest_listing,
                        conflict_plan=conflict_plan,
                    )
                    jobs.extend(sub_jobs)
                    continue
            except OSError as e:
                log.warning("Could not stat %s, transferring as file: %s", src_path, e)

            prefetched = {}
            if source_item is not None and not isinstance(source_item, OSError):
                prefetched = {"stat_answer": source_item}
            job = self.transfer_file(
                source_backend,
                dest_backend,
                src_path,
                dest_path,
                direction,
                move=move,
                dest_listing=dest_listing,
                if_exists=if_exists,
                **prefetched,
            )
            jobs.append(job)

        # A move of folders that hold no file queues no job, so no job
        # finishes to trigger the cleanup: run it now, or the "move" would
        # leave the source folders behind like a copy. (A background walk
        # does this when its jobs are registered.)
        if (
            move
            and getattr(self._local, "pending", None) is None
            and self._active_count == 0
            and self._queued_count == 0
        ):
            self._cleanup_move_dirs()

        return jobs

    def transfer_files_in_background(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_paths: list[str],
        dest_dir: str,
        direction: TransferDirection = TransferDirection.DOWNLOAD,
        move: bool = False,
        *,
        conflict_plan: ConflictPlan | None = None,
        on_done: Callable[[list[TransferJob]], None] | None = None,
    ) -> None:
        """:meth:`transfer_files` with the walk on a worker thread.

        Walking a remote tree is a round trip per folder (is_dir,
        exists/mkdir, list_dir, the resume probe); on the GUI thread that
        froze the window for as long as the tree took. Here the walk only
        builds the jobs; they are registered and queued on the GUI thread
        once it is done, in the order transfer_files would give them, and
        *on_done* gets them there. :meth:`busy` is True for both backends
        meanwhile. After :meth:`shutdown` a walk's result is dropped, and
        after :meth:`cancel_all` too: then the walk stops listing, *on_done*
        gets no jobs and a move removes no source folder."""
        walk = [source_backend, dest_backend, threading.Event()]
        self._walks.append(walk)

        def run() -> None:
            self._local.pending = []
            self._local.move_dirs = []
            self._local.cancelled = walk[2]
            jobs: list[TransferJob] = []
            try:
                jobs = self.transfer_files(
                    source_backend,
                    dest_backend,
                    source_paths,
                    dest_dir,
                    direction,
                    move,
                    conflict_plan=conflict_plan,
                )
            except Exception:  # noqa: BLE001 - what was built is still queued
                log.exception("Transfer walk of %s failed", source_paths)
            finally:
                payload = (walk, jobs, self._local.pending, self._local.move_dirs, move, on_done)
                self._local.pending = None
                self._local.move_dirs = None
                self._local.cancelled = None
                try:
                    self._walk_done.emit(payload)
                except RuntimeError:  # the manager is gone (app quit)
                    pass

        threading.Thread(target=run, name="axross-transfer-walk", daemon=True).start()

    def _finish_walk(self, payload) -> None:
        """GUI thread: register what a walk built, in its order."""
        walk, jobs, pending, move_dirs, move, on_done = payload
        if walk in self._walks:
            self._walks.remove(walk)
        if self._shut_down:
            return
        if walk[2].is_set():
            # Cancel All ran while the walk was listing: queuing its jobs
            # now would carry out the transfer the user just cancelled.
            log.info("Transfer walk cancelled: %d job(s) not queued", len(pending))
            for job, refusal in pending:
                if refusal is None:
                    # Its operation was opened in the journal when it was
                    # built; close it instead of leaving it open for good.
                    job.status = TransferStatus.CANCELLED
                    job.error_message = "Cancelled"
                    TransferWorker._finish_journal(job, status="cancelled", error="Cancelled")
            jobs = []
        else:
            for job, refusal in pending:
                self._commit(job, refusal)
            self._dirs_to_remove_after_move.extend(move_dirs)
            if move and self._active_count == 0 and self._queued_count == 0:
                self._cleanup_move_dirs()
        if on_done is not None:
            try:
                on_done(jobs)
            except Exception:  # noqa: BLE001 - a caller's hook must not lose the jobs
                log.exception("Transfer walk callback failed")
        self.walk_finished.emit()

    def _register(self, job: TransferJob, refusal: str | None = None) -> None:
        """Register and queue *job* - or, inside a background walk, keep
        it for the GUI thread (see transfer_files_in_background)."""
        pending = getattr(self._local, "pending", None)
        if pending is not None:
            pending.append((job, refusal))
            return
        self._commit(job, refusal)

    def _commit(self, job: TransferJob, refusal: str | None = None) -> None:
        self._jobs[job.job_id] = job
        if refusal is not None:  # a row that never runs
            self.job_added.emit(job)
            self.job_error.emit(job.job_id, refusal)
            return
        self._queued_count += 1
        self.job_added.emit(job)
        self._worker.enqueue(job)

    def _walk_cancelled(self) -> bool:
        """True inside a background walk that Cancel All stopped."""
        event = getattr(self._local, "cancelled", None)
        return event is not None and event.is_set()

    def busy(self, backend: object) -> bool:
        """True while a job or a background walk still uses *backend*."""
        if backend is None:
            return False
        if any(backend is w[0] or backend is w[1] for w in self._walks):
            return True
        return bool(self.jobs_using(backend))

    def _refused_job(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_path: str,
        dest_path: str,
        direction: TransferDirection,
        move: bool,
        reason: str,
        *,
        retryable: bool = True,
    ) -> TransferJob:
        """A job that never runs, so the refusal shows in the transfer list."""
        sep = source_backend.separator()
        if not isinstance(sep, str) or not sep:
            sep = "/"
        job = TransferJob(
            source_path=source_path,
            dest_path=dest_path,
            direction=direction,
            filename=source_path.rsplit(sep, 1)[-1] if sep in source_path else source_path,
            move=move,
            status=TransferStatus.ERROR,
            error_message=reason,
            retryable=retryable,
        )
        job.source_backend = source_backend
        job.dest_backend = dest_backend
        log.warning("Transfer refused: %s -> %s: %s", source_path, dest_path, reason)
        self._register(job, refusal=reason)
        return job

    def _unsafe_name_job(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        shown_path: str,
        direction: TransferDirection,
        move: bool,
        exc: Exception,
    ) -> TransferJob:
        """A failed row for an entry whose name cannot be used on both ends.

        *shown_path* is for the list only: it has no destination, and a
        retry is refused, since the name is what cannot be joined safely.
        """
        return self._refused_job(
            source_backend, dest_backend, shown_path, "", direction, move,
            f"name not usable here, not copied: {exc}",
            retryable=False,
        )

    def _transfer_directory(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_dir: str,
        dest_dir: str,
        direction: TransferDirection,
        move: bool = False,
        dest_listing: _DestListings | None = None,
        conflict_plan: ConflictPlan | None = None,
    ) -> list[TransferJob]:
        """Recursively transfer a directory."""
        jobs = []
        if dest_listing is None:
            dest_listing = _DestListings(dest_backend)

        # Create destination directory
        try:
            if dest_backend.exists(dest_dir):
                if not dest_backend.is_dir(dest_dir):
                    raise OSError(f"destination exists and is not a directory: {dest_dir}")
            else:
                dest_backend.mkdir(dest_dir)
                dest_listing.created(dest_dir)
        except OSError as e:
            log.error("Failed to create directory %s: %s", dest_dir, e)
            self.directory_error.emit(dest_dir, f"mkdir failed: {e}")
            # A row in the transfer list: the folder's files are not copied.
            jobs.append(
                self._refused_job(
                    source_backend, dest_backend, source_dir, dest_dir, direction, move,
                    f"cannot create the folder, its contents were not copied: {e}",
                    retryable=False,
                )
            )
            return jobs

        # List source directory
        try:
            items = source_backend.list_dir(source_dir)
        except OSError as e:
            log.error("Failed to list %s: %s", source_dir, e)
            self.directory_error.emit(source_dir, f"list failed: {e}")
            jobs.append(
                self._refused_job(
                    source_backend, dest_backend, source_dir, dest_dir, direction, move,
                    f"cannot read the folder, its contents were not copied: {e}",
                    retryable=False,
                )
            )
            return jobs

        for item in items:
            if self._walk_cancelled():
                return jobs
            try:
                safe_name = _safe_basename(item.name, source_backend, dest_backend)
                src_path = safe_join(source_backend, source_dir, safe_name)
                dst_path = safe_join(dest_backend, dest_dir, safe_name)
            except ValueError as exc:
                sep = source_backend.separator()
                sep = sep if isinstance(sep, str) and sep else "/"
                shown = f"{source_dir.rstrip(sep)}{sep}{item.name}"
                jobs.append(self._unsafe_name_job(source_backend, dest_backend, shown,
                                                  direction, move, exc))
                continue
            if_exists = IF_EXISTS_OVERWRITE
            if conflict_plan is not None:
                resolved = conflict_plan.resolve(dst_path)
                if resolved is None:
                    log.info("Transfer skipped (destination kept): %s", dst_path)
                    continue
                dst_path, if_exists = resolved

            if item.is_dir and getattr(item, "is_link", False):
                # A symlinked folder (SMB lists it with its target's
                # is_dir): descending copies a folder outside the
                # selection -- a move empties it -- and a link to an
                # ancestor never ends. Shown in the transfer list; the
                # link stays, so a moved folder holding it is kept.
                jobs.append(
                    self._refused_job(
                        source_backend,
                        dest_backend,
                        src_path,
                        dst_path,
                        direction,
                        move,
                        "symbolic link to a folder: not followed "
                        "(copy the folder it points to on its own)",
                    )
                )
                continue
            if item.is_dir:
                sub_jobs = self._transfer_directory(
                    source_backend,
                    dest_backend,
                    src_path,
                    dst_path,
                    direction,
                    move=move,
                    dest_listing=dest_listing,
                    conflict_plan=conflict_plan,
                )
                jobs.extend(sub_jobs)
            else:
                job = self.transfer_file(
                    source_backend,
                    dest_backend,
                    src_path,
                    dst_path,
                    direction,
                    move=move,
                    size=int(getattr(item, "size", 0) or 0),
                    dest_listing=dest_listing,
                    if_exists=if_exists,
                    source_item=item,
                )
                jobs.append(job)

        # For move: schedule source dir removal after all files transferred
        if move:
            pending = getattr(self._local, "move_dirs", None)
            target = pending if pending is not None else self._dirs_to_remove_after_move
            target.append((source_backend, source_dir))

        return jobs

    def cancel_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if job:
            job.cancel_event.set()
            # A job waiting for a busy session can be reported now.
            self._scheduler.wake()
            log.info("Cancel requested for %s", job_id)

    def cancel_all(self) -> None:
        """Cancel every pending or running job and every walk still
        building jobs (see :meth:`transfer_files_in_background`); work that
        has not reached the manager yet sees :attr:`cancel_epoch` change."""
        self._cancel_epoch += 1
        for walk in self._walks:
            walk[2].set()
        for job in self._jobs.values():
            if job.status in (TransferStatus.PENDING, TransferStatus.ACTIVE):
                job.cancel_event.set()
        self._scheduler.wake()

    @property
    def cancel_epoch(self) -> int:
        """How often :meth:`cancel_all` ran: a caller that prepares a
        transfer (a conflict check) notes it first and queues nothing when
        it changed meanwhile."""
        return self._cancel_epoch

    def get_job(self, job_id: str) -> TransferJob | None:
        return self._jobs.get(job_id)

    def all_jobs(self) -> list[TransferJob]:
        return list(self._jobs.values())

    def jobs_using(self, backend: object) -> list[TransferJob]:
        """The pending or running jobs that read from or write to
        *backend*: closing its connection now would fail them."""
        if backend is None:
            return []
        return [
            job
            for job in self._jobs.values()
            if job.status in (TransferStatus.PENDING, TransferStatus.ACTIVE)
            and (job.source_backend is backend or job.dest_backend is backend)
        ]

    def retry_job(self, job_id: str) -> TransferJob | None:
        """Retry a failed or cancelled job, resuming from partial data if possible.

        Once per job: the old row stays in the list as failed, and "Retry
        Failed" would otherwise queue it again on every press. Its retry,
        should that fail as well, can be retried in turn."""
        old_job = self._jobs.get(job_id)
        if not old_job:
            return None
        if old_job.status not in (TransferStatus.ERROR, TransferStatus.CANCELLED):
            return None
        if not old_job.retryable or old_job.retried:
            return None
        old_job.retried = True
        if old_job.move:
            self._reclaim_kept_move_dirs(old_job.source_backend, old_job.source_path)

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
            if_exists=old_job.if_exists,
            source_fingerprint=old_job.source_fingerprint,
            source_mode=old_job.source_mode,
            source_mtime=old_job.source_mtime,
        )
        new_job.source_backend = old_job.source_backend
        new_job.dest_backend = old_job.dest_backend
        try:
            from core.operation_journal import start_operation

            new_job.operation_id = start_operation(
                "move" if new_job.move else "transfer",
                source=new_job.source_path,
                dest=new_job.dest_path,
                backend=getattr(new_job.dest_backend, "name", type(new_job.dest_backend).__name__),
                bytes_total=new_job.total_bytes,
                details={
                    "retry_of": job_id,
                    "resume": True,
                    "source_backend": _backend_label(new_job.source_backend),
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("operation journal retry start failed: %s", exc)

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
        # No failed move is left to retry, so no kept folder will empty.
        self._kept_move_dirs.clear()

    def shutdown(self) -> None:
        self._shut_down = True  # a walk still running registers nothing
        self.cancel_all()
        for worker, _thread in self._pool:
            worker.stop()
        # One budget for all of them: a worker in a backend call that does
        # not notice the cancel holds up the quit no longer than one did.
        deadline = time.monotonic() + 5.0
        for _worker, thread in self._pool:
            thread.quit()
            thread.wait(max(0, int((deadline - time.monotonic()) * 1000)))

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
        # _transfer_directory records a folder after its subfolders
        # (post-order), so the recorded order already is deepest first.
        # Walking it reversed tried every parent while its subfolder still
        # existed and kept the parent as "not empty".
        for backend, dir_path in list(self._dirs_to_remove_after_move):
            try:
                remaining = backend.list_dir(dir_path)
                if not remaining:
                    backend.remove(dir_path)
                    log.info("Move: removed empty source directory %s", dir_path)
                    continue
                log.debug("Move: source directory %s not empty, keeping", dir_path)
            except OSError as e:
                log.warning("Move: could not remove source directory %s: %s", dir_path, e)
            if not any(b is backend and d == dir_path for b, d in self._kept_move_dirs):
                self._kept_move_dirs.append((backend, dir_path))
        self._dirs_to_remove_after_move.clear()

    def _reclaim_kept_move_dirs(self, backend, source_path: str) -> None:
        """Put the kept move folders that hold *source_path* back on the
        cleanup list (a retry of its failed move may empty them)."""
        sep = backend.separator() if backend is not None else "/"
        sep = sep if isinstance(sep, str) and sep else "/"
        above = [
            entry for entry in self._kept_move_dirs
            if entry[0] is backend and source_path.startswith(entry[1].rstrip(sep) + sep)
        ]
        if not above:
            return
        self._kept_move_dirs = [
            e for e in self._kept_move_dirs if not any(e is a for a in above)
        ]
        self._dirs_to_remove_after_move.extend(above)
