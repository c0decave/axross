"""Transfer manager — coordinates transfer workers and job queue."""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal

from core import backend_registry
from core.capability_contracts import contract_for_backend
from core.path_policy import safe_join, safe_leaf, transfer_leaf
from core.thread_relay import GuiCall
from core.transfer_conflicts import IF_EXISTS_FAIL, IF_EXISTS_OVERWRITE, prefetch_stats
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

#: Finished (done) jobs kept in the list. Beyond it the oldest go, in
#: chunks of TRIM_SLACK so the dock removes rows in ranges, not one by one:
#: a copy of a million files kept a million jobs (with their backends,
#: events and strings) until "Clear Finished". Failed and cancelled jobs
#: are never dropped - Retry Failed works on them.
MAX_DONE_KEPT = 2000
TRIM_SLACK = 200
#: GUI time one event-loop turn spends registering a walk's jobs.
WALK_COMMIT_SLICE_S = 0.01


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
        self._created: set[str] = set()

    def created(self, folder: str) -> None:
        self._listings[folder] = []
        self._created.add(folder)

    def was_created(self, folder: str) -> bool:
        """True for a folder this batch made (its mkdir succeeded, so it
        was not there and held nothing)."""
        return folder in self._created

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
    # The oldest done jobs left the list (MAX_DONE_KEPT): their ids, oldest
    # first. get_job() no longer knows them.
    jobs_trimmed = pyqtSignal(list)
    # A background walk (transfer_files_in_background) registered its jobs.
    walk_finished = pyqtSignal()
    # A background walk began: Cancel All has something to stop before any
    # job shows (the Transfers dock enables it).
    walk_started = pyqtSignal()

    def __init__(self, parent=None, *, max_parallel: int | None = None):
        """*max_parallel*: jobs that may run at the same time (1..MAX_PARALLEL); None
        reads the "Parallel transfers" setting (core.transfer_pool)."""
        super().__init__(parent)
        if max_parallel is None:
            max_parallel = parallel_transfers()
        elif not valid_parallel(max_parallel):
            raise ValueError(f"max_parallel must be 1..{MAX_PARALLEL}, not {max_parallel!r}")
        self._jobs: dict[str, TransferJob] = {}
        # Done jobs in the order they finished (an ordered set): the
        # oldest are dropped beyond MAX_DONE_KEPT.
        self._done_order: OrderedDict[str, None] = OrderedDict()
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
        # A walk thread hands its result, and a folder it could not create
        # or list, to the GUI thread through these - not through signals of
        # the manager, which is deleted with the main window at quit while a
        # walk may still run (core/thread_relay.py). On the GUI thread they
        # run at once.
        self._walk_done = GuiCall(self._finish_walk)
        # Walks whose jobs are being registered slice by slice (_commit_walk),
        # and whether a job finished meanwhile with nothing else left.
        self._committing = 0
        self._all_finished_owed = False
        # id(walk) -> its jobs registered so far, queued at its end.
        self._held: dict[int, list] = {}
        self._directory_error = GuiCall(self._emit_directory_error)
        # backend -> the backend now used for the same connection, or None
        # (set_backend_resolver): a retry of a job whose session was
        # closed and replaced runs on the replacement.
        self._backend_resolver = None

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
        batch_id: str | None = None,
    ) -> TransferJob:
        """Enqueue a single file transfer.

        *size* is the source size when the caller already has it from a
        listing (0 or None: ask the backend); *source_item* is that
        listing entry. *stat_answer* is what ``source_backend.stat`` just
        returned for the path (a batched stat): it stands for that call.
        *dest_listing* shares destination listings across one batch (see
        _DestListings). *if_exists* is what the worker does
        with an existing destination (see ``core.transfer_conflicts``).
        *batch_id* names the user operation the job is part of (by default
        the one :meth:`transfer_files` is walking on this thread).
        """
        if batch_id is None:
            batch_id = getattr(self._local, "batch_id", "") or ""
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

        # A direct write into a folder this batch just made: no file was
        # there to snapshot for a rollback (see TransferJob.dest_folder_new).
        folder_new = bool(
            not use_temp
            and if_exists == IF_EXISTS_OVERWRITE
            and dest_listing is not None
            and dest_listing.was_created(dest_backend.parent(dest_path))
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
            batch_id=batch_id,
            dest_folder_new=folder_new,
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
                    **({"batch": batch_id} if batch_id else {}),
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("operation journal start failed: %s", exc)

        self._register(job)

        log.debug(
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
        batch_id: str | None = None,
    ) -> list[TransferJob]:
        """Enqueue multiple file transfers to a destination directory.

        Without *conflict_plan* an existing destination file is replaced
        (the scripting semantics, and a sync's confirmed overwrites). With one, every name follows
        the user's answer and every job refuses to replace a file the plan
        did not allow it to replace.

        Every job of the call shares one *batch_id* in the operation journal
        (a new one when none is given), and a move journals each folder it
        creates there: undo reverses the call as one operation, folders
        included (core.undo).
        """
        from core.operation_journal import begin_batch, new_batch_id

        outer_batch = getattr(self._local, "batch_id", "")
        self._local.batch_id = batch_id or outer_batch or new_batch_id()
        if self._local.batch_id != outer_batch:
            # A batch of its own begins (not a folder inside the walk):
            # its marker goes first, so undo knows it holds all of it.
            begin_batch(self._local.batch_id, "move" if move else "transfer",
                        entries=len(source_paths))
        try:
            return self._transfer_files(source_backend, dest_backend, source_paths, dest_dir,
                                        direction, move, conflict_plan=conflict_plan)
        finally:
            self._local.batch_id = outer_batch

    def _transfer_files(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        source_paths: list[str],
        dest_dir: str,
        direction: TransferDirection,
        move: bool,
        *,
        conflict_plan: ConflictPlan | None,
    ) -> list[TransferJob]:
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
                resolved = conflict_plan.resolve(dest_path, src_path)
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
        on_error: Callable[[Exception], None] | None = None,
        batch_id: str | None = None,
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
        self._walk_in_background(
            source_backend, dest_backend, move, on_done, on_error,
            lambda: self.transfer_files(
                source_backend,
                dest_backend,
                source_paths,
                dest_dir,
                direction,
                move,
                conflict_plan=conflict_plan,
                batch_id=batch_id,
            ),
            what=source_paths,
        )

    def transfer_pairs_in_background(
        self,
        source_backend: FileBackend,
        dest_backend: FileBackend,
        pairs: list[tuple[str, str]],
        direction: TransferDirection = TransferDirection.DOWNLOAD,
        move: bool = False,
        *,
        on_done: Callable[[list[TransferJob]], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
        batch_id: str | None = None,
    ) -> None:
        """One file job per ``(source, dest)`` pair, each refusing an
        existing destination, built on a worker thread - the undo of a
        batch puts every file back at its own recorded path (core.undo).

        Before a job is built every destination is checked: one that is
        there again fails the whole call with FileExistsError and nothing
        is queued (an undo that overwrote a file would trade one loss for
        another). The folder each destination belongs in is made first,
        with any missing above it: the move removed the folders it emptied.
        """
        from core.operation_journal import begin_batch, new_batch_id
        from core.trash import recreate_parent_folders

        def build() -> list[TransferJob]:
            taken = [dest for _src, dest in pairs if dest_backend.exists(dest)]
            if taken:
                more = f" and {len(taken) - 1} more" if len(taken) > 1 else ""
                raise FileExistsError(
                    f"{taken[0]}{more} exist(s) again - the undo would overwrite it. "
                    "Move or rename it first."
                )
            outer_batch = getattr(self._local, "batch_id", "")
            self._local.batch_id = batch_id or new_batch_id()
            begin_batch(self._local.batch_id, "move" if move else "transfer",
                        entries=len(pairs))
            jobs: list[TransferJob] = []
            try:
                for src, dest in pairs:
                    if self._walk_cancelled():
                        break
                    recreate_parent_folders(dest_backend, dest)
                    jobs.append(self.transfer_file(
                        source_backend, dest_backend, src, dest, direction, move=move,
                        if_exists=IF_EXISTS_FAIL,
                    ))
            finally:
                self._local.batch_id = outer_batch
            return jobs

        self._walk_in_background(source_backend, dest_backend, move, on_done, on_error,
                                 build, what=[src for src, _dest in pairs][:3])

    def _walk_in_background(self, source_backend, dest_backend, move: bool, on_done,
                            on_error, build: Callable[[], list[TransferJob]], *,
                            what) -> None:
        """Run *build* (it queues jobs through transfer_file) on a worker
        thread; its jobs are registered on the GUI thread (_finish_walk)."""
        walk = [source_backend, dest_backend, threading.Event()]
        self._walks.append(walk)
        self.walk_started.emit()

        def run() -> None:
            self._local.pending = []
            self._local.move_dirs = []
            self._local.cancelled = walk[2]
            jobs: list[TransferJob] = []
            error: Exception | None = None
            try:
                jobs = build()
            except Exception as exc:  # noqa: BLE001 - what was built is still queued
                log.exception("Transfer walk of %s failed", what)
                error = exc
            finally:
                payload = (walk, jobs, self._local.pending, self._local.move_dirs, move, on_done,
                           error, on_error)
                self._local.pending = None
                self._local.move_dirs = None
                self._local.cancelled = None
                self._walk_done(payload)

        threading.Thread(target=run, name="axross-transfer-walk", daemon=True).start()

    def _emit_directory_error(self, path: str, reason: str) -> None:
        self.directory_error.emit(path, reason)

    def _finish_walk(self, payload) -> None:
        """GUI thread: register what a walk built, in its order.

        A big walk is registered in slices of about WALK_COMMIT_SLICE_S,
        one per event-loop turn (:meth:`_commit_walk`): 5 000 jobs at once
        froze the window for 0.4 s. The walk counts as running (busy(),
        unfinished()) until its last job is registered, and all_finished
        waits for that too."""
        walk, jobs, pending, move_dirs, move, on_done, error, on_error = payload
        if self._shut_down:
            if walk in self._walks:
                self._walks.remove(walk)
            return
        if walk[2].is_set():
            self._end_walk(payload, cancelled_from=0)
            return
        self._commit_walk(payload, 0)

    def _commit_walk(self, payload, start: int) -> None:
        """Register the walk's jobs from *start* on, until the slice is used
        up (then again on the next event-loop turn) or all are in."""
        walk, _jobs, pending, *_rest = payload
        if self._shut_down:
            if walk in self._walks:
                self._walks.remove(walk)
            self._committing = max(0, self._committing - (1 if start else 0))
            self._held.pop(id(walk), None)
            return
        if walk[2].is_set():
            # Cancel All between two slices: the rest is not queued.
            self._end_walk(payload, cancelled_from=start)
            return
        if not start:
            self._committing += 1
        hold = self._held.setdefault(id(walk), [])
        deadline = time.monotonic() + WALK_COMMIT_SLICE_S
        index = start
        while index < len(pending):
            job, refusal = pending[index]
            self._commit(job, refusal, hold=hold)
            index += 1
            if index < len(pending) and not index % 16 and time.monotonic() > deadline:
                QTimer.singleShot(0, lambda: self._commit_walk(payload, index))
                return
        self._end_walk(payload)

    def _end_walk(self, payload, *, cancelled_from: int | None = None) -> None:
        """The walk is registered (or cancelled from job *cancelled_from*
        on): its folders, the callbacks, walk_finished."""
        walk, jobs, pending, move_dirs, move, on_done, error, on_error = payload
        if walk in self._walks:
            self._walks.remove(walk)
        # Only now do the workers get the walk's jobs, all at once: a caller's
        # on_done (below) still sees them before any of them has ended, as
        # when they were registered in one go (main_window tracks the tags
        # of moved files there). Cancelled meanwhile, they end as cancelled.
        self._release_held(walk)
        if cancelled_from is not None:
            if cancelled_from:
                self._committing = max(0, self._committing - 1)
            # Cancel All ran while the walk was listing: queuing its jobs
            # now would carry out the transfer the user just cancelled.
            rest = pending[cancelled_from:]
            log.info("Transfer walk cancelled: %d job(s) not queued", len(rest))
            for job, refusal in rest:
                if refusal is None:
                    # Its operation was opened in the journal when it was
                    # built; close it instead of leaving it open for good.
                    job.status = TransferStatus.CANCELLED
                    job.error_message = "Cancelled"
                    TransferWorker._finish_journal(job, status="cancelled", error="Cancelled")
            jobs = []
        else:
            self._committing = max(0, self._committing - 1)  # _commit_walk counted it
            if error is not None:
                # The walk stopped half way: what it built is queued, and
                # on_done gets those jobs - not none, as if nothing ran.
                jobs = [job for job, _refusal in pending]
            self._dirs_to_remove_after_move.extend(move_dirs)
            if move and self._active_count == 0 and self._queued_count == 0:
                self._cleanup_move_dirs()
        if self._all_finished_owed and not self._committing:
            self._all_finished_owed = False
            if self._active_count == 0 and self._queued_count == 0:
                self._cleanup_move_dirs()
                self.all_finished.emit()
        # on_error first: a caller learns the walk was partial before it
        # acts on the jobs on_done hands it.
        if error is not None and on_error is not None and not walk[2].is_set():
            try:
                on_error(error)
            except Exception:  # noqa: BLE001
                log.exception("Transfer walk error callback failed")
        if on_done is not None:
            try:
                on_done(jobs)
            except Exception:  # noqa: BLE001 - a caller's hook must not lose the jobs
                log.exception("Transfer walk callback failed")
        self.walk_finished.emit()

    def _queue_empty(self) -> bool:
        """Nothing running or waiting - and no walk half registered (its
        next slice would queue more); then all_finished is owed to the end
        of that walk."""
        if self._active_count or self._queued_count:
            return False
        if self._committing:
            self._all_finished_owed = True
            return False
        return True

    def _register(self, job: TransferJob, refusal: str | None = None) -> None:
        """Register and queue *job* - or, inside a background walk, keep
        it for the GUI thread (see transfer_files_in_background)."""
        pending = getattr(self._local, "pending", None)
        if pending is not None:
            pending.append((job, refusal))
            return
        self._commit(job, refusal)

    def _commit(self, job: TransferJob, refusal: str | None = None, *, hold=None) -> None:
        """Register *job*; queue it for the workers now, or - *hold*, a
        list - append it there for the caller to queue later."""
        self._jobs[job.job_id] = job
        if refusal is not None:  # a row that never runs
            self.job_added.emit(job)
            self.job_error.emit(job.job_id, refusal)
            return
        self._queued_count += 1
        self.job_added.emit(job)
        if hold is not None:
            hold.append(job)
        else:
            self._worker.enqueue(job)

    def _release_held(self, walk) -> None:
        """Queue the jobs a walk registered slice by slice (see _commit_walk)."""
        held = self._held.pop(id(walk), None)
        if not held:
            return
        many = getattr(self._worker, "enqueue_many", None)
        if callable(many):
            many(held)
        else:
            for job in held:
                self._worker.enqueue(job)

    def _walk_cancelled(self) -> bool:
        """True inside a background walk that Cancel All stopped."""
        event = getattr(self._local, "cancelled", None)
        return event is not None and event.is_set()

    def unfinished(self) -> int:
        """Transfers running or waiting, and folder walks still building
        jobs: what quitting now would cancel."""
        return self._active_count + self._queued_count + len(getattr(self, "_walks", ()))

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
        error: BaseException | None = None,
        context: str = "",
    ) -> TransferJob:
        """A job that never runs, so the refusal shows in the transfer list.

        *error* is the exception behind *reason*: the Transfers panel then
        says it as ``core.user_errors.describe()`` does, in the interface
        language, with *context* ("mkdir" / "list", see
        ``models.transfer_model.REFUSAL_CONTEXTS``) in front; *reason*
        stays the raw text for the tooltip and the log."""
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
        if error is not None:
            job.error = error.with_traceback(None)
        # Not a field of TransferJob: only refused folder rows carry it.
        job.error_context = context
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
                if move:
                    self._journal_move_folder(source_backend, dest_backend, source_dir,
                                              dest_dir, direction)
        except Exception as e:  # noqa: BLE001 - a library error too: a refused row, not a stopped walk
            log.error("Failed to create directory %s: %s", dest_dir, e)
            self._directory_error(dest_dir, f"mkdir failed: {e}")
            # A row in the transfer list: the folder's files are not copied.
            jobs.append(
                self._refused_job(
                    source_backend, dest_backend, source_dir, dest_dir, direction, move,
                    f"cannot create the folder, its contents were not copied: {e}",
                    retryable=False,
                    error=e,
                    context="mkdir",
                )
            )
            return jobs

        # List source directory
        try:
            items = source_backend.list_dir(source_dir)
        except Exception as e:  # noqa: BLE001 - a library error too: a refused row, not a stopped walk
            log.error("Failed to list %s: %s", source_dir, e)
            self._directory_error(source_dir, f"list failed: {e}")
            jobs.append(
                self._refused_job(
                    source_backend, dest_backend, source_dir, dest_dir, direction, move,
                    f"cannot read the folder, its contents were not copied: {e}",
                    retryable=False,
                    error=e,
                    context="list",
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
                resolved = conflict_plan.resolve(dst_path, src_path)
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

    def _journal_move_folder(self, source_backend, dest_backend, source_dir: str,
                             dest_dir: str, direction: TransferDirection) -> None:
        """Journal a folder a move created at the destination (and removes
        at the source once it is empty), in the move's batch: undoing the
        move removes it again when it is empty and makes the source folder
        again - the files' entries alone brought back the files, not the
        folders."""
        try:
            from core.operation_journal import finish_operation, new_operation_id

            batch = getattr(self._local, "batch_id", "") or ""
            finish_operation(
                new_operation_id(),
                "move_folder",
                status="done",
                source=source_dir,
                dest=dest_dir,
                backend=_backend_label(dest_backend),
                details={
                    "direction": direction.name,
                    "source_backend": _backend_label(source_backend),
                    **({"batch": batch} if batch else {}),
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("operation journal of folder %s failed: %s", dest_dir, exc)

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

    def set_backend_resolver(self, resolver) -> None:
        """*resolver(backend)* names the backend now used for the same
        connection as *backend* (the pane's after a reconnect), or None.
        retry_job asks it for a backend that is no longer connected."""
        self._backend_resolver = resolver

    def rebind_backend(self, old: object, new: object) -> int:
        """Jobs that still wait for *old* - queued and not started, or
        failed / cancelled and not retried yet - use *new* instead: *old*
        was a session that dropped and *new* the one that replaced it.
        The jobs held the dead session, so they failed again, and so did
        Retry, which copies a job's backends. Returns how many jobs moved."""
        if old is None or new is None or old is new:
            return 0
        moved = 0
        for job in list(self._jobs.values()):
            if job.status == TransferStatus.PENDING:
                pass
            elif job.status in (TransferStatus.ERROR, TransferStatus.CANCELLED):
                if job.retried:
                    continue
            else:
                continue  # running or done: nothing to move
            changed = False
            if job.source_backend is old:
                job.source_backend = new
                changed = True
            if job.dest_backend is old:
                job.dest_backend = new
                changed = True
            moved += changed
        if moved:
            log.info("%d transfer(s) now use the reconnected %s", moved,
                     getattr(new, "name", type(new).__name__))
        return moved

    def _current_backend(self, backend: object) -> object:
        """*backend*, or the one the resolver names for the same connection
        (the session a pane uses now, after a reconnect).

        The resolver's session wins without asking *backend* whether it is
        still connected: retry_job runs on the GUI thread, and on SMB
        ``connected`` lists the share - on a dead pooled connection that
        redialled the replaced session (up to a minute's connect time-out
        per job and side), and when the server was back it bound the retry
        to the session the pane had retired and the connection manager
        closes under it. Nothing here touches the network."""
        resolver = self._backend_resolver
        if backend is None or resolver is None:
            return backend
        try:
            replacement = resolver(backend)
        except Exception as exc:  # noqa: BLE001 - keep the job's own backend
            log.debug("Transfer retry: backend lookup failed: %s", exc)
            return backend
        if replacement is None or replacement is backend:
            return backend
        return replacement

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
            batch_id=old_job.batch_id,
        )
        # The session the job ran on may have dropped and been replaced
        # (a reconnect): the retry runs on the one in use now.
        new_job.source_backend = self._current_backend(old_job.source_backend)
        new_job.dest_backend = self._current_backend(old_job.dest_backend)
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
                    "direction": new_job.direction.name,
                    "source_backend": _backend_label(new_job.source_backend),
                    **({"batch": new_job.batch_id} if new_job.batch_id else {}),
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

    @staticmethod
    def partial_kept(job: TransferJob) -> str:
        """The hidden partial file (``.<name>.part-…``) a failed or
        cancelled *job* may have left for a resume, or "".

        The worker keeps it where the destination really appends
        (core.server_ops.write_traits ``real_append``) and bytes had
        arrived: Retry then continues it - only while the source is
        unchanged (its fingerprint is in the name). Said in the status
        line, and removed with the job by :meth:`clear_finished`."""
        if job.status not in (TransferStatus.ERROR, TransferStatus.CANCELLED):
            return ""
        if not (job.use_temp_file and job.temp_path and job.dest_backend is not None):
            return ""
        if job.transferred_bytes <= 0 and not job.resume:
            return ""
        from core.server_ops import write_traits

        try:
            if not write_traits(job.dest_backend).real_append:
                return ""
        except Exception:  # noqa: BLE001 - unknown traits: assume it may be there
            pass
        return job.temp_path

    def clear_finished(self) -> None:
        """Remove completed/errored/cancelled jobs - and the partial files
        the failed and cancelled ones kept for a resume (:meth:`partial_kept`):
        once the row is gone nothing could resume them, and the hidden
        ``.name.part-…`` stayed behind with its bytes (UX review round 6)."""
        to_remove = [
            jid
            for jid, j in self._jobs.items()
            if j.status in (TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED)
        ]
        partials = [(self._jobs[jid].dest_backend, path) for jid in to_remove
                    if (path := self.partial_kept(self._jobs[jid]))]
        for jid in to_remove:
            del self._jobs[jid]
        # A retry still queued or running continues the same partial.
        in_use = {j.temp_path for j in self._jobs.values() if j.temp_path}
        self._remove_partials([(b, p) for b, p in partials if p not in in_use])
        self._done_order.clear()
        # No failed move is left to retry, so no kept folder will empty.
        self._kept_move_dirs.clear()

    @staticmethod
    def _remove_partials(partials: list) -> threading.Thread | None:
        """Remove each kept partial ``(backend, path)`` off the GUI thread
        (a remote one is a round trip each). Only names the worker gives a
        partial (core.transfer_worker.PARTIAL_MARK) are touched."""
        from core.transfer_worker import PARTIAL_MARK

        chosen = []
        for backend, path in partials:
            name = path.replace("\\", "/").rsplit("/", 1)[-1]
            if backend is not None and name.startswith(".") and PARTIAL_MARK in name:
                chosen.append((backend, path))
        if not chosen:
            return None

        def run() -> None:
            for backend, path in chosen:
                try:
                    if backend.exists(path):
                        backend.remove(path)
                        log.info("Removed the partial file of a cleared transfer: %s", path)
                except Exception as exc:  # noqa: BLE001 - reported, the rest go on
                    log.warning("Could not remove the partial file %s: %s", path, exc)

        thread = threading.Thread(target=run, name="axross-clear-partials", daemon=True)
        thread.start()
        return thread

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
        # A worker still stuck in a backend call (a dead FTP link, a hung
        # NFS server) after the budget: its QThread, destroyed with the
        # manager while it runs, aborted the whole process at quit
        # ("QThread: Destroyed while thread is still running"). Handed over
        # instead, with the worker it runs, to end with the process.
        from core.thread_lifetime import detach_running_thread

        for worker, thread in self._pool:
            if detach_running_thread(thread, keep=(worker,)):
                log.warning("A transfer worker is still in a backend call at shutdown; "
                            "leaving it to end with the process")

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
            log.debug("Transfer started: %s (%s)", job.filename, job_id)
        self.job_updated.emit(job_id)

    def _on_job_finished(self, job_id: str) -> None:
        self._active_count = max(0, self._active_count - 1)
        job = self._jobs.get(job_id)
        if job:
            job.status = TransferStatus.DONE
            self._done_order[job_id] = None
            log.debug("Transfer finished: %s (%s)", job.filename, job_id)
        self.job_finished.emit(job_id)
        if self._queue_empty():
            self._cleanup_move_dirs()
            self.all_finished.emit()
        self._trim_done()

    def _trim_done(self) -> None:
        """Drop the oldest done jobs once more than MAX_DONE_KEPT +
        TRIM_SLACK are kept, down to MAX_DONE_KEPT."""
        if len(self._done_order) <= MAX_DONE_KEPT + TRIM_SLACK:
            return
        dropped: list[str] = []
        while len(self._done_order) > MAX_DONE_KEPT:
            job_id, _ = self._done_order.popitem(last=False)
            job = self._jobs.get(job_id)
            if job is not None and job.status == TransferStatus.DONE:
                del self._jobs[job_id]
                dropped.append(job_id)
        if dropped:
            log.debug("Transfer list: %d finished job(s) dropped, %d kept",
                      len(dropped), len(self._done_order))
            self.jobs_trimmed.emit(dropped)

    def _on_job_error(self, job_id: str, error: str) -> None:
        self._active_count = max(0, self._active_count - 1)
        job = self._jobs.get(job_id)
        if job:
            job.error_message = error
            log.error("Transfer failed: %s (%s): %s", job.filename, job_id, error)
        self.job_error.emit(job_id, error)
        if self._queue_empty():
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
