"""Several transfer jobs at once: the queue the transfer workers share.

The transfer manager used to run one job after the other on a single
worker. For many small files on a slow link most of each job is waiting
for round trips, which jobs side by side hide. :class:`JobScheduler` is
the queue every worker of a :class:`core.transfer_manager.TransferManager`
takes its jobs from:

* at most ``limit`` jobs run at a time (the "Parallel transfers" setting,
  :func:`parallel_transfers`, default 1 = one job after the other);
* jobs start in queue order, skipping only a job that has to wait;
* a session that is not proven safe for two jobs at once
  (:func:`parallel_safe`) carries one job at a time;
* two jobs never write the same destination path at once, and nothing
  reads a path another job writes (a conflict answer such as "do not
  replace" is checked right before the write, and a second job writing
  the same name in between would slip past it).

With the limit at 1 the first eligible job is always the oldest one, so
the order and the work are the same as with the single worker before.
"""

from __future__ import annotations

import itertools
import logging
import threading
from collections import deque
from collections.abc import Callable
from typing import TYPE_CHECKING

from core import open_limits as OL

if TYPE_CHECKING:
    from core.transfer_worker import TransferJob

log = logging.getLogger(__name__)

PARALLEL_SETTING = "parallel_transfers"
DEFAULT_PARALLEL = 1
MAX_PARALLEL = 8


def valid_parallel(value: object) -> bool:
    """A whole number from 1 to MAX_PARALLEL (``True`` is no number here)."""
    return type(value) is int and 1 <= value <= MAX_PARALLEL


def parallel_transfers() -> int:
    """Transfer jobs that may run at the same time (settings.json, default 1)."""
    value = OL.read_setting(PARALLEL_SETTING, DEFAULT_PARALLEL)
    return value if valid_parallel(value) else DEFAULT_PARALLEL


def set_parallel_transfers(value: int) -> None:
    if not valid_parallel(value):
        raise ValueError(
            f"parallel transfers must be a whole number from 1 to {MAX_PARALLEL}, not {value!r}"
        )
    OL.write_setting(PARALLEL_SETTING, value)


#: Backend classes whose one session may carry two transfer jobs at the
#: same time, by (module, class name). Exact classes only: a subclass can
#: change how the I/O works (core.mtp_client.MtpSession is a LocalFS).
#:
#: * LocalFS: every call is its own system call, every open its own file
#:   object; nothing is shared between calls.
#: * RamFsSession: every operation holds the session's RLock
#:   (core/ram_fs.py), a writer commits under it on close.
#: * SSHSession (SFTP): paramiko's SFTPClient is NOT safe for two threads
#:   (sftp.py _send_packet/_read_packet hold no lock, and
#:   SFTPClient._read_response drops an answer that belongs to another
#:   thread's request), but SSHSession gives every thread an SFTP channel
#:   of its own (core/ssh_client.py _get_sftp_client), and each transfer
#:   worker is its own thread.
#: * SmbSession: every open is its own SMB handle (smbclient.open_file);
#:   smbprotocol's Connection is built for threads: sending takes
#:   sequence_lock and the transport's _sock_lock, and one receiver thread
#:   hands each answer to its request by message id.
#: * WebDavSession: requests does not promise that one Session is thread
#:   safe (psf/requests#2766), so the client gives every thread a Session
#:   of its own (core/webdav_client.py _WebDavClient.session).
#: * S3Session: the boto3 low-level client is thread safe; the session
#:   builds it from a boto3 Session of its own (boto3.client() would use
#:   the shared default session, which is not), registers no event hooks
#:   on it and does not replace it after connecting; every open_write is
#:   its own spool, and upload_fileobj makes a TransferManager per call.
#:
#: FtpSession answers for itself (its ``parallel_transfers_safe``
#: property, core/ftp_client.py): safe while every transfer gets a control
#: connection of its own, one job at a time once the server refused a
#: second one. Everything else is serialized per session, SCP in
#: particular.
_PARALLEL_SAFE = frozenset(
    {
        ("core.local_fs", "LocalFS"),
        ("core.ram_fs", "RamFsSession"),
        ("core.ssh_client", "SSHSession"),
        ("core.smb_client", "SmbSession"),
        ("core.webdav_client", "WebDavSession"),
        ("core.s3_client", "S3Session"),
    }
)

#: A class can say so itself in its own body (not inherited), for backends
#: outside this table (tests, extensions): ``parallel_transfers_safe = True``.
#: A property there is an answer of the instance, which can change while
#: the session lives; the scheduler asks it again before every job.
SAFE_ATTRIBUTE = "parallel_transfers_safe"


def _declared(backend: object):
    return type(backend).__dict__.get(SAFE_ATTRIBUTE)


def parallel_safe(backend: object) -> bool:
    """True when *backend*'s session may carry two jobs at once right now."""
    if backend is None:
        return True
    declared = _declared(backend)
    if isinstance(declared, bool):
        return declared
    if isinstance(declared, property):
        try:
            return getattr(backend, SAFE_ATTRIBUTE) is True
        except Exception:  # noqa: BLE001 - an answer that fails is a no
            log.debug("%s could not say whether it is parallel safe", type(backend).__name__)
            return False
    cls = type(backend)
    return (cls.__module__, cls.__qualname__) in _PARALLEL_SAFE


def _always_safe(backend: object) -> bool:
    """Safe for good: a job using it needs no lane for it. A session that
    answers per instance is always in a lane, so that the jobs it carries
    are counted when it turns unsafe in the middle of a run."""
    if backend is None:
        return True
    if isinstance(_declared(backend), property):
        return False
    return parallel_safe(backend)


def _path_key(backend: object, path: str) -> tuple[int, str]:
    # casefold: on a case-insensitive destination two spellings are one
    # file; serializing two that differ costs only time.
    return id(backend), (path or "").casefold()


class _Claim:
    """What a running job holds: sessions, paths it writes, paths it reads."""

    __slots__ = ("sessions", "writes", "reads")

    def __init__(self, sessions: tuple, writes: tuple, reads: tuple) -> None:
        self.sessions = sessions
        self.writes = writes
        self.reads = reads


def _claim_for(job: TransferJob, lane: tuple) -> _Claim:
    src, dst = job.source_backend, job.dest_backend
    writes = [_path_key(dst, job.dest_path)]
    reads = []
    if job.move:
        writes.append(_path_key(src, job.source_path))  # a move deletes it
    else:
        reads.append(_path_key(src, job.source_path))
    return _Claim(lane, tuple(writes), tuple(reads))


class JobScheduler:
    """The queue the transfer workers share (see the module docstring).

    Thread safe. Pending jobs sit in lanes: one lane per set of
    not-thread-safe sessions they use (the empty set for jobs whose
    sessions are all safe), each lane in queue order. A session that
    answers per instance (FTP) is in the lane too; while it answers safe
    its jobs run side by side. A worker takes the oldest job among the
    lanes whose sessions are free, so a job that waits for its session
    does not hold up others and does not hold a worker.
    """

    def __init__(self, limit: int = DEFAULT_PARALLEL) -> None:
        if not valid_parallel(limit):
            raise ValueError(f"limit must be 1..{MAX_PARALLEL}, not {limit!r}")
        self._cond = threading.Condition()
        self._limit = limit
        self._seq = itertools.count()
        self._lanes: dict[tuple, deque] = {}
        self._running = 0
        self._busy_sessions: dict[int, int] = {}
        self._writes: dict[tuple, int] = {}
        self._reads: dict[tuple, int] = {}
        self._claims: dict[int, _Claim | None] = {}

    # -- configuration --------------------------------------------------------

    @property
    def limit(self) -> int:
        return self._limit

    def set_limit(self, limit: int) -> None:
        """Jobs that start from now on obey *limit*; running ones go on."""
        if not valid_parallel(limit):
            raise ValueError(f"limit must be 1..{MAX_PARALLEL}, not {limit!r}")
        with self._cond:
            self._limit = limit
            self._cond.notify_all()

    # -- the queue ------------------------------------------------------------

    def put(self, job: TransferJob) -> None:
        lane = tuple(
            sorted(
                {
                    id(b)
                    for b in (job.source_backend, job.dest_backend)
                    if not _always_safe(b)
                }
            )
        )
        with self._cond:
            self._lanes.setdefault(lane, deque()).append((next(self._seq), job))
            self._cond.notify_all()

    def pending(self) -> int:
        with self._cond:
            return sum(len(lane) for lane in self._lanes.values())

    def running(self) -> int:
        with self._cond:
            return self._running

    def wake(self) -> None:
        """Let waiting workers look again (a job was cancelled, a worker stops)."""
        with self._cond:
            self._cond.notify_all()

    def take(
        self, index: int, stopped: Callable[[], bool]
    ) -> tuple[TransferJob, bool] | None:
        """Block until worker *index* may run a job; ``(job, claimed)``, or
        None once *stopped()* is true. ``claimed`` is False for a cancelled
        job handed out while its session or path is busy: the worker must
        not touch its backends, only report it cancelled."""
        with self._cond:
            while True:
                if stopped():
                    return None
                if index < self._limit and self._running < self._limit:
                    picked = self._pick()
                    if picked is not None:
                        lane, position, claim = picked
                        queue = self._lanes[lane]
                        _, job = queue[position]
                        del queue[position]
                        if not queue:
                            del self._lanes[lane]
                        self._hold(job, claim)
                        return job, claim is not None
                self._cond.wait()

    def done(self, job: TransferJob) -> None:
        """The worker is through with *job*: free what it held."""
        with self._cond:
            claim = self._claims.pop(id(job), None)
            self._running = max(0, self._running - 1)
            if claim is not None:
                self._release(claim)
            self._cond.notify_all()

    # -- internals (called with the condition held) ----------------------------

    def _pick(self) -> tuple[tuple, int, _Claim | None] | None:
        best: tuple[int, tuple, int, _Claim | None] | None = None
        for lane, queue in self._lanes.items():
            candidate = self._candidate(lane, queue)
            if candidate is not None and (best is None or candidate[0] < best[0]):
                best = candidate
        return None if best is None else best[1:]

    def _sessions_free(self, lane: tuple, job: TransferJob) -> bool:
        """No session of *lane* carries a job, or the one that does may
        carry another one right now (asked again: an instance answer can
        change in the middle of a run). Every job of a lane uses the same
        sessions, so *job*'s backends name them."""
        if not lane:
            return True
        backends = {id(b): b for b in (job.source_backend, job.dest_backend) if b is not None}
        return all(
            sid not in self._busy_sessions or (sid in backends and parallel_safe(backends[sid]))
            for sid in lane
        )

    def _candidate(self, lane: tuple, queue: deque):
        sessions_free = bool(queue) and self._sessions_free(lane, queue[0][1])
        for position, (seq, job) in enumerate(queue):
            claim = _claim_for(job, lane) if sessions_free else None
            if claim is not None and self._paths_free(claim):
                return seq, lane, position, claim
            if job.cancel_event.is_set():
                # Waiting for a session or a path: cancelled now, it needs
                # neither - it is reported without touching a backend.
                return seq, lane, position, None
            if not sessions_free:
                # Every job of this lane waits for the same session; only
                # its head is looked at (one cancelled behind it waits its
                # turn, as it would with one worker).
                return None
        return None

    def _paths_free(self, claim: _Claim) -> bool:
        for key in claim.writes:
            if key in self._writes or key in self._reads:
                return False
        return all(key not in self._writes for key in claim.reads)

    def _hold(self, job: TransferJob, claim: _Claim | None) -> None:
        self._running += 1
        self._claims[id(job)] = claim
        if claim is None:
            return
        for sid in claim.sessions:
            self._busy_sessions[sid] = self._busy_sessions.get(sid, 0) + 1
        for key in claim.writes:
            self._writes[key] = self._writes.get(key, 0) + 1
        for key in claim.reads:
            self._reads[key] = self._reads.get(key, 0) + 1

    def _release(self, claim: _Claim) -> None:
        for table, keys in (
            (self._busy_sessions, claim.sessions),
            (self._writes, claim.writes),
            (self._reads, claim.reads),
        ):
            for key in keys:
                count = table.get(key, 0) - 1
                if count > 0:
                    table[key] = count
                else:
                    table.pop(key, None)


__all__ = [
    "DEFAULT_PARALLEL",
    "JobScheduler",
    "MAX_PARALLEL",
    "PARALLEL_SETTING",
    "SAFE_ATTRIBUTE",
    "parallel_safe",
    "parallel_transfers",
    "set_parallel_transfers",
    "valid_parallel",
]
