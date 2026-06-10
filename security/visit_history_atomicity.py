"""Defense-in-depth lock primitives for visit_history.

The primary fix lives in ``core/visit_history.py``: an
``_HISTORY_RMW_LOCK`` (``threading.RLock``) plus a best-effort
``fcntl.flock`` around the load → mutate → save sequence in
``record_visit``. This module is a *second, independent* enforcement
layer: it exposes the same atomicity contract as a reusable helper so
any future caller that wants to mutate visit history outside of
``record_visit`` (e.g. a future bulk-import or merge-from-peer tool)
cannot accidentally bypass the RMW serialization.

The helper is *not* a drop-in replacement for ``_locked_history_update``
— that function knows where the history file lives. Instead, it
exposes the lower-level primitive (``acquire_history_lock``) so a
parallel module can borrow the same in-process RLock and the same
flock-on-the-same-lockfile semantics. Two callers using
``acquire_history_lock`` from different modules will block on each
other inside the process AND across processes on POSIX, which is the
property the RMW race exploited.

The lockfile path is intentionally derived from the active
``_history_file()`` so test setups that redirect ``HISTORY_FILE`` are
correctly tracked.
"""
from __future__ import annotations

import logging
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover — Windows path
    _fcntl = None

log = logging.getLogger(__name__)


# Shared with core.visit_history via attribute reassignment in
# core.visit_history so a single RLock controls all in-process callers.
# We expose our own RLock here for tests / standalone callers; the
# production wire-up rebinds ``_RLOCK`` to the same object that
# ``core.visit_history._HISTORY_RMW_LOCK`` uses.
_RLOCK: threading.RLock = threading.RLock()


def share_in_process_lock(other_lock: threading.RLock) -> None:
    """Rebind the in-process RLock so this module and another
    coordinate through the SAME primitive. Called by
    ``core.visit_history`` at import to wire the two namespaces
    together. Idempotent — repeated calls with the same object are
    no-ops, and a different lock raises so a silent split is loud.
    """
    global _RLOCK
    if _RLOCK is other_lock:
        return
    # If the module-level RLock was already replaced once, refuse to
    # silently re-replace — that almost certainly indicates two
    # competing wire-ups.
    if _RLOCK is not _MODULE_DEFAULT_LOCK:
        raise RuntimeError(
            "visit_history_atomicity: share_in_process_lock called twice "
            "with different RLocks; this would silently split RMW "
            "serialization between callers."
        )
    _RLOCK = other_lock


_MODULE_DEFAULT_LOCK = _RLOCK


def assert_lock_held(reason: str = "") -> bool:
    """Defense-in-depth tripwire: warn when a visit-history
    mutator runs without the shared RMW lock held by the current thread.

    The primary fix wraps every read-modify-write path
    in ``_locked_history_update``. This helper is the *outer* layer:
    if a future code path lands that calls ``_save`` (or any other
    visit-history mutator) without first acquiring the lock, this
    function surfaces a WARNING tagged with ``reason`` so the
    regression is visible in logs and tests instead of silently losing
    updates. Returns True if the lock is held by the calling thread,
    False otherwise.
    """
    # ``RLock._is_owned`` is a private name but is the stable hook the
    # stdlib (e.g. ``threading.Condition``) itself relies on across
    # CPython versions; we fall through to "assume held" if a future
    # RLock backend drops the hook so the tripwire fails OPEN (don't
    # break callers) while still emitting a debug breadcrumb.
    is_owned = getattr(_RLOCK, "_is_owned", None)
    if is_owned is None:
        log.debug(
            "visit_history_atomicity: assert_lock_held cannot inspect "
            "RLock ownership (%r); tripwire skipped",
            type(_RLOCK).__name__,
        )
        return True
    if is_owned():
        return True
    log.warning(
        "visit_history_atomicity: RMW lock not held by thread %r "
        "during %r — defense-in-depth tripwire; a "
        "writer that bypasses the lock can silently lose updates "
        "from a concurrent record_visit.",
        threading.current_thread().name, reason or "<unknown>",
    )
    return False


@contextmanager
def acquire_history_lock(history_file: Path) -> Iterator[None]:
    """Acquire the visit-history RMW lock around ``history_file``.

    Holds the in-process RLock for the duration of the with-block AND,
    where ``fcntl`` is available, an exclusive ``flock`` on
    ``<history_file>.lock`` so two axross processes sharing the same
    config directory serialize at the OS level too. Callers that fail
    to acquire the flock (e.g. NFS that lies about ``flock`` support)
    still get the in-process RLock, which is the correct subset of
    the failure surface (the original report was about an
    in-process race, the flock is a bonus).
    """
    with _RLOCK:
        lock_fh = None
        try:
            if _fcntl is not None:
                history_file.parent.mkdir(parents=True, exist_ok=True)
                lock_path = history_file.with_name(history_file.name + ".lock")
                lock_fh = open(lock_path, "a+b")
                try:
                    os.chmod(lock_path, 0o600)
                except OSError as exc:
                    log.debug(
                        "visit_history_atomicity: cannot chmod %s: %s",
                        lock_path, exc,
                    )
                _fcntl.flock(lock_fh.fileno(), _fcntl.LOCK_EX)
            yield
        finally:
            if lock_fh is not None:
                try:
                    _fcntl.flock(lock_fh.fileno(), _fcntl.LOCK_UN)
                except OSError as exc:
                    log.debug(
                        "visit_history_atomicity: cannot unlock %s: %s",
                        lock_fh.name, exc,
                    )
                lock_fh.close()
