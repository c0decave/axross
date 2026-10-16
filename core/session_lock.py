"""One lock per session around a protocol handle that is not thread safe.

ftplib, imaplib and poplib pair every reply with the one command they
think is outstanding and read the socket without locking of their own.
A session object is shared - transfer workers, listing workers and the
``core.conn_health`` poll thread all use the same handle - so two
commands in flight at once hand each thread the other's reply.

Backends wrap every method that talks to the server in :func:`serialized`;
anything else that uses the handle (the health probe) takes
:func:`io_lock` for the same session.
"""

from __future__ import annotations

import functools
import threading


def io_lock(session) -> threading.RLock:
    """The session's I/O lock, created on first use.

    ``dict.setdefault`` is atomic, so two threads asking at once still
    get the same lock. Created lazily so a session built without its
    ``__init__`` (tests, subclasses) is covered too."""
    lock = session.__dict__.get("_io_lock")
    if lock is None:
        lock = session.__dict__.setdefault("_io_lock", threading.RLock())
    return lock


def serialized(method):
    """Run ``method`` while holding the session's :func:`io_lock`."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with io_lock(self):
            return method(self, *args, **kwargs)

    return wrapper


def liveness_check(method):
    """For a ``connected``-style probe: run under the lock if it is free;
    if a command is in flight on the handle, the session is evidently
    alive - answer True instead of waiting out a transfer (the caller may
    be the GUI thread) or interleaving a NOOP with it."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        lock = io_lock(self)
        if not lock.acquire(blocking=False):
            return True
        try:
            return method(self, *args, **kwargs)
        finally:
            lock.release()

    return wrapper


__all__ = ["io_lock", "liveness_check", "serialized"]
