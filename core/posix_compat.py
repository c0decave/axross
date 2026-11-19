"""POSIX-only os calls, made safe where the platform lacks them.

Windows has no os.fchmod before Python 3.13, no os.geteuid and no
os.statvfs. Calling one from a Qt virtual (a closeEvent that saves the
session) aborted the whole process. Every module goes through here; a
test keeps direct calls out of core/ and ui/.
"""

from __future__ import annotations

import os
import shutil


def fchmod_private(fd: int, mode: int = 0o600) -> None:
    """``os.fchmod(fd, mode)`` where it exists. On Windows a file in the
    user's profile is already private by its ACL; there is no mode to set."""
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(fd, mode)


def effective_uid() -> int | None:
    """The effective user id, or None where the platform has none."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid is not None else None


def disk_usage(path: str) -> tuple[int, int, int]:
    """``(total, used, free)`` bytes of the file system holding *path*, on
    every platform (shutil.disk_usage, not os.statvfs)."""
    usage = shutil.disk_usage(path)
    return usage.total, usage.used, usage.free


def wait_io(read=(), write=(), timeout: float | None = 0.0) -> tuple[list, list]:
    """``select.select(read, write, [], timeout)`` without its limit: select
    refuses a descriptor past 1023 (ValueError) - a busy server's sockets
    go past it, and a hang-up watch took that for a client gone. poll()
    where the platform has it, select() elsewhere (Windows: sockets only,
    and no such limit)."""
    import select

    read, write = list(read), list(write)
    if not hasattr(select, "poll"):
        r, w, _ = select.select(read, write, [], timeout)
        return r, w
    poller = select.poll()
    by_fd: dict[int, object] = {}
    for obj in read:
        fd = obj if isinstance(obj, int) else obj.fileno()
        by_fd[fd] = obj
        poller.register(fd, select.POLLIN | select.POLLPRI)
    for obj in write:
        fd = obj if isinstance(obj, int) else obj.fileno()
        mask = select.POLLOUT
        if fd in by_fd:
            mask |= select.POLLIN | select.POLLPRI
        by_fd.setdefault(fd, obj)
        poller.register(fd, mask)
    events = poller.poll(None if timeout is None else max(0, int(timeout * 1000)))
    readable, writable = [], []
    read_fds = {obj if isinstance(obj, int) else obj.fileno() for obj in read}
    write_fds = {obj if isinstance(obj, int) else obj.fileno() for obj in write}
    for fd, mask in events:
        obj = by_fd.get(fd)
        # A hang-up or error is readable: the read that follows says what.
        if fd in read_fds and mask & (select.POLLIN | select.POLLPRI | select.POLLHUP
                                      | select.POLLERR | select.POLLNVAL):
            readable.append(obj)
        if fd in write_fds and mask & (select.POLLOUT | select.POLLHUP | select.POLLERR):
            writable.append(obj)
    return readable, writable
