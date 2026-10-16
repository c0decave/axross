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
