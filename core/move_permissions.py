"""Before a move: can every source be removed from where it is?

A move copies, then deletes the source. When the delete is refused
(EACCES: no write permission on the source's folder, a sticky folder the
user does not own the entry in, a folder below it that may not be emptied)
the copy is already made - the job fails with "move partially completed"
and the same file is in two places. Reported with ``[Errno 13]``.

The check runs before anything is queued, on the scan thread: a list of
the sources that cannot be removed, each with the reason. The window then
asks (move as administrator / copy only / cancel). It looks only at local
files - the permission bits of a remote server say nothing reliable about
what its daemon may do - and it does not change any permission.
"""

from __future__ import annotations

import errno
import logging
import os
import stat as stat_module
from dataclasses import dataclass
from typing import Callable

from core.posix_compat import effective_uid

log = logging.getLogger(__name__)

#: Problems reported at most; the dialog names a few, the count is enough.
MAX_PROBLEMS = 50

#: The errors that say the entry is not there (any more).
_GONE = frozenset({errno.ENOENT, errno.ENOTDIR})


@dataclass(frozen=True)
class Undeletable:
    path: str
    reason: str


def _is_plain_local(backend) -> bool:
    from core.local_fs import LocalFS

    return type(backend) is LocalFS


def _may_remove_from(folder: str, entry_st: os.stat_result | None) -> str | None:
    """Why an entry cannot be removed from *folder*, or None when it can."""
    if not os.access(folder, os.W_OK | os.X_OK):
        return f"no write permission on the folder {folder}"
    try:
        folder_st = os.stat(folder)
    except OSError as exc:
        return f"cannot read the folder {folder}: {exc.strerror or exc}"
    if folder_st.st_mode & stat_module.S_ISVTX and entry_st is not None:
        uid = effective_uid()
        if uid not in (None, 0) and uid not in (folder_st.st_uid, entry_st.st_uid):
            return f"the folder {folder} is sticky and the entry belongs to someone else"
    return None


def undeletable_sources(
    backend,
    paths: list[str],
    *,
    cancel: Callable[[], bool] | None = None,
    limit: int = MAX_PROBLEMS,
    missing: list[str] | None = None,
) -> list[Undeletable]:
    """The entries of *paths* (and below them, for folders) a move could not
    remove afterwards. Empty for a backend other than the local one.

    An entry that is not there any more (removed or renamed since it was
    selected or cut) is no permission problem - moving it as administrator
    would not help: it is appended to *missing* instead, and an entry below
    a folder that vanishes during the walk is left out."""
    if not _is_plain_local(backend):
        return []
    problems: list[Undeletable] = []

    def note(path: str, reason: str) -> bool:
        problems.append(Undeletable(path, reason))
        return len(problems) >= limit

    def walk_error(exc: OSError, top: str) -> None:
        if exc.errno in _GONE:
            return
        note(exc.filename or top, exc.strerror or str(exc))

    for top in paths:
        if cancel is not None and cancel():
            break
        try:
            st = os.lstat(top)
        except OSError as exc:
            if exc.errno in _GONE:
                if missing is not None:
                    missing.append(top)
                continue
            if note(top, exc.strerror or str(exc)):
                break
            continue
        reason = _may_remove_from(os.path.dirname(top.rstrip(os.sep)) or os.sep, st)
        if reason and note(top, reason):
            break
        if not stat_module.S_ISDIR(st.st_mode):
            continue
        # A folder is removed after its contents: each folder below must
        # let its own entries go. os.walk does not follow links (a link is
        # removed itself, not its target).
        full = False
        for root, dirs, files in os.walk(top, onerror=lambda e, t=top: walk_error(e, t)):
            if cancel is not None and cancel():
                full = True
                break
            names = dirs + files
            if not names:
                continue
            if not os.access(root, os.W_OK | os.X_OK):
                if note(root, f"no write permission on the folder {root}"):
                    full = True
                    break
                continue
            try:
                root_st = os.stat(root)
            except OSError:
                continue
            uid = effective_uid()
            if root_st.st_mode & stat_module.S_ISVTX and uid not in (None, 0):
                for name in names:
                    child = os.path.join(root, name)
                    try:
                        child_st = os.lstat(child)
                    except OSError:
                        continue
                    if uid not in (root_st.st_uid, child_st.st_uid):
                        if note(child, f"the folder {root} is sticky and the entry belongs "
                                       "to someone else"):
                            full = True
                            break
                if full:
                    break
            if len(problems) >= limit:
                full = True
                break
        if full or len(problems) >= limit:
            break
    if problems:
        log.info("Move check: %d source(s) cannot be removed afterwards, first %s (%s)",
                 len(problems), problems[0].path, problems[0].reason)
    return problems


__all__ = ["MAX_PROBLEMS", "Undeletable", "undeletable_sources"]
