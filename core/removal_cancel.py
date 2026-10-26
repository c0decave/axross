"""Cancel a recursive delete between the entries inside a folder.

A delete of one big folder is a single ``backend.remove(path,
recursive=True)`` call. Its tree walk - ``shutil.rmtree`` for a local path
(a kernel-mounted share as well), the SMB, SFTP and FTP backends' own walks
for a remote one - used to run to the end once started, so a Cancel could
only act between the selected top-level entries.

The caller (the pane's delete job) opens a :func:`cancellable_removal`
scope on its worker thread around ``backend.remove``. The tree walks call
:func:`checkpoint` before every entry and :func:`removed` after it (the
SFTP walk checks before every batch of pipelined file removals, and still
reports each file); once the scope's *cancelled* answers true, the next
checkpoint raises
:class:`RemovalCancelled`, which says how many entries inside were removed
so far. Outside a scope both calls do nothing, so every other caller of
``remove`` (transfers, scripts, MCP) behaves as before.

The scope is per thread: the walk runs synchronously on the thread that
called ``remove``, and another thread's delete is never cancelled by it.

A backend whose server removes a whole tree in one request (WebDAV DELETE,
an S3 / Azure prefix delete, the cloud drives, ``rm -rf`` over a shell) has
no entries to check between: Cancel still waits for that request.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat as stat_module
import threading
from collections.abc import Callable, Iterator


class RemovalCancelled(Exception):  # noqa: N818 - a signal, not an error
    """A cancelled recursive delete stopped before *path*.

    Not an ``OSError`` (nor a ``ValueError`` / ``KeyError``) on purpose: the
    backends turn those into their own "Cannot remove ..." errors, and the
    cancel must reach the caller as itself. *removed* is the number of
    entries inside the folder that were removed before it stopped.
    """

    def __init__(self, path: str, removed: int) -> None:
        super().__init__(f"delete cancelled before {path} ({removed} entries removed)")
        self.path = path
        self.removed = removed


class _Scope:
    def __init__(
        self,
        cancelled: Callable[[], bool],
        on_removed: Callable[[int, str], None] | None,
    ) -> None:
        self.cancelled = cancelled
        self.on_removed = on_removed
        self.count = 0


_local = threading.local()


def _scope() -> _Scope | None:
    return getattr(_local, "scope", None)


@contextlib.contextmanager
def cancellable_removal(
    cancelled: Callable[[], bool],
    on_removed: Callable[[int, str], None] | None = None,
) -> Iterator[_Scope]:
    """Make the recursive deletes on this thread stoppable by *cancelled*.

    *on_removed(count, path)* is called after each entry inside a folder
    is gone (for progress). Scopes nest; the innermost decides.
    """
    previous = _scope()
    scope = _Scope(cancelled, on_removed)
    _local.scope = scope
    try:
        yield scope
    finally:
        _local.scope = previous


def checkpoint(path: str) -> None:
    """Called by a tree walk before it removes *path*: raises
    :class:`RemovalCancelled` once the open scope is cancelled."""
    scope = _scope()
    if scope is not None and scope.cancelled():
        raise RemovalCancelled(path, scope.count)


def removed(path: str) -> None:
    """Called by a tree walk after *path* (an entry inside the folder being
    deleted) is gone."""
    scope = _scope()
    if scope is None:
        return
    scope.count += 1
    if scope.on_removed is not None:
        scope.on_removed(scope.count, path)


# -- local trees -----------------------------------------------------------------------

_O_DIR = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
#: The descriptor-based walk needs what shutil.rmtree's symlink-safe variant
#: needs (Linux, macOS, the BSDs). Elsewhere (Windows) a scope changes nothing:
#: shutil.rmtree runs and Cancel acts between the top-level entries.
_FD_WALK = bool(
    _O_DIR
    and _O_NOFOLLOW
    and os.open in os.supports_dir_fd
    and os.unlink in os.supports_dir_fd
    and os.rmdir in os.supports_dir_fd
    and os.scandir in os.supports_fd
)


def _open_dir(name: str, dir_fd: int | None) -> int:
    # O_NOFOLLOW: a folder swapped for a symlink after it was listed is
    # refused (ELOOP / ENOTDIR) instead of followed out of the tree.
    return os.open(name, os.O_RDONLY | _O_DIR | _O_NOFOLLOW | _O_CLOEXEC, dir_fd=dir_fd)


def _entries(fd: int) -> list[tuple[str, bool]]:
    """(name, is a real folder) for every entry of the folder *fd*."""
    out = []
    with os.scandir(fd) as it:
        for entry in it:
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False  # unlink() then reports what it really is
            out.append((entry.name, is_dir))
    return out


def rmtree(path: str) -> None:
    """``shutil.rmtree(path)`` that a :func:`cancellable_removal` scope can stop.

    Without a scope (or without descriptor support) it IS shutil.rmtree.
    Inside one it walks the tree itself, entry by entry, with the same
    guarantees: links are unlinked and never followed, folders are opened
    relative to their parent with O_NOFOLLOW, the first error is raised as
    an OSError, and a top-level link is refused like shutil refuses it.
    The walk keeps its own stack, so any depth works.
    """
    if _scope() is None or not _FD_WALK:
        shutil.rmtree(path)
        return
    st = os.lstat(path)
    if stat_module.S_ISLNK(st.st_mode):
        raise OSError(f"Cannot call rmtree on a symbolic link: {path}")
    top = _open_dir(path, None)
    # One frame per open folder: (fd, its path, its name in the parent,
    # the entries still to remove).
    stack: list[tuple[int, str, str, list[tuple[str, bool]]]] = []
    try:
        stack.append((top, path, "", _entries(top)))
        while stack:
            fd, folder, name, todo = stack[-1]
            if not todo:
                stack.pop()
                if stack:  # the top folder itself goes after the walk
                    os.close(fd)
                    os.rmdir(name, dir_fd=stack[-1][0])
                    removed(folder)
                continue
            child_name, is_dir = todo.pop()
            child = os.path.join(folder, child_name)
            checkpoint(child)
            if is_dir:
                child_fd = _open_dir(child_name, fd)
                try:
                    child_entries = _entries(child_fd)
                except BaseException:
                    os.close(child_fd)
                    raise
                stack.append((child_fd, child, child_name, child_entries))
                continue
            os.unlink(child_name, dir_fd=fd)
            removed(child)
    finally:
        for fd, _folder, _name, _todo in stack:
            os.close(fd)
        if not stack or stack[0][0] != top:
            os.close(top)
    os.rmdir(path)


__all__ = [
    "RemovalCancelled",
    "cancellable_removal",
    "checkpoint",
    "removed",
    "rmtree",
]
