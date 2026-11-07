"""Name conflicts of an interactive copy / move, found before any job is queued.

The file-manager commands (F5, F6, drag & drop) ask the user what to do
with every name the transfer would replace. :func:`scan_conflicts` walks
the selection against the destination (no Qt, so it can run off the GUI
thread); a :class:`ConflictPlan` records the answers and tells the
transfer manager, per destination path, whether to skip, rename, overwrite
or overwrite only an older file. Every job queued under a plan carries an
``if_exists`` mode the worker re-checks at run time, so a file that
appears after the prompt is never overwritten silently.

Folders merge: a source folder onto an existing folder is not itself a
conflict; the names inside it are.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from core.path_policy import safe_join, transfer_leaf

if TYPE_CHECKING:
    from core.backend import FileBackend

log = logging.getLogger(__name__)

# ``TransferJob.if_exists`` values.
IF_EXISTS_OVERWRITE = "overwrite"  # replace whatever is there (scripting, sync overwrites)
IF_EXISTS_FAIL = "fail"  # never replace: an existing destination fails the job
IF_EXISTS_NEWER = "newer"  # replace only an older file; otherwise skip the job


class ConflictAction(Enum):
    OVERWRITE = "overwrite"
    SKIP = "skip"
    RENAME = "rename"
    OVERWRITE_IF_NEWER = "newer"


class ScanCancelled(Exception):
    """The conflict scan was cancelled before it finished."""


@dataclass(frozen=True)
class TransferConflict:
    """One destination name the transfer would replace."""

    name: str
    source_path: str
    dest_path: str
    dest_dir: str
    source_is_dir: bool
    dest_is_dir: bool
    source_size: int = 0
    dest_size: int = 0
    source_mtime: float | None = None
    dest_mtime: float | None = None

    @property
    def type_mismatch(self) -> bool:
        """A file against a folder (or the reverse): only skip or rename fit."""
        return self.source_is_dir != self.dest_is_dir


@dataclass
class ConflictScan:
    conflicts: list[TransferConflict] = field(default_factory=list)
    # Names present in each destination folder the scan listed, plus the
    # names this transfer itself creates there; renames pick a name free
    # in here, so a renamed item never lands on another item of the batch.
    taken: dict[str, set[str]] = field(default_factory=dict)


def _mtime(item) -> float | None:
    modified = getattr(item, "modified", None)
    if modified is None:
        return None
    try:
        value = modified.timestamp()
    except (AttributeError, OSError, OverflowError, ValueError):
        return None
    # FileItem's default (the epoch) means "not reported".
    return value if value > 0 else None


def _leaf(backend: FileBackend, path: str) -> str:
    sep = backend.separator()
    return path.rsplit(sep, 1)[-1] if sep in path else path


def unique_name(name: str, taken: set[str], *, is_dir: bool = False) -> str:
    """*name*, or ``stem (N).ext`` with the first N not in *taken*.

    The number goes before the last extension of a file (``a (1).txt``);
    a folder, a dotfile without another dot and a name without an
    extension get it at the end.
    """
    if name not in taken:
        return name
    dot = -1 if is_dir else name.rfind(".")
    if dot <= 0:
        stem, ext = name, ""
    else:
        stem, ext = name[:dot], name[dot:]
    n = 1
    while True:
        candidate = f"{stem} ({n}){ext}"
        if candidate not in taken:
            return candidate
        n += 1


def prefetch_stats(backend, paths: list[str]) -> dict[str, object]:
    """``stat`` of each of *paths* in one batch where the backend offers
    ``stat_many`` (SFTP: pipelined), as {path: FileItem or the OSError
    ``stat`` raises}; ``{}`` otherwise, for fewer than two paths, or when
    the batch fails - the caller then asks per path, as before."""
    stat_many = getattr(backend, "stat_many", None)
    if not callable(stat_many) or len(paths) < 2:
        return {}
    try:
        results = stat_many(list(paths))
    except Exception as exc:  # noqa: BLE001 - per-path calls report it
        log.debug("batched stat of %d paths failed: %s", len(paths), exc)
        return {}
    if len(results) != len(paths):
        return {}
    return dict(zip(paths, results))


def scan_conflicts(
    source_backend: FileBackend,
    dest_backend: FileBackend,
    source_paths: list[str],
    dest_dir: str,
    *,
    cancel: Callable[[], bool] = lambda: False,
) -> ConflictScan:
    """Every name under *dest_dir* the transfer of *source_paths* would hit.

    Lists each destination folder once (and only where a source folder
    merges into an existing one). Entries are visited depth first in name
    order, the order the user is asked in. Raises :class:`OSError` when a
    destination folder cannot be listed - the caller cannot tell then
    what would be replaced - and :class:`ScanCancelled` on *cancel*.
    """
    scan = ConflictScan()

    def listing(folder: str) -> dict:
        if cancel():
            raise ScanCancelled()
        entries = {getattr(i, "name", ""): i for i in dest_backend.list_dir(folder)}
        scan.taken[folder] = set(entries)
        return entries

    def visit(items: list[tuple[str, str, object]], folder: str) -> None:
        existing = listing(folder)
        scan.taken[folder].update(name for name, _path, _item in items)
        for name, src_path, src_item in sorted(items, key=lambda t: t[0]):
            if cancel():
                raise ScanCancelled()
            dest_item = existing.get(name)
            if dest_item is None:
                continue
            src_is_dir = bool(getattr(src_item, "is_dir", False))
            dest_is_dir = bool(getattr(dest_item, "is_dir", False))
            dest_path = safe_join(dest_backend, folder, name)
            if src_is_dir and dest_is_dir:
                visit(_children(source_backend, src_path, dest_backend), dest_path)
                continue
            scan.conflicts.append(
                TransferConflict(
                    name=name,
                    source_path=src_path,
                    dest_path=dest_path,
                    dest_dir=folder,
                    source_is_dir=src_is_dir,
                    dest_is_dir=dest_is_dir,
                    source_size=int(getattr(src_item, "size", 0) or 0),
                    dest_size=int(getattr(dest_item, "size", 0) or 0),
                    source_mtime=_mtime(src_item),
                    dest_mtime=_mtime(dest_item),
                )
            )

    top: list[tuple[str, str, object]] = []
    known = prefetch_stats(source_backend, list(source_paths))
    for path in source_paths:
        try:
            name = transfer_leaf(source_backend, dest_backend, _leaf(source_backend, path))
        except ValueError:
            continue  # transfer_files skips it as well
        try:
            item = known[path] if path in known else source_backend.stat(path)
            if isinstance(item, OSError):
                raise item
        except OSError as exc:
            # transfer_files then copies it as a file.
            log.debug("conflict scan: cannot stat %s: %s", path, exc)
            item = None
        top.append((name, path, item))
    visit(top, dest_dir)
    return scan


def _children(
    backend: FileBackend, folder: str, dest_backend: FileBackend
) -> list[tuple[str, str, object]]:
    out = []
    for item in backend.list_dir(folder):
        name = getattr(item, "name", "")
        if getattr(item, "is_dir", False) and getattr(item, "is_link", False):
            continue  # _transfer_directory does not follow it either
        try:
            out.append(
                (transfer_leaf(backend, dest_backend, name), safe_join(backend, folder, name), item)
            )
        except ValueError:
            continue  # _transfer_directory skips it as well
    return out


class ConflictPlan:
    """The user's answer per conflict: per source and destination path -
    two selected files of one name (``x/a.txt``, ``y/a.txt``) share a
    destination but each has an answer of its own.

    A destination path without an answer was free when the scan looked;
    its job is queued with ``if_exists="fail"``.
    """

    def __init__(self, dest_backend: FileBackend, scan: ConflictScan) -> None:
        self._backend = dest_backend
        self._taken = {folder: set(names) for folder, names in scan.taken.items()}
        #: (source path, destination path) -> (target or None, if_exists)
        self._decisions: dict[tuple[str, str], tuple[str | None, str]] = {}
        #: destination path -> the last answer for it, for a caller that
        #: names no source
        self._by_dest: dict[str, tuple[str | None, str]] = {}

    @classmethod
    def never_replace(cls, dest_backend: FileBackend) -> ConflictPlan:
        """A plan without answers: every job, folder contents included,
        refuses to replace a destination that exists when it runs. For
        copies whose caller established the destination was free (the
        compare window's one-sided rows, a sync's "missing" files)."""
        return cls(dest_backend, ConflictScan())

    @classmethod
    def only_newer(cls, dest_backend: FileBackend, pairs) -> ConflictPlan:
        """A plan for ``(source, destination)`` pairs a comparison found
        newer at the source: each job replaces its destination only when
        that is still older when the job runs (IF_EXISTS_NEWER). The
        comparison is a moment's view - a file edited since must not be
        replaced by the copy that was newer then."""
        plan = cls(dest_backend, ConflictScan())
        for source, dest in pairs:
            plan._decisions[(source, dest)] = (dest, IF_EXISTS_NEWER)
            plan._by_dest[dest] = (dest, IF_EXISTS_NEWER)
        return plan

    def decide(self, conflict: TransferConflict, action: ConflictAction) -> None:
        if action is ConflictAction.SKIP:
            answer: tuple[str | None, str] = (None, "")
        elif action is ConflictAction.RENAME:
            taken = self._taken.setdefault(conflict.dest_dir, set())
            new_name = unique_name(conflict.name, taken, is_dir=conflict.source_is_dir)
            taken.add(new_name)
            answer = (safe_join(self._backend, conflict.dest_dir, new_name), IF_EXISTS_FAIL)
        elif conflict.type_mismatch:
            # Overwriting a folder with a file (or the reverse) is not
            # offered; an "all" answer that reaches one leaves it alone.
            answer = (None, "")
        elif action is ConflictAction.OVERWRITE:
            answer = (conflict.dest_path, IF_EXISTS_OVERWRITE)
        elif action is ConflictAction.OVERWRITE_IF_NEWER:
            src, dst = conflict.source_mtime, conflict.dest_mtime
            if src is not None and dst is not None and src <= dst:
                answer = (None, "")
            else:
                # Unknown or newer: the worker compares again when it runs.
                answer = (conflict.dest_path, IF_EXISTS_NEWER)
        else:  # pragma: no cover - exhaustive over ConflictAction
            raise ValueError(f"unknown conflict action: {action!r}")
        self._decisions[(conflict.source_path, conflict.dest_path)] = answer
        self._by_dest[conflict.dest_path] = answer

    def keeps_inside(self, folder: str) -> bool:
        """True when an answer skips a destination below *folder*: that
        entry's source is not moved, so the source folder is not emptied."""
        sep = self._backend.separator() or "/"
        prefix = folder.rstrip(sep) + sep
        return any(
            target is None and path.startswith(prefix)
            for (_source, path), (target, _mode) in self._decisions.items()
        )

    def resolve(self, dest_path: str, source_path: str | None = None) -> tuple[str, str] | None:
        """``(dest_path, if_exists)`` for the job copying *source_path* to
        *dest_path*, or ``None`` to skip it. Without *source_path* (or for
        a source the scan named differently) the answer for *dest_path*."""
        answer = self._decisions.get((source_path, dest_path)) if source_path is not None \
            else None
        if answer is None:
            answer = self._by_dest.get(dest_path, (dest_path, IF_EXISTS_FAIL))
        target, mode = answer
        if target is None:
            return None
        return target, mode
