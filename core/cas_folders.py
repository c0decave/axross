"""Identical folders in the CAS index (the Duplicate Finder's folder mode).

Feedback: find folders that are the same - recursively the same relative
paths and names, each file with the same hash; the folder's own name may
differ. The index (core.cas) holds files only, so a folder's content is
read from the rows below it: its *signature* is the sorted list of
``(path relative to the folder, algorithm, hash)`` of every file below.
Two folders with one signature are copies.

Only folders inside a completed scan's root count. A folder above the
scanned part would show only what was scanned of it and look like a copy
of a smaller one. Of nested matches only the outermost pair is listed:
when ``a`` and ``b`` match, ``a/x`` and ``b/x`` match too and say nothing
new.

The index is a claim about the past. Moving a folder to the trash checks
the live tree first (:func:`trash_identical_folder`): the folder holds
exactly the files of the index, each still with its indexed content, and
the kept folder holds a separate, intact copy of every one of them.
Empty sub-folders are not in the index and are not compared.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field

from core import cas as CAS

log = logging.getLogger(__name__)

#: Folders compared at most (one signature each): a huge index stays bounded.
MAX_FOLDERS = 200_000


@dataclass(frozen=True)
class FolderCopy:
    """One folder of an identical-folder group."""

    backend_id: str
    path: str
    files: int
    size: int


@dataclass
class _Folder:
    pairs: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    size: int = 0


def _sep(path: str) -> str:
    return "\\" if "\\" in path and "/" not in path else "/"


def _ancestors(path: str, root: str):
    """The folders from *path*'s parent up to *root* (inclusive), each with
    the file's path relative to it."""
    sep = _sep(path)
    root = root.rstrip(sep) or sep
    current = path
    while True:
        cut = current.rfind(sep)
        if cut <= 0 and current.startswith(sep):
            parent = sep
        elif cut < 0:
            return
        else:
            parent = current[:cut]
        if not (parent == root or parent.startswith(root.rstrip(sep) + sep) or root == sep):
            return
        yield parent, path[len(parent.rstrip(sep)) + 1:]
        if parent in (root, sep):
            return
        current = parent


def _scan_roots(db_path) -> dict[str, list[str]]:
    roots: dict[str, list[str]] = defaultdict(list)
    for scan in CAS.list_scans(db_path):
        if scan.status == CAS.SCAN_COMPLETE:
            roots[scan.backend_id].append(scan.root)
    return roots


def _root_of(path: str, roots: list[str]) -> str | None:
    """The outermost completed scan root holding *path*."""
    best = None
    for root in roots:
        sep = _sep(root)
        stem = root.rstrip(sep) or sep
        if path.startswith(stem + sep) or stem == sep:
            if best is None or len(stem) < len(best):
                best = stem
    return best


def identical_folders(
    db_path=None,
    algorithm: str = "sha256",
    *,
    folder: str | None = None,
) -> list[list[tuple[FolderCopy, list]]]:
    """Groups of 2+ folders with the same content, largest first. Each
    member is ``(FolderCopy, entries)``, *entries* its files' CasEntry rows
    (for the live check before a removal). *folder* keeps only folders
    strictly inside it."""
    roots = _scan_roots(db_path)
    folders: dict[tuple[str, str], _Folder] = {}
    for entry in _rows(db_path, algorithm):
        if CAS._in_trash(entry.path):
            continue
        root = _root_of(entry.path, roots.get(entry.backend_id, []))
        if root is None:
            continue
        for parent, rel in _ancestors(entry.path, root):
            key = (entry.backend_id, parent)
            data = folders.get(key)
            if data is None:
                if len(folders) >= MAX_FOLDERS:
                    continue
                data = folders[key] = _Folder()
            data.pairs.append((rel.replace("\\", "/"), entry.algorithm, entry.value))
            data.entries.append(entry)
            data.size += int(entry.size or 0)
    by_signature: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for key, data in folders.items():
        if folder is not None:
            sep = _sep(key[1])
            if not key[1].startswith(folder.rstrip(sep) + sep):
                continue
        digest = hashlib.sha256()
        for rel, algo, value in sorted(data.pairs):
            digest.update(f"{rel}\0{algo}\0{value}\n".encode("utf-8", "surrogatepass"))
        by_signature[digest.hexdigest()].append(key)
    groups = {sig: keys for sig, keys in by_signature.items() if len(keys) >= 2}
    # A group whose folders' parents form a group of the same size is the
    # inside of a larger match.
    member_sets = {frozenset(keys) for keys in groups.values()}
    out = []
    for keys in groups.values():
        parents = frozenset((b, _parent(p)) for b, p in keys)
        if len(parents) == len(keys) and parents in member_sets:
            continue
        members = []
        for key in sorted(keys):
            data = folders[key]
            members.append((FolderCopy(key[0], key[1], len(data.entries), data.size),
                            list(data.entries)))
        out.append(members)
    out.sort(key=lambda g: (-g[0][0].size, g[0][0].path))
    return out


def _parent(path: str) -> str:
    sep = _sep(path)
    cut = path.rstrip(sep).rfind(sep)
    return sep if cut <= 0 else path[:cut]


def _rows(db_path, algorithm: str):
    with CAS._connect(db_path) as conn:
        cur = conn.execute(
            f"SELECT {CAS._ENTRY_COLUMNS} FROM cas WHERE algorithm=?", (algorithm.lower(),))
        for row in cur:
            yield CAS._row_to_entry(row)


def _walk(backend, top: str, cancel) -> tuple[dict[str, int], list[str]] | None:
    """Every file below *top* as ``rel -> size``, and what disqualifies the
    tree (links, special entries); None when cancelled."""
    files: dict[str, int] = {}
    problems: list[str] = []
    stack = [(top, "")]
    while stack:
        if cancel is not None and cancel():
            return None
        path, rel = stack.pop()
        for item in backend.list_dir(path):
            if item.name in (".", ".."):
                continue
            child = backend.join(path, item.name)
            child_rel = f"{rel}/{item.name}" if rel else item.name
            if getattr(item, "is_link", False):
                problems.append(f"{child_rel} is a link")
            elif item.is_dir:
                stack.append((child, child_rel))
            else:
                files[child_rel] = int(item.size or 0)
    return files, problems


@dataclass
class FolderOutcome:
    removed: bool
    reason: str = ""


def trash_identical_folder(
    backends,
    remove: tuple[FolderCopy, list],
    keep: tuple[FolderCopy, list],
    *,
    db_path=None,
    trash_root: str | None = None,
    cancel=None,
) -> FolderOutcome:
    """Move the folder *remove* to the axross trash if, right now, it holds
    exactly the indexed files, each with its indexed content, and *keep*
    holds a separate, intact copy of each. Anything else refuses."""
    from core import trash as T

    gone, gone_entries = remove
    kept, kept_entries = keep
    backend = backends.get(gone.backend_id)
    if backend is None or backends.get(kept.backend_id) is None:
        return FolderOutcome(False, "a backend of the group is not connected")
    if gone.backend_id == kept.backend_id and gone.path == kept.path:
        return FolderOutcome(False, "the folder to keep is the one to remove")
    try:
        walked = _walk(backend, gone.path, cancel)
    except OSError as exc:
        return FolderOutcome(False, f"cannot list {gone.path}: {exc}")
    if walked is None:
        return FolderOutcome(False, "cancelled")
    files, problems = walked
    if problems:
        return FolderOutcome(False, problems[0])

    def rel(entry, top):
        sep = _sep(entry.path)
        return entry.path[len(top.rstrip(sep)) + 1:].replace("\\", "/")

    indexed = {rel(e, gone.path): e for e in gone_entries}
    if set(files) != set(indexed):
        extra = sorted(set(files) ^ set(indexed))
        return FolderOutcome(False, f"the folder changed since indexing ({extra[0]}) - "
                                    "rebuild the index")
    partners = {rel(e, kept.path): e for e in kept_entries}
    for name, entry in sorted(indexed.items()):
        if cancel is not None and cancel():
            return FolderOutcome(False, "cancelled")
        partner = partners.get(name)
        if partner is None or not CAS._still_holds(backend, entry):
            return FolderOutcome(False, f"{name} changed since indexing - rebuild the index")
        if not CAS._is_genuine_copy(backends, partner, [entry]):
            return FolderOutcome(False, f"no verified copy of {name} in {kept.path}")
    try:
        T.trash(backend, gone.path, root=trash_root)
    except OSError as exc:
        return FolderOutcome(False, f"trash failed: {exc}")
    for entry in gone_entries:
        try:
            CAS.remove(db_path, entry.backend_id, entry.path)
        except Exception as exc:  # noqa: BLE001 - index drift must not mask success
            log.warning("cas: index cleanup failed for %s: %s", entry.path, exc)
    log.info("Duplicate Finder: moved the folder %s to the trash (a copy of %s)",
             gone.path, kept.path)
    return FolderOutcome(True)


__all__ = ["FolderCopy", "FolderOutcome", "identical_folders", "trash_identical_folder"]
