"""Collect the images, PDFs and videos a folder holds, for the media viewer.

One walk over any :class:`~core.backend.FileBackend` (local or remote), run
by the caller on a background thread. It is bounded on every axis a hostile
or merely huge tree can stretch:

* **items** - at most ``max_items`` media files (hard ceiling :data:`MAX_ITEMS`);
* **depth** - ``max_depth`` levels below the start (ceiling :data:`MAX_DEPTH`);
* **folders** - at most ``max_folders`` listings (ceiling :data:`MAX_FOLDERS`),
  so a remote tree of empty folders cannot keep it busy for hours;
* **loops** - a symlinked folder is never descended (it could lead back up
  or out of the tree), and a folder reached a second time under another
  name (bind mount, server-side link resolution on a local mount) is
  skipped by its identity. A server that resolves links itself and reports
  a plain directory under ever longer paths is stopped by the depth cap.

A folder that cannot be listed is skipped and counted, never fatal. Names a
server sends are joined through :func:`core.path_policy.safe_join`, so
``../x.png`` or ``a/b.png`` never becomes a path.

No Qt here.
"""

from __future__ import annotations

import logging
import os
from collections import deque
from collections.abc import Callable, Collection
from dataclasses import dataclass, field

from core.path_policy import safe_join

log = logging.getLogger(__name__)

IMAGE = "image"
PDF = "pdf"
VIDEO = "video"
KINDS = frozenset({IMAGE, PDF, VIDEO})

#: Extensions whose MIME is in core.previews.ALLOWED_THUMBNAIL_MIMES, plus
#: SVG, which the viewer renders through the sanitising gate in previews.
IMAGE_EXTENSIONS = frozenset(
    {".png", ".jpg", ".jpeg", ".jpe", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ppm", ".svg"}
)
PDF_EXTENSIONS = frozenset({".pdf"})
VIDEO_EXTENSIONS = frozenset(
    {".mp4", ".m4v", ".mkv", ".webm", ".mov", ".avi", ".ogv", ".mpg", ".mpeg", ".wmv"}
)

MAX_ITEMS = 5000
DEFAULT_MAX_ITEMS = MAX_ITEMS
MAX_DEPTH = 32
DEFAULT_MAX_DEPTH = 8
MAX_FOLDERS = 20_000
#: How many unreadable folder paths the result keeps for display.
UNREADABLE_PATHS_KEPT = 20

_BY_EXTENSION = {
    **{ext: IMAGE for ext in IMAGE_EXTENSIONS},
    **{ext: PDF for ext in PDF_EXTENSIONS},
    **{ext: VIDEO for ext in VIDEO_EXTENSIONS},
}


def classify(name: str) -> str | None:
    """The media kind of *name* by its extension, or ``None``."""
    stem, ext = os.path.splitext(name or "")
    if not stem or stem == ".":
        return None
    return _BY_EXTENSION.get(ext.lower())


@dataclass(frozen=True)
class MediaItem:
    path: str  # full backend path
    name: str
    folder: str  # relative to the start folder; "" for the start folder itself
    kind: str
    size: int
    mtime: float


@dataclass
class MediaScan:
    items: list[MediaItem] = field(default_factory=list)
    folders_scanned: int = 0
    unreadable: int = 0
    unreadable_paths: list[str] = field(default_factory=list)
    links_skipped: int = 0
    loops_skipped: int = 0
    depth_capped: bool = False
    truncated: bool = False  # the item or folder cap ended the walk
    cancelled: bool = False


def _mtime(item) -> float:
    try:
        return float(item.modified.timestamp())
    except (AttributeError, OverflowError, OSError, ValueError):
        return 0.0


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _identity(backend, path: str, local: bool):
    """What makes two folder paths the same folder."""
    if local:
        try:
            st = os.stat(path)
            return ("inode", st.st_dev, st.st_ino)
        except OSError:
            return ("path", path)
    try:
        return ("path", backend.normalize(path))
    except Exception:  # noqa: BLE001 - a backend without normalize keeps the raw path
        return ("path", path)


def _is_folder_link(item, path: str, local: bool) -> bool:
    if item.is_dir:
        return True
    return local and os.path.isdir(path)


def _check_args(
    kinds, max_items: int, max_depth: int, max_folders: int, known=KINDS
) -> frozenset[str]:
    chosen = frozenset(kinds or ())
    if not chosen:
        raise ValueError("choose at least one media type")
    unknown = chosen - known if known is not None else frozenset()
    if unknown:
        raise ValueError(f"unknown media type(s): {sorted(unknown)}")
    if not 1 <= max_items <= MAX_ITEMS:
        raise ValueError(f"max_items must be 1-{MAX_ITEMS}, got {max_items}")
    if not 0 <= max_depth <= MAX_DEPTH:
        raise ValueError(f"max_depth must be 0-{MAX_DEPTH}, got {max_depth}")
    if not 1 <= max_folders <= MAX_FOLDERS:
        raise ValueError(f"max_folders must be 1-{MAX_FOLDERS}, got {max_folders}")
    return chosen


def collect_media(
    backend,
    root: str,
    *,
    kinds: Collection[str],
    recursive: bool = False,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_items: int = DEFAULT_MAX_ITEMS,
    max_folders: int = MAX_FOLDERS,
    include_hidden: bool = False,
    only_names: Collection[str] | None = None,
    cancel: Callable[[], bool] = lambda: False,
    progress: Callable[[int, int, str], None] | None = None,
    classify: Callable[[str], str | None] | None = None,
) -> MediaScan:
    """Walk *root* and return the media files of the chosen *kinds*.

    ``only_names`` restricts the start folder to those entries (the pane's
    selection): chosen files are taken as they are, chosen folders are
    walked like the start folder itself. Without ``recursive`` no folder
    below a walked one is entered. ``progress(folders, items, path)`` is
    called once per listed folder; ``cancel()`` is polled between folders.

    ``classify(name)`` replaces the media classifier, for walks that look
    for other kinds of files (the metadata tools: Office, audio) with the
    same caps and loop guards; *kinds* are then whatever it returns.
    """
    chosen = _check_args(
        kinds, max_items, max_depth, max_folders, known=KINDS if classify is None else None
    )
    kind_of = classify if classify is not None else globals()["classify"]
    limit_depth = max_depth if recursive else 0
    local = _is_local(backend)
    sep = "/"
    try:
        sep = backend.separator() or "/"
    except Exception:  # noqa: BLE001 - a backend without separator() is POSIX-like
        pass
    scan = MediaScan()
    seen: set = set()
    # (path, relative parts, depth, restrict-to-names)
    queue: deque[tuple[str, tuple[str, ...], int, frozenset[str] | None]] = deque(
        [(root, (), 0, frozenset(only_names) if only_names is not None else None)]
    )

    while queue:
        if cancel():
            scan.cancelled = True
            break
        if scan.folders_scanned >= max_folders:
            scan.truncated = True
            break
        path, rel, depth, restrict = queue.popleft()
        ident = _identity(backend, path, local)
        if ident in seen:
            scan.loops_skipped += 1
            continue
        seen.add(ident)
        try:
            entries = backend.list_dir(path)
        except Exception as exc:  # noqa: BLE001 - any listing failure skips the folder
            log.info("Media walk: cannot list %s: %s", path, exc)
            scan.unreadable += 1
            if len(scan.unreadable_paths) < UNREADABLE_PATHS_KEPT:
                scan.unreadable_paths.append(path)
            continue
        scan.folders_scanned += 1
        folder = sep.join(rel)
        for entry in sorted(entries, key=lambda e: e.name):
            name = entry.name
            if name in (".", "..") or (not include_hidden and entry.is_hidden):
                continue
            if restrict is not None and name not in restrict:
                continue
            try:
                child = safe_join(backend, path, name)
            except ValueError:
                log.warning("Media walk: unsafe name %r in %s skipped", name, path)
                continue
            if entry.is_link and _is_folder_link(entry, child, local):
                scan.links_skipped += 1
                continue
            if entry.is_dir:
                # A selected folder is a start of its own, at depth 0.
                child_depth = 0 if restrict is not None else depth + 1
                if child_depth > limit_depth:
                    if recursive:
                        scan.depth_capped = True
                    continue
                queue.append((child, rel + (name,), child_depth, None))
                continue
            kind = kind_of(name)
            if kind is None or kind not in chosen:
                continue
            scan.items.append(
                MediaItem(
                    path=child,
                    name=name,
                    folder=folder,
                    kind=kind,
                    size=int(entry.size or 0),
                    mtime=_mtime(entry),
                )
            )
            if len(scan.items) >= max_items:
                scan.truncated = True
                break
        if progress is not None:
            progress(scan.folders_scanned, len(scan.items), path)
        if scan.truncated:
            break
    return scan


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_ITEMS",
    "IMAGE",
    "IMAGE_EXTENSIONS",
    "KINDS",
    "MAX_DEPTH",
    "MAX_FOLDERS",
    "MAX_ITEMS",
    "MediaItem",
    "MediaScan",
    "PDF",
    "PDF_EXTENSIONS",
    "VIDEO",
    "VIDEO_EXTENSIONS",
    "classify",
    "collect_media",
]
