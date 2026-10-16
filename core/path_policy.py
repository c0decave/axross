"""Backend path policy helpers."""

from __future__ import annotations

import os
import posixpath
from dataclasses import dataclass

from core.remote_name import (
    MAX_REMOTE_NAME_BYTES,
    MAX_REMOTE_PATH_BYTES,
    validate_remote_name,
)

#: Levels a backend's recursive delete descends at most. Deeper than any
#: real tree; a server whose every directory holds another one (a loop on
#: the server, or a hostile server) would otherwise drive the walk into
#: RecursionError, which no caller handles.
MAX_RECURSIVE_DELETE_DEPTH = 256


def check_tree_depth(path: str, depth: int, limit: int) -> None:
    """OSError once a recursive delete is *depth* levels below its start."""
    if depth > limit:
        raise OSError(f"Cannot recursively remove {path}: deeper than {limit} levels")


@dataclass(frozen=True)
class BackendPathPolicy:
    separator: str = "/"
    allow_backslash_separator: bool = False
    case_sensitive: bool = True

    @classmethod
    def for_backend(cls, backend) -> "BackendPathPolicy":
        sep = "/"
        try:
            sep = backend.separator()
        except Exception:
            pass
        return cls(
            separator=sep or "/",
            allow_backslash_separator=(sep == "\\"),
            case_sensitive=bool(getattr(backend, "case_sensitive", True)),
        )

    def validate_leaf(self, name: str) -> str:
        validate_remote_name(name, max_bytes=MAX_REMOTE_NAME_BYTES)
        return name

    def validate_path(self, path: str) -> str:
        validate_remote_name(
            path,
            max_bytes=MAX_REMOTE_PATH_BYTES,
            allow_separators=True,
        )
        return path

    def join(self, parent: str, leaf: str) -> str:
        self.validate_leaf(leaf)
        parent = parent or self.separator
        if self.separator == "\\":
            return parent.rstrip("\\/") + "\\" + leaf
        return posixpath.join(parent, leaf)

    def normalize(self, path: str) -> str:
        path = self.validate_path(path)
        if self.separator == "\\":
            rooted = path.replace("/", "\\")
            return os.path.normpath(rooted)
        rooted = path if path.startswith("/") else "/" + path
        return posixpath.normpath(rooted) or "/"


def safe_join(backend, parent: str, leaf: str) -> str:
    """Join one backend path component after validating it."""
    return BackendPathPolicy.for_backend(backend).join(parent, leaf)


def safe_leaf(name: str) -> str:
    validate_remote_name(name)
    return name


def drop_unsafe_names(items, *, keep_dots: bool = False, origin: str = ""):
    """Drop listing entries whose name is not a single safe path component.

    A remote server controls ``item.name``. Consumers join it onto local
    destinations (mirror scripts, compare/sync, downloads); ``../../x`` or
    ``a/b`` would then land outside the target. Validating once at the
    listing is the choke point every consumer shares. ``.`` and ``..`` are
    kept only when the caller's own parser emits them on purpose.
    """
    import logging

    kept = []
    for item in items:
        name = getattr(item, "name", "")
        if keep_dots and name in (".", ".."):
            kept.append(item)
            continue
        try:
            validate_remote_name(name)
        except ValueError:
            logging.getLogger(__name__).warning(
                "dropping unsafe remote name %r%s", name, f" from {origin}" if origin else ""
            )
            continue
        kept.append(item)
    return kept


def _inside(root: str, path: str) -> bool:
    return os.path.commonpath([root, path]) == root


def confined_path(root: str, path: str, *, follow: bool = True) -> str:
    """Map virtual ``path`` onto the local directory ``root`` and keep it there.

    For backends that work through a kernel mount (NFS, iSCSI): the
    SERVER controls the symlinks in that tree, and the client kernel
    resolves them - an absolute link reaches this machine's own files.
    A lexical check cannot see that, so every directory on the way is
    resolved and must stay inside ``root``. With ``follow`` the final
    component's target must too (open, list, chmod, copy); without it
    the entry itself is meant (lstat, readlink, unlink, rename), so a
    link pointing outside can still be inspected and removed.

    Raises :class:`PermissionError` on any escape. Checked at call time:
    a server swapping a link between this check and the use is not
    covered.
    """
    root_abs = os.path.abspath(root)
    lexical = os.path.abspath(os.path.join(root_abs, path.lstrip("/")))
    if not _inside(root_abs, lexical):
        raise PermissionError(f"Path traversal detected: {path}")
    if lexical == root_abs:
        return root_abs
    root_real = os.path.realpath(root_abs)
    parent = os.path.realpath(os.path.dirname(lexical))
    if not _inside(root_real, parent):
        raise PermissionError(f"Path leaves the mount through a symlink: {path}")
    candidate = os.path.join(parent, os.path.basename(lexical))
    if follow and not _inside(root_real, os.path.realpath(candidate)):
        raise PermissionError(f"Path leaves the mount through a symlink: {path}")
    return candidate


__all__ = [
    "BackendPathPolicy",
    "confined_path",
    "drop_unsafe_names",
    "safe_join",
    "safe_leaf",
]
