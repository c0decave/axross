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


__all__ = ["BackendPathPolicy", "safe_join", "safe_leaf"]
