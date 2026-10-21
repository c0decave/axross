"""Preview destructive or high-impact operations before executing them."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from core.path_policy import safe_join

log = logging.getLogger(__name__)

# How many hidden paths a preview keeps as examples; the count is exact.
HIDDEN_EXAMPLES = 20


def is_hidden_entry(item, name: str) -> bool:
    """True for an entry a listing without hidden files does not show: a
    dot name, or one the backend flags hidden (``FileItem.attr_hidden`` -
    Windows / SMB / macOS - the same rule as the pane's filter,
    ``FileItem.is_hidden``). A plain ``hidden`` attribute counts too."""
    return (
        name.startswith(".")
        or bool(getattr(item, "attr_hidden", False))
        or bool(getattr(item, "hidden", False))
    )


@dataclass
class OperationPreview:
    operation: str
    roots: list[str]
    files: int = 0
    dirs: int = 0
    bytes_total: int = 0
    conflicts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False
    # Hidden entries found INSIDE the roots (a root itself is not counted:
    # the user picked it by name). ``hidden`` holds up to HIDDEN_EXAMPLES
    # paths; ``hidden_count`` is the exact number.
    hidden: list[str] = field(default_factory=list)
    hidden_count: int = 0
    cancelled: bool = False

    @property
    def total_items(self) -> int:
        return self.files + self.dirs

    @property
    def incomplete(self) -> bool:
        """The walk did not see every entry (cap, cancel, or an entry it
        could not stat / list / name), so hidden entries cannot be ruled out."""
        return self.truncated or self.cancelled or bool(self.warnings)

    def summary(self) -> str:
        parts = [
            f"{self.operation}: {self.total_items} item(s)",
            f"{self.files} file(s), {self.dirs} dir(s)",
            f"{self.bytes_total} byte(s)",
        ]
        if self.hidden_count:
            parts.append(f"{self.hidden_count} hidden")
        if self.conflicts:
            parts.append(f"{len(self.conflicts)} conflict(s)")
        if self.warnings:
            parts.append(f"{len(self.warnings)} warning(s)")
        if self.truncated:
            parts.append("preview truncated")
        return "; ".join(parts)


def preview_delete(
    backend,
    paths: list[str],
    *,
    max_entries: int = 10_000,
    cancel: Callable[[], bool] | None = None,
    progress: Callable[[int, int, str], None] | None = None,
) -> OperationPreview:
    """Count what deleting *paths* would remove, and the hidden entries in it.

    *cancel* is polled before every entry; once it returns true the walk
    stops and the preview is marked ``cancelled``. *progress* receives
    ``(dirs, files, path)`` for every entry visited. Both serve a caller
    that runs the walk on a worker thread.
    """
    preview = OperationPreview(operation="delete", roots=list(paths))

    def stopped() -> bool:
        if cancel is not None and not preview.cancelled and cancel():
            preview.cancelled = True
        return preview.cancelled

    def walk(path: str, depth: int = 0) -> None:
        if stopped():
            return
        if preview.total_items >= max_entries:
            preview.truncated = True
            return
        try:
            item = backend.stat(path)
        except OSError as exc:
            preview.warnings.append(f"{path}: stat failed: {exc}")
            return
        if getattr(item, "is_dir", False):
            preview.dirs += 1
            if progress is not None:
                progress(preview.dirs, preview.files, path)
            try:
                children = backend.list_dir(path)
            except OSError as exc:
                preview.warnings.append(f"{path}: list failed: {exc}")
                return
            for child in children:
                if stopped():
                    return
                if preview.total_items >= max_entries:
                    preview.truncated = True
                    return
                name = getattr(child, "name", "") or ""
                if not name or name in (".", ".."):
                    continue
                try:
                    child_path = safe_join(backend, path, name)
                except ValueError as exc:
                    preview.warnings.append(f"{path}/{name}: unsafe name: {exc}")
                    continue
                if is_hidden_entry(child, name):
                    preview.hidden_count += 1
                    if len(preview.hidden) < HIDDEN_EXAMPLES:
                        preview.hidden.append(child_path)
                walk(child_path, depth + 1)
        else:
            preview.files += 1
            preview.bytes_total += int(getattr(item, "size", 0) or 0)
            if progress is not None:
                progress(preview.dirs, preview.files, path)

    for root in paths:
        if stopped():
            break
        walk(root)
    return preview


def preview_transfer(
    source_backend,
    dest_backend,
    source_paths: list[str],
    dest_dir: str,
    *,
    operation: str = "copy",
    max_entries: int = 10_000,
) -> OperationPreview:
    preview = OperationPreview(operation=operation, roots=list(source_paths))

    def walk(src_path: str, dst_parent: str) -> None:
        if preview.total_items >= max_entries:
            preview.truncated = True
            return
        try:
            item = source_backend.stat(src_path)
        except OSError as exc:
            preview.warnings.append(f"{src_path}: stat failed: {exc}")
            return
        name = getattr(item, "name", "") or src_path.rstrip("/\\").rsplit("/", 1)[-1]
        try:
            dst_path = safe_join(dest_backend, dst_parent, name)
        except ValueError as exc:
            preview.warnings.append(f"{src_path}: unsafe destination name: {exc}")
            return
        try:
            if dest_backend.exists(dst_path):
                preview.conflicts.append(dst_path)
        except OSError as exc:
            preview.warnings.append(f"{dst_path}: conflict check failed: {exc}")
        if getattr(item, "is_dir", False):
            preview.dirs += 1
            try:
                children = source_backend.list_dir(src_path)
            except OSError as exc:
                preview.warnings.append(f"{src_path}: list failed: {exc}")
                return
            for child in children:
                child_name = getattr(child, "name", "") or ""
                if not child_name or child_name in (".", ".."):
                    continue
                try:
                    child_src = safe_join(source_backend, src_path, child_name)
                except ValueError as exc:
                    preview.warnings.append(f"{src_path}/{child_name}: unsafe name: {exc}")
                    continue
                walk(child_src, dst_path)
        else:
            preview.files += 1
            preview.bytes_total += int(getattr(item, "size", 0) or 0)

    for src in source_paths:
        walk(src, dest_dir)
    return preview


__all__ = ["OperationPreview", "is_hidden_entry", "preview_delete", "preview_transfer"]
