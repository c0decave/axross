"""Preview destructive or high-impact operations before executing them."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from core.path_policy import safe_join

log = logging.getLogger(__name__)


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

    @property
    def total_items(self) -> int:
        return self.files + self.dirs

    def summary(self) -> str:
        parts = [
            f"{self.operation}: {self.total_items} item(s)",
            f"{self.files} file(s), {self.dirs} dir(s)",
            f"{self.bytes_total} byte(s)",
        ]
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
) -> OperationPreview:
    preview = OperationPreview(operation="delete", roots=list(paths))

    def walk(path: str, depth: int = 0) -> None:
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
            try:
                children = backend.list_dir(path)
            except OSError as exc:
                preview.warnings.append(f"{path}: list failed: {exc}")
                return
            for child in children:
                if preview.total_items >= max_entries:
                    preview.truncated = True
                    return
                name = getattr(child, "name", "") or ""
                if not name or name in (".", ".."):
                    continue
                try:
                    walk(safe_join(backend, path, name), depth + 1)
                except ValueError as exc:
                    preview.warnings.append(f"{path}/{name}: unsafe name: {exc}")
        else:
            preview.files += 1
            preview.bytes_total += int(getattr(item, "size", 0) or 0)

    for root in paths:
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


__all__ = ["OperationPreview", "preview_delete", "preview_transfer"]
