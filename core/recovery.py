"""Recovery scan helpers for temp files, trash and journals."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryFinding:
    kind: str
    path: str
    detail: str = ""


def scan_backend_recovery(backend, root: str) -> list[RecoveryFinding]:
    findings: list[RecoveryFinding] = []
    try:
        entries = backend.list_dir(root)
    except OSError as exc:
        return [RecoveryFinding("error", root, f"list failed: {exc}")]

    try:
        from core.atomic_recovery import is_orphan_name
        from core.path_policy import safe_join

        for item in entries:
            name = getattr(item, "name", "") or ""
            if is_orphan_name(name):
                try:
                    path = safe_join(backend, root, name)
                except ValueError as exc:
                    findings.append(
                        RecoveryFinding(
                            "error",
                            root,
                            f"unsafe recovery candidate {name!r}: {exc}",
                        )
                    )
                    continue
                findings.append(
                    RecoveryFinding(
                        "atomic-temp",
                        path,
                        "old atomic-write temp candidate",
                    )
                )
    except Exception as exc:  # noqa: BLE001
        findings.append(RecoveryFinding("error", root, f"atomic scan failed: {exc}"))

    try:
        from core import trash as T

        for entry in T.list_trash(backend):
            findings.append(
                RecoveryFinding(
                    "trash",
                    entry.trash_id,
                    f"{entry.original_path} ({entry.size} bytes)",
                )
            )
    except Exception as exc:  # noqa: BLE001
        findings.append(RecoveryFinding("error", root, f"trash scan failed: {exc}"))

    return findings


def cleanup_atomic_orphans(backend, root: str, *, max_age_seconds: int = 3600) -> int:
    from core.atomic_recovery import sweep_orphans

    return sweep_orphans(backend, root, max_age_seconds=max_age_seconds)


def format_findings(findings: list[RecoveryFinding]) -> str:
    if not findings:
        return "No recovery items found."
    return "\n".join(
        f"[{f.kind}] {f.path}" + (f" — {f.detail}" if f.detail else "") for f in findings
    )


__all__ = [
    "RecoveryFinding",
    "cleanup_atomic_orphans",
    "format_findings",
    "scan_backend_recovery",
]
