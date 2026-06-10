"""Append-only operation journal for mutating file operations."""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.redaction import redact
from core.structured_log import log_event

log = logging.getLogger(__name__)

_LOCK = threading.Lock()
_DEFAULT_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "axross"
JOURNAL_PATH = Path(os.environ.get("AXROSS_OPERATION_JOURNAL", _DEFAULT_DIR / "operations.jsonl"))
MAX_READ_RECENT_BYTES = 4 * 1024 * 1024


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _journal_enabled(journal_path: Path | None) -> bool:
    if journal_path is not None:
        return True
    raw = os.environ.get("AXROSS_OPERATION_JOURNAL", "")
    if raw.strip().lower() in {"0", "false", "no", "off"}:
        return False
    # Unit tests should not write to the user's real state dir unless
    # a test explicitly passes journal_path=...
    if "PYTEST_CURRENT_TEST" in os.environ and not raw:
        return False
    return True


def _target_path(journal_path: Path | None) -> Path:
    if journal_path is not None:
        return Path(journal_path)
    raw = os.environ.get("AXROSS_OPERATION_JOURNAL", "")
    if raw and raw.strip().lower() not in {"0", "false", "no", "off"}:
        return Path(raw)
    return JOURNAL_PATH


@dataclass
class JournalEvent:
    operation_id: str
    phase: str
    operation: str
    timestamp: str = field(default_factory=_utc_now)
    status: str = ""
    source: str = ""
    dest: str = ""
    backend: str = ""
    bytes_total: int = 0
    bytes_done: int = 0
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)


def new_operation_id() -> str:
    return uuid.uuid4().hex[:12]


def append_event(event: JournalEvent, *, journal_path: Path | None = None) -> None:
    """Append one redacted JSONL event to the operation journal."""
    if not _journal_enabled(journal_path):
        return
    path = _target_path(journal_path)
    payload = redact(asdict(event))
    line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    log_event(
        log,
        logging.INFO if event.status not in {"error", "cancelled"} else logging.WARNING,
        f"operation_{event.phase}",
        operation_id=event.operation_id,
        operation=event.operation,
        status=event.status,
        source=event.source,
        dest=event.dest,
        error=event.error,
    )


def start_operation(
    operation: str,
    *,
    source: str = "",
    dest: str = "",
    backend: str = "",
    bytes_total: int = 0,
    details: dict[str, Any] | None = None,
    operation_id: str | None = None,
) -> str:
    op_id = operation_id or new_operation_id()
    append_event(
        JournalEvent(
            operation_id=op_id,
            phase="start",
            operation=operation,
            status="active",
            source=source,
            dest=dest,
            backend=backend,
            bytes_total=int(bytes_total or 0),
            details=details or {},
        )
    )
    return op_id


def record_phase(
    operation_id: str,
    phase: str,
    operation: str,
    *,
    status: str = "active",
    source: str = "",
    dest: str = "",
    backend: str = "",
    bytes_total: int = 0,
    bytes_done: int = 0,
    error: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    append_event(
        JournalEvent(
            operation_id=operation_id,
            phase=phase,
            operation=operation,
            status=status,
            source=source,
            dest=dest,
            backend=backend,
            bytes_total=int(bytes_total or 0),
            bytes_done=int(bytes_done or 0),
            error=error,
            details=details or {},
        )
    )


def finish_operation(
    operation_id: str,
    operation: str,
    *,
    status: str,
    source: str = "",
    dest: str = "",
    backend: str = "",
    bytes_total: int = 0,
    bytes_done: int = 0,
    error: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    record_phase(
        operation_id,
        "finish",
        operation,
        status=status,
        source=source,
        dest=dest,
        backend=backend,
        bytes_total=bytes_total,
        bytes_done=bytes_done,
        error=error,
        details=details,
    )


def read_recent(limit: int = 200, *, journal_path: Path | None = None) -> list[dict]:
    if not _journal_enabled(journal_path):
        return []
    count = int(limit)
    if count <= 0:
        return []
    path = _target_path(journal_path)
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > MAX_READ_RECENT_BYTES:
                handle.seek(size - MAX_READ_RECENT_BYTES)
                handle.readline()
            data = handle.read(MAX_READ_RECENT_BYTES + 1)
    except OSError:
        return []
    if len(data) > MAX_READ_RECENT_BYTES:
        data = data[-MAX_READ_RECENT_BYTES:]
    lines = data.decode("utf-8", errors="replace").splitlines()
    out: list[dict] = []
    for line in lines[-count:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


__all__ = [
    "JOURNAL_PATH",
    "JournalEvent",
    "append_event",
    "finish_operation",
    "new_operation_id",
    "read_recent",
    "record_phase",
    "start_operation",
]
