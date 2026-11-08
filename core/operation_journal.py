"""Append-only operation journal for mutating file operations."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.redaction import _is_sensitive_key, redact, redact_path, redact_text
from core.structured_log import log_event

log = logging.getLogger(__name__)

_LOCK = threading.Lock()
_DEFAULT_DIR = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "axross"
JOURNAL_PATH = Path(os.environ.get("AXROSS_OPERATION_JOURNAL", _DEFAULT_DIR / "operations.jsonl"))
MAX_READ_RECENT_BYTES = 4 * 1024 * 1024
#: Above this size the journal becomes ``<name>.1`` (replacing the older
#: one) and a new file starts: it grew without bound - 100 MB after a few
#: benchmark copies - while only its last few MB are ever read.
MAX_JOURNAL_BYTES = 16 * 1024 * 1024


def _rotate(path: str) -> None:
    """Move the journal at *path* to ``path.1`` (the previous one goes)."""
    try:
        os.replace(path, path + ".1")
    except OSError as exc:
        log.debug("operation journal not rotated: %s", exc)


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


#: Fields that hold the paths undo acts on (top level and inside
#: ``details``, at any depth). They keep their real value: the journal is
#: the user's own file (mode 0600), and a path ``redact_text`` had
#: rewritten ("Basic Course" -> "Basic <redacted>") made undo restore a
#: trashed file under the rewritten name. Only URL credentials go.
_PATH_FIELDS = frozenset({"source", "dest", "path", "output", "temp", "trash_root"})


def _redact_event(value: Any, key: str | None = None) -> Any:
    """``redact`` for a journal event, except for the path fields."""
    if isinstance(value, str) and key in _PATH_FIELDS:
        return redact_path(value)
    if isinstance(value, dict):
        return {
            k: "<redacted>" if _is_sensitive_key(k) else _redact_event(v, str(k))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_event(item) for item in value]
    return redact(value)


def new_operation_id() -> str:
    return uuid.uuid4().hex[:12]


#: The batch the events written on this thread belong to (journal_batch).
_BATCH = threading.local()


def new_batch_id() -> str:
    """An id for the entries of one user operation (one F5 / F6 / drop /
    Paste, one Move to Trash of a selection): undo reverses them together."""
    return "b" + uuid.uuid4().hex[:11]


class journal_batch:  # noqa: N801 - used like a function: ``with journal_batch(id):``
    """Every event this thread writes inside the block carries
    ``details["batch"] = batch_id`` (unless it names a batch itself).

    For callers that journal through code of their own (core.trash.trash
    per selected entry); the transfer engine names the batch on each job,
    whose events are written on worker threads.
    """

    def __init__(self, batch_id: str) -> None:
        self.batch_id = batch_id
        self._outer = ""

    def __enter__(self) -> str:
        self._outer = getattr(_BATCH, "id", "")
        _BATCH.id = self.batch_id
        return self.batch_id

    def __exit__(self, *_exc) -> None:
        _BATCH.id = self._outer


def current_batch() -> str:
    """The batch of :class:`journal_batch` on this thread, or ""."""
    return getattr(_BATCH, "id", "") or ""


#: Value types every caller in this code base builds ``details`` from. A
#: tree of only these is redacted as it is; anything else goes through
#: ``dataclasses.asdict`` first, as every event did before (it turns a
#: nested dataclass into the dict that redaction then masks).
_PLAIN_SCALARS = (str, int, float, bool, type(None))
#: Whether redaction masks a top-level field by its name (none does today).
_TOP_SENSITIVE = {name: _is_sensitive_key(name) for name in (
    "operation_id", "phase", "operation", "timestamp", "status", "source", "dest", "backend",
    "bytes_total", "bytes_done", "error", "details")}
#: What _utc_now writes; nothing of this shape is a secret.
_ISO_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?([+-]\d\d:\d\d|Z)?")


def _is_plain(value: Any) -> bool:
    cls = type(value)
    if cls in _PLAIN_SCALARS:
        return True
    if cls is dict:
        return all(type(k) in _PLAIN_SCALARS and _is_plain(v) for k, v in value.items())
    if cls is list:
        return all(_is_plain(v) for v in value)
    return False


def _event_payload(event: JournalEvent, batch: str) -> dict[str, Any]:
    """The redacted dict of *event* that is written as its line.

    Built field by field, not with ``asdict``: its deep copy of every value
    was a third of a small-file copy's worker time, and redaction copies
    each dict and list again anyway. A ``details`` holding anything but
    plain values takes the old way, so the line stays byte-identical."""
    details = event.details
    if batch and not (details or {}).get("batch"):
        details = {**(details or {}), "batch": batch}
    if type(event) is not JournalEvent or not _is_plain(details):
        if details is not event.details:
            event = JournalEvent(**{**asdict(event), "details": details})
        return _redact_event(asdict(event))
    payload: dict[str, Any] = {}
    for key, value in (
        ("operation_id", event.operation_id),
        ("phase", event.phase),
        ("operation", event.operation),
        ("timestamp", event.timestamp),
        ("status", event.status),
        ("source", event.source),
        ("dest", event.dest),
        ("backend", event.backend),
        ("bytes_total", event.bytes_total),
        ("bytes_done", event.bytes_done),
        ("error", event.error),
    ):
        cls = type(value)
        if cls is str:
            if key in _PATH_FIELDS:
                value = redact_path(value)
            elif key != "timestamp" or not _ISO_TIME.fullmatch(value):
                # The ":" of an ISO time sent it through every redaction
                # pattern (a third of an event's redaction), which leave
                # such a string as it is.
                value = redact_text(value)
        elif cls is not int:
            value = _redact_event(value, key)
        payload[key] = "<redacted>" if _TOP_SENSITIVE[key] else value
    payload["details"] = "<redacted>" if _TOP_SENSITIVE["details"] else _redact_event(details,
                                                                                      "details")
    return payload


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


class _JournalFile:
    """The journal's file descriptor, kept open between events.

    Opening, chmod-ing and closing the file for every event cost more than
    the rest of a small-file copy's per-file work (three events per file).
    The descriptor is kept, and before every write the path is checked to
    still name the file it has open (one ``stat``): a journal that was
    deleted, moved away or replaced is opened (or created) anew, so no
    event goes into an unlinked file; a mode widened meanwhile is tightened
    to 0600 again.

    Every event is still written by one ``os.write`` before
    :func:`append_event` returns. Nothing is held back in memory for a
    later batch write: the events that tell an interrupted move from a
    finished one (worker_start before the first byte, the finish after the
    source was removed) must be in the file whenever the process dies after
    them - killed, crashed, the power button - exactly as with the file
    opened per event. Neither way calls fsync: a crash of the whole machine
    keeps what the kernel had written back, as before.

    Windows does not let a file that is open be deleted or replaced, so
    there the file is opened per event as before.
    """

    _FLAGS = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0)
    KEEP_OPEN = os.name != "nt"

    def __init__(self) -> None:
        self.path: str | None = None
        self.fd = -1
        self.ident: tuple[int, int] = (0, 0)

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
        self.fd, self.path, self.ident = -1, None, (0, 0)

    @classmethod
    def _open(cls, path: str) -> int:
        try:
            fd = os.open(path, cls._FLAGS, 0o600)
        except FileNotFoundError:
            # Create the directory only when it is missing, not per event.
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            fd = os.open(path, cls._FLAGS, 0o600)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return fd

    def _current(self, path: str) -> int:
        """The open descriptor of *path*; (re)opened when the path does not
        name the file this has open (another path, deleted, replaced)."""
        if self.fd >= 0 and self.path == path:
            try:
                st = os.stat(path)
            except OSError:
                st = None
            if st is not None and st.st_size > MAX_JOURNAL_BYTES:
                _rotate(path)  # the open descriptor no longer names the path
                st = None
            if st is not None and (st.st_dev, st.st_ino) == self.ident:
                if st.st_mode & 0o777 != 0o600:
                    try:
                        os.chmod(path, 0o600)
                    except OSError:
                        pass
                return self.fd
        self.close()
        try:
            if os.stat(path).st_size > MAX_JOURNAL_BYTES:
                _rotate(path)  # a big journal from before this process
        except OSError:
            pass
        fd = self._open(path)
        try:
            st = os.fstat(fd)
        except OSError:
            os.close(fd)
            raise
        self.fd, self.path, self.ident = fd, path, (st.st_dev, st.st_ino)
        return fd

    def write(self, path: str, data: bytes) -> None:
        if not self.KEEP_OPEN:
            try:
                if os.stat(path).st_size > MAX_JOURNAL_BYTES:
                    _rotate(path)
            except OSError:
                pass
            fd = self._open(path)
            try:
                _write_all(fd, data)
            finally:
                os.close(fd)
            return
        fd = self._current(path)
        try:
            _write_all(fd, data)
        except OSError:
            self.close()  # the next event opens the file again
            raise


_FILE = _JournalFile()


def append_event(event: JournalEvent, *, journal_path: Path | None = None) -> None:
    """Append one redacted JSONL event to the operation journal. Paths
    keep their real names (see ``_PATH_FIELDS``); the log line about the
    event is redacted in full.

    The line is in the file (handed to the kernel) when this returns, see
    :class:`_JournalFile`. The log line is DEBUG for an event that went as
    planned - the journal is the record of it, and three INFO lines per
    copied file filled the log - and a WARNING for an error or a cancel."""
    if not _journal_enabled(journal_path):
        return
    # A str, not a Path: parsing a Path per event cost more than its write.
    path = os.fspath(journal_path) if journal_path is not None else os.fspath(_target_path(None))
    payload = _event_payload(event, current_batch())
    line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    data = (line + "\n").encode("utf-8")
    with _LOCK:
        _FILE.write(path, data)
    level = logging.WARNING if event.status in {"error", "cancelled"} else logging.DEBUG
    if log.isEnabledFor(level):
        log_event(
            log,
            level,
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


def _tail_lines(path: Path) -> list[str]:
    """The lines of the last :data:`MAX_READ_RECENT_BYTES` of *path*."""
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
    return data.decode("utf-8", errors="replace").splitlines()


def read_recent(limit: int = 200, *, journal_path: Path | None = None) -> list[dict]:
    """The last *limit* events, oldest first - from the rotated journal
    (``.1``) too when the current one holds fewer."""
    if not _journal_enabled(journal_path):
        return []
    count = int(limit)
    if count <= 0:
        return []
    path = _target_path(journal_path)
    lines = _tail_lines(path) if path.exists() else []
    if len(lines) < count:
        older = path.with_name(path.name + ".1")
        if older.exists():
            lines = _tail_lines(older) + lines
    out: list[dict] = []
    for line in lines[-count:]:
        try:
            item = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


__all__ = [
    "JOURNAL_PATH",
    "JournalEvent",
    "append_event",
    "current_batch",
    "finish_operation",
    "journal_batch",
    "new_batch_id",
    "new_operation_id",
    "read_recent",
    "record_phase",
    "start_operation",
]
