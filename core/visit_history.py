"""Visit history — "where was I last?" across hosts.

Sysadmins and programmers who pendel between many remote systems
spend non-trivial time re-discovering "where was I yesterday on box
X". This module records the last-visited directory + a short trail
of recent operations per (protocol, host, username) triple, so
``axross.where_was_i("prod-db-04")`` returns:

    Last seen 3 days ago at /var/log/postgres/.
    Recent ops: list_dir, open_read app.log, list_dir.

Storage:

* JSON file at ``~/.config/axross/visit_history.json``.
* Atomic write (tmpfile + ``os.replace``).
* Written in batches: :func:`record_visit` only queues the visit in
  memory; :func:`flush` - at most ``FLUSH_DELAY_S`` later from a timer
  thread, at exit (atexit), before :func:`clear` - reads the file under
  the lock, applies every queued visit to what is on disk (another
  axross process's visits stay) and writes it once. A mutating script
  call read and rewrote the whole file (0.5 MB, 95 ms) each time.
  :func:`where_was_i` sees the queued visits; the parsed file is kept
  while its inode, size and times are unchanged.
* Bounded — at most ``MAX_HOSTS`` distinct hosts, ``MAX_OPS_PER_HOST``
  recent ops per host. Older entries fall off the end.
* Privacy: nothing here is encrypted; the file is mode 0o600 from
  birth (same pattern as ``core.secure_storage``). Treat as sensitive
  — it carries the path layout of every host you've touched.

The module is intentionally self-contained — no network, no Qt, safe
to import from any context.
"""

from __future__ import annotations

import atexit
import json
import logging
import math
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from core.secure_storage import keep_unreadable_copy
from core import posix_compat
from security.visit_history_atomicity import (
    assert_lock_held as _assert_lock_held,
)
from security.visit_history_atomicity import (
    share_in_process_lock as _share_lock,
)

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows fallback
    _fcntl = None

log = logging.getLogger(__name__)

# Caps — chosen to keep the JSON small enough to load on every
# :func:`record_visit` call. At 200 hosts × 20 ops ≈ 4000 entries,
# the file stays under ~500 KiB on typical paths.
MAX_HOSTS = 200
MAX_OPS_PER_HOST = 20
MAX_PATH_LEN = 512
MAX_OP_DESC_LEN = 80
#: A queued visit is written at most this long after it was recorded.
FLUSH_DELAY_S = 2.0
#: This many queued visits are written at once, without waiting.
FLUSH_AT_PENDING = 500
#: Queued visits kept while writing fails (disk full, a file that cannot
#: be kept): the oldest go beyond this.
MAX_PENDING = 5000

# Same module-level convention as :mod:`core.bookmarks` — module-level
# constants exist so tests can patch them, with a fall-through to a
# live re-read from ``Path.home()`` whenever the constant still equals
# its boot-time snapshot.
CONFIG_DIR = Path.home() / ".config" / "axross"
HISTORY_FILE = CONFIG_DIR / "visit_history.json"
_DEFAULT_CONFIG_DIR = CONFIG_DIR
_DEFAULT_HISTORY_FILE = HISTORY_FILE
_HISTORY_RMW_LOCK = threading.RLock()

# Defense-in-depth: share our RLock with the security/
# atomicity helper so any future caller using
# ``security.visit_history_atomicity.acquire_history_lock`` blocks on
# the SAME in-process primitive. A split-lock regression here would
# silently re-introduce the RMW race; we wire it at import.
_share_lock(_HISTORY_RMW_LOCK)
del _share_lock


def _config_dir() -> Path:
    if CONFIG_DIR != _DEFAULT_CONFIG_DIR:
        return CONFIG_DIR
    return Path.home() / ".config" / "axross"


def _history_file() -> Path:
    if HISTORY_FILE != _DEFAULT_HISTORY_FILE:
        return HISTORY_FILE
    return _config_dir() / "visit_history.json"


@contextmanager
def _locked_history_update():
    """Serialize read-modify-write updates in this and peer processes."""
    with _HISTORY_RMW_LOCK:
        lock_fh = None
        try:
            if _fcntl is not None:
                path = _history_file()
                path.parent.mkdir(parents=True, exist_ok=True)
                lock_path = path.with_name(path.name + ".lock")
                lock_fh = open(lock_path, "a+b")
                try:
                    os.chmod(lock_path, 0o600)
                except OSError as exc:
                    log.debug("visit_history: cannot chmod lockfile: %s", exc)
                _fcntl.flock(lock_fh.fileno(), _fcntl.LOCK_EX)
            yield
        finally:
            if lock_fh is not None:
                try:
                    _fcntl.flock(lock_fh.fileno(), _fcntl.LOCK_UN)
                except OSError as exc:
                    log.debug("visit_history: cannot unlock lockfile: %s", exc)
                lock_fh.close()


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class HostVisit:
    """Last-visited state for one (protocol, host, username) triple."""

    protocol: str
    host: str
    username: str
    last_path: str = ""
    last_seen: float = 0.0  # epoch seconds
    visit_count: int = 0
    recent_ops: list[dict[str, Any]] = field(default_factory=list)

    @property
    def key(self) -> str:
        """Stable lookup key — protocol://user@host."""
        return f"{self.protocol}://{self.username}@{self.host}"

    @classmethod
    def from_dict(cls, d: dict) -> "HostVisit":
        return cls(
            protocol=str(d.get("protocol", "")),
            host=str(d.get("host", "")),
            username=str(d.get("username", "")),
            last_path=str(d.get("last_path", ""))[:MAX_PATH_LEN],
            last_seen=_finite_time(d.get("last_seen")),
            visit_count=int(d.get("visit_count", 0) or 0),
            recent_ops=[
                _sanitize_op_entry(x) for x in d.get("recent_ops", []) if isinstance(x, dict)
            ][:MAX_OPS_PER_HOST],
        )


def _finite_time(value) -> float:
    """Epoch seconds from a hand-editable field; 0.0 ("never") for a
    missing, non-numeric or non-finite one - JSON's Infinity made
    format_visit raise OverflowError, NaN sorted the list at random."""
    seconds = float(value or 0.0)
    return seconds if math.isfinite(seconds) else 0.0


def _sanitize_op_entry(d: dict) -> dict:
    """Clamp + coerce one ``recent_ops`` entry. Hostile JSON could
    otherwise blow the file size up or smuggle CR/LF for log
    poisoning."""
    return {
        "ts": _finite_time(d.get("ts")),
        "verb": str(d.get("verb", ""))[:32],
        "desc": str(d.get("desc", ""))[:MAX_OP_DESC_LEN].replace("\n", " ").replace("\r", ""),
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _clone(v: HostVisit) -> HostVisit:
    return HostVisit(
        protocol=v.protocol, host=v.host, username=v.username, last_path=v.last_path,
        last_seen=v.last_seen, visit_count=v.visit_count,
        recent_ops=[dict(op) for op in v.recent_ops],
    )


#: The file as last read or written: (path, its bytes, visits, complete).
#: Reading compares the bytes (cheap) and parses only a changed file -
#: by content, not by time stamps, which a rewrite within the same clock
#: tick at the same size does not change. Callers get copies.
_FILE_CACHE: tuple | None = None


def _remember(path: Path, data: bytes, visits: dict[str, HostVisit], complete: bool) -> None:
    global _FILE_CACHE
    _FILE_CACHE = (path, data, {k: _clone(v) for k, v in visits.items()}, complete)


class _Visits(dict):
    """The visits ``_load`` read, carrying whether the file was taken in
    completely (``complete``), so ``_save`` under the same lock need not
    read the file a second time to find out. A plain dict carries nothing:
    ``_save`` reads the file then, as before."""

    complete: bool | None = None


def _read() -> tuple[dict[str, HostVisit], bool]:
    """The stored visits, and whether the file was taken in completely
    (a missing file is: it holds nothing)."""
    path = _history_file()
    if not path.exists():
        return {}, True
    try:
        data = path.read_bytes()
        cached = _FILE_CACHE
        if cached is not None and cached[0] == path and cached[1] == data:
            return {k: _clone(v) for k, v in cached[2].items()}, cached[3]
        raw = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        # ValueError covers JSONDecodeError and UnicodeDecodeError.
        log.warning("visit_history: cannot read %s: %s", path, exc)
        return {}, False
    if not isinstance(raw, list):
        log.warning("visit_history: malformed file %s (expected list)", path)
        return {}, False
    out: dict[str, HostVisit] = {}
    complete = True
    for entry in raw:
        if not isinstance(entry, dict):
            complete = False
            continue
        try:
            visit = HostVisit.from_dict(entry)
        except (TypeError, ValueError, OverflowError) as exc:
            log.debug("visit_history: skipping malformed entry: %s", exc)
            complete = False
            continue
        if visit.protocol and visit.host:
            out[visit.key] = visit
        else:
            complete = False
    _remember(path, data, out, complete)
    return out, complete


def _load() -> dict[str, HostVisit]:
    visits, complete = _read()
    loaded = _Visits(visits)
    loaded.complete = complete
    return loaded


def _keep_incomplete_file(complete: bool | None = None) -> None:
    """Before ``_save`` replaces a file ``_read`` cannot take in completely,
    keep a copy of it: what was loaded from it is all that would remain.
    Raises OSError when that copy cannot be made, so the save does not run.

    *complete* is what the caller's own ``_read`` under the same lock found
    (None: read the file here)."""
    if complete is None:
        complete = _read()[1]
    if not complete and not keep_unreadable_copy(_history_file()):
        raise OSError(f"not replacing the unreadable {_history_file()}: no copy could be kept")


def _save(visits: dict[str, HostVisit], *, complete: bool | None = None) -> None:
    """Atomic write at 0o600. Trims to ``MAX_HOSTS`` newest entries.

    *complete*: whether the caller's ``_read``, made under the lock it still
    holds, took the file in completely - saves reading it a second time
    (default: what *visits* carries when ``_load`` made it, else read)."""
    # Defense-in-depth tripwire: every mutator MUST hold the
    # shared RMW lock. If a future code path lands that
    # forgets the wrapper, the security/ helper surfaces a WARNING so
    # the regression shows up in logs and tests instead of silently
    # losing updates under concurrent writers.
    _assert_lock_held("_save")
    path = _history_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError as exc:
        log.debug("visit_history: cannot chmod %s: %s", path.parent, exc)

    if complete is None:
        complete = getattr(visits, "complete", None)
    _keep_incomplete_file(complete)
    items = sorted(visits.values(), key=lambda v: v.last_seen, reverse=True)
    if len(items) > MAX_HOSTS:
        items = items[:MAX_HOSTS]
    payload = [asdict(v) for v in items]

    # Write via tmpfile so the on-disk file is never half-written.
    fd, tmp_path = tempfile.mkstemp(
        prefix=".visit_history-",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        try:
            posix_compat.fchmod_private(fd, 0o600)
        except OSError as exc:
            log.debug("visit_history: cannot chmod tmpfile: %s", exc)
        # json.dumps, not json.dump: dump streams through the pure-Python
        # encoder (10 ms for a full history), dumps uses the C one - the
        # same text.
        text = json.dumps(payload, indent=2)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_path, path)
        _remember(path, text.encode("utf-8"), {v.key: v for v in items}, True)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Queued visits
# ---------------------------------------------------------------------------

#: Visits not yet written: (history file, [(protocol, host, username,
#: path, verb, desc, time), ...]). Its own lock: recording never waits
#: for a flush that holds the file lock.
_PENDING_LOCK = threading.Lock()
_PENDING: list[tuple] = []
_PENDING_PATH: Path | None = None
_TIMER: threading.Timer | None = None


def _apply(visits: dict[str, HostVisit], visit: tuple) -> None:
    protocol, host, username, path, verb, desc, ts = visit
    key = f"{protocol}://{username}@{host}"
    v = visits.get(key) or HostVisit(protocol=protocol, host=host, username=username)
    v.visit_count += 1
    v.last_seen = ts
    if path:
        v.last_path = path[:MAX_PATH_LEN]
    if verb:
        v.recent_ops.insert(0, _sanitize_op_entry({"ts": ts, "verb": verb, "desc": desc}))
        if len(v.recent_ops) > MAX_OPS_PER_HOST:
            v.recent_ops = v.recent_ops[:MAX_OPS_PER_HOST]
    visits[key] = v


def _take_pending() -> list[tuple]:
    """The queued visits of the current history file, taken out of the
    queue (those of another file - HOME or HISTORY_FILE changed since -
    cannot be written any more and are dropped)."""
    global _PENDING, _PENDING_PATH, _TIMER
    with _PENDING_LOCK:
        batch, _PENDING = _PENDING, []
        path, _PENDING_PATH = _PENDING_PATH, None
        if _TIMER is not None:
            _TIMER.cancel()
            _TIMER = None
    if batch and path != _history_file():
        log.info("visit_history: %d visit(s) for %s dropped: the history file changed",
                 len(batch), path)
        return []
    return batch


def _give_back(batch: list[tuple]) -> None:
    """Queue *batch* again in front of what came since (a failed write)."""
    global _PENDING, _PENDING_PATH
    if not batch:
        return
    with _PENDING_LOCK:
        path = _history_file()
        if _PENDING_PATH not in (None, path):
            return
        _PENDING = (batch + _PENDING)[-MAX_PENDING:]
        _PENDING_PATH = path


def _pending_view() -> list[tuple]:
    with _PENDING_LOCK:
        if _PENDING_PATH != _history_file():
            return []
        return list(_PENDING)


def _timer_flush() -> None:
    global _TIMER
    with _PENDING_LOCK:
        _TIMER = None
    flush()


def flush() -> bool:
    """Write the queued visits now: one read of the file (under the file
    lock, so a peer process's visits are kept) and one write. False (and
    the visits stay queued) when writing failed; never raises."""
    with _HISTORY_RMW_LOCK:
        if not _pending_view():
            _take_pending()  # visits of a file no longer in use go
            return True
        batch: list[tuple] = []
        try:
            with _locked_history_update():
                batch = _take_pending()
                if not batch:
                    return True
                visits = _load()
                for visit in batch:
                    _apply(visits, visit)
                _save(visits)
            return True
        except Exception as exc:  # noqa: BLE001 - never fail the caller
            _give_back(batch)
            log.warning("visit_history: %d visit(s) not written yet: %s", len(batch), exc)
            return False


atexit.register(flush)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def record_visit(
    protocol: str,
    host: str,
    username: str = "",
    *,
    path: str = "",
    verb: str = "",
    desc: str = "",
) -> None:
    """Record one operation against a remote host.

    Called by ``ConnectionManager.connect`` (host-level "I touched
    this host" entry) and by individual file ops (``cd``, ``open``,
    ``write``, …) when the caller wants the trail to include them.

    The visit is queued and written by :func:`flush` (at most
    ``FLUSH_DELAY_S`` later, at exit, at ``FLUSH_AT_PENDING`` queued
    visits); :func:`where_was_i` sees it at once.

    Failures (disk full, parent dir vanished, permission denied) are
    logged at WARNING and swallowed — visit history is a
    quality-of-life feature, never load-bearing for the actual
    operation.
    """
    global _PENDING, _PENDING_PATH, _TIMER
    if not protocol or not host:
        return
    try:
        history = _history_file()
        visit = (str(protocol), str(host), str(username or ""), str(path or ""),
                 str(verb or ""), str(desc or ""), time.time())
        with _PENDING_LOCK:
            if _PENDING_PATH != history:
                if _PENDING:
                    log.info("visit_history: %d visit(s) for %s dropped: the history "
                             "file changed", len(_PENDING), _PENDING_PATH)
                _PENDING = []
                _PENDING_PATH = history
            _PENDING.append(visit)
            del _PENDING[:-MAX_PENDING]
            now = len(_PENDING) >= FLUSH_AT_PENDING
            if not now and _TIMER is None:
                _TIMER = threading.Timer(FLUSH_DELAY_S, _timer_flush)
                _TIMER.daemon = True
                _TIMER.name = "visit-history-flush"
                _TIMER.start()
        if now:
            flush()
    except Exception as exc:  # noqa: BLE001 — never fail the caller
        log.warning("visit_history.record_visit suppressed: %s", exc)


def where_was_i(host: str | None = None) -> list[HostVisit] | HostVisit | None:
    """Look up the visit record(s).

    With ``host=None`` returns every recorded host, sorted by most
    recent first. With a host string, returns the most-recent record
    matching that host (across protocols / usernames) or ``None``.
    Queued visits (not yet written) count.
    """
    with _HISTORY_RMW_LOCK:  # not between a flush's taking and writing
        visits = _load()
        for visit in _pending_view():
            _apply(visits, visit)
    items = sorted(visits.values(), key=lambda v: v.last_seen, reverse=True)
    if host is None:
        return items
    h = host.strip().lower()
    if not h:
        return None
    for v in items:
        if v.host.lower() == h:
            return v
    # Substring match — friendly UX for "prod" finding "prod-db-04".
    for v in items:
        if h in v.host.lower():
            return v
    return None


def humanize_age(seconds_ago: float) -> str:
    """Render a ``time.time() - last_seen`` delta as a short human
    string. Used by the CLI / REPL renderers."""
    seconds_ago = max(0.0, seconds_ago)
    if seconds_ago < 60:
        return "just now"
    if seconds_ago < 3600:
        return f"{int(seconds_ago / 60)} min ago"
    if seconds_ago < 86400:
        return f"{int(seconds_ago / 3600)} h ago"
    if seconds_ago < 86400 * 14:
        return f"{int(seconds_ago / 86400)} d ago"
    return f"{int(seconds_ago / (86400 * 7))} w ago"


def format_visit(v: HostVisit) -> str:
    """One-line render — used by both the REPL and the dashboard."""
    age = humanize_age(time.time() - v.last_seen) if v.last_seen else "never"
    target = v.key
    path_part = f" at {v.last_path}" if v.last_path else ""
    return f"{target} — {age}{path_part} (visits={v.visit_count})"


def clear(host: str | None = None) -> int:
    """Remove visit-history records.

    With ``host=None`` clears the whole file. With a host, removes
    every entry whose ``host`` matches (across protocols / usernames).
    Returns the number of records dropped. Queued visits count: they
    are cleared with the rest, or written with the remaining hosts.
    """
    global _FILE_CACHE
    with _locked_history_update():
        batch = _take_pending()
        visits = _load()
        for visit in batch:
            _apply(visits, visit)
        if host is None:
            n = len(visits)
            try:
                _history_file().unlink(missing_ok=True)
            except OSError as exc:
                log.warning("visit_history.clear: %s", exc)
            _FILE_CACHE = None
            return n
        h = host.strip().lower()
        keep = {k: v for k, v in visits.items() if v.host.lower() != h}
        dropped = len(visits) - len(keep)
        if dropped or batch:
            try:
                _save(keep, complete=getattr(visits, "complete", None))
            except Exception:
                _give_back([v for v in batch if v[1].lower() != h])
                raise
        return dropped


__all__ = [
    "HostVisit",
    "MAX_HOSTS",
    "MAX_OPS_PER_HOST",
    "clear",
    "flush",
    "format_visit",
    "humanize_age",
    "record_visit",
    "where_was_i",
]
