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
* Bounded — at most ``MAX_HOSTS`` distinct hosts, ``MAX_OPS_PER_HOST``
  recent ops per host. Older entries fall off the end.
* Privacy: nothing here is encrypted; the file is mode 0o600 from
  birth (same pattern as ``core.secure_storage``). Treat as sensitive
  — it carries the path layout of every host you've touched.

The module is intentionally self-contained — no network, no Qt, safe
to import from any context.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

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
            last_seen=float(d.get("last_seen", 0.0) or 0.0),
            visit_count=int(d.get("visit_count", 0) or 0),
            recent_ops=[
                _sanitize_op_entry(x) for x in d.get("recent_ops", []) if isinstance(x, dict)
            ][:MAX_OPS_PER_HOST],
        )


def _sanitize_op_entry(d: dict) -> dict:
    """Clamp + coerce one ``recent_ops`` entry. Hostile JSON could
    otherwise blow the file size up or smuggle CR/LF for log
    poisoning."""
    return {
        "ts": float(d.get("ts", 0.0) or 0.0),
        "verb": str(d.get("verb", ""))[:32],
        "desc": str(d.get("desc", ""))[:MAX_OP_DESC_LEN].replace("\n", " ").replace("\r", ""),
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _load() -> dict[str, HostVisit]:
    path = _history_file()
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("visit_history: cannot read %s: %s", path, exc)
        return {}
    if not isinstance(raw, list):
        log.warning("visit_history: malformed file %s (expected list)", path)
        return {}
    out: dict[str, HostVisit] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            visit = HostVisit.from_dict(entry)
        except (TypeError, ValueError) as exc:
            log.debug("visit_history: skipping malformed entry: %s", exc)
            continue
        if visit.protocol and visit.host:
            out[visit.key] = visit
    return out


def _save(visits: dict[str, HostVisit]) -> None:
    """Atomic write at 0o600. Trims to ``MAX_HOSTS`` newest entries."""
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
            os.fchmod(fd, 0o600)
        except OSError as exc:
            log.debug("visit_history: cannot chmod tmpfile: %s", exc)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


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

    Failures (disk full, parent dir vanished, permission denied) are
    logged at WARNING and swallowed — visit history is a
    quality-of-life feature, never load-bearing for the actual
    operation.
    """
    if not protocol or not host:
        return
    try:
        with _locked_history_update():
            visits = _load()
            key = f"{protocol}://{username}@{host}"
            v = visits.get(key) or HostVisit(
                protocol=protocol,
                host=host,
                username=username,
            )
            v.visit_count += 1
            v.last_seen = time.time()
            if path:
                v.last_path = path[:MAX_PATH_LEN]
            if verb:
                v.recent_ops.insert(
                    0,
                    _sanitize_op_entry(
                        {
                            "ts": v.last_seen,
                            "verb": verb,
                            "desc": desc,
                        }
                    ),
                )
                if len(v.recent_ops) > MAX_OPS_PER_HOST:
                    v.recent_ops = v.recent_ops[:MAX_OPS_PER_HOST]
            visits[key] = v
            _save(visits)
    except Exception as exc:  # noqa: BLE001 — never fail the caller
        log.warning("visit_history.record_visit suppressed: %s", exc)


def where_was_i(host: str | None = None) -> list[HostVisit] | HostVisit | None:
    """Look up the visit record(s).

    With ``host=None`` returns every recorded host, sorted by most
    recent first. With a host string, returns the most-recent record
    matching that host (across protocols / usernames) or ``None``.
    """
    visits = _load()
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
    Returns the number of records dropped.
    """
    with _locked_history_update():
        visits = _load()
        if host is None:
            n = len(visits)
            try:
                _history_file().unlink(missing_ok=True)
            except OSError as exc:
                log.warning("visit_history.clear: %s", exc)
            return n
        h = host.strip().lower()
        keep = {k: v for k, v in visits.items() if v.host.lower() != h}
        dropped = len(visits) - len(keep)
        if dropped:
            _save(keep)
        return dropped


__all__ = [
    "HostVisit",
    "MAX_HOSTS",
    "MAX_OPS_PER_HOST",
    "clear",
    "format_visit",
    "humanize_age",
    "record_visit",
    "where_was_i",
]
