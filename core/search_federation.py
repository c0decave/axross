"""Universal search federation — translate one query into per-backend
native search.

The motivating sysadmin / programmer ask: *"find all files containing
``hostname.example`` across my SFTP boxes, S3 buckets and IMAP
mailboxes"*. Doing that by hand means six different command-line
tools. This module translates a single ``SearchQuery`` into the most
efficient native query each backend can run, fans out in parallel,
and merges the results.

Per-protocol adapters live in this module (instead of in each backend
file) so the federation logic is in one place. Each adapter takes:

* the ``backend`` instance (already opened),
* a ``SearchQuery`` describing what to find,
* a max-results cap for that backend,

and returns a list of :class:`SearchHit` dataclasses. An adapter that
cannot honour a particular query field gracefully degrades by adding
a ``warning`` to the hit set or by falling back to the generic
client-side ``find + grep`` adapter (``_generic_adapter``).

Design choices:

* **No content download for "name-only" queries.** If the caller asks
  ``query.name="*.conf"`` without a ``contains=…``, we never read a
  byte of file content. Critical on cloud backends where a LIST is
  cheap but a GET is paid by request.
* **Per-backend timeout** so one slow box doesn't stall the
  federation.
* **Bounded parallelism** — default 8 workers across the federation
  regardless of how many backends are searched.
* **Capability-driven**. If a backend has no protocol-specific
  adapter, the generic walker runs; the result is correct but no
  faster than a serial walk would be.
"""

from __future__ import annotations

import fnmatch
import logging
import math
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any

from security.federation_timeout import (
    probe_overdue_indices,
    probe_timeout_keys_for_count,
)

log = logging.getLogger(__name__)


DEFAULT_MAX_HITS_PER_BACKEND = 500
DEFAULT_MAX_HITS_TOTAL = 5000
DEFAULT_PER_BACKEND_TIMEOUT_S = 60.0
DEFAULT_PARALLELISM = 8
MAX_REGEX_CHARS = 512
MAX_GENERIC_VISITED = 100_000

_DANGEROUS_REGEX_RE = re.compile(
    r"\((?:[^()\\]|\\.){0,256}[+*](?:[^()\\]|\\.){0,256}\)"
    r"\s*(?:[+*]|\{\d*,?\d*\})"
)


# ---------------------------------------------------------------------------
# Query + result types
# ---------------------------------------------------------------------------


@dataclass
class SearchQuery:
    """What to search for.

    All filters are AND-combined. Empty fields are no-ops.

    Attributes:
        name: glob (``"*.conf"``, ``"app-*.log"``). Compared
            case-insensitively. Empty → match any.
        regex: regex on the basename. Stronger than ``name``; if both
            are set, both must match. Empty → no regex filter.
        contains: substring or regex (when ``contains_is_regex=True``)
            that must occur inside the file content. Empty → don't
            read content. **Costly** on cloud backends — combine with
            a tight ``name``/``size`` filter when possible.
        contains_is_regex: when True, ``contains`` is treated as a
            regex; when False (default), as a literal substring.
        min_size: ignore files smaller than this. -1 = no minimum.
        max_size: ignore files larger than this. -1 = no maximum.
        modified_after / modified_before: epoch-seconds bounds; 0.0
            disables the corresponding bound.
        roots: per-backend starting paths. ``[]`` = backend's home dir.
        max_depth: directory descent limit for the generic walker.
            ``-1`` = unlimited. Native adapters may ignore this if
            their protocol uses different navigation.
        ignore_dirs: skip directories whose basename matches any of
            these globs. Default skips the obvious noise.
    """

    name: str = ""
    regex: str = ""
    contains: str = ""
    contains_is_regex: bool = False
    min_size: int = -1
    max_size: int = -1
    modified_after: float = 0.0
    modified_before: float = 0.0
    roots: list[str] = field(default_factory=list)
    max_depth: int = 6
    ignore_dirs: tuple[str, ...] = (
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "__pycache__",
        ".tox",
        ".venv",
        "venv",
        ".cache",
        ".pytest_cache",
    )
    _compiled_regex: re.Pattern[str] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )
    _compiled_contains: re.Pattern[str] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def validate(self) -> None:
        """Validate fields that can otherwise fail late or consume CPU."""
        _validate_text(self.name, "name")
        _validate_text(self.regex, "regex")
        _validate_text(self.contains, "contains")
        _validate_int_bound(self.min_size, "min_size")
        _validate_int_bound(self.max_size, "max_size")
        if self.min_size >= 0 and self.max_size >= 0 and self.min_size > self.max_size:
            raise ValueError("min_size must be <= max_size")
        if not isinstance(self.max_depth, int) or isinstance(self.max_depth, bool):
            raise ValueError("max_depth must be an integer")
        if self.max_depth < -1:
            raise ValueError("max_depth must be -1 or greater")
        self.modified_after = _validate_epoch_bound(
            self.modified_after,
            "modified_after",
        )
        self.modified_before = _validate_epoch_bound(
            self.modified_before,
            "modified_before",
        )
        if not isinstance(self.roots, (list, tuple)):
            raise ValueError("roots must be a list of strings")
        for root in self.roots:
            _validate_text(root, "roots[]")
        if not isinstance(self.roots, list):
            self.roots = list(self.roots)
        self._compiled_regex = _compile_user_regex(self.regex, "regex")
        if self.contains_is_regex:
            self._compiled_contains = _compile_user_regex(
                self.contains,
                "contains",
            )
        else:
            self._compiled_contains = None

    def matches_name(self, name: str) -> bool:
        if self.name and not fnmatch.fnmatch(name.lower(), self.name.lower()):
            return False
        if self.regex:
            pattern = self._compiled_regex
            if pattern is None:
                pattern = _compile_user_regex(self.regex, "regex")
                self._compiled_regex = pattern
            if not pattern.search(name):
                return False
        return True

    def matches_size(self, size: int) -> bool:
        if self.min_size >= 0 and size < self.min_size:
            return False
        if self.max_size >= 0 and size > self.max_size:
            return False
        return True

    def matches_mtime(self, mtime: float) -> bool:
        if self.modified_after and mtime < self.modified_after:
            return False
        if self.modified_before and mtime > self.modified_before:
            return False
        return True

    def contains_regex(self) -> re.Pattern[str] | None:
        if not self.contains or not self.contains_is_regex:
            return None
        if self._compiled_contains is None:
            self._compiled_contains = _compile_user_regex(
                self.contains,
                "contains",
            )
        return self._compiled_contains


def _compile_user_regex(pattern: str, field_name: str) -> re.Pattern[str] | None:
    if not pattern:
        return None
    if len(pattern) > MAX_REGEX_CHARS:
        raise ValueError(f"{field_name} regex is too long; limit is {MAX_REGEX_CHARS} chars")
    if _DANGEROUS_REGEX_RE.search(pattern):
        raise ValueError(f"{field_name} regex rejected: nested quantified groups are unsafe")
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"{field_name} regex is invalid: {exc}") from exc


def _validate_text(value: object, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")


def _validate_int_bound(value: object, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    if value < -1:
        raise ValueError(f"{field_name} must be -1 or greater")


def _validate_epoch_bound(value: object, field_name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a finite timestamp")
    try:
        out = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a finite timestamp") from exc
    if not math.isfinite(out) or out < 0:
        raise ValueError(f"{field_name} must be a finite timestamp >= 0")
    return out


@dataclass
class SearchHit:
    """One result row."""

    backend_label: str
    path: str
    size: int = 0
    mtime: float = 0.0
    is_dir: bool = False
    snippet: str = ""  # Short content excerpt for ``contains`` matches.
    score: float = 1.0  # Reserved for ranked-search adapters.
    warning: str = ""  # Non-fatal note from the adapter.


@dataclass
class SearchResult:
    """Aggregated federation result."""

    hits: list[SearchHit] = field(default_factory=list)
    per_backend: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    elapsed_s: float = 0.0
    truncated: bool = False  # True if any cap fired


# ---------------------------------------------------------------------------
# Adapter registry
# ---------------------------------------------------------------------------

# Each adapter takes (backend, query, max_hits) and returns hits.
SearchAdapter = Callable[[Any, SearchQuery, int], list[SearchHit]]
_ADAPTERS: dict[str, SearchAdapter] = {}


def register_adapter(protocol: str, adapter: SearchAdapter) -> None:
    """Plug in a per-protocol search adapter."""
    _ADAPTERS[protocol.strip().lower()] = adapter


def _label(backend) -> str:
    return getattr(backend, "name", type(backend).__name__)


def _backend_protocol(backend) -> str:
    """Best-effort protocol guess from class name. Adapters are keyed
    by the backend-registry protocol_id which we cannot import without
    a circular dep — fall back to a class-name heuristic.

    Backends that want explicit routing can attach a
    ``search_protocol`` attribute.
    """
    explicit = getattr(backend, "search_protocol", "") or ""
    if explicit:
        return explicit.lower()
    cls = type(backend).__name__.lower()
    for proto in (
        "sftp",
        "scp",
        "ssh",
        "ftp",
        "smb",
        "s3",
        "webdav",
        "imap",
        "pop3",
        "nntp",
        "gopher",
        "redis",
        "mongo",
        "postgres",
        "sqlite",
        "rsync",
        "git",
        "svn",
        "azure",
        "dropbox",
        "onedrive",
        "gdrive",
        "telnet",
        "ramfs",
        "local",
    ):
        if proto in cls:
            return proto
    return ""


# ---------------------------------------------------------------------------
# Generic walker — fallback for protocols without a native adapter
# ---------------------------------------------------------------------------


def _generic_adapter(
    backend,
    query: SearchQuery,
    max_hits: int,
) -> list[SearchHit]:
    """Walk the tree client-side. Slow but always correct."""
    label = _label(backend)
    hits: list[SearchHit] = []
    roots = query.roots or [backend.home() if hasattr(backend, "home") else "/"]
    visited: set[str] = set()

    def _push(item: Any, full_path: str) -> bool:
        size = int(getattr(item, "size", 0) or 0)
        if not query.matches_size(size):
            return False
        mtime = _to_epoch(getattr(item, "modified", None))
        if not query.matches_mtime(mtime):
            return False
        snippet = ""
        if query.contains:
            snippet = _read_snippet_for_match(backend, full_path, query)
            if not snippet:
                return False
        hits.append(
            SearchHit(
                backend_label=label,
                path=full_path,
                size=size,
                mtime=mtime,
                is_dir=bool(getattr(item, "is_dir", False)),
                snippet=snippet,
            )
        )
        return True

    def _walk(path: str, depth: int) -> None:
        if len(hits) >= max_hits:
            return
        if len(visited) >= MAX_GENERIC_VISITED:
            log.warning(
                "search: visited cap of %d paths reached on %s",
                MAX_GENERIC_VISITED,
                label,
            )
            return
        if path in visited:
            return
        visited.add(path)
        try:
            entries = backend.list_dir(path)
        except OSError as exc:
            log.debug("search: list_dir(%s) failed on %s: %s", path, label, exc)
            return
        for item in entries:
            if len(hits) >= max_hits:
                return
            name = item.name
            if any(fnmatch.fnmatch(name, ign) for ign in query.ignore_dirs):
                continue
            if hasattr(backend, "join"):
                full = backend.join(path, name)
            else:
                full = f"{path.rstrip('/')}/{name}"
            if getattr(item, "is_dir", False):
                if query.max_depth < 0 or depth < query.max_depth:
                    _walk(full, depth + 1)
                continue
            if query.matches_name(name):
                _push(item, full)

    for root in roots:
        _walk(root, 0)
    return hits


def _to_epoch(raw: Any) -> float:
    if raw is None:
        return 0.0
    if hasattr(raw, "timestamp"):
        try:
            return float(raw.timestamp())
        except (OSError, OverflowError, ValueError):
            return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def _read_snippet_for_match(
    backend,
    path: str,
    query: SearchQuery,
    *,
    cap: int = 64 * 1024,
) -> str:
    """Read up to ``cap`` bytes and check ``query.contains``.

    Returns a short text snippet (the matching line + 60 chars context)
    on hit, or the empty string on miss / unreadable. NEVER raises.
    """
    try:
        handle = backend.open_read(path)
    except OSError as exc:
        log.debug("search: open_read(%s) failed: %s", path, exc)
        return ""
    try:
        data = handle.read(cap)
    except OSError:
        return ""
    finally:
        try:
            handle.close()
        except Exception as exc:  # noqa: BLE001
            log.debug("search: close raised: %s", exc)
    text = data.decode("utf-8", errors="replace")
    if query.contains_is_regex:
        pattern = query.contains_regex()
        if pattern is None:
            return ""
        m = pattern.search(text)
        if not m:
            return ""
        start = max(0, m.start() - 30)
        end = min(len(text), m.end() + 30)
        return text[start:end].replace("\n", " ⏎ ")[:200]
    needle = query.contains
    idx = text.find(needle) if needle else -1
    if idx < 0:
        # Case-insensitive second pass.
        idx = text.lower().find(needle.lower())
        if idx < 0:
            return ""
    start = max(0, idx - 30)
    end = min(len(text), idx + len(needle) + 30)
    return text[start:end].replace("\n", " ⏎ ")[:200]


# ---------------------------------------------------------------------------
# IMAP adapter — uses the IMAP SEARCH command, no client-side walk.
# ---------------------------------------------------------------------------


def _imap_adapter(
    backend,
    query: SearchQuery,
    max_hits: int,
) -> list[SearchHit]:
    label = _label(backend)
    if not hasattr(backend, "search_messages"):
        log.debug("imap adapter: backend has no search_messages — falling through")
        return _generic_adapter(backend, query, max_hits)
    criteria: list[str] = []
    if query.contains:
        # IMAP TEXT is body+headers substring; IMAP doesn't speak regex
        # natively. If the caller passed a regex we fall back to client-side.
        if query.contains_is_regex:
            return _generic_adapter(backend, query, max_hits)
        criteria.extend(["TEXT", _imap_quote(query.contains)])
    if query.modified_after:
        criteria.extend(["SINCE", _imap_date(query.modified_after)])
    if query.modified_before:
        criteria.extend(["BEFORE", _imap_date(query.modified_before)])
    if not criteria:
        criteria = ["ALL"]
    try:
        message_ids = backend.search_messages(" ".join(criteria))
    except (OSError, AttributeError) as exc:
        log.debug("imap adapter: search_messages failed: %s", exc)
        return _generic_adapter(backend, query, max_hits)

    hits: list[SearchHit] = []
    for msg_id in message_ids[:max_hits]:
        hits.append(
            SearchHit(
                backend_label=label,
                path=str(msg_id),
                warning="IMAP returns message IDs, not paths; use imap_search verb to retrieve",
            )
        )
    return hits


def _imap_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _imap_date(epoch: float) -> str:
    import datetime as _dt

    return _dt.datetime.fromtimestamp(epoch).strftime("%d-%b-%Y")


# ---------------------------------------------------------------------------
# DB-FS adapters — Postgres / SQLite / Mongo. They have schema'd
# tables with a ``path`` + ``content`` column that we can SELECT
# against without walking the FS.
# ---------------------------------------------------------------------------


def _dbfs_adapter(
    backend,
    query: SearchQuery,
    max_hits: int,
) -> list[SearchHit]:
    """Use the DB-FS native query if available.

    The DB-FS backends (postgres / sqlite / mongo / redis) all keep a
    ``files`` table/collection with ``path`` + ``size`` + ``mtime`` +
    ``content``. If the backend exposes ``find_by_query`` we use that;
    otherwise we fall back to the generic walker (still correct, just
    not as fast as native SQL).
    """
    if not hasattr(backend, "find_by_query"):
        return _generic_adapter(backend, query, max_hits)
    label = _label(backend)
    try:
        rows = backend.find_by_query(
            name_glob=query.name or None,
            contains=query.contains or None,
            contains_is_regex=query.contains_is_regex,
            min_size=query.min_size if query.min_size >= 0 else None,
            max_size=query.max_size if query.max_size >= 0 else None,
            limit=max_hits,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("dbfs adapter: find_by_query failed: %s", exc)
        return _generic_adapter(backend, query, max_hits)
    hits: list[SearchHit] = []
    for row in rows:
        hits.append(
            SearchHit(
                backend_label=label,
                path=str(row.get("path", "")),
                size=int(row.get("size", 0) or 0),
                mtime=_to_epoch(row.get("mtime")),
                is_dir=bool(row.get("is_dir", False)),
                snippet=str(row.get("snippet", ""))[:200],
            )
        )
    return hits


# ---------------------------------------------------------------------------
# Adapter registration
# ---------------------------------------------------------------------------

# IMAP → native SEARCH. POP3 has no SEARCH; falls back to generic.
register_adapter("imap", _imap_adapter)

# DB-FS family — try native query first; the adapter itself
# falls back to generic if the optional method is absent.
for _proto in ("postgres", "sqlite", "mongo", "redis"):
    register_adapter(_proto, _dbfs_adapter)


# Note: SFTP could shell out to ``find / -name foo`` for big speedups,
# but that requires a remote shell + careful escaping; the generic
# walker is safer for now and the SSH backend's ``exec`` verb is
# already exposed for power users.


# ---------------------------------------------------------------------------
# Federation
# ---------------------------------------------------------------------------


def federated_search(
    backends: list,
    query: SearchQuery,
    *,
    max_hits_per_backend: int = DEFAULT_MAX_HITS_PER_BACKEND,
    max_hits_total: int = DEFAULT_MAX_HITS_TOTAL,
    parallelism: int = DEFAULT_PARALLELISM,
    per_backend_timeout_s: float = DEFAULT_PER_BACKEND_TIMEOUT_S,
    progress: Callable[[SearchHit], None] | None = None,
) -> SearchResult:
    """Run ``query`` against every backend in parallel.

    Each backend gets the most-specific registered adapter; if none
    matches, the generic client-side walker runs. Results are merged
    in arrival order.
    """
    result = SearchResult()
    started = time.monotonic()
    try:
        query.validate()
    except ValueError as exc:
        result.errors["query"] = str(exc)
        result.elapsed_s = time.monotonic() - started
        return result
    if not backends:
        result.elapsed_s = time.monotonic() - started
        return result

    # Lock protects shared mutation of result.hits + early-stop checks
    # from the worker threads.
    lock = threading.Lock()
    stop_flag = threading.Event()

    # Per-backend start timestamps so the timeout budget begins when the
    # adapter actually starts executing, not when the future was queued.
    # Without this, a backend serialised behind a busy worker spends part
    # or all of its budget waiting for a slot and gets falsely timed out.
    # Keyed by submission INDEX (not id(backend)) so duplicate
    # backend objects in the input list each get their own clock instead
    # of inheriting a sibling's started_at.
    started_at: dict[int, float] = {}
    started_lock = threading.Lock()

    def _run(idx: int, backend) -> tuple[str, list[SearchHit] | str]:
        label = _label(backend)
        with started_lock:
            started_at[idx] = time.monotonic()
        proto = _backend_protocol(backend)
        adapter = _ADAPTERS.get(proto, _generic_adapter)
        try:
            hits = adapter(backend, query, max_hits_per_backend)
        except Exception as exc:  # noqa: BLE001
            return (label, f"{type(exc).__name__}: {exc}")
        return (label, hits)

    max_workers = max(1, min(parallelism, len(backends)))
    pool = ThreadPoolExecutor(max_workers=max_workers)
    timeout_keys = probe_timeout_keys_for_count(len(backends))
    # Map future -> (submission index, backend) so the deadline clock and
    # the timed-out error reporting share the same index key.
    futures = {
        pool.submit(_run, timeout_keys[i], b): (timeout_keys[i], b)
        for i, b in enumerate(backends)
    }
    pending = set(futures)
    budget = max(0.0, float(per_backend_timeout_s))
    # Cap the wake-up cadence when no future has begun running yet so the
    # loop doesn't busy-spin on the deadline check.
    queue_poll_s = min(0.05, budget) if budget > 0 else 0.05
    try:
        while pending and not stop_flag.is_set():
            now = time.monotonic()
            running_deadlines: list[float] = []
            for fut in pending:
                idx, _b = futures[fut]
                with started_lock:
                    st = started_at.get(idx)
                if st is not None:
                    running_deadlines.append(st + budget)
            if running_deadlines:
                wake_in = min(running_deadlines) - now
            else:
                wake_in = queue_poll_s
            if wake_in <= 0:
                # A running future has exhausted its per-backend budget.
                # Cancel just that one (cancellation of a running thread
                # is best-effort; we still record the timeout error).
                # Defense-in-depth: delegate the
                # overdue computation to security/federation_timeout.py
                # so the "started_at missing → not overdue" invariant is
                # preserved even if this loop is later refactored, and
                # the index-keyed sibling helper is shared with
                # multi_view's per-probe deadline accounting.
                with started_lock:
                    pending_started = {
                        futures[fut][0]: started_at.get(futures[fut][0])
                        for fut in pending
                    }
                overdue_idx = set(probe_overdue_indices(
                    started_at=pending_started,
                    budget_s=budget,
                    now=now,
                ))
                timed_out: list = [
                    fut for fut in pending if futures[fut][0] in overdue_idx
                ]
                for fut in timed_out:
                    label = _label(futures[fut][1])
                    fut.cancel()
                    result.errors[label] = (
                        f"TimeoutError: exceeded {per_backend_timeout_s:.1f}s"
                    )
                    pending.discard(fut)
                continue
            done, pending = wait(
                pending,
                timeout=wake_in,
                return_when=FIRST_COMPLETED,
            )
            if not done:
                # Timeout fired before anything completed; re-check the
                # per-backend deadlines on the next iteration.
                continue
            for fut in done:
                _idx, backend = futures[fut]
                label = _label(backend)
                if fut.cancelled():
                    result.errors[label] = f"TimeoutError: exceeded {per_backend_timeout_s:.1f}s"
                    continue
                try:
                    label, payload = fut.result()
                except Exception as exc:  # noqa: BLE001
                    result.errors[label] = f"{type(exc).__name__}: {exc}"
                    continue
                if isinstance(payload, str):
                    result.errors[label] = payload
                    continue
                with lock:
                    for hit in payload:
                        if len(result.hits) >= max_hits_total:
                            result.truncated = True
                            stop_flag.set()
                            break
                        result.hits.append(hit)
                        if progress is not None:
                            try:
                                progress(hit)
                            except Exception as exc:  # noqa: BLE001
                                log.warning("search progress callback raised: %s", exc)
                    result.per_backend[label] = len(payload)
                    if stop_flag.is_set():
                        break
        for fut in pending:
            _idx, backend = futures[fut]
            label = _label(backend)
            fut.cancel()
            result.errors.setdefault(
                label,
                f"TimeoutError: exceeded {per_backend_timeout_s:.1f}s",
            )
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    result.elapsed_s = time.monotonic() - started
    return result


def render_result(result: SearchResult, *, max_lines: int = 80) -> str:
    """Pretty-print a :class:`SearchResult` for the REPL."""
    lines: list[str] = []
    lines.append(
        f"federated_search: {len(result.hits)} hits across "
        f"{len(result.per_backend)} backend(s) in {result.elapsed_s:.2f}s"
        + (" (truncated)" if result.truncated else "")
    )
    for hit in result.hits[:max_lines]:
        snip = f" — {hit.snippet}" if hit.snippet else ""
        lines.append(f"  {hit.backend_label:<24} {hit.path}{snip}")
    if len(result.hits) > max_lines:
        lines.append(f"  ... ({len(result.hits) - max_lines} more)")
    if result.errors:
        lines.append("errors:")
        for label, err in result.errors.items():
            lines.append(f"  {label}: {err}")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_MAX_HITS_PER_BACKEND",
    "DEFAULT_MAX_HITS_TOTAL",
    "SearchAdapter",
    "SearchHit",
    "SearchQuery",
    "SearchResult",
    "federated_search",
    "register_adapter",
    "render_result",
]
