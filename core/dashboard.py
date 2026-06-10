"""Federation-status dashboard — one screen, every connection.

Pulls live state from:

* :mod:`core.connection_manager` — what's open, how many references.
* :mod:`core.conn_health`        — last-probe latency / staleness.
* :mod:`core.visit_history`      — when each profile was last touched.
* :mod:`core.operation_journal`  — N most recent mutating operations.
* Optionally per-backend ``disk_usage()`` for capacity columns
  (skipped when expensive / unsupported).

Renders three formats:

* :func:`render_text` — fixed-width text for the status bar / REPL.
* :func:`render_markdown` — markdown for an MCP/LLM tool response.
* :func:`render_json` — structured JSON the GUI can consume.

Read-only by design. The dashboard is always safe to call; it never
performs mutating ops.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from dataclasses import asdict, dataclass, field

log = logging.getLogger(__name__)

CAPACITY_TIMEOUT_S = 5.0
CAPACITY_PROBE_MAX_THREADS = 16
_CAPACITY_SEMAPHORE = threading.BoundedSemaphore(CAPACITY_PROBE_MAX_THREADS)


@dataclass
class HostRow:
    profile_key: str
    protocol: str
    label: str
    healthy: bool = False
    stale: bool = False
    last_latency_ms: float | None = None
    median_latency_ms: float | None = None
    last_visit_ago_s: float | None = None
    last_path: str = ""
    visit_count: int = 0
    refs: int = 0
    capacity_total: int = 0
    capacity_used: int = 0
    capacity_free: int = 0


@dataclass
class RecentOp:
    ts: float
    verb: str
    backend_label: str
    path: str
    detail: str = ""


@dataclass
class DashboardSnapshot:
    captured_at: float
    rows: list[HostRow] = field(default_factory=list)
    recent_ops: list[RecentOp] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def healthy_count(self) -> int:
        return sum(1 for r in self.rows if r.healthy and not r.stale)

    def stale_count(self) -> int:
        return sum(1 for r in self.rows if r.stale)


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


def snapshot(
    *,
    with_capacity: bool = False,
    recent_ops_limit: int = 10,
) -> DashboardSnapshot:
    """Build a one-shot snapshot of the federation."""
    snap = DashboardSnapshot(captured_at=time.time())

    # Pull health records.
    health_by_key: dict[str, object] = {}
    try:
        from core.conn_health import get_manager

        for h in get_manager().all():
            health_by_key[h.profile_key] = h
    except Exception as exc:  # noqa: BLE001
        log.debug("dashboard: conn_health unavailable: %s", exc)
        snap.notes.append(f"conn_health: {exc}")

    # Pull visit history per host.
    visits_by_host: dict[str, object] = {}
    try:
        from core.visit_history import where_was_i

        items = where_was_i(host=None) or []
        for v in items:
            visits_by_host[v.host.lower()] = v
    except Exception as exc:  # noqa: BLE001
        log.debug("dashboard: visit_history unavailable: %s", exc)

    # Walk health-manager records — that's the authoritative list of
    # "currently open" connections. Every health record corresponds to
    # an enrolled session.
    for key, health in health_by_key.items():
        row = HostRow(
            profile_key=key,
            protocol=getattr(health, "protocol", ""),
            label=getattr(health, "label", key),
        )
        row.stale = bool(getattr(health, "stale", False))
        latency = getattr(health, "last_latency_s", None)
        median = getattr(health, "median_latency_s", None)
        if latency is not None:
            row.last_latency_ms = latency * 1000
        if median is not None:
            row.median_latency_ms = median * 1000
        row.healthy = (not row.stale) and row.last_latency_ms is not None

        # Match against visit_history by host substring.
        for hl, v in visits_by_host.items():
            if hl and hl in row.label.lower():
                row.visit_count = int(getattr(v, "visit_count", 0) or 0)
                last_seen = float(getattr(v, "last_seen", 0) or 0)
                if last_seen:
                    row.last_visit_ago_s = max(0.0, snap.captured_at - last_seen)
                row.last_path = str(getattr(v, "last_path", "") or "")[:120]
                break

        snap.rows.append(row)

    # If health-manager has nothing (no probes wired yet), fall back to
    # the connection manager's session keys.
    if not snap.rows:
        try:
            from core.connection_manager import ConnectionManager

            # We don't have the singleton; the GUI keeps one but the
            # API surface allows callers to instantiate ad-hoc.
            cm = ConnectionManager()
            for session in cm.active_sessions():
                label = getattr(session, "name", type(session).__name__)
                snap.rows.append(
                    HostRow(
                        profile_key=label,
                        protocol="?",
                        label=label,
                        healthy=True,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            log.debug("dashboard: cm fallback failed: %s", exc)

    # Recent operations.
    try:
        from core.operation_journal import read_recent

        for entry in read_recent(limit=recent_ops_limit) or []:
            if not isinstance(entry, dict):
                continue
            snap.recent_ops.append(
                RecentOp(
                    ts=float(entry.get("ts", 0.0) or 0.0),
                    verb=str(entry.get("verb", "")),
                    backend_label=str(entry.get("backend", entry.get("backend_label", "")))[:40],
                    path=str(entry.get("path", ""))[:80],
                    detail=str(entry.get("detail", ""))[:120],
                )
            )
    except Exception as exc:  # noqa: BLE001
        log.debug("dashboard: operation_journal unavailable: %s", exc)

    if with_capacity:
        snap.notes.append(
            "capacity columns require an opened backend; use snapshot_with_backends() for that."
        )

    return snap


def snapshot_with_backends(
    backends,
    *,
    recent_ops_limit: int = 10,
) -> DashboardSnapshot:
    """Like :func:`snapshot` plus per-backend ``disk_usage()`` columns.

    ``backends`` is a list of opened backend instances. Each backend's
    ``disk_usage()`` is called once with a 5-second budget; failures
    leave the capacity columns at 0.
    """
    snap = snapshot(recent_ops_limit=recent_ops_limit)
    by_label: dict[str, HostRow] = {r.label: r for r in snap.rows}
    for backend in backends:
        label = getattr(backend, "name", type(backend).__name__)
        row = by_label.get(label)
        if row is None:
            row = HostRow(profile_key=label, protocol="", label=label, healthy=True)
            snap.rows.append(row)
            by_label[label] = row
        root = backend.home() if hasattr(backend, "home") else "/"
        try:
            total, used, free = _disk_usage_with_timeout(
                backend,
                root,
                timeout_s=CAPACITY_TIMEOUT_S,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("dashboard: disk_usage(%s) failed: %s", label, exc)
            continue
        row.capacity_total = int(total or 0)
        row.capacity_used = int(used or 0)
        row.capacity_free = int(free or 0)
    return snap


def _disk_usage_with_timeout(backend, root: str, *, timeout_s: float) -> tuple[int, int, int]:
    """Call backend.disk_usage without letting dashboard hang forever."""
    semaphore = _CAPACITY_SEMAPHORE
    if not semaphore.acquire(blocking=False):
        raise TimeoutError("disk_usage capacity probes saturated")
    q: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def _worker() -> None:
        try:
            q.put((True, backend.disk_usage(root)))
        except Exception as exc:  # noqa: BLE001
            q.put((False, exc))
        finally:
            semaphore.release()

    thread = threading.Thread(
        target=_worker,
        name=f"axross-dashboard-du-{getattr(backend, 'name', type(backend).__name__)}",
        daemon=True,
    )
    try:
        thread.start()
    except BaseException:
        semaphore.release()
        raise
    thread.join(timeout=max(0.0, timeout_s))
    if thread.is_alive():
        raise TimeoutError(f"disk_usage exceeded {timeout_s:.1f}s")
    ok, payload = q.get_nowait()
    if not ok:
        raise payload  # type: ignore[misc]
    total, used, free = payload  # type: ignore[misc]
    return int(total or 0), int(used or 0), int(free or 0)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _human_bytes(n: int) -> str:
    if n <= 0:
        return "—"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    val = float(n)
    for u in units:
        if val < 1024:
            return f"{val:.1f} {u}"
        val /= 1024
    return f"{val:.1f} EiB"


def _human_age(seconds_ago: float | None) -> str:
    if seconds_ago is None or seconds_ago < 0:
        return "—"
    if seconds_ago < 60:
        return "now"
    if seconds_ago < 3600:
        return f"{int(seconds_ago / 60)}m"
    if seconds_ago < 86400:
        return f"{int(seconds_ago / 3600)}h"
    return f"{int(seconds_ago / 86400)}d"


def render_text(snap: DashboardSnapshot, *, with_capacity: bool = False) -> str:
    lines: list[str] = []
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snap.captured_at))
    lines.append(f"axross federation status — {when}")
    lines.append(
        f"  {len(snap.rows)} connection(s), "
        f"{snap.healthy_count()} healthy, "
        f"{snap.stale_count()} stale"
    )
    if not snap.rows:
        lines.append("  (no active connections)")
    else:
        header = f"  {'STATE':<7} {'TARGET':<32} {'LAT':>6} {'MED':>6} {'LAST':>6}  PATH"
        if with_capacity:
            header += "  CAPACITY"
        lines.append(header)
        for row in snap.rows:
            if row.stale:
                state = "✗ stale"
            elif row.last_latency_ms is None:
                state = "· pend"
            else:
                state = "✓ ok  "
            lat = f"{row.last_latency_ms:.0f}ms" if row.last_latency_ms is not None else "—"
            med = f"{row.median_latency_ms:.0f}ms" if row.median_latency_ms is not None else "—"
            age = _human_age(row.last_visit_ago_s)
            line = (
                f"  {state:<7} {row.label:<32} {lat:>6} {med:>6} {age:>6}  {row.last_path or '—'}"
            )
            if with_capacity:
                cap = f"{_human_bytes(row.capacity_used)}/{_human_bytes(row.capacity_total)}"
                line += f"  {cap}"
            lines.append(line)
    if snap.recent_ops:
        lines.append("")
        lines.append("recent ops:")
        for op in snap.recent_ops:
            ts = time.strftime("%H:%M:%S", time.localtime(op.ts)) if op.ts else "—"
            lines.append(f"  {ts}  {op.verb:<10} {op.backend_label:<24} {op.path}")
    if snap.notes:
        lines.append("")
        lines.extend(f"  ⓘ  {n}" for n in snap.notes)
    return "\n".join(lines)


def render_markdown(snap: DashboardSnapshot) -> str:
    """Markdown table — for MCP / LLM tool responses."""
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snap.captured_at))
    out: list[str] = []
    out.append(f"### Axross federation status — {when}")
    out.append("")
    out.append(
        f"**{len(snap.rows)} connection(s)** — "
        f"healthy: {snap.healthy_count()}, stale: {snap.stale_count()}"
    )
    out.append("")
    if snap.rows:
        out.append("| State | Target | Latency | Median | Last visit | Path |")
        out.append("|---|---|---:|---:|---:|---|")
        for r in snap.rows:
            state = "stale" if r.stale else ("pending" if r.last_latency_ms is None else "ok")
            lat = f"{r.last_latency_ms:.0f} ms" if r.last_latency_ms is not None else "—"
            med = f"{r.median_latency_ms:.0f} ms" if r.median_latency_ms is not None else "—"
            age = _human_age(r.last_visit_ago_s)
            out.append(
                f"| {state} | `{r.label}` | {lat} | {med} | {age} | `{r.last_path or '—'}` |"
            )
    if snap.recent_ops:
        out.append("")
        out.append("#### Recent operations")
        out.append("")
        out.append("| When | Verb | Backend | Path |")
        out.append("|---|---|---|---|")
        for op in snap.recent_ops:
            ts = time.strftime("%H:%M:%S", time.localtime(op.ts)) if op.ts else "—"
            out.append(f"| {ts} | `{op.verb}` | `{op.backend_label}` | `{op.path}` |")
    return "\n".join(out)


def render_json(snap: DashboardSnapshot) -> str:
    return json.dumps(
        {
            "captured_at": snap.captured_at,
            "rows": [asdict(r) for r in snap.rows],
            "recent_ops": [asdict(o) for o in snap.recent_ops],
            "notes": list(snap.notes),
            "healthy_count": snap.healthy_count(),
            "stale_count": snap.stale_count(),
        },
        indent=2,
    )


__all__ = [
    "DashboardSnapshot",
    "HostRow",
    "RecentOp",
    "render_json",
    "render_markdown",
    "render_text",
    "snapshot",
    "snapshot_with_backends",
]
