"""Connection-health pulse — live latency / liveness for every
active backend session.

A status-bar indicator wants to answer "is this connection healthy
*right now*?" without nagging the wire too hard. The classic story is
"my SFTP session went stale 8 minutes ago but axross only finds out
when I click on a directory and wait 30 seconds for a TCP RST".

This module attaches a lightweight per-session pulse. Once enrolled, a
session is probed on a configurable cadence (default every 30 s) with
the cheapest no-op the protocol provides:

* SFTP / SSH         — ``transport.send_ignore()``
* SCP                — ``transport.send_ignore()`` (same SSH session)
* FTP / FTPS         — ``NOOP``
* IMAP               — ``NOOP``
* POP3               — ``NOOP``
* WebDAV             — ``OPTIONS /``
* SMB                — fallback to ``backend.connected`` getter
* Generic fallback   — ``backend.connected`` property if it exists

If the probe raises, the entry is marked ``stale`` and exposed to
callers (status bar, dashboard, MCP) so they can drop the session and
reconnect on the next user action.

The poll loop uses one daemon thread shared across all enrolled
sessions; we don't spawn one thread per connection. Callers
``enroll(profile_key, session)`` once on connect and ``unenroll`` on
disconnect — the manager does the rest.

Privacy: the latency record stores host:port + measured RTT only; no
content, no credentials.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_INTERVAL_S = 30.0
MIN_INTERVAL_S = 1.0
HISTORY_LEN = 16  # ring buffer per session


# ---------------------------------------------------------------------------
# Per-session record
# ---------------------------------------------------------------------------


@dataclass
class HealthSample:
    ts: float
    latency_s: float | None  # None on probe failure
    error: str = ""


@dataclass
class HealthRecord:
    profile_key: str  # opaque key, supplied by caller
    protocol: str
    label: str  # human-readable, e.g. "alice@host:22"
    enrolled_at: float = field(default_factory=time.time)
    last_probe_at: float = 0.0
    last_latency_s: float | None = None
    consecutive_failures: int = 0
    stale: bool = False
    history: list[HealthSample] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.stale and self.last_latency_s is not None

    @property
    def median_latency_s(self) -> float | None:
        latencies = [s.latency_s for s in self.history if s.latency_s is not None]
        if not latencies:
            return None
        latencies.sort()
        n = len(latencies)
        return latencies[n // 2] if n % 2 else (latencies[n // 2 - 1] + latencies[n // 2]) / 2


# ---------------------------------------------------------------------------
# Probe selection
# ---------------------------------------------------------------------------


def _probe_for_protocol(protocol: str) -> Callable[[Any], None] | None:
    """Pick the cheapest no-op the protocol can do. ``None`` → fall
    back to the generic ``connected`` property check."""
    p = (protocol or "").lower()
    return _PROBES.get(p)


def _probe_sftp(session: Any) -> None:
    """SSH transport-level keepalive — ``send_ignore`` is documented
    as a no-op probe by the OpenSSH protocol RFC and is the same hook
    paramiko uses for its own keepalive."""
    transport = getattr(session, "_transport", None) or getattr(session, "transport", None)
    if transport is None:
        # Fallback for backends that hide the transport — try a stat
        # of the home dir.
        sftp = getattr(session, "sftp", None) or getattr(session, "_sftp", None)
        if sftp is not None:
            sftp.normalize(".")
            return
        raise OSError("no transport for SFTP probe")
    if hasattr(transport, "send_ignore"):
        transport.send_ignore()
    elif hasattr(transport, "is_active"):
        if not transport.is_active():
            raise OSError("transport not active")
    else:
        raise OSError("transport has no probe hook")


def _probe_ftp(session: Any) -> None:
    ftp = getattr(session, "_ftp", None) or getattr(session, "ftp", None)
    if ftp is None:
        raise OSError("no ftplib handle to probe")
    ftp.voidcmd("NOOP")


def _probe_imap(session: Any) -> None:
    imap = getattr(session, "_imap", None) or getattr(session, "imap", None)
    if imap is None:
        raise OSError("no imaplib handle to probe")
    typ, _data = imap.noop()
    if typ != "OK":
        raise OSError(f"IMAP NOOP returned {typ}")


def _probe_pop3(session: Any) -> None:
    pop = getattr(session, "_pop", None) or getattr(session, "pop", None)
    if pop is None:
        raise OSError("no poplib handle to probe")
    pop.noop()


def _probe_webdav(session: Any) -> None:
    sess = getattr(session, "_session", None) or getattr(session, "session", None)
    url = getattr(session, "_base_url", "") or getattr(session, "base_url", "")
    if sess is None or not url:
        raise OSError("no requests.Session/url to probe")
    resp = sess.request("OPTIONS", url, timeout=10)
    if resp.status_code >= 500:
        raise OSError(f"OPTIONS returned {resp.status_code}")


_PROBES: dict[str, Callable[[Any], None]] = {
    "sftp": _probe_sftp,
    "scp": _probe_sftp,
    "ftp": _probe_ftp,
    "ftps": _probe_ftp,
    "imap": _probe_imap,
    "pop3": _probe_pop3,
    "webdav": _probe_webdav,
}


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class HealthManager:
    """Singleton-ish coordinator. Use :func:`get_manager` to access."""

    def __init__(self, interval_s: float = DEFAULT_INTERVAL_S) -> None:
        self._records: dict[str, HealthRecord] = {}
        self._sessions: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._interval = max(MIN_INTERVAL_S, float(interval_s))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def set_interval(self, seconds: float) -> None:
        with self._lock:
            self._interval = max(MIN_INTERVAL_S, float(seconds))

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="axross-conn-health",
                daemon=True,
            )
            self._thread.start()
            log.debug("conn_health: poll thread started (interval=%.1fs)", self._interval)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
            self._thread = None
        log.debug("conn_health: poll thread stopped")

    # ------------------------------------------------------------------
    # Enrolment
    # ------------------------------------------------------------------

    def enroll(
        self,
        profile_key: str,
        session: Any,
        *,
        protocol: str,
        label: str = "",
    ) -> HealthRecord:
        """Attach a session to the pulse loop."""
        with self._lock:
            record = HealthRecord(
                profile_key=profile_key,
                protocol=protocol,
                label=label or profile_key,
            )
            self._records[profile_key] = record
            self._sessions[profile_key] = session
            self.start()  # idempotent
            log.debug("conn_health: enrolled %s (%s)", profile_key, protocol)
            return record

    def unenroll(self, profile_key: str) -> None:
        with self._lock:
            self._records.pop(profile_key, None)
            self._sessions.pop(profile_key, None)
            log.debug("conn_health: unenrolled %s", profile_key)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def all(self) -> list[HealthRecord]:
        with self._lock:
            return list(self._records.values())

    def get(self, profile_key: str) -> HealthRecord | None:
        with self._lock:
            return self._records.get(profile_key)

    def probe_now(self, profile_key: str) -> HealthRecord | None:
        """Force an immediate probe for one record. Returns the
        updated record, or ``None`` if it isn't enrolled."""
        with self._lock:
            session = self._sessions.get(profile_key)
            record = self._records.get(profile_key)
        if session is None or record is None:
            return None
        self._probe_one(record, session)
        return record

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            with self._lock:
                items = list(self._sessions.items())
                records = dict(self._records)
            for profile_key, session in items:
                record = records.get(profile_key)
                if record is None:
                    continue
                if self._stop.is_set():
                    return
                try:
                    self._probe_one(record, session)
                except Exception as exc:  # noqa: BLE001
                    # Defensive — _probe_one already swallows everything,
                    # but if it doesn't we never want the daemon thread
                    # to die.
                    log.warning("conn_health probe error: %s", exc)

    def _probe_one(self, record: HealthRecord, session: Any) -> None:
        probe = _probe_for_protocol(record.protocol)
        t0 = time.monotonic()
        latency: float | None
        error = ""
        probe_ok: bool
        try:
            if probe is not None:
                probe(session)
            else:
                # Fallback: ask the session whether it considers itself
                # connected. This is a property read, not a wire probe,
                # so it's only useful for protocols that maintain a
                # liveness flag (most do).
                connected = getattr(session, "connected", None)
                if callable(connected):
                    if not connected():
                        raise OSError("connected() returned False")
                elif connected is False:
                    raise OSError("connected attribute is False")
                elif connected is None:
                    raise OSError(
                        f"no health probe registered for protocol {record.protocol!r} "
                        "and session exposes no connected state"
                    )
            latency = time.monotonic() - t0
            probe_ok = True
        except Exception as exc:  # noqa: BLE001
            latency = None
            error = str(exc)[:200]
            probe_ok = False
        sample = HealthSample(ts=time.time(), latency_s=latency, error=error)
        # Every record mutation runs inside `self._lock`. The
        # probe call itself stays outside (it's the slow part — wire
        # I/O on the protocol-specific noop) so a probe that hangs
        # cannot block unrelated enroll/unenroll/all() calls. But the
        # post-probe state update must be atomic: a concurrent probe
        # racing `consecutive_failures += 1` outside the lock can lose
        # increments, and the dashboard formatter can observe a torn
        # (stale=True, consecutive_failures=0) snapshot if last_probe_at
        # / history mutate under the lock while last_latency_s /
        # consecutive_failures / stale mutate outside it.
        with self._lock:
            record.last_latency_s = latency
            if probe_ok:
                record.consecutive_failures = 0
                record.stale = False
            else:
                record.consecutive_failures += 1
                # Two consecutive failures → mark stale. One failure
                # could be a single dropped packet over a flaky LTE
                # link.
                if record.consecutive_failures >= 2:
                    record.stale = True
            record.last_probe_at = sample.ts
            record.history.append(sample)
            if len(record.history) > HISTORY_LEN:
                record.history = record.history[-HISTORY_LEN:]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_GLOBAL: HealthManager | None = None


def get_manager() -> HealthManager:
    """Return the process-wide health manager. Lazily created."""
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = HealthManager()
    return _GLOBAL


def health_pulse() -> list[HealthRecord]:
    """Convenience: snapshot the current health records.

    Returns a list of :class:`HealthRecord`, sorted by most recent
    probe first.
    """
    items = get_manager().all()
    items.sort(key=lambda r: r.last_probe_at, reverse=True)
    return items


def format_pulse_line(r: HealthRecord) -> str:
    """One-line status renderer for REPL / status bar."""
    if r.stale:
        return f"  ✗ {r.label:<28} stale ({r.consecutive_failures}× fail)"
    if r.last_latency_s is None:
        return f"  · {r.label:<28} pending"
    return f"  ✓ {r.label:<28} {r.last_latency_s * 1000:>5.0f} ms"


__all__ = [
    "HealthManager",
    "HealthRecord",
    "HealthSample",
    "format_pulse_line",
    "get_manager",
    "health_pulse",
]
