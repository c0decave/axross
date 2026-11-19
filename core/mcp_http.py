"""HTTP + (optional) mTLS transport for the MCP server.

Wraps the same :func:`core.mcp_server._handle_request` and
:func:`core.mcp_server._build_tools` machinery as the stdio
transport. The HTTP flavour is for deployments where a stdio
subprocess isn't the right fit — a remote LLM runner, an MCP gateway
behind a reverse proxy, or a multi-tenant host where the operator
wants mTLS-based authentication before the JSON-RPC layer even
parses a byte.

Transport shape
---------------
``POST /messages``
    Body: one JSON-RPC request.
    Headers:
      * ``Mcp-Session-Id``: required on every POST after the one
        that carries ``initialize``. The server generates the id
        during the initialize handshake and returns it in the
        response header; the client stamps subsequent requests
        with it.
      * ``MCP-Protocol-Version`` (MCP 2025-06-18 and later): the
        revision initialize agreed on, on every request after it
        (POST, GET, DELETE). A revision the server does not speak,
        or another than the session's, is answered with 400.
    Response: ``application/json`` with one JSON-RPC response; 202
    without a body for a notification; HTTP 400 if the body isn't
    valid JSON or is a batch (an array: no supported revision has
    batches), 400 if the session id is missing on a non-initialize
    request, 404 if the session id is unknown or expired.

``GET /messages``
    ``Accept: text/event-stream`` opens an SSE notification stream
    for a previously established session. The stream relays
    ``notifications/progress`` and ``notifications/message`` frames
    queued during that session's tool calls. The connection stays
    open until the client disconnects, the session is deleted or
    evicted, or a newer GET /messages for the same session takes
    over: a session has at most one stream.

    Reconnect recovery: every event carries an ``id: N`` line with
    a session-scoped monotonic counter. A client that disconnected
    and comes back can supply ``Last-Event-ID: N`` in the GET
    request — the server walks its per-session replay ring forward
    from (N + 1) and emits anything newer before entering the
    live-pull loop. Ring size is ``SSE_REPLAY_BUFFER_SIZE`` (256);
    a reconnect with an id older than the oldest ring entry sees
    an event-id gap rather than silent data loss.

``DELETE /messages``
    Explicitly terminate a session. The server drops the session
    state (cancel registry, notification queue) and ends its open
    SSE stream. Unknown ids are
    answered with 404 so a double-delete doesn't loop.

``GET /health``
    Unauthenticated (needs to be reachable by reverse-proxy health
    probes). Returns ``{"server": "axross-mcp", "version": "…"}``.

mTLS
----
Enabled when :attr:`HTTPServerConfig.cert_file`,
:attr:`key_file` and :attr:`ca_file` are all supplied. The server
wraps its listening socket in an :class:`ssl.SSLContext` with
``verify_mode = CERT_REQUIRED`` and the given CA bundle. A client
that doesn't present a cert signed by the CA is rejected during the
TLS handshake — the HTTP layer never sees them, so path-based
allowlisting isn't needed.

A plain-HTTP mode (no TLS) is supported for local-loopback testing
(``127.0.0.1:…``) but refuses to bind to a non-loopback address
without TLS — that would ship JSON-RPC credentials over the wire
in cleartext, which is a footgun.

Bearer token
------------
Loopback is not a credential: every local user and process reaches
127.0.0.1. A plain-HTTP server therefore demands
``Authorization: Bearer <token>`` on every request but ``GET /health``
(401 otherwise). :attr:`HTTPServerConfig.auth_token` sets it; left
empty on a plain-HTTP server, :func:`build_server` generates one
(``server.auth_token``). ``axross --mcp-http`` hands it to the user
through :func:`publish_token` (a 0600 file). An mTLS server checks the
token only when one is configured - the client certificate already
authenticates.
"""

from __future__ import annotations

import hmac
import http.server
import ipaddress
import json
import logging
import os
import queue
import re
import secrets
import socket
import socketserver
import ssl
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core import mcp_server as _mcp

log = logging.getLogger(__name__)

#: The header a client of MCP 2025-06-18 and later sends on every request
#: after initialize, naming the revision it speaks (HTTP headers are
#: case-insensitive: ``Mcp-Protocol-Version`` is the same header).
PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"

# Cap on the POST /messages body size. A hostile client can set a
# huge Content-Length header and send nothing; rfile.read() would
# block the server thread waiting. 16 MiB is generous for a JSON-RPC
# payload — ``read_file`` responses cap at 4 MiB and outer JSON
# framing is small.
MAX_REQUEST_BYTES = 16 * 1024 * 1024

# Idle timeout for a session. An initialize without follow-up
# activity shouldn't hold resources forever. Tunable via server
# config for long-running batch workflows.
DEFAULT_SESSION_IDLE_SECONDS = 10 * 60  # 10 minutes
#: With the session cap reached, an initialize evicts the session that has
#: been idle longest - if it has been idle at least this long and runs
#: nothing (no task, no SSE stream) - instead of answering 503: sessions
#: left behind without a DELETE no longer lock everyone out.
SESSION_EVICTABLE_AFTER_SECONDS = 30.0
#: Sessions one client (address + credential) may hold at a time.
MAX_SESSIONS_PER_CLIENT = 32
#: Rate-limit buckets kept for clients (oldest unused dropped beyond it).
MAX_CLIENT_BUCKETS = 1024
#: Hard cap on live sessions. Each session owns a 10k-entry queue, a
#: replay ring and a log route, so an unauthenticated ``initialize``
#: loop must not be able to mint them without bound.
MAX_SESSIONS = 256
#: Socket timeout per connection, which also bounds the TLS handshake.
CONNECTION_TIMEOUT_SECONDS = 30.0
#: The whole request line, headers and body must arrive within this: a
#: client trickling one header byte every 20 s kept its connection - and a
#: thread - for good (3000 of them exhausted the threads).
REQUEST_READ_DEADLINE_SECONDS = 15.0
#: Connections served at once (each is a thread). A new one past it takes
#: the place of the oldest connection still sending its request (headers,
#: body or TLS handshake); when every connection is past that, it is closed.
MAX_CONNECTIONS = 1024
#: Connections one address may hold off loopback (on loopback every local
#: client is one address).
MAX_CONNECTIONS_PER_IP = 32
#: Bodies one client may have arriving at once (on loopback every local
#: client is one), and the slowest a body may arrive past its first
#: seconds: token holders trickling bodies held every connection.
MAX_SLOW_BODIES_PER_CLIENT = 16
#: The most of a refused request's body read past before closing.
DISCARD_BODY_BYTES = 1 << 20
#: Default of :func:`min_body_rate` (AXROSS_MCP_MIN_BODY_RATE, bytes/s).
MIN_BODY_RATE = 1024
BODY_RATE_GRACE_SECONDS = 10.0
#: File descriptors kept free besides the connections (log files, the
#: backends' sockets, temp files): the connection cap is sized to leave them.
FD_HEADROOM = 256
#: Once the token or client certificate is checked, the rest of the
#: request (its body) may take this long, and the connection is never
#: taken for a trickling attacker's.
AUTHENTICATED_BODY_DEADLINE_SECONDS = 300.0
#: tools/call requests one session may have running at once.
MAX_CALLS_PER_SESSION = 16

# Maximum number of queued notifications per session. A client that
# never consumes its SSE stream shouldn't be able to grow the queue
# unbounded (tool handlers emit progress from a fast loop).
MAX_QUEUED_NOTIFICATIONS = 10_000

# SSE stream keepalive interval — the loop falls through every N
# seconds with an empty comment frame so intermediate proxies that
# close idle connections don't terminate a quiet-but-alive stream.
SSE_KEEPALIVE_SECONDS = 15.0
# How often an SSE stream looks up from its queue to see whether its
# session was dropped / evicted or a newer stream took it over.
SSE_WAKE_SECONDS = 0.25
# How long a new SSE stream waits for the stream it supersedes to stop
# taking events before it snapshots the replay ring. A stream that is
# between two queue waits stops within SSE_WAKE_SECONDS; one blocked
# in a write takes nothing more from the queue once it returns.
SSE_TAKEOVER_WAIT_SECONDS = 4 * SSE_WAKE_SECONDS

# Size of the per-session replay ring buffer. When an SSE client
# reconnects with a ``Last-Event-ID`` header we walk this ring
# forward from the last-seen id and emit anything newer before
# switching back to live pull. Ring entries fall off FIFO when
# the bound is hit; a client that reconnects with an id older
# than the oldest ring entry sees the gap (ids jump) rather than
# a silent data loss. 256 entries is two orders of magnitude
# above realistic network blip durations without bloating idle
# memory.
SSE_REPLAY_BUFFER_SIZE = 256

# HTTP-level rate cap, applied at the very top of do_POST/GET BEFORE
# any parsing work. This catches floods of malformed / unauthenticated
# requests that would otherwise make it all the way through the
# JSON-RPC dispatcher before being rejected — the tools/call rate
# limiter only gates valid tool calls, not the parse-and-validate
# cost that precedes them. Per-source-IP: 60 req/s with a burst of
# 120, which comfortably covers real clients (initialize + tools/list
# + a handful of tools/call) while killing obvious floods.
DEFAULT_HTTP_IP_BURST = 120
DEFAULT_HTTP_IP_REFILL_PER_SEC = 60.0
# Requests without the bearer token draw from a budget of their own (per
# IP): a flood of them - any local user, or a web page's <img> requests to
# the loopback port - must not use up the budget of the token holder on
# the same address (the bearer check is a constant-time compare, cheaper
# than anything the cap protects).
#: How many sessions of one client (or one address) may use their full
#: rate at once: each session has a bucket of its own, the client one of
#: this many times its size. One flooding session no longer starves the
#: client's - on loopback: every local client's - other sessions, and new
#: sessions bring no fresh budget past it.
FAIR_SHARE_SESSIONS = 4
#: What each session keeps whatever its client's other sessions do: this
#: part of its own rate (and a burst of FAIR_RESERVE_BURST) comes from a
#: reserve of its own when the shared bucket is empty - with 8 flooding
#: sessions a quiet one got none of its calls.
FAIR_RESERVE_SHARE = 0.5
FAIR_RESERVE_BURST = 2


def _now() -> float:
    return time.monotonic()
DEFAULT_HTTP_UNAUTH_BURST = 20
DEFAULT_HTTP_UNAUTH_REFILL_PER_SEC = 5.0


#: Most buckets the HTTP edge cap keeps (addresses, sessions, reserves).
MAX_EDGE_BUCKETS = 4096


class _PerIPRateLimiter:
    """Token bucket keyed by source IP, applied at the HTTP edge.

    Keeps per-IP buckets in a dict; old entries that haven't been
    touched for 5 min are garbage-collected opportunistically on
    each acquire so the map doesn't grow without bound on a
    short-lived-flooder-type attack.

    The bucket refills at ``refill_per_sec``, caps at ``burst``.
    ``try_acquire(ip)`` returns True when a token was available.
    """

    _GC_IDLE_SECONDS = 300.0
    _GC_EVERY_N_CALLS = 256

    def __init__(
        self,
        burst: int = DEFAULT_HTTP_IP_BURST,
        refill_per_sec: float = DEFAULT_HTTP_IP_REFILL_PER_SEC,
    ):
        self._burst = burst
        self._refill = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = {}
        # (tokens, last_touch_monotonic) per IP
        self._lock = threading.Lock()
        self._calls = 0

    def _take_locked(self, key: str, burst: float, refill: float, now: float,
                     take: bool) -> bool:
        if key not in self._buckets and len(self._buckets) >= MAX_EDGE_BUCKETS:
            self._gc(now)
        tokens, last = self._buckets.get(key, (burst, now))
        tokens = min(burst, tokens + max(0.0, now - last) * refill)
        ok = tokens >= 1.0
        if ok and take:
            tokens -= 1.0
        self._buckets[key] = (tokens, now)
        return ok

    def try_acquire(self, ip: str, member: str | None = None) -> bool:
        """A token for *ip*; with *member* (the session) from that
        session's bucket and the address's shared one, FAIR_SHARE_SESSIONS
        times its size - or, that one empty, from the session's own reserve
        (FAIR_RESERVE_SHARE of its rate): one session's flood, or many,
        leave each other session its minimum."""
        now = _now()
        with self._lock:
            self._calls += 1
            if self._calls % self._GC_EVERY_N_CALLS == 0:
                self._gc(now)
            if member is None:
                return self._take_locked(ip, float(self._burst), self._refill, now, True)
            share = FAIR_SHARE_SESSIONS
            # Every attempt, refused ones too: a session asking within its
            # own rate is a quiet one (it may use its reserve below).
            quiet = self._take_locked(f"{ip}#{member}#attempts", float(self._burst),
                                      self._refill, now, True) and \
                self._buckets[f"{ip}#{member}#attempts"][0] >= self._burst / 2
            if not self._take_locked(f"{ip}#{member}", float(self._burst), self._refill, now,
                                     False):
                return False
            if not self._take_locked(ip, float(self._burst) * share, self._refill * share,
                                     now, True):
                # The session's reserve: only for a quiet one (its own
                # bucket at least half full), and from the address's pool
                # of reserves (twice the shared rate) - more sessions add
                # no rate past it.
                if not quiet:
                    return False
                if not self._take_locked(f"{ip}#{member}#reserve", float(FAIR_RESERVE_BURST),
                                         self._refill * FAIR_RESERVE_SHARE, now, False):
                    return False
                if not self._take_locked(f"{ip}#reserves", float(self._burst) * share * 2,
                                         self._refill * share * 2, now, True):
                    return False
                self._take_locked(f"{ip}#{member}#reserve", float(FAIR_RESERVE_BURST),
                                  self._refill * FAIR_RESERVE_SHARE, now, True)
            return self._take_locked(f"{ip}#{member}", float(self._burst), self._refill, now,
                                     True)

    def _gc(self, now: float) -> None:
        stale = [
            ip for ip, (_, last) in self._buckets.items() if now - last > self._GC_IDLE_SECONDS
        ]
        for ip in stale:
            self._buckets.pop(ip, None)
        if len(self._buckets) >= MAX_EDGE_BUCKETS:
            # At the bound the quarter touched longest ago goes (in one go,
            # not one sort per new key).
            keep = MAX_EDGE_BUCKETS * 3 // 4
            for key, _ in sorted(self._buckets.items(), key=lambda kv: kv[1][1])[
                    : len(self._buckets) - keep]:
                self._buckets.pop(key, None)


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Hostname — assume non-loopback unless literally "localhost".
        return host.lower() == "localhost"


def _loopback_host_header(value: str) -> bool:
    """True when a ``Host`` / ``Origin`` authority names this machine.

    A DNS-rebinding page reaches the loopback listener with its own
    hostname in ``Host``; only literal loopback names pass.
    Parsed strictly as ``host[:port]`` (RFC 9110 authority without
    userinfo): a name of letters, digits, dots and dashes or a bracketed
    IPv6 address, and a port of digits only - ``localhost:1@evil``,
    ``localhost/x``, a space, a bare IPv6 address or an empty port are
    refused, never cut down to a loopback name.
    """
    # Only the optional whitespace HTTP allows around a field value.
    match = _HOST_AUTHORITY.fullmatch((value or "").strip(" \t"))
    if match is None:
        return False
    host = match.group(1) or match.group(2)
    port = match.group(3)
    if port is not None and not 0 < int(port) <= 65535:
        return False
    return _is_loopback(host)


#: ``host[:port]``: ``[v6]`` or a DNS name / IPv4 address, then digits only.
_HOST_AUTHORITY = re.compile(r"(?:\[([0-9A-Fa-f:.]{2,45})\]|([A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}))"
                             r")(?::([0-9]{1,5}))?")


class SessionLimitError(RuntimeError):
    """The registry is at ``max_sessions`` even after idle eviction."""


# ---------------------------------------------------------------------------
# Session state — per-client notification queue, cancel registry, log sink
# ---------------------------------------------------------------------------


@dataclass
class _SseEvent:
    """One SSE frame with a session-scoped monotonic id.

    The id is stamped at enqueue time (inside the session's
    replay_lock) and makes it into both the live queue AND the
    replay ring. SSE readers emit the id on the wire as ``id: N``
    so clients can send ``Last-Event-ID: N`` on reconnect to pick
    up where they left off.
    """

    event_id: int
    frame: dict


@dataclass
class _HttpSession:
    """Per-client state kept between POSTs and SSE connections.

    The session id is the stable handle a client uses to route:
      * subsequent POST /messages requests,
      * GET /messages SSE connections,
      * DELETE /messages for explicit shutdown.

    ``queue`` is the buffer between tool-call threads (which produce
    progress/log frames) and the SSE reader thread (which drains
    them to the client). ``cancels`` is scoped to this session so a
    notifications/cancelled from client A can't abort a tool call
    running on behalf of client B.

    ``replay_ring`` + ``next_event_id`` + ``replay_lock`` back the
    Last-Event-ID reconnect protocol. Every event handed to the
    queue is also kept in the ring (bounded FIFO) so a reconnecting
    SSE reader can ask for everything newer than the last id it
    saw before the drop.
    """

    session_id: str
    queue: "queue.Queue[_SseEvent]"
    cancels: _mcp._CancelRegistry
    # Per-session rate limiter — a single global bucket let one
    # noisy client starve every other client on the same server.
    # ``None`` means "no per-session limiter" (stdio / tests /
    # rate_limit_enabled=False); the dispatcher then skips the
    # gate entirely.
    rate_limiter: "_mcp._RateLimiter | None" = None
    # SHA-256 fingerprint of the peer certificate that established
    # this session. None when the session was created over plain
    # HTTP (loopback only). Every subsequent request has its cert
    # fingerprint compared against this one — a leaked session id
    # is worthless to anyone presenting a different cert.
    cert_fingerprint: str | None = None
    # Flag: has this session's sink been registered on the server-
    # wide log forwarder? Used so drop() knows whether to unregister.
    # Stored on the session rather than deduced from the forwarder
    # state so the registry lock doesn't have to cross into the
    # forwarder's lock on every check.
    log_forwarder_registered: bool = False
    last_seen: float = field(default_factory=time.monotonic)
    # Replay ring: the last SSE_REPLAY_BUFFER_SIZE events, oldest
    # first. Entries fall off FIFO. A reconnecting SSE reader with
    # Last-Event-ID walks from (id+1) to the newest entry.
    replay_ring: "deque[_SseEvent]" = field(
        default_factory=lambda: deque(maxlen=SSE_REPLAY_BUFFER_SIZE),
    )
    # Monotonic event id counter — never resets within a session.
    # Starts at 1 so a client that sends ``Last-Event-ID: 0`` on a
    # first connect gets everything the ring holds.
    next_event_id: int = 1
    # Serialises (event_id assignment, ring append, queue put) so a
    # concurrent SSE reconnect never snapshots a ring that's in the
    # middle of being updated.
    replay_lock: threading.Lock = field(default_factory=threading.Lock)
    # Set when the session is dropped (DELETE) or evicted: its SSE
    # stream ends instead of outliving the session.
    closed: threading.Event = field(default_factory=threading.Event)
    # The one live SSE stream as (stop, done) events. A new GET
    # /messages for the session stops the previous stream, so one
    # session never holds more than one streaming thread.
    sse_stream: "tuple[threading.Event, threading.Event] | None" = None
    sse_lock: threading.Lock = field(default_factory=threading.Lock)
    # The MCP revision this session's initialize agreed on.
    protocol: _mcp.ProtocolState = field(default_factory=_mcp.ProtocolState)
    # Who opened it (address + credential): its rate bucket and session
    # count are the client's, not the session's.
    client_key: str = ""
    # The newest event id an SSE stream has written: a new stream without
    # Last-Event-ID starts after it instead of re-sending the ring.
    delivered_event_id: int = 0

    def touch(self) -> None:
        self.last_seen = time.monotonic()


class _FairLimiter:
    """A session's tools/call limiter: a token from its own bucket and
    from its client's shared one."""

    def __init__(self, own, shared, reserve=None, pool=None, attempts=None) -> None:
        self._own = own
        self._shared = shared
        # The session's minimum, used when the shared bucket is empty - by
        # a quiet session only (its attempts, refused ones too, within its
        # own rate: a flooding one asks far more often), and drawn from its
        # client's pool of reserves, so more sessions add no rate past it.
        self._reserve = reserve
        self._pool = pool
        self._attempts = attempts

    def try_acquire(self, cost: float = 1.0) -> bool:
        quiet = self._attempts is None or (
            self._attempts.try_acquire(cost)
            and self._attempts.tokens >= self._attempts._burst / 2)
        if not self._own.try_acquire(cost):
            return False
        if self._shared.try_acquire(cost):
            return True
        if quiet and self._reserve is not None and self._reserve.try_acquire(cost):
            if self._pool is None or self._pool.try_acquire(cost):
                return True
            self._reserve.refund(cost)
        self._own.refund(cost)
        return False

    @property
    def tokens(self) -> float:
        return min(self._own.tokens, self._shared.tokens)


class _SessionRegistry:
    """Thread-safe session store. Creates on demand, evicts idle.

    Holds a reference to the server-wide ``_LogForwarder`` so
    ``drop`` and ``evict_idle`` can unregister the session's
    routing entry. Without that call, the forwarder would keep
    pushing log records into the (now-unreferenced) session queue,
    which amplifies into a log-warning loop once the queue fills."""

    def __init__(
        self,
        *,
        idle_seconds: float = DEFAULT_SESSION_IDLE_SECONDS,
        log_forwarder: "_mcp._LogForwarder | None" = None,
        rate_burst: int | None = None,
        rate_refill_per_sec: float | None = None,
        max_sessions: int = MAX_SESSIONS,
        per_client_cap: bool = True,
    ):
        self._max_sessions = max_sessions
        # False on a loopback server: every local client is one address
        # and one token there, so a per-client cap was everyone's cap.
        self._per_client_cap = per_client_cap
        self._sessions: dict[str, _HttpSession] = {}
        self._lock = threading.Lock()
        self._idle_seconds = idle_seconds
        self._log_forwarder = log_forwarder
        # If both are set, every new session gets a fresh limiter
        # with those params. If either is None, the session runs
        # without a rate gate (tests, or rate_limit_enabled=False).
        self._rate_burst = rate_burst
        self._rate_refill_per_sec = rate_refill_per_sec
        # client key -> its rate bucket (shared by all its sessions: a new
        # session no longer brings a full bucket).
        self._buckets: dict[str, _mcp._RateLimiter] = {}
        # Set by build_server: the task registry, so a session that ends
        # takes its tasks with it.
        self.tasks: "_mcp._TaskRegistry | None" = None

    def _bucket(self, client_key: str) -> "_FairLimiter | None":
        """The new session's limiter: its own bucket, and its client's
        shared one (FAIR_SHARE_SESSIONS times the size)."""
        if self._rate_burst is None or self._rate_refill_per_sec is None:
            return None
        with self._lock:
            pair = self._buckets.pop(client_key, None)
            if pair is None:
                shared = _mcp._RateLimiter(
                    burst=self._rate_burst * FAIR_SHARE_SESSIONS,
                    refill_per_sec=self._rate_refill_per_sec * FAIR_SHARE_SESSIONS)
                # Every reserve of the client together: twice the shared
                # bucket's rate and size.
                pool = _mcp._RateLimiter(
                    burst=self._rate_burst * FAIR_SHARE_SESSIONS * 2,
                    refill_per_sec=self._rate_refill_per_sec * FAIR_SHARE_SESSIONS * 2)
                pair = (shared, pool)
            self._buckets[client_key] = pair  # most recently used last
            while len(self._buckets) > MAX_CLIENT_BUCKETS:
                self._buckets.pop(next(iter(self._buckets)))
        shared, pool = pair
        own = _mcp._RateLimiter(burst=self._rate_burst, refill_per_sec=self._rate_refill_per_sec)
        reserve = _mcp._RateLimiter(
            burst=FAIR_RESERVE_BURST,
            refill_per_sec=self._rate_refill_per_sec * FAIR_RESERVE_SHARE)
        attempts = _mcp._RateLimiter(burst=self._rate_burst,
                                     refill_per_sec=self._rate_refill_per_sec)
        return _FairLimiter(own, shared, reserve, pool, attempts)

    def _running_task_scopes(self) -> set:
        if self.tasks is None:
            return set()
        return {t.scope for t in self.tasks.list_all() if t.status == "running"}

    @staticmethod
    def _busy(sess: _HttpSession, task_scopes: set) -> bool:
        """A session at work is never evicted, however long ago its last
        request began: a tools/call still running, a running task, an open
        SSE stream (a client waiting for a long task's result)."""
        return (sess.cancels.pending() > 0 or sess.session_id in task_scopes
                or sess.sse_stream is not None)

    def _evictable_locked(self, client_key: str | None = None) -> "_HttpSession | None":
        """The session that makes room for a new one (of *client_key*,
        when given): idle SESSION_EVICTABLE_AFTER_SECONDS (no request in
        that time), no running call or task. A session that only holds an
        SSE stream may go too - after every session without one, and first
        from the client holding the most sessions: one local client held
        all 256 sessions with a stream each and locked everyone else out.
        (The idle sweep keeps such a session: it waits on its stream.)"""
        now = time.monotonic()
        task_scopes = self._running_task_scopes()
        per_client: dict[str, int] = {}
        for s in self._sessions.values():
            per_client[s.client_key] = per_client.get(s.client_key, 0) + 1
        candidates = [s for s in self._sessions.values()
                      if (client_key is None or s.client_key == client_key)
                      and now - s.last_seen >= SESSION_EVICTABLE_AFTER_SECONDS
                      and s.cancels.pending() == 0 and s.session_id not in task_scopes]
        return min(candidates,
                   key=lambda s: (s.sse_stream is not None, -per_client[s.client_key],
                                  s.last_seen),
                   default=None)

    def _hog_victim_locked(self) -> "_HttpSession | None":
        """At the server's cap with no idle session: the least recently used
        session without a running call or task of the client holding more
        than half the cap (on loopback every local client is that one
        client). One local client kept all 256 sessions busy with pings;
        its oldest makes room now - the client of a dropped session gets
        404 and starts a new one, as MCP has it."""
        per_client: dict[str, int] = {}
        for s in self._sessions.values():
            per_client[s.client_key] = per_client.get(s.client_key, 0) + 1
        if not per_client:
            return None
        hog, count = max(per_client.items(), key=lambda pair: pair[1])
        if count * 2 <= self._max_sessions:
            return None
        task_scopes = self._running_task_scopes()
        candidates = [s for s in self._sessions.values()
                      if s.client_key == hog and s.cancels.pending() == 0
                      and s.session_id not in task_scopes]
        return min(candidates, key=lambda s: (s.sse_stream is not None, s.last_seen),
                   default=None)

    def create(self, client_key: str = "") -> _HttpSession:
        # Idle eviction runs here so it needs no timer thread; the cap
        # is checked after it, so a quiet server never refuses.
        self.evict_idle()
        evicted = None
        with self._lock:
            mine = sum(1 for s in self._sessions.values() if s.client_key == client_key)
            if self._per_client_cap and mine >= MAX_SESSIONS_PER_CLIENT:
                # The client's own session idle longest makes room: on
                # loopback every local client is one "client" (one address,
                # one token), so refusing would lock the others out.
                evicted = self._evictable_locked(client_key)
                if evicted is None:
                    raise SessionLimitError(
                        f"this client holds {mine} live sessions (cap "
                        f"{MAX_SESSIONS_PER_CLIENT}), none idle for "
                        f"{SESSION_EVICTABLE_AFTER_SECONDS:g}s; end one with DELETE /messages")
                self._sessions.pop(evicted.session_id, None)
            elif len(self._sessions) >= self._max_sessions:
                evicted = self._evictable_locked() or self._hog_victim_locked()
                if evicted is None:
                    raise SessionLimitError(f"more than {self._max_sessions} live sessions")
                self._sessions.pop(evicted.session_id, None)
        if evicted is not None:
            log.info("mcp-http: session %s evicted to make room (idle %.0fs)",
                     evicted.session_id[:8], time.monotonic() - evicted.last_seen)
            self._retire(evicted)
        sid = uuid.uuid4().hex
        sess = _HttpSession(
            session_id=sid,
            queue=queue.Queue(maxsize=MAX_QUEUED_NOTIFICATIONS),
            cancels=_mcp._CancelRegistry(),
            rate_limiter=self._bucket(client_key),
            client_key=client_key,
        )
        with self._lock:
            self._sessions[sid] = sess
        return sess

    def _retire(self, sess: _HttpSession) -> None:
        """What every way a session ends does: stop its stream, cancel its
        tool calls and tasks, close its profiles, unroute its log."""
        sess.closed.set()
        sess.cancels.cancel_all()
        if self.tasks is not None:
            self.tasks.drop_scope(sess.session_id)
        self._unregister_forwarder(sess)

    def get(self, session_id: str) -> _HttpSession | None:
        with self._lock:
            sess = self._sessions.get(session_id)
        if sess is not None:
            sess.touch()
        return sess

    def knows(self, session_id: str) -> bool:
        """Whether *session_id* is a live session (without touching it)."""
        with self._lock:
            return session_id in self._sessions

    def _unregister_forwarder(self, sess: _HttpSession) -> None:
        if self._log_forwarder is not None and sess.log_forwarder_registered:
            self._log_forwarder.unregister_session(sess.session_id)
            sess.log_forwarder_registered = False
        # Profiles the session opened with remote_open (--mcp-tools
        # remote) hold live connections; nobody can address them now.
        from core.mcp_groups import RemoteRegistry

        RemoteRegistry.close_session(sess.session_id)

    def drop(self, session_id: str) -> bool:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess is None:
            return False
        self._retire(sess)
        return True

    def evict_idle(self) -> list[str]:
        """Evict sessions whose ``last_seen`` is older than the idle
        window. Returns the list of dropped ids so callers can log."""
        now = time.monotonic()
        dropped_sessions: list[_HttpSession] = []
        task_scopes = self._running_task_scopes()
        with self._lock:
            for sid, sess in list(self._sessions.items()):
                if now - sess.last_seen > self._idle_seconds and not self._busy(sess, task_scopes):
                    self._sessions.pop(sid, None)
                    dropped_sessions.append(sess)
        # Unregister OUTSIDE the registry lock to keep lock ordering
        # consistent with the forwarder's own lock.
        for sess in dropped_sessions:
            self._retire(sess)
        return [s.session_id for s in dropped_sessions]


class _QueueSink:
    """A file-like shim that parses each write as a JSON-RPC frame,
    stamps it with a session-scoped event id, stores it in the
    session's replay ring, and drops it into the live SSE queue.

    Why not hand the queue to the tool context directly? Because
    :class:`_mcp._ToolContext.progress` writes ``json.dumps(notif)
    + "\\n"`` to a file-like ``stdout``. The stdio transport uses a
    real stdout; the HTTP transport needs the same shape — hence
    this adapter.

    Why the ring too? To support Last-Event-ID replay on SSE
    reconnect. A network blip between client and server would
    otherwise drop every progress notification queued between the
    disconnect and the reconnect; now the client can supply the
    id of the last event it received and the server walks the
    ring forward from there.

    Drop-behaviour on a full queue: silently discard (but the
    ring still gets the entry — a subsequent reconnect can still
    replay it). A tool that emits 10k progress frames without any
    client ever consuming them is already broken; the queue-fill
    guard keeps the server from swelling.
    """

    def __init__(self, sess: _HttpSession):
        self._sess = sess

    def write(self, line: str) -> int:
        if not line or not line.strip():
            return len(line) if line else 0
        try:
            frame = json.loads(line)
        except json.JSONDecodeError:
            # Note: ``log`` is core.mcp_http, which is NOT in
            # _FORWARDED_LOGGER_NAMES, so this warning cannot feed
            # back into a forwarder-queue amplification loop. A
            # change to the forwarded-logger list would need to keep
            # excluding core.mcp_http to preserve that invariant.
            log.warning("queue-sink dropped non-JSON line: %r", line[:80])
            return len(line)
        # Atomic (id → ring → queue) under the session's replay
        # lock. A concurrent SSE reconnect snapshots the ring AND
        # drains the queue inside the same lock, which makes it
        # impossible for one event to end up sent via BOTH the
        # replay pass AND the live queue pull — see _serve_sse.
        with self._sess.replay_lock:
            event_id = self._sess.next_event_id
            self._sess.next_event_id += 1
            event = _SseEvent(event_id=event_id, frame=frame)
            self._sess.replay_ring.append(event)
            try:
                self._sess.queue.put_nowait(event)
            except queue.Full:
                # Ring still holds the entry — reconnect can replay.
                log.warning(
                    "queue-sink dropped live-queue frame (id=%d): "
                    "session queue full; ring still retains it",
                    event_id,
                )
        return len(line)

    def flush(self) -> None:  # stdout-like no-op
        return None


@dataclass
class HTTPServerConfig:
    backend: Any
    host: str = "127.0.0.1"
    port: int = 7331
    allow_write: bool = False
    backend_id: str | None = None
    root: str | None = None
    # Multi-backend registry; see core.mcp_server.ServerConfig.backends.
    backends: dict | None = None
    # Optional capability groups (``--mcp-tools``); see core.mcp_groups.
    tool_groups: frozenset[str] = frozenset()
    # The exec group (--mcp-allow-exec); see core.mcp_groups.
    allow_exec: bool = False
    # Bearer token every request but GET /health must carry. Generated by
    # build_server for a plain-HTTP server when left empty.
    auth_token: str | None = None
    # mTLS — all three required together.
    cert_file: str | None = None
    key_file: str | None = None
    ca_file: str | None = None
    # Session idle timeout. Tests override this to verify eviction;
    # production deployments may tune for long-running jobs.
    session_idle_seconds: float = DEFAULT_SESSION_IDLE_SECONDS
    # Rate limit: applied at tools/call. Defaults inherit from
    # core.mcp_server. Set rate_limit_enabled=False for load tests
    # or private single-client deployments.
    rate_limit_enabled: bool = True
    rate_burst: int = _mcp.DEFAULT_RATE_BURST
    rate_refill_per_sec: float = _mcp.DEFAULT_RATE_REFILL_PER_SEC
    # HTTP-edge per-IP cap. Applied BEFORE body parsing so a flood
    # of unauthenticated or malformed POSTs can't churn CPU inside
    # the dispatcher. Defaults generous enough for real clients
    # (initialize + a few tools/call + keepalive) but reject an
    # obvious flood.
    http_ip_rate_enabled: bool = True
    http_ip_burst: int = DEFAULT_HTTP_IP_BURST
    http_ip_refill_per_sec: float = DEFAULT_HTTP_IP_REFILL_PER_SEC

    def tls_enabled(self) -> bool:
        return bool(self.cert_file and self.key_file and self.ca_file)


def _make_ssl_context(config: HTTPServerConfig) -> ssl.SSLContext:
    """Build a mutual-TLS SSLContext.

    Why not ``ssl.create_default_context(Purpose.CLIENT_AUTH)`` as-
    is? That helper doesn't set ``verify_mode=CERT_REQUIRED`` for
    server-side client-cert validation — it leaves mTLS optional.
    We want it required: no client cert, no connection.
    """
    if not config.tls_enabled():
        raise ValueError("TLS requires cert_file + key_file + ca_file")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=config.cert_file, keyfile=config.key_file)
    ctx.load_verify_locations(cafile=config.ca_file)
    # CERT_OPTIONAL: a certificate that is presented must verify against
    # the CA (else the handshake fails), and the handler refuses every
    # request without one except GET /health - a health probe needs no
    # client certificate.
    ctx.verify_mode = ssl.CERT_OPTIONAL
    # TLS 1.2+ only — MCP is a 2024 spec and the clients that matter
    # all support 1.2. No reason to tolerate legacy.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= _TLS_SERVER_OPTIONS
    return ctx


#: No TLS 1.2 renegotiation (a client could make the server redo the
#: handshake's work at will).
_TLS_SERVER_OPTIONS = getattr(ssl, "OP_NO_RENEGOTIATION", 0)


class _McpHTTPHandler(http.server.BaseHTTPRequestHandler):
    # StreamRequestHandler applies this to the connection socket, so a
    # client that connects and never speaks (or never finishes the TLS
    # handshake) is dropped instead of pinning a thread forever.
    timeout = CONNECTION_TIMEOUT_SECONDS

    def _discard_body(self, length: int) -> None:
        """Read past up to DISCARD_BODY_BYTES of a refused request's body
        (within 2 s) before closing, so the client finishes sending and
        reads its answer instead of a broken pipe."""
        table = getattr(self.server, "connections", None)
        if table is not None:
            table.distrust(self.connection)
        read1 = getattr(self.rfile, "read1", None)
        left = min(length, DISCARD_BODY_BYTES)
        until = time.monotonic() + 2.0
        try:
            self.connection.settimeout(2.0)
            while left > 0 and time.monotonic() < until:
                chunk = (read1(min(65536, left)) if read1 is not None
                         else self.rfile.read(min(65536, left)))
                if not chunk:
                    break
                left -= len(chunk)
        except (OSError, ValueError):
            pass

    def _read_body(self, length: int) -> bytes | None:
        """*length* bytes of body (fewer when the client stops), or None
        when it arrives slower than MIN_BODY_RATE past the first
        BODY_RATE_GRACE_SECONDS (a trickle that holds its connection)."""
        parts = []
        got = 0
        started = time.monotonic()
        read1 = getattr(self.rfile, "read1", None)
        while got < length:
            chunk = (read1(min(65536, length - got)) if read1 is not None
                     else self.rfile.read(min(65536, length - got)))
            if not chunk:
                break
            parts.append(chunk)
            got += len(chunk)
            self._body_got = got
            elapsed = time.monotonic() - started
            if got < length and elapsed > BODY_RATE_GRACE_SECONDS \
                    and got / elapsed < min_body_rate():
                return None
        return b"".join(parts)

    def _authenticated(self) -> None:
        """The token or certificate is checked: the request's body may take
        AUTHENTICATED_BODY_DEADLINE_SECONDS and the connection is no longer
        one a newcomer may push out."""
        table = getattr(self.server, "connections", None)
        if table is not None:
            table.authenticated(self.connection)
        watch = getattr(self.server, "read_deadlines", None)
        if watch is not None:
            watch.extend(self, AUTHENTICATED_BODY_DEADLINE_SECONDS)

    def handle_one_request(self) -> None:
        """One request, read within REQUEST_READ_DEADLINE_SECONDS: past it
        the connection is shut (the per-read socket time-out alone let a
        trickle of one byte every 20 s hold it)."""
        watch = getattr(self.server, "read_deadlines", None)
        if watch is not None:
            watch.add(self)
        table = getattr(self.server, "connections", None)
        if table is not None:
            table.reading(self.connection, True)
        try:
            super().handle_one_request()
        finally:
            self._request_read()

    def _request_read(self) -> None:
        """The request is in: what follows (a tool call, an SSE stream)
        may take as long as it takes - and the connection is no longer
        one a newcomer may push out."""
        watch = getattr(self.server, "read_deadlines", None)
        if watch is not None:
            watch.discard(self)
        table = getattr(self.server, "connections", None)
        if table is not None:
            table.reading(self.connection, False)

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok and self.command != "POST":
            self._request_read()  # no body to wait for
        return ok

    # True for plain-HTTP loopback servers: enables the Host/Origin
    # check in :meth:`_check_local_origin`. Set by the factory.
    _local_only: bool = False
    # mTLS: every path but /health needs a verified client certificate.
    _require_client_cert: bool = False
    # Set by the factory below.
    _tools: list = []
    _server_name: str = "axross-mcp"
    _server_version: str = "?"
    # Resource catalogue (resources/list, resources/read, resources/
    # templates/list). Shared across all handler threads — the
    # backend behind it is assumed thread-safe or serialised by the
    # caller; same assumption as the tool surface.
    _resources = None
    # Session registry — one per server. Each POST resolves/creates a
    # session; each session owns its own cancel registry, queue, and
    # rate limiter. No server-wide rate bucket any more — a global
    # bucket let one hostile client starve all others.
    _sessions: "_SessionRegistry | None" = None
    # Per-IP bucket at the HTTP edge — applied BEFORE we parse the
    # body or look up the session. Catches floods of malformed or
    # unauthenticated POSTs that otherwise spend CPU in the
    # dispatcher before hitting the tools/call rate limit.
    _http_ip_limiter: "_PerIPRateLimiter | None" = None
    _http_unauth_limiter: "_PerIPRateLimiter | None" = None
    # Bearer token (empty: none demanded - an mTLS server without one).
    _auth_token: str = ""
    # Long-running-task registry. Shared across all sessions; the
    # dispatcher scopes tasks by session_id internally so client A
    # can't see / cancel / poll client B's tasks.
    _tasks: "_mcp._TaskRegistry | None" = None

    # Silence the default BaseHTTPRequestHandler stdout log — the
    # server uses :mod:`logging` instead so output can be routed.
    def log_message(self, fmt, *args) -> None:  # noqa: A003, ARG002
        log.info("mcp-http %s - %s", self.address_string(), fmt % args)

    def log_error(self, fmt, *args) -> None:  # noqa: ARG002
        log.warning("mcp-http %s - %s", self.address_string(), fmt % args)

    def send_error(self, code, message=None, explain=None) -> None:
        # A request line the stdlib cannot parse ("POST /messages HTTP/1.",
        # "POST0/messages HTTP/1.1") leaves request_version at HTTP/0.9, and
        # Python 3.11 sent the 400 / 505 as a bare HTML body, no status
        # line. Only "GET <path>" is an HTTP/0.9 request; every other line
        # is answered as HTTP/1.0.
        words = getattr(self, "requestline", "").split()
        if self.request_version == "HTTP/0.9" and not (len(words) == 2 and words[0] == "GET"):
            self.request_version = "HTTP/1.0"
        super().send_error(code, message, explain)

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def _peer_cert_fingerprint(self) -> str | None:
        """Return the SHA-256 fingerprint of the peer's TLS
        certificate, hex-encoded. ``None`` when the connection is
        plain HTTP (no cert to bind to).

        Without this check, a leaked Mcp-Session-Id header lets any
        client on the reachable network impersonate the session
        until idle-eviction. Binding the id to the cert that was
        presented on initialize means a stolen id is useless: the
        impostor can't produce the matching cert at the TLS
        handshake, so their connection never gets past mTLS in the
        first place.
        """
        import hashlib

        sock = self.connection
        # Plain sockets don't have getpeercert; no binding
        # possible (loopback-only deployments accept this
        # explicitly).
        getter = getattr(sock, "getpeercert", None)
        if getter is None:
            return None
        try:
            der = getter(binary_form=True)
        except Exception:  # noqa: BLE001 — handshake didn't set a cert
            return None
        if not der:
            return None
        return hashlib.sha256(der).hexdigest()

    def _client_key(self) -> str:
        """Who is asking: the address and the client certificate (the
        bearer token is the same for every client of a plain server)."""
        ip = self.client_address[0] if self.client_address else "?"
        return f"{ip}|{self._peer_cert_fingerprint() or ''}"

    def _check_ip_cap(self, authenticated: bool = True) -> bool:
        """Return True when the per-IP rate cap lets the request
        through. On reject, already sent a 429; caller should just
        return. /health is exempted because reverse-proxy health
        probes would otherwise starve themselves out. A request without
        the token (*authenticated* False) counts against its own, small
        per-IP budget - never against the token holder's."""
        limiter = self._http_ip_limiter if authenticated else self._http_unauth_limiter
        if limiter is None or self.path == "/health":
            return True
        ip = self.client_address[0] if self.client_address else "?"
        # The token holder's budget is shared fairly by its sessions (on
        # loopback every local client shares the address). Only a session
        # the server knows gets a bucket and reserve of its own; any other
        # id shares one "-" member (a fresh random id per request passed
        # the cap at 2693 req/s and grew the bucket map without end).
        member = None
        if authenticated:
            sid = (self.headers.get("Mcp-Session-Id") or "").strip()
            known = self._sessions is not None and sid and self._sessions.knows(sid)
            member = sid if known else "-"
        if limiter.try_acquire(ip, member=member):
            return True
        self._send_error(429, "too many requests from this IP — slow down")
        return False

    def _token_ok(self) -> bool:
        """Whether the request carries the bearer token (constant-time);
        True when the server has none or for /health."""
        if not self._auth_token or self.path == "/health":
            return True
        header = self.headers.get("Authorization") or ""
        scheme, _, presented = header.partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(
            presented.strip().encode("utf-8"), self._auth_token.encode("utf-8")
        )

    def _check_access(self) -> bool:
        """The client certificate (mTLS, every path but /health), the
        token, then the rate cap of what it says: the token holder's
        per-IP budget for an authenticated request, the separate
        unauthenticated budget (then a 401) for any other. On refusal an
        answer was already sent."""
        if self._require_client_cert and self.path != "/health" \
                and self._peer_cert_fingerprint() is None:
            # The TLS layer asks for a certificate but lets a client
            # without one in (so a health probe works); nothing else does.
            self._send_error(401, "a client certificate is required")
            return False
        if self._token_ok():
            if not self._check_ip_cap(True):
                return False
            if self.path != "/health":  # passes without a token: not trusted
                self._authenticated()
            return True
        if not self._check_ip_cap(False):
            return False
        if not self._check_auth():
            return False
        self._authenticated()
        return True

    def _check_local_origin(self) -> bool:
        """Refuse DNS-rebinding on the unauthenticated loopback listener.

        Plain (non-TLS) servers have no client authentication, so the
        only thing keeping a web page from driving them is that a page
        cannot forge ``Host``. After a rebind the page's own hostname
        arrives in ``Host`` / ``Origin``; reject anything that is not a
        literal loopback name. mTLS servers authenticate the peer and
        are served under whatever name their certificate carries.
        """
        host = self.headers.get("Host")
        origin = self.headers.get("Origin")
        if len(self.headers.get_all("Host") or ()) > 1 or len(
                self.headers.get_all("Origin") or ()) > 1:
            self._send_error(400, "more than one Host or Origin header")
            return False
        if not self._local_only:
            # mTLS: a browser may hold the client certificate. A page of
            # another origin is refused (MCP: validate Origin, 403); a
            # non-browser client sends no Origin at all.
            if origin is not None:
                from urllib.parse import urlsplit

                parts = urlsplit(origin)
                if parts.scheme != "https" or (host or "").lower() != parts.netloc.lower():
                    self._send_error(403, "cross-origin request refused")
                    return False
            return True
        if host is not None and not _loopback_host_header(host):
            self._send_error(403, "Host header is not a loopback name")
            return False
        if origin is not None:
            from urllib.parse import urlsplit

            netloc = urlsplit(origin).netloc
            if not _loopback_host_header(netloc):
                self._send_error(403, "cross-origin request refused")
                return False
        return True

    def _check_auth(self) -> bool:
        """Demand the bearer token. On refusal a 401 was already sent."""
        if self._token_ok():
            return True
        self.send_response(401)
        body = json.dumps({"error": "missing or wrong bearer token"}).encode("utf-8")
        self.send_header("WWW-Authenticate", 'Bearer realm="axross-mcp"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _check_protocol_header(self, sess: "_HttpSession | None") -> bool:
        """The MCP-Protocol-Version header of a request after initialize
        (MCP 2025-06-18): a revision this server does not speak, or one
        other than the session agreed on, is answered with 400. Without
        the header the session's revision applies (a 2024-11-05 client
        never sends it). On refusal the answer was already sent."""
        values = self.headers.get_all(PROTOCOL_VERSION_HEADER) or []
        if not values:
            return True
        if len(values) > 1:
            self._send_error(400, f"more than one {PROTOCOL_VERSION_HEADER} header")
            return False
        claimed = values[0].strip()
        if claimed not in _mcp.SUPPORTED_PROTOCOL_VERSIONS:
            self._send_error(
                400,
                f"unsupported {PROTOCOL_VERSION_HEADER} {claimed[:40]!r}; this server speaks "
                + ", ".join(_mcp.SUPPORTED_PROTOCOL_VERSIONS),
            )
            return False
        agreed = sess.protocol.version if sess is not None else None
        if agreed is not None and claimed != agreed:
            self._send_error(
                400,
                f"{PROTOCOL_VERSION_HEADER} {claimed!r} is not the version this session "
                f"agreed on ({agreed})",
            )
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        if not self._check_local_origin():
            return
        if not self._check_access():
            return
        if self.path == "/health":
            self._send_json(
                {
                    "server": self._server_name,
                    "version": self._server_version,
                }
            )
            return
        if self.path == "/messages":
            accept = self.headers.get("Accept", "")
            if "text/event-stream" not in accept:
                self._send_error(
                    406,
                    "GET /messages requires Accept: text/event-stream",
                )
                return
            self._serve_sse()
            return
        self._send_error(404, "not found")

    def do_DELETE(self) -> None:  # noqa: N802 — stdlib naming
        if not self._check_local_origin():
            return
        if not self._check_access():
            return
        if self.path != "/messages":
            self._send_error(404, "not found")
            return
        if self._sessions is None:
            self._send_error(404, "not found")
            return
        sid = self.headers.get("Mcp-Session-Id")
        if not sid:
            self._send_error(400, "missing Mcp-Session-Id")
            return
        # Refuse DELETE from a different cert — otherwise a leaked
        # id could be used to kill another client's session.
        sess = self._sessions.get(sid)
        if sess is not None and sess.cert_fingerprint is not None:
            if self._peer_cert_fingerprint() != sess.cert_fingerprint:
                self._send_error(
                    403,
                    "session id does not match presented client certificate",
                )
                return
        if not self._check_protocol_header(sess):
            return
        dropped = self._sessions.drop(sid)
        status = 204 if dropped else 404
        self.send_response(status)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 — stdlib naming
        if not self._check_local_origin():
            return
        if not self._check_access():
            return
        if self.path != "/messages":
            self._send_error(404, "not found")
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or 0)
        except (TypeError, ValueError):
            self._send_error(400, "invalid Content-Length")
            return
        if length <= 0:
            self._send_error(400, "empty body")
            return
        # Refuse bodies larger than MAX_REQUEST_BYTES up-front so a
        # hostile client can't lie in Content-Length and make us hang
        # on ``rfile.read(bogus_huge_length)``. The stdlib handler
        # doesn't bound this itself.
        if length > MAX_REQUEST_BYTES:
            self._send_error(413, f"request body > {MAX_REQUEST_BYTES} bytes")
            return
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            # A web form posts text/plain without a preflight: only JSON
            # is a JSON-RPC message here.
            self._send_error(415, "Content-Type must be application/json")
            return
        bodies = getattr(self.server, "bodies", None)
        client = self._client_key()
        if bodies is not None and not bodies.enter(client, self):
            # One client (on loopback: every local one) may have only so
            # many bodies still arriving: 300 token holders trickling 300 s
            # bodies held every connection.
            self._send_error(503, "too many requests of this client are still sending their "
                                  "body; try again")
            self._discard_body(length)
            self.close_connection = True
            return
        try:
            body = self._read_body(length)
        finally:
            if bodies is not None:
                bodies.leave(client, self)
        self._request_read()
        if body is None:
            self._send_error(408, f"request body slower than {min_body_rate()} bytes/s")
            self.close_connection = True
            return
        if len(body) != length:
            # Peer claimed more than they sent — truncated body is a
            # client bug at best and an attack at worst. Don't try to
            # parse what's there; reject cleanly.
            self._send_error(400, "truncated body: Content-Length mismatch")
            return
        try:
            # ValueError covers JSONDecodeError, a body that is not
            # UTF-8 and an integer above the digit limit;
            # RecursionError is nesting deeper than the C stack.
            req = json.loads(body)
        except (ValueError, RecursionError) as exc:
            self._send_error(400, f"invalid JSON: {exc}")
            return
        if isinstance(req, list):
            # No revision this server speaks has batches (2025-06-18
            # removed them; 2025-03-26, which had them, is not offered).
            self._send_error(400, "JSON-RPC batches are not supported: send one request per POST")
            return
        if not isinstance(req, dict):
            self._send_error(400, "request must be a JSON object")
            return
        if "method" not in req and ("result" in req or "error" in req):
            # A client's response (this server sends no requests): 202,
            # no body, as streamable HTTP has it.
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # --- session resolution -------------------------------------
        sid_header = self.headers.get("Mcp-Session-Id")
        method = req.get("method")
        sess: "_HttpSession | None" = None
        created_now = False
        peer_fp = self._peer_cert_fingerprint()
        if self._sessions is not None:
            if sid_header:
                sess = self._sessions.get(sid_header)
                if sess is None:
                    # A stale or forged id — force the client to
                    # re-initialize. 404 matches the MCP streamable-
                    # HTTP recommendation for expired sessions.
                    self._send_error(404, "unknown or expired session")
                    return
                # Cert fingerprint binding: if the session was
                # created over TLS, this request's cert must match
                # the one that established it. Mismatch means the
                # session id was reused by a different client (a
                # leaked header).
                if sess.cert_fingerprint is not None:
                    if peer_fp != sess.cert_fingerprint:
                        log.warning(
                            "mcp-http session-id reuse mismatch: "
                            "session=%s expected_fp=%s got_fp=%s",
                            sid_header[:8],
                            sess.cert_fingerprint[:16],
                            (peer_fp or "none")[:16],
                        )
                        self._send_error(
                            403,
                            "session id does not match presented client certificate",
                        )
                        return
            else:
                if method != "initialize":
                    self._send_error(
                        400,
                        "missing Mcp-Session-Id (only initialize may omit it)",
                    )
                    return
                try:
                    sess = self._sessions.create(self._client_key())
                except SessionLimitError as exc:
                    self._send_error(503, f"too many sessions: {exc}")
                    return
                sess.cert_fingerprint = peer_fp
                created_now = True
        if not created_now and method != "initialize" and not self._check_protocol_header(sess):
            return

        sink = _QueueSink(sess) if sess is not None else None
        # Register this session's sink on the SERVER-WIDE forwarder.
        # One forwarder per server, not per session: Python's logging
        # is additive (every attached handler fires for every record),
        # so one-handler-per-session silently leaked Session B's log
        # frames onto Session A's stream. The forwarder now demuxes
        # via the contextvar that _handle_request sets at entry.
        if sess is not None and self._log_forwarder is not None:
            self._log_forwarder.register_session(sess.session_id, sink)
            sess.log_forwarder_registered = True

        cancels = sess.cancels if sess is not None else None
        # Per-session rate limiter if the session has one; otherwise
        # no gate. A global bucket was scrapped because one hostile
        # client could starve every other session.
        rate_limiter = sess.rate_limiter if sess is not None else None
        is_call = (isinstance(req, dict) and req.get("method") == "tools/call"
                   and req.get("id") is not None)
        if is_call and cancels is not None and cancels.pending() >= MAX_CALLS_PER_SESSION:
            self._send_json(_mcp._err(
                req.get("id"), _mcp.ERR_RATE_LIMITED,
                f"this session already runs {MAX_CALLS_PER_SESSION} calls at once; "
                "wait for one to end", data={"type": "CallLimitError"}),
                session_id=sess.session_id if sess is not None else None)
            return
        watched = None
        hangups = getattr(self.server, "hangups", None)
        if is_call and cancels is not None and hangups is not None \
                and not isinstance(self.connection, ssl.SSLSocket):
            watched = hangups.add(self.connection, cancels, req.get("id"),
                                  http11=self.request_version == "HTTP/1.1")
        try:
            resp = _mcp._handle_request(
                req,
                self._tools,
                stdout=sink,
                cancels=cancels,
                resources=self._resources,
                log_forwarder=self._log_forwarder,
                rate_limiter=rate_limiter,
                session_id=(sess.session_id if sess is not None else None),
                tasks=self._tasks,
                protocol=(sess.protocol if sess is not None else None),
            )
        finally:
            if watched is not None:
                hangups.discard(watched)
        if sess is not None:
            sess.touch()  # idle from the end of its last request, not the start
        if resp is None:
            # Notification with no id — nothing to send back: 202
            # Accepted without a body (streamable HTTP).
            self.send_response(202)
            self.send_header("Content-Length", "0")
            if sess is not None and created_now:
                self.send_header("Mcp-Session-Id", sess.session_id)
            self.end_headers()
            return
        self._send_json(resp, session_id=(sess.session_id if sess is not None else None))

    # ------------------------------------------------------------------
    # SSE stream for notifications/progress and notifications/message
    # ------------------------------------------------------------------
    def _serve_sse(self) -> None:
        if self._sessions is None:
            self._send_error(404, "not found")
            return
        sid = self.headers.get("Mcp-Session-Id")
        if not sid:
            self._send_error(400, "missing Mcp-Session-Id")
            return
        sess = self._sessions.get(sid)
        if sess is None:
            self._send_error(404, "unknown or expired session")
            return
        # Same cert-fingerprint binding as POST — a leaked id
        # can't be used to tap another client's SSE stream.
        if sess.cert_fingerprint is not None:
            if self._peer_cert_fingerprint() != sess.cert_fingerprint:
                self._send_error(
                    403,
                    "session id does not match presented client certificate",
                )
                return
        if not self._check_protocol_header(sess):
            return
        # Last-Event-ID header lets a client resume a dropped stream.
        # Malformed / missing values coerce to 0 which replays the
        # whole ring (that's the right behaviour for first-connect
        # too — a session that never attached a reader before will
        # have an empty ring, so "replay from 0" does nothing).
        raw_last = self.headers.get("Last-Event-ID")
        try:
            # Without the header (a first stream, or a client that does
            # not resume): what no stream has delivered yet, never the
            # events an earlier stream already sent.
            last_event_id = int(raw_last) if raw_last else sess.delivered_event_id
        except ValueError:
            log.debug(
                "mcp-http SSE: ignoring malformed Last-Event-ID %r",
                raw_last,
            )
            last_event_id = sess.delivered_event_id

        # Take the session's stream slot. The previous stream (a
        # reconnect after a blip, or a client opening streams in a
        # loop) is stopped, and we wait until it has stopped pulling
        # from the queue: an event it took in that window is still in
        # the ring and goes out with our replay below.
        stop, done = threading.Event(), threading.Event()
        with sess.sse_lock:
            previous, sess.sse_stream = sess.sse_stream, (stop, done)
        if previous is not None:
            previous[0].set()
            previous[1].wait(SSE_TAKEOVER_WAIT_SECONDS)
        try:
            self._stream_sse(sess, sid, last_event_id, stop)
        finally:
            done.set()
            with sess.sse_lock:
                if sess.sse_stream == (stop, done):
                    sess.sse_stream = None

    def _stream_sse(
        self,
        sess: _HttpSession,
        sid: str,
        last_event_id: int,
        stop: threading.Event,
    ) -> None:
        if sess.closed.is_set():
            self._send_error(404, "unknown or expired session")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        # Disable chunked encoding — stdlib doesn't terminate chunks
        # cleanly for long-lived streams, and we're flushing after
        # each event anyway.
        self.send_header("Connection", "close")
        self.end_headers()

        # Replay: snapshot the ring AND drain the queue under the
        # session's replay lock. Atomic snapshot + drain is the
        # invariant that prevents an event from being sent via both
        # the replay pass AND the live queue pull: the producer
        # takes the same lock before pushing, so any event in the
        # ring at snapshot time is either (a) also in the queue
        # and will be drained here, or (b) already consumed by a
        # prior SSE reader. Either way, the live loop below only
        # ever sees events enqueued AFTER we released the lock.
        with sess.replay_lock:
            replay_events = [e for e in sess.replay_ring if e.event_id > last_event_id]
            while True:
                try:
                    sess.queue.get_nowait()
                except queue.Empty:
                    break
        if replay_events:
            log.info(
                "mcp-http SSE replay: session=%s last_id=%d → %d events",
                sid[:8],
                last_event_id,
                len(replay_events),
            )

        try:
            # Emit the replay first. One frame per event, each with
            # ``id: N`` on its own line so the client's EventSource
            # updates ``lastEventId`` as the stream progresses.
            for ev in replay_events:
                self._write_sse_event(ev, sess)
            keepalive_at = time.monotonic() + SSE_KEEPALIVE_SECONDS
            while not (stop.is_set() or sess.closed.is_set()):
                try:
                    event = sess.queue.get(timeout=SSE_WAKE_SECONDS)
                except queue.Empty:
                    if time.monotonic() >= keepalive_at:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        keepalive_at = time.monotonic() + SSE_KEEPALIVE_SECONDS
                    continue
                if stop.is_set() or sess.closed.is_set():
                    # Superseded while waiting: the event stays in the
                    # replay ring for the stream that took over.
                    break
                self._write_sse_event(event, sess)
            log.info("mcp-http SSE stream ended by the server (session=%s)", sid[:8])
        except (BrokenPipeError, ConnectionResetError):
            log.info("mcp-http SSE client disconnected (session=%s)", sid[:8])
        except Exception:  # noqa: BLE001
            log.exception("mcp-http SSE loop error (session=%s)", sid[:8])

    def _write_sse_event(self, event: _SseEvent, sess: "_HttpSession | None" = None) -> None:
        """Write one SSE frame in the ``id: N\\ndata: {...}\\n\\n`` form.

        Bundled so the replay pass and the live pull loop share a
        single formatter — any future tweak (event types, multi-line
        data) lands in one place."""
        data = _mcp._dumps_wire(event.frame).encode("utf-8")
        line = f"id: {event.event_id}\n".encode("ascii") + b"data: " + data + b"\n\n"
        self.wfile.write(line)
        self.wfile.flush()
        if sess is not None and event.event_id > sess.delivered_event_id:
            sess.delivered_event_id = event.event_id

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    def _send_json(self, payload: dict, status: int = 200, session_id: str | None = None) -> None:
        body = _mcp._dumps_wire(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session_id is not None:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status: int, message: str) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ReadDeadlines:
    """Requests still being read and when each must be in; one watchdog
    thread shuts the connections that are late."""

    def __init__(self) -> None:
        self._due: dict = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def add(self, handler) -> None:
        with self._lock:
            self._due[handler] = time.monotonic() + REQUEST_READ_DEADLINE_SECONDS
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._watch, name="mcp-http-deadlines",
                                                daemon=True)
                self._thread.start()

    def discard(self, handler) -> None:
        with self._lock:
            self._due.pop(handler, None)

    def extend(self, handler, seconds: float) -> None:
        """*handler*'s request may take *seconds* from now (authenticated)."""
        with self._lock:
            if handler in self._due:
                self._due[handler] = time.monotonic() + seconds

    def _watch(self) -> None:
        while True:
            time.sleep(min(0.25, REQUEST_READ_DEADLINE_SECONDS / 4))
            now = time.monotonic()
            with self._lock:
                late = [h for h, due in self._due.items() if due <= now]
                for handler in late:
                    self._due.pop(handler, None)
                if not self._due:
                    self._thread = None
                    idle = True
                else:
                    idle = False
            for handler in late:
                log.info("mcp-http %s: request not read within %gs; connection closed",
                         handler.client_address[0] if handler.client_address else "?",
                         REQUEST_READ_DEADLINE_SECONDS)
                try:
                    handler.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            if idle:
                return


class _HangupWatch:
    """tools/call requests whose client may hang up: one thread looks at
    their plain sockets and cancels a call whose client is gone (it ran on
    until the tool's time-out). An end of input alone is no hang-up - a
    client may shut only its sending side and wait for the answer (``nc
    -N``) - so an HTTP/1.1 client is probed: an interim ``100 Continue``
    (which it skips) is written; a reset in reply is a client that closed,
    anything else a half-close whose call runs on - and whose client is
    probed again every REPROBE_SECONDS, so closing fully later is noticed
    too. A TLS socket is not watched (its bytes cannot be peeked at)."""

    PROBE = b"HTTP/1.1 100 Continue\r\n\r\n"
    PROBE_WAIT = 0.3
    REPROBE_SECONDS = 5.0

    def __init__(self) -> None:
        self._calls: dict = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def add(self, sock, cancels, request_id, http11: bool = True) -> object:
        key = object()
        with self._lock:
            # socket, cancels, id, may probe, last probe (None: input open)
            self._calls[key] = [sock, cancels, request_id, http11, None]
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._watch, name="mcp-http-hangups",
                                                daemon=True)
                self._thread.start()
        return key

    def discard(self, key) -> None:
        # Under the lock: the answer is written only after this, never
        # between the bytes of a probe.
        with self._lock:
            self._calls.pop(key, None)

    def _probe(self, key, sock) -> bool:
        """Write the probe while *key* is still watched; False when the
        write fails (the client is gone)."""
        with self._lock:
            entry = self._calls.get(key)
            if entry is None:
                return True
            if entry[3]:
                try:
                    sock.send(self.PROBE, getattr(socket, "MSG_DONTWAIT", 0))
                except (BlockingIOError, InterruptedError):
                    pass  # full send buffer: a client that does not read, not gone
                except OSError:
                    return False
            entry[4] = time.monotonic()
            return True

    @staticmethod
    def _reset(sock) -> bool:
        """Whether the connection was reset (a write answered by RST)."""
        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
            return True
        try:
            sock.recv(1, socket.MSG_PEEK | getattr(socket, "MSG_DONTWAIT", 0))
        except (BlockingIOError, InterruptedError):
            return False
        return False

    def _watch(self) -> None:
        from core.posix_compat import wait_io

        while True:
            time.sleep(0.1)
            with self._lock:
                calls = [(key, list(entry)) for key, entry in self._calls.items()]
                if not calls:
                    self._thread = None
                    return
            now = time.monotonic()
            for key, (sock, cancels, request_id, http11, probed) in calls:
                gone = False
                try:
                    if probed is None:
                        readable, _ = wait_io([sock], timeout=0)
                        if readable and sock.recv(1, socket.MSG_PEEK) == b"":
                            gone = not self._probe(key, sock)
                    elif now - probed >= self.PROBE_WAIT:
                        if self._reset(sock):
                            gone = True
                        elif http11 and now - probed >= self.REPROBE_SECONDS:
                            gone = not self._probe(key, sock)  # half-closed: ask again
                except (BlockingIOError, InterruptedError):
                    pass
                except (OSError, ValueError):
                    gone = True  # a reset: the client closed
                if gone:
                    log.info("mcp-http: the client of call %r hung up; cancelling it",
                             request_id)
                    cancels.cancel(request_id)
                    self.discard(key)


def min_body_rate() -> int:
    """The slowest a request body may arrive past its first seconds:
    AXROSS_MCP_MIN_BODY_RATE (bytes/s, 0 switches the check off) or
    MIN_BODY_RATE."""
    raw = os.environ.get("AXROSS_MCP_MIN_BODY_RATE", "").strip()
    if not raw:
        return MIN_BODY_RATE
    try:
        return max(0, int(raw))
    except ValueError:
        return MIN_BODY_RATE


#: A body arriving faster than this many times the minimum rate is never
#: the one a fresh request replaces (a healthy upload is not cut).
HEALTHY_BODY_RATE_FACTOR = 4


def _thread_room() -> int | None:
    """How many more threads this process can start, where a limit says:
    RLIMIT_NPROC (counted per user - a rough bound), the cgroup's
    pids.max, the address space (RLIMIT_AS) over the stack each thread
    reserves. None where nothing says."""
    room = []
    try:
        import resource

        nproc = resource.getrlimit(resource.RLIMIT_NPROC)[0]
        if nproc not in (-1, resource.RLIM_INFINITY) and nproc > 0:
            room.append(int(nproc) - threading.active_count())
        space = resource.getrlimit(resource.RLIMIT_AS)[0]
        if space not in (-1, resource.RLIM_INFINITY) and space > 0:
            stack = threading.stack_size() or 8 << 20
            # Each thread reserves its stack and, with glibc, a malloc
            # arena of up to 64 MiB; three quarters of the address space
            # for them (an `ulimit -v` of 36 GB let ~490 start).
            room.append(int(space) * 3 // 4 // (stack + (64 << 20)))
    except (ImportError, OSError, ValueError, AttributeError):
        pass
    try:
        raw = Path("/sys/fs/cgroup/pids.max").read_text(encoding="ascii").strip()
        current = Path("/sys/fs/cgroup/pids.current").read_text(encoding="ascii").strip()
        if raw.isdigit() and current.isdigit():
            room.append(int(raw) - int(current))
    except OSError:
        pass
    return min(room) if room else None


def connection_cap() -> int:
    """MAX_CONNECTIONS, or less when the process's file-descriptor limit
    leaves no room for it: half of what remains after FD_HEADROOM (a
    connection's socket, and what its call opens). 2048 connections at a
    soft limit of 1024 made /health time out and tools fail with EMFILE."""
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (ImportError, OSError, ValueError):
        return MAX_CONNECTIONS
    cap = MAX_CONNECTIONS
    if soft not in (-1, getattr(__import__("resource"), "RLIM_INFINITY", -1)) and soft > 0:
        cap = min(cap, max(8, (int(soft) - FD_HEADROOM) // 2))
    # Threads too: where fewer can start than the fd limit allows, the
    # table never filled and nobody was pushed out (ulimit -v: ~490).
    room = _thread_room()
    if room is not None:
        cap = min(cap, max(8, room * 3 // 4))
    return cap


class _BodySlots:
    """Bodies being read, per client (see MAX_SLOW_BODIES_PER_CLIENT).
    Full, a new body takes the place of the client's slowest one that has
    been arriving for a second or more (its connection is shut): a fresh
    request is not refused because trickling bodies hold every slot."""

    def __init__(self) -> None:
        self._active: dict[str, dict] = {}  # client -> {handler: started}
        self._lock = threading.Lock()

    def enter(self, client: str, handler) -> bool:
        with self._lock:
            mine = self._active.setdefault(client, {})
            if len(mine) >= MAX_SLOW_BODIES_PER_CLIENT:
                now = time.monotonic()
                floor = min_body_rate() * HEALTHY_BODY_RATE_FACTOR
                old = [(rate, h) for rate, h in
                       ((getattr(h, "_body_got", 0) / max(now - t, 1e-3), h)
                        for h, t in mine.items() if now - t >= 1.0)
                       if rate < floor]
                if not old:
                    return False
                _rate, victim = min(old, key=lambda pair: pair[0])
                mine.pop(victim, None)
                try:
                    victim.connection.shutdown(socket.SHUT_RDWR)
                except (OSError, ValueError, AttributeError):
                    pass
            mine[handler] = time.monotonic()
            return True

    def leave(self, client: str, handler) -> None:
        with self._lock:
            mine = self._active.get(client)
            if mine is not None:
                mine.pop(handler, None)
                if not mine:
                    self._active.pop(client, None)


#: How far below the open connections the cap drops when a thread fails to
#: start (see _ConnectionTable.thread_failed), the least it drops to, and
#: after how many thread starts in a row it rises by that step again.
THREAD_FAILURE_HEADROOM = 16
CAP_FLOOR = 8
CAP_RECOVERY_STARTS = 32
#: An address is preferred for the victim only with at least this many
#: connections still sending (and twice the median), each at least
#: BUSY_MIN_AGE_SECONDS old.
BUSY_GROUP_MIN = 3
BUSY_MIN_AGE_SECONDS = 1.0


def _address_group(ip: str) -> str:
    """The address a connection counts against: an IPv6 address's /64 (one
    host holds a whole /64), an IPv4 address itself."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if address.version == 6:
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


#: How many of the oldest connections still sending a newcomer looks at.
VICTIM_SAMPLE = 32
#: A connection still sending its request is judged by what it has sent
#: once it is this old (see _ConnectionTable._oldest_reading_locked).
VICTIM_MIN_AGE_SECONDS = 0.2


def _tcp_info(sock) -> bytes | None:
    option = getattr(socket, "TCP_INFO", None)
    if option is None:
        return None
    try:
        info = sock.getsockopt(socket.IPPROTO_TCP, option, 256)
    except (OSError, ValueError, AttributeError):
        return None
    return info if len(info) >= 136 else None


def _progress(sock) -> tuple[int | None, int | None]:
    """(:func:`_silence_ms`, :func:`_bytes_received`) from one TCP_INFO."""
    import struct

    info = _tcp_info(sock)
    if info is None:
        return _silence_ms(sock), _bytes_received(sock)
    return struct.unpack_from("I", info, 52)[0], struct.unpack_from("Q", info, 128)[0]


def _silence_ms(sock) -> int | None:
    """Milliseconds since the kernel last received data on *sock* (Linux
    TCP_INFO's tcpi_last_data_recv), None where it cannot tell."""
    import struct

    info = _tcp_info(sock)
    return struct.unpack_from("I", info, 52)[0] if info is not None else None


def _bytes_received(sock) -> int | None:
    """Bytes the kernel received on *sock* so far (Linux TCP_INFO's
    tcpi_bytes_received), None where it cannot tell."""
    option = getattr(socket, "TCP_INFO", None)
    if option is None:
        return None
    try:
        import struct

        info = sock.getsockopt(socket.IPPROTO_TCP, option, 256)
        if len(info) < 136:
            return None
        return struct.unpack_from("Q", info, 128)[0]
    except (OSError, ValueError, AttributeError):
        return None


class _ConnectionTable:
    """The connections being served, and since when each is still sending
    its request. Full, a new connection makes room by closing the oldest one
    still sending (an attacker that reconnects without end held every slot
    and locked the token holder out); off loopback one address holds at
    most *per_ip* of them the same way."""

    def __init__(self, max_connections: int | None = None, per_ip: int | None = None) -> None:
        self._max = max_connections if max_connections is not None else MAX_CONNECTIONS
        self._per_ip = per_ip if per_ip is not None else MAX_CONNECTIONS_PER_IP
        self._base = self._max
        self._open: dict = {}  # socket -> [address group, reading since (monotonic) or None]
        # Connections that have shown the token or certificate (not a
        # GET /health): never pushed out. HTTP/1.0: one request each.
        self._trusted: set = set()
        self._started = 0
        self._lock = threading.Lock()

    def _oldest_reading_locked(self, ip: str | None = None):
        """The connection a newcomer replaces, of those still sending their
        request (of *ip*, when given) and not authenticated: of the oldest
        ones at least VICTIM_MIN_AGE_SECONDS old, the one silent longest,
        then with the fewest bytes (a trickler's one byte - not a TLS
        handshake that takes a few round trips behind a slow link). None
        that old (the table turns over faster than that): not simply the
        oldest - a slow handshake - but the oldest of the address holding
        the most."""
        reading = [(since, sock) for sock, (owner, since) in self._open.items()
                   if since is not None and sock not in self._trusted
                   and (ip is None or owner == ip)]
        if not reading:
            return None
        now = time.monotonic()
        pool = reading
        if ip is None:
            # From an address (an IPv6 /64) that clearly holds more of them
            # first - three or more and twice the median of the other
            # addresses: attackers sending more bytes than a slow handshake
            # made that handshake the one replaced every time. Only
            # connections at least BUSY_MIN_AGE_SECONDS old count: one
            # client's parallel calls (one connection each) do not make
            # its address the busy one. Equally busy addresses go in
            # together (none loses for holding the oldest connection).
            counts: dict = {}
            for since, sock in reading:
                if now - since >= BUSY_MIN_AGE_SECONDS:
                    owner = self._open[sock][0]
                    counts[owner] = counts.get(owner, 0) + 1
            if counts:
                ordered = sorted(counts.values())
                top = ordered[-1]
                others = ordered[:-1]
                median = others[len(others) // 2] if others else 0
                if top >= BUSY_GROUP_MIN and top >= 2 * median:
                    busiest = {owner for owner, n in counts.items() if n == top}
                    pool = [(since, sock) for since, sock in reading
                            if self._open[sock][0] in busiest]
        settled = []
        # The oldest few only: the kernel is asked about each, and the
        # accept loop must keep up with a flood. (A busy address's pool
        # always holds some old enough.)
        import heapq

        for since, sock in heapq.nsmallest(VICTIM_SAMPLE, pool, key=lambda pair: pair[0]):
            if now - since < VICTIM_MIN_AGE_SECONDS:
                continue  # too young to judge: its first round trip may be on the way
            # Silent longest first (a burst, then a stall - not a handshake
            # that keeps receiving its next record), then fewest bytes.
            silence, got = _progress(sock)
            settled.append((-(silence if silence is not None else 0),
                            got if got is not None else 0, since, sock))
        if settled:
            return min(settled, key=lambda row: row[:3])[3]
        # None old enough to judge (round 7's rule): the address holding the
        # most - of equally many, the one with the newest connection, not
        # the one holding the oldest (a slow handshake's) - and its oldest.
        held: dict = {}
        for since, sock in reading:
            owner = self._open[sock][0]
            count, newest = held.get(owner, (0, since))
            held[owner] = (count + 1, max(newest, since))
        group = max(held, key=held.get)
        return min((pair for pair in reading if self._open[pair[1]][0] == group),
                   key=lambda pair: pair[0])[1]

    def _evict_locked(self, sock) -> None:
        self._open.pop(sock, None)
        self._trusted.discard(sock)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass

    def admit(self, sock, ip: str) -> bool:
        """Room for *sock* from *ip* (True), or not (False: close it)."""
        with self._lock:
            if not _is_loopback(ip):
                group = _address_group(ip)
                mine = sum(1 for owner, _since in self._open.values() if owner == group)
                if mine >= self._per_ip:
                    victim = self._oldest_reading_locked(group)
                    if victim is None:
                        return False
                    self._evict_locked(victim)
            if len(self._open) >= self._max:
                victim = self._oldest_reading_locked()
                if victim is None:
                    return False
                self._evict_locked(victim)
            # The address group (an IPv6 /64), worked out once.
            self._open[sock] = [_address_group(ip), time.monotonic()]
            return True

    def thread_failed(self, sock) -> None:
        """*sock*'s thread could not start (a thread limit below the cap):
        the table counts as full from now on - the cap drops to what is
        open - and one connection still sending makes room for the next."""
        with self._lock:
            self._open.pop(sock, None)
            # Some headroom below what is open (the threads of the
            # connections pushed out take a moment to end), never below
            # CAP_FLOOR; it comes back as threads start again.
            self._max = max(CAP_FLOOR, min(self._max, len(self._open) - THREAD_FAILURE_HEADROOM))
            self._started = 0
            while len(self._open) > self._max:
                victim = self._oldest_reading_locked()
                if victim is None:
                    break
                self._evict_locked(victim)
            log.warning("mcp-http: no thread could start; the connection cap is now %d",
                        self._max)

    def thread_started(self) -> None:
        """A connection's thread started: after CAP_RECOVERY_STARTS of them
        in a row a lowered cap rises by THREAD_FAILURE_HEADROOM again."""
        with self._lock:
            if self._max >= self._base:
                return
            self._started += 1
            if self._started >= CAP_RECOVERY_STARTS:
                self._started = 0
                self._max = min(self._base, self._max + THREAD_FAILURE_HEADROOM)

    def distrust(self, sock) -> None:
        """*sock*'s request was refused and it is closing: it may be pushed
        out again (a refused trickler must not keep a slot)."""
        with self._lock:
            self._trusted.discard(sock)
            entry = self._open.get(sock)
            if entry is not None:
                entry[1] = time.monotonic()

    def authenticated(self, sock) -> None:
        """*sock* showed the token or certificate: it has its request, and is
        never pushed out from now on (also while its body arrives)."""
        with self._lock:
            entry = self._open.get(sock)
            if entry is not None:
                entry[1] = None
                self._trusted.add(sock)

    def reading(self, sock, still: bool) -> None:
        """*sock* is still sending its request, or has it."""
        with self._lock:
            entry = self._open.get(sock)
            if entry is not None:
                entry[1] = time.monotonic() if still else None

    def release(self, sock) -> None:
        with self._lock:
            self._open.pop(sock, None)
            self._trusted.discard(sock)


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """One thread per request. MCP tool calls may block on backend IO
    (read_file on a 4 MiB blob over SFTP, walk on a slow S3 prefix);
    the stdlib default single-threaded server would queue them."""

    daemon_threads = True
    allow_reuse_address = True
    # listen() backlog: the stdlib's 5 refused connections under a burst.
    request_queue_size = 128

    def _parts(self) -> None:
        if self.__dict__.get("read_deadlines") is None:
            self.read_deadlines = _ReadDeadlines()
            self.hangups = _HangupWatch()
            self.connections = _ConnectionTable(max_connections=connection_cap())
            self.bodies = _BodySlots()

    def process_request(self, request, client_address) -> None:
        """A thread per connection - each reads its own request, so one
        that blocks holds itself only - as _ConnectionTable admits it;
        turned away, the connection is closed unanswered (no thread)."""
        self._parts()
        ip = client_address[0] if client_address else "?"
        if not self.connections.admit(request, ip):
            log.warning("mcp-http: no room for a connection from %s (each one has shown "
                        "its token)", ip)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
            self.connections.thread_started()
        except RuntimeError as exc:
            # "can't start new thread": fewer threads than the cap allows.
            log.warning("mcp-http: a connection from %s got no thread: %s", ip, exc)
            self.connections.thread_failed(request)
            self.shutdown_request(request)
        except BaseException:
            self.connections.release(request)
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            table = self.__dict__.get("connections")
            if table is not None:
                table.release(request)

    def handle_error(self, request, client_address) -> None:
        """A client that went away (reset, broken pipe, a TLS handshake
        that failed) is one log line, not a traceback on stderr."""
        import sys as _sys

        exc = _sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, ssl.SSLError, TimeoutError, socket.timeout)):
            log.info("mcp-http %s: connection ended: %s", client_address[0] if
                     client_address else "?", exc)
            return
        log.exception("mcp-http %s: request failed", client_address[0] if
                      client_address else "?")


def _build_handler_class(
    tools: list,
    resources=None,
    sessions=None,
    log_forwarder=None,
    http_ip_limiter=None,
    tasks=None,
    local_only: bool = False,
    auth_token: str = "",
    http_unauth_limiter=None,
) -> type:
    """Return a _McpHTTPHandler subclass with ``_tools`` bound.

    ``http.server`` instantiates handlers fresh per request, so
    configuration must live on the class. A closure-held handler
    class also keeps the surface scoped to one server instance."""

    class _Bound(_McpHTTPHandler):
        pass

    _Bound._tools = tools
    _Bound._server_name = _mcp.SERVER_NAME
    _Bound._server_version = _mcp.SERVER_VERSION
    _Bound._resources = resources
    _Bound._sessions = sessions
    _Bound._log_forwarder = log_forwarder
    _Bound._http_ip_limiter = http_ip_limiter
    _Bound._http_unauth_limiter = http_unauth_limiter
    _Bound._tasks = tasks
    _Bound._local_only = local_only
    _Bound._require_client_cert = not local_only
    _Bound._auth_token = auth_token
    return _Bound


class _ThreadingServerV6(_ThreadingServer):
    address_family = socket.AF_INET6


def check_config(config: HTTPServerConfig) -> None:
    """Refuse a configuration that must not be served (ValueError with a
    one-line reason): a partial mTLS set, or a non-loopback host
    without TLS."""
    tls_flags = (config.cert_file, config.key_file, config.ca_file)
    if any(tls_flags) and not all(tls_flags):
        raise ValueError(
            "mTLS needs cert_file, key_file and ca_file together; "
            "refusing to fall back to plain HTTP with a partial set"
        )
    if not config.tls_enabled() and not _is_loopback(config.host):
        raise ValueError(
            f"refusing to bind to non-loopback host {config.host!r} "
            "without TLS — would send JSON-RPC traffic in cleartext. "
            "Provide cert_file + key_file + ca_file, or use 127.0.0.1.",
        )


def build_server(config: HTTPServerConfig) -> _ThreadingServer:
    """Construct the HTTP server. Separated from :func:`serve_http` so
    tests can drive a single request at a time."""
    check_config(config)
    if not config.tls_enabled() and not config.auth_token:
        # Loopback is reachable by every local user: never serve it open.
        config.auth_token = _new_token()
    tools = _mcp._build_tools(
        config.backend,
        allow_write=config.allow_write,
        backend_id=config.backend_id,
        root=config.root,
        backends=config.backends,
        tool_groups=config.tool_groups,
        allow_exec=config.allow_exec,
    )
    resources = _mcp._build_resources(config.backend, root=config.root)
    # One forwarder per server. Per-session demux happens inside
    # the forwarder via the contextvar the dispatcher sets.
    log_forwarder = _mcp._LogForwarder()
    _mcp._attach_log_forwarder(log_forwarder)
    # Per-session rate limiter — pass the config values through so
    # _SessionRegistry.create() can mint a fresh bucket per session.
    # rate_limit_enabled=False short-circuits both params to None.
    rate_burst = config.rate_burst if config.rate_limit_enabled else None
    rate_refill = config.rate_refill_per_sec if config.rate_limit_enabled else None
    sessions = _SessionRegistry(
        idle_seconds=config.session_idle_seconds,
        log_forwarder=log_forwarder,
        rate_burst=rate_burst,
        rate_refill_per_sec=rate_refill,
        # Plain HTTP is served on loopback only (check_config).
        per_client_cap=config.tls_enabled(),
    )
    http_ip_limiter = (
        _PerIPRateLimiter(
            burst=config.http_ip_burst,
            refill_per_sec=config.http_ip_refill_per_sec,
        )
        if config.http_ip_rate_enabled
        else None
    )
    http_unauth_limiter = (
        _PerIPRateLimiter(
            burst=DEFAULT_HTTP_UNAUTH_BURST,
            refill_per_sec=DEFAULT_HTTP_UNAUTH_REFILL_PER_SEC,
        )
        if config.http_ip_rate_enabled
        else None
    )
    # Shared task registry: tasks/start + tasks/status + tasks/cancel +
    # tasks/list. The dispatcher scopes tasks by session id internally.
    tasks = _mcp._TaskRegistry()
    sessions.tasks = tasks
    handler_cls = _build_handler_class(
        tools,
        resources=resources,
        sessions=sessions,
        log_forwarder=log_forwarder,
        http_ip_limiter=http_ip_limiter,
        tasks=tasks,
        local_only=not config.tls_enabled(),
        auth_token=config.auth_token or "",
        http_unauth_limiter=http_unauth_limiter,
    )
    # An IPv6 literal ("::1") needs an AF_INET6 socket.
    server_cls = _ThreadingServerV6 if ":" in config.host else _ThreadingServer
    srv = server_cls((config.host, config.port), handler_cls)
    srv.auth_token = config.auth_token or ""  # type: ignore[attr-defined]
    # Stash the forwarder on the server so serve_http's teardown
    # can detach it. Using an attr rather than a closure keeps the
    # build_server result inspectable by tests.
    srv._mcp_log_forwarder = log_forwarder  # type: ignore[attr-defined]
    if config.tls_enabled():
        ctx = _make_ssl_context(config)
        # Handshake in the per-connection thread (first read, under the
        # handler's socket timeout), not inside accept(): otherwise one
        # silent TCP client stalls the accept loop for everyone.
        srv.socket = ctx.wrap_socket(
            srv.socket, server_side=True, do_handshake_on_connect=False
        )
        log.info(
            "MCP HTTP+mTLS bound on %s:%d (cert=%s, ca=%s)",
            config.host,
            config.port,
            config.cert_file,
            config.ca_file,
        )
    else:
        log.info("MCP HTTP (no TLS) bound on %s:%d", config.host, config.port)
    return srv


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _token_directory() -> Path:
    """Where publish_token puts the token: the per-user runtime dir
    (``$XDG_RUNTIME_DIR``, private by spec), else ~/.config/axross."""
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if runtime and os.path.isabs(runtime) and os.path.isdir(runtime):  # relative: ignored
        return Path(runtime) / "axross"
    return Path.home() / ".config" / "axross"


def token_file_name(port: int, host: str | None = None) -> str:
    """``mcp-http-<host>-<port>.token`` (``mcp-http-<port>.token`` without a
    host): two servers on one port number but different addresses do not
    share - and overwrite - one file."""
    if not host:
        return f"mcp-http-{int(port)}.token"
    safe = re.sub(r"[^A-Za-z0-9.-]", "_", host.strip("[]"))
    return f"mcp-http-{safe}-{int(port)}.token"


def withdraw_token(path: Path) -> None:
    """Remove a token file publish_token wrote (the server stopped)."""
    try:
        os.unlink(path)
    except OSError:
        pass


def publish_token(token: str, port: int, directory: Path | None = None,
                  host: str | None = None) -> Path:
    """Write *token* to :func:`token_file_name` (mode 0600) in a 0700
    folder for the client to read; returns the file. An existing file or
    a symlink in its place is replaced, never written through. Call it
    only once the server is bound: a second server on a busy port
    overwrote the running one's token before its bind failed."""
    folder = Path(directory) if directory is not None else _token_directory()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(folder, 0o700)
    except OSError as exc:  # not ours to change: the file itself stays 0600
        log.warning("MCP token folder %s keeps its mode: %s", folder, exc)
    name = token_file_name(port, host)
    path = folder / name
    tmp = folder / f".{name}.{secrets.token_hex(6)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def shutdown_sessions(srv) -> None:
    """End every session of *srv* as DELETE would - their calls and tasks
    are cancelled, their profiles closed - and give the task workers
    SHUTDOWN_TASK_WAIT_SECONDS to stop (as stdio does at its end)."""
    handler = getattr(srv, "RequestHandlerClass", None)
    sessions = getattr(handler, "_sessions", None)
    if sessions is None:
        return
    tasks = sessions.tasks
    workers = [t.thread for t in tasks.list_all() if t.status == "running"] if tasks else []
    with sessions._lock:
        everyone = list(sessions._sessions.values())
        sessions._sessions.clear()
    for sess in everyone:
        sessions._retire(sess)
    deadline = time.monotonic() + _mcp.SHUTDOWN_TASK_WAIT_SECONDS
    for worker in workers:
        if worker is not None:
            worker.join(max(0.0, deadline - time.monotonic()))


def serve_http(config: HTTPServerConfig, *, announce=None) -> None:
    """Blocking HTTP serve loop. Ctrl+C (and SIGTERM, which is turned
    into the same exit) ends it cleanly. *announce(server)* runs once the
    socket is bound - publish the token there, never before - and may
    return a callable that undoes it when the server stops."""
    srv = build_server(config)
    undo = None
    guard = _mcp.sigterm_as_interrupt().__enter__()
    try:
        if announce is not None:
            undo = announce(srv)
        srv.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover — interactive path
        log.info("MCP HTTP: SIGINT / SIGTERM, shutting down")
    finally:
        guard.__exit__(None, None, None)
        # Tasks and running calls end with the server, as on stdio.
        shutdown_sessions(srv)
        if callable(undo):
            undo()
        # Detach the server-wide forwarder so repeated build_server()
        # calls in tests don't pile up handlers on the module logger.
        fwd = getattr(srv, "_mcp_log_forwarder", None)
        if fwd is not None:
            _mcp._detach_log_forwarder(fwd)
        srv.server_close()


__all__ = [
    "HTTPServerConfig",
    "MAX_QUEUED_NOTIFICATIONS",
    "build_server",
    "check_config",
    "publish_token",
    "serve_http",
]
