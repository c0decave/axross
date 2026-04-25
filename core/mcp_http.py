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
    Response: ``application/json`` with one JSON-RPC response, or
    HTTP 400 if the body isn't valid JSON, 401 if the session id
    is missing on a non-initialize request, 404 if the session id
    is unknown or expired.

``GET /messages``
    ``Accept: text/event-stream`` opens an SSE notification stream
    for a previously established session. The stream relays
    ``notifications/progress`` and ``notifications/message`` frames
    queued during that session's tool calls. The connection stays
    open until the client disconnects or the session is evicted.

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
    state (cancel registry, notification queue). Unknown ids are
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
"""
from __future__ import annotations

import http.server
import ipaddress
import json
import logging
import queue
import socketserver
import ssl
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from core import mcp_server as _mcp

log = logging.getLogger("core.mcp_http")

# Cap on the POST /messages body size. A hostile client can set a
# huge Content-Length header and send nothing; rfile.read() would
# block the server thread waiting. 16 MiB is generous for a JSON-RPC
# payload — ``read_file`` responses cap at 4 MiB and outer JSON
# framing is small.
MAX_REQUEST_BYTES = 16 * 1024 * 1024

# Idle timeout for a session. An initialize without follow-up
# activity shouldn't hold resources forever. Tunable via server
# config for long-running batch workflows.
DEFAULT_SESSION_IDLE_SECONDS = 30 * 60  # 30 minutes

# Maximum number of queued notifications per session. A client that
# never consumes its SSE stream shouldn't be able to grow the queue
# unbounded (tool handlers emit progress from a fast loop).
MAX_QUEUED_NOTIFICATIONS = 10_000

# SSE stream keepalive interval — the loop falls through every N
# seconds with an empty comment frame so intermediate proxies that
# close idle connections don't terminate a quiet-but-alive stream.
SSE_KEEPALIVE_SECONDS = 15.0

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

    def __init__(self, burst: int = DEFAULT_HTTP_IP_BURST,
                 refill_per_sec: float = DEFAULT_HTTP_IP_REFILL_PER_SEC):
        self._burst = burst
        self._refill = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = {}
        # (tokens, last_touch_monotonic) per IP
        self._lock = threading.Lock()
        self._calls = 0

    def try_acquire(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._calls += 1
            if self._calls % self._GC_EVERY_N_CALLS == 0:
                self._gc(now)
            tokens, last = self._buckets.get(
                ip, (float(self._burst), now))
            elapsed = max(0.0, now - last)
            tokens = min(float(self._burst),
                         tokens + elapsed * self._refill)
            if tokens >= 1.0:
                tokens -= 1.0
                self._buckets[ip] = (tokens, now)
                return True
            self._buckets[ip] = (tokens, now)
            return False

    def _gc(self, now: float) -> None:
        stale = [ip for ip, (_, last) in self._buckets.items()
                 if now - last > self._GC_IDLE_SECONDS]
        for ip in stale:
            self._buckets.pop(ip, None)


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Hostname — assume non-loopback unless literally "localhost".
        return host.lower() == "localhost"


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

    def touch(self) -> None:
        self.last_seen = time.monotonic()


class _SessionRegistry:
    """Thread-safe session store. Creates on demand, evicts idle.

    Holds a reference to the server-wide ``_LogForwarder`` so
    ``drop`` and ``evict_idle`` can unregister the session's
    routing entry. Without that call, the forwarder would keep
    pushing log records into the (now-unreferenced) session queue,
    which amplifies into a log-warning loop once the queue fills."""

    def __init__(self, *, idle_seconds: float = DEFAULT_SESSION_IDLE_SECONDS,
                 log_forwarder: "_mcp._LogForwarder | None" = None,
                 rate_burst: int | None = None,
                 rate_refill_per_sec: float | None = None):
        self._sessions: dict[str, _HttpSession] = {}
        self._lock = threading.Lock()
        self._idle_seconds = idle_seconds
        self._log_forwarder = log_forwarder
        # If both are set, every new session gets a fresh limiter
        # with those params. If either is None, the session runs
        # without a rate gate (tests, or rate_limit_enabled=False).
        self._rate_burst = rate_burst
        self._rate_refill_per_sec = rate_refill_per_sec

    def create(self) -> _HttpSession:
        sid = uuid.uuid4().hex
        limiter = None
        if (self._rate_burst is not None
                and self._rate_refill_per_sec is not None):
            limiter = _mcp._RateLimiter(
                burst=self._rate_burst,
                refill_per_sec=self._rate_refill_per_sec,
            )
        sess = _HttpSession(
            session_id=sid,
            queue=queue.Queue(maxsize=MAX_QUEUED_NOTIFICATIONS),
            cancels=_mcp._CancelRegistry(),
            rate_limiter=limiter,
        )
        with self._lock:
            self._sessions[sid] = sess
        return sess

    def get(self, session_id: str) -> _HttpSession | None:
        with self._lock:
            sess = self._sessions.get(session_id)
        if sess is not None:
            sess.touch()
        return sess

    def _unregister_forwarder(self, sess: _HttpSession) -> None:
        if (self._log_forwarder is not None
                and sess.log_forwarder_registered):
            self._log_forwarder.unregister_session(sess.session_id)
            sess.log_forwarder_registered = False

    def drop(self, session_id: str) -> bool:
        with self._lock:
            sess = self._sessions.pop(session_id, None)
        if sess is None:
            return False
        self._unregister_forwarder(sess)
        return True

    def evict_idle(self) -> list[str]:
        """Evict sessions whose ``last_seen`` is older than the idle
        window. Returns the list of dropped ids so callers can log."""
        now = time.monotonic()
        dropped_sessions: list[_HttpSession] = []
        with self._lock:
            for sid, sess in list(self._sessions.items()):
                if now - sess.last_seen > self._idle_seconds:
                    self._sessions.pop(sid, None)
                    dropped_sessions.append(sess)
        # Unregister OUTSIDE the registry lock to keep lock ordering
        # consistent with the forwarder's own lock.
        for sess in dropped_sessions:
            self._unregister_forwarder(sess)
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
    ctx.verify_mode = ssl.CERT_REQUIRED
    # TLS 1.2+ only — MCP is a 2024 spec and the clients that matter
    # all support 1.2. No reason to tolerate legacy.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class _McpHTTPHandler(http.server.BaseHTTPRequestHandler):
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

    def _check_ip_cap(self) -> bool:
        """Return True when the per-IP rate cap lets the request
        through. On reject, already sent a 429; caller should just
        return. /health is exempted because reverse-proxy health
        probes would otherwise starve themselves out."""
        if self._http_ip_limiter is None or self.path == "/health":
            return True
        ip = self.client_address[0] if self.client_address else "?"
        if self._http_ip_limiter.try_acquire(ip):
            return True
        self._send_error(429, "too many requests from this IP — slow down")
        return False

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        if not self._check_ip_cap():
            return
        if self.path == "/health":
            self._send_json({
                "server": self._server_name,
                "version": self._server_version,
            })
            return
        if self.path == "/messages":
            accept = self.headers.get("Accept", "")
            if "text/event-stream" not in accept:
                self._send_error(
                    406, "GET /messages requires Accept: text/event-stream",
                )
                return
            self._serve_sse()
            return
        self._send_error(404, "not found")

    def do_DELETE(self) -> None:  # noqa: N802 — stdlib naming
        if not self._check_ip_cap():
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
        dropped = self._sessions.drop(sid)
        status = 204 if dropped else 404
        self.send_response(status)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 — stdlib naming
        if not self._check_ip_cap():
            return
        if self.path != "/messages":
            self._send_error(404, "not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
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
        body = self.rfile.read(length)
        if len(body) != length:
            # Peer claimed more than they sent — truncated body is a
            # client bug at best and an attack at worst. Don't try to
            # parse what's there; reject cleanly.
            self._send_error(400, "truncated body: Content-Length mismatch")
            return
        try:
            req = json.loads(body)
        except json.JSONDecodeError as exc:
            self._send_error(400, f"invalid JSON: {exc}")
            return
        if not isinstance(req, dict):
            self._send_error(400, "request must be a JSON object")
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
                            "session id does not match presented "
                            "client certificate",
                        )
                        return
            else:
                if method != "initialize":
                    self._send_error(
                        400,
                        "missing Mcp-Session-Id (only initialize may omit it)",
                    )
                    return
                sess = self._sessions.create()
                sess.cert_fingerprint = peer_fp
                created_now = True

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
        resp = _mcp._handle_request(
            req, self._tools,
            stdout=sink,
            cancels=cancels,
            resources=self._resources,
            log_forwarder=self._log_forwarder,
            rate_limiter=rate_limiter,
            session_id=(sess.session_id if sess is not None else None),
            tasks=self._tasks,
        )
        if resp is None:
            # Notification with no id — nothing to send back.
            self.send_response(204)
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
        # Last-Event-ID header lets a client resume a dropped stream.
        # Malformed / missing values coerce to 0 which replays the
        # whole ring (that's the right behaviour for first-connect
        # too — a session that never attached a reader before will
        # have an empty ring, so "replay from 0" does nothing).
        raw_last = self.headers.get("Last-Event-ID")
        try:
            last_event_id = int(raw_last) if raw_last else 0
        except ValueError:
            log.debug(
                "mcp-http SSE: ignoring malformed Last-Event-ID %r",
                raw_last,
            )
            last_event_id = 0

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
            replay_events = [
                e for e in sess.replay_ring
                if e.event_id > last_event_id
            ]
            while True:
                try:
                    sess.queue.get_nowait()
                except queue.Empty:
                    break
        if replay_events:
            log.info(
                "mcp-http SSE replay: session=%s last_id=%d → %d events",
                sid[:8], last_event_id, len(replay_events),
            )

        try:
            # Emit the replay first. One frame per event, each with
            # ``id: N`` on its own line so the client's EventSource
            # updates ``lastEventId`` as the stream progresses.
            for ev in replay_events:
                self._write_sse_event(ev)
            while True:
                try:
                    event = sess.queue.get(timeout=SSE_KEEPALIVE_SECONDS)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                self._write_sse_event(event)
        except (BrokenPipeError, ConnectionResetError):
            log.info("mcp-http SSE client disconnected (session=%s)", sid[:8])
        except Exception:  # noqa: BLE001
            log.exception("mcp-http SSE loop error (session=%s)", sid[:8])

    def _write_sse_event(self, event: _SseEvent) -> None:
        """Write one SSE frame in the ``id: N\\ndata: {...}\\n\\n`` form.

        Bundled so the replay pass and the live pull loop share a
        single formatter — any future tweak (event types, multi-line
        data) lands in one place."""
        data = json.dumps(event.frame).encode("utf-8")
        line = (
            f"id: {event.event_id}\n".encode("ascii")
            + b"data: " + data + b"\n\n"
        )
        self.wfile.write(line)
        self.wfile.flush()

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    def _send_json(self, payload: dict, status: int = 200,
                   session_id: str | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
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


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """One thread per request. MCP tool calls may block on backend IO
    (read_file on a 4 MiB blob over SFTP, walk on a slow S3 prefix);
    the stdlib default single-threaded server would queue them."""
    daemon_threads = True
    allow_reuse_address = True


def _build_handler_class(tools: list, resources=None,
                         sessions=None, log_forwarder=None,
                         http_ip_limiter=None, tasks=None) -> type:
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
    _Bound._tasks = tasks
    return _Bound


def build_server(config: HTTPServerConfig) -> _ThreadingServer:
    """Construct the HTTP server. Separated from :func:`serve_http` so
    tests can drive a single request at a time."""
    if not config.tls_enabled() and not _is_loopback(config.host):
        raise ValueError(
            f"refusing to bind to non-loopback host {config.host!r} "
            "without TLS — would send JSON-RPC traffic in cleartext. "
            "Provide cert_file + key_file + ca_file, or use 127.0.0.1.",
        )
    tools = _mcp._build_tools(
        config.backend,
        allow_write=config.allow_write,
        backend_id=config.backend_id,
        root=config.root,
        backends=config.backends,
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
    rate_refill = (config.rate_refill_per_sec
                   if config.rate_limit_enabled else None)
    sessions = _SessionRegistry(
        idle_seconds=config.session_idle_seconds,
        log_forwarder=log_forwarder,
        rate_burst=rate_burst,
        rate_refill_per_sec=rate_refill,
    )
    http_ip_limiter = _PerIPRateLimiter(
        burst=config.http_ip_burst,
        refill_per_sec=config.http_ip_refill_per_sec,
    ) if config.http_ip_rate_enabled else None
    # Shared task registry: tasks/start + tasks/status + tasks/cancel +
    # tasks/list. The dispatcher scopes tasks by session id internally.
    tasks = _mcp._TaskRegistry()
    handler_cls = _build_handler_class(
        tools, resources=resources, sessions=sessions,
        log_forwarder=log_forwarder, http_ip_limiter=http_ip_limiter,
        tasks=tasks,
    )
    srv = _ThreadingServer((config.host, config.port), handler_cls)
    # Stash the forwarder on the server so serve_http's teardown
    # can detach it. Using an attr rather than a closure keeps the
    # build_server result inspectable by tests.
    srv._mcp_log_forwarder = log_forwarder  # type: ignore[attr-defined]
    if config.tls_enabled():
        ctx = _make_ssl_context(config)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        log.info(
            "MCP HTTP+mTLS bound on %s:%d (cert=%s, ca=%s)",
            config.host, config.port, config.cert_file, config.ca_file,
        )
    else:
        log.info("MCP HTTP (no TLS) bound on %s:%d", config.host, config.port)
    return srv


def serve_http(config: HTTPServerConfig) -> None:
    """Blocking HTTP serve loop. Ctrl+C exits cleanly."""
    srv = build_server(config)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover — interactive path
        log.info("MCP HTTP: SIGINT, shutting down")
    finally:
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
    "serve_http",
]
