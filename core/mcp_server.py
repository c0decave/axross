"""Phase 6b — Minimal MCP server exposing axross backends to LLMs.

The MCP (Model Context Protocol) is a JSON-RPC 2.0 dialect for an
LLM client to discover and call tools on a server. This module
implements a stdio-framed MCP server: requests come in on stdin
(line-delimited JSON), responses go out on stdout. Logging goes to
stderr only (anything on stdout would corrupt the protocol stream).

Read-only by default
--------------------
``--mcp-write`` (or ``AXROSS_MCP_WRITE=1``) toggles a small set of
mutating tools. Off by default because an LLM with shell-equivalent
access to a remote SFTP / S3 / Dropbox session is a bigger blast
radius than most users intend.

Backends
--------
The server is started with a default backend (LocalFS rooted at
``$HOME``) and may be given additional named backends that tools
can route to per-call via an optional ``backend_id`` argument; when
omitted the default is used. Use the ``list_backends`` tool to
enumerate what's available. This keeps the common single-backend
shape narrow and predictable while letting operators expose a
curated set of protocols without starting multiple servers.

Activation
----------
``main.py`` only enters this module when ``AXROSS_MCP=1`` is set
**or** the ``--mcp-server`` CLI flag is passed. Otherwise the GUI
boots normally and this module is never imported.

Tool surface (read-only)
------------------------
* ``list_dir(path)``  → listing entries
* ``stat(path)``      → mode/size/mtime
* ``read_file(path, max_bytes=…)`` → bounded read
* ``checksum(path, algorithm=…)`` → native backend fingerprint, with
  a streaming hashlib fallback that emits progress notifications
  when the backend has no cheap native hash
* ``search(needle, ext=…, min_size=…, max_size=…)`` → metadata index
* ``walk(path, max_depth=…, max_entries=…)`` → bounded recursive
  listing with progress notifications
* ``recursive_checksum(path, algorithm=…, max_files=…, max_depth=…,
  max_file_bytes=…)`` → hash every file under path; one progress
  notification per hashed file

Adds when write is enabled:

* ``write_file(path, content_b64)``
* ``mkdir(path)``
* ``remove(path, recursive=False)``
* ``bulk_copy(src, dst, max_files=…, max_depth=…, overwrite=…)`` →
  tree copy, one progress notification per copied file

Long-running operations (MCP progress notifications)
----------------------------------------------------
Clients may supply ``params._meta.progressToken`` on ``tools/call``
to opt into streaming progress. Handlers that can report partial
work — ``walk`` (entries visited), ``grep`` (files scanned), and
``checksum`` (bytes hashed in the streaming fallback) — call
``ctx.progress(done, total, msg)`` inside the loop, which writes a
``notifications/progress`` frame to the same stdout stream the
final response goes to. The stdio transport is naturally serial so
progress frames never interleave with other responses.

Task namespace (fire-and-forget long-running calls)
---------------------------------------------------
For operations that outlive a reasonable request/response window,
a client can issue:

* ``tasks/start(name, arguments)``       → {task_id, status}
* ``tasks/status(task_id)``              → {status, last_progress,
                                            result?, error?}
* ``tasks/cancel(task_id)``              → {ok}
* ``tasks/list()``                       → [{task_id, status, tool, ...}]

The task runs on a background thread with its own cancel event.
``ctx.progress`` calls update the task record AND are still
forwarded to the session's stdout sink (so subscribed SSE
clients see them live). Completed results are capped at
``MAX_TASK_RESULT_BYTES`` and retained for
``TASK_RETENTION_SECONDS`` or until the per-scope cap kicks in.
Session-scoped on HTTP (client A can't observe or cancel client
B's tasks); server-scoped on stdio.
"""
from __future__ import annotations

import base64
import contextvars
import json
import logging
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, IO, Optional

try:  # pragma: no cover — optional dep
    import jsonschema
    _JSONSCHEMA_AVAILABLE = True
except ImportError:  # pragma: no cover
    jsonschema = None  # type: ignore[assignment]
    _JSONSCHEMA_AVAILABLE = False

log = logging.getLogger("core.mcp_server")

# Separate logger for write-tool audit trail. Operators typically
# route this to a different sink (append-only file, SIEM) than the
# general-purpose log. Every successful OR refused write lands
# here with the tool name, paths, and outcome — never the payload
# bytes themselves.
audit_log = logging.getLogger("core.mcp_server.audit")


PROTOCOL_VERSION = "2024-11-05"
# Versions we know how to speak. If a client asks for something older
# we still answer with our current version and hope for the best; if
# they ask for something we explicitly recognise, we echo it. The
# list is ordered newest-first.
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05",)
SERVER_NAME = "axross-mcp"
SERVER_VERSION = "0.1.0"

# JSON-RPC 2.0 standard error codes. We use these instead of a
# generic -32000 so MCP clients can distinguish "you sent bad args"
# from "my handler crashed".
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603

MAX_READ_BYTES = 4 * 1024 * 1024  # 4 MiB cap on a single read_file
# Default wall-clock ceilings per tool category. Values are generous
# enough for real backend latency (an SFTP list_dir on a spinning
# disk can take several seconds) but tight enough that a wedged
# backend call gives up in-session instead of holding the tool thread
# indefinitely.
DEFAULT_TIMEOUT_QUICK = 15.0    # stat, read_file, list_dir, search
DEFAULT_TIMEOUT_WALK = 60.0     # walk, grep
DEFAULT_TIMEOUT_WRITE = 30.0    # write tools
DEFAULT_TIMEOUT_PREVIEW = 30.0  # preview renders a thumbnail
# ``checksum`` may fall back to streaming-hash the whole file when the
# backend has no native fingerprint. Five minutes accommodates a
# gigabyte-class file over a slow link while still bounding a wedged
# backend. Tools that poll ctx.check_cancel() can still be stopped by
# the client at any point before this deadline.
DEFAULT_TIMEOUT_STREAM_HASH = 300.0

# JSON-RPC application error code for rate-limit rejection. The
# -32000 range is "server-defined"; nothing in the MCP spec claims
# a canonical value so we carve out one here.
ERR_RATE_LIMITED = -32001
# JSON-RPC application error code for tool wall-clock timeout. Also
# in the server-defined -32000 range.
ERR_TIMEOUT = -32002

# Rate limit defaults. Token bucket: burst == max instantaneous
# tools/call queued; refill_per_sec == steady-state rate.
DEFAULT_RATE_BURST = 30
DEFAULT_RATE_REFILL_PER_SEC = 1.0  # 60/min
# URI scheme for backend-rooted resources exposed via ``resources/list``
# and ``resources/read``. Referenced as ``axross:///<path>`` in every
# URI the server emits.
RESOURCE_SCHEME = "axross"
# Cap on the number of entries ``resources/list`` returns at the
# root. An LLM that pulled 20k resource descriptors would waste the
# context window; the URI template advertised via
# ``resources/templates/list`` covers arbitrary paths anyway, so the
# flat list is just a discovery aid, not an enumeration.
MAX_RESOURCES_LISTED = 100
# Per-file scan cap for the grep tool. Server-side regex over remote
# files costs network bandwidth; we refuse anything larger than this
# per match candidate.
MAX_GREP_FILE_BYTES = 4 * 1024 * 1024
# Hard ceiling on grep results to keep responses bounded.
MAX_GREP_MATCHES = 500
# Maximum grep pattern length. A legitimate regex is rarely longer
# than a few hundred chars; longer patterns are usually a DoS
# vector (pathological catastrophic-backtracking shapes tend to be
# verbose). Applies before re.compile.
MAX_GREP_PATTERN_LENGTH = 512
# Cheap heuristic for "nested unbounded quantifier" — the canonical
# ReDoS shape ``(a+)+``, ``(.*)*``, ``([abc]+)*``, etc. Captures
# most real-world attacks without false-positiving on patterns like
# ``[a-z]+`` or ``.*hello.*``. Compiled at import time.
import re as _re_preflight
_REDOS_NESTED_QUANTIFIER = _re_preflight.compile(
    r"\([^)]*[+*][^)]*\)\s*[+*]"
)
del _re_preflight
# Emit a progress notification every N entries during walk(). 50 is a
# compromise: often enough to keep a slow client informed, rare enough
# that the notification overhead stays below 2% of the per-entry cost
# on a fast local backend.
WALK_PROGRESS_EVERY = 50
# Chunk size for the streaming-hash fallback in the ``checksum`` tool.
# Matches the file-pane's _stream_sha256 so the two code paths hash at
# the same granularity, and keeps Python's hashlib in its sweet spot
# (any bigger and GIL hold-time per update starts starving the cancel
# check).
STREAM_HASH_CHUNK = 1 << 20  # 1 MiB
# Emit a progress notification every N chunks during streaming-hash.
# Four chunks = 4 MiB of file — small enough that a client watching a
# multi-GB blob gets live feedback, large enough that a 2-MiB file
# completes before the first progress frame (which is what the MCP
# spec recommends — "optional on small operations").
STREAM_HASH_PROGRESS_EVERY = 4
# Default per-file size ceiling for ``recursive_checksum``. Above this
# the file is recorded as ``skipped: "too-large"`` instead of
# streamed. 1 GiB is generous for documents / media but refuses to
# quietly pull a multi-GB VM image through a WAN backend. Callers
# that really want to hash those can bump ``max_file_bytes`` per-call.
RECURSIVE_CHECKSUM_MAX_FILE_BYTES = 1 << 30  # 1 GiB
# Default per-file size ceiling for ``bulk_copy``. Looser than
# ``recursive_checksum`` because copy is the user's explicit intent
# to move the bytes — a user who wants to hash 50 GiB usually means
# "spot-check a tree" and a 1 GiB cap saves them from themselves, but
# a user who wants to copy 50 GiB usually means "move that VM image
# over". 10 GiB keeps the safety rail at "huge object that probably
# shouldn't silently stream over a WAN backend" without refusing
# realistic payloads. Caller overrides per-call.
BULK_COPY_MAX_FILE_BYTES = 10 * (1 << 30)  # 10 GiB
# Allowed algorithm names for ``checksum``. Deliberately restricted to
# the four hashlib.new-safe algorithms that a client can reproduce
# locally — any request for a backend-specific hash (S3 ETag, Dropbox
# content-hash, quickxor) is refused rather than silently stream-
# hashing with sha256, which would give the caller the wrong answer.
_HASHLIB_ALGOS = frozenset({"sha256", "sha1", "md5", "sha512"})


# ---------------------------------------------------------------------------
# Tool catalogue
# ---------------------------------------------------------------------------

class CancelledError(Exception):
    """Raised by ``ToolContext.check_cancel()`` when the client has
    sent ``notifications/cancelled`` for the in-flight request."""


class _CancelRegistry:
    """Thread-safe map of ``request_id → threading.Event`` used to
    deliver ``notifications/cancelled`` from the dispatcher to the
    in-flight tool handler.

    Stdio transport is single-threaded: the registry is overkill but
    harmless. HTTP transport (ThreadingHTTPServer) runs each request
    on its own thread, which is why the registry exists — a cancel
    notification for request #42 has to find the handler-thread's
    event no matter what thread the notification arrives on."""

    def __init__(self) -> None:
        self._events: dict[Any, threading.Event] = {}
        self._lock = threading.Lock()

    def register(self, request_id) -> threading.Event:
        event = threading.Event()
        with self._lock:
            self._events[request_id] = event
        return event

    def unregister(self, request_id) -> None:
        with self._lock:
            self._events.pop(request_id, None)

    def cancel(self, request_id) -> bool:
        """Mark request *request_id* as cancelled. Returns True when
        we actually knew about that id, False otherwise — the
        difference is useful to log the "client cancelled a request
        we'd already finished" pattern."""
        with self._lock:
            event = self._events.get(request_id)
        if event is None:
            return False
        event.set()
        return True


# Hard cap on a serialised task result stored in the registry. A
# tool that returns a 500-entry recursive_checksum result might
# still fit; a gigabyte blob wouldn't — that would turn
# tasks/status into a memory-exhaustion vector. Tasks above the
# cap finish in status="error".
MAX_TASK_RESULT_BYTES = 16 * 1024 * 1024

# Default maximum number of tasks kept in the registry PER SESSION
# (or globally on stdio). Finished tasks beyond the cap are evicted
# oldest-first so tasks/start always succeeds even when a client
# forgets to call tasks/status on older tasks.
MAX_TASKS_PER_SCOPE = 100

# How long a finished task is retained in the registry before it
# becomes eligible for eviction. One hour is long enough for a
# distracted client to come back and poll the result, short
# enough that finished results don't pin memory indefinitely.
TASK_RETENTION_SECONDS = 3600


@dataclass
class _Task:
    """One server-side long-running task. Created by
    ``tasks/start``, polled by ``tasks/status``, cancelled by
    ``tasks/cancel``. The worker thread lives in ``thread``;
    status transitions and result / error / last_progress are
    set by the runner before the thread exits.
    """
    task_id: str
    scope: str  # session_id for HTTP, "" for stdio
    tool_name: str
    arguments: dict
    status: str  # "running" | "done" | "error" | "cancelled"
    started_at: float  # wall-clock seconds since epoch
    finished_at: float | None = None
    last_progress: dict | None = None
    result: Any = None
    error: str | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = field(default=None, repr=False)


class _TaskRegistry:
    """Per-server store of long-running :class:`_Task` records.

    Tasks are scoped via the ``scope`` key — session_id on HTTP,
    empty string on stdio. ``start`` / ``status`` / ``cancel`` /
    ``list_scope`` filter by scope so client A can't observe or
    kill client B's tasks on a shared HTTP server.

    Eviction: finished tasks retire after TASK_RETENTION_SECONDS
    AND whenever the scope has more than MAX_TASKS_PER_SCOPE live
    records (oldest finished first). Running tasks are never
    evicted from underneath their own worker thread.

    Thread-safety: all mutations go through ``_lock``. Lookups
    return a snapshot so callers don't hold the lock across IO.
    """

    def __init__(self, *, max_per_scope: int = MAX_TASKS_PER_SCOPE,
                 retention_seconds: float = TASK_RETENTION_SECONDS) -> None:
        self._tasks: dict[str, _Task] = {}
        self._lock = threading.Lock()
        self._max_per_scope = max_per_scope
        self._retention_seconds = retention_seconds

    def start(self, scope: str, tool_name: str, arguments: dict) -> _Task:
        import secrets as _secrets
        task_id = _secrets.token_hex(8)
        task = _Task(
            task_id=task_id, scope=scope, tool_name=tool_name,
            arguments=arguments, status="running",
            started_at=time.time(),
        )
        with self._lock:
            self._evict_stale_locked(scope)
            self._tasks[task_id] = task
        return task

    def get(self, task_id: str, scope: str) -> _Task | None:
        """Return the task if it exists AND belongs to *scope*.
        Scope mismatch returns None — looks the same as "not
        found" to the caller, which is the point: never leak the
        existence of another client's tasks."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None or task.scope != scope:
                return None
            return task

    def cancel(self, task_id: str, scope: str) -> bool:
        task = self.get(task_id, scope)
        if task is None:
            return False
        task.cancel_event.set()
        return True

    def list_scope(self, scope: str) -> list[_Task]:
        with self._lock:
            return [t for t in self._tasks.values() if t.scope == scope]

    def _evict_stale_locked(self, scope: str) -> None:
        """Drop finished tasks that either aged out of the retention
        window OR pushed the per-scope count over the cap. Caller
        must hold ``_lock``. Running tasks are never evicted."""
        import time as _time
        now = _time.time()
        scope_tasks = [t for t in self._tasks.values() if t.scope == scope]
        # Age-out first.
        for t in scope_tasks:
            if t.status == "running":
                continue
            if (t.finished_at is not None
                    and now - t.finished_at > self._retention_seconds):
                self._tasks.pop(t.task_id, None)
        # Cap-out: oldest finished first.
        scope_tasks = [t for t in self._tasks.values() if t.scope == scope]
        if len(scope_tasks) <= self._max_per_scope:
            return
        finished = [t for t in scope_tasks if t.status != "running"]
        finished.sort(key=lambda t: t.finished_at or t.started_at)
        overflow = len(scope_tasks) - self._max_per_scope
        for t in finished[:overflow]:
            self._tasks.pop(t.task_id, None)


class _RateLimiter:
    """Token-bucket limiter for ``tools/call``.

    Carved out of the dispatcher so servers that want custom quotas
    (a paid-tier gateway, a multi-tenant host) can swap in a
    different implementation without forking the whole module.

    The bucket starts full; ``try_acquire()`` consumes one token and
    returns whether it succeeded. Refill happens lazily on each
    call — no background timer to leak.
    """

    def __init__(self, burst: int = DEFAULT_RATE_BURST,
                 refill_per_sec: float = DEFAULT_RATE_REFILL_PER_SEC):
        if burst <= 0:
            raise ValueError("burst must be positive")
        if refill_per_sec < 0:
            raise ValueError("refill_per_sec must be >= 0")
        self._burst = burst
        self._refill = refill_per_sec
        self._tokens = float(burst)
        self._last = _monotonic()
        self._lock = threading.Lock()

    def try_acquire(self, cost: float = 1.0) -> bool:
        with self._lock:
            now = _monotonic()
            elapsed = max(0.0, now - self._last)
            self._tokens = min(float(self._burst),
                               self._tokens + elapsed * self._refill)
            self._last = now
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False

    @property
    def tokens(self) -> float:
        """Current (approximate) token count. Useful for metrics/
        debug — not atomic with a subsequent try_acquire."""
        return self._tokens


def _monotonic() -> float:
    """Module-private monotonic clock. Wrapping ``time.monotonic`` in
    a helper keeps tests able to patch a single symbol when they
    need to fake time."""
    import time
    return time.monotonic()


@dataclass
class _ToolContext:
    """Per-call context passed to every tool handler.

    ``progress_token`` is the MCP client's opaque value for correlating
    progress notifications with the originating request; ``stdout`` is
    the stream the dispatcher is writing responses to. ``progress()``
    is a no-op when either is absent — tests drive handlers directly
    without a stdout and callers that didn't request progress don't
    supply a token.

    ``cancel_event`` is the ``threading.Event`` the registry set()s
    when a ``notifications/cancelled`` arrived for our request id.
    Long-running handlers should call ``check_cancel()`` periodically
    so the client-side cancel translates to a real stop."""
    progress_token: Any = None
    stdout: Optional[IO] = None
    cancel_event: Optional[threading.Event] = None

    def progress(self, progress: float, total: float | None = None,
                 message: str = "") -> None:
        if self.progress_token is None or self.stdout is None:
            return
        notif = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": self.progress_token,
                "progress": progress,
                "total": total,
                "message": message,
            },
        }
        self.stdout.write(json.dumps(notif) + "\n")
        try:
            self.stdout.flush()
        except Exception:  # noqa: BLE001 — StringIO.flush is a no-op; real pipes may EPIPE
            pass

    def check_cancel(self) -> None:
        """Raise :class:`CancelledError` when the client has cancelled
        this request. Long loops should call this between iterations
        so the cancel lands within one loop tick of arrival."""
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise CancelledError("request cancelled by client")

    @property
    def is_cancelled(self) -> bool:
        return self.cancel_event is not None and self.cancel_event.is_set()


def _run_task(task: _Task, tool: "_Tool", stdout: IO | None) -> None:
    """Background worker body for a ``tasks/start`` invocation.

    Runs ``tool.handler`` with a ``_ToolContext`` wired so that:

    * ``ctx.progress(...)`` updates ``task.last_progress`` AND
      still writes the frame to the client's ``stdout`` (SSE sink
      on HTTP, stdout on stdio) so clients that stayed subscribed
      continue to see live progress.
    * ``ctx.cancel_event`` is the task's own cancel event, so a
      ``tasks/cancel`` flips it and the next
      ``ctx.check_cancel()`` raises.
    * The task_id doubles as the progressToken — a subscribed
      client can correlate notifications/progress frames with the
      task without an extra negotiation round-trip.

    Terminal status is set in ``finally`` so an unhandled exception
    still lands on ``error`` rather than leaving the task forever
    in ``running``. Result serialisation happens here so a tool
    returning a giant blob fails on the task record rather than
    wedging tasks/status later.
    """
    # Late import of json keeps the module-level surface minimal
    # and mirrors the convention used by other helpers in this file.
    import json as _json

    def _on_progress(progress: float, total: float | None = None,
                     message: str = "") -> None:
        task.last_progress = {
            "progress": float(progress),
            "total": float(total) if total is not None else None,
            "message": message,
        }

    ctx = _ToolContext(
        progress_token=task.task_id,
        stdout=stdout,
        cancel_event=task.cancel_event,
    )
    # Wrap ctx.progress so the task's last_progress snapshot stays
    # current AND the original SSE-bound ``stdout`` write still
    # happens. Instance-shadow the method; the dataclass doesn't
    # prevent attribute assignment.
    _orig_progress = ctx.progress

    def _progress(progress, total=None, message=""):
        _on_progress(progress, total, message)
        _orig_progress(progress, total, message)

    ctx.progress = _progress  # type: ignore[method-assign]

    try:
        result = tool.handler(task.arguments, ctx)
        # Serialise eagerly so a too-big-to-return payload fails
        # on the task record rather than making tasks/status choke.
        try:
            encoded = _json.dumps(result)
        except (TypeError, ValueError) as exc:
            task.status = "error"
            task.error = f"tool result not JSON-serialisable: {exc}"
            return
        if len(encoded) > MAX_TASK_RESULT_BYTES:
            task.status = "error"
            task.error = (
                f"tool result ({len(encoded)} bytes) exceeds "
                f"{MAX_TASK_RESULT_BYTES}-byte cap — fetch via "
                f"paginated / narrower tool args"
            )
            return
        task.result = result
        task.status = "done"
    except CancelledError:
        task.status = "cancelled"
    except Exception as exc:  # noqa: BLE001 — surface on task record
        task.status = "error"
        task.error = str(exc)
    finally:
        task.finished_at = time.time()


@dataclass
class _PreviewResult:
    """Marker return type from the ``preview`` handler. The dispatcher
    recognises it and emits an MCP ``image`` content block instead of
    the default ``text`` wrapper."""
    data_b64: str
    mime: str
    width: int = 0
    height: int = 0


@dataclass
class _Tool:
    name: str
    description: str
    schema: dict
    handler: Callable[[dict, _ToolContext], Any]
    write: bool = False  # gated behind --mcp-write
    # Wall-clock ceiling for one invocation. A background timer flips
    # the ctx.cancel_event when the deadline passes; handlers that call
    # ctx.check_cancel() then raise CancelledError and the dispatcher
    # answers -32000 "tool timed out". Tools that don't periodically
    # check cancel won't be force-killed — the timer just nudges them;
    # but every tool added after Commit 3 does check, so timeouts land
    # within one loop tick.
    timeout_seconds: float | None = None


def _backend_id_for(backend) -> str:
    """Stable id matching the convention used by the UI dialogs."""
    cls = type(backend).__name__
    name = getattr(backend, "name", "") or ""
    return f"{cls}:{name}" if name else cls


def _hash_one_path(
    backend, path: str, algo: str, ctx: "_ToolContext",
    *, total_bytes: int | None = None,
    emit_byte_progress: bool = True,
) -> dict:
    """Compute a hashlib hash of one file via the backend.

    Shared by the single-file ``checksum`` tool and the per-file loop
    inside ``recursive_checksum``. The logic is:

    1. Ask ``backend.checksum(path, algorithm=algo)`` for a native
       fingerprint. Trust it only when either the returned string
       has no ``":"`` (raw hex from a backend that honours the
       algorithm kwarg — SSH, WebDAV) OR the prefix matches the
       requested algo (``md5:<hex>`` when md5 asked). Backends that
       ignore the algorithm kwarg (S3 always returns ``md5:..``,
       Dropbox returns ``dropbox:..``) fall through.
    2. Streaming fallback: read the file through ``open_read`` in
       STREAM_HASH_CHUNK byte chunks into ``hashlib.new(algo)``.
       ``ctx.check_cancel()`` runs before every chunk so a client
       cancel lands within one chunk; ``ctx.progress`` emits every
       STREAM_HASH_PROGRESS_EVERY chunks when ``emit_byte_progress``
       is True.

    Callers that already know the file's size pass it via
    ``total_bytes`` to skip a duplicate stat round-trip (list_dir
    hands the size out; recursive walks reuse it). When None, we
    stat lazily and fall back to "total unknown" if that fails.

    The byte-level progress is suppressed inside ``recursive_checksum``
    so the per-file progress (files_done/files_total) stays
    monotonic from the client's perspective. Mixing both scales
    under the same progressToken would make the number regress on
    each new file — MCP clients treat that as a bug.
    """
    import hashlib as _hashlib

    native = backend.checksum(path, algorithm=algo) or ""
    trusted_native = ""
    if ":" in native:
        prefix, _, tail = native.partition(":")
        if prefix == algo and tail:
            trusted_native = tail
    elif native:
        trusted_native = native
    if trusted_native:
        return {"value": trusted_native, "source": "native"}
    size_for_total = total_bytes
    if size_for_total is None:
        try:
            size_for_total = int(getattr(backend.stat(path), "size", 0) or 0)
        except OSError:
            size_for_total = 0
    hasher = _hashlib.new(algo)
    bytes_done = 0
    chunks_since_progress = 0
    with backend.open_read(path) as fh:
        while True:
            ctx.check_cancel()
            chunk = fh.read(STREAM_HASH_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
            bytes_done += len(chunk)
            chunks_since_progress += 1
            if (emit_byte_progress
                    and chunks_since_progress >= STREAM_HASH_PROGRESS_EVERY):
                chunks_since_progress = 0
                ctx.progress(
                    progress=float(bytes_done),
                    total=(float(size_for_total) if size_for_total else None),
                    message=f"hashing {path} — {bytes_done} bytes",
                )
    return {"value": hasher.hexdigest(), "source": "stream"}


def _enforce_root(path: str, root: str) -> str:
    """Normalise *path* and refuse it when it escapes *root*.

    The MCP server is configured with one backend rooted at a
    directory the user explicitly opted into (default: $HOME for
    LocalFS). Without this check, an LLM client could ask to
    ``write_file("/etc/passwd")`` and the backend would happily
    obey because the path is absolute and the backend doesn't
    enforce its own root.

    Two-pass check:

    1. ``abspath`` normalises ``..`` / ``.`` segments so a payload
       like ``/root/../etc/passwd`` collapses to ``/etc/passwd``
       and fails the prefix match below.
    2. ``realpath`` walks the filesystem, resolving every symlink
       component, and we re-check the prefix on the resolved form.
       Without this second pass, a symlink ``/root/escape → /``
       (placed under the root either legitimately or by the LLM
       using the ``symlink`` write tool itself) would let
       ``write_file("/root/escape/etc/cron.d/evil")`` slip through:
       abspath sees ``/root/escape/etc/cron.d/evil`` which starts
       with the root prefix, but the backend writes to
       ``/etc/cron.d/evil``.

    Non-existent paths are tolerated: ``realpath`` of a
    not-yet-created file returns its would-be absolute path with
    symlink-resolved parents. The write then happens at that
    resolved location, which is still prefix-checked.

    Returns the cleaned absolute path on success. Raises
    :class:`PermissionError` (mapped to -32602 by the dispatcher)
    when either pass finds an escape.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if "\x00" in path:
        raise ValueError("path contains NUL byte")
    # ``os.path`` resolution rather than ``backend.normalize`` —
    # backend implementations vary and we want a stable attacker-
    # resistant shape no matter which backend got wired in.
    import os.path as op
    abs_root = op.abspath(root or "/")
    abs_path = op.abspath(op.join(abs_root, path) if not op.isabs(path) else path)

    def _inside(candidate: str) -> bool:
        # Trailing separator guard: prevents ``/etcother`` from
        # sliding through a naïve prefix check on ``/etc``.
        if abs_root == "/":
            return True
        root_prefix = abs_root.rstrip("/") + "/"
        return candidate == abs_root or candidate.startswith(root_prefix)

    if not _inside(abs_path):
        raise PermissionError(
            f"path {path!r} escapes the configured MCP root "
            f"{abs_root!r}"
        )
    # Second pass: resolve symlinks. realpath of a non-existent
    # leaf is the abspath with symlink-resolved parents (strict=
    # False is the default in Python 3.10+), which is exactly the
    # semantic we want — the write will land there.
    real_path = op.realpath(abs_path)
    # The root itself has to be realpath'd too: an operator who set
    # ``--mcp-root`` to a path whose parents contain a symlink
    # should still get a consistent comparison.
    real_root = op.realpath(abs_root)
    # Rebuild the "inside" check against the realpath form.
    if real_root == "/":
        return real_path
    real_prefix = real_root.rstrip("/") + "/"
    if real_path == real_root or real_path.startswith(real_prefix):
        return real_path
    raise PermissionError(
        f"path {path!r} resolves to {real_path!r} via symlink, "
        f"which escapes the configured MCP root {real_root!r}"
    )


def _build_tools(backend, *, allow_write: bool,
                 backend_id: str | None = None,
                 root: str | None = None,
                 backends: dict | None = None,
                 allow_scripts: bool = False) -> list[_Tool]:
    """Build the catalogue. Write tools are added only when allowed.

    *backend_id* is the metadata-index key the search tool is allowed
    to filter against. Defaults to the configured backend's own id —
    never None at runtime, so an LLM client can't enumerate paths
    that live on a backend we don't expose.

    *root* scopes the WRITE tools (write_file, mkdir, remove): every
    path is resolved against it and rejected if it escapes. Defaults
    to ``"/"`` which means "anywhere the backend can reach" — the
    GUI and CLI entry points should pass a tighter root for
    untrusted-LLM scenarios.

    *backends* is an optional registry of ``{id: backend}`` that lets
    each tools/call carry a ``"backend": "<id>"`` argument to pick a
    target other than the default. The ``backend`` positional arg
    remains the fallback used when the call omits ``backend``. This
    keeps single-backend deployments unchanged (no schema churn) and
    only adds the backend-selection field when a registry is wired."""
    server_backend_id = backend_id or _backend_id_for(backend)
    enforced_root = root or "/"

    # Per-call backend selector. When a registry is configured, tool
    # callers can pass ``{"backend": "<id>"}`` to route the invocation
    # to a non-default backend. Missing / None / absent-from-registry
    # falls back to the outer ``backend`` (the default) or raises
    # ValueError if the caller named an unknown id.
    _default_backend = backend

    def _resolve_backend(args):
        bid = args.get("backend") if isinstance(args, dict) else None
        if not bid:
            return _default_backend
        if not backends:
            # Single-backend deployment; the arg is ignored silently
            # rather than erroring — gentler on clients that always
            # pass a backend field by habit.
            return _default_backend
        b = backends.get(bid)
        if b is None:
            raise ValueError(
                f"unknown backend {bid!r}; call 'list_backends' to "
                f"see available ids"
            )
        return b

    def _list_dir(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path") or "/"
        entries = backend.list_dir(path)
        return [
            {
                "name": getattr(it, "name", ""),
                "is_dir": bool(getattr(it, "is_dir", False)),
                "size": int(getattr(it, "size", 0) or 0),
                "modified": (
                    getattr(it, "modified", None).isoformat()
                    if getattr(it, "modified", None) else None
                ),
            }
            for it in entries
            if getattr(it, "name", "") and getattr(it, "name", "") not in (".", "..")
        ]

    def _stat(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("stat requires a path")
        item = backend.stat(path)
        return {
            "name": getattr(item, "name", ""),
            "is_dir": bool(getattr(item, "is_dir", False)),
            "size": int(getattr(item, "size", 0) or 0),
            "modified": (
                getattr(item, "modified", None).isoformat()
                if getattr(item, "modified", None) else None
            ),
        }

    def _read_file(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("read_file requires a path")
        cap = int(args.get("max_bytes") or MAX_READ_BYTES)
        cap = max(0, min(cap, MAX_READ_BYTES))
        with backend.open_read(path) as fh:
            data = fh.read(cap + 1)
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        truncated = len(data) > cap
        if truncated:
            data = data[:cap]
        return {
            "content_b64": base64.b64encode(data).decode("ascii"),
            "size": len(data),
            "truncated": truncated,
        }

    def _checksum(args, ctx):
        """Return a content hash of ``path``. See :func:`_hash_one_path`
        for the native-vs-streaming decision and the cancel / progress
        contract."""
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("checksum requires a path")
        algo = (args.get("algorithm") or "sha256").lower()
        if algo not in _HASHLIB_ALGOS:
            raise ValueError(
                f"checksum algorithm must be one of "
                f"{sorted(_HASHLIB_ALGOS)}; got {algo!r}",
            )
        result = _hash_one_path(backend, path, algo, ctx)
        return {
            "value": result["value"],
            "algorithm": algo,
            "source": result["source"],
        }

    def _search(args, ctx):
        from core import metadata_index as MX
        # Scope to either the caller-requested backend (if it exists
        # in the registry) or the server's default. Never permit an
        # empty / None backend_id — that would search ACROSS every
        # backend the metadata_index ever saw, including ones this
        # server isn't supposed to expose.
        resolved = _resolve_backend(args)
        scope_id = (_backend_id_for(resolved)
                    if resolved is not _default_backend
                    else server_backend_id)
        kwargs = {
            "needle": args.get("needle"),
            "ext": args.get("ext"),
            "min_size": int(args.get("min_size") or 0),
            "backend_id": scope_id,
        }
        if args.get("max_size"):
            kwargs["max_size"] = int(args["max_size"])
        entries = MX.search_all(**kwargs)
        return [
            {
                "backend_id": e.backend_id,
                "path": e.path,
                "name": e.name,
                "size": e.size,
                "is_dir": e.is_dir,
                "modified": e.modified.isoformat() if e.modified else None,
            }
            for e in entries
        ]

    def _walk(args, ctx):
        """Breadth-first traversal of a directory tree with caps on
        depth and entry count. Emits progress every WALK_PROGRESS_EVERY
        entries so a slow backend (SFTP over WAN, S3 with many
        per-prefix round-trips) doesn't leave the client waiting in
        silence.

        Calls ``ctx.check_cancel()`` at the top of each outer-queue
        iteration AND at every progress tick, so a
        ``notifications/cancelled`` from the client lands within one
        list_dir round-trip of arrival."""
        backend = _resolve_backend(args)
        path = args.get("path") or "/"
        max_depth = int(args.get("max_depth") or 4)
        max_entries = int(args.get("max_entries") or 1000)
        if max_depth < 0 or max_entries <= 0:
            raise ValueError("walk: max_depth must be ≥0 and max_entries > 0")
        entries: list[dict] = []
        queue: list[tuple[str, int]] = [(path, 0)]
        while queue and len(entries) < max_entries:
            ctx.check_cancel()
            cur, depth = queue.pop(0)
            try:
                children = backend.list_dir(cur)
            except OSError:
                # Hidden perms or a vanished directory — skip and keep
                # walking; don't abort the whole request on one branch.
                continue
            for child in children:
                if len(entries) >= max_entries:
                    break
                name = getattr(child, "name", "")
                if not name or name in (".", ".."):
                    continue
                full = backend.join(cur, name)
                is_dir = bool(getattr(child, "is_dir", False))
                entries.append({
                    "path": full,
                    "name": name,
                    "is_dir": is_dir,
                    "size": int(getattr(child, "size", 0) or 0),
                })
                if is_dir and depth + 1 < max_depth:
                    queue.append((full, depth + 1))
                if len(entries) % WALK_PROGRESS_EVERY == 0:
                    ctx.check_cancel()
                    ctx.progress(
                        progress=float(len(entries)),
                        total=float(max_entries),
                        message=f"walked {len(entries)} entries @ {cur}",
                    )
        truncated = len(entries) >= max_entries and bool(queue)
        return {"entries": entries, "truncated": truncated}

    def _recursive_checksum(args, ctx):
        """Hash every file under ``path`` breadth-first up to
        ``max_files`` and ``max_depth``.

        Each record is one of three shapes:

        * hashed     — ``{path, size, algorithm, checksum, source}``
        * skipped    — ``{path, size, algorithm, skipped: "too-large"}``
        * errored    — ``{path, size, algorithm, error: "<msg>"}``

        Progress is emitted once per file (``files_done/max_files``).
        The single-file byte-level progress inside
        :func:`_hash_one_path` is suppressed here so the value the
        client sees stays monotonic — mixing files and bytes under
        the same progressToken would make the counter regress.

        A cancel lands within one chunk of the currently-hashing
        file OR at the next directory boundary, whichever comes first.

        Design note: unlike ``walk``, the tree can be accepted as
        either a directory (BFS expansion) or a single file (hashed
        once and returned in a 1-element list). The single-file form
        lets a client batch-hash a specific list of paths by issuing
        one call per path without switching between ``checksum`` and
        ``recursive_checksum`` based on prior knowledge.
        """
        backend = _resolve_backend(args)
        path = args.get("path") or "/"
        algo = (args.get("algorithm") or "sha256").lower()
        if algo not in _HASHLIB_ALGOS:
            raise ValueError(
                f"recursive_checksum algorithm must be one of "
                f"{sorted(_HASHLIB_ALGOS)}; got {algo!r}",
            )
        # ``or DEFAULT`` would coerce an explicit ``0`` to the default
        # and paper over a caller bug; use explicit ``is None`` checks
        # so invalid zeros surface in the validation block below.
        raw_max_files = args.get("max_files")
        max_files = 500 if raw_max_files is None else int(raw_max_files)
        raw_max_depth = args.get("max_depth")
        max_depth = 10 if raw_max_depth is None else int(raw_max_depth)
        raw_max_file_bytes = args.get("max_file_bytes")
        max_file_bytes = (RECURSIVE_CHECKSUM_MAX_FILE_BYTES
                          if raw_max_file_bytes is None
                          else int(raw_max_file_bytes))
        if max_files <= 0:
            raise ValueError("recursive_checksum: max_files must be > 0")
        if max_depth < 0:
            raise ValueError("recursive_checksum: max_depth must be ≥ 0")
        if max_file_bytes <= 0:
            raise ValueError(
                "recursive_checksum: max_file_bytes must be > 0",
            )

        entries: list[dict] = []
        truncated = False

        def _hash_file(full_path: str, size: int) -> None:
            """Hash one file, append a record, emit progress. Keeps
            the inner loop concise whether we took the tree branch or
            the single-file branch."""
            nonlocal truncated
            if size > max_file_bytes:
                entries.append({
                    "path": full_path, "size": size,
                    "algorithm": algo, "skipped": "too-large",
                })
                return
            ctx.check_cancel()
            try:
                result = _hash_one_path(
                    backend, full_path, algo, ctx,
                    total_bytes=size, emit_byte_progress=False,
                )
            except CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — record & continue
                entries.append({
                    "path": full_path, "size": size,
                    "algorithm": algo, "error": str(exc),
                })
                return
            entries.append({
                "path": full_path, "size": size,
                "algorithm": algo,
                "checksum": result["value"],
                "source": result["source"],
            })
            hashed = sum(1 for e in entries if "checksum" in e)
            ctx.progress(
                progress=float(hashed),
                total=float(max_files),
                message=f"{hashed}/{max_files} — {full_path}",
            )

        # Classify the root: file vs directory. The ``walk`` tool
        # always starts with a directory; we don't require that.
        try:
            root_stat = backend.stat(path)
        except OSError as exc:
            raise OSError(
                f"recursive_checksum({path}): stat failed: {exc}",
            ) from exc
        if not getattr(root_stat, "is_dir", False):
            _hash_file(path, int(getattr(root_stat, "size", 0) or 0))
            return {"entries": entries, "truncated": False}

        # BFS over the tree.
        queue: list[tuple[str, int]] = [(path, 0)]
        while queue:
            hashed = sum(1 for e in entries if "checksum" in e)
            if hashed >= max_files:
                truncated = True
                break
            ctx.check_cancel()
            cur, depth = queue.pop(0)
            try:
                children = backend.list_dir(cur)
            except OSError:
                # Hidden perms or a vanished directory — skip and keep
                # walking; don't abort the whole request on one branch.
                continue
            for child in children:
                hashed = sum(1 for e in entries if "checksum" in e)
                if hashed >= max_files:
                    truncated = True
                    break
                name = getattr(child, "name", "")
                if not name or name in (".", ".."):
                    continue
                full = backend.join(cur, name)
                is_dir = bool(getattr(child, "is_dir", False))
                if is_dir:
                    if depth + 1 < max_depth:
                        queue.append((full, depth + 1))
                    continue
                size = int(getattr(child, "size", 0) or 0)
                _hash_file(full, size)
        return {"entries": entries, "truncated": truncated}

    tools = [
        _Tool(
            name="list_dir",
            description="List entries in a directory on the configured backend.",
            schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path on the backend.",
                    },
                },
                "required": ["path"],
            },
            handler=_list_dir,
        ),
        _Tool(
            name="stat",
            description="Return name, type, size, and mtime for one path.",
            schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            handler=_stat,
        ),
        _Tool(
            name="read_file",
            description=(
                "Read up to max_bytes (default 4 MiB) from a file. Returns "
                "base64-encoded bytes. Set ``truncated=true`` when the file "
                "exceeds the cap."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_bytes": {"type": "integer", "minimum": 0},
                },
                "required": ["path"],
            },
            handler=_read_file,
        ),
        _Tool(
            name="checksum",
            description=(
                "Content hash of a file. Tries the backend's native "
                "fingerprint first (S3 ETag, Drive md5Checksum, ssh "
                "sha256sum, etc.); falls back to streaming the file "
                "through hashlib when the backend has no cheap hash. "
                "The streaming fallback emits MCP progress "
                "notifications every few MiB when the caller supplied "
                "_meta.progressToken, and stops within one chunk of a "
                "notifications/cancelled. algorithm must be one of "
                "sha256 / sha1 / md5 / sha512 — backend-specific hash "
                "names (etag, dropbox, quickxor) are rejected."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "algorithm": {
                        "type": "string",
                        "enum": sorted(_HASHLIB_ALGOS),
                    },
                },
                "required": ["path"],
            },
            handler=_checksum,
        ),
        _Tool(
            name="search",
            description=(
                "Search the offline metadata index by name substring, "
                "extension, and size range. Free of network round-trips."
            ),
            schema={
                "type": "object",
                "properties": {
                    "needle": {"type": "string"},
                    "ext": {"type": "string"},
                    "min_size": {"type": "integer", "minimum": 0},
                    "max_size": {"type": "integer", "minimum": 0},
                },
            },
            handler=_search,
        ),
        _Tool(
            name="walk",
            description=(
                "Breadth-first recursive listing under path. Caps at "
                "max_depth (default 4) and max_entries (default 1000). "
                "Emits MCP progress notifications when the caller "
                "supplied _meta.progressToken."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_depth": {"type": "integer", "minimum": 0},
                    "max_entries": {"type": "integer", "minimum": 1},
                },
                "required": ["path"],
            },
            handler=_walk,
        ),
        _Tool(
            name="recursive_checksum",
            description=(
                "Hash every file under path breadth-first. Each record "
                "is either {path, size, algorithm, checksum, source} "
                "(hashed), {path, size, algorithm, skipped: \"too-large\"} "
                "(file above max_file_bytes), or {path, size, algorithm, "
                "error: \"<msg>\"} (backend refused that one file). "
                "Emits one progress notification per hashed file; a "
                "notifications/cancelled lands within one chunk of the "
                "current file. algorithm is one of sha256 / sha1 / md5 "
                "/ sha512. Defaults: max_files=500, max_depth=10, "
                "max_file_bytes=1 GiB. If path names a file instead of "
                "a directory the result contains exactly one record."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "algorithm": {
                        "type": "string",
                        "enum": sorted(_HASHLIB_ALGOS),
                    },
                    "max_files": {"type": "integer", "minimum": 1},
                    "max_depth": {"type": "integer", "minimum": 0},
                    "max_file_bytes": {"type": "integer", "minimum": 1},
                },
                "required": ["path"],
            },
            handler=_recursive_checksum,
        ),
    ]

    # Read-only version-history tools. Not gated behind --mcp-write
    # because they don't mutate anything — a list_versions call on
    # a read-only S3 pane is as safe as list_dir.

    def _list_versions(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("list_versions requires a path")
        versions = backend.list_versions(path)
        return [
            {
                "version_id": getattr(v, "version_id", ""),
                "size": int(getattr(v, "size", 0) or 0),
                "modified": (
                    getattr(v, "modified", None).isoformat()
                    if getattr(v, "modified", None) else None
                ),
                "is_current": bool(getattr(v, "is_current", False)),
                "label": getattr(v, "label", "") or "",
            }
            for v in versions
        ]

    def _open_version_read(args, ctx):
        backend = _resolve_backend(args)
        path = args.get("path")
        version_id = args.get("version_id")
        if not path or not version_id:
            raise ValueError(
                "open_version_read requires path + version_id",
            )
        cap = int(args.get("max_bytes") or MAX_READ_BYTES)
        cap = max(0, min(cap, MAX_READ_BYTES))
        with backend.open_version_read(path, version_id) as fh:
            data = fh.read(cap + 1)
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        truncated = len(data) > cap
        if truncated:
            data = data[:cap]
        return {
            "content_b64": base64.b64encode(data).decode("ascii"),
            "size": len(data),
            "truncated": truncated,
        }

    def _grep(args, ctx):
        """Regex search inside file contents under a root path.

        Recurses up to ``max_depth`` levels, scans each file up to
        ``MAX_GREP_FILE_BYTES`` (anything larger is skipped so we
        don't stream 10 GiB logs by accident), and returns up to
        ``MAX_GREP_MATCHES`` hits as {path, line_no, line_text}.

        Cooperates with cancellation: the outer walk checks
        ``ctx.check_cancel()`` at every directory boundary AND every
        progress tick so client-side cancels land within one
        list_dir round-trip.

        NB: we apply regex line-by-line on UTF-8-decoded bytes with
        ``errors='replace'`` — so a regex like ``[^\\x00]*`` won't
        trip over null bytes; binaries tend to produce gibberish
        lines but the server doesn't crash.
        """
        import re
        backend = _resolve_backend(args)
        pattern = args.get("pattern")
        if not pattern:
            raise ValueError("grep requires a pattern")
        # ReDoS preflight. Python's stdlib ``re`` has no per-call
        # timeout; a catastrophic pattern like ``(a+)+b`` against a
        # line of many ``a``s burns CPU for seconds inside a single
        # regex.search. The outer tool timeout (60s) eventually
        # hard-stops the worker, but 60s of CPU per request × N
        # parallel HTTP clients is a real DoS vector.
        #
        # Two cheap guards:
        #  1. Length cap — a legitimate grep regex is rarely longer
        #     than a few hundred chars; refuse anything larger.
        #  2. Heuristic detection of nested unbounded quantifiers
        #     — the classic ReDoS shape. Doesn't catch every
        #     pathological case (e.g. alternation-based backtracking
        #     ``(a|a)+``) but covers the common ones with zero
        #     false positives on real-world patterns.
        if len(pattern) > MAX_GREP_PATTERN_LENGTH:
            raise ValueError(
                f"grep: pattern too long "
                f"({len(pattern)} > {MAX_GREP_PATTERN_LENGTH} chars)",
            )
        if _REDOS_NESTED_QUANTIFIER.search(pattern):
            raise ValueError(
                "grep: pattern contains a nested unbounded quantifier "
                "(ReDoS risk). Rewrite without '(…+)+' / '(…*)*' shapes."
            )
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"grep: bad regex {pattern!r}: {exc}") from exc
        start = args.get("path") or "/"
        max_depth = int(args.get("max_depth") or 2)
        max_matches = int(args.get("max_matches") or 100)
        max_matches = min(max_matches, MAX_GREP_MATCHES)
        if max_depth < 0 or max_matches <= 0:
            raise ValueError(
                "grep: max_depth must be ≥0 and max_matches > 0",
            )
        matches: list[dict] = []
        queue: list[tuple[str, int]] = [(start, 0)]
        files_scanned = 0
        while queue and len(matches) < max_matches:
            ctx.check_cancel()
            cur, depth = queue.pop(0)
            try:
                children = backend.list_dir(cur)
            except OSError:
                continue
            for child in children:
                if len(matches) >= max_matches:
                    break
                name = getattr(child, "name", "")
                if not name or name in (".", ".."):
                    continue
                full = backend.join(cur, name)
                is_dir = bool(getattr(child, "is_dir", False))
                if is_dir:
                    if depth + 1 < max_depth:
                        queue.append((full, depth + 1))
                    continue
                size = int(getattr(child, "size", 0) or 0)
                if size > MAX_GREP_FILE_BYTES:
                    continue
                try:
                    with backend.open_read(full) as fh:
                        raw = fh.read(MAX_GREP_FILE_BYTES + 1)
                except OSError:
                    continue
                files_scanned += 1
                if files_scanned % WALK_PROGRESS_EVERY == 0:
                    ctx.check_cancel()
                    ctx.progress(
                        progress=float(files_scanned),
                        total=None,
                        message=f"grepped {files_scanned} files @ {cur}",
                    )
                if isinstance(raw, str):
                    raw = raw.encode("utf-8", errors="replace")
                text = raw.decode("utf-8", errors="replace")
                for lineno, line in enumerate(text.splitlines(), start=1):
                    if regex.search(line):
                        matches.append({
                            "path": full,
                            "line_no": lineno,
                            # Trim long lines so one pathological
                            # minified .js file doesn't blow up the
                            # response payload.
                            "line": line[:500],
                        })
                        if len(matches) >= max_matches:
                            break
        truncated = len(matches) >= max_matches
        return {
            "matches": matches,
            "files_scanned": files_scanned,
            "truncated": truncated,
        }

    def _preview(args, ctx):
        """Generate a thumbnail of *path* via ``core.previews`` and
        return it as an MCP image content block (base64 PNG +
        mimeType) — much more native for MCP clients than the
        fire-and-hope base64-in-text shape.

        Only works for backends the previews module considers
        "local" (LocalFS + subclasses); raises PreviewNotAvailable
        otherwise."""
        backend = _resolve_backend(args)
        path = args.get("path")
        if not path:
            raise ValueError("preview requires a path")
        edge = int(args.get("edge") or 256)
        edge = max(16, min(edge, 2048))
        from core import previews as P
        # PreviewNotAvailable / PreviewTooLarge / PreviewDecodeFailed
        # are all ValueError subclasses? No — they're PreviewError.
        # Map them to ValueError (→ -32602) so the client knows the
        # request was the problem, not the server crashing.
        try:
            result = P.thumbnail(backend, path, edge=edge, use_cache=True)
        except P.PreviewError as exc:
            raise ValueError(f"preview({path}): {exc}") from exc
        # Return MCP image content directly — the dispatcher's
        # default wrapper turns results into {"type":"text"} blocks;
        # the preview handler signals otherwise by returning a
        # _ContentBlock wrapper that the dispatcher respects.
        return _PreviewResult(
            data_b64=base64.b64encode(result.data).decode("ascii"),
            mime=result.mime,
            width=result.width,
            height=result.height,
        )

    tools.extend([
        _Tool(
            name="preview",
            description=(
                "Render a thumbnail of an image file. Returns MCP "
                "image content (base64 + mimeType). edge (default "
                "256) is clamped to [16, 2048]. MIME allow-list + "
                "size/dimension caps from core.previews apply. Local "
                "backends only."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "edge": {"type": "integer", "minimum": 16,
                             "maximum": 2048},
                },
                "required": ["path"],
            },
            handler=_preview,
        ),
        _Tool(
            name="grep",
            description=(
                "Regex search inside file contents under a root path. "
                "Recurses up to max_depth (default 2); skips files "
                "larger than 4 MiB. Returns up to max_matches "
                "(default 100, ceiling 500) {path, line_no, line}. "
                "Cooperates with notifications/cancelled."
            ),
            schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string"},
                    "max_depth": {"type": "integer", "minimum": 0},
                    "max_matches": {"type": "integer", "minimum": 1},
                },
                "required": ["pattern"],
            },
            handler=_grep,
        ),
        _Tool(
            name="list_versions",
            description=(
                "List historical versions of a file (S3 ObjectVersions, "
                "Dropbox revisions, GDrive revision-history, Azure blob "
                "snapshots, WebDAV DeltaV). Empty list on backends with "
                "no native versioning."
            ),
            schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            handler=_list_versions,
        ),
        _Tool(
            name="open_version_read",
            description=(
                "Read a specific historical version of a file. Same "
                "max_bytes cap (default 4 MiB) as read_file. version_id "
                "comes from list_versions."
            ),
            schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "version_id": {"type": "string"},
                    "max_bytes": {"type": "integer", "minimum": 0},
                },
                "required": ["path", "version_id"],
            },
            handler=_open_version_read,
        ),
    ])

    if allow_write:

        def _audit(tool_name: str, outcome: str, **fields) -> None:
            """Emit a single audit line. Paths and outcomes are safe
            to log; payloads are never logged (write_file goes
            through this helper with ``size=<bytes>``, never the
            bytes themselves).
            """
            parts = [f"tool={tool_name}", f"outcome={outcome}"]
            for k, v in fields.items():
                parts.append(f"{k}={v!r}")
            audit_log.info(" ".join(parts))

        def _write_file(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            content_b64 = args.get("content_b64")
            if not path or content_b64 is None:
                raise ValueError("write_file requires path + content_b64")
            # Audit "attempt" BEFORE the backend call. A subsequent
            # process death between the write and the "ok" entry
            # still leaves a trace in the audit log — operators see
            # an "attempt" without matching "ok" and know the
            # outcome is unknown.
            _audit("write_file", "attempt", path=path)
            try:
                safe = _enforce_root(path, enforced_root)
                data = base64.b64decode(content_b64, validate=True)
                with backend.open_write(safe) as fh:
                    fh.write(data)
            except BaseException as exc:
                _audit("write_file", "refused", path=path,
                       error=type(exc).__name__)
                raise
            _audit("write_file", "ok", path=safe, size=len(data))
            return {"size": len(data)}

        def _mkdir(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            if not path:
                raise ValueError("mkdir requires a path")
            _audit("mkdir", "attempt", path=path)
            try:
                safe = _enforce_root(path, enforced_root)
                backend.mkdir(safe)
            except BaseException as exc:
                _audit("mkdir", "refused", path=path,
                       error=type(exc).__name__)
                raise
            _audit("mkdir", "ok", path=safe)
            return {"ok": True}

        def _remove(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            if not path:
                raise ValueError("remove requires a path")
            recursive = bool(args.get("recursive", False))
            _audit("remove", "attempt", path=path, recursive=recursive)
            try:
                safe = _enforce_root(path, enforced_root)
                backend.remove(safe, recursive=recursive)
            except BaseException as exc:
                _audit("remove", "refused", path=path,
                       recursive=recursive, error=type(exc).__name__)
                raise
            _audit("remove", "ok", path=safe, recursive=recursive)
            return {"ok": True}

        def _rename(args, ctx):
            backend = _resolve_backend(args)
            src = args.get("src")
            dst = args.get("dst")
            if not src or not dst:
                raise ValueError("rename requires src + dst")
            _audit("rename", "attempt", src=src, dst=dst)
            try:
                safe_src = _enforce_root(src, enforced_root)
                safe_dst = _enforce_root(dst, enforced_root)
                backend.rename(safe_src, safe_dst)
            except BaseException as exc:
                _audit("rename", "refused", src=src, dst=dst,
                       error=type(exc).__name__)
                raise
            _audit("rename", "ok", src=safe_src, dst=safe_dst)
            return {"ok": True}

        def _copy(args, ctx):
            backend = _resolve_backend(args)
            src = args.get("src")
            dst = args.get("dst")
            if not src or not dst:
                raise ValueError("copy requires src + dst")
            _audit("copy", "attempt", src=src, dst=dst)
            try:
                safe_src = _enforce_root(src, enforced_root)
                safe_dst = _enforce_root(dst, enforced_root)
                backend.copy(safe_src, safe_dst)
            except BaseException as exc:
                _audit("copy", "refused", src=src, dst=dst,
                       error=type(exc).__name__)
                raise
            _audit("copy", "ok", src=safe_src, dst=safe_dst)
            return {"ok": True}

        def _ensure_dir(backend, path: str) -> None:
            """Create ``path`` if missing, including any intermediate
            parents. Idempotent — a concurrent writer that creates the
            dir between our exists() and mkdir() does not raise."""
            if backend.exists(path) and backend.is_dir(path):
                return
            parent = backend.parent(path)
            # Terminate when parent == path (root of the backend).
            if parent and parent != path:
                _ensure_dir(backend, parent)
            try:
                backend.mkdir(path)
            except OSError:
                # Re-check after the failure — concurrent creator is
                # fine; anything else propagates.
                if not (backend.exists(path) and backend.is_dir(path)):
                    raise

        def _bulk_copy(args, ctx):
            """Copy a file or directory tree under ``src`` into ``dst``.

            Server-side per-file copy via ``backend.copy`` — same
            semantics as the single-file ``copy`` tool, repeated across
            every file the BFS visits under src. Each record is one
            of:

            * ``{src, dst, size, action: "copied"}``
            * ``{src, dst, size, action: "skipped",
                reason: "too-large" | "exists"}``
            * ``{src, dst, size, action: "error", error: "<msg>"}``

            Progress is emitted once per copied file
            (``files_copied/max_files``). Cancel is checked before
            every file and before every directory descent.

            Single-backend only in V1: src and dst both resolve
            through the same ``_resolve_backend(args)`` path. Cross-
            backend copy would need streaming open_read → open_write
            and is intentionally out of scope — that's what the
            full transfer_manager is for.

            When src is a file, dst is treated as the target file
            path. When src is a directory, dst is the target directory
            and the src tree lands under it; missing intermediate
            directories are created automatically.

            Per-file audit: every refusal OR skip emits its own audit
            line; successful copies are summarised in the final
            ``bulk_copy ok`` record to avoid flooding the audit stream
            when tens of thousands of small files move at once.
            """
            backend = _resolve_backend(args)
            src = args.get("src")
            dst = args.get("dst")
            if not src or not dst:
                raise ValueError("bulk_copy requires src + dst")
            # ``or DEFAULT`` silently coerces 0 → default and hides
            # invalid input; explicit None check surfaces it.
            raw_max_files = args.get("max_files")
            max_files = 1000 if raw_max_files is None else int(raw_max_files)
            raw_max_depth = args.get("max_depth")
            max_depth = 10 if raw_max_depth is None else int(raw_max_depth)
            raw_max_file_bytes = args.get("max_file_bytes")
            max_file_bytes = (BULK_COPY_MAX_FILE_BYTES
                              if raw_max_file_bytes is None
                              else int(raw_max_file_bytes))
            overwrite = bool(args.get("overwrite", False))
            if max_files <= 0:
                raise ValueError("bulk_copy: max_files must be > 0")
            if max_depth < 0:
                raise ValueError("bulk_copy: max_depth must be ≥ 0")
            if max_file_bytes <= 0:
                raise ValueError(
                    "bulk_copy: max_file_bytes must be > 0",
                )

            _audit("bulk_copy", "attempt", src=src, dst=dst,
                   overwrite=overwrite)
            try:
                safe_src = _enforce_root(src, enforced_root)
                safe_dst = _enforce_root(dst, enforced_root)
            except BaseException as exc:
                _audit("bulk_copy", "refused", src=src, dst=dst,
                       error=type(exc).__name__)
                raise

            entries: list[dict] = []
            truncated = False

            def _copy_one(src_file: str, dst_file: str, size: int) -> None:
                nonlocal truncated
                if size > max_file_bytes:
                    _audit("bulk_copy.file", "skipped",
                           src=src_file, dst=dst_file, reason="too-large")
                    entries.append({
                        "src": src_file, "dst": dst_file, "size": size,
                        "action": "skipped", "reason": "too-large",
                    })
                    return
                if not overwrite and backend.exists(dst_file):
                    _audit("bulk_copy.file", "skipped",
                           src=src_file, dst=dst_file, reason="exists")
                    entries.append({
                        "src": src_file, "dst": dst_file, "size": size,
                        "action": "skipped", "reason": "exists",
                    })
                    return
                ctx.check_cancel()
                try:
                    _ensure_dir(backend, backend.parent(dst_file))
                    backend.copy(src_file, dst_file)
                except CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — record + go on
                    _audit("bulk_copy.file", "error",
                           src=src_file, dst=dst_file,
                           error=type(exc).__name__)
                    entries.append({
                        "src": src_file, "dst": dst_file, "size": size,
                        "action": "error", "error": str(exc),
                    })
                    return
                entries.append({
                    "src": src_file, "dst": dst_file, "size": size,
                    "action": "copied",
                })
                copied_count = sum(
                    1 for e in entries if e.get("action") == "copied"
                )
                ctx.progress(
                    progress=float(copied_count),
                    total=float(max_files),
                    message=f"{copied_count}/{max_files} — {src_file}",
                )

            # File vs directory at the root.
            try:
                root_stat = backend.stat(safe_src)
            except OSError as exc:
                _audit("bulk_copy", "refused", src=src, dst=dst,
                       error=type(exc).__name__)
                raise
            if not getattr(root_stat, "is_dir", False):
                _copy_one(
                    safe_src, safe_dst,
                    int(getattr(root_stat, "size", 0) or 0),
                )
                copied = sum(1 for e in entries
                             if e.get("action") == "copied")
                _audit("bulk_copy", "ok", src=src, dst=dst,
                       files_copied=copied)
                return {"entries": entries, "truncated": False}

            # Directory: BFS walk of src, mirror under dst.
            _ensure_dir(backend, safe_dst)
            queue: list[tuple[str, str, int]] = [(safe_src, safe_dst, 0)]
            while queue:
                copied = sum(1 for e in entries
                             if e.get("action") == "copied")
                if copied >= max_files:
                    truncated = True
                    break
                ctx.check_cancel()
                cur_src, cur_dst, depth = queue.pop(0)
                try:
                    children = backend.list_dir(cur_src)
                except OSError:
                    continue
                for child in children:
                    copied = sum(1 for e in entries
                                 if e.get("action") == "copied")
                    if copied >= max_files:
                        truncated = True
                        break
                    name = getattr(child, "name", "")
                    if not name or name in (".", ".."):
                        continue
                    full_src = backend.join(cur_src, name)
                    full_dst = backend.join(cur_dst, name)
                    is_dir = bool(getattr(child, "is_dir", False))
                    if is_dir:
                        if depth + 1 < max_depth:
                            queue.append((full_src, full_dst, depth + 1))
                        continue
                    _copy_one(
                        full_src, full_dst,
                        int(getattr(child, "size", 0) or 0),
                    )

            copied_total = sum(1 for e in entries
                               if e.get("action") == "copied")
            _audit("bulk_copy", "ok", src=src, dst=dst,
                   files_copied=copied_total, truncated=truncated)
            return {"entries": entries, "truncated": truncated}

        def _symlink(args, ctx):
            backend = _resolve_backend(args)
            target = args.get("target")
            link_path = args.get("link_path")
            if not target or not link_path:
                raise ValueError("symlink requires target + link_path")
            # ``target`` is left un-enforced-root: symlinks are
            # allowed to POINT ANYWHERE (dangling links are a
            # legitimate POSIX pattern). Only the link's own path
            # is capped to the MCP root — because that's where the
            # write lands.
            _audit("symlink", "attempt", target=target, link_path=link_path)
            try:
                safe_link = _enforce_root(link_path, enforced_root)
                backend.symlink(target, safe_link)
            except BaseException as exc:
                _audit("symlink", "refused", target=target,
                       link_path=link_path, error=type(exc).__name__)
                raise
            _audit("symlink", "ok", target=target, link_path=safe_link)
            return {"ok": True}

        def _hardlink(args, ctx):
            backend = _resolve_backend(args)
            target = args.get("target")
            link_path = args.get("link_path")
            if not target or not link_path:
                raise ValueError("hardlink requires target + link_path")
            # Unlike symlinks, hardlinks REQUIRE the target to
            # already exist and must resolve to an inode. Still,
            # the target can be anywhere the backend permits; only
            # the link path is root-capped.
            _audit("hardlink", "attempt", target=target, link_path=link_path)
            try:
                safe_link = _enforce_root(link_path, enforced_root)
                backend.hardlink(target, safe_link)
            except BaseException as exc:
                _audit("hardlink", "refused", target=target,
                       link_path=link_path, error=type(exc).__name__)
                raise
            _audit("hardlink", "ok", target=target, link_path=safe_link)
            return {"ok": True}

        def _chmod(args, ctx):
            backend = _resolve_backend(args)
            path = args.get("path")
            mode = args.get("mode")
            if not path or mode is None:
                raise ValueError("chmod requires path + mode (octal)")
            # Accept both integer (0o644) and string ("0o644" / "644")
            # — LLMs tend to format octal inconsistently.
            if isinstance(mode, str):
                try:
                    mode_int = int(mode, 8)
                except ValueError as exc:
                    raise ValueError(
                        f"chmod: mode {mode!r} is not octal",
                    ) from exc
            else:
                mode_int = int(mode)
            if not 0 <= mode_int <= 0o7777:
                raise ValueError(
                    f"chmod: mode {mode_int:o} out of range (0..07777)",
                )
            _audit("chmod", "attempt", path=path, mode=oct(mode_int))
            try:
                safe = _enforce_root(path, enforced_root)
                backend.chmod(safe, mode_int)
            except BaseException as exc:
                _audit("chmod", "refused", path=path, mode=oct(mode_int),
                       error=type(exc).__name__)
                raise
            _audit("chmod", "ok", path=safe, mode=oct(mode_int))
            return {"ok": True}

        tools.extend([
            _Tool(
                name="write_file",
                description="Overwrite a file with base64-encoded bytes.",
                schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content_b64": {"type": "string"},
                    },
                    "required": ["path", "content_b64"],
                },
                handler=_write_file, write=True,
            ),
            _Tool(
                name="mkdir",
                description="Create a directory on the backend.",
                schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
                handler=_mkdir, write=True,
            ),
            _Tool(
                name="remove",
                description="Delete a file or directory.",
                schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "recursive": {"type": "boolean"},
                    },
                    "required": ["path"],
                },
                handler=_remove, write=True,
            ),
            _Tool(
                name="rename",
                description=(
                    "Move/rename a file or directory. Both src and dst "
                    "must live under the configured root."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "src": {"type": "string"},
                        "dst": {"type": "string"},
                    },
                    "required": ["src", "dst"],
                },
                handler=_rename, write=True,
            ),
            _Tool(
                name="copy",
                description=(
                    "Server-side copy of src to dst. Uses the backend's "
                    "native copy primitive (S3 CopyObject, WebDAV COPY, "
                    "shell cp) where available — no client-side streaming."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "src": {"type": "string"},
                        "dst": {"type": "string"},
                    },
                    "required": ["src", "dst"],
                },
                handler=_copy, write=True,
            ),
            _Tool(
                name="bulk_copy",
                description=(
                    "Copy a file OR directory tree from src into dst. "
                    "Per-file records: {src, dst, size, action} where "
                    "action is \"copied\", \"skipped\" (reason: "
                    "\"too-large\" or \"exists\"), or \"error\". Emits "
                    "one progress notification per copied file; a "
                    "notifications/cancelled stops within one file. "
                    "Defaults: max_files=1000, max_depth=10, "
                    "max_file_bytes=10 GiB, overwrite=false. Missing "
                    "dst parent directories are created automatically. "
                    "Same-backend only in V1 — cross-backend copy is "
                    "handled by the transfer manager, not the MCP "
                    "surface."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "src": {"type": "string"},
                        "dst": {"type": "string"},
                        "max_files": {"type": "integer", "minimum": 1},
                        "max_depth": {"type": "integer", "minimum": 0},
                        "max_file_bytes": {"type": "integer", "minimum": 1},
                        "overwrite": {"type": "boolean"},
                    },
                    "required": ["src", "dst"],
                },
                handler=_bulk_copy, write=True,
            ),
            _Tool(
                name="symlink",
                description=(
                    "Create a symbolic link. target may point anywhere "
                    "the backend permits (dangling links are allowed); "
                    "link_path is capped to the MCP root. Raises on "
                    "backends without symlink support (S3, cloud stores)."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "link_path": {"type": "string"},
                    },
                    "required": ["target", "link_path"],
                },
                handler=_symlink, write=True,
            ),
            _Tool(
                name="hardlink",
                description=(
                    "Create a hard link (second name for the same inode). "
                    "Cross-device errors surface as the backend's OSError. "
                    "Most protocols refuse — POSIX/SSH only."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "link_path": {"type": "string"},
                    },
                    "required": ["target", "link_path"],
                },
                handler=_hardlink, write=True,
            ),
            _Tool(
                name="chmod",
                description=(
                    "Change POSIX mode bits. Accepts integer (420 for "
                    "0o644) or octal-string (\"0o644\" / \"644\"). "
                    "Backends without POSIX bits (S3, WebDAV, etc.) raise."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "mode": {
                            "oneOf": [
                                {"type": "integer", "minimum": 0,
                                 "maximum": 0o7777},
                                {"type": "string"},
                            ],
                        },
                    },
                    "required": ["path", "mode"],
                },
                handler=_chmod, write=True,
            ),
        ])

    # ----------------------------------------------------------------
    # Scripting tools (opt-in via allow_scripts).
    #
    # script_list / script_read leak only metadata + bytes the user
    # already wrote; script_write / script_run / script_delete
    # mutate state. ALL are gated behind ``allow_scripts`` because
    # script_run hands the LLM ``exec()`` over Python in the server
    # process — that's strictly more powerful than the per-file
    # write_file tool. Operators who want neither leave the flag off.
    # ----------------------------------------------------------------
    if allow_scripts:
        from core import scripting as _scripting

        def _script_list(args, ctx):
            return {"scripts": _scripting.list_scripts()}

        def _script_read(args, ctx):
            name = args.get("name")
            if not name:
                raise ValueError("script_read requires a name")
            return {"name": name, "source": _scripting.load_script(name)}

        def _script_write(args, ctx):
            name = args.get("name")
            source = args.get("source", "")
            if not name:
                raise ValueError("script_write requires a name")
            path = _scripting.save_script(name, source)
            return {"name": name, "path": path, "size": len(source)}

        def _script_delete(args, ctx):
            name = args.get("name")
            if not name:
                raise ValueError("script_delete requires a name")
            _scripting.delete_script(name)
            return {"name": name, "deleted": True}

        def _script_run(args, ctx):
            """Execute a saved script in a fresh namespace (NOT the
            server's). stdout from the script is captured and
            returned so the LLM can see what the script printed."""
            import contextlib
            import io as _io
            name = args.get("name")
            if not name:
                raise ValueError("script_run requires a name")
            buf = _io.StringIO()
            err_buf = _io.StringIO()
            try:
                with contextlib.redirect_stdout(buf), \
                     contextlib.redirect_stderr(err_buf):
                    ns = _scripting.run_script(name)
            except SystemExit as exc:
                return {
                    "name": name, "exit": int(exc.code or 0),
                    "stdout": buf.getvalue(),
                    "stderr": err_buf.getvalue(),
                    "namespace_keys": [],
                }
            # Strip private + dunder names so the LLM doesn't see
            # injected helper modules.
            keys = sorted(
                k for k in ns
                if not k.startswith("_") and k not in ("axross",)
            )
            return {
                "name": name,
                "stdout": buf.getvalue(),
                "stderr": err_buf.getvalue(),
                "namespace_keys": keys,
            }

        tools.extend([
            _Tool(
                name="script_list",
                description=(
                    "Names of every saved Python script in the server's "
                    "script directory (~/.config/axross/scripts/)."
                ),
                schema={"type": "object", "properties": {}},
                handler=_script_list,
            ),
            _Tool(
                name="script_read",
                description=(
                    "Read the source of a saved script by name. Names are "
                    "[A-Za-z0-9_-]+; the path is built relative to the "
                    "server's script directory."
                ),
                schema={
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
                handler=_script_read,
            ),
            _Tool(
                name="script_write",
                description=(
                    "Save Python source as ``<name>.py`` (mode 0600) in "
                    "the server's script directory. Overwrites any "
                    "existing script with the same name."
                ),
                schema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "source": {"type": "string"},
                    },
                    "required": ["name", "source"],
                },
                handler=_script_write, write=True,
            ),
            _Tool(
                name="script_delete",
                description=(
                    "Remove a saved script by name. Idempotent — no error "
                    "when the file is already gone."
                ),
                schema={
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
                handler=_script_delete, write=True,
            ),
            _Tool(
                name="script_run",
                description=(
                    "Execute a saved script in a fresh namespace seeded "
                    "with ``axross`` (the curated scripting module). "
                    "Returns captured stdout/stderr and the names of "
                    "top-level vars the script left behind. Read "
                    "axross.help() for the available API."
                ),
                schema={
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
                handler=_script_run, write=True,
            ),
        ])

    # Multi-backend wiring: if the caller configured a registry,
    # advertise it via a list_backends tool AND decorate every tool's
    # input schema with an optional ``backend`` field. Single-backend
    # deployments skip both — keeping the schema footprint unchanged.
    if backends:
        # Find the registry id that corresponds to the default
        # backend — identity (``is``) rather than equality so a
        # custom __eq__ doesn't fool the lookup. Only the FIRST
        # match gets is_default=True, so an operator accidentally
        # registering the same instance under two ids doesn't end
        # up with two defaults.
        _default_id: str | None = None
        for _bid, _b in backends.items():
            if _b is _default_backend:
                _default_id = _bid
                break

        def _list_backends(args, ctx):
            out = []
            for bid, b in backends.items():
                out.append({
                    "id": bid,
                    "class": type(b).__name__,
                    "name": getattr(b, "name", "") or "",
                    "is_default": bid == _default_id,
                })
            return out

        tools.append(_Tool(
            name="list_backends",
            description=(
                "List configured backend IDs. Pass the id via the "
                "``backend`` argument on any other tool to route that "
                "call to a non-default backend."
            ),
            schema={"type": "object", "properties": {}},
            handler=_list_backends,
        ))
        for tool in tools:
            if tool.name == "list_backends":
                continue
            props = tool.schema.setdefault("properties", {})
            props.setdefault("backend", {
                "type": "string",
                "description": (
                    "Optional backend id. Omit to use the default; "
                    "call 'list_backends' to enumerate."
                ),
            })
    # Apply default wall-clock timeouts based on tool category. Set
    # here rather than at each _Tool() site so the table is easy to
    # reason about and tune in one place.
    _apply_default_timeouts(tools)
    return tools


# Category → default timeout. Tool names are looked up against this
# map; anything missing lands on DEFAULT_TIMEOUT_QUICK. Callers can
# override on a specific tool by assigning after build.
_TIMEOUT_BY_TOOL = {
    # Quick: one backend op, bounded output.
    "list_dir": DEFAULT_TIMEOUT_QUICK,
    "stat": DEFAULT_TIMEOUT_QUICK,
    "read_file": DEFAULT_TIMEOUT_QUICK,
    "checksum": DEFAULT_TIMEOUT_STREAM_HASH,
    "search": DEFAULT_TIMEOUT_QUICK,
    "list_versions": DEFAULT_TIMEOUT_QUICK,
    "open_version_read": DEFAULT_TIMEOUT_QUICK,
    # Traversal: may hit many files over slow backends.
    "walk": DEFAULT_TIMEOUT_WALK,
    "grep": DEFAULT_TIMEOUT_WALK,
    # recursive_checksum can be long: 500 files × streaming sha256 of
    # up-to-1 GiB each is many minutes even on a fast local backend.
    # The cancel path inside _hash_one_path means clients can always
    # stop sooner; this is just the deadline before the timer fires.
    "recursive_checksum": DEFAULT_TIMEOUT_STREAM_HASH,
    # Preview runs an image decoder + resizer — give it breathing room.
    "preview": DEFAULT_TIMEOUT_PREVIEW,
    # Writes: one round-trip per call, but a slow backend (SMB over a
    # flaky link) can take a while to acknowledge.
    "write_file": DEFAULT_TIMEOUT_WRITE,
    "mkdir": DEFAULT_TIMEOUT_WRITE,
    "remove": DEFAULT_TIMEOUT_WRITE,
    "rename": DEFAULT_TIMEOUT_WRITE,
    "copy": DEFAULT_TIMEOUT_WRITE,
    # bulk_copy walks a tree and issues backend.copy per file. 1000
    # files × 30 s each is a lot — but the cancel path inside the
    # per-file loop means the client can always stop sooner. The
    # streaming-hash ceiling doubles as "long write" ceiling here
    # since no separate long-write constant exists.
    "bulk_copy": DEFAULT_TIMEOUT_STREAM_HASH,
    "symlink": DEFAULT_TIMEOUT_WRITE,
    "hardlink": DEFAULT_TIMEOUT_WRITE,
    "chmod": DEFAULT_TIMEOUT_WRITE,
}


def _apply_default_timeouts(tools: list[_Tool]) -> None:
    for tool in tools:
        if tool.timeout_seconds is None:
            tool.timeout_seconds = _TIMEOUT_BY_TOOL.get(
                tool.name, DEFAULT_TIMEOUT_QUICK,
            )


# ---------------------------------------------------------------------------
# Resources (resources/list, resources/read, resources/templates/list)
# ---------------------------------------------------------------------------

# Conservative text-ish mime prefixes — anything not matching is
# returned as a base64 ``blob`` field per MCP spec. The goal isn't to
# be an authoritative mime detector; it's to avoid sending binary
# bytes to clients as text and getting UnicodeDecodeErrors on their
# end.
_TEXT_MIME_PREFIXES = ("text/", "application/json", "application/xml",
                       "application/yaml", "application/x-yaml",
                       "application/javascript")


def _parse_resource_uri(uri: str) -> str:
    """Parse ``axross://<path>`` and return the raw absolute path.

    Rejects any other scheme with a ValueError so the dispatcher can
    map it to -32602 rather than leaking an internal traceback.

    URL-encoded bytes are decoded: a malicious ``axross:///%2e%2e%2f``
    becomes ``/../`` which ``_enforce_root``'s abspath-then-realpath
    pass will either collapse (if staying inside the root) or
    reject (if escaping). Without this decode, the backend might
    interpret ``%2e`` inconsistently between protocols — a foot-gun
    once a backend that does decode (e.g. future URL-aware one)
    enters the picture.
    """
    import urllib.parse
    if not isinstance(uri, str):
        raise ValueError("uri must be a string")
    prefix = f"{RESOURCE_SCHEME}://"
    if not uri.startswith(prefix):
        raise ValueError(
            f"unsupported resource scheme: {uri!r} — expected "
            f"{prefix}<path>"
        )
    raw = uri[len(prefix):]
    # Strip query + fragment — they aren't meaningful for a file
    # URI and would otherwise be passed to the backend, which
    # might interpret them or fail with a confusing error.
    for sep in ("?", "#"):
        if sep in raw:
            raw = raw.split(sep, 1)[0]
    path = urllib.parse.unquote(raw)
    # Allow both ``axross:///abs/path`` (empty authority, common in
    # URI literature) and ``axross://abs/path``. The path component
    # starts after the first slash of an empty authority or is the
    # whole remainder. Normalise to a leading-slash absolute path.
    if not path.startswith("/"):
        path = "/" + path
    return path


def _guess_mime(path: str) -> str:
    """Best-effort mime guess for a path. Falls back to
    ``application/octet-stream`` so binary-safe callers get the blob
    encoding."""
    import mimetypes
    guess, _ = mimetypes.guess_type(path)
    return guess or "application/octet-stream"


@dataclass
class _ResourceCatalog:
    """Bundle the backend + root so ``_handle_request`` can serve
    ``resources/*`` without re-deriving them on every call.

    Kept separate from the tools catalogue because the MCP spec
    models resources and tools as two different capabilities. A
    server may expose one without the other; tests drive them
    independently."""
    backend: Any
    root: str  # absolute, enforced on every read

    def list_root(self) -> list[dict]:
        """Return up to MAX_RESOURCES_LISTED entries directly under
        the root, each as an MCP resource descriptor. Directories
        are included so an LLM can walk via the URI template."""
        try:
            entries = self.backend.list_dir(self.root)
        except Exception as exc:  # noqa: BLE001 — surface to client
            raise RuntimeError(f"list_root failed: {exc}") from exc
        out: list[dict] = []
        for it in entries:
            name = getattr(it, "name", "") or ""
            if not name or name in (".", ".."):
                continue
            is_dir = bool(getattr(it, "is_dir", False))
            # Slash-terminate dir URIs so clients can tell them apart
            # without an extra stat round-trip.
            child = self.root.rstrip("/") + "/" + name + ("/" if is_dir else "")
            mime = "inode/directory" if is_dir else _guess_mime(name)
            out.append({
                "uri": f"{RESOURCE_SCHEME}://{child}",
                "name": name,
                "description": "directory" if is_dir else f"file, {getattr(it, 'size', 0)} bytes",
                "mimeType": mime,
            })
            if len(out) >= MAX_RESOURCES_LISTED:
                break
        return out

    def list_templates(self) -> list[dict]:
        """One template covering any absolute path under the
        configured root. MCP clients substitute ``{path}`` with
        paths they discovered through tools or previous reads."""
        return [{
            "uriTemplate": f"{RESOURCE_SCHEME}://{{+path}}",
            "name": "backend-file",
            "description": (
                f"Any file reachable through the configured backend, "
                f"rooted at {self.root}. Reads are capped at "
                f"{MAX_READ_BYTES} bytes."
            ),
        }]

    def read(self, uri: str) -> dict:
        """Resolve *uri*, enforce the root, return an MCP
        ``resources/read`` contents entry."""
        raw_path = _parse_resource_uri(uri)
        # Strip trailing slash the caller used as a "is-directory"
        # marker — the backend won't accept it.
        clean = raw_path.rstrip("/") or "/"
        resolved = _enforce_root(clean, self.root)
        with self.backend.open_read(resolved) as fh:
            data = fh.read(MAX_READ_BYTES + 1)
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        if not isinstance(data, (bytes, bytearray)):
            raise RuntimeError(
                "backend.open_read yielded non-bytes; "
                "cannot encode as MCP resource content"
            )
        # Silently truncate at cap — the MCP spec has no partial-read
        # marker on resources/read so we'd have to lie either way.
        # 4 MiB is plenty for any text file an LLM should be reading
        # inline; binary blobs that size are a misuse of the resource
        # channel anyway.
        data = bytes(data[:MAX_READ_BYTES])
        mime = _guess_mime(resolved)
        text_like = any(mime.startswith(p) for p in _TEXT_MIME_PREFIXES)
        entry: dict[str, Any] = {"uri": uri, "mimeType": mime}
        if text_like:
            try:
                entry["text"] = data.decode("utf-8")
            except UnicodeDecodeError:
                # Mime said text but the bytes aren't UTF-8 (a
                # Latin-1 .txt, a binary file with a .log
                # extension). Fall back to blob so the client gets
                # the raw bytes instead of a partial mojibake
                # string.
                entry["blob"] = base64.b64encode(data).decode("ascii")
                entry["mimeType"] = "application/octet-stream"
        else:
            entry["blob"] = base64.b64encode(data).decode("ascii")
        return entry


def _build_resources(backend, *, root: str | None = None) -> _ResourceCatalog:
    """Construct the resources catalogue. Separated from
    :func:`_build_tools` so tests can drive one without the other
    and the HTTP transport can share them trivially."""
    return _ResourceCatalog(backend=backend, root=root or "/")


# ---------------------------------------------------------------------------
# notifications/message — server→client log forwarding (MCP logging cap.)
# ---------------------------------------------------------------------------

# Python logging level → MCP/syslog-style level string. MCP spec lists
# "debug", "info", "notice", "warning", "error", "critical", "alert",
# "emergency"; Python's stdlib doesn't have notice/alert/emergency, so
# we stick to the six that round-trip cleanly.
_PY_LEVEL_TO_MCP = {
    logging.DEBUG: "debug",
    logging.INFO: "info",
    logging.WARNING: "warning",
    logging.ERROR: "error",
    logging.CRITICAL: "critical",
}
_MCP_LEVEL_TO_PY = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "notice": logging.INFO,   # closest python has
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
    "alert": logging.CRITICAL,
    "emergency": logging.CRITICAL,
}


# ContextVar holding the current session id (HTTP) or None (stdio /
# no-session). The dispatcher sets it at entry to ``_handle_request``
# so the log forwarder can pick the right per-session sink on emit.
# A ContextVar survives across threads only when the parent context
# is copied (which is what stdlib's ThreadingMixIn does via
# ``contextvars.copy_context().run``), but we only rely on it being
# set *within* the same thread that runs the handler — every log
# record emitted during that handler sees it.
_current_session_id: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("mcp_current_session_id", default=None)
)


class _LogForwarder(logging.Handler):
    """Forward selected log records to an MCP client as
    ``notifications/message`` JSON-RPC notifications.

    Routing model
    -------------
    There is exactly **one** forwarder per server — attached to the
    ``core.mcp_server`` logger tree once at startup, removed at
    shutdown. Per-client routing is done inside ``emit()`` via a
    session-id → sink table. The HTTP transport registers a sink
    when a session is created and unregisters it on drop / idle
    eviction; stdio never registers anything and uses the
    ``default_sink`` (its stdout).

    Why a single shared instance instead of one handler per
    session? Because Python logging is additive: every attached
    handler receives every record. The previous "one
    ``_LogForwarder`` per session" scheme meant Session A's SSE
    stream received every log frame emitted during Session B's
    tool calls — a silent information-disclosure bug. With demux
    here, a record fires once, picks its sink via the current
    session contextvar, and writes only there.

    Thread-safety
    -------------
    The stdio transport only ever writes to stdout from the main
    request loop, but logging writes can fire from any thread (a
    handler's background pool, the HTTP ThreadingMixIn). A per-
    instance lock serialises per-sink writes.
    """

    def __init__(self, default_sink: IO | None = None,
                 min_level: int = logging.WARNING) -> None:
        super().__init__()
        self._default_sink = default_sink
        # session_id → sink. HTTP transport populates this.
        self._routes: dict[str, IO] = {}
        self._lock = threading.Lock()
        self._min_level = min_level

    # Backwards compat for existing callers / tests that pass a
    # positional sink.
    @property
    def _stdout(self) -> IO | None:
        return self._default_sink

    def set_default_sink(self, sink: IO | None) -> None:
        self._default_sink = sink

    def register_session(self, session_id: str, sink: IO) -> None:
        """Route log records emitted while
        ``_current_session_id.get() == session_id`` to *sink*."""
        with self._lock:
            self._routes[session_id] = sink

    def unregister_session(self, session_id: str) -> None:
        """Stop routing to *session_id*. Records emitted under that
        session after unregister fall through to the default sink
        (usually None on HTTP, so they're silently discarded — the
        session is gone, there's nobody to read them)."""
        with self._lock:
            self._routes.pop(session_id, None)

    def set_min_level(self, level: int) -> None:
        """Update the minimum level to forward. Records below this
        are dropped before the JSON round-trip."""
        self._min_level = level

    @property
    def min_level(self) -> int:
        return self._min_level

    def _pick_sink(self) -> IO | None:
        sid = _current_session_id.get()
        with self._lock:
            if sid is not None:
                route = self._routes.get(sid)
                if route is not None:
                    return route
                # A record emitted during a session whose sink has
                # already been unregistered (rare — the session was
                # just dropped on another thread). Silently discard:
                # there's nobody reading anyway.
                return None
            return self._default_sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.levelno < self._min_level:
                return
            sink = self._pick_sink()
            if sink is None:
                return
            level_str = _PY_LEVEL_TO_MCP.get(record.levelno, "info")
            try:
                message = record.getMessage()
            except Exception:  # noqa: BLE001 — broken %-args shouldn't kill logging
                message = record.msg
            frame = {
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "level": level_str,
                    "logger": record.name,
                    "data": message,
                },
            }
            try:
                line = json.dumps(frame, default=str) + "\n"
            except Exception:  # noqa: BLE001
                return
            # Lock per write so two records don't interleave bytes
            # into the same JSON-RPC line. Note: separate sinks get
            # separate serialisation — fine because each sink is
            # written to from one concrete thread at a time (the
            # per-session queue on HTTP, the main loop on stdio).
            with self._lock:
                try:
                    sink.write(line)
                    sink.flush()
                except Exception:  # noqa: BLE001 — EPIPE on client exit
                    pass
        except Exception:  # noqa: BLE001 — the logging system must never raise
            self.handleError(record)


# Loggers attached to the forwarder. Intentionally narrow: we want the
# client to see MCP server activity and audit events, not every
# unrelated chat from deeper ``core.*`` modules (SFTP reconnects,
# metadata index chatter) which would drown the useful signal.
_FORWARDED_LOGGER_NAMES = ("core.mcp_server", "core.mcp_server.audit")


def _attach_log_forwarder(forwarder: _LogForwarder) -> None:
    for name in _FORWARDED_LOGGER_NAMES:
        logging.getLogger(name).addHandler(forwarder)


def _detach_log_forwarder(forwarder: _LogForwarder) -> None:
    for name in _FORWARDED_LOGGER_NAMES:
        logging.getLogger(name).removeHandler(forwarder)


# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------

def _ok(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id, code: int, message: str, data=None):
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _negotiate_protocol_version(requested) -> str:
    """Pick the version string we'll echo back in the initialize
    response. Rule: if the client asked for one of our supported
    versions, echo it; otherwise answer with our newest. Per MCP
    spec 2024-11-05 the client is allowed to close the connection
    when it can't live with the server's chosen version — we don't
    pretend to support a wire format we don't understand."""
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return PROTOCOL_VERSIONS_NEWEST


PROTOCOL_VERSIONS_NEWEST = SUPPORTED_PROTOCOL_VERSIONS[0]


def _handle_request(req: dict, tools: list[_Tool],
                    stdout: IO | None = None,
                    cancels: _CancelRegistry | None = None,
                    resources: _ResourceCatalog | None = None,
                    log_forwarder: _LogForwarder | None = None,
                    rate_limiter: _RateLimiter | None = None,
                    session_id: str | None = None,
                    tasks: _TaskRegistry | None = None) -> dict | None:
    """Dispatch one request. Returns the response dict, or None if the
    request was a notification (no id) and no response is expected.

    ``stdout`` is the stream progress notifications should be written
    to during a tool call. Tests drive handlers without a stdout; the
    resulting context silently swallows ``ctx.progress()`` calls.

    ``cancels`` is the per-server registry of in-flight cancel events.
    The dispatcher registers the current request's id before calling
    the handler and unregisters in a finally — so an arriving
    ``notifications/cancelled`` can flip the event while the handler
    is still running.

    ``tasks`` is the per-server long-running-task registry. When
    non-None the dispatcher honours the ``tasks/*`` namespace
    (start, status, cancel, list) so clients can fire-and-forget
    a tool call and poll for results. None disables the namespace
    and the server returns -32601 for those methods.
    """
    # Bind the current session id on the contextvar so the
    # log forwarder can demux records to the right per-session sink.
    # Reset in a finally to keep the contextvar clean across request
    # boundaries — otherwise a record emitted later from a different
    # code path would inherit this session id.
    token = _current_session_id.set(session_id)
    try:
        return _dispatch(req, tools, stdout, cancels, resources,
                         log_forwarder, rate_limiter, tasks, session_id)
    finally:
        _current_session_id.reset(token)


def _dispatch(req: dict, tools: list[_Tool],
              stdout: IO | None,
              cancels: _CancelRegistry | None,
              resources: _ResourceCatalog | None,
              log_forwarder: _LogForwarder | None,
              rate_limiter: _RateLimiter | None,
              tasks: _TaskRegistry | None = None,
              session_id: str | None = None) -> dict | None:
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}
    if method == "initialize":
        # Echo the client's requested protocolVersion if we recognise
        # it; fall back to our newest. Let the client decide whether
        # to hang up on a mismatch.
        agreed = _negotiate_protocol_version(params.get("protocolVersion"))
        caps: dict[str, Any] = {"tools": {}}
        if resources is not None:
            # listChanged/subscribe both False — V1 doesn't emit
            # notifications/resources/updated. Clients that want live
            # updates can poll resources/list.
            caps["resources"] = {"listChanged": False, "subscribe": False}
        if log_forwarder is not None:
            # Empty object advertises the logging capability; per MCP
            # spec there are no sub-flags here yet.
            caps["logging"] = {}
        return _ok(req_id, {
            "protocolVersion": agreed,
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "capabilities": caps,
        })
    if method == "ping":
        # MCP standard liveness check. Empty params in, empty result
        # out. Exists so clients can probe the connection without the
        # cost of a tools/list round-trip.
        return _ok(req_id, {})
    if method == "notifications/initialized":
        # Client confirms it received our initialize response. No
        # reply required; the flow is just "ack, we're live".
        return None
    if method == "notifications/cancelled":
        # Deliver the cancel to the in-flight handler for that
        # request id. No response — notifications never get one.
        # Unknown / already-finished ids are silently tolerated per
        # MCP spec (a race between cancel and completion is normal).
        if cancels is not None:
            target = params.get("requestId")
            cancels.cancel(target)
        return None
    if method == "tools/list":
        return _ok(req_id, {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.schema,
                }
                for t in tools
            ],
        })
    if method == "logging/setLevel":
        if log_forwarder is None:
            return _err(req_id, ERR_METHOD_NOT_FOUND,
                        "logging capability not enabled on this server")
        level_str = params.get("level")
        if not isinstance(level_str, str):
            return _err(req_id, ERR_INVALID_PARAMS,
                        "logging/setLevel requires a string level")
        py_level = _MCP_LEVEL_TO_PY.get(level_str.lower())
        if py_level is None:
            return _err(req_id, ERR_INVALID_PARAMS,
                        f"unknown log level: {level_str!r}")
        log_forwarder.set_min_level(py_level)
        # Empty result object per MCP convention — the client polls
        # its own log sink to see the new stream, no confirmation
        # payload is needed.
        return _ok(req_id, {})
    if method == "resources/list":
        if resources is None:
            return _err(req_id, ERR_METHOD_NOT_FOUND,
                        "resources capability not enabled on this server")
        try:
            listing = resources.list_root()
        except Exception as exc:  # noqa: BLE001 — surface cleanly
            return _err(req_id, ERR_INTERNAL,
                        f"resources/list failed: {exc}",
                        data={"type": type(exc).__name__})
        return _ok(req_id, {"resources": listing})
    if method == "resources/templates/list":
        if resources is None:
            return _err(req_id, ERR_METHOD_NOT_FOUND,
                        "resources capability not enabled on this server")
        return _ok(req_id, {"resourceTemplates": resources.list_templates()})
    if method == "resources/read":
        if resources is None:
            return _err(req_id, ERR_METHOD_NOT_FOUND,
                        "resources capability not enabled on this server")
        uri = params.get("uri")
        if not isinstance(uri, str) or not uri:
            return _err(req_id, ERR_INVALID_PARAMS,
                        "resources/read requires a non-empty uri")
        try:
            entry = resources.read(uri)
        except ValueError as exc:
            return _err(req_id, ERR_INVALID_PARAMS,
                        f"resources/read rejected uri: {exc}",
                        data={"type": "ValueError"})
        except PermissionError as exc:
            return _err(req_id, ERR_INVALID_PARAMS,
                        f"resources/read refused uri: {exc}",
                        data={"type": "PermissionError"})
        except Exception as exc:  # noqa: BLE001
            return _err(req_id, ERR_INTERNAL,
                        f"resources/read failed: {exc}",
                        data={"type": type(exc).__name__})
        return _ok(req_id, {"contents": [entry]})
    if method in ("tasks/start", "tasks/status", "tasks/cancel",
                  "tasks/list"):
        if tasks is None:
            return _err(req_id, ERR_METHOD_NOT_FOUND,
                        "tasks namespace not enabled on this server")
        scope = session_id or ""
        if method == "tasks/start":
            name = params.get("name")
            args = params.get("arguments") or {}
            if not isinstance(name, str) or not name:
                return _err(req_id, ERR_INVALID_PARAMS,
                            "tasks/start requires a non-empty 'name'")
            if not isinstance(args, dict):
                return _err(req_id, ERR_INVALID_PARAMS,
                            "tasks/start 'arguments' must be an object")
            tool = next((t for t in tools if t.name == name), None)
            if tool is None:
                return _err(req_id, ERR_METHOD_NOT_FOUND,
                            f"Unknown tool: {name!r}")
            # Validate against the tool's schema — same guard as
            # synchronous tools/call. A malformed task that would
            # immediately fail in the worker is rejected upfront.
            if _JSONSCHEMA_AVAILABLE:
                try:
                    jsonschema.validate(args, tool.schema)
                except jsonschema.ValidationError as exc:
                    return _err(req_id, ERR_INVALID_PARAMS,
                                f"tool {name!r} arguments failed schema: "
                                f"{exc.message}",
                                data={"type": "ValidationError",
                                      "path": list(exc.absolute_path)})
            task = tasks.start(scope, name, args)
            # Spawn worker with a copy_context so contextvar-based
            # session routing in the log forwarder still works.
            ctx_snapshot = contextvars.copy_context()

            def _worker():
                ctx_snapshot.run(_run_task, task, tool, stdout)

            worker_thread = threading.Thread(
                target=_worker, daemon=True,
                name=f"mcp-task-{task.task_id}",
            )
            task.thread = worker_thread
            worker_thread.start()
            return _ok(req_id, {
                "task_id": task.task_id,
                "status": task.status,
                "tool": task.tool_name,
                "started_at": task.started_at,
            })
        if method == "tasks/status":
            task_id = params.get("task_id")
            if not isinstance(task_id, str) or not task_id:
                return _err(req_id, ERR_INVALID_PARAMS,
                            "tasks/status requires a non-empty 'task_id'")
            task = tasks.get(task_id, scope)
            if task is None:
                return _err(req_id, ERR_METHOD_NOT_FOUND,
                            f"unknown task_id {task_id!r}")
            out = {
                "task_id": task.task_id,
                "status": task.status,
                "tool": task.tool_name,
                "started_at": task.started_at,
                "finished_at": task.finished_at,
                "last_progress": task.last_progress,
            }
            # Include result / error only for terminal states so the
            # happy-path response stays small while running.
            if task.status == "done":
                out["result"] = task.result
            elif task.status == "error":
                out["error"] = task.error
            elif task.status == "cancelled":
                out["error"] = "cancelled by tasks/cancel"
            return _ok(req_id, out)
        if method == "tasks/cancel":
            task_id = params.get("task_id")
            if not isinstance(task_id, str) or not task_id:
                return _err(req_id, ERR_INVALID_PARAMS,
                            "tasks/cancel requires a non-empty 'task_id'")
            ok = tasks.cancel(task_id, scope)
            return _ok(req_id, {"ok": ok, "task_id": task_id})
        if method == "tasks/list":
            # Short summary per task — no result / error, no last_progress.
            # Clients call tasks/status for details on a specific id.
            scope_tasks = tasks.list_scope(scope)
            return _ok(req_id, {
                "tasks": [
                    {
                        "task_id": t.task_id,
                        "status": t.status,
                        "tool": t.tool_name,
                        "started_at": t.started_at,
                        "finished_at": t.finished_at,
                    }
                    for t in scope_tasks
                ],
            })
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        meta = params.get("_meta") or {}
        # Rate-limit BEFORE we touch the cancel registry or allocate a
        # context — the cheap rejection path should stay cheap. A
        # tools/list probe isn't rate-limited because it doesn't
        # traverse the backend; only tools/call does work.
        if rate_limiter is not None and not rate_limiter.try_acquire():
            return _err(req_id, ERR_RATE_LIMITED,
                        "tools/call rate limit exceeded — retry shortly",
                        data={"type": "RateLimitError"})
        # Register a cancel event for this request id BEFORE calling
        # the handler, so a notifications/cancelled that arrives on
        # another thread can flip the event while we're mid-handler.
        cancel_event = None
        if cancels is not None and req_id is not None:
            cancel_event = cancels.register(req_id)
        ctx = _ToolContext(
            progress_token=meta.get("progressToken"),
            stdout=stdout,
            cancel_event=cancel_event,
        )
        tool = next((t for t in tools if t.name == name), None)
        if tool is None:
            if cancels is not None and req_id is not None:
                cancels.unregister(req_id)
            return _err(req_id, ERR_METHOD_NOT_FOUND, f"Unknown tool: {name!r}")
        # Validate the supplied arguments against the tool's declared
        # inputSchema before we call the handler. jsonschema is an
        # optional dep — when absent we fall back to the handler's
        # own ValueError-raising checks.
        if _JSONSCHEMA_AVAILABLE:
            try:
                jsonschema.validate(args, tool.schema)
            except jsonschema.ValidationError as exc:
                if cancels is not None and req_id is not None:
                    cancels.unregister(req_id)
                return _err(req_id, ERR_INVALID_PARAMS,
                            f"tool {name!r} arguments failed schema: "
                            f"{exc.message}",
                            data={"type": "ValidationError",
                                  "path": list(exc.absolute_path)})
        # Wall-clock timeout enforcement. Two parallel mechanisms:
        #
        # 1. A threading.Timer flips ``cancel_event`` at the deadline.
        #    Handlers that poll ``ctx.check_cancel()`` (walk, grep)
        #    then exit cleanly on the next tick.
        #
        # 2. The handler runs on a dedicated worker thread joined
        #    with the timeout. If the handler is wedged inside a
        #    single blocking IO call (backend.read_file on a huge
        #    blob, backend.checksum stream-hashing a slow SFTP
        #    transfer), the cooperative cancel event is useless.
        #    The join-with-timeout still returns control to the
        #    dispatcher so the *client* is unblocked and receives
        #    ERR_TIMEOUT — even though the background thread may
        #    keep running and eventually complete its side effect.
        #    That's the honest trade-off: we cannot safely interrupt
        #    an arbitrary blocking IO call mid-flight.
        timer = None
        timed_out = threading.Event()
        if tool.timeout_seconds and cancel_event is not None:
            def _on_deadline():
                timed_out.set()
                cancel_event.set()
            timer = threading.Timer(tool.timeout_seconds, _on_deadline)
            timer.daemon = True
            timer.start()

        result_box: list = [None]
        error_box: list[BaseException | None] = [None]
        # Propagate our contextvars context so the worker's log
        # records still demux to the right session sink. A raw
        # Thread loses the contextvars binding set by the outer
        # _handle_request — copy_context().run fixes that.
        ctx_snapshot = contextvars.copy_context()

        def _runner():
            try:
                result_box[0] = tool.handler(args, ctx)
            except BaseException as exc:  # noqa: BLE001 — surface via error_box
                error_box[0] = exc

        worker = threading.Thread(
            target=lambda: ctx_snapshot.run(_runner),
            name=f"mcp-tool-{name}",
            daemon=True,
        )
        try:
            worker.start()
            # Give the worker slightly longer than the timer, so the
            # timer fires first and the cancel_event is set before
            # we decide "it really is hung". 200 ms grace covers the
            # timer's own scheduling latency.
            wait_for = (tool.timeout_seconds + 0.2
                        if tool.timeout_seconds else None)
            worker.join(timeout=wait_for)
            if worker.is_alive():
                # Hard stop: the handler ignored (or didn't poll)
                # the cooperative cancel. Return timeout; leave the
                # worker running as a zombie — it holds backend
                # state we can't safely pull out from under it.
                timed_out.set()
                return _err(req_id, ERR_TIMEOUT,
                            f"tool {name!r} exceeded its "
                            f"{tool.timeout_seconds}s timeout "
                            f"(worker still running in background)",
                            data={"type": "TimeoutError",
                                  "hard_stop": True})
            if error_box[0] is not None:
                exc = error_box[0]
                if isinstance(exc, CancelledError):
                    if timed_out.is_set():
                        return _err(req_id, ERR_TIMEOUT,
                                    f"tool {name!r} exceeded its "
                                    f"{tool.timeout_seconds}s timeout",
                                    data={"type": "TimeoutError"})
                    return _err(req_id, ERR_INTERNAL,
                                f"tool {name!r} cancelled by client",
                                data={"type": "CancelledError"})
                if isinstance(exc, (ValueError, TypeError)):
                    # TypeError from handler arg-coercion (``int(None)``,
                    # ``int([...])``) maps to -32602 alongside ValueError
                    # so clients can tell their payload was bad, not
                    # the server.
                    return _err(req_id, ERR_INVALID_PARAMS,
                                f"tool {name!r} rejected args: {exc}",
                                data={"type": type(exc).__name__})
                return _err(req_id, ERR_INTERNAL,
                            f"tool {name!r} failed: {exc}",
                            data={"type": type(exc).__name__})
            result = result_box[0]
        finally:
            if timer is not None:
                timer.cancel()
            if cancels is not None and req_id is not None:
                cancels.unregister(req_id)
        # Image content (preview tool): emit MCP ``image`` block.
        if isinstance(result, _PreviewResult):
            return _ok(req_id, {
                "content": [{
                    "type": "image",
                    "data": result.data_b64,
                    "mimeType": result.mime,
                }],
                "isError": False,
                "_meta": {
                    "width": result.width,
                    "height": result.height,
                },
            })
        return _ok(req_id, {
            "content": [{"type": "text",
                         "text": json.dumps(result, default=str)}],
            "isError": False,
        })
    if method is None:
        return _err(req_id, ERR_INVALID_REQUEST,
                    "Invalid Request: missing method")
    if req_id is None:
        # Notification we don't recognise — silent per JSON-RPC.
        return None
    return _err(req_id, ERR_METHOD_NOT_FOUND,
                f"Method not found: {method!r}")


# ---------------------------------------------------------------------------
# Server entry
# ---------------------------------------------------------------------------

@dataclass
class ServerConfig:
    backend: object
    allow_write: bool = False
    backend_id: str | None = None  # explicit override; default = derived
    # Write-tool root cap. Defaults to "/" (no extra restriction);
    # production setups expose only what the LLM is meant to touch
    # (e.g. "/home/user/data") so a path-traversal payload can't
    # write to /etc.
    root: str | None = None
    # Optional multi-backend registry: ``{id: backend_instance}``.
    # When set, the tools/call surface gains a list_backends tool
    # and every other tool accepts an optional ``backend`` arg that
    # routes the call to the named backend. The ``backend`` field on
    # this config is still the default (used when a tool call omits
    # ``backend``). Single-backend deployments leave this None.
    backends: dict | None = None
    # Scripting tools (script_list / read / write / run / delete) are
    # gated behind their own opt-in. Read-only would still leak any
    # secrets the user has pasted into local scripts; write+run hands
    # the LLM ``exec()`` over Python in the server process. Default
    # OFF so a casual LLM connection can't reach the script surface.
    allow_scripts: bool = False
    stdin: IO = field(default_factory=lambda: sys.stdin)
    stdout: IO = field(default_factory=lambda: sys.stdout)
    # Rate limit: token-bucket guarding tools/call only. Default on
    # so a runaway agent can't flood a backend, but tests and tight
    # local deployments can disable.
    rate_limit_enabled: bool = True
    rate_burst: int = DEFAULT_RATE_BURST
    rate_refill_per_sec: float = DEFAULT_RATE_REFILL_PER_SEC


def serve(config: ServerConfig) -> int:
    """Run the stdio JSON-RPC loop. Returns the exit code (0 on EOF,
    non-zero on protocol failure that we couldn't recover from)."""
    tools = _build_tools(
        config.backend,
        allow_write=config.allow_write,
        backend_id=config.backend_id,
        root=config.root,
        backends=config.backends,
        allow_scripts=config.allow_scripts,
    )
    resources = _build_resources(config.backend, root=config.root)
    cancels = _CancelRegistry()
    tasks = _TaskRegistry()
    rate_limiter = _RateLimiter(
        burst=config.rate_burst,
        refill_per_sec=config.rate_refill_per_sec,
    ) if config.rate_limit_enabled else None
    # Forward server logs to the client as notifications/message.
    # Install AFTER the first info log so that "serve starting" lands
    # in stderr (where operators look) rather than being the very
    # first JSON-RPC notification on a channel that the client hasn't
    # yet acked initialize on.
    log.info(
        "MCP serve starting: %d tool(s), write=%s",
        len(tools), config.allow_write,
    )
    log_forwarder = _LogForwarder(config.stdout)
    _attach_log_forwarder(log_forwarder)
    try:
        while True:
            line = config.stdin.readline()
            if not line:
                log.info("MCP serve: stdin closed, exiting")
                return 0
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                response = _err(None, ERR_PARSE, f"Parse error: {exc}")
            else:
                if not isinstance(req, dict):
                    response = _err(None, ERR_INVALID_REQUEST,
                                    "Invalid Request: not an object")
                else:
                    response = _handle_request(
                        req, tools, stdout=config.stdout, cancels=cancels,
                        resources=resources, log_forwarder=log_forwarder,
                        rate_limiter=rate_limiter, tasks=tasks,
                    )
            if response is not None:
                config.stdout.write(json.dumps(response) + "\n")
                config.stdout.flush()
    finally:
        _detach_log_forwarder(log_forwarder)


def default_backend():
    """Return the default backend used when no explicit one is given:
    LocalFS rooted at the user's home dir."""
    from core.local_fs import LocalFS
    return LocalFS()


__all__ = [
    "CancelledError",
    "DEFAULT_RATE_BURST",
    "DEFAULT_RATE_REFILL_PER_SEC",
    "ERR_INTERNAL",
    "ERR_INVALID_PARAMS",
    "ERR_INVALID_REQUEST",
    "ERR_METHOD_NOT_FOUND",
    "ERR_PARSE",
    "ERR_RATE_LIMITED",
    "ERR_TIMEOUT",
    "MAX_READ_BYTES",
    "MAX_RESOURCES_LISTED",
    "PROTOCOL_VERSION",
    "RESOURCE_SCHEME",
    "SERVER_NAME",
    "SERVER_VERSION",
    "SUPPORTED_PROTOCOL_VERSIONS",
    "ServerConfig",
    "default_backend",
    "serve",
]
