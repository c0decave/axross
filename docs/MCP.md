# MCP server — deep-dive

Axross can run as a [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server so an LLM client (Claude Desktop, Cline, a custom agent)
can drive any configured backend through a JSON-RPC tool surface.

The server speaks MCP protocol version **2024-11-05**.

Languages: **English** · [Deutsch](MCP_de.md) · [Español](MCP_es.md)

---

## 1. Transports

### 1.1 Stdio

```bash
# Read-only; default backend is LocalFS rooted at $HOME.
axross --mcp-server

# Or via env var (same behaviour):
AXROSS_MCP=1 axross

# Write tools (write_file, mkdir, remove, rename, copy, symlink,
# hardlink, chmod). Path-traversal capped to a root you choose:
axross --mcp-server --mcp-write --mcp-root /home/me/data
```

Requests arrive on stdin (line-delimited JSON), responses go out on
stdout. Logs go to stderr only. When the MCP path is taken, PyQt is
not imported — the server runs cleanly on a headless host.

### 1.2 HTTP (+ optional mTLS)

```bash
# Loopback HTTP (non-loopback without TLS is refused):
axross --mcp-server --mcp-http 127.0.0.1:7331

# mTLS — all three files required:
axross --mcp-server --mcp-http 0.0.0.0:7331 \
    --mcp-cert server.pem --mcp-key server.key --mcp-ca trusted-ca.pem
```

Endpoints:

| Method + Path                         | Purpose                                                     |
|--------------------------------------|-------------------------------------------------------------|
| `POST /messages`                     | Send one JSON-RPC request, receive one response.            |
| `GET /messages` (SSE)                | Open an event-stream for notifications scoped to a session. |
| `DELETE /messages`                   | Explicitly terminate a session.                             |
| `GET /health`                        | Unauthenticated; returns `{server, version}`.               |

Sessions are required on HTTP. The first `POST /messages` carrying
`initialize` gets a fresh session id back in the `Mcp-Session-Id`
response header; every subsequent request stamps that id. Unknown
or expired ids answer 404.

mTLS is built with `CERT_REQUIRED` + TLS 1.2 minimum: a client that
can't present a certificate signed by the CA bundle is rejected
during the handshake before any HTTP parsing.

---

## 2. Tool surface

### Read-only tools (always available)

| Name                 | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| `list_dir(path)`     | Directory entries.                                                  |
| `stat(path)`         | Name, type, size, mtime.                                            |
| `read_file(path, max_bytes=)` | Base64-encoded file content; capped at 4 MiB by default.    |
| `checksum(path, algorithm=)`  | Native fingerprint where available (S3 ETag, sha256, md5).  |
| `search(needle, ext, min_size, max_size)` | Offline metadata index, scoped to the active backend's id. |
| `walk(path, max_depth, max_entries)`      | Bounded recursive listing; emits `notifications/progress`. |
| `grep(pattern, path, max_depth, max_matches)` | Regex search inside file contents. Skips files over 4 MiB, caps matches at 500. |
| `list_versions(path)` | Per-version metadata where the backend supports it.                |
| `open_version_read(path, version_id)` | Base64 content of a specific version.                      |
| `preview(path, edge=256)` | Thumbnail of an image — returned as MCP **image content** with proper mimeType. |

### Write tools (only when `--mcp-write`)

| Name                              | Description                                                                |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content_b64)`   | Base64 upload.                                                             |
| `mkdir(path)`                     | Create directory.                                                          |
| `remove(path, recursive=False)`   | Delete.                                                                    |
| `rename(src, dst)`                | Rename / move.                                                             |
| `copy(src, dst)`                  | Server-side copy where backend supports it; stream-copy fallback.          |
| `symlink(target, link_path)`      | Backends with `supports_symlinks=True` only.                               |
| `hardlink(target, link_path)`     | Backends with `supports_hardlinks=True` only.                              |
| `chmod(path, mode)`               | POSIX mode bits. Accepts int or octal string.                              |

Every write tool resolves its path via `_enforce_root` first — a
payload like `/etc/passwd` is rejected before any IO hits the
backend. Every call emits an audit-log entry on
`core.mcp_server.audit`, containing the tool, outcome, path, and
size — never the payload bytes.

### Capability: resources

When the server is built with a resource catalogue, three extra
endpoints are advertised:

| Method                         | Purpose                                                |
|--------------------------------|--------------------------------------------------------|
| `resources/list`               | Up to 100 entries directly under the configured root.  |
| `resources/templates/list`     | A URI template covering any absolute path.             |
| `resources/read`               | Fetch one `axross://<path>` URI.                      |

Text-like mimes return `{uri, mimeType, text}`; anything else (or
a `.txt` whose bytes aren't valid UTF-8) falls back to
`{uri, mimeType: octet-stream, blob: b64(bytes)}`.

### Capability: logging

When the server wires a `_LogForwarder` (stdio transport does this
by default; HTTP does per-session), selected log records are
forwarded to the client as `notifications/message` frames. Only
the `core.mcp_server` logger tree is forwarded — unrelated backend
chatter doesn't leak.

Client can dial the threshold live:

```json
{"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel",
 "params": {"level": "debug"}}
```

Accepted levels: `debug`, `info`, `notice`, `warning`, `error`,
`critical`, `alert`, `emergency`.

---

## 3. Progress, cancellation, timeouts

### 3.1 Progress

Pass `_meta.progressToken` on a `tools/call` and the server emits
`notifications/progress` frames from handlers that support them
(`walk` today, traversal-style tools in the future). On stdio the
frames go straight to stdout; on HTTP they're queued per-session
and relayed over the SSE stream (`GET /messages`).

### 3.2 Cancellation

Clients send `notifications/cancelled` with a `requestId`. A
per-session cancel registry flips a `threading.Event` that every
long-running handler polls via `ctx.check_cancel()`. The handler
raises `CancelledError`, the dispatcher answers -32603 with
`data.type = "CancelledError"`, and the client discards the
response.

### 3.3 Timeouts

Every tool has a wall-clock ceiling:

| Category  | Timeout | Tools                                                                      |
|-----------|---------|----------------------------------------------------------------------------|
| Quick     | 15 s    | `stat`, `read_file`, `list_dir`, `checksum`, `search`, `list_versions`, `open_version_read` |
| Traversal | 60 s    | `walk`, `grep`                                                             |
| Preview   | 30 s    | `preview`                                                                  |
| Writes    | 30 s    | every write tool                                                           |

Two parallel mechanisms back the deadline:

1. A `threading.Timer` flips the handler's cancel event when the
   deadline elapses. Handlers that poll `ctx.check_cancel()`
   (`walk`, `grep`) exit cleanly on the next tick.
2. The dispatcher runs the handler on a dedicated worker thread
   and joins with the same timeout. If the handler is wedged in a
   single blocking IO call (`backend.read_file` on a huge blob;
   `backend.checksum` stream-hashing slow SFTP), the join returns
   control to the dispatcher so the **client** is unblocked and
   receives `ERR_TIMEOUT` — even though the background thread may
   keep running and eventually complete its side effect.

The response in the hard-stop case carries
`data.hard_stop = true` so clients can tell the server gave up
waiting (as opposed to a cooperative cancel where the handler
stopped mid-work).

Error code **-32002** with `data.type = "TimeoutError"` in both
cases, distinct from client-initiated cancel (-32603,
`CancelledError`).

**Honest caveat:** the hard-stop does *not* abort the backend
call. A `write_file` that times out may still land bytes on the
remote. A `remove` that times out may still delete the path. The
client sees a timeout response; the operator should assume the
underlying operation's outcome is unknown and either re-check or
re-issue with a suitable idempotency key. We can't safely
interrupt arbitrary blocking IO; anyone who tells you they can
is either lying or running under fork().

---

## 4. Rate limiting

Default on: 30-token burst, refills at 1 token/sec (60
`tools/call` per minute steady-state). Only `tools/call` is
limited; `tools/list`, `initialize`, `ping`, `resources/*`, and
`logging/setLevel` stay free.

Rejection is -32001 with `data.type = "RateLimitError"`.

Tune via `ServerConfig.rate_burst` / `rate_refill_per_sec` or
disable with `rate_limit_enabled = False`.

---

## 5. Multi-backend

Pass a dict of `{id: backend}` as `ServerConfig.backends`
(or `HTTPServerConfig.backends`). When present:

 - A new read-only `list_backends` tool returns
   `[{id, class, name, is_default}]` so the LLM can enumerate.
 - Every other tool's inputSchema gains an optional `backend: string`
   field. Omit it to route to the default; pass an id to route
   elsewhere. Unknown ids land on -32602.

Example:

```python
from core.mcp_server import ServerConfig, serve
from core.local_fs import LocalFS
from core.s3_client import S3Backend

serve(ServerConfig(
    backend=LocalFS(),           # default
    backends={
        "home": LocalFS(),
        "bucket": S3Backend(…),
    },
))
```

---

## 6. HTTP session lifecycle

```
┌──────────┐                                 ┌──────────┐
│  client  │  POST /messages  {initialize}   │  server  │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │  200  Mcp-Session-Id: <uuid>    │          │
│          │ <────────────────────────────── │          │
│          │                                 │          │
│          │  GET  /messages  (SSE)          │          │
│          │       Mcp-Session-Id: <uuid>    │          │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │   data: notifications/progress  │          │
│          │   data: notifications/message   │          │
│          │ <────────────────────────────── │          │
│          │                                 │          │
│          │  POST /messages  {tools/call}   │          │
│          │       Mcp-Session-Id: <uuid>    │          │
│          │ ──────────────────────────────> │          │
│          │                                 │          │
│          │  DELETE /messages               │          │
│          │       Mcp-Session-Id: <uuid>    │          │
└──────────┘                                 └──────────┘
```

 - Idle sessions are evicted after 30 minutes (tunable).
 - Per-session queue cap: 10 000 notifications. A client that
   never drains its SSE stream doesn't grow server memory
   unbounded — excess frames are dropped with a warning log.
 - SSE keepalive: a comment line every 15 s so idle-killer
   proxies don't tear the stream.

---

## 7. Security hardening

Every item below is an explicit guard against a red-team scenario
we've thought about. Tests live in
`tests/test_hardening_regressions.py` (classes `McpServerTests`
and `McpHttpTransportTests`).

### 7.1 Filesystem escape — symlink-resolving root check

`_enforce_root` runs a two-pass check on every write-tool path:
first `abspath` to collapse `..` / `.`, then `realpath` to
resolve symlinks and a second prefix test against the resolved
root. Without the second pass, a symlink placed under the
configured root (either externally or by the LLM using the
`symlink` write tool) would point at `/` and let
`write_file("/root/escape/etc/cron.d/evil")` slip past. Now
rejected with `PermissionError` → -32602.

### 7.2 Log demux — no cross-session leak

There is exactly **one** `_LogForwarder` per server, attached to
the `core.mcp_server` logger tree. A `contextvars.ContextVar` set
at dispatcher entry tells `emit()` which session's queue to route
the record into. Session A's SSE stream never receives log frames
emitted during Session B's tool calls. The earlier "one forwarder
per session" design silently leaked across sessions because
Python logging is additive.

### 7.3 Session forwarder unregister on drop

`_SessionRegistry.drop` and `evict_idle` unregister the session's
sink from the forwarder before discarding the session. Without
this step, log records kept writing into the dropped session's
queue, eventually raising `queue.Full`, which logged a warning,
which fired the forwarder, which wrote to every dead queue —
log-amplification loop. Now: sink removed with the session.

### 7.4 Hard-stop timeout

See §3.3. In short: handlers run on a dedicated worker thread
joined with the tool's deadline. If the worker wedges inside a
blocking backend call, the dispatcher still returns `ERR_TIMEOUT`
with `data.hard_stop = true`; the worker keeps running as a
zombie (we can't safely interrupt blocking IO), but the client is
unblocked.

### 7.5 Grep ReDoS preflight

Before `re.compile`, patterns are tested against:

 - Length cap (512 chars).
 - Nested-unbounded-quantifier heuristic (`(…+)+`, `(…*)*`, etc.)

Catastrophic-backtracking patterns reject at -32602 with an
actionable message. Not caught: alternation-based backtracking
(`(a|a)+`) — the 60-s hard-stop from §3.3 is the backstop there.

### 7.6 Per-session rate limiter

Each `_HttpSession` owns its own token bucket. One hostile client
can drain its own tokens without affecting any other session on
the same server. Config: `rate_burst`, `rate_refill_per_sec` on
`HTTPServerConfig` (defaults 30-token burst, 1 token/sec refill).

### 7.7 Per-IP HTTP edge cap

Before body parsing / session lookup / dispatch, `do_GET` /
`do_POST` / `do_DELETE` consult a per-source-IP bucket
(`_PerIPRateLimiter`). A flood of malformed or unauthenticated
POSTs can't burn CPU in the JSON-RPC pipeline. `/health` is
exempt so reverse-proxy probes don't starve themselves out.
Bucket entries idle > 5 min are GC'd. Config: `http_ip_burst`,
`http_ip_refill_per_sec`, `http_ip_rate_enabled` (defaults 120
burst, 60 req/s).

### 7.8 Session-id bound to client-cert fingerprint

On `initialize`, the server snapshots SHA-256 of the peer's DER
certificate onto `_HttpSession.cert_fingerprint`. Every
subsequent POST / DELETE / SSE connection re-derives the
fingerprint and rejects with 403 on mismatch. A leaked
`Mcp-Session-Id` header is worthless to anyone presenting a
different cert. Non-TLS (loopback) sessions have no fingerprint
and no binding — explicit trade-off for local-dev ergonomics.

### 7.9 Audit "attempt" before the backend call

Every write-tool emits an `outcome=attempt` audit entry BEFORE
invoking the backend, then `outcome=ok` or `outcome=refused`
after. A process crash between a successful backend call and the
"ok" entry still leaves a trace: operators see an "attempt"
without a matching outcome and know the state is unknown.

### 7.10 Resource URI decode + query/fragment strip

`_parse_resource_uri` decodes percent-encoded bytes
(`%2e%2e%2f` → `../`) before `_enforce_root` sees the path, so
encoded traversal attempts get caught by the realpath pass from
§7.1. Query strings and fragments are stripped so they can't
leak into backend-specific paths.

### 7.11 `list_backends` — unique default

When an operator registers the same backend instance under two
ids, only the first one claims `is_default = true`. Previously
the identity check said both were default, which confused
clients trying to pick a primary.

---

## 8. Error codes

| Code     | Name                    | Used for                                              |
|----------|-------------------------|-------------------------------------------------------|
| -32700   | PARSE                   | JSON decode failed.                                   |
| -32600   | INVALID_REQUEST         | Missing method, non-object body.                      |
| -32601   | METHOD_NOT_FOUND        | Unknown method / tool / disabled capability.          |
| -32602   | INVALID_PARAMS          | jsonschema failure, ValueError in handler, bad URI.   |
| -32603   | INTERNAL                | Handler raised an unexpected exception, or cancel.    |
| **-32001** | **RATE_LIMITED**      | `tools/call` throttled.                               |
| **-32002** | **TIMEOUT**           | Tool exceeded its wall-clock timeout.                 |
