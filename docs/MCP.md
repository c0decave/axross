# MCP server — deep-dive

Axross can run as a [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server so an LLM client (Claude Desktop, Cline, a custom agent)
can work on a local directory tree through a JSON-RPC tool surface.
The CLI server (`axross --mcp-server`, stdio or HTTP) serves the local
filesystem (`LocalFS`), confined to the MCP root. Optional
**capability groups** (`--mcp-tools`, §9) add metadata, the Duplicate
Finder, the packer, archives, encryption, the search index, file-type
detection, transfers between backends, saved connection profiles as
extra backends, and the extension list. A machine-readable manifest of
every tool is `axross --mcp-list-tools` / [`mcp-tools.json`](mcp-tools.json)
(§9.7).

The server speaks MCP protocol version **2024-11-05**.

Languages: **English** · [Deutsch](MCP_de.md) · [Español](MCP_es.md)

---

## 1. Transports

### 1.1 Stdio

```bash
# Read-only; LocalFS, MCP root defaults to $HOME (override with --mcp-root):
axross --mcp-server

# Or via env var (same behaviour):
AXROSS_MCP=1 axross

# The nine write tools (write_file, mkdir, remove, rename, copy,
# bulk_copy, symlink, hardlink, chmod). Path-traversal capped to a
# root you choose. AXROSS_MCP_WRITE=1 is the env-var equivalent:
axross --mcp-server --mcp-write --mcp-root ~/data

# Script tools (script_list/api_schema/read/write/delete/run) — stdio only:
axross --mcp-server --mcp-allow-scripts

# Capability groups (§9); AXROSS_MCP_TOOLS=metadata,packer is the
# env-var equivalent, 'all' switches on every group:
axross --mcp-server --mcp-tools metadata,filetype
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools all

# Commands and scripts on remote hosts (§9.8), its own opt-in that
# 'all' does not include; no env-var equivalent:
axross --mcp-server --mcp-tools remote,exec --mcp-allow-exec

# Print the tool manifest (JSON) for a set of flags, start nothing:
axross --mcp-list-tools --mcp-tools all --mcp-write
```

`--mcp-write` without `--mcp-root` is refused (exit 2): the default root
is your home directory, which is too wide to be writable. An unknown
`--mcp-tools` group is refused (exit 2) with one stderr line that lists
the valid groups.

`--mcp-allow-scripts` is refused (exit 2) in the `paranoid` security
mode, and refused together with `--mcp-http` (exit 2): script
execution over a network transport is not offered. See §2 for what
the script tools can reach.

`--mcp-allow-exec` is refused (exit 2) in the `paranoid` security
mode. Unlike the script tools it runs nothing on the server's own
host, so it is offered on both transports; see §9.8.

Requests arrive on stdin (line-delimited JSON), responses go out on
stdout. Logs go to stderr only. When the MCP path is taken, PyQt is
not imported — the server runs cleanly on a headless host.

### 1.2 HTTP (+ optional mTLS)

```bash
# Loopback HTTP (non-loopback without TLS is refused), bearer token required:
axross --mcp-server --mcp-http 127.0.0.1:7331
# [::1]:7331 for IPv6 loopback

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

**Bearer token on plain HTTP.** Loopback is not a credential: every
local user and process reaches `127.0.0.1`. A server without mTLS
therefore answers every request except `GET /health` with `401` unless
it carries `Authorization: Bearer <token>`. At start the token is shown
once on stderr and written to
`$XDG_RUNTIME_DIR/axross/mcp-http-PORT.token` (else `~/.config/axross/`;
the file is mode 0600, its folder 0700). It is new on every start; set
`AXROSS_MCP_HTTP_TOKEN` to keep one fixed for a client config. axross'
own MCP client (the agent's external MCP servers, docs/USAGE.md) sends
the token stored for that server in the keyring. With mTLS the client
certificate authenticates; the token is demanded there only when
`AXROSS_MCP_HTTP_TOKEN` is set. Earlier versions let a plain loopback
server accept any local process without a credential - with `--mcp-tools
remote,exec --mcp-allow-exec` another user on the machine could open the
saved profiles and run commands.

Sessions are required on HTTP. The first `POST /messages` carrying
`initialize` gets a fresh session id back in the `Mcp-Session-Id`
response header; every subsequent request stamps that id. Unknown
or expired ids answer 404.

mTLS is built with `CERT_REQUIRED` + TLS 1.2 minimum: a client that
can't present a certificate signed by the CA bundle is rejected
during the handshake before any HTTP parsing.

The HTTP transport serves the read-only and (with `--mcp-write`) the
write tools and the `--mcp-tools` groups; it never serves the script
tools.

---

## 2. Tool surface

The file tools below are always the base. Everything else (metadata,
duplicates, packer, archives, encryption, index building, file types,
transfers, remote profiles, extensions) is a capability group, see §9.

### Read-only tools (always available)

| Name                 | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| `list_dir(path)`     | Directory entries.                                                  |
| `stat(path)`         | Name, type, size, mtime.                                            |
| `read_file(path, max_bytes=, encoding=)` | Base64-encoded file content; capped at 4 MiB by default. `encoding="text"` returns `text` (UTF-8, `replaced=true` when undecodable bytes were replaced) — for models that cannot decode Base64. |
| `checksum(path, algorithm=)`  | `sha256` (default), `sha1`, `md5` or `sha512`. Uses the backend's native hash only when it is of the requested algorithm, else streams the file through hashlib (emits progress). |
| `search(needle, ext, min_size, max_size)` | Offline metadata index, scoped to the active backend's id and the MCP root. |
| `walk(path, max_depth, max_entries)`      | Bounded recursive listing; emits `notifications/progress`. |
| `recursive_checksum(path, algorithm, max_files, max_depth, max_file_bytes)` | Hash every file under a path (files over 1 GiB skipped by default); one progress frame per hashed file. |
| `grep(pattern, path, max_depth, max_matches)` | Regex search inside file contents. Skips files over 4 MiB, caps matches at 500; emits progress. |
| `list_versions(path)` | Per-version metadata where the backend supports it.                |
| `open_version_read(path, version_id, max_bytes=)` | Base64 content of a specific version.          |
| `preview(path, edge=256)` | Thumbnail of an image — returned as MCP **image content** with proper mimeType. |

### Write tools (only when `--mcp-write`)

| Name                              | Description                                                                |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content \| content_b64)` | Upload: `content` as UTF-8 text or `content_b64` as Base64 bytes, exactly one. |
| `mkdir(path)`                     | Create directory.                                                          |
| `remove(path, recursive=False)`   | Delete.                                                                    |
| `rename(src, dst)`                | Rename / move.                                                             |
| `copy(src, dst)`                  | Server-side copy where backend supports it; stream-copy fallback.          |
| `bulk_copy(src, dst, max_files, max_depth, max_file_bytes, overwrite)` | Tree copy (files over 10 GiB skipped by default); one progress frame per copied file. |
| `symlink(target, link_path)`      | `link_path` must lie under the root; `target` is deliberately **not** root-checked (it may dangle or point outside — later tools resolve links through `_enforce_root` before following them). No capability flag is checked; a backend without symlinks fails the call. |
| `hardlink(target, link_path)`     | Both ends must lie under the root. No capability flag is checked; a backend without hardlinks fails the call. |
| `chmod(path, mode)`               | POSIX mode bits. Accepts int or octal string.                              |

Every write tool resolves its paths via `_enforce_root` first — a
payload like `/etc/passwd` is rejected before any IO hits the
backend (the one exception is the `symlink` target, see above).
Every call emits audit-log entries on `core.mcp_server.audit`,
containing the tool, outcome, path, and size — never the payload
bytes.

### Script tools (only when `--mcp-allow-scripts`, stdio only)

| Name                          | Description                                                       |
|-------------------------------|-------------------------------------------------------------------|
| `script_list()`               | Names of the saved scripts in `~/.config/axross/scripts/`.        |
| `script_api_schema(names?)`   | The `axross.*` API as JSON (same as `axross.api_schema(names)` and [`scripting-api.json`](scripting-api.json)): rules and errors for scripts; per function signature, typed parameters, return type, whole docstring, examples, `raises`, `mutates`, `prompts`; the public classes, the types the API returns and the methods of every backend session. `names: []` gives the index alone, a list of names only those. Read-only. |
| `script_read(name)`           | Source of one saved script.                                       |
| `script_write(name, source)`  | Save `<name>.py` (mode 0600); overwrites.                         |
| `script_delete(name)`         | Remove a saved script; idempotent.                                |
| `script_run(name, args?, timeout_s?)` | Run a saved script in its own Python process with `axross.*` in scope; `args` become `sys.argv[1:]`. Returns a structured reply (below). |

`script_run` in detail — what a client can rely on:

* **A child process, never the server.** stdin is empty: `input()` gets
  `EOFError` and can never read the JSON-RPC stream. The child runs in a
  process group of its own; when the run ends, every process it started
  ends with it (one that calls `setsid` escapes).
* **Wall clock.** `timeout_s` (default 60, at most 600) stops the run:
  SIGTERM to the group, SIGKILL 3 s later. `tasks/start` + `tasks/cancel`
  run and stop a script in the background.
* **Reply.** `{name, exit, timed_out, duration_ms, stdout, stderr,
  namespace_keys}`; after an uncaught exception also `error_type`,
  `error` and a bounded `traceback` (the script's frames only). `exit`
  follows `SystemExit` exactly (`None` is 0, an int is itself even above
  255, anything else is printed to stderr and gives 1); a stopped run
  has the negative signal number. `namespace_keys` are the top-level
  names the script left (at most 500).
* **Output.** stdout and stderr hold up to 1 MiB of characters each;
  more stops the run and the call fails (`script output exceeded …`).
* **No human.** The child runs with `AXROSS_NONINTERACTIVE=1`:
  `axross.confirm()` raises `NonInteractiveError` unless the script
  passes `assume_yes=True`, and a write to a profile flagged
  *production* is refused unless the server was started with
  `AXROSS_TARPIT_DISABLE=1`. `script_api_schema` marks every function
  that can need a human (`prompts`) or change state (`mutates`).
* **Arguments.** `args`: at most 64 strings of at most 4096 characters,
  no NUL; a bad `args` or `timeout_s` is refused before anything runs
  (`-32602`).

**Security note:** the script tools are **not** confined to the MCP
root at all. Names are restricted to `[A-Za-z0-9_-]+` inside the
script directory, but `script_run` executes arbitrary Python with
the server's user rights — it can read and write anything that user
can, open network connections and use every `axross.*` backend. Treat
`--mcp-allow-scripts` as handing the client a shell. It is refused in
`paranoid` security mode and on `--mcp-http`. `script_write`,
`script_delete` and `script_run` leave attempt / ok / refused lines
on `core.mcp_server.audit` (name, size, exit code, `timed_out`, the
exception type — never the source, the arguments or the script's
output).

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

Both transports wire one `_LogForwarder` per server (stdio writes to
stdout; HTTP routes each record to the SSE stream of the session it
was emitted in). Selected log records are forwarded to the client as
`notifications/message` frames. Only the `core.mcp_server` and
`core.mcp_server.audit` loggers are forwarded — unrelated backend
chatter doesn't leak. The default threshold is `warning`; audit lines
are `info`, so they reach the client only after it lowers the level.

Client can dial the threshold live:

```json
{"jsonrpc": "2.0", "id": 1, "method": "logging/setLevel",
 "params": {"level": "debug"}}
```

Accepted levels: `debug`, `info`, `notice`, `warning`, `error`,
`critical`, `alert`, `emergency`.

**On HTTP the level is server-wide, not per session:** there is one
shared forwarder, so a `logging/setLevel` from any session changes
the threshold for every session on that server. Routing stays
per-session — a session only ever receives its own records — but
one client can make all clients' streams more or less verbose.

### Other methods

| Method          | Purpose                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `initialize`    | Handshake; answers protocol version, server info and capabilities.     |
| `ping`          | MCP liveness check; empty result.                                       |
| `tools/list`    | The tool catalogue with input schemas.                                  |
| `tools/call`    | Run one tool synchronously.                                             |
| `tasks/start`   | **Axross extension, not part of MCP.** Start a tool in the background; returns `task_id`. Same schema check, same rate limit and same per-tool timeout as `tools/call`; at most 8 running tasks per scope (`MAX_RUNNING_TASKS_PER_SCOPE`). |
| `tasks/status`  | Status, last progress, and result or error once finished.               |
| `tasks/cancel`  | Cancel a running task.                                                  |
| `tasks/list`    | Short summary of the scope's tasks.                                     |

Tasks are scoped per session on HTTP and server-wide on stdio.
Finished tasks are kept for an hour (`TASK_RETENTION_SECONDS`); once a
scope holds more than 100 tasks (`MAX_TASKS_PER_SCOPE`) the oldest
finished ones are evicted early. Results over 16 MiB become an error.

---

## 3. Progress, cancellation, timeouts

### 3.1 Progress

Pass `_meta.progressToken` on a `tools/call` and the server emits
`notifications/progress` frames from the handlers that support them:
`walk` (entries visited), `grep` (files scanned), `checksum` (bytes
hashed, streaming fallback only), `recursive_checksum` (files hashed)
and `bulk_copy` (files copied), and the long group tools of §9
(`metadata_read` / `metadata_export` on folders, `metadata_remove`,
`file_type_scan`, `duplicates_scan`, `duplicates_dedupe`,
`index_build`, `pack`, `archive_extract`, `transfer_copy`). Inside a
`tasks/start` task the same
tools report progress with the `task_id` as token. On stdio the frames go to
stdout through the same lock as every response, so frames from
different threads never interleave inside a line; on HTTP they're
queued per-session and relayed over the SSE stream (`GET /messages`).

### 3.2 Cancellation

Clients send `notifications/cancelled` with a `requestId`. A cancel
registry (per session on HTTP, per server on stdio) flips a
`threading.Event` that every long-running handler polls via
`ctx.check_cancel()`. The handler raises `CancelledError`, the
dispatcher answers -32603 with `data.type = "CancelledError"`, and
the client discards the response.

**Known limitation — stdio:** the stdio loop is single-threaded. While
a synchronous `tools/call` runs, the loop waits for it and reads no
further input, so a `notifications/cancelled` for that call is only
read after the call has finished. On stdio a synchronous `tools/call`
is therefore stopped only by its timeout (§3.3). Work that must be
cancellable on stdio goes through `tasks/start` + `tasks/cancel`,
which works on both transports. On HTTP every request runs on its own
thread, so `notifications/cancelled` reaches a running call.

### 3.3 Timeouts

Every tool has a wall-clock ceiling:

| Class (`timeout_class`) | Timeout | Tools                                                                      |
|-----------|---------|----------------------------------------------------------------------------|
| `quick`   | 15 s    | `stat`, `read_file`, `list_dir`, `search`, `list_versions`, `open_version_read`, and every tool without an entry of its own — including the script tools other than `script_run` |
| `walk`    | 60 s    | `walk`, `grep`                                                             |
| `preview` | 30 s    | `preview`                                                                  |
| `write`   | 30 s    | `write_file`, `mkdir`, `remove`, `rename`, `copy`, `symlink`, `hardlink`, `chmod` |
| `stream`  | 300 s   | `checksum`, `recursive_checksum`, `bulk_copy`                              |
| `long`    | 1800 s  | whole-tree group jobs (§9): `duplicates_scan`, `duplicates_dedupe`, `index_build`, `pack`, `archive_extract`, `transfer_copy`, `transfer_move`, `metadata_remove` |
| `script`  | 610 s   | `script_run`. It stops its child at its own `timeout_s` (default 60 s, at most 600 s); the class adds the kill grace and the output drain, so the deadline only backs that up |

The class of every group tool is in the manifest (§9.7). A
`tasks/start` task gets the same timeout as its tool.

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

Default on: 30-token burst, refills at 1 token/sec (60 calls per
minute steady-state). `tools/call` and `tasks/start` draw from the
same bucket (one bucket per server on stdio, one per session on
HTTP); `tools/list`, `initialize`, `ping`, `resources/*`,
`tasks/status|cancel|list` and `logging/setLevel` stay free.

Rejection is -32001 with `data.type = "RateLimitError"`. A
`tasks/start` beyond the running-task cap is also -32001, with
`data.type = "TaskLimitError"`.

Tune via `ServerConfig.rate_burst` / `rate_refill_per_sec` or
disable with `rate_limit_enabled = False`.

---

## 5. Multi-backend

From the CLI, the `remote` group (§9.5) is the way to more backends:
`remote_open` turns a saved connection profile into the backend
`profile:<name>`, and the default `LocalFS` gets the id `local`.
Embedding the server from Python, you can also pass a dict of
`{id: backend}` as `ServerConfig.backends` (or
`HTTPServerConfig.backends`). In both cases:

 - A read-only `list_backends` tool returns
   `[{id, class, name, is_default, remote}]` (opened profiles add
   `profile`, `protocol`, `production`) so the LLM can enumerate.
 - Every other tool's inputSchema gains an optional `backend: string`
   field (tools that name their backends themselves, like
   `transfer_copy`, or touch none, do not). Omit it to route to the
   default; pass an id to route elsewhere. Unknown ids land on -32602.
 - Backends of a static library registry are confined to the MCP root
   like the default one; profiles opened with `remote_open` are not
   (§9.5).

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
 - One SSE stream per session: a new `GET /messages` ends the
   previous stream (its unsent events are replayed on the new one),
   and `DELETE` or idle eviction ends the open stream.

---

## 7. Security hardening

Every item below is an explicit guard against a red-team scenario
we've thought about. The MCP tests live in `tests/test_mcp_*.py`:

| File | Covers |
|------|--------|
| `tests/test_mcp_error_redaction.py` | Secrets in backend error text are redacted (tools/call, tasks, recursive_checksum). |
| `tests/test_mcp_http_hardening.py` | DNS rebinding (Host/Origin), session cap and idle eviction, malformed params/ids, partial TLS flags, idle TCP client vs. accept. |
| `tests/test_mcp_http_bearer_token.py` | Plain HTTP refuses requests without the bearer token (401, `/health` exempt), the token file is 0600 and never written through a symlink, `--mcp-http` always serves with one. |
| `tests/test_mcp_http_sse_lifecycle.py` | One SSE stream per session, DELETE/idle eviction end it, replay on reconnect. |
| `tests/test_mcp_search_root.py` | `search` never returns indexed paths outside the root. |
| `tests/test_mcp_tasks_limits.py` | `tasks/start` rate limit, running-task cap, tool timeout. |
| `tests/test_mcp_write_root.py` | `--mcp-write` needs `--mcp-root`; `--mcp-allow-scripts` refused with `--mcp-http`. |
| `tests/test_mcp_script_audit.py` | Script tools write the audit trail, without source or output. |
| `tests/test_mcp_script_run_child.py` | `script_run` in a child: timeout and group kill, no grandchild left, `input()` never reads the stdio stream, cancel, output cap, argument checks, structured reply. |
| `tests/test_mcp_stdio_write_lock.py` | Concurrent stdio writers never interleave inside a line. |
| `tests/test_mcp_tools_flag.py` | `--mcp-tools` / `AXROSS_MCP_TOOLS` parsing, unknown group exit 2, default surface unchanged, read-only `all` offers no mutating tool. |
| `tests/test_mcp_group_metadata_filetype.py` | `metadata` and `filetype` groups: root escapes, symlinks, no overwrite, audit. |
| `tests/test_mcp_group_duplicates_index.py` | `duplicates` and `index` groups: index rows outside the root never show, dedupe re-check, trash under the root. |
| `tests/test_mcp_group_packer_archive.py` | `packer` and `archive` groups: zip-slip, password never logged, cancel leaves nothing. |
| `tests/test_mcp_group_crypto.py` | `crypto` group: passphrase never in answers, errors or audit; no overwrite. |
| `tests/test_mcp_group_remote_transfer.py` | `remote` and `transfer` groups: no secrets listed, no prompts, host keys, production profiles, per-session scoping, resumable copy. |
| `tests/test_exec_everywhere.py` | `exec()` of Telnet, rsh, ADB, WinRM and Cisco: exit status as `returncode`, stdin over a temporary file, env keys checked and values quoted, output caps, Cisco `show` only. |
| `tests/test_mcp_group_exec.py` | `exec` group: off without `--mcp-allow-exec` (also under `all`), refused in paranoid mode, backends without a shell refused, interpreter per backend, production profiles run nothing, audit without command, stdin or output. |
| `tests/test_mcp_group_extensions.py` | `extensions` group: listing never imports an extension. |
| `tests/test_mcp_manifest.py` | `--mcp-list-tools` and the committed `docs/mcp-tools.json` stay in sync with the code. |
| `tests/test_mcp_protocol_matrix.py` | Every registered protocol has a route: `remote_open` reaches each profile protocol (stored password handed over, files written and read back), browser sign-in and paranoid-mode refusals carry their reason, the URL-only ones open through `axross.open_url`. |
| `tests/test_mcp_docs_group_table.py` | The §9.2 table of this file and of its German and Spanish versions lists exactly the group tools of `docs/mcp-tools.json`. |
| `tests/test_mcp_groups_e2e.py` | The real server over stdio and HTTP with `--mcp-tools all`: one call per group, `tasks/start` + `tasks/cancel`. |
| `tests/test_fuzz_mcp.py` | Hostile requests against the dispatcher, both transports and every group tool. |

§7.1, §7.5, §7.7, §7.8, §7.11 and the hard-stop of §7.4 have no
dedicated test in that set yet.

### 7.0 Script tools are not root-confined

The MCP root (§7.1) confines the file tools only. The script tools
(`--mcp-allow-scripts`, stdio only) run arbitrary Python as the
server's user (in a child process, so a script cannot stall or read
the server's protocol stream) and are not confined to anything — see §2.

### 7.1 Filesystem escape — symlink-resolving root check

`_enforce_root` runs a two-pass check on every write-tool path:
first `abspath` to collapse `..` / `.`, then `realpath` to
resolve symlinks and a second prefix test against the resolved
root. Without the second pass, a symlink placed under the
configured root (either externally or by the LLM using the
`symlink` write tool) would point at `/` and let
`write_file("/root/escape/etc/cron.d/evil")` slip past. Now
rejected with `PermissionError`, answered as -32603 with
`data.type = "PermissionError"` and a message naming the root. The
capability groups (§9) run every local path through the same check.

`remove`, `rename` and `transfer_move` act on the directory entry
itself: after the same check they resolve only the parent
(`_enforce_root_entry`), so on a symlink they remove or move the
link, never the folder or file it points to. A link that points out
of the root stays refused.

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
and no binding; every request of theirs must carry the bearer token
instead (§1.2), so a leaked session id alone is worthless there too.

### 7.9 Audit "attempt" before the backend call

Every write tool — and `script_write`, `script_delete`,
`script_run` — emits an `outcome=attempt` audit entry BEFORE
invoking the backend (or the script), then `outcome=ok` or
`outcome=refused` after. A process crash between a successful backend call and the
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
| -32603   | INTERNAL                | Handler raised an exception other than ValueError/TypeError (OSError, `PermissionError` of a root escape, a refused profile, …; `data.type` names it), or cancel. |
| **-32001** | **RATE_LIMITED**      | `tools/call` / `tasks/start` throttled, or running-task cap reached. |
| **-32002** | **TIMEOUT**           | Tool exceeded its wall-clock timeout.                 |

---

## 9. Capability groups (`--mcp-tools`)

Without `--mcp-tools` the server offers exactly the tools of §2.
`--mcp-tools GROUP[,GROUP...]` (repeatable; `AXROSS_MCP_TOOLS` is
merged with it) adds groups; `all` adds every group. An unknown group
stops the start with exit code 2 and one stderr line listing the
valid groups. The flag is called `--mcp-tools`, not `--backend`:
"backend" already means a protocol backend in axross, and remote
backends are one of the groups.

### 9.1 Common setups

```bash
# Read-only: the file tools plus metadata reading and content types
axross --mcp-server --mcp-tools metadata,filetype

# Pack and extract inside ~/data (mutating tools need --mcp-write,
# which needs --mcp-root)
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools packer,archive

# Build the search index and find duplicates, read-only
axross --mcp-server --mcp-root ~/photos --mcp-tools index,duplicates

# Saved profiles as extra backends, copy between them and ~/data
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools remote,transfer

# Run commands on the opened profiles (SSH, Telnet, rsh, ADB, WinRM, Cisco)
axross --mcp-server --mcp-tools remote,exec --mcp-allow-exec

# Everything, over loopback HTTP
axross --mcp-server --mcp-http 127.0.0.1:7331 --mcp-write --mcp-root ~/data --mcp-tools all
# ... or with environment variables
AXROSS_MCP=1 AXROSS_MCP_WRITE=1 AXROSS_MCP_TOOLS=all axross --mcp-root ~/data
```

### 9.2 Groups and tools

Read-only tools of a group need only `--mcp-tools <group>`; mutating
ones are not even registered without `--mcp-write` (and `--mcp-write`
is refused without `--mcp-root`). The `exec` group is the exception:
its tools need `--mcp-allow-exec` instead, and `all` leaves the group
out unless that flag is given (§9.8).

| Group | Tool | Kind | Required flags | Timeout class |
|-------|------|------|----------------|---------------|
| `metadata` | `metadata_read` | read-only | `--mcp-tools metadata` | stream |
| `metadata` | `metadata_export` | read-only | `--mcp-tools metadata` | stream |
| `metadata` | `metadata_export_file` | mutating | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | stream |
| `metadata` | `metadata_remove` | mutating | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | long |
| `duplicates` | `duplicates_scan` | read-only | `--mcp-tools duplicates` | long |
| `duplicates` | `duplicates_scans` | read-only | `--mcp-tools duplicates` | quick |
| `duplicates` | `duplicates_groups` | read-only | `--mcp-tools duplicates` | quick |
| `duplicates` | `duplicates_dedupe` | mutating | `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR` | long |
| `packer` | `pack_formats` | read-only | `--mcp-tools packer` | quick |
| `packer` | `pack` | mutating | `--mcp-tools packer` `--mcp-write` `--mcp-root DIR` | long |
| `archive` | `archive_list` | read-only | `--mcp-tools archive` | walk |
| `archive` | `archive_extract` | mutating | `--mcp-tools archive` `--mcp-write` `--mcp-root DIR` | long |
| `crypto` | `encrypt` | mutating | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `crypto` | `decrypt` | mutating | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `index` | `index_build` | read-only | `--mcp-tools index` | long |
| `filetype` | `file_type` | read-only | `--mcp-tools filetype` | quick |
| `filetype` | `file_type_scan` | read-only | `--mcp-tools filetype` | stream |
| `transfer` | `transfer_copy` | mutating | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `transfer` | `transfer_move` | mutating | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `remote` | `remote_profiles` | read-only | `--mcp-tools remote` | quick |
| `remote` | `remote_open` | read-only | `--mcp-tools remote` | walk |
| `remote` | `remote_close` | read-only | `--mcp-tools remote` | quick |
| `remote` | `list_backends` | read-only | `--mcp-tools remote` | quick |
| `exec` | `remote_exec` | mutating | `--mcp-tools exec` `--mcp-allow-exec` | long |
| `exec` | `remote_script` | mutating | `--mcp-tools exec` `--mcp-allow-exec` | long |
| `exec` | `exec_backends` | read-only | `--mcp-tools exec` `--mcp-allow-exec` | quick |
| `agent` | `agent_run` | read-only | `--mcp-tools agent` | long |
| `extensions` | `extensions_list` | read-only | `--mcp-tools extensions` | quick |
| `extensions` | `extensions_info` | read-only | `--mcp-tools extensions` | quick |

"Read-only" means: no file of the user changes. `duplicates_scan` and
`index_build` do write axross' own indexes (the Duplicate Finder's
and the metadata search's, under `~/.local/share/axross/`), the same
indexes the GUI uses; `remote_open` opens a network connection.

What each group does:

* **metadata** — read metadata of images (EXIF/XMP/IPTC; JPEG, PNG,
  WebP, GIF, TIFF), Office files, PDF and audio/video (ffprobe) of a
  file or a folder; export it as JSON or CSV, as text or into a new
  file; remove it by writing a cleaned copy next to each file
  (`photo.jpg` → `photo.clean.jpg`). In-place removal is not offered
  over MCP: it keeps the original in the axross trash of the home
  directory, outside the MCP root.
* **duplicates** — the Duplicate Finder: hash a folder into the
  duplicate index, list scans and duplicate groups (every copy inside
  the folder asked for and inside the root — rows the GUI indexed
  elsewhere never show), and dedupe: keep the oldest copy of each
  group and move the others to `<root>/.axross-trash`, after
  re-checking every copy on disk. A dry run unless `dry_run=false`.
* **packer** — zip, tar.gz / tar.zst / tar.xz / tar.bz2, 7z (with a
  password: AES-256, file list encrypted too) and single-file gz / zst
  / xz / bz2. ZIP has no password option (ZipCrypto is broken).
* **archive** — list members without extracting; extract into a fresh
  folder (`x.zip` → `x`, `x-1`, …) with the zip-slip, link, size
  (1 GiB), entry-count (10,000) and ratio (100) guards of
  `core.archive`. Local archives only: copy a remote archive with
  `transfer_copy` first.
* **crypto** — the axross `.axenc` format of the GUI (AES-256-GCM,
  PBKDF2-SHA256 with 200,000 iterations, at most 1 GiB per file).
* **index** — fill the offline metadata index that `search` reads, so
  `search` finally has data without the GUI; `prune` drops rows of
  files that are gone.
* **filetype** — identify files by content (magic bytes, the same
  detector as the GUI) and flag an extension that lies.
* **transfer** — copy files or trees, or move one file, between any
  two backends (`local` and the profiles opened with `remote_open`);
  `resumable=true` copies in 4 MiB segments with a manifest under
  `$XDG_STATE_HOME/axross/resume/`, so an interrupted copy continues
  where it stopped when called again with the same arguments.
* **remote** — see §9.5.
* **exec** — run commands and scripts on remote hosts; see §9.8.
* **agent** — hand a task to the user's own LLM; see §9.9.
* **extensions** — list installed extensions, enabled or not. None can
  run over MCP: an extension's `activate(api)` gets the Qt
  `ExtensionAPI` and can only add menu actions, context actions and
  docks — there is no headless action to call, and loading one runs
  its code with the user's rights.

### 9.3 Safety model

Every guard of the base server stays; the groups add layers:

1. **Opt-in per group.** No flag, no group.
2. **`--mcp-write` per mutating tool**, which itself requires
   `--mcp-root`. Without it the mutating tools do not exist.
3. **Root confinement.** Every local path goes through the
   symlink-resolving root check of §7.1; walks skip symlinks and
   entries that resolve outside the root.
4. **Nothing is overwritten.** Archives, extracted folders, encrypted
   and decrypted files, metadata exports and cleaned copies get a
   fresh name (`bundle (2).zip`, `x-1`, `a (2).txt`,
   `photo.clean (1).jpg`); created files are mode 0600 where axross
   creates them itself (exports, decrypted plaintext, ciphertext).
5. **Audit.** Every mutating group tool writes `attempt` and then
   `ok` or `refused` to `core.mcp_server.audit` — paths, names, counts
   and sizes, never file contents, passphrases or passwords.
6. **Secrets stay out of answers.** Passphrases and the 7z password
   are `writeOnly` schema fields that appear in no result, error or
   audit line; `remote_profiles` lists profiles through a field
   allow-list (no password, key, token, SAS or connection string).
7. **Bounded work.** Every list has a cap (`max_files`, `max_groups`,
   `max_entries`, …, `truncated=true` when cut); long jobs report
   progress, poll cancellation and run under `tasks/start`; results
   above 16 MiB are refused like any tool result.

### 9.4 Paranoid security mode

No group is refused as a whole. What the paranoid mode blocks in the
GUI and in scripting stays blocked here:

* `remote_open` refuses the legacy protocols (`ftp`, `telnet`,
  `cisco-telnet`, `tftp`, `gopher`, `nntp`, `pop3`, `rsh`);
  `remote_profiles` reports them as `openable: false`.
* `metadata_*` do not run ffprobe / ffmpeg on audio and video (the
  report carries the reason), exactly as in the GUI.
* `extensions_list` reports `allowed: false` and every extension
  `active: false`.
* The script tools stay refused (`--mcp-allow-scripts` exits 2).
* The `exec` group stays refused (`--mcp-allow-exec` exits 2).

### 9.5 Remote profiles

* `remote_profiles` lists the saved profiles (name, protocol, host,
  port, user, auth type, whether a password is stored, production
  flag) and says per profile whether `remote_open` would refuse it.
* `remote_open(profile)` connects through the GUI's connection
  manager and registers the backend `profile:<name>`; every other tool
  reaches it via `backend: "profile:<name>"`. `remote_close` drops it.
* **Credentials come from the keyring**, only when the profile stores
  its password ("Store password" in the connection dialog). The MCP
  server never prompts: a profile that needs a password that is not
  stored, an SSH host key that is not yet in `~/.ssh/known_hosts`, or
  a browser sign-in (OneDrive, SharePoint, Google Drive, Dropbox) is
  refused with an error that says so. Connect such a profile once in
  the GUI.
* **`--mcp-root` does not apply to remote paths**: a profile reaches
  what its server lets that account reach. A profile that resolves to
  the local file system is refused, because it would bypass the root.
* **Production-flagged profiles are read-only over MCP**: the GUI's
  countdown before a destructive operation cannot be shown, so every
  mutation on them is refused.
* Opened profiles are per session on HTTP (one client never sees
  another's), at most 8 per session; when an HTTP session ends
  (`DELETE` or idle eviction) its connections are closed.
* Opening an arbitrary URL is not offered: an LLM-chosen URL could
  point the server at `sftp://localhost` with the user's SSH agent, or
  at a local file (`sqlite://`, `git+local://`), and walk around
  `--mcp-root`. A saved profile is the user's own decision.
* Which protocols a profile can name: every protocol of the connection
  dialog. The ten URL-only backends (`exchange`, `git`, `ldap`, `mongodb`, `postgres`, `redis`, `rsh`, `slp`, `sqlite`, `wmi`) have no
  connection dialog and so no profile; over MCP they are reached only
  by the script tools (`--mcp-allow-scripts`, stdio) with
  `axross.open_url`. `tests/test_mcp_protocol_matrix.py` holds the
  split against the backend registry.

### 9.6 One JSON-RPC call per group

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"metadata_read","arguments":{"path":"/home/me/data/IMG_0001.jpg"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"duplicates_scan","arguments":{"path":"/home/me/data/photos"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"pack","arguments":{"folder":"/home/me/data","names":["report","notes.txt"],"archive_name":"bundle","format":"7z","password":"…"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"archive_extract","arguments":{"path":"/home/me/data/bundle.zip"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"encrypt","arguments":{"path":"/home/me/data/notes.txt","passphrase":"…"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"index_build","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"file_type_scan","arguments":{"path":"/home/me/data/inbox","mismatches_only":true}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"transfer_copy","arguments":{"src":"/home/me/data/report","dst_backend":"profile:nas","dst":"/backup/report","resumable":true}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"remote_open","arguments":{"profile":"nas"}}}
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"extensions_list","arguments":{}}}
```

A long job in the background, cancellable on both transports:

```json
{"jsonrpc":"2.0","id":11,"method":"tasks/start","params":{"name":"duplicates_scan","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":12,"method":"tasks/status","params":{"task_id":"<task_id>"}}
{"jsonrpc":"2.0","id":13,"method":"tasks/cancel","params":{"task_id":"<task_id>"}}
```

### 9.7 Machine-readable manifest

`axross --mcp-list-tools` takes the same `--mcp-tools`, `--mcp-write`
`--mcp-allow-scripts` and `--mcp-allow-exec` flags (and `AXROSS_MCP_*`
variables) as the
server, starts nothing and prints JSON:

```json
{
  "server": "axross-mcp",
  "protocol_version": "2024-11-05",
  "generated_for": {"mcp_allow_exec": true, "mcp_allow_scripts": true, "mcp_tools": ["..."], "mcp_write": true},
  "timeout_classes": {"quick": 15.0, "walk": 60.0, "write": 30.0, "preview": 30.0, "stream": 300.0, "long": 1800.0},
  "groups": {"metadata": {"description": "...", "tools": ["metadata_read", "..."]}},
  "tools": [{"name": "...", "group": "...", "mutating": false, "required_flags": ["--mcp-tools metadata"],
             "transports": ["stdio", "http"], "timeout_class": "stream", "timeout_seconds": 300.0,
             "description": "...", "input_schema": {"type": "object", "...": "..."}}]
}
```

Every schema lists types, required fields, enums, defaults and bounds,
and group tools refuse unknown arguments (`additionalProperties:
false`). [`mcp-tools.json`](mcp-tools.json) is the manifest for
`--mcp-tools all --mcp-write --mcp-allow-scripts --mcp-allow-exec`;
`tests/test_mcp_manifest.py` fails when it no longer matches the code.
[LLM_GUIDE.md](LLM_GUIDE.md) is the short guide for LLM clients; its
tool catalog is generated from this manifest.

### 9.8 Commands on remote hosts (`exec`)

`--mcp-tools exec --mcp-allow-exec` adds three tools:

* `exec_backends` lists every backend that can run commands, as
  `{backend, class, kind}`; `kind` is `posix-shell` (SSH, SCP, Telnet,
  rsh, ADB), `powershell` (WinRM) or `ios-show` (Cisco Telnet). Open
  a saved profile with `remote_open` (group `remote`) first.
* `remote_exec(backend, command, stdin?, env?, timeout?, max_output?)`
  runs one command and returns `{returncode, stdout, stderr,
  truncated_stdout, truncated_stderr}`. A non-zero exit is a result,
  not an error. Telnet and ADB have no separate error stream: their
  stderr arrives inside `stdout`.
* `remote_script(backend, script, interpreter?, args?, env?, …)` sends
  the script on stdin to `sh -s --`, `bash -s --`, `python3 -` or
  `perl -` (default `sh`), with `args` quoted after it. A WinRM host
  runs the script as PowerShell (`interpreter: "powershell"`, no
  `args`); a Cisco device runs no scripts.

Limits and guards:

* **Its own opt-in.** `--mcp-allow-exec` is a flag only (no
  `AXROSS_MCP_*` variable), `--mcp-tools all` without it registers
  none of the three tools, and `--mcp-write` does not enable them.
  The paranoid security mode refuses the flag (exit 2).
* **Remote only.** A backend without a remote shell — the local file
  system, S3, WebDAV, … — is refused with "has no remote shell". A
  command goes only to the shell of the host a backend is connected
  to, never into a local process of the server (that is what the
  stdio-only script tools do), so `exec` is offered over HTTP too.
* **Production-flagged profiles run nothing** (§9.5).
* **Cisco: `show` commands only.** Anything else (`configure`,
  `reload`, `write memory`, a second line) is refused before it is
  sent, and so are the output modifiers that write to flash
  (`| redirect`, `| tee`, `| append`, `>`); `| include`, `| exclude`,
  `| begin`, `| section` and `| count` stay allowed.
* **stdin** reaches the command over a temporary file on Telnet and
  ADB (removed afterwards) and directly on SSH, SCP and rsh; WinRM and
  Cisco refuse it.
* **env** names must match `[A-Za-z_][A-Za-z0-9_]*`; values are quoted
  for the remote shell (`export K='v'; ` or `$env:K = 'v'; `).
* **Bounded.** `timeout` 1–3600 s (default 60), `max_output` up to
  16 MiB of stdout (default 1 MiB), stderr at most 1 MiB; the
  `truncated_*` flags tell when output was cut.
* **Audit without content.** Each call logs `attempt` and `ok` or
  `refused` with the backend, its class, the length and the first 16
  hex digits of the SHA-256 of the command, the stdin length and the
  exit status — never the command, its stdin or its output, which
  often carry passwords.

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"remote_open","arguments":{"profile":"web01"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remote_exec","arguments":{"backend":"profile:web01","command":"df -h /","timeout":30}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remote_script","arguments":{"backend":"profile:web01","interpreter":"python3","script":"import sys; print(sys.argv[1:])","args":["a b","c"]}}}
```

### 9.9 Hand a task to the local LLM (`agent`)

`--mcp-tools agent` adds `agent_run(task, profile?, groups?, max_steps?)`:
the client - another LLM - hands a task to the user's own model, the
active LLM profile of the axross GUI (LM Studio, Ollama, vLLM,
llama.cpp; any OpenAI-compatible server) or the one named. That model
works with axross' read-only file tools inside the MCP root, plus the
read-only tools of the groups listed in `groups`, and the call returns
`{answer, stopped, calls, profile, model}`. `remote` and `extensions`
reach beyond the root (saved connections with their stored
credentials, the extensions' code): `groups` may name them only when
the server itself was started with them in `--mcp-tools`.

* **It changes nothing.** The inner agent gets no write, exec, script
  or agent tool: on a headless server nobody could confirm a change.
  Changes with a local model go through the Agent dock of the GUI,
  which asks before each one.
* **The content stays where the profile points.** A profile whose
  server is not on this machine or its network (or is reached through
  a proxy) needs the consent given in the GUI; without it the call is
  refused before anything is sent.
* **Bounded.** `max_steps` (1–30, default 10) model requests; tool
  results are cut for the model; the call runs in the `long` timeout
  class; `tasks/cancel` stops it after the model request in flight.
* The API key comes from the keyring and never appears in a result or
  a log line.
