# MCP server — deep-dive

Axross can run as a [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) server so an LLM client (Claude Desktop, Cline, a custom agent)
can work on a local directory tree through a JSON-RPC tool surface.
The CLI server (`axross --mcp-server`, stdio or HTTP) serves the local
filesystem (`LocalFS`), confined to the MCP root. Optional
**capability groups** (`--mcp-tools`, §9) add metadata, the Duplicate
Finder, archives (create, list, extract), encryption, the search index, file-type
detection, transfers between backends, saved connection profiles as
extra backends, and the extension list. A machine-readable manifest of
every tool is `axross --mcp-list-tools` / [`mcp-tools.json`](mcp-tools.json)
(§9.7).

The server speaks the MCP revisions **2025-11-25**, **2025-06-18** and
**2024-11-05** (§1.4): `initialize` answers the client's revision when it
is one of them and the newest otherwise.

Without the GUI: the package **axross-headless-mcp** (`pip install axross-headless-mcp`, no
PyQt6) is this server with the same flags, stdio by default; the image
`ghcr.io/c0decave/axross-headless-mcp` is it in a container (§1.3). Both ship with
every release, and the server is listed in the official MCP registry as
`io.github.c0decave/axross-headless-mcp`.

Languages: **English** · [Deutsch](MCP_de.md) · [Español](MCP_es.md)

---

## 1. Transports

### 1.1 Stdio

```bash
# Read-only; LocalFS, MCP root defaults to $HOME (override with --mcp-root):
axross --mcp-server

# Or via env var (same behaviour):
AXROSS_MCP=1 axross

# The nine write tools (write_file, restore_file_version, create_directory,
# delete_path, move_path, copy_file, copy_tree, create_link,
# set_permissions). Path-traversal capped to a root you choose. AXROSS_MCP_WRITE=1 is the env-var equivalent:
axross --mcp-server --mcp-write --mcp-root ~/data

# Script tools (list_scripts, get_script_api, read_script, write_script,
# delete_script, run_script) — stdio only:
axross --mcp-server --mcp-allow-scripts

# Capability groups (§9); AXROSS_MCP_TOOLS=metadata,archive is the
# env-var equivalent, 'all' switches on every group but adb ('all,adb': every one):
axross --mcp-server --mcp-tools metadata,filetype
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools all

# Commands and scripts on remote hosts (§9.8), its own opt-in that
# 'all' does not include; no env-var equivalent:
axross --mcp-server --mcp-tools remote,exec --mcp-allow-exec

# Print the tool manifest (JSON) for a set of flags, start nothing:
axross --mcp-list-tools --mcp-tools all,adb --mcp-write
```

`--mcp-write` without `--mcp-root` is refused (exit 2): the default root
is your home directory, which is too wide to be writable. An
`--mcp-root` that does not exist is refused (exit 2). An unknown
`--mcp-tools` group is refused (exit 2) with one stderr line that lists
the valid groups.

`AXROSS_MCP=1` starts the server only when no `--script` is given: an
explicit `axross --script FILE` runs the script (the variable is
inherited by everything the client's environment starts), and
`--script` together with `--mcp-server`, `--mcp-http` or
`--mcp-list-tools` is refused (exit 2). A script run (`run_script`,
a frozen build's `axross --script -` child) gets no `AXROSS_MCP*`
variable.

The `paranoid` security mode below is the one in force at the start:
`AXROSS_SECURITY_MODE` when set, else the mode chosen in *Edit >
Settings > Security*.

`--mcp-allow-scripts` is refused (exit 2) in the `paranoid` security
mode, and refused together with `--mcp-http` (exit 2): script
execution over a network transport is not offered. See §2 for what
the script tools can reach.

`--mcp-allow-exec` is refused (exit 2) in the `paranoid` security
mode, and without the exec group (`--mcp-tools exec`, `all` or
`AXROSS_MCP_TOOLS=exec`): the flag alone serves nothing. Unlike the
script tools it runs nothing on the server's own host, so it is
offered on both transports; see §9.8.

Secret files are not read, whatever the root (§7.12): axross's own
tokens and keys and the private keys in `~/.ssh` and `~/.gnupg`.
`--mcp-allow-secret-reads` lets the tools read them; it is stdio only
(refused together with `--mcp-http`, exit 2).

Requests arrive on stdin (line-delimited JSON), responses go out on
stdout. Logs go to stderr only. When the MCP path is taken, PyQt is
not imported — the server runs cleanly on a headless host.

### 1.2 HTTP (+ optional mTLS)

`--mcp-http HOST:PORT` implies `--mcp-server` (`axross --mcp-http
127.0.0.1:7331` alone serves HTTP; it used to open the window instead).

```bash
# Loopback HTTP (non-loopback without TLS is refused), bearer token required:
axross --mcp-server --mcp-http 127.0.0.1:7331
# [::1]:7331 for IPv6 loopback

# mTLS — all three files required; only with them may it listen beyond
# loopback (0.0.0.0 without them is refused):
axross --mcp-server --mcp-http 0.0.0.0:7331 \
    --mcp-cert server.pem --mcp-key server.key --mcp-ca trusted-ca.pem
```

Plain HTTP serves loopback only. In a container that means the host
cannot reach it through `-p`: use mTLS there, or `--network host` with
`--mcp-http 127.0.0.1:7331`. `Transfer-Encoding: chunked` request bodies
are refused (400): a POST needs `Content-Length`.

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
`$XDG_RUNTIME_DIR/axross/mcp-http-HOST-PORT.token` (else `~/.config/axross/`;
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
or expired ids answer 404. A notification is answered `202 Accepted`
without a body. A client of 2025-06-18 or later also sends
`MCP-Protocol-Version: <revision>` on every request after `initialize`
(POST, GET, DELETE): a revision the server does not speak, or another
one than the session agreed on, is answered `400`; without the header
the session's revision applies. A JSON array (a JSON-RPC batch) is
refused with `400` - no supported revision has batches.

mTLS is built with `CERT_REQUIRED` + TLS 1.2 minimum: a client that
can't present a certificate signed by the CA bundle is rejected
during the handshake before any HTTP parsing.

The HTTP transport serves the read-only and (with `--mcp-write`) the
write tools and the `--mcp-tools` groups; it never serves the script
tools.

### 1.3 Without the GUI: `axross-headless-mcp` and the Docker image

`axross-headless-mcp` is the same server as its own package, without PyQt6 - for
a server, a container, CI. Its command takes exactly the MCP flags of
this section; `--mcp-server` may be left out (stdio is its default):

```bash
pipx install axross-headless-mcp              # or pip; 'axross-headless-mcp[all]' adds every protocol
axross-headless-mcp --mcp-root ~/data --mcp-tools all                 # stdio
axross-headless-mcp --mcp-http 127.0.0.1:7331 --mcp-root ~/data       # HTTP, bearer token
axross-headless-mcp --mcp-list-tools --mcp-tools all                  # the manifest
```

A client starts it like `axross --mcp-server` (Claude Code: `claude mcp
add axross -- axross-headless-mcp --mcp-root ~/data --mcp-tools all`; Claude
Desktop and others: `"command": "axross-headless-mcp", "args": [...]`). It reads
axross's settings, saved profiles and indexes in `~/.config/axross` like
axross does. `scripts/export_standalone.py mcp OUT` writes the package
from this tree: the modules the MCP path imports (and the backends the
registry names in strings), nothing of `ui/`; a module that imports
PyQt6 when it is imported stops the export.

The image (`Dockerfile.mcp`, released as
`ghcr.io/c0decave/axross-headless-mcp:<version>` and `:latest`) runs as the
non-root user `axross`; mount the folder to work in at `/data`:

```bash
docker run -i --rm -v "$PWD:/data" ghcr.io/c0decave/axross-headless-mcp:latest \
    --mcp-server --mcp-root /data --mcp-tools all
# HTTP from a container: mTLS (plain HTTP is loopback-only, see 1.2)
docker run --rm -p 7331:7331 -v "$PWD:/data" -v "$PWD/certs:/certs:ro" \
    ghcr.io/c0decave/axross-headless-mcp:latest --mcp-server --mcp-root /data \
    --mcp-http 0.0.0.0:7331 --mcp-cert /certs/server.pem \
    --mcp-key /certs/server-key.pem --mcp-ca /certs/ca.pem
```

### 1.4 Protocol revisions

| Revision | What a session of it gets |
|---|---|
| 2024-11-05 | Tools as `{name, description, inputSchema}`, results as text; refused arguments are JSON-RPC error -32602. What axross always sent. |
| 2025-06-18 | Also: each tool's `title` and **annotations** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, §2), an `outputSchema` for `get_path_info`, `read_file`, `compute_file_checksum` and `walk_tree`, and `structuredContent` (the result object; the text block keeps the same JSON) for every tool whose result is an object. `serverInfo.title`. The `MCP-Protocol-Version` header on HTTP (§1.2). |
| 2025-11-25 | Also: arguments a tool refuses (schema or value) come back as a tool error (`isError: true`) the model can read and correct, not as -32602; an unknown tool stays -32601. `serverInfo.description` and `websiteUrl`. |

A client asking for anything else - 2025-03-26 (the one revision with
JSON-RPC batches, which 2025-06-18 removed again), a future one -
is answered with 2025-11-25 and decides itself whether to stay. The
`server/discover` probe of newer clients (2026-07-28) is an unknown
method (-32601) here; the official SDK then falls back to `initialize`.
`tests/test_mcp_protocol_revisions.py` holds the table;
`tests/test_mcp_sdk_interop.py` drives the server with the official MCP
Python SDK over stdio and HTTP.

---

## 2. Tool surface

The file tools below are always the base. Everything else (metadata,
duplicates, archives, encryption, index building, file types,
transfers, remote profiles, extensions) is a capability group, see §9.

Every tool carries a `title` and **annotations** (sent from 2025-06-18
on, §1.4; in the manifest always): `readOnlyHint` - it changes nothing
(`scan_duplicates` and `build_index` write axross's indexes, so they are
not read-only although `--mcp-write` does not gate them);
`destructiveHint` - it can overwrite, remove or change what exists
(`false`: it only adds, under a free name); `idempotentHint` - the same
call again changes nothing more (`false` wherever a second call writes
`x (2)` or that is not certain); `openWorldHint` - it reaches beyond the
configured backends (`open_remote_profile`, `run_backend_command`,
`run_script`, `run_llm_agent`). They are hints for a client's confirmation
dialogs, not guarantees - the gates are the flags. The table is
`_TOOL_HINTS` in `core/mcp_server.py`; a tool without an entry fails
`tests/test_mcp_protocol_revisions.py`.

### Read-only tools (always available)

| Name                 | Description                                                         |
|----------------------|---------------------------------------------------------------------|
| `list_directory(path)`     | Directory entries.                                                  |
| `get_path_info(path)`         | Name, type, size, mtime.                                            |
| `read_file(path, max_bytes=, encoding=, offset=)` | Base64-encoded file content; capped at 4 MiB by default. `encoding="text"` returns `text` (UTF-8, `replaced=true` when undecodable bytes were replaced) — for models that cannot decode Base64. `offset` starts at that byte; when more follows (`truncated=true`) `next_offset` says where to continue (a text page never ends inside a character). The Agent dock sizes each read to its tool-result limit. |
| `compute_file_checksum(path, algorithm=)`  | `sha256` (default), `sha1`, `md5` or `sha512`. Uses the backend's native hash only when it is of the requested algorithm, else streams the file through hashlib (emits progress). |
| `search_index(pattern, ext, min_size, max_size, max_results)` | Offline metadata index, scoped to the active backend's id and the MCP root; at most `max_results` results (default 1000, at most 10 000), a cancel stops it. |
| `walk_tree(path, max_depth, max_entries, offset)`      | Bounded recursive listing (at most 100 000 entries, 64 levels), each folder's entries by name; emits `notifications/progress`. Past `max_entries` the result has `next_offset`: pass it as `offset` for the next page (each page walks from `path` again). Folders it could not list are named in `unreadable`; `complete` is false then. |
| `compute_tree_checksums(path, algorithm, max_files, max_depth, max_file_bytes)` | Hash every file under a path (files over 1 GiB skipped by default); one progress frame per hashed file. A folder it could not list is an `error` record with `folder: true`; `complete` says whether every file was hashed. |
| `search_content(pattern, path, max_depth, max_matches, offset)` | Regex search inside file contents. Skips files over 4 MiB, caps matches at 500 per call - `next_offset` pages on; emits progress. Folders and files it could not read are named in `unreadable`; no match with `complete: false` is no answer. |
| `list_file_versions(path)` | Per-version metadata where the backend supports it.                |
| `read_file_version(path, version_id, max_bytes=)` | Base64 content of a specific version.          |
| `render_preview(path, edge=256)` | Thumbnail of an image — returned as MCP **image content** with proper mimeType. Decoded by Qt, or by Pillow where there is no Qt (axross-headless-mcp with its `images` extra); without either the tool is not listed. |

### Write tools (only when `--mcp-write`)

| Name                              | Description                                                                |
|-----------------------------------|----------------------------------------------------------------------------|
| `write_file(path, content \| content_b64, write_mode=, offset=)` | Upload: `content` as UTF-8 text or `content_b64` as Base64 bytes, exactly one. `write_mode`: `replace` (default, the whole file), `create` (a new file only; a taken name fails with `File exists`, the name is claimed without replacing), `append` (at the end of an existing file), `at_offset` (overwrite from `offset`, at most the file's size). `append` and `at_offset` rewrite the file through a temp file, so they are atomic too; the existing file may hold at most 64 MiB. A new file is 0600; a file written over keeps its mode without the bits `set_permissions` refuses (setuid, setgid, sticky, group and world write - `& 0755`); `copy_file` and `copy_tree` carry modes the same way. |
| `restore_file_version(path, version_id)` | Make an older version (`list_file_versions`) the current content again: streamed through a temp file where the backend renames. On a versioning backend the restore is itself a new version. The local disk keeps no versions: it fails there. |
| `create_directory(path)`                     | Create directory.                                                          |
| `delete_path(path, recursive=False)`   | Delete.                                                                    |
| `move_path(src, dst)`                | Rename / move.                                                             |
| `copy_file(src, dst)`                  | Server-side copy where backend supports it; stream-copy fallback.          |
| `copy_tree(src, dst, max_files, max_depth, max_file_bytes, overwrite)` | Tree copy (files over 10 GiB skipped by default); one progress frame per copied file. |
| `create_link(target, link_path, kind=)` | `kind: "symbolic"` (default): `link_path` must lie under the root and, locally, so must what `target` leads to (it may dangle); SFTP and NFS store `target` as given. `kind: "hard"`: both ends under the root, a secret file refused. A backend without such links fails the call with a plain message. The former `create_symlink` and `create_hardlink` call it with their `kind`. |
| `set_permissions(path, mode)`               | POSIX mode bits. Accepts int or octal string.                              |

Every write tool resolves its paths via `_enforce_root` first — a
payload like `/etc/passwd` is rejected before any IO hits the
backend (a symbolic link's `target` is checked where it leads, see above).
Every call emits audit-log entries on `core.mcp_server.audit`,
containing the tool, outcome, path, and size — never the payload
bytes.

### Script tools (only when `--mcp-allow-scripts`, stdio only)

| Name                          | Description                                                       |
|-------------------------------|-------------------------------------------------------------------|
| `list_scripts()`               | Names of the saved scripts in `~/.config/axross/scripts/`.        |
| `get_script_api(names?)`   | The `axross.*` API as JSON (same as `axross.api_schema(names)` and [`scripting-api.json`](scripting-api.json)): rules and errors for scripts; per function signature, typed parameters, return type, whole docstring, examples, `raises`, `mutates`, `prompts`; the public classes, the types the API returns and the methods of every backend session. `names: []` gives the index alone, a list of names only those. Read-only. |
| `read_script(name)`           | Source of one saved script.                                       |
| `write_script(name, source)`  | Save `<name>.py` (mode 0600); overwrites.                         |
| `delete_script(name)`         | Remove a saved script; idempotent.                                |
| `run_script(name, args?, timeout?)` | Run a saved script in its own Python process with `axross.*` in scope; `args` become `sys.argv[1:]`. Returns a structured reply (below). |

`run_script` in detail — what a client can rely on:

* **A child process, never the server.** stdin is empty: `input()` gets
  `EOFError` and can never read the JSON-RPC stream. The child runs in a
  process group of its own; when the run ends, every process it started
  ends with it (one that calls `setsid` escapes).
* **Wall clock.** `timeout` (default 60, at most 600) stops the run:
  SIGTERM to the group, SIGKILL 3 s later. `axross/tasks/start` + `axross/tasks/cancel`
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
  `AXROSS_TARPIT_DISABLE=1`. `get_script_api` marks every function
  that can need a human (`prompts`) or change state (`mutates`).
* **Arguments.** `args`: at most 64 strings of at most 4096 characters,
  no NUL; a bad `args` or `timeout` is refused before anything runs
  (`-32602`).

**Security note:** the script tools are **not** confined to the MCP
root at all. Names are restricted to `[A-Za-z0-9_-]+` inside the
script directory, but `run_script` executes arbitrary Python with
the server's user rights — it can read and write anything that user
can, open network connections and use every `axross.*` backend. Treat
`--mcp-allow-scripts` as handing the client a shell. It is refused in
`paranoid` security mode and on `--mcp-http`. `write_script`,
`delete_script` and `run_script` leave attempt / ok / refused lines
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

**On HTTP the level is per session:** a `logging/setLevel` sets the
threshold of the session that sent it (one client no longer makes every
client's stream more or less verbose); a session that never sets one
gets the default, `warning`. Each audit line is forwarded once.

### Other methods

| Method          | Purpose                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `initialize`    | Handshake; answers protocol version, server info and capabilities.     |
| `ping`          | MCP liveness check; empty result.                                       |
| `tools/list`    | The tool catalogue with input schemas.                                  |
| `tools/call`    | Run one tool synchronously.                                             |
| `axross/tasks/start`   | **Axross extension, not part of MCP.** Start a tool in the background; returns `task_id`. Same schema check, same rate limit and same per-tool timeout as `tools/call`; at most 8 running tasks per scope (`MAX_RUNNING_TASKS_PER_SCOPE`) and 16 in the server (`MAX_RUNNING_TASKS_TOTAL`). |
| `axross/tasks/status`  | Status, last progress, and result or error once finished; `abandoned: true` when the task ended without its tool (below). |
| `axross/tasks/cancel`  | Cancel a running task; answers `{ok, task_id, status}`.                 |
| `axross/tasks/list`    | Short summary of the scope's tasks.                                     |

The methods are `axross/tasks/*`: MCP 2025-11-25 defines a `tasks/*` of
its own (task-augmented requests, `taskId`, other states), which this
server does not offer. Sessions of 2024-11-05 and 2025-06-18 may still
call the bare `tasks/start`, `tasks/status`, `tasks/cancel`, `tasks/list`;
a 2025-11-25 session gets -32601 for them. An unknown task id is -32602.

Tasks are scoped per session on HTTP and server-wide on stdio. A
cancel - and a tool's timeout - asks the tool to stop; the tools stop
within one chunk or entry (compute_file_checksum hashes local files chunk by chunk,
copy_path_to_backend checks between chunks). A tool that does not stop within
`TASK_STOP_GRACE_SECONDS` (10 s; a backend call that cannot be
interrupted) is abandoned: the task ends (`cancelled`, or `error` after
a timeout, with `abandoned: true`), its slot is free, the call runs out
in the background and its result is dropped. An HTTP session that ends
(DELETE, idle eviction) cancels and forgets its tasks; a stdio server
whose client closes stdin (or that gets SIGTERM) cancels its tasks and
gives them 5 s to clean up before it exits. Finished tasks are kept for
an hour (`TASK_RETENTION_SECONDS`), at most 100 per scope
(`MAX_TASKS_PER_SCOPE`) and 64 MiB of results in the whole server
(`MAX_TASK_RESULTS_TOTAL_BYTES`), oldest finished first, in every scope
on every call. A result over 16 MiB becomes an error.

**Notifications and the lifecycle.** A message without an `id` is a
notification: it is never answered and never runs a tool (a `tools/call`
without an id does nothing). An `id` of `null`, a `jsonrpc` other than
`"2.0"` and any request but `initialize` and `ping` before `initialize`
are -32600. A client's response object is ignored (HTTP: 202).

---

## 3. Progress, cancellation, timeouts

### 3.1 Progress

Pass `_meta.progressToken` on a `tools/call` and the server emits
`notifications/progress` frames from the handlers that support them:
`walk_tree` (entries visited), `search_content` (files scanned), `compute_file_checksum` (bytes
hashed, streaming fallback only), `compute_tree_checksums` (files hashed)
and `copy_tree` (files copied), and the long group tools of §9
(`read_metadata` / `export_metadata` on folders, `strip_metadata`,
`scan_file_types`, `scan_duplicates`, `trash_duplicates`,
`build_index`, `create_archive`, `extract_archive`, `copy_path_to_backend`). `total` is
sent only when it is known (the bytes of one file, the files of a list);
a walk does not know its count, and its cap (`max_entries`, `max_files`)
is no total, so those frames have none. Inside a
`axross/tasks/start` task the same
tools report progress with the `task_id` as token. On stdio the frames go to
stdout through the same lock as every response, so frames from
different threads never interleave inside a line; on HTTP they're
queued per-session and relayed over the SSE stream (`GET /messages`).

### 3.2 Cancellation

Clients send `notifications/cancelled` with a `requestId`. A cancel
registry (per session on HTTP, per server on stdio) flips a
`threading.Event` that every long-running handler polls via
`ctx.check_cancel()`. The handler raises `CancelledError` and the
cancelled request gets **no response** (as MCP says); the same event is
core.transfer_hooks' cancel for the call, so a backend's long listing, a
server-side copy command or a spooled upload stop on it too.

On stdio every `tools/call` and `resources/read` runs on a worker thread
(at most 16 at once): the loop keeps reading, answers `ping` while a
70 s create_archive runs, and delivers `notifications/cancelled` to the call. When
stdin closes, the calls in flight get 5 s to finish and answer (a client
that pipes its requests still reads them), then what still runs is
cancelled and the server exits. On HTTP every request runs on its own
thread as well. Stdio is a pipe with back-pressure: a client that sends
more than 16 calls without reading stdout waits once the answers fill
the pipe (the workers wait to write, new calls wait for a worker) -
read the answers as they come.

A call that does not stop - a backend call that cannot be interrupted -
is left to end in the background when its timeout passes (a task: after
`TASK_STOP_GRACE_SECONDS`). Such threads are counted: while 8
(`MAX_ABANDONED_WORKERS`) still run, new `tools/call` and
`axross/tasks/start` are refused (-32001) instead of piling up threads.
A profile opened over MCP has a 60 s read timeout on its SFTP channel
(a server that stops answering ends the call), and an SFTP folder
listing stops at 300,000 entries and at a cancel.

### 3.3 Timeouts

Every tool has a wall-clock ceiling:

| Class (`timeout_class`) | Timeout | Tools                                                                      |
|-----------|---------|----------------------------------------------------------------------------|
| `quick`   | 15 s    | `get_path_info`, `read_file`, `list_directory`, `search_index`, `list_file_versions`, `read_file_version`, and every tool without an entry of its own — including the script tools other than `run_script` |
| `walk_tree`    | 60 s    | `walk_tree`, `search_content`                                                             |
| `render_preview` | 30 s    | `render_preview`                                                                  |
| `write`   | 30 s    | `write_file`, `create_directory`, `delete_path`, `move_path`, `copy_file`, `create_link`, `set_permissions`, `restore_from_trash` |
| `stream`  | 300 s   | `compute_file_checksum`, `compute_tree_checksums`, `copy_tree`, `restore_file_version`      |
| `long`    | 1800 s  | whole-tree group jobs (§9): `scan_duplicates`, `trash_duplicates`, `build_index`, `create_archive`, `extract_archive`, `copy_path_to_backend`, `move_file_to_backend`, `strip_metadata` |
| `script`  | 610 s   | `run_script`. It stops its child at its own `timeout` (default 60 s, at most 600 s); the class adds the kill grace and the output drain, so the deadline only backs that up |

The class of every group tool is in the manifest (§9.7). A
`axross/tasks/start` task gets the same timeout as its tool.

Two parallel mechanisms back the deadline:

1. A `threading.Timer` flips the handler's cancel event when the
   deadline elapses. Handlers that poll `ctx.check_cancel()`
   (`walk_tree`, `search_content`) exit cleanly on the next tick.
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
remote. A `delete_path` that times out may still delete the path. The
client sees a timeout response; the operator should assume the
underlying operation's outcome is unknown and either re-check or
re-issue with a suitable idempotency key. We can't safely
interrupt arbitrary blocking IO; anyone who tells you they can
is either lying or running under fork().

---

## 4. Rate limiting

Default on: 30-token burst, refills at 1 token/sec (60 calls per
minute steady-state). `tools/call` and `axross/tasks/start` draw from the
same bucket (one bucket per server on stdio, one per session on
HTTP); `tools/list`, `initialize`, `ping`, `resources/*`,
`axross/tasks/status|cancel|list` and `logging/setLevel` stay free.

Rejection is -32001 with `data.type = "RateLimitError"`. A
`axross/tasks/start` beyond the running-task cap is also -32001, with
`data.type = "TaskLimitError"`.

Tune via `ServerConfig.rate_burst` / `rate_refill_per_sec` or
disable with `rate_limit_enabled = False`.

---

## 5. Multi-backend

From the CLI, the `remote` group (§9.5) is the way to more backends:
`open_remote_profile` turns a saved connection profile into the backend
`profile:<name>`, and the default `LocalFS` gets the id `local`.
Embedding the server from Python, you can also pass a dict of
`{id: backend}` as `ServerConfig.backends` (or
`HTTPServerConfig.backends`). In both cases:

 - A read-only `list_backends` tool returns
   `[{id, class, name, is_default, remote}]` (opened profiles add
   `profile`, `protocol`, `production`) so the LLM can enumerate.
 - Every other tool's inputSchema gains an optional `backend: string`
   field (tools that name their backends themselves, like
   `copy_path_to_backend`, or touch none, do not). Omit it to route to the
   default; pass an id to route elsewhere. Unknown ids land on -32602.
 - Backends of a static library registry are confined to the MCP root
   like the default one; profiles opened with `open_remote_profile` are not
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

 - Idle sessions are evicted after 10 minutes (tunable), counted from
   the end of their last request. A session at work is never evicted, by
   the idle sweep or to make room: a `tools/call` still running, a running
   task and an open SSE stream (a client waiting for a long task's result)
   count as activity for the idle sweep. At the session cap (256) an
   `initialize` evicts a session idle 30 s or more (no request in that
   time) without a running call or task, instead of answering 503: first
   one without an SSE stream, then one that only holds its stream - from
   the client holding the most sessions, idle longest (one local client
   held all 256 sessions with a stream each). With none idle that long,
   the client holding more than half the sessions - on loopback every
   local client together - gives up its least recently used session that
   runs nothing (a client kept 256 sessions busy with pings); that
   session's client gets 404 and starts a new one, as MCP has it. Only
   when every session runs a call or task is the answer 503. Under mTLS one client (its address and certificate)
   holds at most 32 sessions, and at that cap its own session idle
   longest makes room the same way; on loopback (plain HTTP) every local
   client is one address and one token, so only the server's cap applies.
 - Rate: each session has its own `tools/call` bucket, and its client
   one shared bucket four times that size (`FAIR_SHARE_SESSIONS`). When
   the shared bucket is empty, a session still has a reserve of its own:
   half its rate (`FAIR_RESERVE_SHARE`, 0.5 calls/s, burst 2) - for a
   quiet session only (its attempts, refused ones included, within its
   own rate), and drawn from its client's pool of reserves, twice the
   shared rate. So flooding sessions - any number - leave a quiet session
   that minimum, and more sessions add no rate past the shared bucket and
   the pool. The pool is shared by the quiet sessions: very many of them
   each calling just under its own rate (200 at once) divide it, and a
   quiet session then gets its share of the pool, not 0.5 calls/s. The per-IP edge cap (§7.7) is shared the same way
   - with a bucket and reserve only for a session the server knows (any
   other `Mcp-Session-Id` shares one; the edge keeps at most 4096
   buckets).
 - A session runs at most 16 `tools/call` at once (-32001,
   `CallLimitError`, past it). On plain HTTP a client that closes its
   connection while its call runs has the call cancelled: the server
   watches the socket, and at the end of the client's input writes an
   interim `100 Continue` (an HTTP/1.1 client skips it) - a reset in reply
   is a closed client, anything else a half-close (`nc -N`, `shutdown(
   SHUT_WR)`) whose call runs on and is answered; it is asked again every
   5 s, so closing fully later is noticed too. An HTTP/1.0 request gets no
   interim answer. Under TLS the call runs to its end or time-out.
 - Every connection is read on a thread of its own (a TLS handshake or a
   request that blocks holds that connection only). At most 1024 are
   served at once - fewer when the process's file-descriptor limit is low:
   half of what is left after 256 descriptors of headroom (384 at a soft
   limit of 1024), and fewer where fewer threads can start (RLIMIT_NPROC,
   the cgroup's pids.max, an address-space limit); a thread that still
   fails to start lowers the cap to 16 below what is open (never below 8),
   and after 32 thread starts in a row it rises again by 16. During a
   reconnect flood at a thread limit a request can still wait several
   seconds (3.7-5.6 s measured at 1000-1400 connections/s) or be reset.
   Past the cap a new connection takes the place of one that has never
   shown its token or certificate: from an address (an IPv6 /64) that
   clearly holds more such connections at least 1 s old (three or more,
   and twice the median of the other addresses; one client's parallel
   calls, a connection each, do not count) first; then, of the oldest ones
   at least 0.2 s old, the one silent longest (a burst and then a stall,
   not a handshake that keeps receiving its next record), then the one
   that sent the fewest bytes. None that old (the table turns over faster):
   not simply the oldest - a slow handshake - but the oldest of the address
   holding the most (of equally many, the one with the newest connection). A connection that has shown its token or
   certificate is never pushed out (`GET /health`, which needs no token,
   does not count; the server speaks HTTP/1.0, one request per
   connection). Known limit: from the client's own
   address (or /64), connections that trickle a byte every few
   milliseconds look more alive than a slow handshake and can push it
   out - the attacker needs that address. A request's
   head must arrive within 15 s; its body, once authenticated, may take up
   to 300 s but no slower than 1 KiB/s after its first 10 s (408 then;
   `AXROSS_MCP_MIN_BODY_RATE` sets the rate in bytes/s, 0 switches it
   off). One client - on loopback every local one - has at most 16 bodies
   arriving at once: past that a fresh request takes the place of the
   slowest one that has been arriving for a second at less than four times
   the minimum rate, and gets 503 when every body is faster (up to 1 MiB
   of its body is read past first, so the client sees the 503 rather than
   a broken pipe). Off loopback
   one address (an IPv6 /64) holds at most 32 connections. On loopback
   every local process is one address: a local process that opens
   connections faster than a request arrives can still delay it -
   loopback trusts local processes that far. TLS renegotiation is off.
 - Stopping the server (Ctrl+C, SIGTERM) ends every session as DELETE
   would - running calls and tasks are cancelled - and gives the task
   workers 5 s, as on stdio.
 - A session that ends cancels its running tool calls and tasks.
 - A new SSE stream without `Last-Event-ID` sends only what no stream
   delivered yet; with it, the replay from that id.
 - `POST` needs `Content-Type: application/json` (415 otherwise: a web
   form cannot post one without a preflight). Under mTLS an `Origin`
   other than the server's own `https://` origin is refused (403), and
   every path but `GET /health` needs a verified client certificate (the
   TLS layer asks for one but lets a health probe in without).
 - The bearer token file is written once the socket is bound (a second
   server on a busy port no longer overwrites the running one's), is
   named `mcp-http-<host>-<port>.token`, and is removed when the server
   stops (also on SIGTERM).
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
| `tests/test_mcp_error_redaction.py` | Secrets in backend error text are redacted (tools/call, tasks, compute_tree_checksums). |
| `tests/test_mcp_http_hardening.py` | DNS rebinding (Host/Origin), session cap and idle eviction, malformed params/ids, partial TLS flags, idle TCP client vs. accept. |
| `tests/test_secfix_r7_host_header.py` | `Host` parsed strictly as `host[:port]` (`localhost:1@evil`, paths, spaces, bare IPv6 refused); two `Host`/`Origin` headers refused (MCP HTTP and reverse-serve). |
| `tests/test_mcp_http_bearer_token.py` | Plain HTTP refuses requests without the bearer token (401, `/health` exempt), the token file is 0600 and never written through a symlink, `--mcp-http` always serves with one. |
| `tests/test_mcp_http_sse_lifecycle.py` | One SSE stream per session, DELETE/idle eviction end it, replay on reconnect. |
| `tests/test_mcp_search_root.py` | `search_index` never returns indexed paths outside the root. |
| `tests/test_mcp_tasks_limits.py` | `axross/tasks/start` rate limit, running-task cap, tool timeout. |
| `tests/test_mcp_write_root.py` | `--mcp-write` needs `--mcp-root`; `--mcp-allow-scripts` refused with `--mcp-http`. |
| `tests/test_mcp_secret_reads.py` | Secret files (§7.12) are not read, grepped, hashed, previewed, copied, moved or hard-linked, also through a symlink, a group tool or `resources/read`; their names are listed; `--mcp-allow-secret-reads` (stdio only) lets them be read. |
| `tests/test_mcp_http_mode.py` | `--mcp-http` alone starts the HTTP server (it opened the window) and does not detach from the terminal. |
| `tests/test_mcp_script_audit.py` | Script tools write the audit trail, without source or output. |
| `tests/test_mcp_script_run_child.py` | `run_script` in a child: timeout and group kill, no grandchild left, `input()` never reads the stdio stream, cancel, output cap, argument checks, structured reply. |
| `tests/test_mcp_stdio_write_lock.py` | Concurrent stdio writers never interleave inside a line. |
| `tests/test_mcp_tools_flag.py` | `--mcp-tools` / `AXROSS_MCP_TOOLS` parsing, unknown group exit 2, default surface unchanged, read-only `all` offers no mutating tool. |
| `tests/test_mcp_group_metadata_filetype.py` | `metadata` and `filetype` groups: root escapes, symlinks, no overwrite, audit. |
| `tests/test_mcp_group_duplicates_index.py` | `duplicates` and `index` groups: index rows outside the root never show, dedupe re-check, trash under the root. |
| `tests/test_mcp_group_packer_archive.py` | The `archive` group (packing and unpacking): zip-slip, password never logged, cancel leaves nothing. |
| `tests/test_mcp_group_crypto.py` | `crypto` group: passphrase never in answers, errors or audit; no overwrite. |
| `tests/test_mcp_group_remote_transfer.py` | `remote` and `transfer` groups: no secrets listed, no prompts, host keys, production profiles, per-session scoping, resumable copy. |
| `tests/test_exec_everywhere.py` | `exec()` of Telnet, rsh, ADB, WinRM and Cisco: exit status as `returncode`, stdin over a temporary file, env keys checked and values quoted, output caps, Cisco `show` only. |
| `tests/test_mcp_group_exec.py` | `exec` group: off without `--mcp-allow-exec` (also under `all`), refused in paranoid mode, backends without a shell refused, interpreter per backend, production profiles run nothing, audit without command, stdin or output. |
| `tests/test_mcp_group_extensions.py` | `extensions` group: listing never imports an extension. |
| `tests/test_mcp_manifest.py` | `--mcp-list-tools` and the committed `docs/mcp-tools.json` stay in sync with the code. |
| `tests/test_mcp_protocol_matrix.py` | Every registered protocol has a route: `open_remote_profile` reaches each profile protocol (stored password handed over, files written and read back), browser sign-in and paranoid-mode refusals carry their reason, the URL-only ones open through `axross.open_url`. |
| `tests/test_mcp_docs_group_table.py` | The §9.2 table of this file and of its German and Spanish versions lists exactly the group tools of `docs/mcp-tools.json`. |
| `tests/test_mcp_groups_e2e.py` | The real server over stdio and HTTP with `--mcp-tools all`: one call per group, `axross/tasks/start` + `axross/tasks/cancel`. |
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
`create_link` write tool) would point at `/` and let
`write_file("/root/escape/etc/cron.d/evil")` slip past. Now
rejected with `PermissionError`, answered as a tool result flagged
`isError` with `_meta.type = "PermissionError"` and a text naming the
root (§8). The
capability groups (§9) run every local path through the same check.
Tools that check many paths in one call (`search_content`, `search_index`,
`compute_tree_checksums`) resolve the root once per call and still resolve
every path on its own; the next call resolves the root again, so a
root re-pointed while the server runs is seen by the next call.

`delete_path`, `move_path` and `move_file_to_backend` act on the directory entry
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

### 7.5 search_content ReDoS preflight

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

Every write tool — and `write_script`, `delete_script`,
`run_script` — emits an `outcome=attempt` audit entry BEFORE
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

### 7.12 Secret files are not read

The default root is the home folder, and some files there turn "read
my files" into the user's accounts. No tool hands out their contents,
whatever the root (`core.protected_places.read_refusal`):

* axross's tokens: `~/.config/axross/*token*` (the Google Drive,
  OneDrive and Dropbox refresh tokens of every profile, the MCP HTTP
  token; `$XDG_RUNTIME_DIR/axross/*token*` too);
* its keys: the chat accounts' state (`~/.local/state/axross/chat/`,
  encryption keys and sync tokens), the Bluetooth link keys
  (`bluetooth-direct-keys.json`), the ADB key it made (`~/.android/adbkey`);
* every file in `~/.ssh` but `*.pub`, `known_hosts`, `authorized_keys`
  and `config` (a private key may have any name);
* GnuPG's `private-keys-v1.d/`, `openpgp-revocs.d/` and `secring.gpg`.

Refused: `read_file`, `compute_file_checksum`, `render_preview`, `read_file_version`,
`resources/read`; in `search_content` and `compute_tree_checksums` such a file is
reported unreadable; `copy_file`, `copy_tree`, `move_path` and `create_link` with `kind: "hard"` do not
take one (or a folder holding one) as their source; the capability
groups (§9) see it as outside the root. A symlink to a secret is
resolved and refused. Names stay listable (`list_directory`, `walk_tree`, `get_path_info`,
`search_index`). In the agent sandbox the host's home counts too.
Anywhere (a project folder too): a file holding a private key or a
password database (a KeePass signature at its start; `-----BEGIN …
PRIVATE KEY-----`, OpenSSH or PuTTY in its first MiB - also after the
certificates of a bundle), and files secret by their name (`.env`,
`.env.*` except `.example`/`.sample`/`.template`/`.dist`, `*.env`,
`.envrc`, `.netrc`, `.git-credentials`, `.pgpass`, `.npmrc`, `.pypirc`,
`.htpasswd`, `*.tfstate`, `*.kdbx`, `id_rsa`, `id_ed25519`, `id_ecdsa` and
their copies such as `id_rsa.bak`, `*.ppk`, `*.p12`, `*.pfx`,
`kubeconfig`, `credentials.json`, `client_secret*.json`, `secrets.yaml`,
`secrets.json`, `.my.cnf`, `.mylogin.cnf`, `.vault-token`, `.s3cfg`,
`.boto`, `.aws/credentials`, `.docker/config.json`,
`.kube/config`), and these names with a backup suffix (`.bak`, `~`,
`.old`, `.orig`, `.save`, `.swp`: `.env~`, `.netrc.bak`); also
`token.json`, `service-account*.json`, `credentials.tfrc.json`,
`.dockercfg`, `*.jks`, `secring.gpg`. Past the first MiB every local read
is scanned as it goes (core.protected_places.SecretScanningReader): a
private key's BEGIN or END line anywhere in a file stops `read_file`,
`search_content`, `resources/read` and every tool that copies or transforms bytes
(`encrypt_file`, `create_archive`, `copy_path_to_backend` to a remote, `copy_file`...) - a key
padded past 1 MiB is not handed out inside an archive or an .axenc
either. **On a remote** (a profile opened with `open_remote_profile`) the
name-based rules apply too - the names above, `.ssh/` but its public
files, `.gnupg/` private parts - and what `read_file` serves is scanned
for a key.

**What the content scan finds, and what it does not.** It finds a PEM,
OpenSSH or ssh.com/Tectia private key's BEGIN or END line (five or four
dashes, spaced or not, any case), a PuTTY key's first line and an age
identity (`AGE-SECRET-KEY-1…`) anywhere in a file - inside an
uncompressed tar or a stored zip member, mid-line, in UTF-16 and UTF-32
too - and a
KeePass database by the signature at its start. A `read_file` window from
the middle of a key block is refused too: the server walks back over the
block's base64 lines to its BEGIN line (up to 16 MiB). It does **not**
find: a key that is compressed (`.tar.gz`, a deflated zip member, a
`.gz`) or encoded (base64 of a PEM, hex); a KeePass database inside an
archive; cloud credentials and tokens in files with neutral names (an
AWS key pair, a kubeconfig token, an API key in `settings.ini` - only the
names listed above are known); passwords in general. On a remote only
what `read_file` serves is scanned; copies from a remote are not. The
pinned opens of §7.1 (no folder swap between check and read) need Linux's
`/proc`; on macOS and BSD the path is opened again by name. Treat the
scan as a guard against accidents, and keep secrets outside the root.

Below `/proc` a
process's `environ`, `cmdline`, `mem`, `maps`, `fd` and the like and all of
`/proc/self` (a root of `/` would hand out axross's API keys), and
`/run/secrets`. `set_permissions` refuses a file with other hard links.
`--mcp-allow-secret-reads` (stdio only) switches the check off; the
agent's own tools always keep it. The write side (§2, the protected
places of `core.protected_places`) is a list of its own and unchanged by
this switch. Besides the home's start files and Git's code files (in any
case: `head`, `.GIT`), it refuses at any depth the project files other
programs run code from - the folders `.claude`, `.vscode`, `.cursor`,
`.idea`, `.zed`, `.devcontainer`, `.husky` (and `.fleet`, `.gemini`,
`.codex`, `.windsurf`, `.roo`, `.kiro`, `.amazonq`, `.continue`, `.theia`)
and `.mcp.json`, `.devcontainer.json`, `*.code-workspace`,
`.pre-commit-config.yaml`, `lefthook.yml`, `.overcommit.yml` - the folder a
repository's `core.hooksPath` names (its config, `~/.gitconfig`,
`/etc/gitconfig`, `GIT_CONFIG_*`) and the files its config includes. It
also refuses the files an enabled MCP server of Agent Settings runs on this
machine (its script; beside a Python script any module file, which Python
would import first: `core.mcp_script_pin`) - and that server does not start
with files that changed since the user confirmed them, until the user says
so (USAGE.md, MCP servers).

Every name a path goes by is checked - as typed, after each symlink on
the way, and resolved - on both sides: a key behind
`~/.ssh/id_ed25519 -> ~/keys/id_ed25519` is refused under either name, and
`~/dotfiles/kitty/kitty.conf` is not written when `~/.config/kitty` links
there (grant the target to allow it). A hard link to a secret file is not
read; a file with other hard links is not written at all (in place, the
other names - maybe `~/.bashrc` or a `.git/config` - would change too).

**Default-deny for reads.** Besides the secrets, the contents of a hidden
entry of the home (`~/.config/<app>`, `~/.mozilla`, ...) and of `~/snap`
(also `~/Library`, `%APPDATA%`) are not handed out unless the operator
granted that folder: an `--mcp-root` inside such a place (for the agent:
its folder or an extra folder there; read-only is enough; the secrets in
it stay unread). A root of the
whole home lifts nothing. Names stay listable; other files read as before.
`--mcp-allow-secret-reads` lifts this too.

---

## 8. Error codes

| Code     | Name                    | Used for                                              |
|----------|-------------------------|-------------------------------------------------------|
| -32700   | PARSE                   | JSON decode failed.                                   |
| -32600   | INVALID_REQUEST         | Missing method, non-object body.                      |
| -32601   | METHOD_NOT_FOUND        | Unknown method / disabled capability.                 |
| -32602   | INVALID_PARAMS          | Unknown tool or task id, jsonschema failure, ValueError in handler, bad URI (2025-11-25 sessions: a refused argument is a tool error result instead). |
| -32603   | INTERNAL                | A result that cannot be sent (not serialisable, over the size cap), or a call cancelled by the client. |
| **-32001** | **RATE_LIMITED**      | `tools/call` / `axross/tasks/start` throttled, or running-task cap reached. |
| **-32002** | **TIMEOUT**           | Tool exceeded its wall-clock timeout.                 |

A tool that ran and failed - its handler raised anything other than
ValueError / TypeError: an OSError (a missing file, a name that exists),
the `PermissionError` of a root escape or a secret file, a refused
profile, … - is not a JSON-RPC error. As the MCP specification asks, it is
a normal **result flagged `isError`**, so the model sees the reason and
can react:

```json
{"jsonrpc": "2.0", "id": 7, "result": {
  "content": [{"type": "text", "text": "tool 'read_file' failed: [Errno 2] No such file or directory: '/w/missing.txt'"}],
  "isError": true,
  "_meta": {"type": "FileNotFoundError"}}}
```

The text is redacted like every error message (credentials in URLs,
`password=` pairs, auth headers); `_meta.type` names the exception.
Bad arguments stay -32602 - in a 2025-11-25 session they are such a
result too (§1.4) - and so does an unknown tool (-32602, as MCP names
it). An archive refused as unsafe and an image that has no preview are
the tool's failure: an `isError` result, not -32602.

**File names that are not UTF-8.** A name whose bytes are not UTF-8 (a
Latin-1 name on a Linux disk) goes out with U+FFFD in place of the
undecodable bytes - JSON may carry a lone surrogate, but a client's UTF-8
decoder refuses it (the official SDK dropped the response and waited
forever) - and a sibling field with the raw bytes in base64: `name_b64`,
`path_b64`, ... Every path argument has a twin that takes them back:
`path_b64`, `src_b64`, `dst_b64`, `dest_dir_b64`, `folder_b64`,
`link_path_b64`, `out_b64`, `target_b64`, `names_b64` (a list); the twin
wins over the plain argument. Error texts carry U+FFFD only.

---

## 9. Capability groups (`--mcp-tools`)

Without `--mcp-tools` the server offers exactly the tools of §2.
`--mcp-tools GROUP[,GROUP...]` (repeatable; `AXROSS_MCP_TOOLS` is
merged with it) adds groups; `all` adds every general group - every
group but `adb`, a group for one kind of device, which comes only by
name: `--mcp-tools all,adb` is every group. An unknown group
stops the start with exit code 2 and one stderr line listing the
valid groups.

**Compatibility (0.15.184):** up to 0.15.183 `all` held every group;
since the `adb` group (20 tools) arrived, `all` leaves it out, so a
file-manager client keeps 54 tools rather than 74. A command line that
wants the Android tools names them: `--mcp-tools all,adb` or
`remote,adb`. The flag is called `--mcp-tools`, not `--backend`:
"backend" already means a protocol backend in axross, and remote
backends are one of the groups.

### 9.1 Common setups

```bash
# Read-only: the file tools plus metadata reading and content types
axross --mcp-server --mcp-tools metadata,filetype

# Pack and extract inside ~/data (mutating tools need --mcp-write,
# which needs --mcp-root)
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools archive

# Build the search index and find duplicates, read-only
axross --mcp-server --mcp-root ~/photos --mcp-tools index,duplicates

# Saved profiles as extra backends, copy between them and ~/data
axross --mcp-server --mcp-write --mcp-root ~/data --mcp-tools remote,transfer

# Run commands on the opened profiles (SSH, Telnet, rsh, ADB, WinRM, Cisco)
axross --mcp-server --mcp-tools remote,exec --mcp-allow-exec

# An Android phone opened as an ADB profile: identity, apps, SMS, log;
# changes (install, start, stop, permissions, reboot) need --mcp-write
axross --mcp-server --mcp-write --mcp-root ~/apks --mcp-tools remote,adb

# Every general group (all but adb), over loopback HTTP; all,adb for every group
axross --mcp-server --mcp-http 127.0.0.1:7331 --mcp-write --mcp-root ~/data --mcp-tools all
# ... or with environment variables
AXROSS_MCP=1 AXROSS_MCP_WRITE=1 AXROSS_MCP_TOOLS=all axross --mcp-root ~/data
```

### 9.2 Groups and tools

Tool names read verb then resource since 0.15.183 (`list_directory`, `get_path_info`, `search_content` ...); `tools/call` still takes the former names (list_dir, stat, grep, ...), which `tools/list` no longer shows. Former tools live on in another one, and their names still answer: export_metadata_file is `export_metadata` with `out`, exec_backends is `list_backends` with `can_run_commands`, extensions_info is `list_extensions` with `name`; since 0.15.184 create_symlink and create_hardlink are `create_link` with `kind`, run_backend_script is `run_backend_command` with `script`. The group packer is part of `archive` now; `--mcp-tools packer` still works. Renamed parameters still work too: `search_index`'s needle and limit (`pattern`, `max_results`), `run_script`'s timeout_s (`timeout`), `create_archive`'s folder (`path`), the 0-based max_depth of `scan_file_types` and `copy_path_to_backend` (`subfolder_levels`), and `run_llm_agent`'s profile (`llm_profile`).

Read-only tools of a group need only `--mcp-tools <group>`; mutating
ones are not even registered without `--mcp-write` (and `--mcp-write`
is refused without `--mcp-root`). The `exec` group is the exception:
its tools need `--mcp-allow-exec` instead, and `all` leaves the group
out unless that flag is given (§9.8). `export_metadata` needs only
`--mcp-tools metadata`; its `out` (save the export as a file) is there
with `--mcp-write`.

| Group | Tool | Kind | Required flags | Timeout class |
|-------|------|------|----------------|---------------|
| `metadata` | `read_metadata` | read-only | `--mcp-tools metadata` | stream |
| `metadata` | `export_metadata` | mutating | `--mcp-tools metadata` | stream |
| `metadata` | `strip_metadata` | mutating | `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR` | long |
| `duplicates` | `scan_duplicates` | read-only | `--mcp-tools duplicates` | long |
| `duplicates` | `list_duplicate_scans` | read-only | `--mcp-tools duplicates` | quick |
| `duplicates` | `list_duplicate_groups` | read-only | `--mcp-tools duplicates` | quick |
| `duplicates` | `trash_duplicates` | mutating | `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR` | long |
| `duplicates` | `list_trash` | read-only | `--mcp-tools duplicates` | quick |
| `duplicates` | `restore_from_trash` | mutating | `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR` | write |
| `archive` | `list_archive_formats` | read-only | `--mcp-tools archive` | quick |
| `archive` | `create_archive` | mutating | `--mcp-tools archive` `--mcp-write` `--mcp-root DIR` | long |
| `archive` | `list_archive_members` | read-only | `--mcp-tools archive` | walk |
| `archive` | `extract_archive` | mutating | `--mcp-tools archive` `--mcp-write` `--mcp-root DIR` | long |
| `crypto` | `encrypt_file` | mutating | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `crypto` | `decrypt_file` | mutating | `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR` | stream |
| `index` | `build_index` | read-only | `--mcp-tools index` | long |
| `filetype` | `identify_file_type` | read-only | `--mcp-tools filetype` | walk |
| `filetype` | `scan_file_types` | read-only | `--mcp-tools filetype` | stream |
| `transfer` | `copy_path_to_backend` | mutating | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `transfer` | `move_file_to_backend` | mutating | `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR` | long |
| `remote` | `list_remote_profiles` | read-only | `--mcp-tools remote` | quick |
| `remote` | `open_remote_profile` | read-only | `--mcp-tools remote` | walk |
| `remote` | `close_remote_profile` | read-only | `--mcp-tools remote` | quick |
| `remote` | `list_backends` | read-only | `--mcp-tools remote` | quick |
| `adb` | `get_device_info` | read-only | `--mcp-tools adb` | walk |
| `adb` | `list_device_properties` | read-only | `--mcp-tools adb` | walk |
| `adb` | `get_battery_status` | read-only | `--mcp-tools adb` | walk |
| `adb` | `list_apps` | read-only | `--mcp-tools adb` | walk |
| `adb` | `get_app_info` | read-only | `--mcp-tools adb` | walk |
| `adb` | `list_running_apps` | read-only | `--mcp-tools adb` | walk |
| `adb` | `get_logcat` | read-only | `--mcp-tools adb` | walk |
| `adb` | `take_screenshot` | mutating | `--mcp-tools adb` | walk |
| `adb` | `list_sms` | read-only | `--mcp-tools adb` | stream |
| `adb` | `start_app` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | walk |
| `adb` | `stop_app` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | walk |
| `adb` | `install_app` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | long |
| `adb` | `uninstall_app` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | stream |
| `adb` | `export_app` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | long |
| `adb` | `grant_permission` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | walk |
| `adb` | `revoke_permission` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | walk |
| `adb` | `reboot_device` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | walk |
| `adb` | `write_sms` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | walk |
| `adb` | `compose_sms` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | walk |
| `adb` | `send_at_command` | mutating | `--mcp-tools adb` `--mcp-write` `--mcp-root DIR` | stream |
| `exec` | `run_backend_command` | mutating | `--mcp-tools exec` `--mcp-allow-exec` | long |
| `agent` | `run_llm_agent` | read-only | `--mcp-tools agent` | long |
| `agent` | `list_llm_profiles` | read-only | `--mcp-tools agent` | quick |
| `extensions` | `list_extensions` | read-only | `--mcp-tools extensions` | quick |

"Read-only" means: no file of the user changes. `scan_duplicates` and
`build_index` do write axross' own indexes (the Duplicate Finder's
and the metadata search's, under `~/.local/share/axross/`), the same
indexes the GUI uses; `open_remote_profile` opens a network connection.

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
  `list_trash` lists that trash (only entries whose original place is
  inside the MCP root, newest first, paged) and `restore_from_trash`
  moves one back - to its original path or to `dst`, never over an
  existing entry, never outside a writable root or into a protected
  place, and not at all when its record does not verify (core.trash's
  HMAC).
* **archive** — create zip, tar.gz / tar.zst / tar.xz / tar.bz2, 7z (with a
  password: AES-256, file list encrypted too) and single-file gz / zst
  / xz / bz2. ZIP has no password option (ZipCrypto is broken). List
  members without extracting; extract into a fresh
  folder (`x.zip` → `x`, `x-1`, …) with the zip-slip, link, size
  (1 GiB), entry-count (10,000) and ratio (100:1, for members of
  64 MiB or more) guards of `core.archive`. Local archives only: copy a remote archive with
  `copy_path_to_backend` first.
* **crypto** — the axross `.axenc` format of the GUI (AES-256-GCM,
  PBKDF2-SHA256 with 200,000 iterations, at most 1 GiB per file).
* **index** — fill the offline metadata index that `search_index` reads, so
  `search_index` finally has data without the GUI; `prune` drops rows of
  files that are gone.
* **filetype** — identify files by content (magic bytes, the same
  detector as the GUI) and flag an extension that lies.
* **transfer** — copy files or trees, or move one file, between any
  two backends (`local` and the profiles opened with `open_remote_profile`);
  `resumable=true` copies in 4 MiB segments with a manifest under
  `$XDG_STATE_HOME/axross/resume/`, so an interrupted copy continues
  where it stopped when called again with the same arguments.
* **remote** — see §9.5.
* **adb** — Android devices opened as ADB profiles; see §9.10.
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
   audit line; `list_remote_profiles` lists profiles through a field
   allow-list (no password, key, token, SAS or connection string).
7. **Bounded work.** Every list has a cap (`max_files`, `max_groups`,
   `max_entries`, …, `truncated=true` when cut); long jobs report
   progress, poll cancellation and run under `axross/tasks/start`; results
   above 16 MiB are refused like any tool result.
8. **Writes of one backend run one at a time** (one lock per backend a
   call changes, keyed by the backend the call's arguments resolve to -
   `local` for this machine, whatever string names it): two calls cannot
   interleave a rename and a symlink. A call takes all its locks at once
   or none - it never holds one while waiting for another - so a remote
   whose CLOSE takes 30 minutes holds only that remote's writes, not the
   local disk's, even while a move from it waits. Waiting is first come,
   first served among calls that could go.
9. **Outputs appear whole or not at all.** decrypt_file, encrypt_file, create_archive
   and the copies write under a temporary name that carries the process id and
   rename when complete. Each temporary path is recorded in
   `~/.local/state/axross/partials/` (or `$XDG_STATE_HOME`); the next
   server start removes what a killed process left - only axross's own
   temporary names with the dead process's id, inside the root that
   server serves, reached without a symlink. Records are neither written
   nor read while that folder lies inside the served root (an agent could
   plant one there).

### 9.4 Paranoid security mode

No group is refused as a whole. What the paranoid mode blocks in the
GUI and in scripting stays blocked here:

* `open_remote_profile` refuses the legacy protocols (`ftp`, `telnet`,
  `cisco-telnet`, `tftp`, `gopher`, `nntp`, `pop3`, `rsh`);
  `list_remote_profiles` reports them as `openable: false`.
* `metadata_*` do not run ffprobe / ffmpeg on audio and video (the
  report carries the reason), exactly as in the GUI.
* `list_extensions` reports `allowed: false` and every extension
  `active: false`.
* The script tools stay refused (`--mcp-allow-scripts` exits 2).
* The `exec` group stays refused (`--mcp-allow-exec` exits 2).
* The `adb` tools that change a device (start, stop, install,
  uninstall, permissions, reboot, SMS, AT) are refused; the reading
  ones and `export_app` work.

### 9.5 Remote profiles

* `list_remote_profiles` lists the saved profiles (name, protocol, host,
  port, user, auth type, whether a password is stored, production
  flag) and says per profile whether `open_remote_profile` would refuse it.
* `open_remote_profile(profile)` connects through the GUI's connection
  manager and registers the backend `profile:<name>`; every other tool
  reaches it via `backend: "profile:<name>"`. `close_remote_profile` drops it.
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
* **A stalled server holds its own profile, not the server.** An SFTP
  request that gets no answer for 60 s fails, even while the server
  answers keepalives, and a cancelled call stops waiting within 5 s.
  `AXROSS_MCP_REMOTE_TIMEOUT` (seconds, 5 to 3600) sets that deadline. A
  request a healthy server may take long over - the CLOSE that flushes an
  upload, a REMOVE, a rename, fsync - waits up to 30 minutes while the
  connection answers keepalives (a NAS flushing for 70 s lost the upload).
  Calls that did not stop are counted per backend: at 8 on one profile,
  new calls on that profile are refused (-32001, `AbandonedWorkers`)
  while local tools and other profiles go on; `close_remote_profile` tears the
  connection down, which ends the stalled calls, and `open_remote_profile` can
  connect it again.
* **What a remote sends is checked against what it said.** A copy or
  move whose source sends another number of bytes than its size is an
  error (`size-mismatch`) and leaves nothing behind - `move_file_to_backend`
  keeps the source then. Every count an answer carries (listing entries,
  extended attributes, in a listing and in a stat) is bounded by the
  bytes that carry it - a 13-byte answer claiming 4 billion entries is
  refused at once - and a long answer notices a cancel and a closed
  connection. A listing stops at 300,000 entries or 64 MiB of
  answers - names, longnames and attributes, extended ones too (900 KiB
  of them per entry took a listing past 2.5 GB); a name over 4 KiB is
  left out, extended attributes are not kept. `compute_file_checksum` and a
  server-side copy run no command on anything but a regular file (a
  symlink to `/dev/zero`: `sha256sum` ran on the server for good) nor on
  a file in `/proc`, `/sys` or `/dev` (`/proc/kmsg` is a regular file of
  size 0 that never ends); a file of size 0 is hashed here, and a hash
  that streams the file stops 16 MiB past the size it gave.
* **Outputs appear whole.** Downloads into the root are written under a
  temporary name and renamed; a `resumable` copy writes
  `.<name>.axross-resume.part` beside the destination (a later run
  resumes it) and replaces the destination only when it is complete - a
  failing source or a refused secret leaves an existing destination as
  it was. A hostile name in a remote folder (`C:..`) is skipped, not the
  whole copy; a folder that cannot be listed makes `build_index`,
  `scan_file_types`, `metadata_*` and `scan_duplicates` say `truncated`
  (and name it in `unreadable`).
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
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_metadata","arguments":{"path":"/home/me/data/IMG_0001.jpg"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_duplicates","arguments":{"path":"/home/me/data/photos"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_archive","arguments":{"path":"/home/me/data","names":["report","notes.txt"],"archive_name":"bundle","format":"7z","password":"…"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"extract_archive","arguments":{"path":"/home/me/data/bundle.zip"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"encrypt_file","arguments":{"path":"/home/me/data/notes.txt","passphrase":"…"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"build_index","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"scan_file_types","arguments":{"path":"/home/me/data/inbox","mismatches_only":true}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"copy_path_to_backend","arguments":{"src":"/home/me/data/report","dst_backend":"profile:nas","dst":"/backup/report","resumable":true}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"open_remote_profile","arguments":{"profile":"nas"}}}
{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"list_extensions","arguments":{}}}
```

A long job in the background, cancellable on both transports:

```json
{"jsonrpc":"2.0","id":11,"method":"axross/tasks/start","params":{"name":"scan_duplicates","arguments":{"path":"/home/me/data"}}}
{"jsonrpc":"2.0","id":12,"method":"axross/tasks/status","params":{"task_id":"<task_id>"}}
{"jsonrpc":"2.0","id":13,"method":"axross/tasks/cancel","params":{"task_id":"<task_id>"}}
```

### 9.7 Machine-readable manifest

`axross --mcp-list-tools` takes the same `--mcp-tools`, `--mcp-write`
`--mcp-allow-scripts` and `--mcp-allow-exec` flags (and `AXROSS_MCP_*`
variables) as the
server, starts nothing and prints JSON:

```json
{
  "server": "axross-mcp",
  "protocol_version": "2025-11-25",
  "protocol_versions": ["2025-11-25", "2025-06-18", "2024-11-05"],
  "generated_for": {"mcp_allow_exec": true, "mcp_allow_scripts": true, "mcp_tools": ["..."], "mcp_write": true},
  "timeout_classes": {"quick": 15.0, "walk": 60.0, "write": 30.0, "preview": 30.0, "stream": 300.0, "long": 1800.0,
                      "script": 610.0},
  "groups": {"metadata": {"description": "...", "tools": ["read_metadata", "..."]}},
  "tools": [{"name": "...", "title": "...", "group": "...", "mutating": false,
             "required_flags": ["--mcp-tools metadata"],
             "transports": ["stdio", "http"], "timeout_class": "stream", "timeout_seconds": 300.0,
             "description": "...", "annotations": {"title": "...", "readOnlyHint": true, "...": "..."},
             "input_schema": {"type": "object", "...": "..."}, "output_schema": "(some tools)"}]
}
```

Every schema lists types, required fields, enums, defaults and bounds,
and group tools refuse unknown arguments (`additionalProperties:
false`). [`mcp-tools.json`](mcp-tools.json) is the manifest for
`--mcp-tools all,adb --mcp-write --mcp-allow-scripts --mcp-allow-exec`
(every group);
`tests/test_mcp_manifest.py` fails when it no longer matches the code.
[LLM_GUIDE.md](LLM_GUIDE.md) is the short guide for LLM clients; its
tool catalog is generated from this manifest.

### 9.8 Commands on remote hosts (`exec`)

`--mcp-tools exec --mcp-allow-exec` adds one tool and a field:

* `list_backends` gives every backend `commands`, and with
  `can_run_commands=true` lists only those that can run commands;
  `commands` is `posix-shell` (SSH, SCP, Telnet,
  rsh, ADB), `powershell` (WinRM) or `ios-show` (Cisco Telnet). Open
  a saved profile with `open_remote_profile` (group `remote`) first.
* `run_backend_command(backend, command, stdin?, env?, timeout?, max_output?)`
  runs one command and returns `{returncode, stdout, stderr,
  truncated_stdout, truncated_stderr}`. A non-zero exit is a result,
  not an error. Telnet and ADB have no separate error stream: their
  stderr arrives inside `stdout`.
* `run_backend_command(backend, script, interpreter?, args?, env?, …)` -
  `script` instead of `command` - sends
  the script on stdin to `sh -s --`, `bash -s --`, `python3 -` or
  `perl -` (default `sh`), with `args` quoted after it. A WinRM host
  runs the script as PowerShell (`interpreter: "powershell"`, no
  `args`); a Cisco device runs no scripts. The former
  `run_backend_script` calls it this way.

Limits and guards:

* **Its own opt-in.** `--mcp-allow-exec` is a flag only (no
  `AXROSS_MCP_*` variable), `--mcp-tools all` without it does not
  register the tool, and `--mcp-write` does not enable it.
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
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_remote_profile","arguments":{"profile":"web01"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_backend_command","arguments":{"backend":"profile:web01","command":"df -h /","timeout":30}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_backend_command","arguments":{"backend":"profile:web01","interpreter":"python3","script":"import sys; print(sys.argv[1:])","args":["a b","c"]}}}
```

### 9.9 Hand a task to the local LLM (`agent`)

`--mcp-tools agent` adds `list_llm_profiles()` - the profiles' names and
models and which one is active, never a key, an endpoint or a host - and
`run_llm_agent(task, llm_profile?, groups?, max_steps?)` (the former
argument name `profile` still works):
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
  class; `axross/tasks/cancel` stops it after the model request in flight.
* The API key comes from the keyring and never appears in a result or
  a log line.

### 9.10 Android devices (`adb`)

`--mcp-tools remote,adb` adds 20 tools for an Android device that is open
as an ADB profile (`open_remote_profile`: TCP to the phone's `adb tcpip`
port, USB, or the adb server of this computer). Every adb tool takes its
backend id, and it is required: `backend: "profile:phone"`. The tools that
change the device or the MCP root are there with `--mcp-write` only. `all`
does not include the group (since 0.15.184): name it, `--mcp-tools all,adb`.

| Tool | What it does | What Android allows |
|---|---|---|
| `get_device_info` | maker, model, Android version, SDK, security patch, build, ABIs, serial, IMEI / MEID, the shell's uid | the build properties everywhere; the IMEI only where the phone service answers the shell, or a vendor property holds it (Luhn checked), else null with the reason |
| `list_device_properties` | `getprop`, filtered by a glob | everywhere |
| `get_battery_status` | charge, state, health, temperature, voltage | everywhere; `simulated` when `dumpsys battery set` overrides it |
| `list_apps`, `get_app_info` | packages with version, uid, installer, system / user, enabled; one app's versions, times, flags, APK paths and permissions | everywhere (older `pm` options fall back) |
| `list_running_apps` | apps with a process, their pids and memory, the one in front | `ps -A` (a plain `ps` before Android 8) |
| `get_logcat` | the newest log lines by priority, tag or app | everywhere; by app only on Android 7 and newer |
| `take_screenshot` | the screen as an image (with `out` and `--mcp-write`: a new PNG in the root) | secure windows show black |
| `list_sms` | `content://sms` by box, newest first, paged | only where the shell has READ_SMS (not on many builds) |
| `start_app` / `stop_app` | the launcher activity (the monkey where Android cannot resolve it) / `am force-stop` | everywhere |
| `install_app` / `uninstall_app` | an `.apk` from the MCP root via `/data/local/tmp` (removed again) / `pm uninstall` | the phone may refuse: another signature, a downgrade, installs over USB off (Xiaomi), a very old target SDK; system apps are refused |
| `export_app` | an app's APK files (base and splits) into a folder of the MCP root | everywhere |
| `grant_permission` / `revoke_permission` | `pm grant` / `pm revoke` of a runtime permission, read back | runtime and development permissions only |
| `reboot_device` | into Android, recovery or the bootloader | most builds let the shell reboot |
| `write_sms` | a message into the inbox, sent or drafts, read back | since Android 4.4 only the default SMS app writes the store; the shell's write is dropped silently unless its app-op WRITE_SMS is allowed - the tool reads back and says so |
| `compose_sms` | opens the SMS app with number and text | never sends by itself: a person taps Send |
| `send_at_command` | one AT command to the modem, a reply of at most 4 KiB, 1-30 s | only where a modem node exists and root opens it (`adb root`, `su`) |

Guards:

* **Commands are argument lists**, each argument quoted for the device's
  `sh`; an argument with a control character other than a tab is refused,
  and so is a command line over 16 KiB. Package, activity and permission
  names, property filters, log tags, phone numbers, SMS boxes, AT commands
  (no `;`) and modem nodes are checked against narrow patterns first.
* **Answers are untrusted text:** control, bidi and other invisible
  characters (U+061C, U+2060–U+206F, the tag characters) are dropped,
  every field and list is capped, numbers are read as ASCII digits only.
  Where an app's own text can imitate an answer's lines (its versionName
  in `dumpsys package`), `get_app_info` says `consistent: false` instead
  of trusting the copy.
* **The APK** of `install_app` is opened through the confined root: no
  `..`, no symbolic link, no second hard link, a regular ZIP of at most
  4 GiB; it is sent from the opened file, cut at the size checked (a file
  that grows meanwhile is refused), and its copy in `/data/local/tmp` is
  removed also when the push or the install fails.
* **Production profiles and the paranoid mode:** the tools that change
  the device are refused on a profile flagged production and in the
  paranoid security mode; the reading ones work.
* **Audit:** every changing call writes `attempt` and `ok` or `refused`
  with the backend, the package and the permission - never an SMS text,
  a phone number or an AT command (its SHA-256 prefix and length only).
* **Time:** every call has a deadline; no command starts once it has
  passed, and `notifications/cancelled` stops one between two commands.
* `run_llm_agent` gets none of these tools; the GUI's agent neither.
