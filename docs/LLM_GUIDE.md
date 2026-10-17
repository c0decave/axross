# axross for LLM agents

How a language model drives axross correctly: through the MCP server
(the tools below) or, where the operator allows it, through Python
scripts that use the `axross.*` API. [MCP.md](MCP.md) is the full
reference for the server; this guide is the short path to using it
right. The tool catalog (§11) is generated from
[`mcp-tools.json`](mcp-tools.json) and the scripting catalog (§12) from
[`scripting-api.json`](scripting-api.json); tests hold both files
against the code.

---

## 1. What the operator decides, not you

Every capability is switched on by a start flag. If a tool is missing
from `tools/list`, it was not enabled — ask the operator; there is no
way around it from the client side.

| Flag | Adds |
|---|---|
| *(none)* | The read-only file tools of the default backend (group `core`). |
| `--mcp-write` (needs `--mcp-root DIR`) | The write tools (group `write`) and the mutating tools of every enabled group. |
| `--mcp-tools GROUP[,…]` or `all` | Capability groups: metadata, duplicates, packer, archive, crypto, index, filetype, transfer, remote, agent, extensions — and exec, which `all` leaves out. |
| `--mcp-allow-exec` | The `exec` group: commands and scripts on remote hosts. |
| `--mcp-tools agent` | `agent_run`: hand a task to the user's own local LLM, which reads with axross' tools and changes nothing. |
| `--mcp-allow-scripts` (stdio only) | The script tools: saved Python scripts with the `axross.*` API, run as the server's user. |

The `paranoid` security mode refuses `--mcp-allow-scripts`,
`--mcp-allow-exec` and the legacy protocols (FTP, Telnet, TFTP, rsh, …).
`axross --mcp-list-tools <flags>` prints exactly what a start with
those flags would serve.

## 2. First calls

1. `initialize`, then `tools/list`. Every tool has a strict JSON schema
   (`additionalProperties: false`): send only the arguments it lists.
2. `list_backends` — the backends you can address. The default is the
   local file system, confined to `--mcp-root`.
3. With the `remote` group: `remote_profiles` lists the operator's
   saved connections and says per profile whether it can be opened
   (`openable`, and `reason` when not); `remote_open` connects one.
4. With the `exec` group: `exec_backends` lists the opened backends that
   can run commands and of which kind.

## 3. Paths and backends

- **Paths are absolute** on the backend they belong to: `/home/me/data/a.txt`
  locally; on a remote profile `/` is the top of what the profile
  shows (on S3 the profile's bucket).
- **`backend` picks the target.** Omit it for the default backend; pass
  an id from `list_backends` (`local`, `profile:<name>`) for any other.
  An unknown id is `-32602`.
- **The MCP root confines the local file system only.** A local path
  outside `--mcp-root` — also through a symlink — is refused. A remote
  profile reaches what its server lets that account reach.
- **Explore before you act**: `list_dir("/")` on a fresh profile,
  `stat` before a large `read_file`.
- **Profiles flagged production are read-only** over MCP: every
  mutation on them — and every command of the `exec` group — is refused.
- **Credentials never pass through you.** `remote_open` uses the
  password the operator stored in the keyring; a profile that needs a
  password that is not stored, an SSH host key that is not yet trusted,
  or a browser sign-in (OneDrive, SharePoint, Google Drive, Dropbox) is
  refused with a message that says so. Ask the operator to connect it
  once in the GUI. Never ask the user to paste a password into the chat.

## 4. Reading and writing files

- `read_file` returns `{content_b64, size, truncated}`: content is
  Base64, at most 4 MiB per call (`max_bytes` lowers it). For a text
  file pass `encoding: "text"` and get `{text, size, truncated,
  replaced}` instead (UTF-8; `replaced` tells that undecodable bytes
  were replaced, so the file is not plain text). When `truncated` is
  true there is more; use `checksum` to identify a file without reading
  it.
- `write_file` takes `content` (UTF-8 text) or `content_b64` (Base64
  bytes) — exactly one — and replaces the file, atomically
  where the backend allows it (one upload on object stores, a temporary
  sibling renamed into place elsewhere); a backend without rename
  (TFTP) is written directly.
- Group tools never overwrite: archives, extracted folders, decrypted
  files and exports get a fresh name (`bundle (2).zip`, `x-1`), which
  the result reports. Use the path from the result, not the one you
  expected.
- Some backends cannot do everything (`remove` on TFTP, any write on
  POP3 or Cisco). The error says so; do not retry the same call.

## 5. Long work

- Calls have a wall-clock limit by class (`quick` 15 s … `long`
  1800 s; the catalog lists each tool's). A call over it fails with
  `-32002`.
- For whole trees and big files use `tasks/start` (same arguments as
  `tools/call`), then poll `tasks/status` and stop with `tasks/cancel`.
  On stdio this is the only way to cancel a running job.
- Calls are rate-limited (`-32001`): back off and retry later, do not
  loop.

## 6. Errors

| Code | Meaning | What to do |
|---|---|---|
| `-32602` | Your arguments were wrong: schema, a bad value, a refused path shape, an unknown backend. The message starts with `tool '<name>' rejected args:`. | Fix the arguments. |
| `-32603` | The operation failed: the backend raised (`data.type` names the exception: `FileNotFoundError`, `PermissionError`, `OSError`, …), a root escape, a refused profile, a cancelled call. The message starts with `tool '<name>' failed:`. | Read the message. A `PermissionError` is a decision — do not try to route around it. |
| `-32601` | Unknown method or tool, or a capability that is switched off. | Check `tools/list`. |
| `-32001` | Rate limit or too many running tasks. | Wait, then retry. |
| `-32002` | The tool ran out of time. | Narrow the request or use `tasks/start`. |

## 7. Commands on remote hosts (`exec`)

- `remote_exec` returns `{returncode, stdout, stderr, truncated_stdout,
  truncated_stderr}`. A non-zero `returncode` is a result, not an
  error — read `stderr`. Telnet and ADB deliver stderr inside `stdout`.
- `remote_script` sends a script on stdin to `sh` (default), `bash`,
  `python3` or `perl`, with `args` quoted after it; prefer it to
  building a long quoted one-liner. WinRM hosts take PowerShell
  (`interpreter: "powershell"`, no `args`); Cisco devices take no
  scripts.
- `env` sets variables for the command (names `[A-Za-z_][A-Za-z0-9_]*`).
- Cisco runs `show` commands only; output modifiers that write to flash
  (`| redirect`, `| tee`, `| append`, `>`) are refused, the filters
  (`| include`, `| exclude`, `| begin`, `| section`, `| count`) work.
- The audit log records that a command ran (backend, length, a hash) —
  not what it was. Commands still run with the profile's rights:
  state what a command will change before you run it.

## 8. Delegating to the user's local model (`--mcp-tools agent`)

- `agent_run(task)` hands a task to the user's own LLM (the active
  profile of the axross GUI, or `profile`). It reads with axross' tools
  inside the MCP root (plus the read-only tools of `groups`) and returns
  `{answer, stopped, calls, profile, model}`.
- Use it to keep file content on the user's machine — summarising
  documents, finding something in a folder — and to save your own
  context. It cannot change anything; do changes yourself or ask the
  user to use the Agent dock.
- It is slow (a local model, `max_steps` requests) and can be wrong:
  check what matters.

## 9. Python scripts (`--mcp-allow-scripts`)

A script reaches what no tool does: every backend through
`axross.open_url`, the per-protocol helpers (databases, mail, LDAP, SNMP,
remote shells) and many steps in one call. It runs as the server's user,
in its own process, with nobody to answer a question.

### 9.1 First steps

1. `script_api_schema` with `names: []`: the index — `rules`, `errors`,
   `groups` (every function and class by topic), the session methods and
   `legend` (what each field means). Then `script_api_schema` with the
   names you plan to call: whole docstring, parameters with defaults,
   `examples`, `raises`, `mutates` (can change something), `prompts` (can
   need a human) and the types they return. Without a server, the same
   data is [`scripting-api.json`](scripting-api.json); §12 is its compact
   catalog.
2. `script_write(name, source)` saves the script, `script_run(name, args,
   timeout_s)` runs it: `args` become `sys.argv[1:]`.
3. Read the reply: `exit` (the `sys.exit` value; negative: stopped by a
   signal), `stdout`, `stderr`, `timed_out` and, after an uncaught
   exception, `error_type`, `error` and `traceback`.

### 9.2 A script that reports to a machine

```python
import json
import sys

import axross

root = sys.argv[1] if len(sys.argv) > 1 else "/"
with axross.open("backup-server") as b:          # closed again, also after an error
    entries = [
        {"path": b.join(root, e.name), "size": e.size, "dir": e.is_dir}
        for e in b.list_dir(root)                 # e.name is a name, not a path
    ]
print(json.dumps(entries, default=str))           # one JSON document on stdout
```

### 9.3 Idioms

- **Open**: `axross.open(name)` for a saved profile (`axross.list_profiles()`
  names them); `axross.open_url(url)` for any backend by URL — the only
  way to the backends without a profile: `ldap://`, `postgres://host/db`,
  `mongodb://`, `redis://`, `git+https://host/repo.git`, `rsh://`,
  `exchange://`, `wmi://`, `slp://`, `sqlite://`. `axross.localfs()` is
  the local file system, `axross.ramfs()` a scratch space in memory.
- **Read**: `axross.read_text(b, path)` and `axross.read_bytes(b, path)`
  read at most 64 MiB unless `max_bytes` says otherwise; stream anything
  bigger with `with b.open_read(path) as fh:`.
- **Walk**: `axross.find_files(b, root, ext="log")` yields every file
  below `root` (its `name` is the full path); `axross.summarize(b, path)`
  gives the gist of a folder without listing it all.
- **Write and copy**: `axross.write_text(b, path, text)`,
  `axross.copy(src_b, src, dst_b, dst)` and `axross.move(...)` refuse an
  existing target; pass `overwrite=True` only when replacing is the task.
  For big or flaky transfers use `axross.resumable_copy`.
- **Delete**: `axross.preview_delete(b, [path])` first, then
  `axross.remove(b, path, confirm=True)` or the restorable
  `axross.trash(b, path, confirm=True)` — only for a delete the operator
  asked for.
- **Compare**: `axross.hash_file(b, path)` returns the bare hex digest of
  the algorithm you name on every backend; `axross.checksum` may answer
  with the backend's own fingerprint (`md5:…` or `s3-etag:…` on S3) —
  compare the prefix first.
- **Commands**: `axross.exec(b, cmd)` on an SSH or SCP session returns an
  `ExecResult`; `.check()` raises `OSError` on a non-zero exit. Quote
  arguments with `shlex.quote`.
- **SQLite URLs follow the SQLAlchemy convention:** `sqlite:///data.db`
  is relative to the current directory, `sqlite:////srv/data.db` (four
  slashes) is the absolute path `/srv/data.db`.

### 9.4 Pitfalls

- **The session methods skip the guards.** `b.remove`, `b.rename` and
  `b.open_write` neither refuse an existing target nor ask for
  `confirm=True` nor wait for the production countdown; the `axross.*`
  helpers do. Change files through the helpers.
- **Nobody answers.** `script_run` sets `AXROSS_NONINTERACTIVE=1` and an
  empty stdin: `axross.confirm()` raises `NonInteractiveError` unless the
  script passes `assume_yes=True` — pass it only for an action the
  operator asked for — and a change on a profile flagged production is
  refused unless the operator started axross with
  `AXROSS_TARPIT_DISABLE=1`. `axross.is_interactive()` tells which case a
  script is in.
- **Paths follow the session.** Most sessions use `/`; `axross.localfs()`
  follows the host and WinRM and WMI sessions use `\`. Join with
  `b.join` and `b.parent`, not `os.path`.
- **Wrong kind of session.** The per-protocol helpers (`axross.exec`,
  `axross.query`, `axross.imap_search`, …) raise `TypeError` on a session
  of another protocol. `copy`, `symlink` and `hardlink` exist on some
  sessions only: test `hasattr(b, "copy")` and the `supports_symlinks`
  attribute first.
- **Output is bounded.** `stdout` and `stderr` have a size limit (see
  `script_run` in §11); a script that prints more is stopped. Aggregate
  before printing.

### 9.5 Errors in a script

Catch the narrow class first — `NonInteractiveError` is a
`PermissionError`, which is an `OSError`:

```python
try:
    axross.write_text(b, path, text)
except FileExistsError:
    ...                               # the target exists: another path, or overwrite=True
except axross.NonInteractiveError:
    ...                               # needs a human: report it, do not work around it
except PermissionError:
    ...                               # refused (server, confirm=, security mode)
except OSError as exc:
    ...                               # I/O failed or the session cannot do it
```

The table in §12 says what each exception means. A refusal is a
decision: report it instead of retrying another way.

## 10. Do and don't

- **Do** read `tools/list` and `list_backends` before guessing names or
  ids.
- **Do** keep reads bounded (`max_bytes`, `max_entries`, `max_depth`)
  and check `truncated`.
- **Do** report what you changed: the paths from the results, the
  commands you ran.
- **Don't** retry a refused call with a changed path or backend to get
  around a guard (root, production flag, paranoid mode).
- **Don't** put secrets into arguments that are not marked as secret
  (passphrases and archive passwords are; command lines are not).
- **Don't** assume a write replaced a file in place on a group tool —
  they write fresh names.

---

## 11. Tool catalog

<!-- BEGIN GENERATED TOOL CATALOG (python -m core.llm_guide) -->

55 tools in 15 sets, from `docs/mcp-tools.json` (generated for `--mcp-tools agent,archive,crypto,duplicates,exec,extensions,filetype,index,metadata,packer,remote,transfer --mcp-write --mcp-allow-scripts --mcp-allow-exec`). A tool marked *backend* takes the optional `backend` argument (an id from `list_backends`; omit it for the default backend).

Timeout classes: `quick` 15 s, `preview` 30 s, `write` 30 s, `walk` 60 s, `stream` 300 s, `script` 610 s, `long` 1800 s.

### `core`

File tools of the configured backend; always on, read-only.

#### `list_dir` — read-only · quick (15 s) · stdio + http · *backend*

List entries in a directory on the configured backend.

- `path` (string, required): Absolute path on the backend.

#### `stat` — read-only · quick (15 s) · stdio + http · *backend*

Return name, type, size, and mtime for one path.

- `path` (string, required)

#### `read_file` — read-only · quick (15 s) · stdio + http · *backend*

Read up to max_bytes (default 4 MiB) from a file. Returns {content_b64, size, truncated} - or with encoding='text' {text, size, truncated, replaced}: UTF-8, undecodable bytes replaced (replaced=true). truncated=true when the file exceeds the cap.

- `path` (string, required)
- `encoding` (string, one of `base64`, `text`, default `"base64"`): base64 (exact bytes) or text (UTF-8, for text files).
- `max_bytes` (integer, >= 0)

#### `checksum` — read-only · stream (300 s) · stdio + http · *backend*

Content hash of a file. Tries the backend's native fingerprint first (S3 ETag, Drive md5Checksum, ssh sha256sum, etc.); falls back to streaming the file through hashlib when the backend has no cheap hash. The streaming fallback emits MCP progress notifications every few MiB when the caller supplied _meta.progressToken, and stops within one chunk of a notifications/cancelled. algorithm must be one of sha256 / sha1 / md5 / sha512 — backend-specific hash names (etag, dropbox, quickxor) are rejected.

- `path` (string, required)
- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`)

#### `search` — read-only · quick (15 s) · stdio + http · *backend*

Search the offline metadata index by name substring, extension, and size range. Free of network round-trips.

- `ext` (string)
- `max_size` (integer, >= 0)
- `min_size` (integer, >= 0)
- `needle` (string)

#### `walk` — read-only · walk (60 s) · stdio + http · *backend*

Breadth-first recursive listing under path. Caps at max_depth (default 4) and max_entries (default 1000). Emits MCP progress notifications when the caller supplied _meta.progressToken.

- `path` (string, required)
- `max_depth` (integer, >= 0)
- `max_entries` (integer, >= 1)

#### `recursive_checksum` — read-only · stream (300 s) · stdio + http · *backend*

Hash every file under path breadth-first. Each record is either {path, size, algorithm, checksum, source} (hashed), {path, size, algorithm, skipped: "too-large"} (file above max_file_bytes), or {path, size, algorithm, error: "<msg>"} (backend refused that one file). Emits one progress notification per hashed file; a notifications/cancelled lands within one chunk of the current file. algorithm is one of sha256 / sha1 / md5 / sha512. Defaults: max_files=500, max_depth=10, max_file_bytes=1 GiB. If path names a file instead of a directory the result contains exactly one record.

- `path` (string, required)
- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`)
- `max_depth` (integer, >= 0)
- `max_file_bytes` (integer, >= 1)
- `max_files` (integer, >= 1)

#### `preview` — read-only · preview (30 s) · stdio + http · *backend*

Render a thumbnail of an image file. Returns MCP image content (base64 + mimeType). edge (default 256) is clamped to [16, 2048]. MIME allow-list + size/dimension caps from core.previews apply. Local backends only.

- `path` (string, required)
- `edge` (integer, 16..2048)

#### `grep` — read-only · walk (60 s) · stdio + http · *backend*

Regex search inside file contents under a root path. Recurses up to max_depth (default 2); skips files larger than 4 MiB. Returns up to max_matches (default 100, ceiling 500) {path, line_no, line}. Cooperates with notifications/cancelled.

- `pattern` (string, required)
- `max_depth` (integer, >= 0)
- `max_matches` (integer, >= 1)
- `path` (string)

#### `list_versions` — read-only · quick (15 s) · stdio + http · *backend*

List historical versions of a file (S3 ObjectVersions, Dropbox revisions, GDrive revision-history, Azure blob snapshots, WebDAV DeltaV, Git: one per commit that changed the file). Empty list on backends with no native versioning.

- `path` (string, required)

#### `open_version_read` — read-only · quick (15 s) · stdio + http · *backend*

Read a specific historical version of a file. Same max_bytes cap (default 4 MiB) as read_file. version_id comes from list_versions.

- `path` (string, required)
- `version_id` (string, required)
- `max_bytes` (integer, >= 0)

### `write`

Write tools; only with --mcp-write, which needs --mcp-root.

#### `write_file` — mutating · write (30 s) · stdio + http · *backend*

Overwrite a file with content (UTF-8 text) or content_b64 (base64 bytes) - exactly one of them. Returns {size}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `path` (string, required)
- `content` (string): The new content as UTF-8 text.
- `content_b64` (string): The new content as base64 bytes.

#### `mkdir` — mutating · write (30 s) · stdio + http · *backend*

Create a directory on the backend.

Needs: `--mcp-write` `--mcp-root DIR`.

- `path` (string, required)

#### `remove` — mutating · write (30 s) · stdio + http · *backend*

Delete a file or directory.

Needs: `--mcp-write` `--mcp-root DIR`.

- `path` (string, required)
- `recursive` (boolean)

#### `rename` — mutating · write (30 s) · stdio + http · *backend*

Move/rename a file or directory. Both src and dst must live under the configured root.

Needs: `--mcp-write` `--mcp-root DIR`.

- `dst` (string, required)
- `src` (string, required)

#### `copy` — mutating · write (30 s) · stdio + http · *backend*

Server-side copy of src to dst. Uses the backend's native copy primitive (S3 CopyObject, WebDAV COPY, shell cp) where available — no client-side streaming.

Needs: `--mcp-write` `--mcp-root DIR`.

- `dst` (string, required)
- `src` (string, required)

#### `bulk_copy` — mutating · stream (300 s) · stdio + http · *backend*

Copy a file OR directory tree from src into dst. Per-file records: {src, dst, size, action} where action is "copied", "skipped" (reason: "too-large", "exists", "unsafe-name", or "max-depth" for a folder below max_depth), or "error" (folder: true for a folder that could not be listed). "truncated" is true when max_files or max_depth cut the walk; "complete" is true only when every file was copied or already existed. Emits one progress notification per copied file; a notifications/cancelled stops within one file. Defaults: max_files=1000, max_depth=10, max_file_bytes=10 GiB, overwrite=false. Missing dst parent directories are created automatically. Same-backend only in V1 — cross-backend copy is handled by the transfer manager, not the MCP surface.

Needs: `--mcp-write` `--mcp-root DIR`.

- `dst` (string, required)
- `src` (string, required)
- `max_depth` (integer, >= 0)
- `max_file_bytes` (integer, >= 1)
- `max_files` (integer, >= 1)
- `overwrite` (boolean)

#### `symlink` — mutating · write (30 s) · stdio + http · *backend*

Create a symbolic link. target may point anywhere the backend permits (dangling links are allowed); link_path is capped to the MCP root. Raises on backends without symlink support (S3, cloud stores).

Needs: `--mcp-write` `--mcp-root DIR`.

- `link_path` (string, required)
- `target` (string, required)

#### `hardlink` — mutating · write (30 s) · stdio + http · *backend*

Create a hard link (second name for the same inode). Cross-device errors surface as the backend's OSError. Most protocols refuse — POSIX/SSH only.

Needs: `--mcp-write` `--mcp-root DIR`.

- `link_path` (string, required)
- `target` (string, required)

#### `chmod` — mutating · write (30 s) · stdio + http · *backend*

Change POSIX mode bits. Accepts integer (420 for 0o644) or octal-string ("0o644" / "644"). Backends without POSIX bits (S3, WebDAV, etc.) raise.

Needs: `--mcp-write` `--mcp-root DIR`.

- `mode` (any, required)
- `path` (string, required)

### `scripts`

Saved-script tools; only with --mcp-allow-scripts, stdio only, not confined to the MCP root; refused in the paranoid security mode.

#### `script_list` — read-only · quick (15 s) · stdio

Names of every saved Python script in the server's script directory (~/.config/axross/scripts/).

Needs: `--mcp-allow-scripts`.

#### `script_api_schema` — read-only · quick (15 s) · stdio

Describe the ``axross`` scripting API that script_run gives a script, as JSON built from the live code: rules and errors (the conventions and exceptions a script meets), groups (the names by topic), per public function its signature, parameters with types and defaults, return type, whole docstring, examples, ``raises``, ``mutates`` (can change files, remote state or settings) and ``prompts`` (needs a human: under script_run it raises NonInteractiveError unless the script opts in, e.g. confirm(assume_yes=True)); the public classes; the types the API returns (FileItem, results) with fields and methods; the methods every backend session has (with close() and the with statement); and a legend of every field. Same data as axross.api_schema(names) and docs/scripting-api.json. The whole API is large: call it with names=[] for the index, then with the names you need.

Needs: `--mcp-allow-scripts`.

- `names` (array of string): Only these functions, classes and types, plus the types they use; [] gives the index alone. Default: everything.

#### `script_read` — read-only · quick (15 s) · stdio

Read the source of a saved script by name. Names are [A-Za-z0-9_-]+; the path is built relative to the server's script directory.

Needs: `--mcp-allow-scripts`.

- `name` (string, required)

#### `script_write` — mutating · quick (15 s) · stdio

Save Python source as ``<name>.py`` (mode 0600) in the server's script directory. Overwrites any existing script with the same name.

Needs: `--mcp-allow-scripts`.

- `name` (string, required)
- `source` (string, required)

#### `script_delete` — mutating · quick (15 s) · stdio

Remove a saved script by name. Idempotent — no error when the file is already gone.

Needs: `--mcp-allow-scripts`.

- `name` (string, required)

#### `script_run` — mutating · script (610 s) · stdio

Run a saved script in its own Python process with ``axross`` (the scripting API; see script_api_schema) in its namespace. stdin is empty, so input() gets EOF and axross.confirm() raises NonInteractiveError unless the script passes assume_yes=True. ``args`` become sys.argv[1:]. The run is stopped after ``timeout_s`` seconds, with every process it started. Returns {name, exit, timed_out, duration_ms, stdout, stderr, namespace_keys} and, after an uncaught exception, error_type, error and traceback; exit follows SystemExit (None is 0, an int is itself, anything else is printed and gives 1) and is the negative signal number of a stopped run. stdout and stderr hold up to 1048576 characters each; more stops the run and fails the call.

Needs: `--mcp-allow-scripts`.

- `name` (string, required)
- `args` (array of string): The script's sys.argv[1:]. Default: none.
- `timeout_s` (number, <= 600.0): Wall-clock limit in seconds. Default: 60.

### `agent`

Hand a task to the user's own LLM (the active profile of the axross GUI): it works with the read-only tools inside the MCP root and answers; it can change nothing.

#### `agent_run` — read-only · long (1800 s) · stdio + http

Hand a task to the user's own LLM (the active LLM profile of the axross GUI, or 'profile'). It works with axross' read-only tools inside the MCP root - plus the read-only tools of 'groups' - and returns {answer, stopped, calls, profile, model}. It cannot change files or run commands. Use it to keep file content on the user's machine, e.g. to summarise documents with a local model.

Needs: `--mcp-tools agent`.

- `task` (string, required): What the local model should do, in plain language.
- `groups` (array of string): Extra tool groups the model may use (read-only tools only).
- `max_steps` (integer, default `10`, 1..30): Most model requests for this task.
- `profile` (string): An LLM profile name; default: the active one.

### `archive`

List an archive's members; extract it into a fresh folder (mutating).

#### `archive_list` — read-only · walk (60 s) · stdio + http · *backend*

List an archive's members without extracting anything: {path, total, truncated, entries: [{name, size (uncompressed), compressed, mtime, is_dir}]}. Local backend only.

Needs: `--mcp-tools archive`.

- `path` (string, required): Archive file (zip family, tar.*, 7z, rar, gz/bz2/xz/zst) on the local backend.
- `max_entries` (integer, default `1000`, 1..10000): Return at most this many entries.

#### `archive_extract` — mutating · long (1800 s) · stdio + http · *backend*

Extract an archive into a new folder named after it inside dest_dir (default: the archive's folder): 'x.zip' -> 'x', then 'x-1', … - an existing folder is never written into. Zip-slip, absolute paths, links, more than 10,000 entries, more than 1 GiB or a compression ratio above 100 are refused and nothing is left behind. Returns {path (the new folder), files}. Progress per file; cancellable (the partial folder is removed). Local backend only.

Needs: `--mcp-tools archive` `--mcp-write` `--mcp-root DIR`.

- `path` (string, required): Archive file (zip family, tar.*, 7z, rar, gz/bz2/xz/zst) on the local backend.
- `dest_dir` (string): Existing folder under the MCP root to extract into.

### `crypto`

Encrypt a file into the axross .axenc format and decrypt it again (mutating).

#### `encrypt` — mutating · stream (300 s) · stdio + http · *backend*

Encrypt a file (at most 1 GiB) into the axross encrypted-overlay format next to it: 'a.txt' -> 'a.txt.axenc', then 'a.txt (2).axenc' - nothing is overwritten. The plaintext stays in place, as in the GUI. Returns {path (the .axenc file), size, plaintext_size}.

Needs: `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR`.

- `passphrase` (string, required, secret, never echoed): Passphrase (PBKDF2-SHA256, 200,000 iterations, AES-256-GCM). Never logged or returned.
- `path` (string, required): File to encrypt.

#### `decrypt` — mutating · stream (300 s) · stdio + http · *backend*

Decrypt an .axenc file into a new file next to it: 'a.txt.axenc' -> 'a.txt', or 'a (2).txt' when that exists (a name without .axenc gets '.decrypted'); mode 0600, nothing is overwritten. A wrong passphrase or a tampered file fails with nothing written. Returns {path (the plaintext file), size}.

Needs: `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR`.

- `passphrase` (string, required, secret, never echoed): Passphrase (PBKDF2-SHA256, 200,000 iterations, AES-256-GCM). Never logged or returned.
- `path` (string, required): The .axenc file.

### `duplicates`

Duplicate Finder: scan a folder into the duplicate index, list scans and duplicate groups; dedupe to the axross trash (mutating, dry run by default).

#### `duplicates_scan` — read-only · long (1800 s) · stdio + http · *backend*

Hash every file under a folder into the Duplicate Finder's index (the same index the GUI uses), skipping symlinks and the axross trash; files whose size and mtime did not change are not hashed again unless rehash. Returns {scan_id, root, backend_id, algorithm, files_indexed, status}. One progress notification per file; cancellable (rows indexed so far are kept). Run it before duplicates_groups.

Needs: `--mcp-tools duplicates`.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`, default `"sha256"`): Hash algorithm.
- `path` (string): Folder; default: the MCP root (local backend).
- `rehash` (boolean, default `false`): Hash every file even when unchanged.

#### `duplicates_scans` — read-only · quick (15 s) · stdio + http · *backend*

The scan history of the addressed backend, newest first, limited to scans of folders inside the MCP root: {scans: [{scan_id, root, backend_id, algorithm, started_at, finished_at, files_indexed, files_in_index, duplicate_groups, status (complete|cancelled|failed|running), error}], truncated}.

Needs: `--mcp-tools duplicates`.

#### `duplicates_groups` — read-only · quick (15 s) · stdio + http · *backend*

Groups of identical files from the index, every copy inside path. Each group is {algorithm, value (hash), size, copies: [{path, size, mtime, scan_id, keep}]} in survivor order: the first copy (keep=true) is the oldest by mtime (ties: shorter, then alphabetically first path) and is what duplicates_dedupe keeps. The index is a record of the last scan; nothing is read from the files. Returns {path, groups, truncated}.

Needs: `--mcp-tools duplicates`.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`): Only groups hashed with this algorithm; omit for all.
- `max_groups` (integer, default `100`, 1..1000): Return at most this many groups.
- `path` (string): Folder; default: the MCP root (local backend).
- `scan_id` (integer, 0..2147483647): Only groups with at least one copy from this scan (duplicates_scans); 0 = rows from before scans were recorded.

#### `duplicates_dedupe` — mutating · long (1800 s) · stdio + http · *backend*

Keep the first copy of every duplicate group inside path and move the others to the axross trash (restorable; for the local backend the trash is <MCP root>/.axross-trash). A dry run unless dry_run=false: the dry run only returns the plan. A real run re-checks every copy on disk first: a copy that changed since the scan, or a group without another verified copy, is reported in refused and left alone. Returns {path, dry_run, groups, undated_groups, keep, trash, removed, refused: [{path, reason}], failed: [{path, reason}], trash_root}.

Needs: `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR`.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`): Only groups hashed with this algorithm; omit for all.
- `dry_run` (boolean, default `true`): true: only plan; false: move the planned copies to the trash.
- `path` (string): Folder; default: the MCP root (local backend).
- `scan_id` (integer, 0..2147483647): Only groups with at least one copy from this scan (duplicates_scans); 0 = rows from before scans were recorded.

### `exec`

Run commands and scripts on remote hosts over SSH, SCP, Telnet, rsh, ADB, WinRM (PowerShell) and Cisco (show commands only); only with --mcp-allow-exec (mutating), refused in the paranoid security mode and on production profiles.

#### `remote_exec` — mutating · long (1800 s) · stdio + http · *backend*

Run one command on a remote host (backend = an id from exec_backends) and return {returncode, stdout, stderr, truncated_stdout, truncated_stderr}. A non-zero exit is a result, not an error. Telnet and ADB deliver stderr inside stdout. Cisco: show commands only. WinRM: PowerShell.

Needs: `--mcp-tools exec` `--mcp-allow-exec`.

- `command` (string, required): The command line.
- `env` (object): Environment variables for the command (names [A-Za-z_][A-Za-z0-9_]*).
- `max_output` (integer, default `1048576`, 1..16777216): Bytes of stdout kept (stderr: at most 1 MiB); truncated_* tells when output was cut.
- `stdin` (string): Text fed to the command's stdin (not on WinRM/Cisco).
- `timeout` (integer, default `60`, 1..3600): Seconds before the command is given up.

#### `remote_script` — mutating · long (1800 s) · stdio + http · *backend*

Run a script on a remote host: POSIX hosts get it on stdin of sh, bash, python3 or perl with args after it; WinRM hosts run it as PowerShell. Same result as remote_exec.

Needs: `--mcp-tools exec` `--mcp-allow-exec`.

- `script` (string, required): The script text.
- `args` (array of string): Script arguments.
- `env` (object): Environment variables for the command (names [A-Za-z_][A-Za-z0-9_]*).
- `interpreter` (string, one of `bash`, `perl`, `powershell`, `python3`, `sh`): sh by default; powershell on WinRM.
- `max_output` (integer, default `1048576`, 1..16777216): Bytes of stdout kept (stderr: at most 1 MiB); truncated_* tells when output was cut.
- `timeout` (integer, default `60`, 1..3600): Seconds before the command is given up.

#### `exec_backends` — read-only · quick (15 s) · stdio + http

List the backends that can run commands: {backend, class, kind} with kind posix-shell, powershell or ios-show. Open more with remote_open.

Needs: `--mcp-tools exec` `--mcp-allow-exec`.

### `extensions`

List installed extensions and whether they are enabled (read-only: extensions are GUI plugins).

#### `extensions_list` — read-only · quick (15 s) · stdio + http

The installed extensions (user and bundled) and their state, read without importing any of them: {allowed (false in the paranoid security mode), runnable_over_mcp (always false), why_not_runnable, extensions: [{id ('user:<name>' or 'bundled:<name>'), name, version, description, author, source, enabled (switched on in Extensions > Manage Extensions), loadable, error, active (loaded by the GUI: enabled, loadable and allowed)}]}. Extensions are GUI plugins with no headless actions, so none can be run here.

Needs: `--mcp-tools extensions`.

#### `extensions_info` — read-only · quick (15 s) · stdio + http

One extension by id: {id ('user:<name>' or 'bundled:<name>'), name, version, description, author, source, enabled (switched on in Extensions > Manage Extensions), loadable, error, active (loaded by the GUI: enabled, loadable and allowed)} plus runnable_over_mcp and why_not_runnable.

Needs: `--mcp-tools extensions`.

- `ext_id` (string, required): Extension id from extensions_list.

### `filetype`

Identify files by content (magic bytes), flag extension mismatches.

#### `file_type` — read-only · quick (15 s) · stdio + http · *backend*

Identify one file by its content (magic bytes), not its name, and say whether the extension matches. Returns {path, name, kind (file|directory|special|error|timeout|cancelled), description, mime (from the content), extension, extension_mime (what the name claims), verdict (match|mismatch|unknown), mismatch (bool), size, encoding, line_endings, engine, file_command, bytes_read, error}. Never fails for an unreadable file: kind is then error or timeout with error set.

Needs: `--mcp-tools filetype`.

- `path` (string, required): File to identify.
- `max_bytes` (integer, default `65536`, 1..1048576): Read at most this many bytes per file.
- `use_file_command` (boolean, default `true`): Also ask file(1) for its description (local files only).

#### `file_type_scan` — read-only · stream (300 s) · stdio + http · *backend*

Identify every file under a folder (breadth-first, symlinks skipped). Returns {path, files_scanned, truncated, entries: [{path, name, kind (file|directory|special|error|timeout|cancelled), description, mime (from the content), extension, extension_mime (what the name claims), verdict (match|mismatch|unknown), mismatch (bool), size, encoding, line_endings, engine, file_command, bytes_read, error}]}; with mismatches_only only files whose content contradicts their extension are listed. One progress notification per file; honours cancellation.

Needs: `--mcp-tools filetype`.

- `path` (string, required): Folder to scan.
- `max_bytes` (integer, default `65536`, 1..1048576): Read at most this many bytes per file.
- `max_depth` (integer, default `2`, 0..50): Subfolder levels to descend (0: the folder itself only).
- `max_files` (integer, default `500`, 1..5000): Stop after this many files (truncated=true).
- `mismatches_only` (boolean, default `false`): List only files whose content does not match the extension.
- `use_file_command` (boolean, default `true`): Also ask file(1) for its description (local files only).

### `index`

Build or refresh the offline metadata index that the search tool reads.

#### `index_build` — read-only · long (1800 s) · stdio + http · *backend*

Walk a folder and record every entry (name, size, type, mtime) in the offline metadata index that the search tool reads - the same index as the GUI's metadata search. Additive; prune=true also drops index rows under the folder whose file no longer exists. Returns {path, backend_id, recursive, indexed, pruned}. One progress notification per entry; cancellable (what was indexed is kept).

Needs: `--mcp-tools index`.

- `path` (string): Folder; default: the MCP root (local backend).
- `prune` (boolean, default `false`): Also drop rows of files under the folder that are gone.
- `recursive` (boolean, default `true`): Descend into subfolders.

### `metadata`

Show and export file metadata (EXIF/XMP/IPTC, Office, PDF, media tags); remove it (mutating, writes a cleaned copy).

#### `metadata_read` — read-only · stream (300 s) · stdio + http · *backend*

Read the metadata of a file or of every supported file in a folder: images (JPEG/PNG/WebP/GIF/TIFF), Office (docx/xlsx/pptx/odt/ods/odp), PDF, audio/video (ffprobe). Returns {path, is_dir, truncated, files: [{path, name, kind, size, error, truncated, removable_count, fields: [{group, name, value, removable}]}]}}. An unsupported or unreadable file is a report with error set, not a failure. Values are length-bounded. Local paths are confined to the MCP root.

Needs: `--mcp-tools metadata`.

- `path` (string, required): A file, or a folder whose supported files are used.
- `max_files` (integer, default `200`, 1..2000): For a folder: at most this many files (truncated=true when cut).
- `recursive` (boolean, default `false`): For a folder: descend into subfolders.

#### `metadata_export` — read-only · stream (300 s) · stdio + http · *backend*

The metadata_read data of a file or folder as one text in JSON or CSV. Returns {path, format, files, truncated, text}.

Needs: `--mcp-tools metadata`.

- `path` (string, required): A file, or a folder whose supported files are used.
- `format` (string, one of `json`, `csv`, default `"json"`): json: {"files": [...]}; csv: one row per field, formula-safe.
- `max_files` (integer, default `200`, 1..2000): For a folder: at most this many files (truncated=true when cut).
- `recursive` (boolean, default `false`): For a folder: descend into subfolders.

#### `metadata_export_file` — mutating · stream (300 s) · stdio + http · *backend*

Write the metadata_export text of path into the new file out (under the MCP root, mode 0600). An existing file is never overwritten: 'meta.json' becomes 'meta (2).json'. Returns {path (the file written), format, files, truncated, size}.

Needs: `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR`.

- `out` (string, required): File to create.
- `path` (string, required): A file, or a folder whose supported files are used.
- `format` (string, one of `json`, `csv`, default `"json"`): json: {"files": [...]}; csv: one row per field, formula-safe.
- `max_files` (integer, default `200`, 1..2000): For a folder: at most this many files (truncated=true when cut).
- `recursive` (boolean, default `false`): For a folder: descend into subfolders.

#### `metadata_remove` — mutating · long (1800 s) · stdio + http · *backend*

Remove the metadata of a file, or of every supported file in a folder, by writing a cleaned copy next to each ('photo.jpg' -> 'photo.clean.jpg', then 'photo.clean (1).jpg'); the original is never modified and nothing is overwritten. Images keep orientation and colour profile, pixels are not re-encoded. PDF removal needs pypdf, audio/video needs ffmpeg (both blocked in the paranoid security mode). Returns {path, mode: 'copy', truncated, results: [{path, status (cleaned|unchanged|unsupported|error), output, removed, error, note, sha256}]}.

Needs: `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR`.

- `path` (string, required): A file, or a folder whose supported files are used.
- `max_files` (integer, default `200`, 1..2000): For a folder: at most this many files (truncated=true when cut).
- `recursive` (boolean, default `false`): For a folder: descend into subfolders.

### `packer`

List archive formats; pack files and folders into zip / tar.* / 7z / single-file compression, 7z optionally AES-256 encrypted (mutating).

#### `pack_formats` — read-only · quick (15 s) · stdio + http

The archive formats pack can write and whether each is usable here: {formats: [{format, label, suffix, single (exactly one file in), encrypts (takes a password), available, reason}], levels}.

Needs: `--mcp-tools packer`.

#### `pack` — mutating · long (1800 s) · stdio + http · *backend*

Pack entries of folder into a new archive folder/archive_name + suffix. Folders are packed recursively; symbolic links are skipped and listed in skipped, never followed. The archive is written to a temporary file first and an existing archive is never overwritten: 'bundle.zip' becomes 'bundle (2).zip'. Only 7z takes a password (AES-256; encrypt_names also hides the file list); ZIP and tar refuse one. Single-file formats (gz, bz2, xz, zst) take exactly one file. Returns {path, format, files, folders, bytes_in, bytes_out, skipped, encrypted}. One progress notification per file; cancellable (nothing is left behind).

Needs: `--mcp-tools packer` `--mcp-write` `--mcp-root DIR`.

- `archive_name` (string, required): Archive file name without directory; the format's suffix is added when missing.
- `folder` (string, required): Folder holding the entries; the archive is created here.
- `names` (array of string, required): Names of files or folders directly inside folder (no path separators, no repeats).
- `encrypt_names` (boolean, default `true`): 7z with password: also encrypt the file list.
- `format` (string, one of `zip`, `tar.gz`, `tar.zst`, `tar.xz`, `tar.bz2`, `7z`, `gz`, `zst`, `xz`, `bz2`, default `"zip"`): Archive format (see pack_formats).
- `level` (string, one of `fast`, `normal`, `best`, default `"normal"`): Compression level.
- `password` (string, secret, never echoed): 7z only: encrypt with AES-256. Never logged or returned.

### `remote`

List saved connection profiles (no secrets), open one as an extra backend that every tool can address with its backend argument, close it again.

#### `remote_profiles` — read-only · quick (15 s) · stdio + http

The saved connection profiles, without any secret: {profiles: [{name, protocol, host, port, username, auth_type, store_password, production, open_as (backend id when opened in this session, else null), openable, reason (why remote_open would refuse, else empty)}]}.

Needs: `--mcp-tools remote`.

#### `remote_open` — read-only · walk (60 s) · stdio + http

Connect a saved profile and register it as backend 'profile:<name>' for this session; every other tool then reaches it with backend='profile:<name>'. Credentials come from the keyring when the profile stores them; a profile that would need a prompt (password not stored, SSH host key not yet trusted, browser sign-in) fails with an error instead. --mcp-root does not apply to remote paths. Writing needs --mcp-write, and a production-flagged profile stays read-only. Returns {backend, profile, protocol, class, production, writable, reused}.

Needs: `--mcp-tools remote`.

- `profile` (string, required): Profile name.

#### `remote_close` — read-only · quick (15 s) · stdio + http · *backend*

Disconnect a profile opened with remote_open in this session. Returns {backend, closed}.

Needs: `--mcp-tools remote`.

#### `list_backends` — read-only · quick (15 s) · stdio + http

List the backend ids: {id, class, name, is_default, remote} per backend; a profile opened with remote_open adds profile, protocol and production. Pass the id via the ``backend`` argument on any other tool to route that call to that backend.

Needs: `--mcp-tools remote`.

### `transfer`

Copy or move files and folders between backends, optionally resumable (mutating).

#### `transfer_copy` — mutating · long (1800 s) · stdio + http

Copy a file or a folder tree from one backend to another (or within one). Local paths are confined to the MCP root, remote ones are not. Existing destination files are skipped unless overwrite; symlinks are skipped; missing destination folders are created. resumable=true copies each file in 4 MiB segments with a local manifest: a cancelled or failed run continues where it stopped when called again with the same arguments. Returns {src, dst, copied, truncated, entries: [{src, dst, size, action (copied|skipped|error), reason, bytes, resumed_segments, error}]}. Progress per file; cancellable.

Needs: `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR`.

- `dst` (string, required): Destination path on dst_backend (the file, or the folder that becomes the copy of a source folder).
- `src` (string, required): Source path on src_backend.
- `dst_backend` (string, default `"local"`): Backend id of the destination.
- `max_depth` (integer, default `10`, 0..50): Subfolder levels to descend.
- `max_file_bytes` (integer, default `10737418240`, 1..1125899906842624): Skip files above this size (reason too-large).
- `max_files` (integer, default `1000`, 1..10000): Copy at most this many files (truncated=true).
- `overwrite` (boolean, default `false`): Replace existing destination files.
- `resumable` (boolean, default `false`): Segmented copy that can continue after an interruption.
- `src_backend` (string, default `"local"`): Backend id of the source (list_backends); 'local' is the local file system under the MCP root.

#### `transfer_move` — mutating · long (1800 s) · stdio + http

Move one file to another backend (copy, then delete the source; the copy is removed again if the source cannot be deleted) or within one backend (rename). An existing destination is refused. Returns {src, dst, bytes}.

Needs: `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR`.

- `dst` (string, required): Destination path on dst_backend (the file, or the folder that becomes the copy of a source folder).
- `src` (string, required): Source path on src_backend.
- `dst_backend` (string, default `"local"`): Backend id of the destination.
- `src_backend` (string, default `"local"`): Backend id of the source (list_backends); 'local' is the local file system under the MCP root.

<!-- END GENERATED TOOL CATALOG -->

---

## 12. Scripting catalog

<!-- BEGIN GENERATED SCRIPTING CATALOG (python -m core.llm_guide) -->

111 functions, 11 classes, 29 session members and 34 further types, from `docs/scripting-api.json` (schema version 2). Each line: signature, then whether the call can change something, whether it can need a human, and what the axross layer raises itself; then the first paragraph of its docstring. The manifest has the whole docstring, the examples and the parameters.

### Rules

- **namespace**: A script run by script_run, axross --script or the Scripts dock finds the API bound as axross; import axross gives the same names.
- **sessions**: open(profile_name), open_url(url), localfs() and ramfs() return a session b with the backend_protocol methods. Open it in a with block: leaving the block ends the connection, also after an exception; b.close() does the same by hand.
- **paths**: Paths are absolute strings in the session's own syntax. Most sessions use '/'; localfs() uses the host's separator and WinRM and WMI sessions use '\'. Build paths with b.join() and b.parent() rather than os.path, which follows the host.
- **listing**: b.list_dir(path) returns a list of FileItem and b.stat(path) one FileItem (see types): name is the entry's name inside the directory, not a path - join it to the directory; modified is naive local time; is_dir and is_link give the kind. find_files(b, root, ...) walks a tree and yields the files as FileItem whose name is the full path; it skips folders it cannot read.
- **helpers-before-session-methods**: Change files with the axross.* helpers, not the raw session methods. copy, move, write_bytes, write_text and encrypt refuse an existing target unless overwrite=True (move across backends refuses it even then); remove and trash refuse without confirm=True; write_bytes writes atomically where the backend allows it; copy, move, remove, trash, write_bytes, write_text, dedupe and remove_metadata wait for the production countdown on a profile flagged production. b.remove(), b.rename(), b.open_write() and the other session methods do none of this.
- **no-human**: Under script_run nobody can answer: stdin is empty and AXROSS_NONINTERACTIVE=1 is set. A function with prompts=true raises NonInteractiveError (a PermissionError) instead of asking: confirm() unless assume_yes=True is passed, and a change on a production profile unless the operator started axross with AXROSS_TARPIT_DISABLE=1. is_interactive() tells a script which case it is in. Pass assume_yes=True only for an action the operator asked for.
- **bounded-reads**: read_bytes() and read_text() read at most 67108864 (64 MiB) bytes unless max_bytes says otherwise, and raise OSError above it. Stream bigger files: with b.open_read(path) as fh: then fh.read(chunk_size) in a loop.
- **handles**: b.open_read() and b.open_write() return file handles the caller must close: use them in a with block. b.open_write() has none of write_bytes()'s checks.
- **checksums**: checksum(b, path) returns the backend's fingerprint marked with its algorithm ('sha256:<hex>', 'md5:<hex>', 's3-etag:<etag>', ...), which may not be the algorithm asked for: compare the prefix before the value. hash_file(b, path, algorithm) always streams and returns the bare hex digest of that algorithm - use it to compare files across backends.
- **wrong-session-kind**: Per-protocol helpers (exec, interactive_shell, query, tables, imap_search, ldap_search, share, ...) raise TypeError on a session of another kind.
- **output**: print() goes to stdout, which script_run returns with stderr, the exit status and, after an uncaught exception, error_type, error and traceback. Print a result a machine reads as one JSON document; sys.exit(n) sets the exit status.

### Errors

| Exception | Base | Meaning | What to do |
|---|---|---|---|
| `OSError` | `Exception` | An I/O operation failed or the session cannot do it: protocol error, connection lost, an operation the backend does not support, a read above max_bytes. The subclasses below say more. | Read the message. Do not repeat the same call unchanged. |
| `FileNotFoundError` | `OSError` | The path does not exist on that session. | List the parent directory and check the path. |
| `FileExistsError` | `OSError` | The target exists and overwrite=False (copy, move, write_bytes, write_text, encrypt). | Choose another path, or pass overwrite=True only when replacing it is intended. |
| `IsADirectoryError` | `OSError` | A file operation got a folder (for example metadata() on a directory). | Use the folder variant the message names. |
| `PermissionError` | `OSError` | A refusal: the server denied access, remove() or trash() was called without confirm=True, or the security mode blocks the feature. | Do not route around it. confirm=True is for deletes the operator asked for. |
| `NonInteractiveError` | `PermissionError` | The call needs a human and none can answer: confirm() without assume_yes=True, or a change on a production profile. | Pass assume_yes=True only for what the operator asked for; production changes need the operator. |
| `KeyError` | `LookupError` | open() got a profile name that is not saved, or docs() an unknown topic. | list_profiles() gives the saved names. |
| `TypeError` | `Exception` | The session is the wrong kind for the helper (exec() on S3, query() on a session that is no database) or an argument has the wrong type. | Check the session's protocol and the signature. |
| `ValueError` | `Exception` | An argument value is invalid: an unknown URL scheme, a port out of range, a script name outside [A-Za-z0-9_-], an unknown mode or format. | Fix the argument; the message names it. |
| `KeyboardInterrupt` | `BaseException` | Someone stopped the production countdown before a change. | Do not repeat the change. |

### Open / connect

- `axross.open(profile_name: str, password: str | None = None, key_passphrase: str | None = None) -> FileBackend` — read-only · prompts (NonInteractiveError without a human) · raises KeyError. Open a backend by saved profile name. Returns a FileBackend session. Raises :class:`KeyError` if the profile doesn't exist and :class:`OSError` for connection failure.
- `axross.open_url(url: str, **kwargs: Any) -> FileBackend` — read-only · prompts (NonInteractiveError without a human) · raises TypeError, ValueError. Open a backend from a URL like ``sftp://user@host/``, ``s3://bucket``, ``smb://server/share``, ``gopher://host:70``.
- `axross.localfs() -> LocalFS` — read-only. Return a LocalFS session pointed at the host's filesystem.
- `axross.ramfs(max_bytes: int | None = None) -> RamFsSession` — read-only. Return a fresh RamFS session — bytes never touch disk. ``max_bytes`` overrides the default per-instance cap.
- `axross.list_profiles() -> list[str]` — read-only. Return the names of all saved connection profiles.
- `axross.get_profile(name: str) -> ConnectionProfile | None` — read-only. Look up a saved :class:`ConnectionProfile` by name.
- `axross.save_profile(profile: ConnectionProfile) -> None` — mutates. Persist a :class:`core.profiles.ConnectionProfile`. The profile object itself can be constructed via ``ConnectionProfile(name=..., protocol=..., host=...)`` — see ``help(core.profiles.ConnectionProfile)``.
- `axross.delete_profile(name: str) -> None` — mutates. Delete a saved profile by name. No-op if the profile doesn't exist.
- `axross.list_backends() -> list[str]` — read-only. Return the protocol IDs of every registered backend (sftp, smb, s3, …) regardless of whether the optional dependency is installed. Use :func:`available_backends` for the installed subset.
- `axross.available_backends() -> list[str]` — read-only. Return the protocol IDs of backends whose dependencies are actually installed.

### File I/O

- `axross.copy(src_backend: FileBackend, src_path: str, dst_backend: FileBackend, dst_path: str, buffer_size: int = 1048576, *, overwrite: bool = False) -> int` — mutates · prompts (NonInteractiveError without a human) · raises FileExistsError, OSError. Copy bytes from one backend to another. Returns the number of bytes transferred. Same-backend copies use the backend's native ``copy()`` if available; cross-backend copies always stream.
- `axross.move(src_backend: FileBackend, src_path: str, dst_backend: FileBackend, dst_path: str, *, overwrite: bool = False) -> int` — mutates · prompts (NonInteractiveError without a human) · raises FileExistsError, OSError. Move a file from one backend to another. Same-backend uses rename; cross-backend uses copy + delete-source.
- `axross.remove(backend: FileBackend, path: str, *, recursive: bool = False, confirm: bool = False) -> str` — mutates · prompts (NonInteractiveError without a human) · raises PermissionError. Delete ``path`` from ``backend`` after an explicit opt-in.
- `axross.trash(backend: FileBackend, path: str, *, root: str | None = None, confirm: bool = False) -> str` — mutates · prompts (NonInteractiveError without a human) · raises PermissionError. Move ``path`` to Axross trash after an explicit opt-in.
- `axross.read_bytes(backend: FileBackend, path: str, *, max_bytes: int | None = 67108864) -> bytes` — read-only · raises OSError, ValueError. Read a file into memory.
- `axross.write_bytes(backend: FileBackend, path: str, data: bytes, *, overwrite: bool = False) -> int` — mutates · prompts (NonInteractiveError without a human) · raises FileExistsError, OSError. Write ``data`` to ``path`` on ``backend``. Returns bytes written.
- `axross.read_text(backend: FileBackend, path: str, encoding: str = 'utf-8', *, max_bytes: int | None = 67108864) -> str` — read-only · raises OSError, ValueError. Read an entire file as text. Decodes the bytes via ``encoding`` with ``errors="replace"`` so a stray non-UTF-8 byte never raises; use :func:`read_bytes` when you need exact-bytes round-trip.
- `axross.write_text(backend: FileBackend, path: str, text: str, encoding: str = 'utf-8', *, overwrite: bool = False) -> int` — mutates · prompts (NonInteractiveError without a human) · raises FileExistsError, OSError. Write a UTF-8 text file. Convenience wrapper around :func:`write_bytes` — encodes ``text`` and forwards. Returns the number of bytes written. Existing destinations are refused unless ``overwrite=True`` is passed.
- `axross.checksum(backend: FileBackend, path: str, algorithm: str = 'sha256') -> str` — read-only. Return the backend's content fingerprint for ``path``. Falls back to a streaming hash when the backend has no cheap server-side checksum.
- `axross.hash_bytes(data: bytes, algorithm: str = 'sha256') -> str` — read-only. Hex digest of ``data`` under ``algorithm`` (anything :mod:`hashlib.new` accepts: sha1, sha256, sha512, md5, …).
- `axross.hash_file(backend: FileBackend, path: str, algorithm: str = 'sha256', chunk_size: int = 1048576) -> str` — read-only. Streaming hex digest of a backend-side file. Same as :func:`checksum` but never tries to use a server-side fingerprint — use this when you specifically want algorithm parity across different backends.

### Encryption + archives

- `axross.encrypt(backend: FileBackend, path: str, passphrase: str, keep_original: bool = True, *, overwrite: bool = False) -> str` — mutates · raises FileExistsError, OSError, ValueError. Encrypt ``path`` with the axross encrypted-overlay format and write the ciphertext to ``<path>.axenc``. Returns the new path.
- `axross.decrypt(backend: FileBackend, path: str, passphrase: str) -> bytes` — read-only. Read and decrypt an .axenc file. Returns the plaintext bytes — the caller decides where to put them (write_bytes to disk, hand them to a parser, etc.).
- `axross.extract_archive(local_path: str, dst_dir: str, progress: Callable[[int, int, str], None] | None = None) -> str` — mutates. Extract a local archive (zip / tar / 7z) to ``dst_dir``. Returns the destination directory after the extract. Refuses zip-bombs and zip-slip via the same guards used by the file-manager UI.
- `axross.is_archive(path: str) -> bool` — read-only. True when ``path`` looks like a zip / tar / 7z by extension.

### Bookmarks + scripts

- `axross.list_bookmarks() -> list` — read-only. Return all saved bookmarks (list of :class:`Bookmark`).
- `axross.add_bookmark(name: str, path: str, backend_name: str = 'Local', profile_name: str = '', icon_name: str = 'bookmark') -> None` — mutates. Create a new bookmark. Idempotent on (path, backend_name).
- `axross.remove_bookmark(index: int) -> None` — mutates. Remove the bookmark at ``index`` (zero-based).
- `axross.script_dir() -> str` — read-only · raises OSError. Return the script-storage directory path. Created on first access. Mode 0700 so other local users can't read scripts that might contain credentials.
- `axross.list_scripts() -> list[str]` — read-only · raises OSError. Names of every saved script in :func:`script_dir`.
- `axross.save_script(name: str, source: str) -> str` — mutates · raises OSError, ValueError. Write ``source`` to ``script_dir()/<name>.py`` (mode 0o600). Overwrites any existing file with the same name. Returns the final on-disk path.
- `axross.load_script(name: str) -> str` — read-only · raises OSError, ValueError. Read the source of a saved script as a UTF-8 string. Raises ``FileNotFoundError`` when the script doesn't exist; ``ValueError`` when the name contains characters outside the allow-list.
- `axross.delete_script(name: str) -> None` — mutates · raises OSError, ValueError. Remove a saved script. No-op if the file is already gone.
- `axross.run_script(name: str, env: dict | None = None) -> dict` — mutates · prompts (NonInteractiveError without a human) · raises OSError, ValueError. Execute a saved script in a fresh namespace pre-populated with ``axross`` (this module). Returns the post-exec namespace so the caller can inspect any variables it left behind. ``env`` overrides / augments the initial namespace.

### Per-protocol

- `axross.find_tftp_files(backend: FileBackend, wordlist: list[str] | str | None = None, on_progress: Callable[[str, int, int], None] | None = None) -> list[FileItem]` — read-only. Walk ``backend.find_files()`` (TFTP wordlist scan). The backend must be a :class:`TftpSession`; raises :class:`AttributeError` otherwise.
- `axross.slp_discover(host: str, scope: str = 'DEFAULT', port: int = 427, use_tcp: bool = False) -> dict` — read-only. One-shot SLPv2 discover: returns ``{service_type: [(url, ttl)]}`` for everything the daemon at ``host`` advertises in ``scope``. Pure read; no SrvReg path is ever exercised (CVE-2023-29552 mitigation).
- `axross.nntp_post(backend: FileBackend, group: str, subject: str, body: str, author: str = 'axross <noreply@axross>') -> None` — mutates · raises ValueError. Post a fully-formed article to ``group`` on ``backend`` (an :class:`NntpSession`). Builds a minimal RFC 5322 envelope around ``subject`` + ``body``; for richer headers, hand the writer a pre-built bytes payload via ``backend.open_write(...)``.
- `axross.git_push(backend: FileBackend, branch: str | None = None) -> None` — mutates. Push committed work on ``backend`` (a :class:`GitFsSession`) to its origin. Raises :class:`GitForceRefused` on non-fast-forward. Pass ``branch=None`` to push every branch the session has touched.
- `axross.exec(backend: FileBackend, cmd: str, *, timeout: float | None = 30.0, stdin: bytes | str | None = None, stdout_cap: int = 1048576, stderr_cap: int = 65536, env: dict[str, str] | None = None) -> ExecResult` — mutates · raises TypeError. Run a shell command on a remote backend. Returns :class:`models.exec_result.ExecResult` with ``returncode``, ``stdout``, ``stderr`` and the corresponding ``truncated_*`` flags.
- `axross.interactive_shell(backend: FileBackend, *, term: str = 'xterm-256color', cols: int = 80, rows: int = 24, env: dict[str, str] | None = None) -> InteractiveShell` — mutates · raises TypeError. Open an interactive shell on the same SSH transport ``backend`` is already using. Multiplexing — file ops on ``backend`` keep working while the shell is open. Returns a :class:`models.interactive_shell.InteractiveShell` wrapper with ``read`` / ``write`` / ``read_until`` / ``resize_pty`` / ``close`` / ``interact`` / iter-as-lines.
- `axross.query(backend: FileBackend, sql_or_args: str, *args: Any, **kwargs: Any) -> list[dict]` — mutates · raises TypeError. Generic database-query dispatch. Calls ``backend.query()`` for SQL backends (SQLite / Postgres) or ``backend.find()`` for Mongo when ``sql_or_args`` looks like a collection name + filter dict.
- `axross.tables(backend: FileBackend) -> list[str]` — read-only · raises TypeError. Return every table (SQLite/Postgres) or collection (Mongo) on ``backend``. Wraps the per-backend method of the same name.
- `axross.imap_search(backend: FileBackend, criteria: str = 'ALL', *, mailbox: str = 'INBOX') -> list` — read-only · raises TypeError. Wrapper around message-backend search. For IMAP this returns the list of UIDs matching an IMAP search expression (RFC 3501); for Exchange it returns the backend's lightweight message dicts:
- `axross.imap_move(backend: FileBackend, uid: int, src_mailbox: str, dst_mailbox: str) -> None` — mutates · raises TypeError. Move an IMAP message by UID. Uses MOVE if the server supports it, COPY+\Deleted+EXPUNGE otherwise. See ``ImapSession.move``.
- `axross.imap_set_flags(backend: FileBackend, uid: int, flags: list[str], *, mailbox: str = 'INBOX', mode: str = 'set') -> None` — mutates · raises TypeError. STORE flags on an IMAP message by UID. ``mode`` is ``set`` / ``add`` / ``remove``.
- `axross.share(backend: FileBackend, path: str, **kwargs: Any) -> str` — mutates · raises TypeError. Create a shareable link for ``path`` on a cloud backend that supports it. Dispatches to:
- `axross.ldap_search(backend: FileBackend, base_dn: str, filter: str = '(objectClass=*)', *, scope: str = 'subtree', attributes: list[str] | None = None, limit: int = 1000) -> list[dict]` — read-only · raises TypeError. Run a raw LDAP search via the connected ``LdapFsSession``. Returns up to ``limit`` entries as dicts ``{dn, attributes}``:

### Network helpers

- `axross.dns_resolve(host: str, family: str = 'any') -> list[str]` — read-only. Return the IPs ``host`` resolves to. ``family`` is ``"v4"``, ``"v6"``, or ``"any"``.
- `axross.dns_records(name: str, rtype: str = 'A', *, resolver: str | None = None, timeout: float = 3.0) -> list[str]` — read-only · raises OSError. Return DNS records of ``rtype`` for ``name``. Uses ``dnspython`` so we get TXT/MX/SRV/CAA/NAPTR records in addition to the basic A / AAAA / CNAME / NS / PTR.
- `axross.dns_reverse(ip: str, *, resolver: str | None = None, timeout: float = 3.0) -> list[str]` — read-only · raises OSError. PTR lookup for an IP. Returns a list (most addresses have at most one PTR but the protocol allows multiple).
- `axross.port_open(host: str, port: int, timeout: float = 3.0) -> bool` — read-only. ``True`` if a TCP connect to ``host:port`` succeeds within ``timeout`` seconds. Useful for lab-up probes in scripts.
- `axross.port_scan(host: str, ports: Iterable[int], *, timeout: float = 1.0, concurrency: int = 64) -> list[int]` — read-only · raises ValueError. Concurrent TCP-connect scan. Returns the sorted list of ports that accepted a connection within ``timeout``.
- `axross.subnet_hosts(cidr: str) -> list[str]` — read-only · raises ValueError. Iterate every usable host in ``cidr`` (e.g. ``"10.0.0.0/29"``). Returns a list of IP strings — for /29 that's 6 addresses, for /24 it's 254. Refuses ranges larger than /16 to prevent the user from accidentally enumerating 65k addresses they didn't mean to.
- `axross.tcp_banner(host: str, port: int, *, timeout: float = 3.0, max_bytes: int = 4096, send: bytes | None = None) -> bytes` — read-only. Connect to ``host:port`` and read up to ``max_bytes`` of the server's initial response. Useful for service-ID probes (SSH, FTP, SMTP, IMAP all greet with a banner).
- `axross.tls_cert(host: str, port: int = 443, *, timeout: float = 5.0, sni: str | None = None, verify: bool = False) -> TlsCert` — read-only · raises OSError. TLS handshake against ``host:port`` and return the parsed leaf certificate.
- `axross.ssh_hostkey(host: str, port: int = 22, *, timeout: float = 5.0) -> SshHostKey` — read-only. Connect, complete the SSH KEX, fetch the server's host key and return its fingerprints. NO authentication is attempted.
- `axross.http_probe(url: str, *, method: str = 'GET', headers: dict[str, str] | None = None, body: bytes | str | None = None, timeout: float = 10.0, allow_redirects: bool = True, body_cap: int = 1048576, raw_cap: int | None = None, verify: bool = True) -> HttpProbe` — read-only · raises OSError, ValueError. Lightweight HTTP/HTTPS probe via ``requests``. Returns the response status, headers, body (up to ``body_cap``), redirect chain, and the TLS leaf cert when applicable.
- `axross.snmp_get(host: str, oid: str, *, community: str = 'public', port: int = 161, timeout: float = 3.0, retries: int = 1, user: str | None = None, auth_key: str | None = None, priv_key: str | None = None, auth_proto: str | None = None, priv_proto: str | None = None) -> SnmpVar` — read-only · raises OSError. Issue a single SNMP GET request. Returns one ``SnmpVar`` for the OID. Raises ``OSError`` on transport failure.
- `axross.snmp_walk(host: str, base_oid: str, *, community: str = 'public', port: int = 161, timeout: float = 3.0, retries: int = 1, max_vars: int = 10000, user: str | None = None, auth_key: str | None = None, priv_key: str | None = None, auth_proto: str | None = None, priv_proto: str | None = None) -> list[SnmpVar]` — read-only · raises OSError. Walk an OID subtree, returning every leaf as an ``SnmpVar``. ``max_vars`` caps the result at a sane number — a walk of ``1.3`` on a packed device returns thousands of varbinds.
- `axross.snmp_set(host: str, oid: str, value: Any, *, value_type: str = 'OctetString', community: str = 'private', port: int = 161, timeout: float = 3.0, retries: int = 1) -> SnmpVar` — mutates · raises OSError, ValueError. Issue an SNMP SET. ``value_type`` is the pysnmp type-class name (``OctetString`` / ``Integer`` / ``Counter32`` / …).
- `axross.ping(host: str, *, port: int = 80, timeout: float = 3.0, count: int = 1) -> list[PingResult]` — read-only. TCP-based reachability probe — connect to ``host:port`` and measure RTT. Returns one ``PingResult`` per ``count`` attempt.
- `axross.mac_lookup(mac: str) -> OuiInfo` — read-only · raises OSError, ValueError. Look up the IEEE OUI vendor for a MAC address.
- `axross.whois(query: str, *, timeout: float = 5.0) -> WhoisInfo` — read-only · raises NotImplementedError, OSError. RIR / ASN / registrar lookup.
- `axross.time_skew(host: str, *, source: str = 'http', port: int | None = None, timeout: float = 5.0, verify_tls: bool = False) -> TimeSkew` — read-only · raises NotImplementedError, OSError, ValueError. Measure clock drift of ``host`` vs. the local clock.

### Search across backends

- `axross.find_files(backend: FileBackend, path: str, *, pattern: str | None = None, ext: str | None = None, mtime_after: datetime | None = None, mtime_before: datetime | None = None, size_min: int | None = None, size_max: int | None = None, max_depth: int | None = None, follow_links: bool = False) -> Iterator` — read-only · raises TypeError. Recursive walk of ``backend`` rooted at ``path``, filtered by every non-None criterion. Yields :class:`models.file_item.FileItem`.
- `axross.grep(backend: FileBackend, path: str, pattern: str, *, max_size: int = 10485760, max_matches: int = 100, ignore_case: bool = False, binary: bool = False) -> list[GrepHit]` — read-only · raises OSError, TypeError. Search ``backend:path`` for ``pattern`` (a regex). Returns up to ``max_matches`` hits.
- `axross.diff_files(b1: FileBackend, p1: str, b2: FileBackend, p2: str, *, max_bytes: int = 10485760, n_context: int = 3) -> list[str]` — read-only · raises ValueError. Unified diff of two files, possibly on different backends. Returns a list of diff lines (incl. ``--- / +++`` headers). Empty list = no difference.

### Duplicate index

- `axross.duplicate_scans() -> list[ScanRecord]` — read-only. Return the Duplicate Finder's scan history, newest first.
- `axross.duplicates(*, scan: ScanRecord | int | None = None, folder: str | None = None, algorithm: str | None = None) -> list[list[CasEntry]]` — read-only. Return the duplicate groups of the Duplicate Finder's index.
- `axross.dedupe(*, keep: str = 'oldest', dry_run: bool = True, scan: ScanRecord | int | None = None, folder: str | None = None, algorithm: str | None = None, backends: list[FileBackend] | None = None) -> DedupeResult` — mutates · prompts (NonInteractiveError without a human) · raises ValueError. Keep the first copy of every duplicate group, trash the others.

### Content inspection

- `axross.file_type(backend: FileBackend | str | os.PathLike[str], path: str | None = None, *, max_bytes: int = 65536, timeout: float = 15.0, use_file_command: bool = True) -> FileTypeInfo` — read-only · raises TypeError. Identify a file's real type from its content (magic bytes), not its name.
- `axross.magic_type(data: bytes, *, default: str = 'application/octet-stream') -> str` — read-only · raises OSError. Detect file type by magic bytes. Returns the MIME type if recognised, ``default`` otherwise. Uses pure-Python ``puremagic`` so no libmagic dep is needed at runtime.
- `axross.text_encoding(data: bytes, *, sample_bytes: int = 65536) -> dict` — read-only · raises OSError. Guess the text encoding of ``data``. Returns a dict:
- `axross.entropy(data: bytes, *, base: int = 2) -> float` — read-only. Shannon entropy of ``data`` in bits/byte (when ``base=2``).
- `axross.archive_inspect(path: str, *, max_entries: int = 100000) -> list[ArchiveEntry]` — read-only · raises OSError, ValueError. List the entries inside ``path`` without extracting. Detects the archive type by extension first (``.zip`` / ``.tar*`` / ``.7z``) and falls through to magic-byte sniffing for unknown suffixes.

### File metadata

- `axross.metadata(backend: FileBackend, path: str) -> MetadataReport` — read-only · raises IsADirectoryError. Return the metadata of one file as a ``MetadataReport``.
- `axross.remove_metadata(backend: FileBackend, path: str, *, mode: str | None = None, recursive: bool = False) -> list` — mutates · prompts (NonInteractiveError without a human) · raises FileNotFoundError, ValueError. Remove the metadata of a file, or of every supported file in a folder.
- `axross.export_metadata(backend: FileBackend, root: str, *, fmt: str = 'json', recursive: bool = False, out: str | None = None) -> str` — mutates · raises ValueError. Return the metadata of a file or of every supported file in a folder, as JSON (``{"files": [...]}``) or CSV (one row per field).

### Safety + diagnostics

- `axross.diagnose(backend: FileBackend, *, root: str | None = None, write_test: bool = False) -> str` — mutates. Run live diagnostics against an open backend and return a plain-text report.
- `axross.preview_delete(backend: FileBackend, paths: list[str], *, max_entries: int = 10000) -> str` — read-only. Preview a delete/trash operation before executing it.
- `axross.preview_transfer(source_backend: FileBackend, dest_backend: FileBackend, source_paths: list[str], dest_dir: str, *, operation: str = 'copy', max_entries: int = 10000) -> str` — read-only. Preview a copy/move before queueing it.
- `axross.recovery_scan(backend: FileBackend, root: str | None = None) -> str` — read-only. Scan a backend location for recoverable temp/trash items and return a plain-text report.
- `axross.recent_operations(limit: int = 20) -> list[dict]` — read-only. Return recent operation-journal events: secrets redacted, paths as they are on disk (undo needs them).
- `axross.security_mode(name: str | None = None) -> str` — mutates. Get or set the runtime security mode.

### Credential testing (authorised use only)

- `axross.bruteforce(profile: ConnectionProfile | str, *, users: Iterable[str], passwords: Iterable[str], rate_per_min: float = 30.0, timeout_per_attempt: float = 10.0, abort_on_lockout: bool = True, abort_after_n_lockouts: int = 1, abort_after_n_failures: int | None = None, max_attempts: int | None = None, stop_on_first_success_per_user: bool = True, progress: Callable[[AttemptOutcome], None] | None = None, on_unknown_host: Callable[[object], bool] | None = None, state_file: str | os.PathLike[str] | None = None, dry_run: bool = False, jitter_s: float = 0.0, authorized: bool = False) -> AttackReport` — mutates. Run a brute-force credential test in user-major order against a saved profile (name or :class:`ConnectionProfile`).
- `axross.spray(profile: ConnectionProfile | str, *, users: Iterable[str], password: str | None = None, passwords: Iterable[str] | None = None, rate_per_min: float = 30.0, timeout_per_attempt: float = 10.0, abort_on_lockout: bool = True, abort_after_n_lockouts: int = 1, max_attempts: int | None = None, stop_on_first_success_per_user: bool = True, progress: Callable[[AttemptOutcome], None] | None = None, on_unknown_host: Callable[[object], bool] | None = None, state_file: str | os.PathLike[str] | None = None, dry_run: bool = False, jitter_s: float = 0.0, authorized: bool = False) -> AttackReport` — mutates. Run a password spray in password-major order — the safer pattern for AD-style targets where lockout is per-user-per-window.
- `axross.enumerate_users(profile: ConnectionProfile | str, candidates: Iterable[str], *, method: str = 'auto', timeout_per_probe: float = 10.0, timing_samples: int = 5, rate_per_min: float = 30.0, jitter_s: float = 0.0, progress: Callable[[EnumResult], None] | None = None, on_unknown_host: Callable[[object], bool] | None = None, authorized: bool = False) -> EnumReport` — mutates. Probe whether each candidate username exists on the target.

### Multi-system workflow

- `axross.where_was_i(host: str | None = None) -> list[HostVisit] | HostVisit | None` — read-only. Look up the visit-history record(s).
- `axross.health_pulse() -> list[HealthRecord]` — read-only. Snapshot the live connection-health pulse for every enrolled session — last-probe latency, median latency, staleness flag.
- `axross.summarize(backend: FileBackend, path: str = '', *, max_entries: int = 2000) -> Summary` — read-only. One-paragraph synopsis of a directory: file/dir/link counts, extension histogram, age buckets, newest/oldest entries, top-5 largest files. Reads metadata only — no file contents are fetched.
- `axross.explain(backend: FileBackend, path: str = '') -> ExplainResult` — read-only. Heuristic best-guess "what IS this directory?" — git repo, PostgreSQL data dir, nginx config tree, k8s manifests, Maildir, web-server log dir, and friends. Returns the highest-confidence pattern match as a :class:`core.inspect.ExplainResult`, or an empty result if nothing scored above 0.2.
- `axross.compare_file(backends: list[FileBackend], path: str, *, content: bool = True, content_cap_bytes: int | None = None, parallelism: int = 8, per_target_timeout_s: float = 30.0) -> CompareReport` — read-only. Compare the SAME path across N backends in parallel.
- `axross.inspect_targets(targets: list[tuple[FileBackend, str]], *, content: bool = True, content_cap_bytes: int | None = None, parallelism: int = 8, per_target_timeout_s: float = 30.0) -> InspectReport` — read-only. Inspect a list of ``(backend, path)`` pairs in parallel.
- `axross.federated_search(backends: list[FileBackend], query: SearchQuery | None = None, *, name: str = '', regex: str = '', contains: str = '', contains_is_regex: bool = False, min_size: int = -1, max_size: int = -1, modified_after: float = 0.0, modified_before: float = 0.0, roots: list[str] | None = None, max_depth: int = 6, max_hits_per_backend: int = 500, max_hits_total: int = 5000, parallelism: int = 8, per_backend_timeout_s: float = 60.0, progress: Callable[[SearchHit], None] | None = None) -> SearchResult` — read-only. Run one search query against many backends in parallel.
- `axross.resumable_copy(src_backend: FileBackend, src_path: str, dst_backend: FileBackend, dst_path: str, *, segment_size: int = 4194304, manifest_path: str | os.PathLike[str] | None = None, overwrite: bool = False, progress: Callable[[int, int], None] | None = None) -> ResumeReport` — mutates. Cross-backend copy with checkpoint-resume.
- `axross.dashboard(*, with_capacity: bool = False, recent_ops_limit: int = 10, fmt: str = 'text', backends: list[FileBackend] | None = None) -> str` — read-only. Federation-status dashboard — one screen, every connection.

### Time-lapse / trail

- `axross.snapshot_now(backend: FileBackend, path: str, *, name: str = '', head_hash: bool = False, max_files: int = 5000) -> Snapshot` — mutates. Take a single time-lapse snapshot of a directory tree.
- `axross.start_trail(backend: FileBackend, path: str, *, name: str = '', interval_s: float = 300.0, head_hash: bool = False, max_files: int = 5000, on_snapshot: Callable[[Snapshot], None] | None = None) -> str` — mutates. Start a background trail — periodic snapshots until :func:`stop_trail` is called. Returns the trail name.
- `axross.stop_trail(name: str) -> bool` — mutates. Stop a named background trail. Returns True if one was found.
- `axross.list_trails() -> list[dict]` — read-only. List every recorded trail with its metadata.
- `axross.list_snapshots(trail_name: str, *, limit: int = 100) -> list[Snapshot]` — read-only. List the most recent snapshots of one trail (newest first).
- `axross.diff_snapshots(snapshot_a: int, snapshot_b: int) -> TrailDiff` — read-only. Compare snapshot A to snapshot B (B is the newer / target).

### Reverse-serve (expose a backend over S3 / WebDAV)

- `axross.serve_s3(backend: FileBackend, *, bind: str = '127.0.0.1', port: int = 9000, read_only: bool = False, auth_token: str | None = '', root_path: str = '/') -> ReverseServer` — mutates. Expose ``backend`` as a minimum-viable S3 endpoint so any existing S3 client (aws-cli / restic / rclone / terraform) can speak to it.
- `axross.serve_webdav(backend: FileBackend, *, bind: str = '127.0.0.1', port: int = 8080, read_only: bool = False, auth_token: str | None = '', root_path: str = '/') -> ReverseServer` — mutates. Expose ``backend`` as a minimum-viable WebDAV endpoint — ``davfs2 mount``, gnome-files (``davs://``), macOS Finder, browser read-only listings all work; they ask for the token as the password (any user name). Same token rules as :func:`serve_s3`. Returns a :class:`core.reverse_serve.ReverseServer`.

### Result types (dataclasses returned by helpers above)

- class `axross.TlsCert`
- class `axross.SshHostKey`
- class `axross.HttpProbe`
- class `axross.GrepHit`
- class `axross.SnmpVar`
- class `axross.ArchiveEntry`
- class `axross.PingResult`
- class `axross.OuiInfo`
- class `axross.WhoisInfo`
- class `axross.TimeSkew`

### UI helpers (REPL / scripts)

- `axross.message(text: str, *, title: str = 'axross', level: str = 'info') -> None` — read-only. Show a modal informational dialog with the given message.
- `axross.confirm(text: str, *, title: str = 'axross', default_yes: bool = False, assume_yes: bool = False) -> bool` — read-only · prompts (NonInteractiveError without a human). Show a Yes/No dialog. Returns True on Yes, False otherwise.
- `axross.toast(text: str, *, level: str = 'info', timeout: float = 4.0) -> None` — read-only. Non-modal toast in the bottom-right corner of the main window.
- `axross.is_interactive() -> bool` — read-only. True when a human can answer :func:`confirm` right now.
- class `axross.NonInteractiveError`

### Misc

- `axross.help() -> None` — read-only. Print the curated cheat-sheet of the scripting surface.
- `axross.docs(name: str | None = None) -> str` — read-only · raises KeyError. Return long-form documentation as Markdown.
- `axross.api_schema(names: list[str] | None = None) -> dict` — read-only · raises RuntimeError, ValueError. Describe the scripting API as JSON-serialisable data, for a machine.

### Session methods (`b` = what `open`, `open_url`, `localfs` and `ramfs` return)

- `b.checksum(path: str, algorithm: str = 'sha256') -> str` — read-only · without support: No cheap checksum: callers hash a full read themselves.. Return a hex-encoded checksum of the file's content.
- `b.chmod(path: str, mode: int) -> None` — mutates. Change file permissions. mode is octal (e.g. 0o755).
- `b.copy(src: str, dst: str) -> None` — mutates · only some sessions: test `hasattr(b, name)`. Server-side copy of *src* to *dst* within this backend.
- `b.disk_usage(path: str) -> tuple[int, int, int]` — read-only · without support: Not reported.. Return (total, used, free) bytes for the filesystem containing path. Returns (0, 0, 0) if not supported.
- `b.exists(path: str) -> bool` — read-only. Check if path exists.
- `b.hardlink(target: str, link_path: str) -> None` — mutates · only some sessions: test `hasattr(b, name)`. Create a hard link at *link_path* to the same inode as *target*. Raises :class:`OSError` on backends that don't model hardlinks. LocalFS overrides this.
- `b.home() -> str` — read-only. Return the home/default directory.
- `b.is_dir(path: str) -> bool` — read-only. Check if path is a directory.
- `b.join(*parts: str) -> str` — read-only. Join path components using this backend's separator.
- `b.list_dir(path: str) -> list[FileItem]` — read-only. List directory contents. Raises OSError on failure.
- `b.list_versions(path: str) -> list[FileVersion]` — read-only · without support: No versioning: an empty list.. Return historical versions of *path*, newest first.
- `b.mkdir(path: str) -> None` — mutates. Create a directory. Raises OSError on failure.
- `b.name` — read-only. Human-readable name for this backend (e.g. 'Local' or 'user@host').
- `b.normalize(path: str) -> str` — read-only. Normalize a path (resolve .., ., etc.).
- `b.open_read(path: str) -> IO[bytes]` — read-only. Open a file for reading. Caller must close the returned handle.
- `b.open_version_read(path: str, version_id: str) -> IO[bytes]` — read-only · without support: No versioning: raises OSError.. Open a historical version of *path* for streaming read.
- `b.open_write(path: str, append: bool = False) -> IO[bytes]` — mutates. Open a file for writing. Caller must close the returned handle.
- `b.parent(path: str) -> str` — read-only. Return the parent directory of the given path.
- `b.readlink(path: str) -> str` — read-only · without support: No symbolic links: raises OSError.. Read symlink target. Raises OSError if not a symlink.
- `b.remove(path: str, recursive: bool = False) -> None` — mutates. Remove a file or directory. If recursive=True, remove directory tree.
- `b.rename(src: str, dst: str) -> None` — mutates. Rename/move a file or directory.
- `b.separator() -> str` — read-only. Return the path separator for this backend.
- `b.stat(path: str) -> FileItem` — read-only. Get file/directory info. Raises OSError on failure.
- `b.supports_hardlinks` — read-only. True when this session can create hard links with hardlink(); read it with getattr(b, 'supports_hardlinks', False).
- `b.supports_symlinks` — read-only. True when this session can create symbolic links with symlink(); read it with getattr(b, 'supports_symlinks', False).
- `b.symlink(target: str, link_path: str) -> None` — mutates · only some sessions: test `hasattr(b, name)`. Create a symbolic link at *link_path* pointing to *target*.
- `b.close() -> None` — read-only. End the session: ``disconnect()`` when the class has one.
- `b.__enter__()` — read-only. Return the session itself: ``with axross.open(name) as b:``.
- `b.__exit__(exc_type, exc, tb) -> bool` — read-only. End the session when the ``with`` block is left, also after an exception, which is never swallowed.

### Types

- `axross.PingResult` (class, `core.net_helpers`): host, port, reachable, rtt_ms — Outcome of a TCP-ping. ``rtt_ms`` is ``None`` when the host didn't accept the connection within the timeout; otherwise it's the round-trip in milliseconds (connect-only, no full TLS/TCP handshake).
- `axross.OuiInfo` (class, `core.net_helpers`): mac, oui, vendor, vendor_long — OUI (Organisationally Unique Identifier) lookup result. ``vendor`` is the short name (``"VMware"``); ``vendor_long`` the full registry entry (``"VMware, Inc."``). Both ``None`` when the OUI isn't in the database.
- `axross.WhoisInfo` (class, `core.net_helpers`): query, kind, asn, asn_description, country, cidr, registry, raw — Result of a :func:`whois` lookup. ``kind`` is ``"ip"`` for address lookups (RIR / ASN data) or ``"domain"`` for registrar queries. Some fields will be ``None`` when the source registry doesn't expose them.
- `axross.TimeSkew` (class, `core.net_helpers`): host, source, offset_seconds, rtt_seconds — Result of a :func:`time_skew` measurement. ``offset_seconds`` is positive when the remote source is AHEAD of local; negative when behind. ``rtt_seconds`` is the round-trip used to compute the offset (useful for confidence: small RTT → tight offset). ``source`` records which protocol answered.
- `axross.TlsCert` (class, `core.net_helpers`): subject, issuer, san, not_before, not_after, serial, sha256, raw_der — Parsed peer certificate. ``raw_der`` is the binary DER blob so callers can re-parse with their own tooling if needed.
- `axross.SshHostKey` (class, `core.net_helpers`): host, port, key_type, fingerprint_sha256, fingerprint_md5, raw — SSH host key as returned by paramiko's transport handshake. ``key_type`` is paramiko's name (``ssh-ed25519``, ``ssh-rsa``, ``ecdsa-sha2-nistp256`` …). ``fingerprint_sha256`` is the standard base64 form OpenSSH's ``ssh-keygen -l`` prints.
- `axross.HttpProbe` (class, `core.net_helpers`): status, url, headers, body, truncated, redirect_chain, cert — Result of an :func:`http_probe` call. ``redirect_chain`` lists every URL we were redirected through (incl. the original); ``cert`` is non-None for HTTPS responses.
- `axross.SnmpVar` (class, `core.snmp_helpers`): oid, type, value — One OID/value pair returned from a GET / WALK.
- `axross.GrepHit` (class, `core.net_helpers`): path, line_no, line — GrepHit(path: 'str', line_no: 'int', line: 'str')
- `axross.ArchiveEntry` (class, `core.net_helpers`): name, size, compressed_size, is_dir, modified — One entry from :func:`archive_inspect`. ``size`` is the uncompressed size in bytes; ``compressed_size`` is what's actually on disk (None when the format doesn't track it separately — tar). ``modified`` is a UTC datetime when known.
- `axross.NonInteractiveError` (exception, `core.ui_helpers`) — A confirmation is needed, but no human can answer it.
- `AttackReport` (class, `core.cred_attack`): target_protocol, target_host, target_port, started_at, finished_at, attempts, successes, aborted, abort_reason, attempted_count, errors, lockouts, summary() — Final report from one bruteforce/spray run.
- `AttemptOutcome` (class, `core.cred_attack`): username, password_hash, result, elapsed_s, error_message, timestamp, to_dict() — The trace record for one credential attempt.
- `AttemptResult` (enum, `core.cred_attack`): SUCCESS, FAILED, LOCKOUT, ERROR, SKIPPED — Outcome of a single credential attempt.
- `CasEntry` (class, `core.cas`): backend_id, path, algorithm, value, size, indexed_at, mtime, scan_id — One row from the CAS index.
- `CompareReport` (class, `core.multi_view`): path, probes, content_diff, all_equal() — Result of comparing the SAME path across N backends.
- `ConnectionProfile` (class, `core.profiles`): name, protocol, host, port, username, auth_type, key_file, store_password, proxy_mode, proxy_type, proxy_host, proxy_port, proxy_username, store_proxy_password, proxy_command, proxy_command_confirmed, _proxy_password_override, address_family, ftp_passive, ftps_verify_tls, smb_share, webdav_url, s3_bucket, s3_region, s3_endpoint, rsync_module, rsync_ssh, rsync_ssh_key, nfs_export, nfs_version, azure_container, azure_connection_string, azure_account_name, azure_sas_token, azure_share, onedrive_client_id, onedrive_tenant_id, sharepoint_site_url, gdrive_client_id, gdrive_client_secret, dropbox_app_key, dropbox_app_secret, iscsi_target_iqn, iscsi_mount_point, imap_ssl, pop3_ssl, nntp_ssl, tftp_filelist, tftp_filelist_enabled, tftp_max_size_bytes, adb_mode, adb_usb_serial, mtp_device_id, mtp_mounter, ssh_keepalive_interval, smb_client_name, telnet_naws_width, telnet_naws_height, rsync_preserve_metadata, suppress_shell_history, terminal_theme, production, get_password(), get_proxy_password(), set_password(), set_proxy_password(), to_dict() — A saved connection profile (multi-protocol).
- `Credential` (class, `core.cred_attack`): username, password — A pair of (username, password) the loop discovered as valid.
- `DedupeResult` (class, `core.cas`): dry_run, groups, keep, trash, undated_groups, removed, refused, failed, render() — What :func:`dedupe` planned and, unless a dry run, did.
- `EnumReport` (class, `core.cred_attack`): target_protocol, target_host, started_at, finished_at, results, hits(), summary() — EnumReport(target_protocol: 'str', target_host: 'str', started_at: 'float', finished_at: 'float', results: 'list[EnumResult]' = <factory>)
- `EnumResult` (class, `core.cred_attack`): username, likely_exists, confidence, method, notes — Per-candidate enumeration verdict.
- `ExecResult` (class, `models.exec_result`): returncode, stdout, stderr, truncated_stdout, truncated_stderr, ok, check() — ExecResult(returncode: 'int', stdout: 'bytes', stderr: 'bytes', truncated_stdout: 'bool' = False, truncated_stderr: 'bool' = False)
- `ExplainResult` (class, `core.inspect`): label, confidence, evidence, hint, render() — Heuristic verdict on what a directory IS.
- `Field` (class, `core.metadata_formats`): group, name, value, removable — Field(group: 'str', name: 'str', value: 'str', removable: 'bool' = True)
- `FileItem` (class, `models.file_item`): name, size, modified, permissions, is_dir, is_link, link_target, owner, group, accessed, created, mode_str, permissions_str, size_human, type_char — Represents a single file or directory entry, local or remote.
- `FileTypeInfo` (class, `core.file_type`): path, name, kind, description, mime, extension, extension_mime, verdict, size, encoding, line_endings, engine, file_command, bytes_read, error, mismatch, summary() — What one file really is.
- `FileVersion` (class, `models.file_version`): version_id, modified, size, is_current, label — One historical revision of a file.
- `HealthRecord` (class, `core.conn_health`): profile_key, protocol, label, enrolled_at, last_probe_at, last_latency_s, consecutive_failures, stale, history, healthy, median_latency_s — HealthRecord(profile_key: 'str', protocol: 'str', label: 'str', enrolled_at: 'float' = <factory>, last_probe_at: 'float' = 0.0, last_latency_s: 'float | None' = None, consecutive_failures: 'int' = 0, stale: 'bool' = False, history: 'list[HealthSample]' = <factory>)
- `HealthSample` (class, `core.conn_health`): ts, latency_s, error — HealthSample(ts: 'float', latency_s: 'float | None', error: 'str' = '')
- `HostVisit` (class, `core.visit_history`): protocol, host, username, last_path, last_seen, visit_count, recent_ops, key — Last-visited state for one (protocol, host, username) triple.
- `InspectReport` (class, `core.multi_view`): targets, hashes_consistent() — Result of inspecting an arbitrary list of (backend, path) pairs.
- `InteractiveShell` (class, `models.interactive_shell`): closed, label, close(), fileno(), interact(), read(), read_stderr(), read_until(), resize_pty(), write() — Thin wrapper around a paramiko ``Channel`` in shell+PTY mode.
- `LocalFS` (session, `core.local_fs`): local_path(), same_file(), set_modified() — Local filesystem backend implementing the FileBackend protocol.
- `MetadataReport` (class, `core.metadata_tools`): path, name, kind, fields, error, size, truncated, removable, to_dict() — What one file carries. ``error`` is set when it could not be read (completely); ``fields`` may still hold what was read before that.
- `RamFsSession` (session, `core.ram_fs`): connected, max_bytes, size_bytes, disconnect() — In-process RAM-backed FileBackend.
- `ResumeReport` (class, `core.copy_resume`): src_label, src_path, dst_label, dst_path, total_bytes, bytes_transferred, segments_skipped, segments_transferred, elapsed_s, manifest_path, completed, summary() — ResumeReport(src_label: 'str', src_path: 'str', dst_label: 'str', dst_path: 'str', total_bytes: 'int', bytes_transferred: 'int', segments_skipped: 'int', segments_transferred: 'int', elapsed_s: 'float', manifest_path: 'str', completed: 'bool')
- `ReverseServer` (class, `core.reverse_serve`): flavour, bind, port, backend_label, httpd, thread, auth_token, base_url, shutdown() — Live handle on a running reverse-server.
- `ScanRecord` (class, `core.cas`): scan_id, backend_id, root, algorithm, started_at, finished_at, files_indexed, status, files_in_index, duplicate_groups, error — One rebuild of the index, as the history shows it.
- `SearchHit` (class, `core.search_federation`): backend_label, path, size, mtime, is_dir, snippet, score, warning — One result row.
- `SearchQuery` (class, `core.search_federation`): name, regex, contains, contains_is_regex, min_size, max_size, modified_after, modified_before, roots, max_depth, ignore_dirs, _compiled_regex, _compiled_contains, contains_regex(), matches_mtime(), matches_name(), matches_size(), validate() — What to search for.
- `SearchResult` (class, `core.search_federation`): hits, per_backend, errors, elapsed_s, truncated — Aggregated federation result.
- `Snapshot` (class, `core.trail`): snapshot_id, trail_name, ts, file_count, total_bytes, tree_hash, truncated — Snapshot(snapshot_id: 'int', trail_name: 'str', ts: 'float', file_count: 'int', total_bytes: 'int', tree_hash: 'str', truncated: 'bool' = False)
- `Summary` (class, `core.inspect`): backend_label, path, file_count, dir_count, link_count, total_bytes, extensions, age_buckets, largest, newest, oldest, truncated, error, render() — Structured directory snapshot.
- `TargetProbe` (class, `core.multi_view`): label, path, exists, size, mtime, permissions, is_dir, is_link, sha256, content, truncated, error, elapsed_s — One backend × one path probe result.
- `TrailDiff` (class, `core.trail`): added, removed, modified, unchanged, is_empty(), summary() — Diff between two snapshots of the same trail.

<!-- END GENERATED SCRIPTING CATALOG -->
