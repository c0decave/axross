# axross for LLM agents

How a language model drives axross correctly: through the MCP server
(the tools below) or, where the operator allows it, through Python
scripts that use the `axross.*` API. [MCP.md](MCP.md) is the full
reference for the server; this guide is the short path to using it
right. The tool catalog at the end is generated from
[`mcp-tools.json`](mcp-tools.json), which a test holds against the
code.

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

- `script_api_schema` first: every `axross.*` function with typed
  parameters, `mutates` (changes files or remote state) and `prompts`
  (can need a human).
- Write with `script_write`, run with `script_run(name, args,
  timeout_s)`. The reply carries `exit`, `stdout`, `stderr` and, after
  an uncaught exception, `error_type`, `error` and `traceback`.
- Nobody can answer a prompt: `axross.confirm()` raises
  `NonInteractiveError` unless the script passes `assume_yes=True` —
  pass it only for an action the operator asked for.
- Open sessions with `with` so they close also after an error:

  ```python
  import axross
  with axross.open("backup-server") as b:
      for entry in b.list_dir("/var/log"):
          print(entry.name, entry.size)
  ```
- `axross.open(name)` opens a saved profile; `axross.open_url(url)` any
  backend by URL — the only way to the backends without a profile:
  `ldap://`, `postgres://host/db`, `mongodb://`, `redis://`,
  `git+https://host/repo.git`, `rsh://`, `exchange://`, `wmi://`,
  `slp://`, `sqlite://`.
- **SQLite URLs follow the SQLAlchemy convention:** `sqlite:///data.db`
  is relative to the current directory, `sqlite:////srv/data.db` (four
  slashes) is the absolute path `/srv/data.db`.

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

List historical versions of a file (S3 ObjectVersions, Dropbox revisions, GDrive revision-history, Azure blob snapshots, WebDAV DeltaV). Empty list on backends with no native versioning.

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

Copy a file OR directory tree from src into dst. Per-file records: {src, dst, size, action} where action is "copied", "skipped" (reason: "too-large" or "exists"), or "error". Emits one progress notification per copied file; a notifications/cancelled stops within one file. Defaults: max_files=1000, max_depth=10, max_file_bytes=10 GiB, overwrite=false. Missing dst parent directories are created automatically. Same-backend only in V1 — cross-backend copy is handled by the transfer manager, not the MCP surface.

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

Describe the ``axross`` scripting API that script_run gives a script, as JSON built from the live code: per public function its signature, parameters with types and defaults, return type, first docstring paragraph, group, ``mutates`` (can change files, remote state or settings) and ``prompts`` (needs a human: under script_run it raises NonInteractiveError unless the script opts in, e.g. confirm(assume_yes=True)); the public classes; and the methods every backend session has (with close() and the with statement). Same data as axross.api_schema().

Needs: `--mcp-allow-scripts`.

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
