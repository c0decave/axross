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
- For whole trees and big files use `axross/tasks/start` (same arguments as
  `tools/call`), then poll `axross/tasks/status` and stop with `axross/tasks/cancel`.
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
| `-32002` | The tool ran out of time. | Narrow the request or use `axross/tasks/start`. |

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

Rules every tool shares (the server's initialize instructions; a description names one with a short tag such as "Refuses secret files."):

- Paths are absolute or relative to the MCP root; local paths stay inside the root, a remote backend takes that host's paths. Tools take backend only when there is more than one; its ids come from list_backends, served then ('profile:<name>' after remote_open); omitted, the default backend. A <name>_b64 argument carries the raw bytes of a non-UTF-8 name in base64, as listings return it (name_b64), and replaces <name>.
- Tools that write files need --mcp-write (they say so); the script tools --mcp-allow-scripts, the remote command tools --mcp-allow-exec; each optional group its --mcp-tools name. remove deletes for good; only duplicates_dedupe moves files to axross's restorable trash.
- Secret files (SSH and GnuPG private keys, axross's tokens; on remote hosts also .env and credentials files) are refused, unless the server was started with --mcp-allow-secret-reads.
- Write guards: writes stay inside a writable MCP root and outside protected places (shell and session start files, autostart, user services, SSH and GnuPG folders, axross settings); production-flagged profiles are read-only.
- Paranoid mode (AXROSS_SECURITY_MODE=paranoid or the app setting) turns off scripts, extensions, remote commands, ffmpeg/ffprobe and legacy protocols.
- max_depth: walk, grep, recursive_checksum and bulk_copy count levels from 1 (1 = path's own entries); file_type_scan and transfer_copy count subfolder levels from 0 (0 = path's own files).
- truncated: a limit (max_*, or max_depth leaving a folder unentered) cut the result; tree walks also carry complete, false when anything was cut or left unread, and unreadable ({path, error} in walk and grep, folder paths elsewhere). A call past its time limit fails with a timeout error and returns nothing; work it started may still finish.
- An idempotent tool changes nothing more when repeated; the description names the error a repeat may give.

### `core`

File tools of the configured backend; always on, read-only.

#### `list_dir` — read-only · quick (15 s) · stdio + http · *backend*

List the entries of one folder, one level deep.

**Use when:** you need what is directly inside a folder.

**Instead:** walk for a subtree or a capped listing; stat for one path; search for indexed names.

**Behavior:** read-only. Every entry, hidden ones too, in the backend's order; a symlink is listed itself (is_link true, is_dir false). No entry cap, but a result over 16 MiB fails. A missing path or a file fails. Time limit: 15 s.

**Returns:** a JSON array of {name, is_dir, is_link, size, modified (ISO 8601 or null)}; structuredContent wraps it as {entries}.

- `path` (string): The folder to list (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `stat` — read-only · quick (15 s) · stdio + http · *backend*

Get the type, size, modification time and mode of one file or folder.

**Use when:** checking that a path exists or what it is, or reading the mode before chmod.

**Instead:** list_dir for a folder's entries; read_file for the contents.

**Behavior:** read-only. Follows a symlink: the fields, name included, are the target's; is_link says the path itself is a link (local disk; remote backends report false). Nothing at path, or a dangling link, fails. Time limit: 15 s.

**Returns:** {name, is_dir, is_link, size, modified (ISO 8601 or null), mode (octal such as '0644', null without POSIX bits)}.

- `path` (string): The file or folder to describe (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `read_file` — read-only · quick (15 s) · stdio + http · *backend*

Read one file's contents as base64 bytes or UTF-8 text, at most 4 MiB per call.

**Use when:** you need a file's contents; page through a larger one with offset.

**Instead:** grep to find lines across files; open_version_read for an older version; preview for an image.

**Behavior:** read-only. Refuses secret files. A folder or missing file fails; text never cuts a character in two. Time limit: 15 s.

**Returns:** {content_b64 or text, size (bytes returned; stat gives the file's), truncated, replaced (text: bad bytes became U+FFFD)}; with truncated or an offset also offset and next_offset. Past the end: empty, truncated false.

- `encoding` (string, one of `base64`, `text`, default `"base64"`): base64 (default): the exact bytes, safe for any file. text: decoded as UTF-8 - pass it for text files.
- `max_bytes` (integer, default `4194304`, 0..4194304): Most bytes to return; 0 or omitted means the ceiling, 4194304 (4 MiB).
- `offset` (integer, default `0`, >= 0): Byte offset to start at; pass the previous call's next_offset to continue.
- `path` (string): The file to read (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `checksum` — read-only · stream (300 s) · stdio + http · *backend*

Compute one file's hash (md5, sha1, sha256 or sha512).

**Use when:** comparing a file with a copy or a published digest without transferring it.

**Instead:** recursive_checksum for a folder; duplicates_scan to find identical files.

**Behavior:** read-only. Uses the backend's own hash when it has one (e.g. sha256sum over SSH), else streams the file; cancellable. Refuses secret files. A folder or missing path fails. Time limit: 5 min.

**Returns:** {value (hex digest), algorithm, source (native|stream)}.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`, default `"sha256"`): The hash algorithm.
- `path` (string): The file to hash (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `search` — read-only · quick (15 s) · stdio + http · *backend*

Find files and folders by name, extension and size in the offline metadata index, without touching the backend.

**Use when:** looking up names fast across folders indexed before.

**Instead:** walk for the live tree (slower, never stale); grep for contents.

**Requires:** an index from index_build or the axross app.

**Behavior:** read-only; results can be stale. The given filters must all match; none gives every indexed entry. Pages with offset and limit. Time limit: 15 s.

**Returns:** a JSON array of {backend_id, path, name, size, is_dir, modified}; structuredContent {entries, indexed (false: no index yet), truncated (more after this page)}. Fewer than limit entries is the last page.

- `ext` (string): File extension, matched whole in any case; a leading dot is ignored, e.g. 'pdf'.
- `limit` (integer, default `1000`, 1..10000): Most results to return.
- `max_size` (integer, >= 0): Largest size in bytes, inclusive; omit for no upper bound. Below min_size nothing matches.
- `min_size` (integer, default `0`, >= 0): Smallest size in bytes, inclusive.
- `needle` (string): Substring of the file name, matched ignoring case and Unicode normalisation, e.g. 'report' finds 'Q3_Report.pdf'.
- `offset` (integer, default `0`, >= 0): Matches to skip, for the next page: the previous offset + limit.
- `path` (string): Only entries anywhere below this folder (absolute, or relative to the MCP root).
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `walk` — read-only · walk (60 s) · stdio + http · *backend*

List the live folder tree under path, breadth-first, to max_depth levels.

**Use when:** you need every file and folder below a path.

**Instead:** list_dir for one level; search for the indexed (faster, maybe stale) view; grep for contents.

**Behavior:** read-only. Symlinked folders are listed, not entered. Hitting max_entries, or a folder at max_depth left unentered, sets truncated; an unlistable subfolder goes to unreadable. Progress; cancellable. Time limit: 60 s.

**Returns:** {entries: [{path, name, is_dir, is_link, size, modified}], truncated, unreadable: [{path, error}], complete (false when anything was cut or unread)}.

- `max_depth` (integer, default `4`, 1..64): Levels to visit, counted from 1: 1 = path's own entries.
- `max_entries` (integer, default `1000`, 1..100000): Most entries to return (files and folders together).
- `path` (string): The folder to walk (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `recursive_checksum` — read-only · stream (300 s) · stdio + http · *backend*

Hash every file under a folder (or one file) and list each digest.

**Use when:** verifying or comparing a whole tree, e.g. after a copy.

**Instead:** checksum for one file; duplicates_scan to group identical files.

**Behavior:** read-only, breadth-first. Symlinked files are hashed, symlinked folders get an error record. Refuses secret files. Files above max_file_bytes are skipped; max_files or a folder at max_depth sets truncated. Unreadable entries get records. Progress per file; cancellable. Time limit: 5 min.

**Returns:** {entries: [{path, size, algorithm, then checksum and source, or skipped, or error (folder: true for an unlisted folder)}], truncated, complete}.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`, default `"sha256"`): The hash algorithm.
- `max_depth` (integer, default `10`, 1..64): Levels to visit, counted from 1: 1 = path's own entries.
- `max_file_bytes` (integer, default `1073741824`, >= 1): Files larger than this many bytes are skipped (default 1 GiB).
- `max_files` (integer, default `500`, 1..50000): Most files to hash; truncated=true when there were more.
- `path` (string): The folder (or one file) to hash (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `preview` — read-only · preview (30 s) · stdio + http

Render a PNG thumbnail of an image file on the local disk.

**Use when:** you need to see an image (PNG, JPEG, GIF, BMP, WebP, TIFF ...) under the MCP root.

**Instead:** read_file for the raw bytes; metadata_read for EXIF. A remote image: transfer_copy (needs --mcp-write) to the local disk first.

**Behavior:** read-only, local disk only. Files over 50 MiB, images over 20000 px, SVG, other types and undecodable files fail. Time limit: 30 s.

**Returns:** an MCP image content block (image/png) with _meta {width, height}.

- `edge` (integer, default `256`, 16..2048): Longest side of the thumbnail in pixels, 16-2048.
- `path` (string): The image file on the local disk (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `grep` — read-only · walk (60 s) · stdio + http · *backend*

Search file contents under a folder for lines matching a regular expression.

**Use when:** finding which files contain a word or pattern, with line numbers.

**Instead:** search or walk to match names; read_file for a whole file.

**Behavior:** read-only, breadth-first; include narrows by file name. Every file is read as UTF-8 text, binary ones too: bad bytes show as U+FFFD. Files over 4 MiB are skipped; lines are cut at 500 characters. Patterns with nested quantifiers, or slower than 5 s on a file, are refused (ReDoS). Refuses secret files. Time limit: 60 s.

**Returns:** {matches: [{path, line_no, line}], files_scanned, truncated (max_matches, or a folder at max_depth not searched), unreadable, complete}; no match with complete=false is no answer.

- `pattern` (string, required): A Python regular expression, matched against each line, e.g. 'import|require' or '(?i)password'.
- `include` (string): Only files whose name matches this glob, case-sensitive, e.g. '*.py' or '*.[ch]'.
- `max_depth` (integer, default `2`, 1..64): Levels to visit, counted from 1: 1 = path's own entries.
- `max_matches` (integer, default `100`, 1..500): Most matching lines to return.
- `path` (string): The folder to search (absolute, or relative to the MCP root); default the MCP root, '/' on a remote backend.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `list_versions` — read-only · quick (15 s) · stdio + http · *backend*

List the stored older versions of one file.

**Use when:** you need an earlier state on a versioning backend (S3, Dropbox, Drive, Azure, WebDAV DeltaV, Git).

**Instead:** open_version_read to read one; read_file for the current one.

**Behavior:** read-only. Unsorted (the backend's order). Backends without versions, the local disk too, give [] (open_version_read fails there). Time limit: 15 s.

**Returns:** a JSON array of {version_id, size, modified (ISO 8601 or null), is_current, label (may be empty)}; structuredContent: {versions}.

- `path` (string): The file whose versions to list (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `open_version_read` — read-only · quick (15 s) · stdio + http · *backend*

Read the bytes of one older version of a file (from list_versions), at most 4 MiB.

**Use when:** inspecting or recovering an older version.

**Instead:** read_file for the current version.

**Requires:** a version_id from list_versions.

**Behavior:** read-only. No offset: only the first 4 MiB of a version can be read over MCP. Refuses secret files. Backends without versions fail. Time limit: 15 s.

**Returns:** {content_b64, size, truncated (the version is longer)}.

- `version_id` (string, required): The version_id of one entry from list_versions for this path.
- `max_bytes` (integer, default `4194304`, 0..4194304): Most bytes to return; 0 or omitted means the ceiling, 4194304 (4 MiB).
- `path` (string): The file to read (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

### `write`

Write tools; only with --mcp-write, which needs --mcp-root.

#### `write_file` — mutating · write (30 s) · stdio + http · *backend*

Create a file or replace its whole contents with text or bytes.

**Use when:** saving content to one file; to edit, read_file, change, write back.

**Instead:** copy to duplicate a file; mkdir for folders.

**Requires:** available only with --mcp-write.

**Behavior:** destructive - replaces the file. Idempotent: a repeat changes nothing more. Atomic (temp file, rename); new local files get mode 0600. The parent must exist; a symlink at path is followed (its target is written), a folder fails. A request is at most 16 MiB. Write guards apply. Time limit: 30 s.

**Returns:** {size: bytes written}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `content` (string): The new content as text, stored UTF-8 encoded. Exactly one of content and content_b64 is required: neither or both fails.
- `content_b64` (string): content as base64 of the raw bytes, for binary files; give this or content.
- `path` (string): The file to create or replace (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `mkdir` — mutating · write (30 s) · stdio + http · *backend*

Create a folder, with missing parents on the local disk.

**Use when:** a folder must exist before writing into it.

**Instead:** bulk_copy and transfer_copy make their destinations.

**Requires:** available only with --mcp-write.

**Behavior:** only adds. Idempotent: a repeat changes nothing more; locally it succeeds. Remote backends create no parents, and an existing folder fails there with 'exists'. A file at path fails. Write guards apply. Time limit: 30 s.

**Returns:** {ok: true}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `path` (string): The folder to create (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `remove` — mutating · write (30 s) · stdio + http · *backend*

Permanently delete a file, symbolic link or folder.

**Use when:** something must go for good; there is no trash.

**Instead:** rename to move it aside; remove has no trash.

**Requires:** available only with --mcp-write.

**Behavior:** destructive, irreversible. Idempotent: a repeat changes nothing more; it fails with 'No such file'. A non-empty folder needs recursive=true; a failure half-way leaves the rest. A symlink is removed, not its target. Write guards apply. Time limit: 30 s.

**Returns:** {ok: true}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `path` (string): The file, link or folder to delete (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `recursive` (boolean, default `false`): true: also delete everything inside a folder. false: a non-empty folder fails.

#### `rename` — mutating · write (30 s) · stdio + http · *backend*

Move or rename a file or folder within one backend.

**Use when:** renaming, or moving on the same backend - folders too.

**Instead:** copy to keep the original; transfer_move to another backend.

**Requires:** available only with --mcp-write.

**Behavior:** destructive for the old path. Idempotent: a repeat changes nothing more; it fails with 'target already exists'. Native rename (atomic locally), else copy then delete. dst's parent must exist; an existing dst is never replaced. A symlink moves itself; secret files cannot be moved. Write guards apply. Time limit: 30 s.

**Returns:** {ok: true}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `dst` (string): Its new path, including the new name; must not exist yet (absolute, or relative to the MCP root). Required unless dst_b64 is given.
- `dst_b64` (string): dst as base64 of its raw bytes, for non-UTF-8 names; replaces dst.
- `src` (string): The file or folder to move (absolute, or relative to the MCP root). Required unless src_b64 is given.
- `src_b64` (string): src as base64 of its raw bytes, for non-UTF-8 names; replaces src.

#### `copy` — mutating · write (30 s) · stdio + http · *backend*

Copy one file to a new path on the same backend.

**Use when:** duplicating a single file.

**Instead:** bulk_copy for a folder tree (copy takes files only); transfer_copy across backends or for big files.

**Requires:** available only with --mcp-write.

**Behavior:** only adds. Idempotent: a repeat changes nothing more; it fails with 'already exists'. Native copy (S3, WebDAV, cp over SSH) where possible; locally mode and mtime are kept. dst's parent must exist; a folder as src fails. Refuses secret files. Write guards apply. Time limit: 30 s.

**Returns:** {ok: true}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `dst` (string): The new file's path, including its name; must not exist yet (absolute, or relative to the MCP root). Required unless dst_b64 is given.
- `dst_b64` (string): dst as base64 of its raw bytes, for non-UTF-8 names; replaces dst.
- `src` (string): The file to copy (absolute, or relative to the MCP root). Required unless src_b64 is given.
- `src_b64` (string): src as base64 of its raw bytes, for non-UTF-8 names; replaces src.

#### `bulk_copy` — mutating · stream (300 s) · stdio + http · *backend*

Copy a folder tree (or one file) to another path on the same backend.

**Use when:** duplicating or merging a folder on one backend.

**Instead:** copy for a single file; transfer_copy across backends.

**Requires:** available only with --mcp-write.

**Behavior:** breadth-first; src's entries land in dst, folders are created. Existing files are skipped unless overwrite=true (destructive). Idempotent: a repeat changes nothing more (overwrite=true rewrites the same files). Locally mode and mtime are kept. Failures per file are recorded. Refuses secret files. Write guards apply. Progress; cancellable. Time limit: 5 min.

**Returns:** {entries, truncated, complete}; actions and reasons in outputSchema.

Needs: `--mcp-write` `--mcp-root DIR`.

- `dst` (string): The copy (absolute, or relative to the MCP root): for a file the new file, for a folder the folder that becomes the copy, made if missing. Required unless dst_b64 is given.
- `dst_b64` (string): dst as base64 of its raw bytes, for non-UTF-8 names; replaces dst.
- `max_depth` (integer, default `10`, 1..64): Levels to visit, counted from 1: 1 = src's own entries. Deeper folders get a 'max-depth' record.
- `max_file_bytes` (integer, default `10737418240`, >= 1): Files larger than this many bytes are skipped (default 10 GiB).
- `max_files` (integer, default `1000`, 1..100000): Most files to copy; truncated=true when there were more.
- `overwrite` (boolean, default `false`): true: replace files that exist at the destination. false: skip them (reason 'exists').
- `src` (string): The file or folder to copy (absolute, or relative to the MCP root). Required unless src_b64 is given.
- `src_b64` (string): src as base64 of its raw bytes, for non-UTF-8 names; replaces src.

#### `symlink` — mutating · write (30 s) · stdio + http · *backend*

Create a symbolic link at link_path pointing to target.

**Use when:** a second path should lead to a file or folder.

**Instead:** hardlink for a second name of one file; copy for a copy.

**Requires:** available only with --mcp-write.

**Behavior:** only adds. Idempotent: a repeat changes nothing more; it fails with 'File exists'. Locally the target must also stay inside the root; it may dangle. Local disk, SFTP and NFS only. Write guards apply. Time limit: 30 s.

**Returns:** {ok: true}, plus target when the one stored differs.

Needs: `--mcp-write` `--mcp-root DIR`.

- `link_path` (string): The new link's own path; must not exist yet (absolute, or relative to the MCP root). Required unless link_path_b64 is given.
- `link_path_b64` (string): link_path as base64 of its raw bytes, for non-UTF-8 names; replaces link_path.
- `target` (string): What the link points to: absolute, or relative to the link's folder, e.g. '../shared/data.csv'. SFTP and NFS store it as given. Required unless target_b64 is given.
- `target_b64` (string): target as base64 of its raw bytes, for non-UTF-8 names; replaces target.

#### `hardlink` — mutating · write (30 s) · stdio + http · *backend*

Create a hard link: a second name for an existing file.

**Use when:** one file must appear under two paths.

**Instead:** symlink for folders or across file systems; copy for a copy.

**Requires:** available only with --mcp-write.

**Behavior:** only adds. Idempotent: a repeat changes nothing more; it fails with 'File exists'. One file system; local disk, SFTP and NFS only. Refuses secret files. Write guards apply. Time limit: 30 s.

**Returns:** {ok: true}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `link_path` (string): The new name; must not exist yet (absolute, or relative to the MCP root). Required unless link_path_b64 is given.
- `link_path_b64` (string): link_path as base64 of its raw bytes, for non-UTF-8 names; replaces link_path.
- `target` (string): The existing file to link to; unlike symlink's target it is resolved like any path (absolute, or relative to the MCP root). Required unless target_b64 is given.
- `target_b64` (string): target as base64 of its raw bytes, for non-UTF-8 names; replaces target.

#### `chmod` — mutating · write (30 s) · stdio + http · *backend*

Set the POSIX permission bits of a file or folder.

**Use when:** making a script executable or a file private, e.g. '755', '600'; stat shows the current mode.

**Instead:** write_file already makes new files private (0600).

**Requires:** available only with --mcp-write.

**Behavior:** destructive - replaces the mode. Idempotent: a repeat changes nothing more. Follows a symlink. Bits outside 0755 and files with several hard links are refused; backends without POSIX modes fail. Write guards apply. Time limit: 30 s.

**Returns:** {ok: true}.

Needs: `--mcp-write` `--mcp-root DIR`.

- `mode` (any, required): The new mode in octal: a string such as '644', '0644' or '0o755', or the integer value (420 = 0o644). Bits outside 0755 (setuid, setgid, sticky, group or world write) are refused.
- `path` (string): The file or folder (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

### `scripts`

Saved-script tools; only with --mcp-allow-scripts, stdio only, not confined to the MCP root; refused in the paranoid security mode.

#### `script_list` — read-only · quick (15 s) · stdio

List the names of the saved Python scripts.

**Use when:** looking for a script to read, run or delete.

**Instead:** script_read for a source; script_api_schema for the API.

**Requires:** available only with --mcp-allow-scripts (stdio only).

**Behavior:** read-only; the server's script folder, not the MCP root. Time limit: 15 s.

**Returns:** {scripts: [name, ...]}, sorted, without '.py'.

Needs: `--mcp-allow-scripts`.

#### `script_api_schema` — read-only · quick (15 s) · stdio

Describe the axross Python API that scripts can call, as JSON from the live code.

**Use when:** writing a script: names=[] gives the index (about 30 KB), then ask for the names you need.

**Instead:** script_read to see an existing script.

**Requires:** available only with --mcp-allow-scripts (stdio only).

**Behavior:** read-only; runs no code. Without names: the whole API, some 200 KB. An unknown name fails. Time limit: 15 s.

**Returns:** {schema_version, module, legend, rules, errors, groups (names by topic), functions, classes, backend_protocol, types}; the index has functions and classes empty, names fills them for those names.

Needs: `--mcp-allow-scripts`.

- `names` (array of string): Function, class or type names (from the index's groups), e.g. ['open_url', 'FileItem']; each comes with the types it uses. [] gives the index alone; omitted, the whole API.

#### `script_read` — read-only · quick (15 s) · stdio

Read the Python source of one saved script.

**Use when:** checking a script before script_run or script_write.

**Instead:** script_list for names; read_file for files under the MCP root.

**Requires:** available only with --mcp-allow-scripts (stdio only).

**Behavior:** read-only. A missing script, a bad name or a symlinked file fails. Time limit: 15 s.

**Returns:** {name, source}.

Needs: `--mcp-allow-scripts`.

- `name` (string, required): The script's name, from script_list: letters, digits, '_' and '-', at most 80 characters, without '.py', e.g. 'disk_report'.

#### `script_write` — mutating · quick (15 s) · stdio

Save Python source as a named script, replacing one of that name.

**Use when:** creating or changing a script for script_run.

**Instead:** write_file for files under the MCP root.

**Requires:** available only with --mcp-allow-scripts (stdio only).

**Behavior:** destructive for a script of that name. Idempotent: a repeat changes nothing more. Atomic, mode 0600, in the script folder. Over 1 MiB of UTF-8 fails. Runs nothing. Time limit: 15 s.

**Returns:** {name, path, size (bytes)}.

Needs: `--mcp-allow-scripts`.

- `name` (string, required): The script's name: letters, digits, '_' and '-', at most 80 characters, without '.py', e.g. 'disk_report'.
- `source` (string, required): The complete Python source; it runs with the module axross already imported.

#### `script_delete` — mutating · quick (15 s) · stdio

Delete one saved script permanently.

**Use when:** a script is no longer needed.

**Instead:** script_write to replace its source.

**Requires:** available only with --mcp-allow-scripts (stdio only).

**Behavior:** destructive, no trash. Idempotent: a repeat changes nothing more; it succeeds with deleted false. A bad name fails. Time limit: 15 s.

**Returns:** {name, deleted (false: there was no such script)}.

Needs: `--mcp-allow-scripts`.

- `name` (string, required): The script's name, from script_list: letters, digits, '_' and '-', at most 80 characters, without '.py', e.g. 'disk_report'.

#### `script_run` — mutating · script (610 s) · stdio

Run a saved Python script in a child process with the axross API imported.

**Use when:** a job needs logic the file tools lack, e.g. a loop over backends.

**Instead:** the file tools for single steps; remote_exec on a remote host.

**Requires:** available only with --mcp-allow-scripts (stdio only); the script must exist; off in paranoid mode.

**Behavior:** destructive - runs with the server user's full rights, outside the MCP root. Not idempotent: it runs again. stdin is empty; API prompts raise NonInteractiveError unless the script passes assume_yes=True to them. Stopped after timeout_s. Over 1 MiB of stdout or stderr fails the call with no output, though what the script did stays (remote_exec truncates instead).

**Returns:** {name, exit (negative: killed by that signal), timed_out, duration_ms, stdout, stderr, namespace_keys (globals left defined)}, plus {error_type, error, traceback} after an exception.

Needs: `--mcp-allow-scripts`.

- `name` (string, required): The script's name, from script_list: letters, digits, '_' and '-', at most 80 characters, without '.py', e.g. 'disk_report'.
- `args` (array of string, default `[]`): Command-line arguments, the script's sys.argv[1:], e.g. ['--dry-run', 'docs']; no NUL characters.
- `timeout_s` (number, default `60.0`, <= 600.0): Wall-clock limit for the run in seconds.

### `agent`

Hand a task to the user's own LLM (the active profile of the axross GUI): it works with the read-only tools inside the MCP root and answers; it can change nothing.

#### `agent_run` — read-only · long (1800 s) · stdio + http

Hand a task to the user's own LLM profile, which works with axross tools that write no files and answers in text.

**Use when:** file contents should stay with the user's model, e.g. a local one.

**Instead:** read_file or grep directly - faster, when the contents may reach you.

**Requires:** available only with --mcp-tools agent; an LLM profile set up in the axross app (an unknown name's error lists them).

**Behavior:** does not write files itself; sends file contents to the configured LLM, so it is not read-only. Its model gets the groups' tools that need no --mcp-write, inside the MCP root. Not idempotent: it asks again. Stops after max_steps; cancellable. Time limit: 30 min.

**Returns:** {answer, stopped (answered|max_steps|cancelled), calls, profile, model}.

Needs: `--mcp-tools agent`.

- `task` (string, required): What the model should do, in plain language, e.g. 'Summarise the PDFs in reports/2024 in five bullet points'.
- `groups` (array of string): Extra groups for the model, each with its tools that need no --mcp-write: metadata (metadata_read, metadata_export); duplicates (duplicates_scan, duplicates_scans, duplicates_groups); packer (pack_formats); archive (archive_list); index (index_build); filetype (file_type, file_type_scan); remote (remote_profiles, remote_open, remote_close, list_backends); extensions (extensions_list, extensions_info). remote and extensions fail unless this server runs with them. Default: none (the core file tools only).
- `max_steps` (integer, default `10`, 1..30): Most model requests for this task; reaching it ends with stopped=max_steps.
- `profile` (string): Name of an LLM profile set up in the axross app. No tool lists them: omit it for the active profile, the usual choice. An unknown name fails.

### `archive`

List an archive's members; extract it into a fresh folder (mutating).

#### `archive_list` — read-only · walk (60 s) · stdio + http

List the members of an archive on the local disk without extracting.

**Use when:** checking contents or unpacked size before archive_extract.

**Instead:** archive_extract (needs --mcp-write) to unpack it. A remote archive: transfer_copy (needs --mcp-write) to the local disk first.

**Requires:** available only with --mcp-tools archive.

**Behavior:** read-only, local disk only. Unknown or damaged files fail; an encrypted 7z or ZIP needs password; 7z needs py7zr, rar rarfile. Refuses secret files. Cancellable. Time limit: 60 s.

**Returns:** {path, total, truncated, entries: [{name, size, compressed, mtime (Unix seconds), modified (ISO 8601), is_dir}]}.

Needs: `--mcp-tools archive`.

- `max_entries` (integer, default `1000`, 1..10000): Return at most this many members; total still counts all, truncated tells when some were left out.
- `password` (string, secret, never echoed): The password of an encrypted 7z or ZIP (e.g. one pack made with a password). Without it such an archive fails with 'the archive is encrypted with a password'; a wrong one fails too. Never logged or returned.
- `path` (string): The archive on the local disk (absolute, or relative to the MCP root): zip family, tar.*, 7z, rar, gz, bz2, xz or zst. Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `archive_extract` — mutating · long (1800 s) · stdio + http

Extract an archive on the local disk into a new folder named after it.

**Use when:** unpacking; look with archive_list first.

**Instead:** archive_list to look; decrypt for .axenc files. A remote archive: transfer_copy to the local disk first.

**Requires:** available only with --mcp-tools archive and --mcp-write.

**Behavior:** only adds - 'x.zip' -> folder 'x', then 'x-1' (folders count with '-n'). Not idempotent: a repeat makes 'x-1'. An encrypted archive needs password. Zip-slip, over 10,000 members or 1 GiB unpacked, or zip bombs are refused, leaving nothing. Links are never extracted. Local disk only. Write guards apply. Time limit: 30 min.

**Returns:** {path (the new folder), files}, plus skipped_links and note (how many links were left out) when there were links.

Needs: `--mcp-tools archive` `--mcp-write` `--mcp-root DIR`.

- `dest_dir` (string): An existing local folder that receives the new folder (absolute, or relative to the MCP root). Default: the archive's folder.
- `dest_dir_b64` (string): dest_dir as base64 of its raw bytes, for non-UTF-8 names; replaces dest_dir.
- `password` (string, secret, never echoed): The password of an encrypted 7z or ZIP (e.g. one pack made with a password). Without it such an archive fails with 'the archive is encrypted with a password'; a wrong one fails too. Never logged or returned.
- `path` (string): The archive on the local disk (absolute, or relative to the MCP root): zip family, tar.*, 7z, rar, gz, bz2, xz or zst. Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

### `crypto`

Encrypt a file into the axross .axenc format and decrypt it again (mutating).

#### `encrypt` — mutating · stream (300 s) · stdio + http · *backend*

Encrypt one file into a new .axenc file next to it (axross's format).

**Use when:** one file must be kept or shared under a passphrase; decrypt reverses it.

**Instead:** pack as 7z with a password for several files.

**Requires:** available only with --mcp-tools crypto and --mcp-write.

**Behavior:** only adds; the plaintext stays ('a.txt' -> 'a.txt.axenc', taken: 'a.txt (2).axenc'). Not idempotent: each call adds a file. At most 1 GiB; new local files are mode 0600. Refuses secret files. Write guards apply. Cancellable. Time limit: 5 min.

**Returns:** {path, size, plaintext_size}.

Needs: `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR`.

- `passphrase` (string, required, secret, never echoed): The passphrase; the key is derived with PBKDF2-SHA256 (200,000 iterations) for AES-256-GCM. Never logged or returned.
- `path` (string): The file to encrypt, not a folder (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

#### `decrypt` — mutating · stream (300 s) · stdio + http · *backend*

Decrypt an .axenc file into a new plaintext file next to it.

**Use when:** restoring a file encrypted with axross.

**Instead:** archive_extract for encrypted 7z or ZIP archives.

**Requires:** available only with --mcp-tools crypto and --mcp-write.

**Behavior:** only adds ('a.txt.axenc' -> 'a.txt', taken: 'a (2).txt'; a name without .axenc gets '.decrypted'). Not idempotent: each call adds a file. A wrong passphrase or tampered file fails, leaving nothing. At most 1 GiB; new local files are mode 0600. Write guards apply. Cancellable. Time limit: 5 min.

**Returns:** {path, size}.

Needs: `--mcp-tools crypto` `--mcp-write` `--mcp-root DIR`.

- `passphrase` (string, required, secret, never echoed): The passphrase; the key is derived with PBKDF2-SHA256 (200,000 iterations) for AES-256-GCM. Never logged or returned.
- `path` (string): The .axenc file to decrypt (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.

### `duplicates`

Duplicate Finder: scan a folder into the duplicate index, list scans and duplicate groups; dedupe to the axross trash (mutating, dry run by default).

#### `duplicates_scan` — read-only · long (1800 s) · stdio + http · *backend*

Run a duplicate scan: hash every file under a folder into the Duplicate Finder's index.

**Use when:** before duplicates_groups or duplicates_dedupe, or after changes.

**Instead:** duplicates_scans for past scans; checksum for one file.

**Requires:** available only with --mcp-tools duplicates.

**Behavior:** writes index rows, never files. path must be a folder. Not idempotent: each run adds a scan record (the rows stay the same). Symlinks, the axross trash and secret files are skipped. Unchanged files are not hashed again unless rehash. The local disk hashes by reading; remote backends use their own checksum, so ETag-only ones (plain S3, WebDAV) index nothing. A capped or cancelled scan keeps its rows. Progress. Time limit: 30 min.

**Returns:** {scan_id (null: no scan record was written), root, backend_id, algorithm, files_indexed, status, truncated (max_files), complete, unreadable (folder paths)}.

Needs: `--mcp-tools duplicates`.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`, default `"sha256"`): Hash algorithm for the index rows.
- `max_files` (integer, 1..1000000): Visit at most this many entries; reaching it stops the walk and sets truncated=true. Default 1,000,000 on the local backend, 100,000 on a remote one.
- `path` (string): The folder (absolute, or relative to the MCP root). Default on the local backend: the MCP root; other backends need it.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `rehash` (boolean, default `false`): Hash every file again, even when size and mtime are unchanged.

#### `duplicates_scans` — read-only · quick (15 s) · stdio + http · *backend*

List past duplicate scans (scan history), newest first.

**Use when:** choosing a scan_id, or checking that a scan finished.

**Instead:** duplicates_scan to run one; duplicates_groups for the duplicates.

**Requires:** available only with --mcp-tools duplicates.

**Behavior:** read-only; this backend's scans (local: inside the MCP root), the newest 1000 only. Time limit: 15 s.

**Returns:** {scans: [{scan_id, root, backend_id, algorithm, started_at, finished_at (ISO 8601, null while running), files_indexed, files_in_index, duplicate_groups, status, error}], truncated}.

Needs: `--mcp-tools duplicates`.

#### `duplicates_groups` — read-only · quick (15 s) · stdio + http · *backend*

List groups of identical files from the duplicate index, every copy inside path.

**Use when:** reviewing duplicates after duplicates_scan.

**Instead:** duplicates_dedupe (needs --mcp-write) with dry_run for the trash plan.

**Requires:** available only with --mcp-tools duplicates.

**Behavior:** read-only; the index as of the last scan, no file is read. Groups come by hash; empty files never group. The first copy (keep=true) is the oldest, the one duplicates_dedupe keeps. Pages with offset and max_groups. Time limit: 15 s.

**Returns:** {path, truncated, groups: [{algorithm, value, size, copies: [{path, size, mtime (Unix seconds), modified (ISO 8601), scan_id, keep}]}]}.

Needs: `--mcp-tools duplicates`.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`): Only groups hashed with this algorithm; omit for every algorithm.
- `max_groups` (integer, default `100`, 1..1000): Return at most this many groups; more sets truncated=true.
- `offset` (integer, default `0`, 0..2147483647): Groups to skip, for the next page: the previous offset + max_groups.
- `path` (string): The folder (absolute, or relative to the MCP root). Default on the local backend: the MCP root; other backends need it.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `scan_id` (integer, 0..2147483647): Only groups with at least one copy from this scan (a scan_id from duplicates_scans); 0 = rows from before scans were recorded. Omit for all scans.

#### `duplicates_dedupe` — mutating · long (1800 s) · stdio + http · *backend*

Keep the first copy of each duplicate group inside path and move the others to the axross trash.

**Use when:** after duplicates_groups; run dry_run=true first.

**Instead:** duplicates_groups to look; remove to delete for good.

**Requires:** available only with --mcp-tools duplicates and --mcp-write.

**Behavior:** destructive but restorable; dry_run=true (default) only plans. Idempotent: a repeat changes nothing more: trashed copies leave the index, so a repeat plans none. Each copy is re-checked first; changed ones go to refused. The trash is .axross-trash in the MCP root (remote: the home folder); restore in the axross app. Time limit: 30 min.

**Returns:** {path, dry_run, groups, undated_groups (survivor chosen by path), keep, trash (planned moves), removed (moves done; [] on dry_run), refused, failed, trash_root}.

Needs: `--mcp-tools duplicates` `--mcp-write` `--mcp-root DIR`.

- `algorithm` (string, one of `md5`, `sha1`, `sha256`, `sha512`): Only groups hashed with this algorithm; omit for every algorithm.
- `dry_run` (boolean, default `true`): true: only return the plan; false: move the planned copies to the trash.
- `path` (string): The folder (absolute, or relative to the MCP root). Default on the local backend: the MCP root; other backends need it.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `scan_id` (integer, 0..2147483647): Only groups with at least one copy from this scan (a scan_id from duplicates_scans); 0 = rows from before scans were recorded. Omit for all scans.

### `exec`

Run commands and scripts on remote hosts over SSH, SCP, Telnet, rsh, ADB, WinRM (PowerShell) and Cisco (show commands only); only with --mcp-allow-exec (mutating), refused in the paranoid security mode and on production profiles.

#### `remote_exec` — mutating · long (1800 s) · stdio + http · *backend*

Run one command line on a remote host (SSH, Telnet, ADB, WinRM, Cisco).

**Use when:** a shell command is needed there (ps, df, a Cisco show).

**Instead:** remote_script for scripts; the file tools for files.

**Requires:** available only with --mcp-tools exec and --mcp-allow-exec; a backend from exec_backends; off in paranoid mode.

**Behavior:** destructive - runs with the profile user's rights. Not idempotent: it runs again. Refused on production profiles. A non-zero exit is a result; past timeout the call fails and no output returns. Telnet and ADB mix stderr into stdout; Cisco runs show only; WinRM PowerShell.

**Returns:** {returncode, stdout, stderr, truncated_stdout, truncated_stderr} (text, UTF-8 with undecodable bytes replaced).

Needs: `--mcp-tools exec` `--mcp-allow-exec`.

- `command` (string, required): The command line, run by the remote's shell, e.g. 'df -h /'.
- `env` (object): Environment variables for the command as {NAME: value}, e.g. {"LANG": "C"}. On POSIX shells they are exported in the command line, so other users of the host may see the values: pass no secrets this way.
- `max_output` (integer, default `1048576`, 1..16777216): Most bytes of stdout kept; stderr keeps min(max_output, 1 MiB). truncated_stdout / truncated_stderr tell when output was cut.
- `stdin` (string): Text fed to the command's stdin (UTF-8); not supported on WinRM or Cisco. Default: none.
- `timeout` (number, default `60`, 1..1740): Seconds the command may run (at most 1740, below the call's 30 min); longer fails with a timeout error and returns no output.

#### `remote_script` — mutating · long (1800 s) · stdio + http · *backend*

Run a multi-line script on a remote host: sh, bash, python3 or perl on POSIX, PowerShell on WinRM.

**Use when:** the job needs loops or a scripting language there.

**Instead:** remote_exec for one command; script_run on this machine.

**Requires:** available only with --mcp-tools exec and --mcp-allow-exec; a backend from exec_backends; off in paranoid mode.

**Behavior:** destructive - runs with the profile user's rights. Not idempotent: it runs again. The script goes to the interpreter's stdin, so it cannot read stdin itself. Refused on production profiles and Cisco. Past timeout the call fails and no output returns.

**Returns:** {returncode, stdout, stderr, truncated_stdout, truncated_stderr} (text, UTF-8 with undecodable bytes replaced).

Needs: `--mcp-tools exec` `--mcp-allow-exec`.

- `script` (string, required): The script text, e.g. 'for f in /var/log/*.log; do wc -l "$f"; done'.
- `args` (array of string): Arguments passed to the script ($1... / sys.argv[1:]) as raw strings; the server shell-quotes each one. POSIX hosts only. Default: none.
- `env` (object): Environment variables for the script as {NAME: value}, e.g. {"LANG": "C"}. On POSIX shells they are exported in the command line, so other users of the host may see the values: pass no secrets this way.
- `interpreter` (string, one of `bash`, `perl`, `powershell`, `python3`, `sh`): What runs the script. Default: sh on POSIX hosts, powershell on WinRM (the only choice there).
- `max_output` (integer, default `1048576`, 1..16777216): Most bytes of stdout kept; stderr keeps min(max_output, 1 MiB). truncated_stdout / truncated_stderr tell when output was cut.
- `timeout` (number, default `60`, 1..1740): Seconds the script may run (at most 1740, below the call's 30 min); longer fails with a timeout error and returns no output.

#### `exec_backends` — read-only · quick (15 s) · stdio + http

List the open backends that can run commands.

**Use when:** choosing remote_exec's or remote_script's backend.

**Instead:** list_backends for all; remote_open to open more.

**Requires:** available only with --mcp-tools exec and --mcp-allow-exec.

**Behavior:** read-only; runs and opens nothing. Time limit: 15 s.

**Returns:** {backends: [{backend, class (the backend's implementation, e.g. 'SSHSession'), kind: posix-shell, powershell (WinRM) or ios-show (Cisco IOS, show commands only)}]}.

Needs: `--mcp-tools exec` `--mcp-allow-exec`.

### `extensions`

List installed extensions and whether they are enabled (read-only: extensions are GUI plugins).

#### `extensions_list` — read-only · quick (15 s) · stdio + http

List the installed axross extensions (app plugins) and their state.

**Use when:** asking which extensions exist, are on, or fail to load.

**Instead:** extensions_info for one by id.

**Requires:** available only with --mcp-tools extensions.

**Behavior:** read-only; imports nothing. Extensions add app menus only, so none runs over MCP; they are off in paranoid mode. Time limit: 15 s.

**Returns:** {allowed, why_not_runnable, extensions: [{id ('user:<name>' or 'bundled:<name>'), name, version, description, author, source, enabled (switched on in Extensions > Manage Extensions), loadable, error, active (loaded by the GUI: enabled, loadable and allowed)}]}.

Needs: `--mcp-tools extensions`.

#### `extensions_info` — read-only · quick (15 s) · stdio + http

Show one installed axross extension by id.

**Use when:** you have an id from extensions_list and need its state or error.

**Instead:** extensions_list to find ids.

**Requires:** available only with --mcp-tools extensions.

**Behavior:** read-only; imports nothing. An unknown id fails. Time limit: 15 s.

**Returns:** one extensions_list entry plus why_not_runnable.

Needs: `--mcp-tools extensions`.

- `ext_id` (string, required): The extension id from extensions_list, e.g. 'bundled:arcade' or 'user:my_tool'.

### `filetype`

Identify files by content (magic bytes), flag extension mismatches.

#### `file_type` — read-only · walk (60 s) · stdio + http · *backend*

Identify one file's real type from its content (magic bytes) and check the extension against it.

**Use when:** an extension may lie, or encoding and line endings matter.

**Instead:** file_type_scan for a folder; stat for size and date.

**Requires:** available only with --mcp-tools filetype.

**Behavior:** read-only; reads at most max_bytes. An unreadable or missing file is a result (kind error); reading gives up after 15 s per file (kind timeout). Refuses secret files. Time limit: 60 s.

**Returns:** {path, name, kind, verdict (match|mismatch|unknown), mime, extension, ...}; every field in outputSchema.

Needs: `--mcp-tools filetype`.

- `max_bytes` (integer, default `65536`, 1..1048576): Bytes read from the start of the file for the content check (64 KiB default, at most 1 MiB).
- `path` (string): The file to identify (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `use_file_command` (boolean, default `true`): Also run the file(1) command for its description (file_command); local regular files only, ignored on remote backends.

#### `file_type_scan` — read-only · stream (300 s) · stdio + http · *backend*

Identify the content type of every file under a folder and flag misleading extensions.

**Use when:** auditing a folder for disguised files (mismatches_only=true).

**Instead:** file_type for one file; walk for names only.

**Requires:** available only with --mcp-tools filetype.

**Behavior:** read-only, breadth-first, name order; symlinks are skipped. max_files or a folder at max_depth sets truncated; an unlistable folder goes to unreadable. Refuses secret files. Progress; cancellable. Time limit: 5 min.

**Returns:** {path, files_scanned, truncated, complete, unreadable (folder paths), entries: [file_type records]}; mismatches_only lists verdict=mismatch only.

Needs: `--mcp-tools filetype`.

- `max_bytes` (integer, default `65536`, 1..1048576): Bytes read from the start of each file for the content check (64 KiB default, at most 1 MiB).
- `max_depth` (integer, default `2`, 0..50): Counted from 0 (walk-style tools count from 1): 0 = path's own files, 1 = also its subfolders'.
- `max_files` (integer, default `500`, 1..5000): Stop after identifying this many files; more sets truncated=true.
- `mismatches_only` (boolean, default `false`): List only files whose content contradicts their extension.
- `path` (string): The folder to scan (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `use_file_command` (boolean, default `true`): Also run the file(1) command for its description (file_command); local regular files only, ignored on remote backends.

### `index`

Build or refresh the offline metadata index that the search tool reads.

#### `index_build` — read-only · long (1800 s) · stdio + http · *backend*

Record every entry under a folder (name, size, type, mtime) in the offline index that search reads.

**Use when:** before search, or to refresh it.

**Instead:** search to query; walk for the live state.

**Requires:** available only with --mcp-tools index.

**Behavior:** writes index rows, never files; reads listings only. Idempotent: a repeat changes nothing more. prune=true drops rows of files now gone. Linked folders are not followed; folders deeper than 50 levels go to unreadable. A cancelled run keeps its rows. Progress. Time limit: 30 min.

**Returns:** {path, backend_id, recursive, indexed, pruned, truncated (max_files), complete, unreadable (folder paths)}.

Needs: `--mcp-tools index`.

- `max_files` (integer, 1..1000000): Visit at most this many entries; reaching it stops the walk and sets truncated=true. Default 1,000,000 on the local backend, 100,000 on a remote one.
- `path` (string): The folder to index (absolute, or relative to the MCP root). Default on the local backend: the MCP root; other backends need it.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `prune` (boolean, default `false`): Afterwards drop index rows below the folder whose file is gone.
- `recursive` (boolean, default `true`): Also index the subfolders (false: the folder's own entries only).

### `metadata`

Show and export file metadata (EXIF/XMP/IPTC, Office, PDF, media tags); remove it (mutating, writes a cleaned copy).

#### `metadata_read` — read-only · stream (300 s) · stdio + http · *backend*

Read the embedded metadata (EXIF, XMP, document properties, tags) of a file or of every supported file in a folder.

**Use when:** checking what a photo, document or media file reveals before sharing it.

**Instead:** metadata_export for one JSON/CSV text; metadata_remove (needs --mcp-write) for cleaned copies.

**Requires:** available only with --mcp-tools metadata.

**Behavior:** read-only. Images, Office, PDF, audio/video (ffprobe, off in paranoid mode). A file it cannot read is a report with error set. Refuses secret files. Values are cut at 512 characters. Cancellable. Time limit: 5 min.

**Returns:** {path, is_dir, truncated, files: [{path, kind, error ('' when read), fields: [{group, name, value, removable}], ...}]}.

Needs: `--mcp-tools metadata`.

- `max_files` (integer, default `200`, 1..2000): For a folder: take at most this many files; more sets truncated=true. Ignored for a file.
- `path` (string): A file, or a folder whose supported files are read (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `recursive` (boolean, default `false`): For a folder: also take the files in its subfolders (false: the folder's own files only). Ignored for a file.

#### `metadata_export` — read-only · stream (300 s) · stdio + http · *backend*

Export the metadata_read data of a file or folder as one JSON or CSV text.

**Use when:** you need the metadata as a document to quote or diff.

**Instead:** metadata_read for structured fields; metadata_export_file (needs --mcp-write) for a file, better for big folders.

**Requires:** available only with --mcp-tools metadata.

**Behavior:** read-only; reads as metadata_read does. A result over 16 MiB fails. Time limit: 5 min.

**Returns:** {path, format, files (number of file reports), truncated, text}.

Needs: `--mcp-tools metadata`.

- `format` (string, one of `json`, `csv`, default `"json"`): Text format. json: {"files": [<metadata_read file report>, ...]}; csv: header path,kind,group,field,value,removable,error and one row per field, cells that would start a spreadsheet formula prefixed with '.
- `max_files` (integer, default `200`, 1..2000): For a folder: take at most this many files; more sets truncated=true. Ignored for a file.
- `path` (string): A file, or a folder whose supported files are read (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `recursive` (boolean, default `false`): For a folder: also take the files in its subfolders (false: the folder's own files only). Ignored for a file.

#### `metadata_export_file` — mutating · stream (300 s) · stdio + http · *backend*

Save the metadata_export text of path as a new file at out, on the same backend.

**Use when:** the export should stay on disk next to the data.

**Instead:** metadata_export for the text in the response.

**Requires:** available only with --mcp-tools metadata and --mcp-write.

**Behavior:** only adds; a taken name gets a counter ('meta (2).json'). Not idempotent: each call adds a file. Written via a temporary name; new local files are mode 0600. Write guards apply. Time limit: 5 min.

**Returns:** {path (the file written, not the source), format, files, truncated, size (bytes)}.

Needs: `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR`.

- `format` (string, one of `json`, `csv`, default `"json"`): Text format. json: {"files": [<metadata_read file report>, ...]}; csv: header path,kind,group,field,value,removable,error and one row per field, cells that would start a spreadsheet formula prefixed with '.
- `max_files` (integer, default `200`, 1..2000): For a folder: take at most this many files; more sets truncated=true. Ignored for a file.
- `out` (string): The new file on path's backend (absolute, or relative to the MCP root); its folder must exist. A taken name gets a counter. Required unless out_b64 is given.
- `out_b64` (string): out as base64 of its raw bytes, for non-UTF-8 names; replaces out.
- `path` (string): A file, or a folder whose supported files are read (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `recursive` (boolean, default `false`): For a folder: also take the files in its subfolders (false: the folder's own files only). Ignored for a file.

#### `metadata_remove` — mutating · long (1800 s) · stdio + http · *backend*

Strip the metadata of a file, or of each supported file in a folder, into cleaned copies next to the originals.

**Use when:** sharing a file without its camera, GPS or author data; look with metadata_read first.

**Instead:** metadata_export_file to keep the metadata as a record.

**Requires:** available only with --mcp-tools metadata and --mcp-write; PDF needs pypdf; audio/video ffmpeg, off in paranoid mode.

**Behavior:** only adds; originals stay ('photo.jpg' -> 'photo.clean.jpg', taken: 'photo.clean (1).jpg'); no in-place mode. Not idempotent: a repeat writes another copy. A missing file fails. Refuses secret files. Write guards apply. Progress; cancellable. Time limit: 30 min.

**Returns:** {path, truncated, results: [{path, status, output (the copy), removed (fields), sha256, error}]}; status: cleaned, unchanged, unsupported, skipped (read-only folder) or error.

Needs: `--mcp-tools metadata` `--mcp-write` `--mcp-root DIR`.

- `max_files` (integer, default `200`, 1..2000): For a folder: take at most this many files; more sets truncated=true. Ignored for a file.
- `path` (string): A file, or a folder whose supported files are cleaned (absolute, or relative to the MCP root). Required unless path_b64 is given.
- `path_b64` (string): path as base64 of its raw bytes, for non-UTF-8 names; replaces path.
- `recursive` (boolean, default `false`): For a folder: also take the files in its subfolders (false: the folder's own files only). Ignored for a file.

### `packer`

List archive formats; pack files and folders into zip / tar.* / 7z / single-file compression, 7z optionally AES-256 encrypted (mutating).

#### `pack_formats` — read-only · quick (15 s) · stdio + http

List the archive formats pack can write and whether each works here.

**Use when:** before pack, to pick an available format.

**Instead:** archive_list to read an archive; pack (needs --mcp-write) to create one.

**Requires:** available only with --mcp-tools packer.

**Behavior:** read-only, no arguments; availability depends on installed packages (zstd, py7zr). Time limit: 15 s.

**Returns:** {formats: [{format, label, suffix, single (one file in), encrypts (takes a password), available, reason}], levels (what pack's level takes)}.

Needs: `--mcp-tools packer`.

#### `pack` — mutating · long (1800 s) · stdio + http · *backend*

Pack entries of one folder into a new archive in that folder.

**Use when:** bundling or compressing files, optionally with a 7z password.

**Instead:** pack_formats for formats; archive_extract to unpack; encrypt for one file.

**Requires:** available only with --mcp-tools packer and --mcp-write.

**Behavior:** any backend (bytes pass through this machine). Only adds: a taken name gets a counter ('bundle (2).zip'). Not idempotent: each call adds an archive. A failure leaves nothing. Symlinks and secret files go to skipped. Write guards apply. Progress. Time limit: 30 min.

**Returns:** {path, format, files, folders, bytes_in, bytes_out, skipped, encrypted}.

Needs: `--mcp-tools packer` `--mcp-write` `--mcp-root DIR`.

- `archive_name` (string, required): Archive file name without a folder, e.g. 'bundle'; the format's suffix (.zip, .tar.gz, ...) is added when missing.
- `encrypt_names` (boolean, default `true`): 7z with a password: also encrypt the file list, so names are hidden without the password. Ignored otherwise.
- `folder` (string): The folder holding the entries (absolute, or relative to the MCP root); the archive is created in it. Required unless folder_b64 is given.
- `folder_b64` (string): folder as base64 of its raw bytes, for non-UTF-8 names; replaces folder.
- `format` (string, one of `zip`, `tar.gz`, `tar.zst`, `tar.xz`, `tar.bz2`, `7z`, `gz`, `zst`, `xz`, `bz2`, default `"zip"`): Archive format; pack_formats tells which are available here. gz, zst, xz and bz2 compress exactly one file.
- `level` (string, one of `fast`, `normal`, `best`, default `"normal"`): Compression level: fast (larger, quicker), normal or best (smallest, slowest).
- `names` (array of string): Names of files or folders directly inside folder, e.g. ['report.pdf', 'images']; no path separators, no repeats. Required unless names_b64 is given.
- `names_b64` (array of string): names as base64 of each name's raw bytes, for non-UTF-8 names; replaces names.
- `password` (string, secret, never echoed): 7z only: encrypt the archive with AES-256 using this password; any other format fails with one. Never logged or returned.

### `remote`

List saved connection profiles (no secrets), open one as an extra backend that every tool can address with its backend argument, close it again.

#### `remote_profiles` — read-only · quick (15 s) · stdio + http

List the saved connection profiles (SFTP, SMB, WebDAV, S3 ...) and whether remote_open can open each.

**Use when:** finding the name to pass to remote_open.

**Instead:** list_backends for what is open now.

**Requires:** available only with --mcp-tools remote.

**Behavior:** read-only; no network, no keyring, never a secret. Time limit: 15 s.

**Returns:** {profiles: [{name, protocol, host, port, username, auth_type, store_password (a password is kept), production, open_as (its backend id when open), openable, reason}]}, by name.

Needs: `--mcp-tools remote`.

#### `remote_open` — read-only · walk (60 s) · stdio + http

Connect a saved profile as backend 'profile:<name>' for this session.

**Use when:** files on a remote server or cloud store are needed.

**Instead:** remote_profiles to list profiles; remote_close when done.

**Requires:** available only with --mcp-tools remote; a profile that needs no prompt (password in the keyring, host key trusted).

**Behavior:** changes no files; opens a network connection and holds one of 8 session slots (a ninth fails: 'call remote_close first'). Idempotent: a repeat changes nothing more; it returns the open one (reused=true). Remote paths are outside --mcp-root; production profiles are read-only. Time limit: 60 s.

**Returns:** {backend, profile, protocol, class (the backend's implementation, e.g. 'SSHSession'), production, writable, reused}.

Needs: `--mcp-tools remote`.

- `profile` (string, required): The saved profile's name, exactly as remote_profiles lists it, e.g. 'nas'.

#### `remote_close` — read-only · quick (15 s) · stdio + http · *backend*

Disconnect a profile that remote_open opened in this session.

**Use when:** done with a remote backend, or to free a slot.

**Instead:** list_backends to see what is open.

**Requires:** available only with --mcp-tools remote.

**Behavior:** changes no files; the id stops working and calls stuck on it end. Idempotent: a repeat changes nothing more; it fails with 'no open backend'. A connection lent by an axross pane is refused. Time limit: 15 s.

**Returns:** {backend, closed: true}.

Needs: `--mcp-tools remote`.

#### `list_backends` — read-only · quick (15 s) · stdio + http

List the backend ids this session can address, the default marked.

**Use when:** choosing another tool's backend argument, e.g. after remote_open.

**Instead:** remote_profiles for saved connections; exec_backends for those that run commands.

**Behavior:** read-only; connects nothing. Served whenever tools take a backend argument. Time limit: 15 s.

**Returns:** a JSON array of {id, class (the backend's implementation, e.g. 'SSHSession'), name, is_default, remote}, opened profiles add {profile, protocol, production}; structuredContent: {backends}.

Needs: `--mcp-tools remote`.

### `transfer`

Copy or move files and folders between backends, optionally resumable (mutating).

#### `transfer_copy` — mutating · long (1800 s) · stdio + http

Copy a file or folder tree from one backend to another, or within one.

**Use when:** data must cross backends, or a big copy should be resumable.

**Instead:** copy or bulk_copy within one backend; transfer_move to move one file.

**Requires:** available only with --mcp-tools transfer and --mcp-write.

**Behavior:** never changes the source. Existing files are skipped unless overwrite=true (destructive). Idempotent: a repeat changes nothing more. Regular files only; whatever is left out gets a reason. resumable=true and the same arguments continue an interrupted run; without it a partial file starts over. Mode and mtime are not kept (new local files 0600). Refuses secret files. Write guards apply. Progress; cancellable. Time limit: 30 min.

**Returns:** {src, dst, copied, truncated, complete, entries}; reasons in outputSchema.

Needs: `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR`.

- `dst` (string): Destination on dst_backend (absolute, or relative to the MCP root): the file, or for a source folder the folder that becomes its copy. Parents are created. Required unless dst_b64 is given.
- `dst_b64` (string): dst as base64 of its raw bytes, for non-UTF-8 names; replaces dst.
- `dst_backend` (string): Backend id of the destination, from list_backends; omit for the default backend.
- `max_depth` (integer, default `10`, 0..50): Counted from 0 (walk-style tools count from 1): 0 = src's own files, 1 = also its subfolders'.
- `max_file_bytes` (integer, default `10737418240`, 1..1125899906842624): Skip files larger than this many bytes (reason too-large), also when a source sends more than it reported. Default 10 GiB.
- `max_files` (integer, default `1000`, 1..10000): Copy at most this many files; more sets truncated=true.
- `overwrite` (boolean, default `false`): Replace destination files that exist (false: skip them, reason exists).
- `resumable` (boolean, default `false`): Copy in 4 MiB segments that a repeated call can resume after an interruption.
- `src` (string): Source path on src_backend (absolute, or relative to the MCP root). Required unless src_b64 is given.
- `src_b64` (string): src as base64 of its raw bytes, for non-UTF-8 names; replaces src.
- `src_backend` (string): Backend id of the source, from list_backends, e.g. 'profile:nas'; omit for the default backend.

#### `transfer_move` — mutating · long (1800 s) · stdio + http

Move one file to another backend: copy, check the byte count, delete the source.

**Use when:** a file must leave one backend for another.

**Instead:** rename within one backend (folders too); for a folder across backends transfer_copy, then remove.

**Requires:** available only with --mcp-tools transfer and --mcp-write.

**Behavior:** destructive for the source, deleted only after a complete copy. Idempotent: a repeat changes nothing more; it fails with 'destination exists'. An existing destination or a folder fails. Refuses secret files. Write guards apply. Time limit: 30 min.

**Returns:** {src, dst, bytes}.

Needs: `--mcp-tools transfer` `--mcp-write` `--mcp-root DIR`.

- `dst` (string): The destination file on dst_backend (absolute, or relative to the MCP root); it must not exist. Parents are created. Required unless dst_b64 is given.
- `dst_b64` (string): dst as base64 of its raw bytes, for non-UTF-8 names; replaces dst.
- `dst_backend` (string): Backend id of the destination, from list_backends; omit for the default backend.
- `src` (string): The source file on src_backend, not a folder (absolute, or relative to the MCP root). Required unless src_b64 is given.
- `src_b64` (string): src as base64 of its raw bytes, for non-UTF-8 names; replaces src.
- `src_backend` (string): Backend id of the source, from list_backends, e.g. 'profile:nas'; omit for the default backend.

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
| `TypeError` | `Exception` | The session is the wrong kind for the helper (exec() on S3, query() on a session that is not a database) or an argument has the wrong type. | Check the session's protocol and the signature. |
| `ValueError` | `Exception` | An argument value is invalid: an unknown URL scheme, a port out of range, a script name outside [A-Za-z0-9_-], an unknown mode or format. | Fix the argument; the message names it. |
| `KeyboardInterrupt` | `BaseException` | Someone stopped the production countdown before a change. | Do not repeat the change. |

### Open / connect

- `axross.open(profile_name: str, password: str | None = None, key_passphrase: str | None = None) -> FileBackend` — read-only · prompts (NonInteractiveError without a human) · raises KeyError. Open a backend by saved profile name. Returns a FileBackend session. Raises :class:`KeyError` if the profile doesn't exist and :class:`OSError` for connection failure.
- `axross.open_url(url: str, **kwargs: Any) -> FileBackend` — read-only · prompts (NonInteractiveError without a human) · raises TypeError, ValueError. Open a backend from a URL like ``sftp://user@host/``, ``s3://bucket``, ``smb://server/share``, ``gopher://host:70``.
- `axross.localfs() -> LocalFS` — read-only. Return a LocalFS session pointed at the host's filesystem.
- `axross.ramfs(max_bytes: int | None = None) -> RamFsSession` — read-only. Return a fresh RamFS session — bytes never touch disk. ``max_bytes`` overrides the default per-instance cap.
- `axross.list_profiles() -> list[str]` — read-only. Return the names of all saved connection profiles.
- `axross.get_profile(name: str) -> ConnectionProfile | None` — read-only. Look up a saved :class:`ConnectionProfile` by name.
- `axross.save_profile(profile: ConnectionProfile) -> None` — mutates · raises OSError. Persist a :class:`core.profiles.ConnectionProfile`. The profile object itself can be constructed via ``ConnectionProfile(name=..., protocol=..., host=...)`` — see ``help(core.profiles.ConnectionProfile)``. Raises OSError when the profiles file could not be written.
- `axross.delete_profile(name: str) -> None` — mutates · raises OSError. Delete a saved profile by name. No-op if the profile doesn't exist. Raises OSError when the profiles file could not be written.
- `axross.list_backends() -> list[str]` — read-only. Return the protocol IDs of every registered backend (sftp, smb, s3, …) regardless of whether the optional dependency is installed. Use :func:`available_backends` for the installed subset.
- `axross.available_backends() -> list[str]` — read-only. Return the protocol IDs of backends whose dependencies are actually installed.

### File I/O

- `axross.copy(src_backend: FileBackend, src_path: str, dst_backend: FileBackend, dst_path: str, buffer_size: int = 1048576, *, overwrite: bool = False) -> int` — mutates · prompts (NonInteractiveError without a human) · raises FileExistsError, OSError. Copy bytes from one backend to another. Returns the number of bytes transferred. Same-backend copies use the backend's native ``copy()`` if available; cross-backend copies always stream.
- `axross.move(src_backend: FileBackend, src_path: str, dst_backend: FileBackend, dst_path: str, *, overwrite: bool = False) -> int` — mutates · prompts (NonInteractiveError without a human) · raises FileExistsError, OSError. Move a file from one backend to another. Same-backend uses rename; cross-backend uses copy + delete-source.
- `axross.remove(backend: FileBackend, path: str, *, recursive: bool = False, confirm: bool = False, keep_namespace_root: bool = False, follow_dfs_link: bool = False, confirm_alias: bool = False) -> str` — mutates · prompts (NonInteractiveError without a human) · raises PermissionError. Delete ``path`` from ``backend`` after an explicit opt-in.
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
- `axross.add_bookmark(name: str, path: str, backend_name: str = 'Local', profile_name: str = '', icon_name: str = 'bookmark') -> None` — mutates. Create a new bookmark. Idempotent on (path, backend_name). Raises OSError when the bookmarks file could not be written.
- `axross.remove_bookmark(index: int) -> None` — mutates · raises IndexError. Remove the bookmark at ``index`` (zero-based, as :func:`list_bookmarks` lists them). Raises IndexError for an index outside that list (also a negative one) and OSError when the bookmarks file could not be written.
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
- `axross.imap_move(backend: FileBackend, uid: int, src_mailbox: str, dst_mailbox: str) -> None` — mutates · raises TypeError. Move an IMAP message by UID. Uses MOVE if the server supports it; otherwise COPY, flag the source \Deleted and expunge it - by UID (UIDPLUS), or with a plain EXPUNGE only when no other message in the source mailbox is flagged \Deleted (it would be expunged too); in that case the move is refused before anything is copied. A stale UID raises FileNotFoundError. See ``ImapSession.move``.
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
- `axross.snmp_get(host: str, oid: str, *, community: str = 'public', port: int = 161, timeout: float = 3.0, retries: int = 1, user: str | None = None, auth_key: str | None = None, priv_key: str | None = None, auth_proto: str | None = None, priv_proto: str | None = None) -> SnmpVar` — read-only · raises FileNotFoundError, OSError, ValueError. Issue a single SNMP GET request. Returns one ``SnmpVar`` for the OID. Raises ``OSError`` on transport failure.
- `axross.snmp_walk(host: str, base_oid: str, *, community: str = 'public', port: int = 161, timeout: float = 3.0, retries: int = 1, max_vars: int = 10000, user: str | None = None, auth_key: str | None = None, priv_key: str | None = None, auth_proto: str | None = None, priv_proto: str | None = None) -> list[SnmpVar]` — read-only · raises OSError, ValueError. Walk an OID subtree, returning every leaf as an ``SnmpVar``. ``max_vars`` caps the result at a sane number — a walk of ``1.3`` on a packed device returns thousands of varbinds.
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

- `axross.serve_s3(backend: FileBackend, *, bind: str = '127.0.0.1', port: int = 9000, read_only: bool = False, auth_token: str | None = '', root_path: str = '/', cert_file: str | None = None, key_file: str | None = None, allow_insecure_http: bool = False) -> ReverseServer` — mutates. Expose ``backend`` as a minimum-viable S3 endpoint so any existing S3 client (aws-cli / restic / rclone / terraform) can speak to it.
- `axross.serve_webdav(backend: FileBackend, *, bind: str = '127.0.0.1', port: int = 8080, read_only: bool = False, auth_token: str | None = '', root_path: str = '/', cert_file: str | None = None, key_file: str | None = None, allow_insecure_http: bool = False) -> ReverseServer` — mutates. Expose ``backend`` as a minimum-viable WebDAV endpoint — ``davfs2 mount``, gnome-files (``davs://``), macOS Finder, browser read-only listings all work; they ask for the token as the password (any user name). Same token and TLS rules as :func:`serve_s3` (``cert_file`` / ``key_file`` / ``allow_insecure_http``). Returns a :class:`core.reverse_serve.ReverseServer`.

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
- `CasEntry` (class, `core.cas`): backend_id, path, algorithm, value, size, indexed_at, mtime, scan_id, file_id — One row from the CAS index.
- `CompareReport` (class, `core.multi_view`): path, probes, content_diff, all_equal() — Result of comparing the SAME path across N backends.
- `ConnectionProfile` (class, `core.profiles`): name, protocol, host, port, username, auth_type, key_file, store_password, proxy_mode, proxy_type, proxy_host, proxy_port, proxy_username, store_proxy_password, proxy_command, proxy_command_confirmed, _proxy_password_override, address_family, ftp_passive, ftps_verify_tls, smb_share, webdav_url, s3_bucket, s3_region, s3_endpoint, rsync_module, rsync_ssh, rsync_ssh_key, nfs_export, nfs_version, nfs_minor, nfs_machine_name, nfs_uid, nfs_gid, nfs_gids, nfs_privileged_port, nfs_client_id, azure_container, azure_connection_string, azure_account_name, azure_sas_token, azure_share, onedrive_client_id, onedrive_tenant_id, sharepoint_site_url, gdrive_client_id, gdrive_client_secret, dropbox_app_key, dropbox_app_secret, iscsi_target_iqn, iscsi_mount_point, iscsi_initiator_name, iscsi_initiator_interface, imap_ssl, imap_starttls, pop3_ssl, pop3_starttls, nntp_ssl, tftp_filelist, tftp_filelist_enabled, tftp_max_size_bytes, db_name, db_tls, ldap_ssl, ldap_starttls, slp_scope, exchange_email, adb_mode, adb_usb_serial, mtp_device_id, mtp_mounter, ssh_keepalive_interval, sftp_timeout, smb_client_name, telnet_naws_width, telnet_naws_height, rsync_preserve_metadata, winrm_https, winrm_verify_tls, suppress_shell_history, terminal_theme, production, get_password(), get_proxy_password(), nfs_sender_chosen(), set_password(), set_proxy_password(), tls_mode(), to_dict() — A saved connection profile (multi-protocol).
- `Credential` (class, `core.cred_attack`): username, password — A pair of (username, password) the loop discovered as valid.
- `DedupeResult` (class, `core.cas`): dry_run, groups, keep, trash, undated_groups, removed, refused, failed, render() — What :func:`dedupe` planned and, unless a dry run, did.
- `EnumReport` (class, `core.cred_attack`): target_protocol, target_host, started_at, finished_at, results, hits(), summary() — EnumReport(target_protocol: 'str', target_host: 'str', started_at: 'float', finished_at: 'float', results: 'list[EnumResult]' = <factory>)
- `EnumResult` (class, `core.cred_attack`): username, likely_exists, confidence, method, notes — Per-candidate enumeration verdict.
- `ExecResult` (class, `models.exec_result`): returncode, stdout, stderr, truncated_stdout, truncated_stderr, ok, check() — ExecResult(returncode: 'int', stdout: 'bytes', stderr: 'bytes', truncated_stdout: 'bool' = False, truncated_stderr: 'bool' = False)
- `ExplainResult` (class, `core.inspect`): label, confidence, evidence, hint, render() — Heuristic verdict on what a directory IS.
- `Field` (class, `core.metadata_formats`): group, name, value, removable — Field(group: 'str', name: 'str', value: 'str', removable: 'bool' = True)
- `FileItem` (class, `models.file_item`): name, size, modified, permissions, is_dir, is_link, link_target, owner, group, accessed, created, attr_hidden, stat_error, is_hidden, is_nav, mode_str, permissions_str, size_human, type_char — Represents a single file or directory entry, local or remote.
- `FileTypeInfo` (class, `core.file_type`): path, name, kind, description, mime, extension, extension_mime, verdict, size, encoding, line_endings, engine, file_command, bytes_read, error, mismatch, summary() — What one file really is.
- `FileVersion` (class, `models.file_version`): version_id, modified, size, is_current, label — One historical revision of a file.
- `HealthRecord` (class, `core.conn_health`): profile_key, protocol, label, enrolled_at, last_probe_at, last_latency_s, consecutive_failures, stale, history, healthy, median_latency_s — HealthRecord(profile_key: 'str', protocol: 'str', label: 'str', enrolled_at: 'float' = <factory>, last_probe_at: 'float' = 0.0, last_latency_s: 'float | None' = None, consecutive_failures: 'int' = 0, stale: 'bool' = False, history: 'list[HealthSample]' = <factory>)
- `HealthSample` (class, `core.conn_health`): ts, latency_s, error — HealthSample(ts: 'float', latency_s: 'float | None', error: 'str' = '')
- `HostVisit` (class, `core.visit_history`): protocol, host, username, last_path, last_seen, visit_count, recent_ops, key — Last-visited state for one (protocol, host, username) triple.
- `InspectReport` (class, `core.multi_view`): targets, hashes_consistent() — Result of inspecting an arbitrary list of (backend, path) pairs.
- `InteractiveShell` (class, `models.interactive_shell`): closed, label, close(), fileno(), interact(), read(), read_stderr(), read_until(), resize_pty(), write() — Thin wrapper around a paramiko ``Channel`` in shell+PTY mode.
- `LocalFS` (session, `core.local_fs`): local_path(), private_writes(), rename_no_replace(), same_file(), set_modified() — Local filesystem backend implementing the FileBackend protocol.
- `MetadataReport` (class, `core.metadata_tools`): path, name, kind, fields, error, size, truncated, removable, to_dict() — What one file carries. ``error`` is set when it could not be read (completely); ``fields`` may still hold what was read before that.
- `RamFsSession` (session, `core.ram_fs`): connected, max_bytes, size_bytes, disconnect() — In-process RAM-backed FileBackend.
- `ResumeReport` (class, `core.copy_resume`): src_label, src_path, dst_label, dst_path, total_bytes, bytes_transferred, segments_skipped, segments_transferred, elapsed_s, manifest_path, completed, summary() — ResumeReport(src_label: 'str', src_path: 'str', dst_label: 'str', dst_path: 'str', total_bytes: 'int', bytes_transferred: 'int', segments_skipped: 'int', segments_transferred: 'int', elapsed_s: 'float', manifest_path: 'str', completed: 'bool')
- `ReverseServer` (class, `core.reverse_serve`): flavour, bind, port, backend_label, httpd, thread, auth_token, tls, base_url, shutdown() — Live handle on a running reverse-server.
- `ScanRecord` (class, `core.cas`): scan_id, backend_id, root, algorithm, started_at, finished_at, files_indexed, status, files_in_index, duplicate_groups, error — One rebuild of the index, as the history shows it.
- `SearchHit` (class, `core.search_federation`): backend_label, path, size, mtime, is_dir, snippet, score, warning, category, archive_path, member — One result row.
- `SearchQuery` (class, `core.search_federation`): name, regex, contains, contains_is_regex, min_size, max_size, modified_after, modified_before, roots, max_depth, ignore_dirs, categories, search_archives, include_hidden, case_sensitive, _compiled_regex, _compiled_contains, _folded_name, _folded_name_for, contains_regex(), matches_mtime(), matches_name(), matches_size(), validate() — What to search for.
- `SearchResult` (class, `core.search_federation`): hits, per_backend, errors, elapsed_s, truncated — Aggregated federation result.
- `Snapshot` (class, `core.trail`): snapshot_id, trail_name, ts, file_count, total_bytes, tree_hash, truncated — Snapshot(snapshot_id: 'int', trail_name: 'str', ts: 'float', file_count: 'int', total_bytes: 'int', tree_hash: 'str', truncated: 'bool' = False)
- `Summary` (class, `core.inspect`): backend_label, path, file_count, dir_count, link_count, total_bytes, extensions, age_buckets, largest, newest, oldest, truncated, error, render() — Structured directory snapshot.
- `TargetProbe` (class, `core.multi_view`): label, path, exists, size, mtime, permissions, is_dir, is_link, sha256, content, truncated, error, elapsed_s — One backend × one path probe result.
- `TrailDiff` (class, `core.trail`): added, removed, modified, unchanged, is_empty(), summary() — Diff between two snapshots of the same trail.

<!-- END GENERATED SCRIPTING CATALOG -->
