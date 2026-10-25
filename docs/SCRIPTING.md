# Scripting & REPL

Axross is more than a file manager — it ships an **embedded Python
REPL**, a **curated `axross.*` API** that wraps every backend, a
**searchable doc pane**, a **persistent script directory**, and a
**MCP-tool surface** that lets an LLM agent write & run its own
scripts.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

**Contents**

- [The ways to run code against axross](#the-ways-to-run-code-against-axross)
- [The Scripts dock](#the-scripts-dock)
- [The `axross.*` API](#the-axross-api)
  - [Open / connect](#open--connect)
  - [File I/O](#file-io)
  - [Encryption + archives](#encryption--archives)
  - [Bookmarks](#bookmarks)
  - [Script directory](#script-directory)
  - [Per-protocol passthroughs](#per-protocol-passthroughs)
  - [Network helpers](#network-helpers)
  - [File metadata](#file-metadata)
  - [Safety + diagnostics](#safety--diagnostics)
  - [Duplicate index](#duplicate-index)
- [REPL slash-commands](#repl-slash-commands)
- [Bundled example scripts](#bundled-example-scripts)
- [The MCP tool surface](#the-mcp-tool-surface)
- [Scripts a machine runs](#scripts-a-machine-runs)
- [See also](#see-also)

---

## The ways to run code against axross

| Surface | When | Entry point |
|---|---|---|
| **Scripts dock** | Write, save, manage and run scripts in the GUI | *View > Panels > Scripts* (next to *Console*) |
| **Console dock** (REPL) | Interactive exploration inside the GUI | Bottom dock, *Console* tab |
| **`axross --script <file>`** | Headless / cron / CI | `axross --script myscript.py` |
| **REPL slash-commands** | Save / load / run scripts from the prompt | `.save name`, `.run name` |
| **Scheduled jobs** | Run a saved script on an interval | *View > Scheduled Jobs…* |
| **MCP `script_*` tools** | LLM agent drives axross | Run with `--mcp-allow-scripts` |

Every surface uses the same `core.scripting` module under the hood,
so anything you can do at the REPL, you can do in a script,
headless, or through an LLM. *Help > Scripting Guide* shows this guide
and the full API reference inside the app; *F1* lists the Scripts dock
keys and the slash-commands.

---

## The Scripts dock

*View > Panels > Scripts* opens the script manager, tabbed next to the
Console. Left: your saved scripts (`~/.config/axross/scripts/`) and the
bundled **Examples**. Centre: a Python editor with syntax highlighting,
line numbers and auto-indent (Tab inserts four spaces, Shift+Tab
dedents, both on a whole selection). Bottom: the output of the last run.

| Action | What it does |
|---|---|
| **New** | Creates `<name>.py` from a short template (names: letters, digits, `_`, `-`) |
| **Save** (Ctrl+S) | Writes the editor text (mode 0600). An edited script shows `*` |
| **Save As…** | Saves the editor text under a new name; the original file is unchanged |
| **Rename…** / **Delete** | Rename or delete the file; Delete asks first |
| **Run** (Ctrl+Return) | Saves unsaved edits, then runs the script **in its own Python process** |
| **Stop** | Terminates the run; kills it if it has not ended after 3 s |
| **Run in Console** | Runs the saved script in the Console's live namespace (like `.run`) |
| **Copy to My Scripts** | Makes an editable copy of a bundled example (examples are read-only); its end carries the example's call as a commented "Try it" section |
| **Run** / **Run in Console** on an example | Shows the example's Usage call to adjust (paths, hosts, profiles), then runs the example with it |

How a run behaves:

- The child runs with the same `axross` namespace as `axross --script`
  (`__name__ == "__main__"`, `__file__` is the script path), in the
  script directory, isolated with `python -I` so a saved script called
  `json.py` cannot replace the stdlib for the others. The window never
  waits for it; one run at a time.
- stdout and stderr (red) stream into the output pane, which keeps the
  newest 10 000 lines and cuts lines over 1 000 characters. The status
  line shows the exit status and the duration, or *stopped*.
- A traceback line that points into the script is a link: click it to
  jump to that line in the editor.
- Closing the window stops a running script. Switching to another
  script, or closing the window, with unsaved edits asks to save,
  discard or cancel.
- There is no terminal in a separate run: `axross.confirm()` raises
  `axross.NonInteractiveError` instead of answering for you (pass
  `assume_yes=True` to answer yes without asking), and
  `axross.message()` prints. Use **Run in Console** for scripts that
  need dialogs — they then run on the GUI thread, and the window waits
  until they finish.
- Scripts that a scheduled job runs are marked `[scheduled]`; renaming
  or deleting one warns first, because the job refers to it by name.
- In **paranoid** security mode (*Edit > Settings > Security*) Run
  and Run in Console are disabled (the tooltip says why); `.run` and
  the child process refuse as well.

---

## The `axross.*` API

The curated namespace covers **over a hundred public names**
(`len(axross.__all__)`; `axross.api_schema()` lists every one) across connect/backend,
profiles, file I/O, crypto/archives, bookmarks, scripts, per-protocol
passthroughs, DNS/net, network helpers, SNMP, cross-backend search,
content inspection, safety/diagnostics, UI helpers and reference.
Every function has a docstring; the REPL's doc pane and
`axross.help()` both pull straight from those.

### Open / connect

```python
b = axross.open("backup-server")            # by saved profile name
b = axross.open_url("sftp://alice@host/")   # by URL
local = axross.localfs()                     # the host's filesystem
ram = axross.ramfs(max_bytes=64 * 1024 ** 2) # in-process volatile workspace

axross.list_profiles()      # names of saved profiles
axross.get_profile(name)    # get the ConnectionProfile
axross.save_profile(p)      # add or replace
axross.delete_profile(name)

axross.list_backends()      # all registered protocols
axross.available_backends() # only the ones whose deps are installed
```

### File I/O

```python
axross.copy(b1, src, b2, dst)       # cross-backend copy
axross.move(b1, src, b2, dst)       # cross-backend move (rename or copy+delete)
axross.copy(b1, src, b2, dst, overwrite=True)  # explicit replacement
axross.remove(b, path, confirm=True)           # permanent delete
axross.trash(b, path, confirm=True)            # recoverable delete
axross.checksum(b, path)            # native checksum if cheap, else streaming hash
axross.read_bytes(b, path)
axross.write_bytes(b, path, data, overwrite=True)
axross.read_text(b, path)
axross.write_text(b, path, text, overwrite=True)
axross.hash_bytes(data, "sha256")
axross.hash_file(b, path, "sha256")
```

Copy/write/encrypt refuse existing targets by default. Pass
`overwrite=True` only when replacement is intentional. `remove()` and
`trash()` require `confirm=True` so headless scripts do not delete on
accident.

### Encryption + archives

```python
axross.encrypt(b, "/secret.txt", "passphrase")     # keeps /secret.txt
axross.encrypt(b, "/secret.txt", "passphrase", keep_original=False)
axross.decrypt(b, "/secret.txt.axenc", "passphrase")
axross.extract_archive("/tmp/x.zip", "/tmp/out")   # zip-bomb / zip-slip guarded
axross.is_archive("/tmp/x.zip")
```

### Bookmarks

```python
axross.list_bookmarks()
axross.add_bookmark(name="logs", path="/var/log", backend_name="Local")
axross.remove_bookmark(index)
```

### Script directory

```python
axross.script_dir()                   # ~/.config/axross/scripts/, mode 0700
axross.list_scripts()                 # every saved script name
axross.save_script("hello", "...")    # mode 0600 from birth
axross.load_script("hello")           # source as str
axross.run_script("hello")            # exec in a fresh ns; returns the ns
axross.delete_script("hello")
```

### Per-protocol passthroughs

```python
axross.find_tftp_files(tftp_session)              # bundled wordlist + cache
axross.slp_discover("10.0.0.10", scope="DEFAULT") # CVE-2023-29552 mitigated
axross.nntp_post(nntp_session, "alt.test", subject, body)
axross.git_push(git_session)                      # FF-only, no force-push
```

### Network helpers

```python
axross.dns_resolve("example.com", family="any")
axross.port_open("10.0.0.1", 22, timeout=3.0)
```

### File metadata

```python
report = axross.metadata(b, "/photos/IMG_0001.jpg")      # MetadataReport
for f in report.fields:
    print(f.group, f.name, f.value, "kept" if not f.removable else "")
axross.remove_metadata(b, "/photos/IMG_0001.jpg")        # in place, Ctrl+Z restores
axross.remove_metadata(b, "/photos", recursive=True, mode="copy")  # name.clean.ext
axross.export_metadata(b, "/photos", fmt="csv", recursive=True, out="/tmp/meta.csv")
```

Images keep only the EXIF orientation and the ICC profile and are never
re-encoded; PDF removal needs the `[metadata]` extra (pypdf), audio /
video needs ffmpeg. One `remove_metadata` call is one undo step.

### Safety + diagnostics

```python
axross.preview_delete(local, ["/tmp/old"])
axross.preview_transfer(src, dst, ["/logs"], "/backup", operation="copy")
axross.diagnose(src, root="/", write_test=False)
axross.recovery_scan(src, "/")
axross.recent_operations(20)
axross.security_mode("paranoid")  # block previews, scripts and legacy protocols
```

### Duplicate index

The Duplicate Finder's index (*View > Duplicate Finder…*, Ctrl+Shift+D)
and its scan history (*View > Duplicate Index & History…*). Every group
lists its copies in survivor order: the oldest by modification time
first, ties to the shorter, then the alphabetically first path; copies
without a time sort last.

```python
for scan in axross.duplicate_scans():            # newest first
    print(scan.scan_id, scan.status, scan.root, scan.duplicate_groups)
groups = axross.duplicates(folder="/home/me/Photos")   # or scan=<id>
plan = axross.dedupe(folder="/home/me/Photos")   # dry run: nothing touched
print(plan.render())                             # keep / trash per group
axross.dedupe(folder="/home/me/Photos", dry_run=False)  # to the axross trash
```

`dedupe(dry_run=False)` keeps the first copy of every group and moves the
others to the axross trash (restorable), after re-checking each file and
the kept copy on the live backend; it acts only on the `backends` you pass
(default: the local filesystem).

---

## REPL slash-commands

Typed at the `>>> ` prompt; not Python. They never touch the
interpreter namespace.

| Command | Effect |
|---|---|
| `.help` | This list |
| `.scripts` | Names of every saved script |
| `.save <name>` | Save the current session's history into `<name>.py` |
| `.load <name>` | Print the source of a saved script |
| `.run <name>` | Execute a saved script in the live REPL namespace (refused in paranoid mode) |
| `.delete <name>` | Remove a saved script |
| `.open` | Print the script-directory path |

---

## Bundled example scripts

32 example scripts under `resources/scripts/`. Each defines functions;
the `Usage::` block of its docstring shows the call, so a file run as it
is prints nothing. In the GUI they are listed under **Examples** in the
Scripts dock: **Run** or **Run in Console** shows that call to adjust and
runs the example with it, **Copy to My Scripts** makes an editable copy
with the call as a commented "Try it" section. A run that only defined
functions says so in the status line.

Public `axross.*` API examples live under
[`examples/scripting_api/`](../examples/scripting_api/). They are
ordinary Python modules with local smoke tests and opt-in Docker-lab
protocol tests.

| Script | What it does | E2E tested |
|---|---|:---:|
| `mirror.py` | Incremental hash-aware sync between any two backends | ✓ |
| `dedupe.py` | Find duplicate files by sha256 across a tree | ✓ |
| `du.py` | Disk-usage tree, sorted by size — `du -sh` for any backend | ✓ |
| `bulk_rename.py` | Regex rename across a directory, dry-run by default | ✓ |
| `find_secrets.py` | Scan for AWS keys, JWTs, private-key blocks, .env values | ✓ |
| `port_scan.py` | Concurrent TCP probe across hosts × COMMON_PORTS | ✓ |
| `redact.py` | Encrypt every file matching a regex with `.axenc` | ✓ |
| `hash_audit.py` | Verify a `<sha256>\\t<path>` manifest against a backend | ✓ |
| `fingerprint_diff.py` | sha256-diff two trees: added / removed / changed / unchanged | ✓ |
| `sqlite_export.py` | Pack a directory tree into one SQLite-FS file | ✓ |
| `ramfs_decrypt.py` | Decrypt `.axenc` straight into RAM, never touching disk | ✓ |
| `bookmarks_export.py` | Dump / restore saved bookmarks via JSON or CSV | ✓ |
| `s3_inventory.py` | Object count + total bytes + top-N + extension histogram | ✓ |
| `git_changelog.py` | Walk a Git-FS branch, emit `<sha>  <subject>` lines | ✓ |
| `gopher_archive.py` | Recursively download a Gopher hole | ✓ |
| `tftp_audit.py` | Wordlist scan across a list of TFTP hosts | smoke |
| `slp_inventory.py` | SLPv2 service discovery across a host list | smoke |
| `nntp_subjects.py` | Subject lines for the last N articles in a Usenet group | smoke |
| `webdav_quota.py` | RFC 4331 `disk_usage` across WebDAV endpoints | smoke |
| `cisco_collect.py` | `show running-config` + version + interfaces from IOS hosts | smoke |
| `imap_archive.py` | Download every message in an IMAP folder as `.eml` | smoke |
| `lab_smoke.py` | "Is every configured backend reachable?" smoke test | smoke |

The "smoke" rows compile and import correctly; they aren't
end-to-end exercised because they need live infrastructure (a TFTP
server, an SLP daemon, an IMAP mailbox, a Cisco device, …) the
default test sandbox doesn't ship.

---

## The MCP tool surface

The same scripting machinery is exposed to MCP clients (Claude
Desktop, Cline, custom agents). Run with `--mcp-allow-scripts` to
expose:

| Tool | Description | Gated by |
|---|---|---|
| `script_list` | Names of every saved script | `--mcp-allow-scripts` |
| `script_api_schema` | The `axross.*` API as JSON (`axross.api_schema()`) | `--mcp-allow-scripts` |
| `script_read` | Source of a saved script | `--mcp-allow-scripts` |
| `script_write` | Save Python source as `<name>.py` (mode 0o600) | `--mcp-allow-scripts` |
| `script_run` | Run a saved script in its own process (`args`, `timeout_s`); return exit status, stdout/stderr, an uncaught exception | `--mcp-allow-scripts` |
| `script_delete` | Remove a saved script | `--mcp-allow-scripts` |

`script_run` runs arbitrary Python as the server's user — in a child
process with empty stdin, a wall-clock timeout and its own process
group, but with every right of that user — so the flag is **separate
from `--mcp-write`**: don't enable scripting for an LLM client you
don't already trust with arbitrary code execution. With both flags
off, the MCP surface stays read-only. [MCP.md](MCP.md) §2 has the
full reply format.

---

## Scripts a machine runs

An LLM (or cron, CI, any caller without a human at the keyboard) needs
a few guarantees the REPL never had to give. What the API offers:

- **Discover before you write.** `axross.api_schema()` (MCP:
  `script_api_schema`; committed as
  [`scripting-api.json`](scripting-api.json)) is the API as JSON,
  built from the code: rules and errors for scripts, the names by
  topic, per function the signature with types, the whole docstring,
  its examples, what it raises, `mutates` (can change files, remote
  state or settings) and `prompts` (can need a human); the methods every
  backend session has and the types the API returns (`FileItem` and the
  results). `axross.api_schema(names=[])` is the index alone,
  `axross.api_schema(["copy"])` one function in full.
  `axross.docs(name)` is the prose for one function;
  [LLM_GUIDE.md](LLM_GUIDE.md) §9 and §12 are the short path for a
  language model.
- **Nobody to ask.** Without a Qt window and without a terminal on
  stdin — or with `AXROSS_NONINTERACTIVE=1`, which `script_run` sets —
  `axross.confirm()` raises `axross.NonInteractiveError` (a
  `PermissionError`) instead of guessing an answer. Pass
  `assume_yes=True` to answer yes without asking there;
  `axross.is_interactive()` tells a script which case it is in. A write
  to a profile flagged *production* is refused the same way unless the
  environment that starts axross sets `AXROSS_TARPIT_DISABLE=1`. A run
  from the Scripts panel still gets the countdown: its output is live
  and Stop ends it, so a human can watch and stop it.
- **Close what you open.** Every session supports `with`; leaving the
  block ends the connection, also after an exception:

  ```python
  with axross.open("backup-server") as b:
      print(axross.summarize(b, "/var/log").render())
  ```
- **Arguments and exit status.** `script_run` hands `args` to the
  script as `sys.argv[1:]` and reports `sys.exit(n)` as `exit`; an
  uncaught exception comes back as `error_type`, `error` and
  `traceback`.

---

## See also

- [USAGE.md](USAGE.md) / [USAGE_de.md](USAGE_de.md) / [USAGE_es.md](USAGE_es.md) — full GUI walkthrough
- [MCP.md](MCP.md) / [MCP_de.md](MCP_de.md) / [MCP_es.md](MCP_es.md) — MCP server reference
- [OPSEC.md](OPSEC.md) — operational-security defaults
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — adversarial review of every backend
