# Scripting & REPL

Axross is more than a file manager — it ships an **embedded Python
REPL**, a **curated `axross.*` API** that wraps every backend, a
**searchable doc pane**, a **persistent script directory**, and a
**MCP-tool surface** that lets an LLM agent write & run its own
scripts.

[English](SCRIPTING.md) · [Deutsch](SCRIPTING_de.md) · [Español](SCRIPTING_es.md)

---

## The four ways to run code against axross

| Surface | When | Entry point |
|---|---|---|
| **Console dock** (REPL) | Interactive exploration inside the GUI | Bottom dock, *Console* tab |
| **`axross --script <file>`** | Headless / cron / CI | `axross --script myscript.py` |
| **REPL slash-commands** | Save / load / run scripts from the prompt | `.save name`, `.run name` |
| **MCP `script_*` tools** | LLM agent drives axross | Run with `--mcp-allow-scripts` |

Every surface uses the same `core.scripting` module under the hood,
so anything you can do at the REPL, you can do in a script,
headless, or through an LLM.

---

## The `axross.*` API

The curated namespace covers **35+ verbs** in seven groups. Every
function has a docstring; the REPL's doc pane and `axross.help()`
both pull straight from those.

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
axross.checksum(b, path)            # native checksum if cheap, else streaming hash
axross.read_bytes(b, path)
axross.write_bytes(b, path, data)
axross.read_text(b, path)
axross.write_text(b, path, text)
axross.hash_bytes(data, "sha256")
axross.hash_file(b, path, "sha256")
```

### Encryption + archives

```python
axross.encrypt(b, "/secret.txt", "passphrase")     # → /secret.txt.axenc
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
| `.run <name>` | Execute a saved script in the live REPL namespace |
| `.delete <name>` | Remove a saved script |
| `.open` | Print the script-directory path |

---

## Bundled example scripts

22 ready-to-use scripts under `resources/scripts/`. Run any of them
via `axross --script resources/scripts/<name>.py` or copy into
`~/.config/axross/scripts/` and call from the REPL with
`.run <name>`.

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
| `script_read` | Source of a saved script | `--mcp-allow-scripts` |
| `script_write` | Save Python source as `<name>.py` (mode 0o600) | `--mcp-allow-scripts` |
| `script_run` | Execute a saved script, return stdout/stderr + namespace keys | `--mcp-allow-scripts` |
| `script_delete` | Remove a saved script | `--mcp-allow-scripts` |

`script_run` runs Python in the server process, so the flag is
**separate from `--mcp-write`** — don't enable scripting for an LLM
client you don't already trust with arbitrary code execution. With
both flags off, the MCP surface stays read-only.

---

## See also

- [USAGE.md](USAGE.md) / [USAGE_de.md](USAGE_de.md) / [USAGE_es.md](USAGE_es.md) — full GUI walkthrough
- [MCP.md](MCP.md) / [MCP_de.md](MCP_de.md) / [MCP_es.md](MCP_es.md) — MCP server reference
- [OPSEC.md](OPSEC.md) — operational-security defaults
- [RED_TEAM_NOTES.md](RED_TEAM_NOTES.md) — adversarial review of every backend
