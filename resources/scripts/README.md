# Bundled axross scripts

32 ready-to-run Python scripts that exercise the `axross.*` scripting
surface against the registered backends. Each is a single self-contained
`.py` file under this directory.

## Three ways to run

```bash
# 1. one-shot from the source tree
axross --script resources/scripts/du.py /etc

# 2. one-shot from stdin (pipe a script in)
axross --script - < resources/scripts/du.py

# 3. from inside the REPL — copy once, then ``.run <name>``
cp resources/scripts/du.py ~/.config/axross/scripts/
# inside axross GUI, open the Console dock, then:
#   .run du
```

When the script needs arguments, `--script` forwards them after the
script path:

```bash
axross --script resources/scripts/dedupe.py ~/Downloads
```

Inside the script, the curated API is reachable as `axross.*` —
the same surface documented in [`docs/SCRIPTING_REFERENCE.md`](
../../docs/SCRIPTING_REFERENCE.md) and via `axross.help()` /
`axross.docs()` at runtime.

## Topical index

### Cross-backend file ops
| Script | What it does |
|---|---|
| [`mirror.py`](mirror.py) | Incremental mirror between two backends (any registered protocol) |
| [`dedupe.py`](dedupe.py) | Find duplicate files by content hash |
| [`cas_dedupe.py`](cas_dedupe.py) | Content-addressable dedupe across multiple backends |
| [`fingerprint_diff.py`](fingerprint_diff.py) | sha256-diff two backend trees |
| [`du.py`](du.py) | Disk-usage tree across any backend, sorted by size |
| [`hash_audit.py`](hash_audit.py) | Verify a manifest against a backend |
| [`atomic_replace.py`](atomic_replace.py) | Safe in-place rewrite via `core.atomic_io` |
| [`bulk_rename.py`](bulk_rename.py) | Regex-based rename across a directory |

### Encryption / RAM-only pipelines
| Script | What it does |
|---|---|
| [`encrypted_archive.py`](encrypted_archive.py) | Pack a directory as one encrypted blob |
| [`encrypted_stream.py`](encrypted_stream.py) | Encrypt/decrypt big files via the streaming codec |
| [`ramfs_decrypt.py`](ramfs_decrypt.py) | Decrypt an `.axenc` file straight into RAM |
| [`ramfs_pipeline.py`](ramfs_pipeline.py) | Chain transforms through a RAM workspace |
| [`redact.py`](redact.py) | Encrypt every file under PATH whose name matches a pattern |

### Discovery / probing
| Script | What it does |
|---|---|
| [`connection_probe.py`](connection_probe.py) | Open every saved profile, time the connect |
| [`port_scan.py`](port_scan.py) | Small-and-fast TCP port probe |
| [`lab_smoke.py`](lab_smoke.py) | Touch every available backend's root |
| [`backend_capabilities.py`](backend_capabilities.py) | Capability matrix across every registered backend |

### Per-protocol audits
| Script | What it does |
|---|---|
| [`tftp_audit.py`](tftp_audit.py) | Wordlist scan across a list of TFTP servers |
| [`webdav_quota.py`](webdav_quota.py) | Print WebDAV quota across a list of endpoints |
| [`s3_inventory.py`](s3_inventory.py) | Content-type histogram + top-N largest objects |
| [`slp_inventory.py`](slp_inventory.py) | Discover SLP services across a host list |
| [`cisco_collect.py`](cisco_collect.py) | Collect IOS `show <cmd>` output across a host list |
| [`gopher_archive.py`](gopher_archive.py) | Recursively download a Gopher hole |
| [`nntp_subjects.py`](nntp_subjects.py) | Collect subject lines for the most recent N articles |
| [`imap_archive.py`](imap_archive.py) | Archive an IMAP folder to `.eml` files on disk |
| [`git_changelog.py`](git_changelog.py) | Extract a flat changelog from a Git-FS branch |
| [`sqlite_export.py`](sqlite_export.py) | Pack a directory tree into a single SQLite file |

### Triage / safety
| Script | What it does |
|---|---|
| [`find_secrets.py`](find_secrets.py) | Scan a backend for files containing leaked secrets |
| [`profile_audit.py`](profile_audit.py) | Flag risky settings across saved profiles |
| [`bookmark_audit.py`](bookmark_audit.py) | Verify every saved bookmark still resolves |
| [`bookmarks_export.py`](bookmarks_export.py) | Export saved axross bookmarks to JSON / CSV |
| [`snapshot_walk.py`](snapshot_walk.py) | Version timeline via `core.snapshot_browse` |

## Per-script docs

Each script's full multi-paragraph docstring is the source of truth for
what it does, what arguments it accepts, and what it touches on the
backends. To see them:

* **In the GUI / REPL**: `axross.docs("scripts")` returns the rendered
  Markdown; the doc-pane's *Scripts* tab shows the same content.
* **From the source**: `head -40 resources/scripts/<name>.py` (every
  script starts with its docstring).
* **Auto-generated reference**: this index plus the per-script
  docstring blocks land in [`docs/SCRIPTING_REFERENCE.md`](
  ../../docs/SCRIPTING_REFERENCE.md) — regenerate via:
  ```bash
  python -c "import core.scripting as s; \
    open('docs/SCRIPTING_REFERENCE.md','w').write(s._render_full_reference())"
  ```

## Adding your own

Drop any `.py` file into `~/.config/axross/scripts/` and it shows up
in the REPL's `.scripts` listing. Inside the script:

```python
"""my_script.py — one-line summary the doc-pane will surface.

A longer paragraph explaining what the script does, what arguments
it expects, and what side effects it has on the backends.
"""
import sys

# axross.* is pre-injected when the script runs via --script or
# REPL .run; for direct ``python -m`` execution import it manually.
if "axross" not in dir():
    import core.scripting as axross

b = axross.localfs()
print(len(list(b.list_dir("/etc"))), "entries in /etc")
```

The first line of the docstring is what `axross.docs("scripts")` and
the doc-pane show. Keep it short + descriptive.
