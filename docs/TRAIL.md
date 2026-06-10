# Trail — Time-Lapse Snapshots of a Directory

Languages: **English** · [Deutsch](TRAIL_de.md) · [Español](TRAIL_es.md)

Pick a path on any backend axross speaks. Tell axross to take a
metadata snapshot every N seconds. Later, replay the timeline and
see *what changed when* — added files, removed files, mtime jumps,
optional content-hash drift on the first 32 KiB.

> **Trail is not a backup tool.** It records a *ledger of changes*,
> not the file contents. Use it for change tracking ("did anyone
> touch /etc/cron.d in the last 24 h?"), forensic timeline
> reconstruction ("when did this binary's mtime jump?"), and growth
> monitoring ("this log directory grew 800 MB overnight — when?").

| Verb | What it does |
|---|---|
| `axross.snapshot_now(backend, path)` | Take one snapshot now. |
| `axross.start_trail(backend, path, interval_s=300)` | Begin periodic snapshots in the background. |
| `axross.stop_trail(name)` | Stop a named trail. |
| `axross.list_trails()` | List every recorded trail. |
| `axross.list_snapshots(trail_name)` | List snapshots of one trail (newest first). |
| `axross.diff_snapshots(snapshot_a, snapshot_b)` | Diff two snapshots — added / removed / modified path lists. |

---

## Storage

* SQLite database at `~/.config/axross/trail.db`, mode 0o600.
* Schema: `trails` (config), `snapshots` (per-snapshot summary),
  `files` (per-file row × snapshot).
* One row per file per snapshot — bounded by
  `MAX_FILES_PER_SNAPSHOT` (5000 default) so a runaway tree does
  not fill disk.
* No file content. Optional `head_hash=True` reads the first 32 KiB
  per file and stores a SHA-256 prefix; off by default because it
  pays N reads per snapshot against the backend.

---

## Quick start

```python
>>> b = axross.open("prod-web-01")
>>> snap = axross.snapshot_now(b, "/etc/nginx/conf.d")
>>> snap
Snapshot(snapshot_id=1, trail_name='alice@prod-web-01:22:/etc/nginx/conf.d',
         ts=1715284812.4, file_count=14, total_bytes=8192,
         tree_hash='a7c3…', truncated=False)
```

Now wait 5 minutes, change a config file, take another:

```python
>>> snap2 = axross.snapshot_now(b, "/etc/nginx/conf.d")
>>> diff = axross.diff_snapshots(snap.snapshot_id, snap2.snapshot_id)
>>> print(diff.summary())
+0 added, -0 removed, ~1 modified, 13 unchanged
>>> diff.modified
['/etc/nginx/conf.d/upstream.conf']
```

The trail is now in the database with two snapshots. Render the
timeline:

```python
>>> from core.trail import render_timeline
>>> print(render_timeline("alice@prod-web-01:22:/etc/nginx/conf.d"))
trail alice@prod-web-01:22:/etc/nginx/conf.d:
  · #2     2026-05-09 14:35:04  files=14     bytes=8192         tree=88aa…
  · #1     2026-05-09 14:30:12  files=14     bytes=8192         tree=a7c3…
```

---

## Background loops

`axross.start_trail` runs the snapshot loop in a daemon thread:

```python
>>> name = axross.start_trail(
...     b, "/etc/cron.d",
...     interval_s=600,            # every 10 minutes
...     head_hash=True,            # also drift-check first 32 KiB
... )
>>> name
'alice@prod-web-01:22:/etc/cron.d'
>>> # … later …
>>> axross.stop_trail(name)
True
```

* Minimum interval 30 s; below that the loop spends more time
  walking than waiting. Default is 300 s.
* The thread is daemonic — it dies with the process. Call
  `axross.stop_trail(name)` for a clean shutdown.
* Multiple trails coexist; they don't interfere.
* Each snapshot is its own SQLite transaction so a crashed
  interpreter never half-writes a snapshot.

---

## Tree hash

Every snapshot carries a `tree_hash` — a SHA-256 of the manifest
sorted by path. Two snapshots with the same `tree_hash` are
identical down to mtime + size + (optional) head-hash. The cheap
"did anything change between these two snapshots?" check is
`a.tree_hash == b.tree_hash`.

The diff output (`added` / `removed` / `modified`) is what you
want when you need to know *what* changed; `tree_hash` is the
O(1) "anything changed at all?" check.

---

## Export

```python
>>> from core.trail import export_trail_jsonl
>>> n = export_trail_jsonl(name, "/tmp/cron-trail.jsonl")
>>> n
72
```

JSONL one-line-per-snapshot — useful for offline analysis or for
plugging the trail into another tool. The export is metadata only;
file rows live in SQLite for fast queries but aren't part of the
JSONL by default.

---

## Truncation

A snapshot is `truncated=True` when the directory has more files
than `max_files`. The walker stops once it hits the cap, so the
trail keeps working — but the truncated snapshot is only a
top-N-files view. Two truncated snapshots may show false
"removed" entries if the cap clipped different parts of the tree.

Bump `max_files` per call (`axross.snapshot_now(b, path,
max_files=20000)`) when you need a dense tree fully captured. The
SQLite DB pays for it linearly, so 20000 × 50 snapshots is fine,
1_000_000 × 50 is not.

---

## OPSEC

* The trail database carries the path layout of every directory
  you've snapshotted. Mode is 0o600 by default; treat it as
  sensitive engagement data.
* `head_hash=True` causes one read per file per snapshot. Visible
  on the wire; visible in server logs. Use sparingly.
* Trail does not enrol against `core.conn_health`, so a stalled
  backend simply drops the snapshot for that interval (logged as a
  warning); it does not cascade to other trails.

---

## See also

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — verbs that compare files across hosts.
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — full API reference.
