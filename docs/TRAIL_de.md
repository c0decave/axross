# Trail — Time-Lapse-Snapshots eines Verzeichnisses

[English](TRAIL.md) · [Deutsch](TRAIL_de.md) · [Español](TRAIL_es.md)

Wähle einen Pfad auf irgendeinem Backend, das axross spricht. Sag
axross, alle N Sekunden einen Metadata-Snapshot zu machen. Später
spielst du die Timeline ab und siehst *was wann passiert ist* —
neue Dateien, gelöschte, mtime-Sprünge, optional Content-Hash-Drift
auf den ersten 32 KiB.

> **Trail ist kein Backup-Tool.** Es speichert ein *Ledger of
> Changes*, nicht den Inhalt. Use für Change-Tracking („hat jemand
> /etc/cron.d in den letzten 24 h angefasst?"), Forensik-Timeline
> („wann sprang die mtime dieser Binary?") und Growth-Monitoring
> („Log-Dir wuchs 800 MB über Nacht — wann?").

| Verb | Was es tut |
|---|---|
| `axross.snapshot_now(backend, path)` | Einen Snapshot jetzt nehmen. |
| `axross.start_trail(backend, path, interval_s=300)` | Hintergrund-Snapshots beginnen. |
| `axross.stop_trail(name)` | Benannten Trail stoppen. |
| `axross.list_trails()` | Jeden aufgezeichneten Trail listen. |
| `axross.list_snapshots(trail_name)` | Snapshots eines Trails listen (neueste zuerst). |
| `axross.diff_snapshots(snapshot_a, snapshot_b)` | Zwei Snapshots diffen — added / removed / modified. |

---

## Storage

* SQLite-DB unter `~/.config/axross/trail.db`, mode 0o600.
* Schema: `trails` (Config), `snapshots` (Per-Snapshot-Summary),
  `files` (eine Zeile pro Datei × Snapshot).
* Eine Zeile pro Datei pro Snapshot — gekappt durch
  `MAX_FILES_PER_SNAPSHOT` (5000 default), damit ein Runaway-Tree
  nicht die Disk füllt.
* Kein Inhalt. Optional `head_hash=True` liest die ersten 32 KiB pro
  Datei und speichert SHA-256-Prefix; default off, weil das N Reads
  pro Snapshot gegen das Backend zahlt.

---

## Quickstart

```python
>>> b = axross.open("prod-web-01")
>>> snap = axross.snapshot_now(b, "/etc/nginx/conf.d")
>>> snap
Snapshot(snapshot_id=1, trail_name='alice@prod-web-01:22:/etc/nginx/conf.d',
         ts=1715284812.4, file_count=14, total_bytes=8192,
         tree_hash='a7c3…', truncated=False)
```

5 Minuten warten, eine Config ändern, nächsten Snapshot:

```python
>>> snap2 = axross.snapshot_now(b, "/etc/nginx/conf.d")
>>> diff = axross.diff_snapshots(snap.snapshot_id, snap2.snapshot_id)
>>> print(diff.summary())
+0 added, -0 removed, ~1 modified, 13 unchanged
>>> diff.modified
['/etc/nginx/conf.d/upstream.conf']
```

Trail steht jetzt mit zwei Snapshots in der DB. Timeline rendern:

```python
>>> from core.trail import render_timeline
>>> print(render_timeline("alice@prod-web-01:22:/etc/nginx/conf.d"))
trail alice@prod-web-01:22:/etc/nginx/conf.d:
  · #2     2026-05-09 14:35:04  files=14     bytes=8192         tree=88aa…
  · #1     2026-05-09 14:30:12  files=14     bytes=8192         tree=a7c3…
```

---

## Hintergrund-Loops

`axross.start_trail` läuft die Snapshot-Loop in einem Daemon-Thread:

```python
>>> name = axross.start_trail(
...     b, "/etc/cron.d",
...     interval_s=600,            # alle 10 min
...     head_hash=True,            # auch Drift-Check erste 32 KiB
... )
>>> name
'alice@prod-web-01:22:/etc/cron.d'
>>> # … später …
>>> axross.stop_trail(name)
True
```

* Mindest-Interval 30 s. Default 300 s.
* Thread daemon — stirbt mit dem Prozess. `axross.stop_trail(name)`
  für sauberen Shutdown.
* Mehrere Trails parallel ohne Interferenz.
* Jeder Snapshot eigene SQLite-Transaction — gecrashter Interpreter
  schreibt nie halbe Snapshots.

---

## Tree-Hash

Jeder Snapshot trägt einen `tree_hash` — SHA-256 des Manifests
sortiert nach Pfad. Zwei Snapshots mit gleichem `tree_hash` sind
identisch bis auf mtime + size + (optional) head-hash. Cheap
„hat sich überhaupt was geändert?" = `a.tree_hash == b.tree_hash`.

Diff-Output (`added` / `removed` / `modified`) ist was du brauchst,
wenn du wissen willst *was* — `tree_hash` ist der O(1)-„irgendwas?"-
Check.

---

## Export

```python
>>> from core.trail import export_trail_jsonl
>>> n = export_trail_jsonl(name, "/tmp/cron-trail.jsonl")
>>> n
72
```

JSONL eine-Zeile-pro-Snapshot — für Offline-Analyse oder zum
Anschluss an andere Tools. Export ist nur Metadata; File-Rows
bleiben in SQLite für schnelle Queries und sind nicht im JSONL
default.

---

## Truncation

Snapshot ist `truncated=True`, wenn das Verzeichnis mehr Files als
`max_files` hat. Walker stoppt am Cap, Trail läuft weiter — aber
der truncated Snapshot ist nur eine Top-N-Files-Sicht. Zwei
truncated Snapshots können false-„removed"-Einträge zeigen, wenn
der Cap unterschiedliche Tree-Teile geclippt hat.

`max_files` per Aufruf hochziehen (`axross.snapshot_now(b, path,
max_files=20000)`) wenn ein dichter Tree voll erfasst werden muss.
SQLite-DB zahlt linear, also 20000 × 50 Snapshots ok, 1.000.000 × 50
nicht.

---

## OPSEC

* Trail-DB trägt das Pfad-Layout jedes gesnapshotteten Verzeichnisses.
  Mode 0o600; sensibel behandeln.
* `head_hash=True` macht einen Read pro Datei pro Snapshot. Sichtbar
  auf der Leitung, sichtbar in Server-Logs. Sparsam einsetzen.
* Trail meldet sich nicht bei `core.conn_health` an — ein stallendes
  Backend droppt diesen Snapshot (logged WARNING), ohne andere Trails
  zu beeinflussen.

---

## Siehe auch

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — Verbs zum Vergleich von Dateien über Hosts.
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — vollständige API-Referenz.
