# Multi-System-Workflows

[English](MULTI_SYSTEM.md) · [Deutsch](MULTI_SYSTEM_de.md) · [Español](MULTI_SYSTEM_es.md)

Sysadmins, Programmierer und Netzwerk-Admins, die zwischen vielen
Systemen pendeln, verlieren täglich nicht-trivial Zeit damit, Kontext
zu rekonstruieren („wo war ich gestern auf prod-db-04?"), dieselbe
Abfrage gegen N Hosts zu fahren („hat jede Box dieselbe nginx.conf?")
oder nach einer abgerissenen Verbindung weiterzumachen. axross's
Multi-System-Layer bündelt das in einer kleinen Verb-Liste, callable
aus REPL, Skripten und MCP — und einsetzbar über alle 30+ Protokolle,
die axross spricht.

| Verb | Was es tut |
|---|---|
| `axross.where_was_i(host=None)` | Letztes Verzeichnis + recent ops auf einem Host abrufen. |
| `axross.health_pulse()` | Live-Latenz / Stale-Flag für jede angemeldete Session. |
| `axross.summarize(backend, path)` | Ein-Absatz-Übersicht über ein Verzeichnis (LLM-freundlich). |
| `axross.explain(backend, path)` | Heuristische Vermutung „was IST das hier für ein Verzeichnis?". |
| `axross.compare_file([b1, b2, …], path)` | Gleicher Pfad über N Backends — Metadata + Diff. |
| `axross.inspect_targets([(b1, p1), (b2, p2), …])` | Heterogene `(backend, path)`-Liste vergleichen. |
| `axross.federated_search([b1, b2, …], name=…, contains=…)` | Eine Anfrage, native Suche pro Protokoll. |
| `axross.resumable_copy(src, srcp, dst, dstp)` | Cross-Backend-Copy mit Checkpoint-Resume. |
| `axross.dashboard(fmt="text")` | Ein-Bildschirm-Federation-Status. |

---

## `where_was_i` — gestrigen Kontext zurückholen

```python
>>> axross.where_was_i("prod-db")
HostVisit(protocol='sftp', host='prod-db-04.internal', username='alice',
          last_path='/var/log/postgres/', last_seen=1715284812.4,
          visit_count=27, recent_ops=[…])

>>> from core.visit_history import format_visit
>>> for v in axross.where_was_i():
...     print(format_visit(v))
sftp://alice@prod-db-04.internal — 12 min ago at /var/log/postgres/ (visits=27)
imap://alice@mail.example.com   — 4 h ago  at /INBOX                (visits=4)
```

Records werden automatisch beim connect / Datei-Op geschrieben. JSON
unter `~/.config/axross/visit_history.json` (mode 0o600), gekappt bei
200 Hosts × 20 Ops/Host. Sensibel behandeln — die Datei trägt das
Pfad-Layout jeder Box, die du angefasst hast. Löschen mit
`core.visit_history.clear()`.

---

## `health_pulse` — lebt diese Verbindung noch?

```python
>>> from core.conn_health import format_pulse_line
>>> for r in axross.health_pulse():
...     print(format_pulse_line(r))
  ✓ alice@prod-db-04:22         53 ms
  ✓ alice@prod-web-01:22        19 ms
  ✗ alice@flaky-vpn-host:22  stale (3× fail)
```

Jede angemeldete Session wird auf konfigurierbarer Kadenz (default
30 s) mit dem billigsten No-Op des Protokolls geprobt — `send_ignore`
für SSH, `NOOP` für FTP/IMAP/POP3, `OPTIONS /` für WebDAV, generisches
`connected`-Property sonst. Nach zwei aufeinanderfolgenden Failures
wird `stale` gesetzt, sodass Statusbar / Dashboard die Session
aufgeben und beim nächsten User-Click neu verbinden können.

Read-only; ein Daemon-Thread für alle Sessions. Latenz-Record =
host:port + RTT — kein Content, keine Creds.

---

## `summarize` — Ein-Absatz „was ist hier?"

```python
>>> b = axross.open_url("sftp://alice@prod-db-04/")
>>> axross.summarize(b, "/var/log/postgres/").render()
'SFTP:/var/log/postgres/ — 47 files, 3 dirs, 1.2 GiB total. '
'Top types: .log=42, .gz=4, .pid=1. '
'Newest: postgresql-Mon.log (12 min ago). '
'Oldest: postgresql-2024-archive.gz (412 d ago). '
'Age: <1h=3, <1d=4, <1w=37, <1mo=3.'
```

Liest nur Metadaten — nie den Inhalt. Eine Round-Trip pro
Verzeichnis; gekappt bei 2000 Einträgen. Liefert :class:`Summary`
(Counts, Histogramme, Top-5 nach Größe). Designed für LLM-Kontext —
ein Agent, der `summarize` einmal fragt, kennt das Wesentliche; einer,
der jedes Item listet, sprengt sein Context-Window.

---

## `explain` — heuristische „was IST das?"

```python
>>> axross.explain(b, "/var/lib/postgresql/16/main").render()
'PostgreSQL data directory (confidence 1.00) — A pg_data dir; …  '
'[evidence: PG_VERSION, postgresql.conf, pg_hba.conf, base, global]'
```

Eingebaute Patterns: Git-Repo, PostgreSQL/MySQL/MongoDB-Datadirs,
/etc-style Config-Tree, systemd Drop-Ins, nginx/Apache, Web-Log-Dir,
k8s-Manifests, Python-Projekt, Node.js-Projekt, Docker-Compose,
Maildir, WordPress. Liefert den höchst-konfidenten Match oder leeres
Result. Heuristik, nicht autoritativ — Confidence-Score ist „trust,
but verify". Eigene Patterns: `_PATTERNS` in
[`core/inspect.py`](../core/inspect.py) erweitern.

---

## `compare_file` — gleicher Pfad über N Hosts

```python
>>> hosts = [
...     axross.open("prod-web-01"),
...     axross.open("prod-web-02"),
...     axross.open("prod-web-03"),
... ]
>>> from core.multi_view import render_compare
>>> rep = axross.compare_file(hosts, "/etc/nginx/nginx.conf")
>>> print(render_compare(rep))
compare '/etc/nginx/nginx.conf' across 3 backend(s):
  · alice@prod-web-01:22       size=4096B    sha256=a1b2c3d4e5f6… mtime=1715000000 (87ms)
  · alice@prod-web-02:22       size=4096B    sha256=a1b2c3d4e5f6… mtime=1715000000 (94ms)
  · alice@prod-web-03:22       size=4112B    sha256=9988ff77ee66… mtime=1715284800 (102ms)
--- diff against alice@prod-web-03:22 ---
--- alice@prod-web-01:22
+++ alice@prod-web-03:22
@@ -34,7 +34,7 @@
-    worker_connections 768;
+    worker_connections 1024;
```

Parallel — N Hosts in einem Threadpool (default 8 Workers).
Hard-Cap 8 MiB auf Content-Reads; cap-truncated Probes sind im Report
markiert. `content=False` skippt den Body-Download und vergleicht nur
Metadaten — billiger auf Cloud-Backends, wo jeder GET kostet.

---

## `inspect_targets` — heterogene `(backend, path)`-Probe

```python
>>> targets = [
...     (axross.localfs(),                 "/tmp/installer.bin"),
...     (axross.open_url("s3://my-bucket"), "releases/installer.bin"),
...     (axross.open("backup-sftp"),       "/srv/installers/installer.bin"),
... ]
>>> rep = axross.inspect_targets(targets)
>>> from core.multi_view import render_inspect
>>> print(render_inspect(rep))
inspect 3 target(s):
  · Local                       /tmp/installer.bin               size=5242880   sha256=ee44…
  · S3:my-bucket                releases/installer.bin           size=5242880   sha256=ee44…
  · alice@backup-sftp:22        /srv/installers/installer.bin    size=5242880   sha256=ee44…
→ all collected hashes match.
```

Gleiche Engine wie `compare_file`, aber für eine heterogene Liste.
Das „ist das wirklich dieselbe Datei?"-Verb. Liefert
`TargetProbe`-Liste in Eingabe-Reihenfolge; `hashes_consistent()`
gibt das Boolean.

---

## `federated_search` — eine Anfrage, alle Backends

```python
>>> backends = [
...     axross.open("prod-web-01"),
...     axross.open("prod-web-02"),
...     axross.open("backup-s3"),
...     axross.open("imap-archive"),
... ]
>>> rep = axross.federated_search(
...     backends,
...     name="*.conf",
...     contains="X-Forwarded-For",
...     roots=["/etc/nginx"],
... )
```

Per-Backend-Adapter-Dispatch:

| Backend | Native Anfrage |
|---|---|
| IMAP | IMAP `SEARCH` (Volltext + Datums-Prädikate) |
| Postgres-FS / SQLite-FS / Mongo-FS / Redis-FS | nativer `find_by_query` (LIKE / `$regex` / SCAN) |
| Sonst | client-seitiger Walker mit optionalem Content-`read` für `contains=` |

Ohne nativen Adapter läuft der generische Walker — korrekt, aber
client-seitig langsam. Eigener Adapter:
`core.search_federation.register_adapter(protocol, callable)`.

Gekappt: Per-Backend-Cap 500, Total-Cap 5000, Per-Backend-Timeout
60 s, Parallelism 8. Caps markieren `truncated=True`.

---

## `resumable_copy` — Checkpoint-Cross-Backend-Copy

```python
>>> rep = axross.resumable_copy(
...     src_backend, "/big/dataset.tar.zst",
...     dst_backend, "/srv/backup/dataset.tar.zst",
...     segment_size=4 * 1024 * 1024,
... )
>>> print(rep.summary())
copy_resume: SFTP:src/dataset.tar.zst → SFTP:dst/dataset.tar.zst
   (8589934592/8589934592 bytes, 1024 skipped + 1024 transferred, 412.3s) — done
```

Source wird in Segmente aufgeteilt, ein JSON-Manifest schreibt nach
jedem fertigen Segment, beim Re-Run wird ab dem ersten unfertigen
Segment fortgesetzt — nach Verifikation, dass die im Ziel
gespeicherten Hashes stimmen. Manifest standardmäßig in
`/tmp/axross-resume/<safe-name>.json` (mode 0o600); per
`manifest_path=…` overridebar.

Konservatives Verifizieren: jeder Mismatch auf einem „done"-Segment
verwirft das Manifest und startet ab Byte 0 neu. Lieber neu
übertragen als eine halb-korrupte Datei abliefern.

S3 als Ziel fällt aktuell auf „neu starten bei Failure" zurück
(Multipart-Upload ist Folgearbeit).

---

## `dashboard` — Ein-Bildschirm-Federation-Status

```python
>>> print(axross.dashboard())
axross federation status — 2026-05-09 14:32:18
  3 connection(s), 2 healthy, 1 stale
  STATE   TARGET                            LAT    MED   LAST  PATH
  ✓ ok    alice@prod-db-04:22              53ms   58ms     1m  /var/log/postgres/
  ✓ ok    alice@prod-web-01:22             19ms   21ms    12m  /etc/nginx/
  ✗ stale alice@flaky-vpn-host:22           —      —      —   —

recent ops:
  14:31:47  list_dir   alice@prod-db-04:22      /var/log/postgres/
  14:30:10  open_read  alice@prod-web-01:22     /etc/nginx/nginx.conf
```

Drei Formate: `text` (REPL/Statusbar), `markdown` (MCP/LLM), `json`
(GUI/Skripte). Pull aus `core.conn_health` (Live-Latenz),
`core.visit_history` (last-touched), `core.operation_journal`
(recent ops). Read-only.

`with_capacity=True` zusammen mit `core.dashboard.snapshot_with_backends`
fügt `disk_usage()`-Spalten hinzu (5-Sek-Budget pro Backend).

---

## Siehe auch

* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — auto-generierte API-Referenz.
* [`docs/DAILY_DRIVER.md`](DAILY_DRIVER.md) — Production-Tarpit + adaptive Chunk-Größe.
* [`docs/REVERSE_SERVE.md`](REVERSE_SERVE.md) — Backend per S3 / WebDAV anderen Tools verfügbar machen.
* [`docs/TRAIL.md`](TRAIL.md) — Time-Lapse / Change-Tracking für ein Verzeichnis.
