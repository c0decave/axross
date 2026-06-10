# Multi-System Workflows

Languages: **English** · [Deutsch](MULTI_SYSTEM_de.md) · [Español](MULTI_SYSTEM_es.md)

Sysadmins, programmers and network admins who pendulum between many
systems spend a non-trivial chunk of their day reproducing context
("where was I yesterday on prod-db-04?"), running the same query
against N hosts ("does each box have the same nginx.conf?"), and
recovering after a flaky connection. axross's multi-system layer
collects these into a small set of verbs callable from REPL, scripts
and MCP — and reusable across all 30+ protocols axross speaks.

| Verb | What it does |
|---|---|
| `axross.where_was_i(host=None)` | Recall the last directory + recent ops on a host. |
| `axross.health_pulse()` | Live latency / staleness for every enrolled session. |
| `axross.summarize(backend, path)` | One-paragraph synopsis of a directory (LLM-friendly). |
| `axross.explain(backend, path)` | Heuristic guess at what kind of directory this is. |
| `axross.compare_file([b1, b2, …], path)` | Same path across N backends — metadata + diff. |
| `axross.inspect_targets([(b1, p1), (b2, p2), …])` | Compare a list of (backend, path) pairs. |
| `axross.federated_search([b1, b2, …], name=…, contains=…)` | One query, native search per protocol. |
| `axross.resumable_copy(src, srcp, dst, dstp)` | Cross-backend copy with checkpoint resume. |
| `axross.dashboard(fmt="text")` | One-screen federation status. |

This document explains each in turn — what it's for, when to reach
for it, and what its OPSEC posture is.

---

## `where_was_i` — recover yesterday's context

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

Records are written automatically by axross's connect / file-op verbs.
Storage is a JSON file at `~/.config/axross/visit_history.json`,
mode 0o600, capped at 200 hosts × 20 ops per host. Treat it as
sensitive engagement data — it carries the path layout of every host
you've touched. Clear with `core.visit_history.clear()`.

---

## `health_pulse` — is this connection still alive?

```python
>>> from core.conn_health import format_pulse_line
>>> for r in axross.health_pulse():
...     print(format_pulse_line(r))
  ✓ alice@prod-db-04:22         53 ms
  ✓ alice@prod-web-01:22        19 ms
  ✗ alice@flaky-vpn-host:22  stale (3× fail)
```

Every enrolled session is probed on a configurable cadence (default
30 s) with the cheapest no-op the protocol exposes — `send_ignore`
for SSH, `NOOP` for FTP/IMAP/POP3, `OPTIONS /` for WebDAV, generic
`connected` property otherwise. After two consecutive failures the
record is marked `stale` so the status bar / dashboard / `dashboard()`
can drop the session and reconnect on the next user action.

The pulse is read-only; one daemon thread shared across every
session. Latency record is host:port + RTT — no content, no creds.

---

## `summarize` — one-paragraph "what's in this place"

```python
>>> b = axross.open_url("sftp://alice@prod-db-04/")
>>> axross.summarize(b, "/var/log/postgres/").render()
'SFTP:/var/log/postgres/ — 47 files, 3 dirs, 1.2 GiB total. '
'Top types: .log=42, .gz=4, .pid=1. '
'Newest: postgresql-Mon.log (12 min ago). '
'Oldest: postgresql-2024-archive.gz (412 d ago). '
'Age: <1h=3, <1d=4, <1w=37, <1mo=3.'
```

Reads metadata only — never the file bodies. One round-trip per
directory; bounded at 2000 entries (configurable). Returns
:class:`Summary` (counts, histograms, top-5 by size) so callers can
inspect rather than parse the rendered string. Designed for LLM
context: an agent that asks `summarize` once gets the gist; an agent
that lists every entry blows its context window.

---

## `explain` — heuristic "what IS this directory?"

```python
>>> axross.explain(b, "/var/lib/postgresql/16/main").render()
'PostgreSQL data directory (confidence 1.00) — A pg_data dir; …  '
'[evidence: PG_VERSION, postgresql.conf, pg_hba.conf, base, global]'
```

Built-in patterns: git repository, PostgreSQL / MySQL / MongoDB data
dirs, /etc-style config tree, systemd unit drop-ins, nginx + Apache,
web-server log dir, k8s manifests, Python project root, Node.js
project, Docker Compose project, Maildir, WordPress install. Returns
the highest-confidence match or an empty result. Heuristic, not
authoritative — the confidence score is the operator's hint to
"trust, but verify".

Add your own patterns by extending `_PATTERNS` in
[`core/inspect.py`](../core/inspect.py).

---

## `compare_file` — same path across N hosts

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

Parallel — N hosts probed in a thread pool (default 8 workers). Hard
size cap (8 MiB) on content reads; cap-truncated probes are flagged
in the report. Pass `content=False` to compare metadata only — useful
on cloud backends where a GET is paid by request.

---

## `inspect_targets` — heterogenous (backend, path) probe

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

Same engine as `compare_file`, but targets a heterogenous list. The
"is this really the same file?" verb. Returns the list of
:class:`TargetProbe` aligned with input order; `hashes_consistent()`
gives you the boolean.

---

## `federated_search` — one query, every backend

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
>>> print(rep.summary if hasattr(rep, 'summary') else f"{len(rep.hits)} hits")
```

Per-backend adapter dispatch:

| Backend | Native query used |
|---|---|
| IMAP | IMAP `SEARCH` (full-text + date predicates) |
| Postgres-FS / SQLite-FS / Mongo-FS / Redis-FS | native `find_by_query` (LIKE / `$regex` / SCAN) |
| Anything else | client-side recursive walk with optional content `read` for `contains=` |

If a backend has no native adapter, the generic walker still produces
correct results — just at client-side speeds. Add a custom adapter
via `core.search_federation.register_adapter(protocol, callable)`.

Bounded: per-backend hit cap (default 500), total hit cap (5000),
per-backend timeout (60 s), parallelism (8). Caps mark the result
`truncated=True` so the caller knows to narrow the query.

---

## `resumable_copy` — checkpointed cross-backend copy

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

Splits the source into segments, writes a JSON manifest after each
segment completes, and on a re-run resumes from the first incomplete
segment after verifying the destination's recorded hashes. Manifest
lives next to a temp dir by default
(`/tmp/axross-resume/<safe-name>.json`, mode 0o600); pass
`manifest_path=…` to override.

The manifest stores `(segment, sha256)` pairs; the verification step
is conservative — any mismatch on a "done" segment discards the
manifest and restarts from byte 0. Better to retransfer than to
ship a half-corrupt file.

S3 as a destination currently falls back to "restart on failure"
(multipart-upload integration is the right primitive there and is a
follow-up).

---

## `dashboard` — one-screen federation status

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

Three formats:

* `axross.dashboard()` — fixed-width text for REPL / status bar.
* `axross.dashboard(fmt="markdown")` — markdown table for MCP / LLM
  responses.
* `axross.dashboard(fmt="json")` — structured JSON for the GUI / scripts.

Pulls from `core.conn_health` (live latency), `core.visit_history`
(last-touched), `core.operation_journal` (recent ops). Read-only —
never performs mutating ops.

`axross.dashboard(with_capacity=True)` adds capacity columns when the
caller hands a list of opened backends to
`core.dashboard.snapshot_with_backends` — `disk_usage()` per backend
with a 5-second budget; failures leave the columns at 0.

---

## See also

* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — auto-generated full API reference for these verbs and everything else.
* [`docs/DAILY_DRIVER.md`](DAILY_DRIVER.md) — supporting infrastructure (production tarpit, adaptive chunk-sizing).
* [`docs/REVERSE_SERVE.md`](REVERSE_SERVE.md) — the inverse of these verbs — let other tools speak to axross-managed backends.
* [`docs/TRAIL.md`](TRAIL.md) — time-lapse / change-tracking on a directory.
