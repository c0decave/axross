# Workflows Multi-Sistema

[English](MULTI_SYSTEM.md) · [Deutsch](MULTI_SYSTEM_de.md) · [Español](MULTI_SYSTEM_es.md)

Sysadmins, programadores y administradores de red que se mueven entre
muchos sistemas pierden parte importante del día reconstruyendo
contexto («¿dónde estaba ayer en prod-db-04?»), corriendo la misma
consulta contra N hosts («¿cada caja tiene la misma nginx.conf?») y
recuperándose tras conexiones inestables. La capa multi-sistema de
axross junta esto en un set pequeño de verbos accesibles desde REPL,
scripts y MCP — y reutilizables sobre los 30+ protocolos que axross
habla.

| Verbo | Qué hace |
|---|---|
| `axross.where_was_i(host=None)` | Recordar el último directorio + ops recientes en un host. |
| `axross.health_pulse()` | Latencia / staleness en vivo de cada sesión inscrita. |
| `axross.summarize(backend, path)` | Síntesis de un párrafo de un directorio (LLM-friendly). |
| `axross.explain(backend, path)` | Adivinanza heurística de qué tipo de directorio es. |
| `axross.compare_file([b1, b2, …], path)` | Mismo path en N backends — metadata + diff. |
| `axross.inspect_targets([(b1, p1), (b2, p2), …])` | Lista heterogénea de pares (backend, path). |
| `axross.federated_search([b1, b2, …], name=…, contains=…)` | Una consulta, búsqueda nativa por protocolo. |
| `axross.resumable_copy(src, srcp, dst, dstp)` | Copia cross-backend con resume por checkpoint. |
| `axross.dashboard(fmt="text")` | Estado de la federación en una pantalla. |

---

## `where_was_i` — recuperar contexto del día anterior

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

Los registros se escriben automáticamente en connect / file-op. JSON
en `~/.config/axross/visit_history.json` (mode 0o600), limitado a 200
hosts × 20 ops/host. Dato sensible — lleva el layout de paths de cada
caja que tocaste. Limpiar con `core.visit_history.clear()`.

---

## `health_pulse` — ¿esta conexión sigue viva?

```python
>>> from core.conn_health import format_pulse_line
>>> for r in axross.health_pulse():
...     print(format_pulse_line(r))
  ✓ alice@prod-db-04:22         53 ms
  ✓ alice@prod-web-01:22        19 ms
  ✗ alice@flaky-vpn-host:22  stale (3× fail)
```

Cada sesión inscrita se prueba con cadencia configurable (30 s
default) usando el no-op más barato del protocolo — `send_ignore`
para SSH, `NOOP` para FTP/IMAP/POP3, `OPTIONS /` para WebDAV,
property `connected` genérica si no. Tras dos fallos consecutivos
queda `stale` para que la status-bar / dashboard suelten la sesión y
reconecten al siguiente click.

Solo lectura; un thread daemon compartido. Registro de latencia =
host:port + RTT — sin contenido, sin credenciales.

---

## `summarize` — síntesis de un párrafo

```python
>>> b = axross.open_url("sftp://alice@prod-db-04/")
>>> axross.summarize(b, "/var/log/postgres/").render()
'SFTP:/var/log/postgres/ — 47 files, 3 dirs, 1.2 GiB total. '
'Top types: .log=42, .gz=4, .pid=1. '
'Newest: postgresql-Mon.log (12 min ago). '
'Oldest: postgresql-2024-archive.gz (412 d ago). '
'Age: <1h=3, <1d=4, <1w=37, <1mo=3.'
```

Lee solo metadata — nunca el contenido. Un round-trip por directorio;
limitado a 2000 entradas. Devuelve :class:`Summary` (counts,
histogramas, top-5 por tamaño). Diseñado para contexto LLM — un
agente que llama `summarize` una vez tiene la idea; uno que lista
cada item revienta su context window.

---

## `explain` — heurística «¿qué ES esto?»

```python
>>> axross.explain(b, "/var/lib/postgresql/16/main").render()
'PostgreSQL data directory (confidence 1.00) — A pg_data dir; …  '
'[evidence: PG_VERSION, postgresql.conf, pg_hba.conf, base, global]'
```

Patrones built-in: repo git, datadirs PostgreSQL/MySQL/MongoDB,
config-tree estilo /etc, drop-ins systemd, nginx/Apache, dir de logs,
manifests k8s, raíz de proyecto Python, Node.js, Docker Compose,
Maildir, WordPress. Devuelve el match con mayor confidence o vacío.
Heurístico — la confidence es «trust, but verify». Patrones propios:
extender `_PATTERNS` en [`core/inspect.py`](../core/inspect.py).

---

## `compare_file` — mismo path en N hosts

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

Paralelo — N hosts en thread-pool (8 workers default). Hard-cap
8 MiB en lecturas; probes truncados se marcan en el report.
`content=False` salta la descarga del body y solo difunde metadata
— más barato en backends cloud.

---

## `inspect_targets` — pares heterogéneos

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

Mismo motor que `compare_file` para una lista heterogénea. El verbo
«¿es realmente el mismo archivo?». Devuelve la lista de
`TargetProbe` en orden de entrada; `hashes_consistent()` da el
boolean.

---

## `federated_search` — una consulta, todos los backends

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

Dispatch por backend:

| Backend | Consulta nativa |
|---|---|
| IMAP | IMAP `SEARCH` (full-text + predicados de fecha) |
| Postgres-FS / SQLite-FS / Mongo-FS / Redis-FS | `find_by_query` nativo (LIKE / `$regex` / SCAN) |
| Resto | walker cliente, opcional `read` de contenido para `contains=` |

Sin adapter nativo, el walker genérico produce resultados correctos
pero a velocidad client-side. Adapter propio:
`core.search_federation.register_adapter(protocol, callable)`.

Limitado: cap por backend 500, cap total 5000, timeout por backend
60 s, parallelism 8. Los caps marcan `truncated=True`.

---

## `resumable_copy` — copia con checkpoint

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

Divide la fuente en segmentos, escribe un manifest JSON tras cada
segmento exitoso, en re-run sigue desde el primer segmento incompleto
— tras verificar que los hashes guardados en destino concuerdan.
Manifest por defecto en `/tmp/axross-resume/<safe-name>.json` (mode
0o600); override con `manifest_path=…`.

Verificación conservadora: cualquier mismatch en un segmento «done»
descarta el manifest y reinicia desde byte 0. Mejor retransmitir que
entregar un archivo medio corrupto.

S3 como destino actualmente cae en «reiniciar al fallar»
(integración multipart-upload es follow-up).

---

## `dashboard` — estado de federación en una pantalla

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

Tres formatos: `text` (REPL/status-bar), `markdown` (MCP/LLM), `json`
(GUI/scripts). Combina `core.conn_health` (latencia en vivo),
`core.visit_history` (último contacto), `core.operation_journal`
(ops recientes). Solo lectura.

`with_capacity=True` junto a `core.dashboard.snapshot_with_backends`
añade columnas `disk_usage()` (presupuesto 5 s por backend).

---

## Ver también

* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — referencia API auto-generada.
* [`docs/DAILY_DRIVER.md`](DAILY_DRIVER.md) — tarpit de producción + chunk adaptativo.
* [`docs/REVERSE_SERVE.md`](REVERSE_SERVE.md) — exponer un backend por S3 / WebDAV.
* [`docs/TRAIL.md`](TRAIL.md) — time-lapse / change-tracking de un directorio.
