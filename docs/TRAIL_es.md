# Trail — Snapshots time-lapse de un directorio

[English](TRAIL.md) · [Deutsch](TRAIL_de.md) · [Español](TRAIL_es.md)

Elige un path en cualquier backend que axross hable. Dile a axross
que tome un snapshot de metadata cada N segundos. Después reproduces
la timeline y ves *qué cambió cuándo* — files añadidos, eliminados,
saltos de mtime, opcional drift de hash de los primeros 32 KiB.

> **Trail no es una herramienta de backup.** Guarda un *registro de
> cambios*, no contenido. Úsalo para change-tracking («¿alguien tocó
> /etc/cron.d en las últimas 24 h?»), reconstrucción forense de
> timeline («¿cuándo saltó la mtime de este binario?»), monitoreo de
> crecimiento («el dir de logs creció 800 MB durante la noche —
> ¿cuándo?»).

| Verbo | Qué hace |
|---|---|
| `axross.snapshot_now(backend, path)` | Tomar un snapshot ahora. |
| `axross.start_trail(backend, path, interval_s=300)` | Snapshots periódicos en background. |
| `axross.stop_trail(name)` | Detener un trail nombrado. |
| `axross.list_trails()` | Listar cada trail registrado. |
| `axross.list_snapshots(trail_name)` | Listar snapshots de un trail (más reciente primero). |
| `axross.diff_snapshots(snapshot_a, snapshot_b)` | Diff de dos snapshots — added / removed / modified. |

---

## Almacenamiento

* Base SQLite en `~/.config/axross/trail.db`, mode 0o600.
* Esquema: `trails` (config), `snapshots` (resumen por snapshot),
  `files` (una fila por archivo × snapshot).
* Una fila por archivo por snapshot — limitado por
  `MAX_FILES_PER_SNAPSHOT` (5000 default).
* Sin contenido. Opcional `head_hash=True` lee los primeros 32 KiB
  por archivo y guarda SHA-256 prefix; off por default porque paga
  N reads por snapshot contra el backend.

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

Esperar 5 min, modificar un config, otro snapshot:

```python
>>> snap2 = axross.snapshot_now(b, "/etc/nginx/conf.d")
>>> diff = axross.diff_snapshots(snap.snapshot_id, snap2.snapshot_id)
>>> print(diff.summary())
+0 added, -0 removed, ~1 modified, 13 unchanged
>>> diff.modified
['/etc/nginx/conf.d/upstream.conf']
```

El trail tiene ahora dos snapshots en la base. Render de la
timeline:

```python
>>> from core.trail import render_timeline
>>> print(render_timeline("alice@prod-web-01:22:/etc/nginx/conf.d"))
trail alice@prod-web-01:22:/etc/nginx/conf.d:
  · #2     2026-05-09 14:35:04  files=14     bytes=8192         tree=88aa…
  · #1     2026-05-09 14:30:12  files=14     bytes=8192         tree=a7c3…
```

---

## Loops en background

`axross.start_trail` corre el loop de snapshots en un thread daemon:

```python
>>> name = axross.start_trail(
...     b, "/etc/cron.d",
...     interval_s=600,            # cada 10 min
...     head_hash=True,            # también drift-check primeros 32 KiB
... )
>>> name
'alice@prod-web-01:22:/etc/cron.d'
>>> # … después …
>>> axross.stop_trail(name)
True
```

* Intervalo mínimo 30 s. Default 300 s.
* Thread daemon — muere con el proceso. `axross.stop_trail(name)`
  para shutdown limpio.
* Múltiples trails en paralelo sin interferir.
* Cada snapshot es su propia transacción SQLite — un intérprete que
  crasheea nunca deja un snapshot a medias.

---

## Tree-hash

Cada snapshot lleva un `tree_hash` — SHA-256 del manifest ordenado
por path. Dos snapshots con mismo `tree_hash` son idénticos a nivel
de mtime + size + (opcional) head-hash. Check barato «¿cambió
algo?» = `a.tree_hash == b.tree_hash`.

El diff (`added` / `removed` / `modified`) es lo que necesitas para
saber *qué* cambió; `tree_hash` es el check O(1) «¿hubo cambios?».

---

## Export

```python
>>> from core.trail import export_trail_jsonl
>>> n = export_trail_jsonl(name, "/tmp/cron-trail.jsonl")
>>> n
72
```

JSONL una-línea-por-snapshot — para análisis offline o conexión a
otra herramienta. Export es solo metadata; las filas de archivo
quedan en SQLite para queries rápidas y no van en el JSONL default.

---

## Truncation

Un snapshot es `truncated=True` si el directorio tiene más archivos
que `max_files`. El walker para en el cap, el trail sigue
funcionando — pero el snapshot truncado es solo una vista top-N. Dos
snapshots truncados pueden mostrar entradas false-«removed» si el
cap recortó partes distintas del árbol.

Sube `max_files` por llamada (`axross.snapshot_now(b, path,
max_files=20000)`) cuando necesites un árbol denso completo. La DB
SQLite lo paga lineal, así que 20000 × 50 snapshots está bien,
1.000.000 × 50 no.

---

## OPSEC

* La DB del trail lleva el layout de paths de cada directorio que
  snapshoteaste. Mode 0o600; trátalo como dato sensible.
* `head_hash=True` causa un read por archivo por snapshot. Visible
  en la línea, visible en logs del server. Úsalo con moderación.
* Trail no se inscribe en `core.conn_health` — un backend stallado
  simplemente dropea el snapshot de ese intervalo (warning en log),
  no afecta otros trails.

---

## Ver también

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — verbos para comparar archivos entre hosts.
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — referencia API completa.
