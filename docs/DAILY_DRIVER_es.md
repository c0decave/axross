# Primitivas de Daily-Driver — Tarpit, chunking adaptativo

[English](DAILY_DRIVER.md) · [Deutsch](DAILY_DRIVER_de.md) · [Español](DAILY_DRIVER_es.md)

Dos primitivas pequeñas debajo de los verbos multi-sistema:

* **Tarpit de producción** — countdown de 3 s la primera vez que
  haces algo destructivo en un perfil marcado `production`.
  Disciplina anti-typo.
* **Chunk adaptativo** — cada stream largo elige el tamaño de chunk
  según RTT + throughput medidos, no un buffer hardcodeado. Pequeño
  en links satelitales para mantener responsividad, grande en LAN
  Gbit para saturarlo.

[`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) tiene los verbos que
construyen sobre esto.

---

## Tarpit de producción

Marcar un perfil como producción:

```python
>>> from core.profiles import ConnectionProfile, ProfileManager
>>> p = ProfileManager().get("prod-db-04")
>>> p.production = True
>>> ProfileManager().save(p)
```

El primer op destructivo por pane-session contra ese perfil recibe
un countdown de 3 s:

```
  ⚠ axross production tarpit
    target: prod-db-04 (sftp://prod-db-04.internal)
    op:     remove file /var/lib/postgresql/16/main/postmaster.pid
    Hit Ctrl-C in the next 3 s to abort.
       2.3s …
```

Comportamiento por defecto:

* **Una vez por pane-session.** El punto es romper el autopiloto, no
  ahogar al operador. Tras un disparo, el pane corre a velocidad
  normal el resto de la sesión.
* **Headless / REPL** imprime a stderr, acepta Ctrl-C. **GUI**
  redirige el renderer a un QDialog con
  `core.safety_tarpit.set_countdown_renderer`.
* **CI** se deshabilita con `AXROSS_TARPIT_DISABLE=1` — flag por
  proceso; nunca pongas `production=False` solo para que el CI
  pase.

Envolver un op destructivo:

```python
from core.safety_tarpit import production_gate

with production_gate(profile, "remove file /var/log/foo.log",
                     session_id="pane-3"):
    backend.remove("/var/log/foo.log")
```

Dentro del `with` el gate ya disparó o se suprimió. Un
`KeyboardInterrupt` durante el countdown se propaga y el op no
corre.

El flag `production` round-trippea por `ConnectionProfile.to_dict` /
`from_dict`, persiste en `profiles.json`.

---

## Chunk adaptativo

Buffer hardcodeado está mal en más links que los que está bien.
1 MiB óptimo en LAN Gbit quema RTTs en 4G y es directamente dañino
en satélite (un chunk por round-trip; RTT domina throughput).

`core.adaptive_io.AdaptiveChunker` es una state machine: arranca con
chunk de prueba 32 KiB, mide throughput + RTT en las primeras 4
muestras, luego elige chunk steady desde el bandwidth-delay product:

```
chunk = clamp(throughput * 0.2s, MIN_CHUNK, MAX_CHUNK)
       (redondeado a potencia de dos)
```

Reasesa cada 32 chunks. Caída de throughput ≥30 % → halvar; subida
≥30 % → doblar. Banda de histéresis previene oscilación.

Lo usa `axross.resumable_copy`. Loop propio:

```python
from core.adaptive_io import adaptive_copy

with src.open_read(src_path) as r, dst.open_write(dst_path) as w:
    moved = adaptive_copy(r, w, total_bytes=size, progress=cb)
```

Control fino:

```python
from core.adaptive_io import AdaptiveChunker

c = AdaptiveChunker()
with src.open_read(p) as r:
    while True:
        chunk_size, _ = c.next_chunk()
        t0 = time.monotonic()
        buf = r.read(chunk_size)
        if not buf:
            break
        dst.write(buf)
        hint = c.record(len(buf), time.monotonic() - t0)
        if hint:
            log.debug(hint)
```

Bounds: 16 KiB ≤ chunk ≤ 16 MiB. Más allá de 16 MiB la mayoría de
stacks fragmentan y el feedback adaptativo pierde señal — el cap
refleja utilidad, no posibilidad.

---

## Ver también

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — verbos sobre estas primitivas.
* [`docs/OPSEC.md`](OPSEC.md) — qué revela el cliente al server.
* [`docs/REVERSE_SERVE.md`](REVERSE_SERVE.md) — exponer backend por S3/WebDAV.
* [`docs/TRAIL.md`](TRAIL.md) — snapshots periódicos de un directorio.
