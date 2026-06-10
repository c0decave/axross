# Daily-Driver-Primitives — Tarpit, adaptive Chunking

[English](DAILY_DRIVER.md) · [Deutsch](DAILY_DRIVER_de.md) · [Español](DAILY_DRIVER_es.md)

Zwei kleine Primitives unter den Multi-System-Verbs:

* **Production Tarpit** — 3-Sekunden-Countdown beim ersten Destruktiv-Op
  pro Pane-Session gegen ein als `production` markiertes Profil.
  Anti-Typo-Disziplin.
* **Adaptive Chunk-Größe** — jeder Long-Running-Stream wählt die
  Chunk-Größe aus gemessener RTT + Throughput, statt aus einem
  hartcodierten Buffer. Klein genug auf Sat-Links für Reagibilität,
  groß genug auf Gbit-LAN für Sättigung.

[`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) hat die Verbs, die hierauf
aufbauen.

---

## Production Tarpit

Profil als production markieren:

```python
>>> from core.profiles import ConnectionProfile, ProfileManager
>>> p = ProfileManager().get("prod-db-04")
>>> p.production = True
>>> ProfileManager().save(p)
```

Der erste Destruktiv-Op pro Pane-Session bekommt einen 3-Sek-Countdown:

```
  ⚠ axross production tarpit
    target: prod-db-04 (sftp://prod-db-04.internal)
    op:     remove file /var/lib/postgresql/16/main/postmaster.pid
    Hit Ctrl-C in the next 3 s to abort.
       2.3s …
```

Default-Verhalten:

* **Einmal pro Pane-Session.** Punkt ist Autopilot-Brechen, nicht
  den Operator zumüllen. Nach einem Trigger läuft das Pane normal
  weiter.
* **Headless / REPL** schreibt nach stderr, akzeptiert Ctrl-C.
  **GUI** kann den Renderer mit
  `core.safety_tarpit.set_countdown_renderer` auf einen QDialog
  umlenken.
* **CI deaktivieren** mit `AXROSS_TARPIT_DISABLE=1` — flag ist
  prozess-lokal; setze niemals `production=False` am Profil nur damit
  CI durchläuft.

Destruktiv-Op wrappen:

```python
from core.safety_tarpit import production_gate

with production_gate(profile, "remove file /var/log/foo.log",
                     session_id="pane-3"):
    backend.remove("/var/log/foo.log")
```

Im `with` ist der Gate entweder gefeuert oder unterdrückt. Ein
`KeyboardInterrupt` während des Countdowns propagiert raus, der
Op läuft nicht.

`production`-Flag round-trippt durch `ConnectionProfile.to_dict` /
`from_dict`, persistiert in `profiles.json`.

---

## Adaptive Chunk-Größe

Hardgecodete Buffer-Größen sind auf mehr Links falsch als richtig.
1 MiB optimal auf Gbit-LAN brennt RTTs auf 4G und ist auf Satellit
direkt schädlich (1 Chunk pro Round-Trip; RTT dominiert Throughput).

`core.adaptive_io.AdaptiveChunker` ist eine State-Machine: startet
mit 32 KiB Probe-Chunk, misst Throughput + RTT für die ersten 4
Samples, dann steady-Chunk-Größe aus Bandwidth-Delay-Product:

```
chunk = clamp(throughput * 0.2s, MIN_CHUNK, MAX_CHUNK)
       (auf Power-of-Two gerundet)
```

Reassessment alle 32 Chunks. Throughput-Drop ≥30 % → halbieren;
Throughput-Anstieg ≥30 % → verdoppeln. Hysterese-Bänder gegen
Oscillation.

Used by `axross.resumable_copy`. Eigene Loop:

```python
from core.adaptive_io import adaptive_copy

with src.open_read(src_path) as r, dst.open_write(dst_path) as w:
    moved = adaptive_copy(r, w, total_bytes=size, progress=cb)
```

Feinere Kontrolle:

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

Bounds: 16 KiB ≤ chunk ≤ 16 MiB. Über 16 MiB fragmentieren die meisten
Stacks und das adaptive Feedback verliert Signal — Cap reflektiert
Nutzbarkeit, nicht Möglichkeit.

---

## Siehe auch

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — Verbs auf diesen Primitives.
* [`docs/OPSEC.md`](OPSEC.md) — was der axross-Client dem Server preisgibt.
* [`docs/REVERSE_SERVE.md`](REVERSE_SERVE.md) — Backend per S3/WebDAV exponieren.
* [`docs/TRAIL.md`](TRAIL.md) — periodische Snapshots eines Verzeichnisses.
