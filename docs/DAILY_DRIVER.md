# Daily-Driver Primitives — Tarpit, Adaptive Chunking

Languages: **English** · [Deutsch](DAILY_DRIVER_de.md) · [Español](DAILY_DRIVER_es.md)

Two small primitives that sit underneath the multi-system verbs but
are worth knowing about on their own:

* **Production tarpit** — a 3-second countdown the first time you do
  something destructive on a profile flagged `production`. Anti-typo
  discipline.
* **Adaptive chunk-sizing** — every long-running stream picks a
  chunk size based on measured RTT + throughput, not a hard-coded
  buffer. Small enough on satellite links to stay responsive, large
  enough on a Gbit LAN to saturate it.

Read [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) for the verbs that
build on top of these.

---

## Production tarpit

Mark a profile as production:

```python
>>> from core.profiles import ConnectionProfile, ProfileManager
>>> p = ProfileManager().get("prod-db-04")
>>> p.production = True
>>> ProfileManager().save(p)
```

The first destructive op per pane-session against this profile gets
a 3-second countdown:

```
  ⚠ axross production tarpit
    target: prod-db-04 (sftp://prod-db-04.internal)
    op:     remove file /var/lib/postgresql/16/main/postmaster.pid
    Hit Ctrl-C in the next 3 s to abort.
       2.3s …
```

Default behaviour:

* **Once per pane-session.** The point is to break autopilot, not
  drown the operator. After the gate fires once, the pane runs at
  normal speed for the rest of the session.
* **Headless / REPL** — print to stderr, accept Ctrl-C as the bail
  signal. **GUI** — replaces the renderer with a coloured QDialog +
  countdown bar (call `core.safety_tarpit.set_countdown_renderer`
  from your Qt code).
* **Disable for CI** — set `AXROSS_TARPIT_DISABLE=1` in scripted
  environments. The flag is intentionally per-process; never
  `production=False` on the actual profile when you want CI to
  succeed against it.

Wrap any destructive op:

```python
from core.safety_tarpit import production_gate

with production_gate(profile, "remove file /var/log/foo.log",
                     session_id="pane-3"):
    backend.remove("/var/log/foo.log")
```

Inside the `with`, the gate either fired its countdown or was
suppressed (already armed earlier in this session). `KeyboardInterrupt`
during the countdown propagates out so the caller's destructive op
never runs.

The `production` flag round-trips through `ConnectionProfile.to_dict`
/ `from_dict` so it persists in `profiles.json`.

---

## Adaptive chunk-sizing

Hard-coded buffer sizes are wrong on more links than they're right.
A 1 MiB chunk that's optimal on a Gbit LAN burns RTTs on a 4G uplink
and is genuinely harmful on satellite (one chunk per round-trip;
RTT dominates throughput).

`core.adaptive_io.AdaptiveChunker` is a state machine: starts with
a 32 KiB probe chunk, measures throughput + RTT for the first 4
samples, then picks a steady chunk size from the bandwidth-delay
product:

```
chunk = clamp(throughput * 0.2s, MIN_CHUNK, MAX_CHUNK)
       (rounded to power-of-two)
```

Reassesses every 32 chunks. If measured throughput drops by ≥30 %,
halves; if it climbs by ≥30 %, doubles. Hysteresis bands prevent
oscillation.

Used by `axross.resumable_copy` internally; you can drive your own
loop:

```python
from core.adaptive_io import adaptive_copy

with src.open_read(src_path) as r, dst.open_write(dst_path) as w:
    moved = adaptive_copy(r, w, total_bytes=size, progress=cb)
```

Or finer control:

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

Bounds: 16 KiB ≤ chunk ≤ 16 MiB. Beyond 16 MiB most stacks fragment
and the adaptive feedback loop loses signal; the cap reflects what's
useful, not what's possible.

---

## See also

* [`docs/MULTI_SYSTEM.md`](MULTI_SYSTEM.md) — verbs that consume these primitives.
* [`docs/OPSEC.md`](OPSEC.md) — what the axross client reveals to the server.
* [`docs/REVERSE_SERVE.md`](REVERSE_SERVE.md) — expose a backend over S3 / WebDAV.
* [`docs/TRAIL.md`](TRAIL.md) — periodic snapshots of a directory tree.
