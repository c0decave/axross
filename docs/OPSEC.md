# OpSec — What the Axross Client Reveals to the Server

Most threat modelling asks "what does an attacker send *to* me?" This
document asks the mirror question: when an Axross user connects to a
remote server, what does the **client** give away about itself — its
identity, its software stack, its local environment — to that server
and to any on-path observer?

The intended audience is someone who wants to use Axross from a
sensitive position (red-team C2, investigation work, journalism on a
hostile network) and needs to know which signals are inherent to the
protocol vs. avoidable fingerprints Axross leaves on top.

## Threat model

**In scope:**

- Application-layer fingerprints an observer can attribute to Axross
  specifically (distinct from any generic Python/OpenSSH/rsync
  client).
- Metadata that survives a transfer and lets the server correlate the
  upload to the client machine (local UIDs, mtimes, umask).
- Local-host information that leaks over auxiliary channels (DNS,
  env-var forwarding, banner strings).

**Out of scope:**

- OS-level network fingerprints (TCP timestamps, TTL, MSS, window
  scaling). That's an OS/kernel discipline — run Axross behind a
  platform that normalises these if you need it.
- TLS JA3/JA4 fingerprints of Python's stdlib `ssl` module. These
  are determined by OpenSSL's cipher list and Python's
  `ssl.create_default_context()`, not by Axross. Mitigation lives
  in the interpreter + OpenSSL build.
- User error (password typed into the wrong profile, hostname auto-
  completed from shell history, keys reused across identities).
- Whatever the server decides to log from what you legitimately send
  (your username, filenames you browse, paths you chmod).

## Design principle: blend in, don't randomise

Before describing the findings, one cross-cutting rule that drove the
mitigation choices below:

> **Constant randomisation is itself a fingerprint.**

A real Windows machine does not change its `WorkstationName` on every
SMB session. A real terminal does not pick new NAWS dimensions each
telnet connect. A real OpenSSH client doesn't jitter its keepalive
interval. If Axross **randomises**, it produces a signal that stands
out against the baseline of ordinary clients: "this endpoint's
identity drifts in a suspiciously non-human pattern".

The better play is to **blend into the dominant plurality**:

- Pick the single most common value (80×24 for NAWS, `OpenSSH_9.6p1`
  for SSH banner, `WORKSTATION` for SMB).
- Let the user **override per profile** when they know the target
  expects something specific. Overrides that the user consciously
  sets to match a cover story are low-risk; a tool that auto-rolls
  the dice is high-risk.
- When a value truly must be unique per install (e.g. an ADB pub
  key), make it as **uninformative as possible** — a fixed neutral
  comment, not `user@hostname`.

Only two places randomise by design: `secrets.token_hex(6)` for
atomic temp files (already unavoidable — you need per-write
uniqueness) and TLS session keys (protocol-mandated). Everything
else aims for boring and uniform.
