# Credential Testing — Brute-Force, Spray, User Enumeration

Languages: **English** · [Deutsch](CRED_ATTACK_de.md) · [Español](CRED_ATTACK_es.md)

Axross ships a small credential-testing surface (`core.cred_attack`,
exposed as `axross.bruteforce`, `axross.spray` and
`axross.enumerate_users`) for **authorised** assessments — pentests
you have written permission for, lab self-tests, and CTF environments.
The whole module refuses to run unless the caller passes
`authorized=True`; this gate is a hard refusal, not a polite hint, and
there is no env-var override.

This document explains what the surface does, how the safety defaults
behave, and what to read before you run it against anything live.

> **Read this first.** Credential testing is intrusive, noisy on the
> wire, and easy to misuse. The defaults below are conservative for a
> reason. If you find yourself loosening them, write down *why* in the
> engagement notes — future you will want the receipt.

---

## What the API does

| Function | Pattern | Use case |
|---|---|---|
| `axross.bruteforce(profile, users=…, passwords=…)` | iterate `user × password` (user-major) | One target user, many candidate passwords. Or many users when you accept the per-user lockout risk. |
| `axross.spray(profile, users=…, password=…)` | iterate `password × user` (password-major) | One password against a user pool — the standard pattern against AD / Microsoft 365 where lockout is per-user-per-window. |
| `axross.enumerate_users(profile, candidates, method=…)` | per-protocol oracle or statistical timing | Probe whether each candidate username exists on the target *before* you fire any spray. |

All three accept either a `ConnectionProfile` instance or the name of
a saved profile. Network settings (host, port, proxy, TLS) are taken
from the template; the username and password are overridden per
attempt.

---

## OPSEC defaults — what you get out of the box

The defaults are tuned to produce **the smallest signal that still
gets the job done**. You can override every one of them per call;
the point is that "do nothing" runs are the safe path.

| Default | Value | Why |
|---|---|---|
| Authorisation gate | `authorized=True` is required | One-line refusal of the surface for casual misuse. No env-var skip, no remembered "yes". |
| Rate limit | 30 attempts / minute | One attempt every two seconds blends with normal user-error login retries. Faster fires honour-system IDS rules at most well-run targets. |
| Per-attempt timeout budget | 10 s | Attempts that return after the budget become `ERROR`; hard blocking is still bounded by each protocol backend's own socket/connect timeout. |
| Lockout abort | First `LOCKOUT` outcome stops the run | One signal is enough — the next two would be policy violations. Loosen explicitly if your engagement letter allows. |
| Stop on first success per user | True | Don't keep guessing once a user is in. |
| Password handling in logs | SHA-256 prefix only | Cleartext passwords never reach the structured logger. Successful credentials are returned to the caller in plaintext, which is what they came for. |
| Resume state | opt-in JSON file | If you need to survive Ctrl-C, pass `state_file=…`; the file is rewritten atomically after every attempt. Treat it as sensitive — it carries username + password-hash pairs and the target identity. |
| Paranoid security mode | refuses the whole module | Set `AXROSS_SECURITY_MODE=paranoid` and credential testing is blocked entirely until you switch back. |

---

## Brute-force vs. spray — pick one

The two share an engine; only the iteration order changes. That order
is the difference between a quiet engagement and an account-locked
helpdesk ticket.

* **Brute-force** (`axross.bruteforce`): try every password for user 1,
  then user 2, and so on. Goes through one user's lockout window
  *fast*. Right when you have a single user and a long candidate-list,
  or when the target has no lockout policy (offline KDC dump, lab
  workstation, etc).

* **Spray** (`axross.spray`): try one password against every user, then
  the next password. Each user sees one attempt per pass; lockout
  windows rarely fill up. Right for AD / Entra ID / OWA / IMAP-on-real-MTA
  / WebDAV-on-Nextcloud / SMB-on-domain-member.

If you don't have a strong reason to brute-force, **spray**.

For SSH/SCP targets, host-key policy still applies. If the host key is
not already trusted, pass an explicit `on_unknown_host=` callback that
implements your engagement's trust rule; the credential-testing surface
will not auto-trust SSH hosts by default.

The module fails closed for protocols/profiles where candidate
passwords are not consumed during connect (for example TFTP/NFS/RamFS,
OAuth-only cloud drives, or Azure profiles that already carry a
connection string/SAS token). That avoids false-positive "success"
reports on transports that are not actually authenticating the
candidate secret.

---

## Lockout classification — the heuristic

`core.cred_attack.classify_error()` inspects the exception text from
each failed attempt and decides:

* `LOCKOUT` — strings like `account locked`, `STATUS_ACCOUNT_LOCKED_OUT`,
  `too many login attempts`, `rate limit`, `throttle`, `try again later`,
  IIS / Postfix / Dovecot / OpenLDAP / sshd-PAM / Cisco IOS wording, …
* `FAILED` — `authentication failed`, `permission denied`, `no such user`,
  `STATUS_LOGON_FAILURE`, `incorrect password`, …
* `ERROR` — connection refused, timeout, name resolution failure,
  broken pipe, …
* default → `ERROR` (unknown wording may be a backend crash, TLS issue,
  proxy failure, or parser bug; do not silently count it as a wrong
  password).

The classifier is intentionally heuristic. The list of markers is in
`core/cred_attack.py`; if your target uses bespoke wording, extend it
at runtime:

```python
from core.cred_attack import register_marker

# A custom appliance that says "ACCOUNT FROZEN" on lockout and
# "BAD CREDS" on plain auth-fail.
register_marker("account frozen", kind="lockout")
register_marker("bad creds", kind="auth_fail")
```

The order matters — lockout markers are checked first so an exception
that says "too many failed login attempts — account locked out" is
classified as LOCKOUT (which contains `failed`, but matches LOCKOUT
first).

---

## User enumeration

Two orthogonal methods:

### Oracle (`method="oracle"` or `"auto"` when registered)

The protocol leaks user existence through a difference in error
behaviour between known and unknown usernames. Built-in oracles:

| Protocol | Mechanism | Confidence |
|---|---|---|
| `pop3` | `USER` / `PASS` response wording — `no such user` vs `auth failed` | 0.7–0.9 |
| `ftp` / `ftps` | `USER` returns `331 Password required` (known) vs `530 user cannot log in` (unknown) | 0.7–0.8 |

Add your own at runtime via `register_oracle(protocol, callable)`.
The callable signature is `(profile, candidates: list[str], timeout_s: float, *, rate_limiter=None, jitter_s=0.0) -> list[EnumResult]`.
Older three-argument custom oracles still run, but axross logs a
warning because those callables must apply their own pacing.

### Timing (`method="timing"` or `"auto"` fallback)

Generic. Works on any backend reachable through `ConnectionManager`.
For each candidate the loop fires `timing_samples` (default 5) login
attempts with a junk password and records the wall-clock time. Per
candidate it takes the **median** (robust against outliers); across
candidates it computes the global median + median-absolute-deviation
(MAD) and flags candidates whose median exceeds `global + 3·MAD` as
"likely exists" (the server actually performed a hash compare) and
those below `global − 3·MAD` as "likely doesn't exist" (short-circuit).
Candidates inside the noise floor return `confidence=0`.

Both oracle probes and timing attempts are paced by the same
`rate_per_min` default as `spray`/`bruteforce` (30/min). Timing uses
one token per login attempt, so `timing_samples=5` means at least five
paced probes per candidate.

Caveats:

* Timing-based results have a real false-positive rate. Treat them as
  a hint, not as evidence. Validate the strong hits with a single
  spray pass against just those usernames.
* Server-side rate limiting flattens timing differences. If the target
  is fronted by a WAF that injects a synthetic delay, timing is dead;
  use the oracle path or skip enumeration.
* If you can avoid it, don't enumerate at all — use a list you already
  have from OSINT / phishing-pretext recon. Enumeration creates extra
  log lines on the target.

---

## Resume after Ctrl-C

Pass `state_file="/path/to/run.json"` to either `bruteforce` or
`spray`. The runner:

1. Loads any prior state file at the top of the run. If the file
   targets a different host/port/protocol it's ignored (the warning is
   logged) and a fresh run starts.
2. After every attempt, atomically rewrites the file with the
   running set of `[username, password_hash]` pairs already tried plus
   the running set of `[username, password_hash]` pairs that succeeded.
3. On a subsequent run, skips any `(user, hash)` pair already in the
   attempted list and emits a `SKIPPED` outcome for it.

Because the state file holds password **hashes**, not the cleartext
passwords, it is safe to ship between operator boxes — but the file
still carries target identity (host/port/protocol) and the names of
every user attempted, so treat it as sensitive engagement data.

---

## Progress callbacks

`progress=callable` fires with each `AttemptOutcome` (or `EnumResult`).
Useful for live UIs, structured-log redirection, or external dashboards:

```python
from core.cred_attack import AttemptOutcome, AttemptResult

def show(outcome: AttemptOutcome) -> None:
    if outcome.result is AttemptResult.SUCCESS:
        print(f"  ✓ {outcome.username}")
    elif outcome.result is AttemptResult.LOCKOUT:
        print(f"  ✗ LOCKOUT user={outcome.username}")

axross.spray(
    profile, users=[…], password="Spring2026!",
    progress=show, authorized=True,
)
```

Exceptions raised in your callback are logged (`WARNING`) and
swallowed; the run does not abort.

---

## Examples

Runnable scripts under [`examples/`](../examples/):

* [`examples/spray_pop3.py`](../examples/spray_pop3.py) — single-password spray against a POP3 mailbox pool.
* [`examples/bruteforce_ssh.py`](../examples/bruteforce_ssh.py) — brute-force against one SSH account with a candidate list and a resume file.
* [`examples/enum_pop3.py`](../examples/enum_pop3.py) — POP3 user-enum oracle then spray only the hits.
* [`examples/dry_run.py`](../examples/dry_run.py) — generate a run plan without firing any packets.

All examples take `authorized=True` only after a literal confirmation
prompt — copy them as a starting point but keep that prompt.

---

## Hard rules

These are not suggestions:

1. **Authorisation in writing.** A paying customer's verbal "go ahead"
   is not a scope document. Hold the engagement letter before you call
   any of these functions against a third-party target.
2. **No third-party targets in tests.** The module's own test suite
   never connects to the open internet — it uses dummy in-process
   stubs. Don't change that.
3. **Don't loop on `ERROR`.** A network error is not authoritative;
   the runner already does NOT count it against the lockout budget,
   but if `ERROR` outcomes start dominating, **stop the run** and
   investigate. A misconfigured proxy, a dropped VPN, or a target's
   anti-bot WAF can make every attempt look transient when the target
   has actually started rate-limiting your source IP.
4. **Don't run with `abort_on_lockout=False` "for speed".** That flag
   exists for the engagement where the customer explicitly says "you
   may exhaust the lockout policy as part of the test"; it is not a
   throttle bypass.
5. **Treat the success list as compromised material.** Cleartext
   passwords are returned to the caller — write them to a sealed file
   immediately, and never to a shell history or to a process invoked
   via `subprocess.run([…, password])`.

---

## See also

* [`docs/OPSEC.md`](OPSEC.md) — what the axross client reveals to the server.
* [`docs/SCRIPTING_REFERENCE.md`](SCRIPTING_REFERENCE.md) — full `axross.*` API reference.
* [`docs/RED_TEAM_NOTES.md`](RED_TEAM_NOTES.md) — adversarial review of every backend.
* [`SECURITY.md`](../SECURITY.md) — vulnerability disclosure policy.
