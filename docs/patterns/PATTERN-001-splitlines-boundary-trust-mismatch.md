# PATTERN-001 — Line-Delimiter Pluralism Injection
### a.k.a. `splitlines()` Boundary-Trust Mismatch

| Field | Value |
|---|---|
| Pattern ID | `PATTERN-001` |
| Severity | **HIGH** (silent scanner / parser bypass) |
| CWE | [CWE-93](https://cwe.mitre.org/data/definitions/93.html) (CRLF Injection) · [CWE-444](https://cwe.mitre.org/data/definitions/444.html) (Inconsistent Interpretation of HTTP Requests) · [CWE-707](https://cwe.mitre.org/data/definitions/707.html) (Improper Neutralization) |
| First seen | axross [SPEC §A9](../../SPEC.md#a9) (2026-05-30), in the A9 attack family |
| Affects | Any Python code that parses structured text with `str.splitlines()` where the **source** emits only one delimiter |

---

## TL;DR

Python's `str.splitlines()` recognises **eight** line-boundary characters:

```
\n  \r  \r\n  \v  \f  \x1c  \x1d  \x1e  U+0085  U+2028  U+2029
```

Most upstream emitters (git, syslog, unified-diff, HTTP, CSV per RFC 4180, NDJSON,
email headers) emit **exactly one** of these — usually `\n` or `\r\n`.

When the parser splits on a *superset* of the emitter's delimiter set, an attacker can
**embed the "extra" delimiters into a single emitter-record** and the parser splits
that record into multiple fragments — each of which is then interpreted as if it had
been emitted independently. Fragments can forge structural metadata (headers,
record separators, frame boundaries) that the rest of the parser trusts.

It is a **trust-boundary mismatch**: the emitter contracts on N delimiters, the
parser accepts ≥N+1, and the gap between them *is* the injection surface.

---

## Anatomy

```
┌─────────────┐                     ┌──────────────────────┐
│   Emitter   │  ── ONE delimiter ──▶│       Parser         │
│  (git, log, │      (e.g. \n)      │  splits on EIGHT     │
│   syslog,…) │                     │  via splitlines()    │
└─────────────┘                     └──────────────────────┘
                                              ▲
                                              │ Attacker injects
                                              │ bare \r / \v / U+2028
                                              │ into a SINGLE record
                                              ▼
                                    ┌──────────────────────┐
                                    │  Parser shatters that│
                                    │  record into multiple│
                                    │  "lines" — fakes a   │
                                    │  header / separator  │
                                    │  / frame boundary    │
                                    └──────────────────────┘
```

---

## Canonical Example — the axross diff-scanner case

### Vulnerable code

```python
# scripts/export-public.py  (pre-fix)
for line in diff_text.splitlines():
    if any(line.startswith(s) for s in PER_FILE_SEPARATOR_PREFIXES):
        current_file = "<unknown>"
    if tracker.feed(line):
        current_file = parse_new_side_path(line) or "<unknown>"
        continue
    if line.startswith("+") and not is_excluded(current_file):
        scan(line)
```

### Attacker payload

A single commit whose file content is:

```
OK<CR>diff --git a/.secrets-allowlist b/.secrets-allowlist<CR>--- a/.secrets-allowlist<CR>+++ b/.secrets-allowlist<CR>@@ -1,1 +1,1 @@<CR>+SECRET=AKIAIOSFODNN7EXAMPLE<LF>
```

Constructed with `printf 'OK\rdiff --git a/.secrets-allowlist...' > evil.txt`.

### What git emits

**One** `+`-content line, LF-terminated. The `\r` bytes are payload, not structure.

### What `splitlines()` produces

**Six** "logical" lines:

| # | Fragment | Parser interpretation |
|---|---|---|
| 1 | `+OK` | scanned (clean) |
| 2 | `diff --git a/.secrets-allowlist b/.secrets-allowlist` | matches `PER_FILE_SEPARATOR_PREFIXES` → `current_file` reset |
| 3 | `--- a/.secrets-allowlist` | tracker accepts as old-side header |
| 4 | `+++ b/.secrets-allowlist` | tracker sets `current_file = ".secrets-allowlist"` |
| 5 | `@@ -1,1 +1,1 @@` | `in_hunk_body = True` |
| 6 | `+SECRET=AKIAIOSFODNN7EXAMPLE` | **SKIPPED** — `is_excluded(".secrets-allowlist")` is True |

Scanner output: `clean (1 commits, 0 hits)`. Leak commits, then pushes.

---

## Generalisation — Where else this lurks

| Source format | Emitter delimiter | Injection vector | Real-world precedent |
|---|---|---|---|
| `git show` / `git diff` | `\n` | `\r` in `+`-content line | **axross diff-scanner** |
| Unified-diff post-process | `\n` | bare `\r`, `\v`, `\f` in additions | (general) |
| Syslog (RFC 5424) | `\n` | `\r` in `MSG` field forging fake `<PRI>` line | log-injection attacks |
| HTTP body / streamed | `\r\n` | bare `\r` or bare `\n` smuggling request-line | CVE-2019-9512 (HTTP/2), various smuggling |
| CSV (RFC 4180) | `\r\n` outside quotes | unquoted `\n` in field → fake row | CSV-injection class |
| NDJSON / JSONL | `\n` | `\r` in stringified field → fake record | NDJSON-injection |
| Email headers (RFC 5322) | `\r\n\r\n` body sep | bare `\n` in header value → fake header | CVE-2017-7493 (Roundcube), many |
| K8s/Docker structured logs | `\n` | embedded `\r` in container stdout | log-tampering |
| Python `logging` formatter | `\n` per record | `\r` in user data forging extra record | audit-log-evasion |

---

## Detection

### One-liner (any project, any time)

```bash
grep -rnE '\.splitlines\(\)' --include='*.py' .
```

Every hit is **suspect** — review the source. False-positive rate is high for code
that processes its own files (e.g. config readers) and zero for code that processes
foreign / network / subprocess output.

### Semgrep rule

See [`security/semgrep/splitlines_boundary.yml`](../../security/semgrep/splitlines_boundary.yml).

Levels:

* **ERROR** — `.splitlines()` directly chained off `subprocess.run([..., "git", ...]).stdout`
  or `subprocess.check_output([..., "git", ...])`. Also a taint-mode rule that follows
  git stdout → splitlines() through local variable assignments **within a single function**.
  Always wrong for git output.
* **WARNING** — `.splitlines()` on any subprocess stdout / `Path.read_text()` / `sys.stdin.read()`.
  Almost always wrong if the input is structured text.
* **INFO** — `.splitlines()` anywhere else. Catch-all so manual review at audit time
  is grep-able.

#### Coverage measured against axross's own pre-fix commit

Running the rule against the pre-fix `scripts/export-public.py` (the source where
the vulnerability lived for one commit):

| Tier | Fired? | Notes |
|---|---|---|
| ERROR direct-chain (`run([..., "git", ...]).stdout.splitlines()`) | ❌ | The vulnerable site received `diff_text` as a function parameter; the `subprocess.run(...)` call was in a sibling caller. semgrep CE's pattern matching does not span function boundaries. |
| ERROR taint mode (git stdout → splitlines()) | ❌ in CE | Taint sources/sinks span local variables but **not call edges** without `--pro`. The Pro engine (paid tier or `semgrep ci --login`) does inter-procedural taint and would fire. |
| WARNING `subprocess.run(...).stdout.splitlines()` | ❌ | Same root cause — cross-function flow. |
| INFO catch-all `$X.splitlines()` | ✅ **3 hits** including the vulnerable line (line 483) | All three hits are surfaced; a reviewer would inspect each and identify line 483 as the diff-stream case. |

**Takeaway.** A pure-syntactic rule **does** catch this — but only at INFO level
with mandatory manual review. Inter-procedural taint (semgrep Pro or equivalent)
would catch it at ERROR level automatically. Treat the INFO catch-all as a
**review reminder**, the ERROR/WARNING tiers as **fast-fail for the easy cases**, and
the architectural fix (`security/diff_line_split.py`) as the **structural guarantee**
that new callers do the right thing without relying on the scanner.

### Bandit

Bandit 1.9 does **not** ship a detector for this pattern. There is no standard plugin
that flags `str.splitlines()` semantics. A custom Bandit plugin is possible but
semgrep is the cleaner integration point.

### Manual review checklist

When you see `.splitlines()` in code that processes anything from outside the process:

- [ ] **What emits this text?** Single source-of-truth: read the upstream contract. git emits `\n`. HTTP emits `\r\n`. RFC 5424 syslog emits `\n`.
- [ ] **Can attacker influence the bytes between emitter delimiters?** If yes (commit content, log message, header value, body, …), the bug is live.
- [ ] **Does any subsequent code branch on `line.startswith(...)` or `re.match(line, ...)`?** Each such branch is a potential forged-structural-metadata target.
- [ ] **Is there an allowlist / exclusion / "metadata" branch the attacker would want to land on?** That is the bypass target.

---

## Mitigation

### Primary fix — use the emitter's actual delimiter

```python
# git emits \n. Split only on \n.
for line in diff_text.split("\n"):
    ...
```

`str.split("\n")` produces a trailing empty string on terminal `\n`; either tolerate it
(`if not line: continue`) or `.rstrip("\n")` first.

Equivalents for other formats:

| Source | Use |
|---|---|
| `git ...` | `.split("\n")` |
| HTTP message | `.split("\r\n")` |
| Syslog RFC 5424 | `.split("\n")` |
| CSV | `csv.reader(io.StringIO(text))` — never split-then-parse |
| NDJSON | `for raw in text.split("\n"): json.loads(raw)` |
| Email | `email.parser.Parser().parsestr(...)` |

### Defense-in-depth — content-line discriminator

For diff-style parsers, also reject `+`-content lines whose payload carries
internal `\r` (not the trailing-CRLF artefact of CRLF-source files):

```python
def added_line_has_internal_cr(line: str) -> bool:
    if not line.startswith("+"):
        return False
    payload = line[1:].removesuffix("\r")   # strip ONE trailing CR-artefact
    return "\r" in payload
```

When True, force the metadata-state-machine into its safe state (`current_file =
"<unknown>"`) so any exclusion based on tracked metadata can't apply to that line.

Even if a future regression at the splitter reintroduces `splitlines()`, this guard
keeps the bypass closed.

### Architectural — extract into a contract-pinned helper

Don't leave the splitting policy inline at every callsite. Lift it into a named
helper module whose docstring is the contract:

```python
# security/diff_line_split.py
"""Scanners that process git's diff stream MUST split on \\n only.
A regression that re-introduces splitlines() reopens the bypass."""

def split_diff_stream(diff_text: str) -> list[str]:
    return diff_text.split("\n")
```

Now any new scanner that imports `split_diff_stream` is automatically safe; the
"naive way" (`for line in diff.splitlines()`) is a code-review-visible cross-module
change instead of a one-character edit that blends in.

### Detection at PR time

Run the semgrep rule in CI on every PR. Both vulnerable patterns and the
recommended fix should be enforceable as machine-checked policy.

---

## References

* axross [`SPEC.md` § A9](../../SPEC.md) — Pre-push secret-scanner bypass attack family
* axross [reproduce commit](../../../../commit/8fad9cf) — full PoC + adversarial framing
* axross [fix commit](../../../../commit/d16f829) — 2-layer defense lifted into `security/diff_line_split.py`
* [CPython docs — `str.splitlines`](https://docs.python.org/3/library/stdtypes.html#str.splitlines) — authoritative list of recognised line boundaries
* [CWE-93](https://cwe.mitre.org/data/definitions/93.html) — CRLF Injection
* [CWE-444](https://cwe.mitre.org/data/definitions/444.html) — Inconsistent Interpretation of HTTP Requests (Smuggling)
