# Axross — Specification

Axross is a multi-protocol file manager and security toolkit. This
document records the product-shape invariants the codebase commits to
and the threat model the security goals are gated against.

The detailed entry-point inventory lives in
[`docs/ATTACK-SURFACE.md`](docs/ATTACK-SURFACE.md). This file is the
higher-level contract; the attack-surface doc is the per-ingress
breakdown.

## Scope

In-scope deliverables:

- A Qt-based desktop GUI (`PyQt6`) with multi-pane file workflows
  across 30+ protocols.
- A curated headless `axross.*` Python API for scripting and
  embedded REPL use.
- An MCP server (stdio and HTTP/SSE transports) that exposes a
  read-only-by-default subset of the API to LLM agents.
- Resource scripts under `resources/scripts/` runnable via
  `--script` or the REPL `.run` slash-command.

Out of scope: a hosted/managed service, a credentials database, a
network proxy, or any always-on listening daemon outside the
explicit `--mcp-http` mode.

## Public API stability

Public surface is the names exposed by `axross.__init__` and the
top-level functions in `core/scripting.py`. Renames and removals
require a Dependency-Justification trailer; additive changes do not.
A pinned baseline tag fixes the surface that `api_stable` measures
against.

## Operating modes

1. **GUI** — default; PyQt6 mainloop with file panes, REPL dock,
   bookmarks, layout presets.
2. **Headless script** — `axross --script <file|->` runs Python
   against the curated API without loading Qt.
3. **MCP stdio** — `axross --mcp-server`; LLM agent drives via
   JSON-RPC on stdin/stdout.
4. **MCP HTTP** — `axross --mcp-http HOST:PORT`; same dispatcher,
   HTTP transport. Non-loopback hosts require mTLS
   (`--mcp-cert/--mcp-key/--mcp-ca`).

A given process is in exactly one of the above modes; MCP-write and
script execution are independent feature flags layered on the MCP
modes.

## Security mode

`core/security_mode.py` defines tiered policies (`paranoid` blocks
both `--script` and MCP script execution). The current policy is
queried before any irreversible privileged operation.

## Threat Model

### Assets

1. **Local filesystem and home directory** — Axross reads/writes
   arbitrary local paths on behalf of the operator.
2. **Stored credentials** — connection profiles may carry
   passwords / SSH keys / OAuth tokens stored under
   `~/.local/state/axross/`.
3. **Remote sessions** — open backends hold authenticated
   connections to SFTP/SMB/S3/IMAP/etc.; abuse means full access
   to whatever those credentials reach.
4. **In-memory plaintext secrets** — passwords decrypted for use
   during a session sit in the GUI/MCP process memory.
5. **Operator audit log** — `~/.local/state/axross/logs/axross.log`
   records connection attempts; its integrity matters for after-
   the-fact incident review.

### Threat actors

- **T1 — Hostile remote server.** A target server Axross connects to
  (red-team or audit context). Fully controls the bytes it sends.
- **T2 — Malicious LLM/MCP client.** A model that has been
  prompt-injected via the documents it reads, or a compromised
  agent loop. Drives the MCP tool surface.
- **T3 — Network attacker between LLM and `--mcp-http`.** Tries
  TLS-downgrade, session-id replay, IP spoofing.
- **T4 — Co-tenant user on the host.** Unprivileged user trying
  to read Axross logs, credential cache, or REPL history.
- **T5 — Supply-chain attacker.** Compromised dependency on PyPI
  that Axross imports.
- **T6 — Operator running a hostile script.** Operator was tricked
  (phishing, copy-paste) into running a script that calls the
  `axross.*` API with malicious arguments.

### Trust boundaries

- **Operator ↔ filesystem.** Mediated by `_mutation_gate`,
  `destructive_preview`, `_refuse_existing_target_unless_overwrite`,
  `trash()` soft delete.
- **Axross ↔ remote server (T1).** Mediated by per-protocol parsers
  hardened against malformed responses, archive-extract `..`
  rejection, output-size caps, `conn_health` reconnect rate limit.
- **Axross ↔ MCP client (T2).** Mediated by MCP root pinned to
  `backend.home()`, write tools off by default, `script_run` gated
  by `--mcp-allow-scripts` AND non-paranoid security mode, task
  registry caps (`MAX_TASKS_PER_SCOPE`).
- **Network ↔ MCP HTTP listener (T3).** Mediated by mTLS
  (`CERT_REQUIRED`), `_PerIPRateLimiter`, idle session eviction,
  loopback-only-without-TLS policy.
- **Other host users ↔ Axross state (T4).** Mediated by mode 0700
  on `LOG_DIR` and mode 0600 on `LOG_FILE` and history files.
- **Axross ↔ PyPI deps (T5).** Mediated by pinned `pyproject.toml`,
  `pip-audit` in the `deps-cve-clean` gate, SBOM diff in
  `security/sbom_diff.py`.

### Top-rank attacks the design must prevent

- **A1 — Archive zip-slip.** Hostile archive containing `..` or
  absolute paths writes outside the destination. Defense: member
  name rejection in `core/archive.py`.
- **A2 — MCP path escape.** Tool argument like
  `../../etc/passwd` reads outside MCP root. Defense: path
  normalisation against `backend.home()` at request time.
- **A3 — Non-loopback MCP HTTP without TLS.** Bind to `0.0.0.0`
  without certs. Defense: explicit refusal in `main.py` bind
  guard.
- **A4 — Credential disclosure via logs.** Password leaks into
  `axross.log` from an exception. Defense: log
  formatters strip auth from URLs; passwords never go into
  `logger.debug(profile)`.
- **A5 — DoS by tool-call flood.** LLM agent in a loop spawns
  thousands of tasks. Defense: `MAX_TASKS_PER_SCOPE` cap and
  `_RateLimiter`.
- **A6 — Hostile remote inflates a stream.** A server claims a
  small file but streams gigabytes. Defense:
  `_read_capped_stream` and per-op byte caps in `atomic_io`.
- **A7 — Script-runner escape.** A `--script` runner attempting
  to read `/etc/shadow` or set `LD_PRELOAD` via `os.environ`.
  Defense: paranoid mode blocks `--script` entirely; non-paranoid
  modes trust the operator's choice (documented).
- **A8 — Cross-protocol relay overrun.** S3 → SFTP relay where
  the source lies about file size and the destination buffer
  blows up. Defense: cap-driven streaming in `adaptive_io.py`.
- **A9 — Pre-push secret-scanner bypass via crafted git artefacts.**
  A contributor (or a copy-paste accident from a hostile snippet)
  encodes a credential in a commit whose filename, content line, or
  merge-commit structure causes the `scripts/export-public.py` /
  pre-push secret scanner to skip the scan and let the secret reach
  the public mirror. Attack sub-classes seen and defended:

  - **A9a — Non-ASCII / quoted-form filename inconsistency.** A
    filename like `"\303\251vil"` is decoded inconsistently across
    `git ls-tree`, `git diff-tree`, `git show`, and `git status`
    callers, so a callsite that skipped the C-quoted form silently
    excluded the file from scanning. Defense:
    `--end-of-options` plus `--literal-pathspecs` on every callsite,
    and a single `parse_quoted_pathname` decoder reused by every
    consumer.
  - **A9b — Header-shape collision in diff content.** An added line
    whose payload begins with `++ b/<secret>` renders in unified
    diff as `+++ b/<secret>`, byte-identical to a real header.
    A shape-only header recogniser would route the line to the
    "skip, this is metadata" branch instead of scanning it.
    Defense: `DiffHeaderTracker` stateful gate
    (in-hunk-body ⇒ no-header), plus the trailing-space
    discriminator in `is_added_side_header`.
  - **A9c — Combined-diff multi-file tracker reset.** Merge-commit
    combined diffs use `diff --cc <path>` or `diff --combined <path>`
    as per-file separators, not `diff --git`. A tracker that reset
    state only on `diff --git` pinned `current_file` to the first
    file and (when that file matched `SCAN_EXCLUDE_PREFIXES`)
    silently skipped every subsequent file's content scan.
    Defense: `PER_FILE_SEPARATOR_PREFIXES` enumerates
    every git per-file emit shape and is consumed by both the
    tracker and a 2nd-layer caller reset.
  - **A9d — Merge-commit content skip.** A pre-push hook that only
    diffs against parent 1 misses adds introduced by the merge
    resolution itself. Defense: `changed_files_in_commit`
    is merge-aware and diffs against every parent.
  - **A9e — Fail-open on git failure.** A `commit_diff` /
    `git show` that swallowed git's non-zero exit and returned an
    empty diff let the scan pass as "clean" on what was really a
    broken read. Defense: every git invocation in the
    scan path propagates failures (fail-closed contract).
  - **A9f — Root-level filename-block bypass.** Slash-bearing
    blocked names (`.kube/config`) were only matched when nested
    under a parent directory; the same file at repo root slipped
    through. Defense: root-anchored matcher with a
    canonical-credential helper reused by every callsite.
  - **A9g — Staged-blob pathspec glob mis-resolution.** Without
    `--literal-pathspecs`, a staged blob path containing shell glob
    metacharacters resolved against the working tree instead of
    the index. Defense: `--literal-pathspecs` on every
    staged-blob resolution call.
  - **A9h — Scanner self-reference exclusion bypass.** The
    `is_excluded()` matcher for the SCAN_EXCLUDE_PREFIXES tuple
    used a bare `path.startswith(prefix)`, which lacks a path
    boundary for FILE-shaped entries (vs. directory-shaped entries
    whose trailing `/` supplies the boundary). A path that merely
    begins with a file entry's bytes — e.g.
    `scripts/export-public.py-evil.txt`,
    `.secrets-allowlistEVIL.py` — was treated as a scanner self-
    reference and the entire content scan skipped.
    Three-layer defense:
    1. Path-boundary-anchored matcher in
       `security.scan_exclude_paths.is_excluded_path` —
       directory entries keep `startswith` semantics; file
       entries require exact equality or `entry + "/"` prefix.
       The matcher also defensively skips empty entries even
       on a poisoned policy so a deserialization or
       `object.__setattr__` round-trip that bypasses the
       constructor cannot trigger worktree-wide exclusion.
    2. Policy-data validator in
       `security.scan_exclude_paths.validate_policy` raising
       `PolicyError` on empty / whitespace / double-slash
       entries. Available as a public callable for explicit
       fail-closed checks at caller-side import time.
    3. Mandatory construction-time validation via
       `ScanExcludePolicy.__post_init__` — every freshly
       constructed policy is validated, regardless of whether
       the caller remembers to invoke `validate_policy`. This
       closes the "future caller forgets to validate" gap by
       making the well-formedness check the dataclass's
       construction contract, not an optional follow-up.
  - **A9i — CR-injection in `+`-content line forges diff structure.**
    `str.splitlines()` breaks not only at `\n` but also at bare `\r`,
    `\v`, `\f`, `\x1c`-`\x1e`, U+0085, U+2028, U+2029 — none of which
    git emits as a structural terminator. A scanner that iterates
    `diff_text.splitlines()` therefore shatters a single
    `+`-content line whose payload carries embedded `\r` bytes into
    multiple "logical" fragments that the per-file-separator,
    `+++ b/<path>` header, and `@@` hunk-marker recognisers match in
    textual order. An attacker who committed a file whose content
    began with `OK\rdiff --git a/.secrets-allowlist
    b/.secrets-allowlist\r--- a/.secrets-allowlist\r+++
    b/.secrets-allowlist\r@@ -1,1 +1,1 @@\r+<FORBIDDEN>` produced a
    forged "header chain" that pinned `current_file` to a
    SCAN_EXCLUDE_PREFIXES entry, and `is_excluded(current_file)`
    silently skipped the trailing `+<FORBIDDEN>` payload.
    Two-layer defense:
    1. LF-only stream split in
       `security.diff_line_split.split_diff_stream` (the helper that
       `scripts/export-public.py:scan_diff_lines` consumes) keeps the
       CR-laced line as ONE element — the forged fragments never
       become standalone diff elements.
    2. `security.diff_line_split.added_line_has_internal_cr` is a
       named predicate every scanner can apply to pin
       `current_file := "<unknown>"` for any `+`-content line whose
       payload contains an embedded `\r` other than a single
       trailing CRLF artifact (Windows-checkout safety: legitimate
       `.secrets-allowlist` lines on a CRLF-source file MUST NOT be
       misclassified as injection). Taking the scanner-self-
       reference allowlist off the table even if a hypothetical
       future regression at the header-tracker layer accepted a
       CR-injected fragment as a header.
  - **A9j — Sidecar TOML silently dropped on tomllib-less Python.**
    `pyproject.toml` sets `requires-python = ">=3.10"` while
    `tomllib` only entered the stdlib in 3.11; on a supported 3.10
    runtime without a `tomli` polyfill the pre-fix
    `if not sidecar.exists() or tomllib is None: return` combined
    predicate at `scripts/export-public.py:Rules._overlay` made the
    operator-supplied `.public-export-rules.toml` (forbidden
    substrings / regexes / filenames / extensions) silently
    inactive — no warning, no log line, no failure. An operator who
    relied on a custom rule to block a project-specific secret
    pattern would get a "clean" scan that did not honour that rule.
    Two-layer defense:
    1. The loader at `scripts/export-public.py:Rules._overlay`
       splits the combined predicate and prints a loud stderr
       warning when the sidecar is present but the parser is
       missing, identifying both the sidecar path and the missing-
       parser root cause + two fix paths (install `tomli` polyfill
       OR upgrade to Python 3.11+).
    2. The disposition decision (ABSENT / ACTIVE /
       INACTIVE_NO_PARSER) lives in
       `security.sidecar_overlay_safety.decide_sidecar_overlay` so a
       future sidecar-shaped loader (separate scan-mode sidecar,
       audit tool, CI gate) that reaches for the same combined
       predicate has a named import to consult; the silent-drop
       path is unreachable through the helper because the
       `inactive_no_parser` branch carries a warning the caller can
       only drop on the floor by deliberately ignoring the return
       value of a frozen dataclass.
  - **A9k — Line-scope safety/placeholder bypass in
    `detect_secrets`.** `security.scan_natural_language.detect_secrets`
    tested `SECRET_PLACEHOLDERS` and `SECRET_SAFE_PATTERNS` against
    the FULL LINE (`line.strip()[:200]` and `line` respectively)
    instead of against the matched credential expression. So a real
    hardcoded credential whose line carried an unrelated, attacker-
    controlled trailing comment (`# TODO: rotate next quarter`,
    `# see example/config.py`, `# also from cfg.get('pw')`,
    `# legacy default; os.environ override at runtime`) silently
    dropped the SECRET finding because the comment text matched a
    placeholder/safe token. A single line of attacker-supplied
    comment, on a file that already passes review for its production
    code path, was enough to hide a hardcoded credential from the
    documented secret scanner. Same structural defect
    class as PATTERN-001 (boundary-trust mismatch): the security
    decision (`is this a legitimate non-secret?`) was computed over a
    wider scope than the bytes the decision is actually about.
    Defense: `detect_secrets` now scopes both the placeholder check
    and the safe-pattern check to `match.group(0)` — the matched
    assignment expression returned by the active SECRET_PATTERN
    regex — so the trailing-comment shape is unreachable: the
    placeholder/safe tokens must appear in the credential value or
    in the RHS of the assignment, not in a trailing comment, to
    suppress the finding. The high-entropy detector path
    (`security.scan_natural_language.detect_secrets` lines 918-936)
    already scopes its placeholder check to the captured credential
    value (`val`) and is unaffected.

  Trust-boundary assumption: contributors are *semi-trusted* — the
  team trusts each peer not to push a deliberate exploit, but the
  scanner is the last automated line of defense against accidental
  or "lazy-malicious" leaks (copy-pasted credentials, secrets
  inside merge-resolution patches, autogenerated fixtures
  containing real tokens). A maintainer with force-push access can
  always bypass any pre-push hook by rewriting history
  server-side; that is the operator's responsibility, not the
  scanner's.

### Out of scope (intentionally undefended)

- Operator-typed REPL code that imports `os` and calls
  `os.system`. The REPL is, by design, full Python.
- Kernel- or hypervisor-level attacks against the Axross host.
- Side-channel timing attacks against TLS / SSH; we trust the
  underlying library implementations.
- Quantum-capable adversaries; the cryptographic choices target
  classical attackers only.

### Detection / response

- `axross.log` (mode 0600) records connection attempts, tool
  calls, and any policy refusal. Operators are expected to ship
  this to their SIEM.
- `security/run_analysis.sh` orchestrates `bandit`, `pip-audit`,
  `semgrep`, `yara`, and entropy/network-egress scans for
  pre-release gating.
- A continuous security loop re-runs `vuln_scan`,
  `deps_cve_scan`, `scan_secrets`, and the OWASP-driven soft
  reviews regularly.

## Non-goals

- Axross is **not** a sandbox for executing arbitrary code from
  untrusted servers. Operators connecting to a hostile host must
  rely on Axross *parsers* being safe, not on Axross *isolating*
  them from the bytes.
- Axross does **not** provide a credentials vault — it integrates
  with the operator's keyring/SSH-agent rather than holding a
  master password.
