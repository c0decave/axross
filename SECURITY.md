# Security Policy

## Supported versions

Axross is pre-1.0. Only the latest tagged release on `main` receives
security fixes. Older tags are historical.

## Reporting a vulnerability

Please report suspected vulnerabilities by email to
**mlux@undisclose.de** with subject prefix `[axross security]`.
If you prefer encrypted mail, request the PGP key at the same address first.

Do **not** file a public GitHub issue for anything with exploit potential
until we've had a chance to acknowledge and fix the report.

### What to include

- Version / commit SHA you tested against.
- Protocol backend or subsystem affected (`core/mcp_server.py`,
  `core/archive.py`, `core/fuse_mount.py`, a specific client, …).
- Reproduction steps — ideally a minimal script or `pytest` case.
- Expected vs. observed behavior.
- Whether the issue is exploitable remotely or only locally.

### What to expect

- **Acknowledgement** within 3 working days.
- **Triage and severity assessment** within 7 working days.
- **Fix timeline** depends on severity:
  - Critical (RCE, auth bypass, sandbox escape): patch targeted within 14
    days plus a coordinated disclosure window.
  - High (privilege escalation, data exposure, cryptographic weakness):
    within 30 days.
  - Medium / Low: batched into the next regular release.
- **Credit** in the release notes and `NOTICE` if you wish — please state
  your preferred attribution in the initial report.

## Non-security bugs

Regular bugs (crashes that aren't exploitable, UI glitches, failing tests
in specific environments) go into the normal GitHub issue tracker.

## Known boundaries of trust

Axross is a user-facing file manager; it trusts its operator. The project
does **not** attempt to mitigate threats that originate from:

- A malicious local user account with write access to `~/.config/axross/`
  or your OS keyring.
- A malicious Qt theme / plugin loaded by the runtime.
- An attacker who has already escaped the FUSE mount containment and is
  running arbitrary code as the axross user.

It **does** attempt to mitigate:

- Rich-text / markup injection through filenames and profile labels
  (`QLabel`, `QMessageBox`, `QAction` user-supplied text goes through
  `html.escape` plus strip of `<` `>`).
- Zip-slip, tar-symlink, and archive-bomb attacks against
  `core/archive.py` (realpath containment, post-`makedirs` symlink
  re-check, `MAX_EXTRACT_FILES` / `MAX_EXTRACT_TOTAL_BYTES` / compression
  ratio caps, ground-truth size verification against lying metadata).
- Path traversal through the MCP write tools (`_enforce_root` with
  symlink-resolving containment check).
- Credential leakage via accidentally-world-readable token files
  (`0o600` from birth via `fchmod` on the temp fd before rename).
- Cross-session log leakage in the HTTP MCP transport.

Anything you think belongs on that list but isn't — please report.
