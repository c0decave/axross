"""Defense-in-depth helper: classify git pre-push stdin tuples.

git invokes pre-push hooks with one line per ref of the shape::

    <local-ref> SP <local-sha> SP <remote-ref> SP <remote-sha>

with the all-zero sha (``ZERO_SHA``) used for "does not exist". Four
distinct kinds of updates can appear and each needs a different scan
strategy:

* **create**  — first push of a new branch (``remote_sha == ZERO_SHA``).
  Scan every commit reachable from ``local_sha``.
* **delete**  — branch deletion (``local_sha == ZERO_SHA``). No commits
  are being added; scan must short-circuit.
* **update**  — normal update (both shas non-zero). Scan
  ``remote_sha..local_sha``.
* **noop**    — same sha both sides (idempotent push). Nothing to scan.

Centralising this classification keeps the policy-of-record in
``security/`` rather than scattered inside the hook script, so any
other callsite (CI gate, second hook, future audit tool) reuses the
same definition and we cannot regress the empty-range handling that
previously crashed on branch deletions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

ZERO_SHA = "0" * 40

PushKind = Literal["create", "delete", "update", "noop"]


@dataclass(frozen=True)
class PushRefUpdate:
    """One classified ref update from pre-push stdin."""

    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str
    kind: PushKind

    @property
    def needs_commit_scan(self) -> bool:
        """True iff this update introduces commits that must be scanned."""
        return self.kind in ("create", "update")


def is_zero_sha(sha: str) -> bool:
    """A sha is "zero" iff it is exactly 40 ASCII '0' chars.

    git only writes the canonical ZERO_SHA; we accept the canonical form
    only and refuse to be lenient (a malformed shorter zero string is a
    sign of corruption, not a deletion intent).
    """
    return sha == ZERO_SHA


def classify_push_line(line: str) -> PushRefUpdate | None:
    """Parse one pre-push stdin line; return None for malformed input.

    Refuses to guess on lines that do not have exactly 4 whitespace-
    separated fields — the caller's correct response is to skip them,
    not to crash and not to fall through to a default kind.
    """
    parts = line.strip().split()
    if len(parts) != 4:
        return None
    local_ref, local_sha, remote_ref, remote_sha = parts
    kind = _kind(local_sha, remote_sha)
    return PushRefUpdate(
        local_ref=local_ref,
        local_sha=local_sha,
        remote_ref=remote_ref,
        remote_sha=remote_sha,
        kind=kind,
    )


def classify_push_stdin(lines: Iterable[str]) -> list[PushRefUpdate]:
    """Parse all pre-push stdin lines; drop malformed ones."""
    out: list[PushRefUpdate] = []
    for line in lines:
        upd = classify_push_line(line)
        if upd is not None:
            out.append(upd)
    return out


def _kind(local_sha: str, remote_sha: str) -> PushKind:
    local_zero = is_zero_sha(local_sha)
    remote_zero = is_zero_sha(remote_sha)
    if local_zero and remote_zero:
        # Both zero is an unusual no-op (delete a ref that didn't exist).
        # Treat as no-op so the scanner skips it without crashing.
        return "noop"
    if local_zero:
        return "delete"
    if remote_zero:
        return "create"
    if local_sha == remote_sha:
        return "noop"
    return "update"
