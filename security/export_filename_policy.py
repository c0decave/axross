"""Defense-in-depth helper for the blocked-filename contract: every
scan mode in `scripts/export-public.py` (worktree, staged, commit-range,
history) must apply the same blocked-filename / blocked-extension policy.

Before this contract was enforced uniformly, the commit-range and
history scans did not call the
filename guard, so a developer could land a path like `id_rsa` or
`secrets.pem` in a pushed commit even though the worktree-scan would
have refused the same path. The first fix (fe7fef21) added the check
inline in the script. Lifting the policy into this module gives it:

* A single canonical home outside `scripts/` (defense in depth — the
  script is one of two layers enforcing the rule).
* A focused test surface (`tests/test_export_filename_policy.py`)
  covering happy / edge / sad in isolation.
* Re-use for future callers (CI gate, secondary hook, audit tool)
  without re-implementing `endswith` logic.

Behaviour is preserved as a pure refactor: same case-sensitive matching,
same `endswith` semantics for extensions, same `name == base or
endswith("/" + name)` semantics for filename suffixes (so entries like
`.kube/config` still work).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from typing import Iterable

DEFAULT_BLOCKED_EXTENSIONS: tuple[str, ...] = (
    ".sqlite", ".sqlite3", ".db", ".dump", ".bak",
    ".pcap", ".pcapng", ".pfx", ".p12", ".key", ".pem",
)
DEFAULT_BLOCKED_FILENAMES: tuple[str, ...] = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".npmrc", ".pypirc",
    "kubeconfig", ".kube/config",
    "credentials",
)


@dataclass(frozen=True)
class FilenameBlockPolicy:
    """Effective filename-block ruleset.

    Tuples (not lists) so the dataclass remains hashable and immutable
    — callers can safely cache it across requests.
    """

    extensions: tuple[str, ...]
    filenames: tuple[str, ...]

    @classmethod
    def default(cls) -> "FilenameBlockPolicy":
        return cls(
            extensions=DEFAULT_BLOCKED_EXTENSIONS,
            filenames=DEFAULT_BLOCKED_FILENAMES,
        )

    def extend(
        self,
        extensions: Iterable[str] = (),
        filenames: Iterable[str] = (),
    ) -> "FilenameBlockPolicy":
        """Return a new policy with extra extensions / filenames merged in.

        Pure: never mutates `self`. Order is `default + overlay` so
        sidecar config additions appear after the defaults in any
        debug listing.
        """
        new_exts = tuple(self.extensions) + tuple(extensions)
        new_names = tuple(self.filenames) + tuple(filenames)
        return replace(self, extensions=new_exts, filenames=new_names)


def is_blocked_filename(policy: FilenameBlockPolicy, rel: str) -> str | None:
    """Return a `extension:.X` / `filename:NAME` reason string when the
    path is blocked, else `None`. Empty paths return `None`.

    Match semantics for filenames:

    * ``base == name``      — bare filename anywhere (e.g. ``id_rsa``,
      ``foo/id_rsa``);
    * ``rel == name``       — slash-bearing name at the repo root (e.g.
      ``.kube/config`` tracked at root, which is the canonical
      Kubernetes credential layout);
    * ``rel.endswith("/" + name)`` — slash-bearing name nested under any
      parent (e.g. ``home/.kube/config``).

    The ``rel == name`` arm was added for the root-level canonical
    case: without it, a root-
    level ``.kube/config`` slipped past the guard because the basename
    is just ``config`` and the endswith arm needs a leading separator
    the root case does not produce.
    """
    if not rel:
        return None
    base = os.path.basename(rel)
    for ext in policy.extensions:
        if rel.endswith(ext):
            return f"extension:{ext}"
    for name in policy.filenames:
        if base == name or rel == name or rel.endswith("/" + name):
            return f"filename:{name}"
    return None
