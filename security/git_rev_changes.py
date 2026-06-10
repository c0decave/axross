"""Defense-in-depth helper for the merge-aware-changes contract: callers that
enumerate "files changed in a commit" for filename-rule enforcement
MUST treat merge commits the same as non-merge commits.

Before this fix, ``scripts/export-public.py:changed_files_in_commit``
called ``git diff-tree --no-commit-id --name-only --diff-filter=ACMR
-r --root -z REV`` *without* ``-m``/``-c``/``--cc``. Per git's
default merge-commit behaviour, diff-tree emits NOTHING for a merge
commit in that mode — so for every merge rev in a pushed range,
``scan_path_names`` was silently fed the empty list and the
blocked-filename contract ("canonical-credential filenames like
``.kube/config`` are blocked regardless of content") was bypassed by
any author with merge-commit authority. ``scan_diff_lines`` still
fired on the combined diff, but content-only scanning is not enough:
``.kube/config`` headers, ``.aws/config`` profile metadata, and any
empty-on-purpose blocked-name file trip no regex.

This helper centralises the "merge-aware path enumeration" policy:

* ``-m`` makes diff-tree show each parent's diff separately for a
  merge commit. The *union* of those paths — i.e. everything that
  differs from at least one parent — is exactly what the filename-
  rule scan needs to enforce the blocked-filename contract on every
  commit, including merges.
* Paths are deduplicated within REV so a 2+-parent merge that
  modifies the same path against multiple parents does not produce
  duplicate hits downstream.
* ``--root`` is preserved so diff-tree treats the empty tree as
  parent for the initial commit (no parent), keeping the helper
  uniform across root / normal / merge commits.

Lifting the contract into ``security/`` mirrors the tracked-files
precedent: the policy lives outside ``scripts/`` so any other caller
(CI gate, audit tool, replacement hook) inherits the merge-aware
semantics rather than re-introducing the bypass with a bare
``git diff-tree``. The helper has its own focused test suite that
exercises happy / edge / sad cases independent of the end-to-end
script tests.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterator


def iter_changed_files(root: Path, rev: str) -> Iterator[str]:
    """Yield paths whose blob in REV differs from at least one parent,
    filtered to ACMR (added/copied/modified/renamed) ops, deduplicated.

    Merge-aware: passes ``-m`` so diff-tree emits per-parent diffs for
    merge commits instead of the default empty output. The union of
    paths across all parents is yielded; duplicates suppressed.

    ``--end-of-options`` is placed immediately before ``rev`` so a
    caller (current or future) that passes a ``rev`` starting with
    ``-`` cannot accidentally smuggle a diff-tree option (e.g.
    ``--patch``) into the args. Without the separator git would parse
    a dash-prefixed ``rev`` as a flag — either changing output
    formatting or, more importantly, hiding the "no rev was provided"
    error path. Today's only in-tree callers feed REVs from
    ``git rev-list`` (always plain hex SHAs), but the helper lives in
    ``security/`` so any future caller — CI gate, audit tool, hook —
    inherits the same hardened contract instead of relying on its own
    arg-validation discipline.

    Fail-closed: on any git failure (corrupt rev, non-git dir, missing
    binary, non-zero exit) the iterator yields nothing. The caller's
    "0 files" report then truthfully reflects that nothing was checked
    rather than crashing the scan with an exception.
    """
    try:
        proc = subprocess.run(
            [
                "git", "-C", str(root),
                "diff-tree", "-m", "--no-commit-id", "--name-only",
                "--diff-filter=ACMR", "-r", "--root", "-z",
                "--end-of-options", rev,
            ],
            capture_output=True,
            check=False,
        )
    except (OSError, FileNotFoundError):
        return
    if proc.returncode != 0:
        return
    seen: set[str] = set()
    for part in proc.stdout.split(b"\0"):
        if not part:
            continue
        rel = part.decode("utf-8", errors="surrogateescape")
        if rel in seen:
            continue
        seen.add(rel)
        yield rel


def list_changed_files(root: Path, rev: str) -> list[str]:
    """Convenience: materialise ``iter_changed_files`` into a list."""
    return list(iter_changed_files(root, rev))
