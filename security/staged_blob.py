"""Defense-in-depth helper for the staged-blob contract: scanners that
inspect staged content MUST read the index blob, not the working tree.

Before this fix, `scripts/export-public.py --check-staged` opened the
worktree file, so a developer could `git add` a secret-bearing file
and then sanitise the worktree copy before commit — the hook saw the
clean worktree and let the secret land in the index. The fix in
edf3635 was to scan the staged blob via `git ls-files -s` →
`git cat-file -p`. This module exports that contract as a stand-alone
helper so:

* `scripts/export-public.py` is no longer the only place enforcing it
  (defense in depth: a second layer outside `scripts/`),
* future scanners (CI hook, secondary pre-receive, audit tool) can
  reuse the same policy and cannot regress to "read the worktree
  again",
* the contract has a focused test suite (`tests/test_staged_blob_helper.py`)
  that exercises happy / edge / sad cases independently of the
  end-to-end script tests.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


@dataclass(frozen=True)
class StagedBlob:
    """One file in the git index.

    ``path``     — repository-relative path as recorded in the index.
    ``oid``      — full 40-char (or longer for SHA-256) git object id.
    ``_root``    — repo root; needed so ``read_*`` can shell out.
    """

    path: str
    oid: str
    _root: Path

    def read_bytes(self) -> bytes:
        """Return the staged blob's raw bytes; b"" on git failure."""
        proc = subprocess.run(
            ["git", "-C", str(self._root), "cat-file", "-p", self.oid],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            return b""
        return proc.stdout

    def read_text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        return self.read_bytes().decode(encoding, errors=errors)


def resolve_staged_blob(root: Path, rel: str) -> StagedBlob | None:
    """Resolve the index blob for ``rel`` in repo ``root``.

    Returns ``None`` when the path is not present at stage 0 (i.e. not
    staged, not part of the index, or stuck in an unmerged 1/2/3 slot
    from a conflict). Never raises — fail-closed: a returning helper
    that cannot find the blob means the caller scans nothing for that
    path, which is preferable to crashing the hook.

    Literal-pathspec contract: ``rel`` is interpreted as a LITERAL path, not a
    glob pathspec. Without ``--literal-pathspecs``, git treats wildcard
    characters (``*``, ``?``, ``[…]``) in ``rel`` as shell-glob meta
    characters and may return entries for OTHER tracked files that
    happen to glob-match — letting an attacker name a secret-bearing
    file ``secrets?.env`` and have the helper return the OID of a
    sibling ``secrets1.env`` (lex-first stage-0 entry wins the loop).
    The top-level ``--literal-pathspecs`` flag forces git to compare
    ``rel`` byte-for-byte against index entries.
    """
    proc = subprocess.run(
        ["git", "--literal-pathspecs",
         "-C", str(root), "ls-files", "-s", "-z", "--", rel],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    for entry in proc.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, _, _path = entry.partition(b"\t")
        fields = metadata.split()
        # Layout: <mode> <oid> <stage>\t<path>. Stage 0 = merged.
        if len(fields) >= 3 and fields[2] == b"0":
            return StagedBlob(
                path=rel,
                oid=fields[1].decode("ascii"),
                _root=root,
            )
    return None


def iter_staged_blobs(root: Path, paths: Iterable[str]) -> Iterator[StagedBlob]:
    """Yield ``StagedBlob`` for each path that is currently staged.

    Paths with no index entry (deleted, unmerged, or never added) are
    silently dropped — the caller can compare ``set(paths)`` against
    the yielded paths if it needs to detect this.
    """
    for rel in paths:
        blob = resolve_staged_blob(root, rel)
        if blob is not None:
            yield blob
