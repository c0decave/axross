"""Defense-in-depth helper for the tracked-files contract: scanners that
enumerate tracked files MUST use ``git ls-files -z`` so non-ASCII
paths arrive verbatim, not octal-quoted.

Before this fix, ``scripts/export-public.py:tracked_files`` called
``git ls-files`` in text mode. Git's default ``core.quotePath=true``
emits paths like ``"\303\244hhh.py"`` (with literal quotes and
backslash-escapes) for any name containing a byte outside printable
ASCII. The script then iterated those quoted strings as filesystem
paths, ``(root / quoted).is_file()`` returned False, and the file
was silently skipped — so a secret in ``ähhh.py`` slipped past
``--check`` (rc=0, "0 files scanned"). The fix in this same series
is to read ``ls-files -z`` as bytes and split on NUL, surrogateescape-
decoding so even non-UTF-8 byte sequences survive a round-trip.

Lifting the contract into ``security/`` means:

* the policy lives outside ``scripts/`` (defense in depth: a second
  layer that other callers — CI gate, audit tool, replacement hook —
  can reuse without re-implementing ``-z`` handling),
* the contract has its own focused test suite that exercises happy/
  edge/sad cases independent of the end-to-end script tests,
* a future regression to ``ls-files`` (text mode) in any caller is
  caught by the helper tests, not just by the one scan_paths
  reproduce.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterator


def iter_tracked(root: Path) -> Iterator[str]:
    """Yield each tracked path in ``root`` exactly as git records it.

    Uses ``git ls-files -z`` so:

    * non-ASCII names (``ähhh.py``, ``unicodé dir/leak.txt``) arrive
      verbatim instead of octal-quoted,
    * paths containing newlines or other unusual bytes are not split
      mid-name,
    * non-UTF-8 byte sequences (legal on POSIX filesystems) survive
      via ``surrogateescape`` decoding — the caller can still pass
      them to ``Path`` without crashing.

    Fail-closed: on any git failure (non-git directory, missing
    binary, etc.) the iterator yields nothing. The caller's "0 files
    scanned" report then truthfully reflects that nothing was checked,
    rather than crashing the scan with an exception.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=False,
        )
    except (OSError, FileNotFoundError):
        return
    if proc.returncode != 0:
        return
    for part in proc.stdout.split(b"\0"):
        if not part:
            continue
        yield part.decode("utf-8", errors="surrogateescape")


def list_tracked(root: Path) -> list[str]:
    """Convenience: materialise ``iter_tracked`` into a list."""
    return list(iter_tracked(root))
