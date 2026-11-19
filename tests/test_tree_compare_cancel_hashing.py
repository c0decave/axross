"""Compare Panes stops hashing when it is cancelled.

Review: Cancel (or closing the window) stopped the walk, but the pass that
classifies the entries never asked should_continue: every file with the
same size and another mtime was still read on both sides - on a remote
pane, all of them downloaded once more for a result nobody would see.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import tree_compare as TC  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def test_sad_a_cancelled_compare_reads_no_more_files(tmp_path):
    left, right = tmp_path / "l", tmp_path / "r"
    for root, when in ((left, 1_000_000_000), (right, 1_100_000_000)):
        root.mkdir()
        for i in range(50):
            path = root / f"f{i:03}.bin"
            path.write_bytes(b"x" * 100)
            os.utime(path, (when, when))
    reads = []
    cancelled = []

    def hasher(_backend, path):
        reads.append(path)
        if len(reads) == 2:
            cancelled.append(True)  # Cancel is clicked while the first pair is read
        return "h"

    fs = LocalFS()
    entries = TC.compare_trees(fs, str(left), fs, str(right), hasher=hasher,
                               should_continue=lambda: not cancelled)
    assert len(reads) == 2
    assert len(entries) <= 1


def test_happy_an_uncancelled_compare_reads_every_pair(tmp_path):
    left, right = tmp_path / "l", tmp_path / "r"
    for root, when in ((left, 1_000_000_000), (right, 1_100_000_000)):
        root.mkdir()
        for i in range(5):
            path = root / f"f{i}.bin"
            path.write_bytes(b"x")
            os.utime(path, (when, when))
    reads = []
    fs = LocalFS()
    entries = TC.compare_trees(fs, str(left), fs, str(right),
                               hasher=lambda _b, p: reads.append(p) or "h",
                               should_continue=lambda: True)
    assert len(reads) == 10 and len(entries) == 5
