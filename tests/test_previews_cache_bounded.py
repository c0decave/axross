"""The thumbnail cache on disk stays bounded.

Every thumbnail ever made stayed in ~/.cache/axross/thumbnails: browsing a
large photo library left gigabytes there for good. Now, when a store finds
more than CACHE_MAX_FILES thumbnails, the least recently used go until
CACHE_KEEP_FILES are left.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import previews as P  # noqa: E402


def test_sad_the_cache_is_pruned_past_its_bound(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(P, "CACHE_MAX_FILES", 20)
    monkeypatch.setattr(P, "CACHE_KEEP_FILES", 10)
    monkeypatch.setattr(P, "CACHE_PRUNE_EVERY", 10**9)
    root = P._cache_root()
    now = time.time()
    for i in range(25):
        f = root / f"{i:064x}.png"
        P._store_cached(f, b"png")
        os.utime(f, (now - 1000 + i, now - 1000 + i))
    monkeypatch.setattr(P, "CACHE_PRUNE_EVERY", 1)
    P._store_cached(root / ("f" * 64 + ".png"), b"png")
    left = sorted(p.name for p in root.iterdir())
    assert len(left) <= 10
    assert "f" * 64 + ".png" in left  # the newest stays
    assert f"{0:064x}.png" not in left  # the oldest went


def test_edge_a_cache_under_its_bound_is_left_alone(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setattr(P, "CACHE_PRUNE_EVERY", 1)
    root = P._cache_root()
    for i in range(5):
        P._store_cached(root / f"{i:064x}.png", b"png")
    assert len(list(root.iterdir())) == 5


def test_edge_a_cache_hit_counts_as_a_use(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    root = P._cache_root()
    f = root / ("a" * 64 + ".png")
    P._store_cached(f, b"png")
    os.utime(f, (1000, 1000))
    assert P._load_cached(f) == b"png"
    assert f.stat().st_mtime > 1000
