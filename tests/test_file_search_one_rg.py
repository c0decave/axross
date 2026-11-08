"""Find Files with rg: one rg walks the root, not one rg per 256 files.

Measured before (30,000 files, a content search): 2.9-3.7 s with rg -
slower than pure Python (1.8-2.3 s) - against 0.18 s for a bare
``rg -l``: the walk classified and stat'ed every file and started rg once
per 256 of them, one after the other (118 runs). Now one rg over the root
(with the walk's depth, hidden and ignore rules) reports the matching
files while the walk decides as before which files count; only matching
files are classified. A symlinked file (rg's walk does not follow links)
goes to rg by name, a file larger than the content cap is searched in its
prefix by Python, as before.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import file_search as FS  # noqa: E402
from core import search_federation as SF  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

pytestmark = pytest.mark.skipif(FS.find_tool("rg") is None, reason="rg is not installed")


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "t"
    for d in range(6):
        sub = root / f"d{d}" / "deep"
        sub.mkdir(parents=True)
        for i in range(60):
            body = "needle here\n" if (d * 60 + i) % 37 == 0 else "hay\n"
            (sub / f"f{i:02d}.txt").write_text(body)
    (root / ".hid").mkdir()
    (root / ".hid" / "h.txt").write_text("needle hidden\n")
    (root / "skipme").mkdir()
    (root / "skipme" / "s.txt").write_text("needle skipped\n")
    (root / "brace{a}").mkdir()
    (root / "brace{a}" / "b.txt").write_text("needle in braces\n")
    target = root / "d0" / "deep" / "f00.txt"
    os.symlink(target, root / "link.txt")
    return root


def _run(root, monkeypatch=None, tools=True, **query):
    if not tools:
        monkeypatch.setattr(FS, "find_tool", lambda name: None)
    hits = []
    summary = FS.run_search([FS.SearchScope(LocalFS(), str(root))], SF.SearchQuery(**query),
                            on_hit=lambda s, h: hits.append(h))
    return {os.path.relpath(h.path, root): (h.snippet, h.category) for h in hits}, summary


@pytest.mark.parametrize("query", [
    {"contains": "needle"},
    {"contains": "NEEDLE", "include_hidden": True},
    {"contains": "needle", "ignore_dirs": ("skipme",)},
    {"contains": "needle", "ignore_dirs": ("brace{a}", "[s]kipme")},  # not handed to rg
    {"contains": "needle", "max_depth": 1},
    {"contains": "ne+dle", "contains_is_regex": True, "name": "*.txt"},
])
def test_happy_one_rg_finds_what_python_finds(tree, monkeypatch, query):
    with_rg, summary = _run(tree, **query)
    assert summary.engines and all("rg" in e for e in summary.engines.values())
    python, _ = _run(tree, monkeypatch, tools=False, **query)
    assert with_rg == python


def test_edge_a_symlinked_file_is_searched_through_the_link(tree):
    hits, _ = _run(tree, contains="needle")
    assert "link.txt" in hits and hits["link.txt"][0]


def test_edge_a_file_over_the_cap_is_searched_in_its_prefix(tree):
    big = tree / "big.txt"
    big.write_bytes(b"x" * 2000 + b"\nneedle late\n")
    early = tree / "early.txt"
    early.write_bytes(b"needle early\n" + b"y" * 3000)
    hits = []
    FS.run_search([FS.SearchScope(LocalFS(), str(tree))], SF.SearchQuery(contains="needle"),
                  on_hit=lambda s, h: hits.append(os.path.basename(h.path)),
                  limits=FS.SearchLimits(max_content_bytes=1024))
    assert "early.txt" in hits and "big.txt" not in hits


def test_sad_a_pattern_rg_refuses_is_searched_by_python(tree):
    hits, summary = _run(tree, contains=r"(?<=ne)edle", contains_is_regex=True)
    assert hits and all(rel.endswith(".txt") for rel in hits)
    assert "python" in "".join(summary.engines.values())


def test_sad_max_hits_stops_the_walk_and_the_rg(tree):
    hits = []
    summary = FS.run_search([FS.SearchScope(LocalFS(), str(tree))],
                            SF.SearchQuery(contains="needle"),
                            on_hit=lambda s, h: hits.append(h),
                            limits=FS.SearchLimits(max_hits=3))
    assert len(hits) == 3 and summary.truncated


# -- regression guards (counted) ----------------------------------------------------------------


def _count_rg(monkeypatch):
    starts = []
    real = FS._ToolProcess.__init__

    def counted(self, argv, cancel):
        starts.append(argv)
        real(self, argv, cancel)

    monkeypatch.setattr(FS._ToolProcess, "__init__", counted)
    return starts


def test_perf_happy_a_content_search_starts_one_rg_for_the_tree(tree, monkeypatch):
    starts = _count_rg(monkeypatch)
    hits, _ = _run(tree, contains="needle")
    rg_walks = [a for a in starts if a[-2] == "--" and a[-1] == str(tree)]
    assert len(rg_walks) == 1
    assert len(starts) <= 2  # the walk's rg, and rg by name for the symlink
    assert len(hits) >= 10


def test_perf_happy_only_matching_files_are_classified(tree, monkeypatch):
    names = []
    real = FS.classify_name
    monkeypatch.setattr(FS, "classify_name", lambda n, p="": names.append(n) or real(n, p))
    hits, _ = _run(tree, contains="needle")
    assert len(names) == len(hits)  # not one per file of the tree (365)
