"""Find Files: the noise-folder check (``SearchQuery.ignore_dirs``) is one
compiled expression per run instead of an fnmatch call per pattern.

Measured before: a search runs it for every entry (the built-in walker) or
for every path part of every file (the fd walker) - ten fnmatch calls each,
258 ms per 80,000 names, now 11 ms. The answer must be fnmatch's: every
test compares with the former ``any(fnmatch.fnmatch(name, p) ...)``.
"""

from __future__ import annotations

import fnmatch
import os
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from core import file_search as FS  # noqa: E402
from core.search_federation import SearchQuery  # noqa: E402


def _run(patterns) -> FS._Run:
    query = SearchQuery(name="*")
    query.ignore_dirs = tuple(patterns)
    return FS._Run(query, FS.SearchLimits(), lambda *_a: None, lambda: False, None,
                   use_tools=False, use_sift=False)


def _former(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


NAMES = [
    ".git", ".GIT", "git", ".gitignore", "node_modules", "node_modules2", "x_node_modules",
    "__pycache__", "venv", ".venv", "venvs", ".cache", "cache", ".pytest_cache", ".tox",
    "", ".", "..", "a\nb", "日本", "Ünïcode", "*", "?", "[abc]", "a.b", "a+b", "a b",
    "file.TXT", "x" * 300,
]
PATTERNS = [
    SearchQuery().ignore_dirs,
    ("*.tmp", "build?", "[!a-c]*x", "[abc]", "*cache*", "Thumbs.db"),
    ("[", "a[", "\\", "*[*", "**", "?*?", ".*"),
    ("CamelCase", "UPPER*"),
    (),
]


@pytest.mark.parametrize("patterns", PATTERNS)
def test_happy_every_name_is_judged_like_fnmatch(patterns):
    run = _run(patterns)
    for name in NAMES:
        assert run.ignored(name) == _former(name, patterns), (name, patterns)


def test_edge_random_names_and_patterns_agree_with_fnmatch():
    rnd = random.Random(5)
    alphabet = "ab.*?[]!-_xZ日 \\"
    for _ in range(200):
        patterns = tuple("".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 6)))
                         for _ in range(rnd.randint(0, 4)))
        run = _run(patterns)
        for _ in range(30):
            name = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 8)))
            assert run.ignored(name) == _former(name, patterns), (name, patterns)


def test_edge_the_case_rule_is_the_platforms(monkeypatch):
    """fnmatch folds case where os.path.normcase does (Windows); so does
    the compiled check - shown with a normcase that lowercases."""
    import ntpath

    monkeypatch.setattr(os.path, "normcase", ntpath.normcase)
    run = _run(("Node_Modules", "*.CACHE"))
    for name in ("node_modules", "NODE_MODULES", "x.cache", "X.Cache", "nodemodules"):
        assert run.ignored(name) == _former(name, ("Node_Modules", "*.CACHE")), name


def test_sad_a_search_still_skips_noise_folders(tmp_path):
    for folder in ("node_modules", "src", ".git", "venv"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "hit.txt").write_text("x")
    from core.local_fs import LocalFS

    for use_tools in (False, True):  # the built-in walker and fd, if installed
        hits = []
        FS.run_search([FS.SearchScope(LocalFS(), str(tmp_path))], SearchQuery(name="*.txt"),
                      on_hit=lambda scope, hit: hits.append(Path(hit.path).parent.name),
                      cancel=lambda: False, use_tools=use_tools, use_sift=False)
        assert hits == ["src"], use_tools


def test_perf_happy_judging_80000_names_is_cheap():
    names = [f"d{i % 300:03d}" for i in range(40000)] + [f"n{i:05d}.log" for i in range(40000)]
    patterns = SearchQuery().ignore_dirs
    run = _run(patterns)

    def cost(judge) -> float:
        best = 1e9
        for _ in range(3):
            start = time.thread_time()
            for name in names:
                judge(name)
            best = min(best, time.thread_time() - start)
        return best

    new = cost(run.ignored)
    old = cost(lambda name: _former(name, patterns))
    assert new < old / 4, (new, old)


def test_perf_sad_the_comparison_catches_a_check_as_slow_as_before():
    """Negative control of the comparison above: the former check against
    itself is not four times cheaper."""
    names = [f"n{i:05d}.log" for i in range(30000)]
    patterns = SearchQuery().ignore_dirs

    def cost() -> float:
        best = 1e9
        for _ in range(3):
            start = time.thread_time()
            for name in names:
                _former(name, patterns)
            best = min(best, time.thread_time() - start)
        return best

    again, old = cost(), cost()
    assert not again < old / 4, (again, old)
