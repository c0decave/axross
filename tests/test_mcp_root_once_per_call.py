"""The MCP root is resolved once per tool call, not once per row
(core.mcp_server, docs/plans entry 6).

``grep`` confines every file it reads and the index ``search`` every row it
returns. Each check resolved the configured root with ``os.path.realpath``
again. Now a tool call resolves each root once and keeps the per-row
realpath of the path - the same check, exactly, for every path - and a
root re-pointed between two calls is still noticed by the second call.
"""

from __future__ import annotations

import os
import posixpath
from unittest import mock

import pytest

from core import mcp_server as M
from core import metadata_index as MX
from core.local_fs import LocalFS

N = 40


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for i in range(N):
        (root / f"f{i:03d}.txt").write_text(f"needle {i}\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("needle secret\n")
    return root, outside


def tool(name, root, *, extra_roots=()):
    tools = M._build_tools(LocalFS(), allow_write=False, backend_id="local", root=str(root),
                           extra_roots=extra_roots)
    return next(t for t in tools if t.name == name)


def grep(root, path=None, *, extra_roots=()):
    args = {"pattern": "needle", "path": str(path or root), "max_depth": 3,
            "max_matches": 1000}
    result = tool("grep", root, extra_roots=extra_roots).handler(args, M._ToolContext())
    return result if isinstance(result, list) else result["matches"]


def matched_files(matches) -> set[str]:
    return {os.path.basename(m["path"]) for m in matches}


class RealpathCounter:
    """Counts os.path.realpath calls, and those of one argument."""

    def __init__(self, watched: str):
        self.watched = watched
        self.total = 0
        self.of_watched = 0
        self._real = posixpath.realpath

    def __call__(self, path, *args, **kwargs):
        self.total += 1
        if os.fspath(path) == self.watched:
            self.of_watched += 1
        return self._real(path, *args, **kwargs)


def counting(watched):
    counter = RealpathCounter(str(watched))
    return counter, mock.patch.object(posixpath, "realpath", counter)


def search(root, db, needle, **kwargs):
    real = MX.search_all
    with mock.patch.object(MX, "search_all", lambda **kw: real(**{**kw, "db_path": db})):
        return tool("search", root, **kwargs).handler({"needle": needle}, M._ToolContext())


# --- fewer realpath calls ---------------------------------------------------------------


def test_happy_grep_resolves_the_root_once_per_call(tree):
    root, _outside = tree
    counter, patch = counting(root)
    with patch:
        matches = grep(root)
    assert len(matched_files(matches)) == N
    assert counter.of_watched == 2  # the root once, the start path (= the root) once
    # one per file read, plus the root and the start path - was about 2N
    assert counter.total <= N + 2, counter.total


def test_happy_index_search_resolves_the_root_once_per_call(tree, tmp_path):
    root, outside = tree
    db = str(tmp_path / "idx.sqlite")
    for i in range(N):
        MX.upsert(db, "local", str(root / f"f{i:03d}.txt"), name=f"row{i}", size=1,
                  is_dir=False)
    MX.upsert(db, "local", str(outside / "secret.txt"), name="rowsecret", size=1,
              is_dir=False)
    counter, patch = counting(root)
    with patch:
        rows = search(root, db, "row")
    assert len(rows) == N and all(r["name"] != "rowsecret" for r in rows)
    assert counter.of_watched == 1
    assert counter.total <= N + 2, counter.total  # N rows in the root, 1 outside, the root


def test_happy_recursive_checksum_resolves_the_root_once_per_call(tree):
    """The same per-file check as grep (its twin): every hashed file was
    confined against a freshly resolved root."""
    import hashlib

    root, _outside = tree
    (root / "escape").symlink_to(_outside, target_is_directory=True)
    counter, patch = counting(root)
    with patch:
        result = tool("recursive_checksum", root).handler(
            {"path": str(root), "max_depth": 3}, M._ToolContext())
    entries = result if isinstance(result, list) else result["entries"]
    hashed = {os.path.basename(e["path"]): e["checksum"] for e in entries if "checksum" in e}
    assert len(hashed) == N and "secret.txt" not in hashed
    assert hashed["f000.txt"] == hashlib.sha256(b"needle 0\n").hexdigest()
    assert counter.of_watched == 2  # the root once, the start path (= the root) once


# --- the root is re-resolved by every call ----------------------------------------------


def test_sad_a_root_swapped_between_two_calls_is_noticed(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a.txt").write_text("needle in first\n")
    (second / "b.txt").write_text("needle in second\n")
    link = tmp_path / "root"
    link.symlink_to(first)
    grep_tool = tool("grep", link)
    args = {"pattern": "needle", "path": str(link), "max_depth": 2}

    def run():
        result = grep_tool.handler(args, M._ToolContext())
        return matched_files(result if isinstance(result, list) else result["matches"])

    assert run() == {"a.txt"}
    tmp = tmp_path / "root.new"
    tmp.symlink_to(second)
    os.replace(tmp, link)  # the root now points elsewhere - same tool, next call
    assert run() == {"b.txt"}


def test_sad_index_search_notices_a_swapped_root(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    link = tmp_path / "root"
    link.symlink_to(first)
    db = str(tmp_path / "idx.sqlite")
    MX.upsert(db, "local", str(link / "x.txt"), name="x.txt", size=1, is_dir=False)
    (first / "x.txt").write_text("x")
    # x.txt in the second root is a link back into the first: inside the
    # first root, outside the second
    (second / "x.txt").symlink_to(first / "x.txt")
    search_tool = tool("search", link)
    real = MX.search_all

    def run():
        with mock.patch.object(MX, "search_all", lambda **kw: real(**{**kw, "db_path": db})):
            return [r["name"] for r in search_tool.handler({"needle": "x"}, M._ToolContext())]

    assert run() == ["x.txt"]
    tmp = tmp_path / "root.new"
    tmp.symlink_to(second)
    os.replace(tmp, link)
    assert run() == []  # resolves to first/x.txt - outside the new real root


# --- the confinement itself is unchanged ------------------------------------------------


def test_sad_a_symlink_escape_inside_the_root_is_still_refused(tree, tmp_path):
    root, outside = tree
    (root / "escape").symlink_to(outside)
    (root / "secret-link.txt").symlink_to(outside / "secret.txt")
    files = matched_files(grep(root))
    assert "secret.txt" not in files and "secret-link.txt" not in files
    assert len(files) == N
    db = str(tmp_path / "idx.sqlite")
    for path in (root / "escape" / "secret.txt", root / "secret-link.txt"):
        MX.upsert(db, "local", str(path), name="s-" + path.name, size=1, is_dir=False)
    assert search(root, db, "s-") == []


def test_edge_a_non_existent_leaf_is_kept_as_before(tree, tmp_path):
    root, _outside = tree
    db = str(tmp_path / "idx.sqlite")
    MX.upsert(db, "local", str(root / "gone" / "missing.txt"), name="missing.txt", size=1,
              is_dir=False)
    MX.upsert(db, "local", str(tmp_path / "missing-outside.txt"), name="missing-outside.txt",
              size=1, is_dir=False)
    assert [r["name"] for r in search(root, db, "missing")] == ["missing.txt"]


def test_edge_extra_roots_are_each_resolved_once(tree, tmp_path):
    root, outside = tree
    extra = tmp_path / "extra"
    extra.mkdir()
    for i in range(5):
        (extra / f"e{i}.txt").write_text("needle extra\n")
    counter, patch = counting(extra)
    with patch:
        files = matched_files(grep(root, extra, extra_roots=((str(extra), False),)))
    assert files == {f"e{i}.txt" for i in range(5)}
    assert counter.of_watched == 2  # the extra root once, the start path once


def test_sad_a_start_path_outside_every_root_is_refused(tree, tmp_path):
    root, outside = tree
    extra = tmp_path / "extra"
    extra.mkdir()
    with pytest.raises(PermissionError):
        grep(root, outside, extra_roots=((str(extra), False),))


# --- exactly the same answer for every path ---------------------------------------------


def _outcome(fn, *args, **kwargs):
    try:
        return ("ok", fn(*args, **kwargs))
    except (PermissionError, ValueError) as exc:
        return (type(exc).__name__, str(exc))


@pytest.fixture
def maze(tmp_path):
    """A root reached through a symlinked parent, with links inside and out."""
    real_parent = tmp_path / "real"
    (real_parent / "root" / "sub").mkdir(parents=True)
    (tmp_path / "away").mkdir()
    (tmp_path / "away" / "f").write_text("x")
    root_real = real_parent / "root"
    (root_real / "sub" / "f").write_text("x")
    (root_real / "in-link").symlink_to(root_real / "sub")
    (root_real / "out-link").symlink_to(tmp_path / "away")
    (root_real / "dot-link").symlink_to(".")
    (root_real / "loop").symlink_to(root_real / "loop")
    (tmp_path / "alias").symlink_to(real_parent)
    return tmp_path, str(tmp_path / "alias" / "root")


PATHS = ["sub/f", "sub", ".", "", "/", "..", "../away/f", "sub/../../away", "in-link/f",
         "out-link/f", "out-link", "dot-link/sub/f", "loop", "loop/x", "missing", "sub/missing",
         "missing/deeper/leaf", "out-link/missing", "x\x00y", "./sub//f/", "sub/./f"]


@pytest.mark.parametrize("rel", PATHS)
def test_edge_the_check_with_a_resolved_root_is_the_same_for_every_path(maze, rel):
    base, root = maze
    candidates = [rel, os.path.join(root, rel) if rel else root,
                  os.path.join(str(base), "real", "root", rel),
                  os.path.join(str(base), "away", rel)]
    real_root = os.path.realpath(os.path.abspath(root))
    for path in candidates:
        for configured in (root, root + "/", str(base / "real" / "root"), "/"):
            resolved = os.path.realpath(os.path.abspath(configured or "/"))
            before = _outcome(M._enforce_root, path, configured)
            after = _outcome(M._enforce_root, path, configured, real_root=resolved)
            assert before == after, (path, configured)
    assert real_root == str(base / "real" / "root")


@pytest.mark.parametrize("name", ["docs/MCP.md", "docs/MCP_de.md", "docs/MCP_es.md"])
def test_happy_the_mcp_guides_say_the_root_is_resolved_per_call(name):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, name), encoding="utf-8") as fh:
        text = " ".join(fh.read().split())
    assert "(`grep`, `search`, `recursive_checksum`)" in text
