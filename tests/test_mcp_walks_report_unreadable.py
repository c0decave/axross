"""MCP tree tools say what they could not read.

bulk_copy (0.12.10) and federated_search (0.14.97) learnt that a walk
which drops an unreadable folder and answers ``truncated: false`` makes a
partial result look complete. Four more walks still did it
(``except OSError: continue``):

* ``transfer_copy`` (core/mcp_groups.py) - an unlistable folder, every
  folder below max_depth, unsafe names and symlinks vanished without a
  record; an agent that copies a tree and then deletes the source loses
  whatever was left out. It now records each of them like bulk_copy and
  answers ``complete``.
* ``walk``, ``grep`` and ``recursive_checksum`` (core/mcp_server.py) - an
  unreadable folder vanished from the result, an unreadable ROOT gave an
  empty, complete-looking answer (a tree "without files", a grep with "no
  match", two checksum sets that compare equal). An unreadable root is an
  error now; an unreadable folder below it is listed (``unreadable`` /
  an ``error`` record with ``folder: true``) and ``complete`` is false.
"""

from __future__ import annotations

import os

import pytest

from core.local_fs import LocalFS
from tests import mcp_group_testkit as T

POSIX_USER = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="POSIX permissions, not root"
)


class _Flaky(LocalFS):
    """LocalFS whose listing of chosen folders times out."""

    def __init__(self, failing=()):
        super().__init__()
        self.failing = set(failing)

    def list_dir(self, path):
        if os.path.abspath(path) in self.failing:
            raise TimeoutError(f"listing {path} timed out")
        return super().list_dir(path)


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    src = r / "src"
    (src / "sub").mkdir(parents=True)
    (src / "top.txt").write_text("needle top\n")
    (src / "sub" / "a.txt").write_text("needle a\n")
    (src / "locked").mkdir()
    (src / "locked" / "hidden.txt").write_text("needle hidden\n")
    yield r
    os.chmod(src / "locked", 0o700)


def _tools(root, backend=None, write=False, groups=()):
    return T.build(root, set(groups), allow_write=write, backend=backend)


def _lock(root):
    os.chmod(root / "src" / "locked", 0)


# ------------------------------------------------------------------ happy

def test_happy_complete_walks_say_so(root):
    tools = _tools(root)
    src = str(root / "src")
    walked = T.call(tools, "walk", {"path": src})
    assert walked["complete"] is True and walked["unreadable"] == []
    grep = T.call(tools, "grep", {"pattern": "needle", "path": src})
    assert grep["complete"] is True and len(grep["matches"]) == 3
    sums = T.call(tools, "recursive_checksum", {"path": src})
    assert sums["complete"] is True
    assert sorted(os.path.basename(e["path"]) for e in sums["entries"]) == [
        "a.txt", "hidden.txt", "top.txt"]


def test_happy_transfer_copy_of_a_readable_tree_is_complete(root):
    tools = _tools(root, write=True, groups={"transfer"})
    out = T.call(tools, "transfer_copy", {"src": str(root / "src"), "dst": str(root / "dst")})
    assert out["complete"] is True and out["copied"] == 3
    assert (root / "dst" / "locked" / "hidden.txt").read_text() == "needle hidden\n"


# ------------------------------------------------------------------ sad

@POSIX_USER
def test_sad_walk_names_an_unreadable_folder(root):
    _lock(root)
    out = T.call(_tools(root), "walk", {"path": str(root / "src")})
    assert out["complete"] is False
    assert [u["path"] for u in out["unreadable"]] == [str(root / "src" / "locked")]
    assert out["unreadable"][0]["error"]


@POSIX_USER
def test_sad_grep_names_an_unreadable_folder(root):
    _lock(root)
    out = T.call(_tools(root), "grep", {"pattern": "needle", "path": str(root / "src")})
    assert out["complete"] is False and len(out["matches"]) == 2
    assert [u["path"] for u in out["unreadable"]] == [str(root / "src" / "locked")]


@POSIX_USER
def test_sad_recursive_checksum_records_an_unreadable_folder(root):
    _lock(root)
    out = T.call(_tools(root), "recursive_checksum", {"path": str(root / "src")})
    assert out["complete"] is False
    folders = [e for e in out["entries"] if e.get("folder")]
    assert [e["path"] for e in folders] == [str(root / "src" / "locked")]
    assert folders[0]["error"]


@POSIX_USER
def test_sad_transfer_copy_records_an_unlistable_folder(root):
    _lock(root)
    tools = _tools(root, write=True, groups={"transfer"})
    out = T.call(tools, "transfer_copy", {"src": str(root / "src"), "dst": str(root / "dst")})
    assert out["complete"] is False and out["copied"] == 2
    errors = [e for e in out["entries"] if e["action"] == "error"]
    assert len(errors) == 1 and errors[0]["folder"] is True
    assert errors[0]["src"] == str(root / "src" / "locked")


def test_sad_an_unreadable_root_is_an_error_not_an_empty_tree(root):
    src = str(root / "src")
    tools = _tools(root, backend=_Flaky({src}))
    for name, args in (("walk", {"path": src}),
                       ("grep", {"pattern": "needle", "path": src}),
                       ("recursive_checksum", {"path": src})):
        with pytest.raises(T.RpcError) as caught:
            T.call(tools, name, args)
        assert "timed out" in caught.value.message, name


def test_sad_transfer_copy_with_an_unlistable_source_root_is_no_empty_copy(root):
    src = str(root / "src")
    tools = _tools(root, backend=_Flaky({src}), write=True, groups={"transfer"})
    out = T.call(tools, "transfer_copy", {"src": src, "dst": str(root / "dst")})
    assert out["complete"] is False and out["copied"] == 0
    assert [e["action"] for e in out["entries"]] == ["error"]


# ------------------------------------------------------------------ edge

def test_edge_transfer_copy_reports_folders_below_max_depth_and_symlinks(root):
    os.symlink("top.txt", root / "src" / "link.txt")
    tools = _tools(root, write=True, groups={"transfer"})
    out = T.call(tools, "transfer_copy",
                 {"src": str(root / "src"), "dst": str(root / "dst"), "max_depth": 0})
    assert out["truncated"] is True and out["complete"] is False
    reasons = sorted((e.get("reason"), os.path.basename(e["src"]))
                     for e in out["entries"] if e["action"] == "skipped")
    assert reasons == [("max-depth", "locked"), ("max-depth", "sub"), ("symlink", "link.txt")]
    assert not (root / "dst" / "sub").exists()


def test_edge_a_listing_timeout_below_the_root_is_unreadable_not_fatal(root):
    src = root / "src"
    tools = _tools(root, backend=_Flaky({str(src / "sub")}))
    out = T.call(tools, "walk", {"path": str(src)})
    assert out["complete"] is False
    assert [u["path"] for u in out["unreadable"]] == [str(src / "sub")]
    assert "timed out" in out["unreadable"][0]["error"]
