"""MCP tools confined to more than one folder: the agent's folder plus
extra folders, each read-only or read-write.

The agent's sandbox mounts extra folders (a project, a data share) beside
the agent's folder; the tools must reach exactly those - reading in every
one, writing only in the read-write ones - and nothing else. Without
extra folders nothing changes.
"""

from __future__ import annotations

import os

import pytest

from tests import mcp_group_testkit as T


@pytest.fixture
def tree(tmp_path):
    for name in ("main", "ro", "rw", "outside"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "f.txt").write_text(name)
    return tmp_path


def _tools(tree, **kw):
    return T.build(tree / "main", set(), allow_write=True,
                   extra_roots=((str(tree / "ro"), False), (str(tree / "rw"), True)), **kw)


def _read(tools, path):
    return T.call(tools, "read_file", {"path": str(path), "encoding": "text"})


# -- happy ---------------------------------------------------------------------


def test_happy_every_folder_can_be_read(tree):
    tools = _tools(tree)
    for name in ("main", "ro", "rw"):
        out = _read(tools, tree / name / "f.txt")
        assert name in str(out)


def test_happy_the_read_write_folder_and_the_main_one_can_be_written(tree):
    tools = _tools(tree)
    T.call(tools, "write_file", {"path": str(tree / "rw" / "new.txt"), "content": "x"})
    T.call(tools, "write_file", {"path": str(tree / "main" / "new.txt"), "content": "y"})
    assert (tree / "rw" / "new.txt").read_text() == "x"
    assert (tree / "main" / "new.txt").read_text() == "y"


def test_happy_relative_paths_belong_to_the_main_folder(tree):
    tools = _tools(tree)
    T.call(tools, "write_file", {"path": "rel.txt", "content": "z"})
    assert (tree / "main" / "rel.txt").read_text() == "z"


# -- sad -----------------------------------------------------------------------


def test_sad_the_read_only_folder_refuses_every_change(tree):
    tools = _tools(tree)
    for name, args in (
        ("write_file", {"path": str(tree / "ro" / "x.txt"), "content": "x"}),
        ("remove", {"path": str(tree / "ro" / "f.txt")}),
        ("rename", {"src": str(tree / "ro" / "f.txt"), "dst": str(tree / "rw" / "g.txt")}),
        ("rename", {"src": str(tree / "rw" / "f.txt"), "dst": str(tree / "ro" / "g.txt")}),
    ):
        with pytest.raises(T.RpcError):
            T.call(tools, name, args)
    assert sorted(os.listdir(tree / "ro")) == ["f.txt"]
    assert (tree / "rw" / "f.txt").exists()


def test_sad_a_folder_outside_every_root_stays_closed(tree):
    tools = _tools(tree)
    with pytest.raises(T.RpcError):
        _read(tools, tree / "outside" / "f.txt")
    with pytest.raises(T.RpcError):
        T.call(tools, "write_file", {"path": str(tree / "outside" / "x"), "content": "x"})


def test_sad_a_link_from_an_extra_folder_out_is_refused(tree):
    os.symlink(tree / "outside", tree / "rw" / "escape")
    tools = _tools(tree)
    with pytest.raises(T.RpcError):
        _read(tools, tree / "rw" / "escape" / "f.txt")


# -- edge ----------------------------------------------------------------------


def test_edge_an_extra_folder_itself_cannot_be_removed(tree):
    tools = _tools(tree)
    with pytest.raises(T.RpcError):
        T.call(tools, "remove", {"path": str(tree / "rw"), "recursive": True})
    assert (tree / "rw" / "f.txt").exists()


def test_edge_a_sibling_with_a_common_prefix_is_not_inside(tree):
    (tree / "rw-other").mkdir()
    (tree / "rw-other" / "f.txt").write_text("other")
    tools = _tools(tree)
    with pytest.raises(T.RpcError):
        _read(tools, tree / "rw-other" / "f.txt")


def test_edge_without_extra_folders_nothing_changes(tree):
    tools = T.build(tree / "main", set(), allow_write=True)
    with pytest.raises(T.RpcError):
        _read(tools, tree / "ro" / "f.txt")
    assert "main" in str(_read(tools, tree / "main" / "f.txt"))
