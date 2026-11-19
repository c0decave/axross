"""Second security review, MCP: walk, recursive_checksum and bulk_copy have an
upper cap on their counts and depth (a caller's max_entries=10**9 kept the
whole tree in memory), and search has a limit and stops on a cancel."""

from __future__ import annotations

import os
import sqlite3
import threading
from unittest import mock

import pytest

from core import mcp_server as M
from core import metadata_index as MX
from core.local_fs import LocalFS


def _tools(root, write=False):
    return {t.name: t for t in M._build_tools(LocalFS(), allow_write=write, backend_id="local", root=str(root))}


@pytest.mark.parametrize("tool,args", [
    ("walk", {"max_entries": M.MAX_WALK_ENTRIES + 1}),
    ("walk", {"max_depth": M.MAX_TREE_DEPTH + 1}),
    ("recursive_checksum", {"max_files": M.MAX_RECURSIVE_CHECKSUM_FILES + 1}),
    ("recursive_checksum", {"max_depth": M.MAX_TREE_DEPTH + 1}),
])
def test_sad_a_count_above_the_cap_is_refused(tmp_path, tool, args):
    tools = _tools(tmp_path)
    with pytest.raises(ValueError):
        tools[tool].handler({"path": str(tmp_path), **args}, M._ToolContext())
    schema = tools[tool].schema["properties"]
    for key in args:
        assert "maximum" in schema[key], key


@pytest.mark.parametrize("args", [{"max_files": M.MAX_BULK_COPY_FILES + 1}, {"max_depth": M.MAX_TREE_DEPTH + 1}])
def test_sad_bulk_copy_above_the_cap_is_refused(tmp_path, args):
    (tmp_path / "a").mkdir()
    tools = _tools(tmp_path, write=True)
    with pytest.raises(ValueError):
        tools["bulk_copy"].handler({"src": str(tmp_path / "a"), "dst": str(tmp_path / "b"), **args},
                                   M._ToolContext())
    for key in args:
        assert "maximum" in tools["bulk_copy"].schema["properties"][key], key


def test_happy_the_caps_themselves_are_accepted(tmp_path):
    (tmp_path / "f").write_text("x")
    tools = _tools(tmp_path)
    out = tools["walk"].handler({"path": str(tmp_path), "max_entries": M.MAX_WALK_ENTRIES,
                                 "max_depth": M.MAX_TREE_DEPTH}, M._ToolContext())
    assert [e["name"] for e in out["entries"]] == ["f"]


@pytest.fixture
def index(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    db = str(tmp_path / "idx.sqlite")
    for i in range(30):
        MX.upsert(db, "local", os.path.join(str(root), f"hit-{i:02d}.txt"), name=f"hit-{i:02d}.txt", size=1,
                  is_dir=False)
    for i in range(30):
        MX.upsert(db, "local", os.path.join(str(tmp_path), "outside", f"hit-o{i:02d}.txt"),
                  name=f"hit-o{i:02d}.txt", size=1, is_dir=False)
    real = MX.search_all
    seen = {}

    def search_all(**kw):
        seen.update(kw)
        return real(**{**kw, "db_path": db})

    with mock.patch.object(MX, "search_all", search_all):
        yield root, seen


def test_happy_search_takes_a_limit_after_the_root_is_applied(index):
    root, seen = index
    tool = _tools(root)["search"]
    hits = tool.handler({"needle": "hit-", "limit": 5}, M._ToolContext())
    assert len(hits) == 5 and all(h["path"].startswith(str(root)) for h in hits)
    assert "maximum" in tool.schema["properties"]["limit"]
    with pytest.raises(ValueError):
        tool.handler({"needle": "hit-", "limit": M.MAX_SEARCH_RESULTS + 1}, M._ToolContext())


def test_happy_search_has_a_default_limit_and_bounds_the_rows_it_reads(index):
    root, seen = index
    _tools(root)["search"].handler({"needle": "hit-"}, M._ToolContext())
    assert seen.get("limit") is not None and seen["limit"] <= M.MAX_SEARCH_SCAN
    assert callable(seen.get("cancel"))


def test_sad_a_cancelled_search_stops(index):
    root, _ = index
    event = threading.Event()
    event.set()
    ctx = M._ToolContext()
    ctx.cancel_event = event
    with pytest.raises(M.CancelledError):
        _tools(root)["search"].handler({"needle": "hit-"}, ctx)


def test_sad_a_search_the_index_stops_midway_is_a_cancel(index, monkeypatch):
    root, _ = index
    event = threading.Event()
    ctx = M._ToolContext()
    ctx.cancel_event = event

    def interrupted(**kw):
        event.set()
        assert kw["cancel"]() is True
        raise sqlite3.OperationalError("interrupted")

    monkeypatch.setattr(MX, "search_all", interrupted)
    with pytest.raises(M.CancelledError):
        _tools(root)["search"].handler({"needle": "hit-"}, ctx)
