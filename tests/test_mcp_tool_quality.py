"""Tool definitions a client (and a directory's quality score, Glama's TDQS)
can judge without reading the code.

Measured before: 54 parameters of 23 tools had no description; list_dir,
stat and search were one-line descriptions without their result; search
(offline index) and walk (live tree) did not point at each other; and
initialize sent no instructions."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcp_groups as G  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _all_tools(tmp_path):
    return M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path), allow_scripts=True,
                          tool_groups=frozenset(G.GROUPS), allow_exec=True)


def test_sad_every_parameter_of_every_tool_is_described(tmp_path):
    missing = {
        tool.name: [name for name, spec in (tool.schema or {}).get("properties", {}).items()
                    if not str(spec.get("description", "")).strip()]
        for tool in _all_tools(tmp_path)
    }
    assert {k: v for k, v in missing.items() if v} == {}


@pytest.mark.parametrize("name", ["list_dir", "stat", "search", "mkdir", "remove", "rename",
                                  "copy", "script_delete"])
def test_sad_a_tool_says_what_it_returns(tmp_path, name):
    tool = next(t for t in _all_tools(tmp_path) if t.name == name)
    assert "Returns" in tool.description, tool.description


def test_sad_search_and_walk_point_at_each_other(tmp_path):
    tools = {t.name: t.description for t in _all_tools(tmp_path)}
    assert "walk" in tools["search"] and "index" in tools["search"]
    assert "search" in tools["walk"] and "list_dir" in tools["walk"]
    assert "walk" in tools["list_dir"]


def _initialize(version):
    tools = M._build_tools(LocalFS(), allow_write=False, root=None)
    return M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                              "params": {"protocolVersion": version}}, tools,
                             protocol=M.ProtocolState())["result"]


@pytest.mark.parametrize("version", ["2025-11-25", "2025-06-18"])
def test_happy_initialize_sends_short_factual_instructions(version):
    text = _initialize(version)["instructions"]
    assert text == M.SERVER_INSTRUCTIONS and len(text) < 1000
    # Facts about the tools, never requests to the model a client could
    # mistake for injected instructions.
    assert not re.search(r"\b(you|your|must|should|always|never|ignore|do not)\b", text, re.I)
    for tool in ("list_dir", "walk", "stat", "read_file", "grep", "search", "list_backends"):
        assert tool in text


def test_edge_a_2024_session_gets_no_instructions():
    assert "instructions" not in _initialize("2024-11-05")
