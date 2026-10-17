"""``--mcp-tools GROUP[,GROUP...]`` / ``AXROSS_MCP_TOOLS`` select the optional
MCP capability groups.

No flag keeps today's tool surface exactly; ``all`` switches on every group;
an unknown group stops the start with exit code 2 and one line on stderr
that lists the valid groups.
"""

from __future__ import annotations

import os
import sys

import pytest

from core import mcp_groups as G
from core import mcp_server as M
from core.local_fs import LocalFS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The tool surface before capability groups existed; the default must not move.
BASE_READ_TOOLS = [
    "list_dir",
    "stat",
    "read_file",
    "checksum",
    "search",
    "walk",
    "recursive_checksum",
    "preview",
    "grep",
    "list_versions",
    "open_version_read",
]
BASE_WRITE_TOOLS = [
    "write_file",
    "mkdir",
    "remove",
    "rename",
    "copy",
    "bulk_copy",
    "symlink",
    "hardlink",
    "chmod",
]


# -- parse_groups ----------------------------------------------------------------


def test_happy_single_group():
    assert G.parse_groups(["packer"]) == frozenset({"packer"})


def test_happy_comma_separated_and_repeated_values_are_merged():
    got = G.parse_groups(["packer,archive", "metadata"])
    assert got == frozenset({"packer", "archive", "metadata"})


def test_happy_all_expands_to_every_group():
    assert G.parse_groups(["all"]) == frozenset(G.GROUPS)
    assert "all" not in G.GROUPS


def test_edge_case_and_whitespace_are_ignored():
    assert G.parse_groups([" Packer , ARCHIVE "]) == frozenset({"packer", "archive"})


def test_edge_all_with_other_groups_is_still_all():
    assert G.parse_groups(["metadata,all"]) == frozenset(G.GROUPS)


def test_edge_no_values_means_no_groups():
    assert G.parse_groups(None) == frozenset()
    assert G.parse_groups([]) == frozenset()


def test_sad_unknown_group_names_the_valid_ones():
    with pytest.raises(G.GroupError) as err:
        G.parse_groups(["packer,backend"])
    text = str(err.value)
    assert "'backend'" in text
    for name in ("all", *G.GROUPS):
        assert name in text
    assert "\n" not in text


def test_sad_flag_without_any_group_is_refused():
    with pytest.raises(G.GroupError):
        G.parse_groups([" , "])


def test_happy_env_value_is_merged_with_the_flag():
    got = G.groups_from(["packer"], env_value="archive, metadata")
    assert got == frozenset({"packer", "archive", "metadata"})


def test_edge_empty_env_value_adds_nothing():
    assert G.groups_from(None, env_value="") == frozenset()
    assert G.groups_from(None, env_value="   ") == frozenset()


def test_sad_unknown_group_in_env_is_refused():
    with pytest.raises(G.GroupError):
        G.groups_from(None, env_value="nope")


# -- the default tool surface does not move ------------------------------------


def _names(**kw) -> list[str]:
    return [t.name for t in M._build_tools(LocalFS(), root="/tmp", **kw)]


def test_happy_default_surface_is_unchanged_read_only():
    assert _names(allow_write=False) == BASE_READ_TOOLS
    assert _names(allow_write=False, tool_groups=frozenset()) == BASE_READ_TOOLS


def test_happy_default_surface_is_unchanged_with_write():
    assert _names(allow_write=True, tool_groups=frozenset()) == BASE_READ_TOOLS + BASE_WRITE_TOOLS


def test_sad_build_tools_refuses_an_unknown_group():
    with pytest.raises(G.GroupError):
        M._build_tools(LocalFS(), allow_write=False, root="/tmp", tool_groups=frozenset({"x"}))


# -- main.py -------------------------------------------------------------------


def _main(*argv: str, env: dict | None = None):
    sys.path.insert(0, ROOT)
    from tests.test_mcp_write_root import _main_in_process

    return _main_in_process(*argv, env=env)


def test_sad_unknown_group_exits_2_with_one_line_before_any_server():
    code, err, serve, serve_http = _main("--mcp-server", "--mcp-tools", "backend")
    assert code == 2, err
    assert len(err.strip().splitlines()) == 1, err
    assert "backend" in err and "packer" in err and "all" in err
    serve.assert_not_called()
    serve_http.assert_not_called()


def test_sad_unknown_group_via_env_exits_2():
    code, err, serve, _ = _main("--mcp-server", env={"AXROSS_MCP_TOOLS": "packer,bogus"})
    assert code == 2, err
    assert "bogus" in err
    serve.assert_not_called()


def test_happy_groups_reach_the_stdio_config():
    code, err, serve, _ = _main(
        "--mcp-server", "--mcp-tools", "packer,archive", "--mcp-tools", "crypto"
    )
    assert code == 0, err
    config = serve.call_args.args[0]
    assert config.tool_groups == frozenset({"packer", "archive", "crypto"})


def test_happy_env_groups_reach_the_stdio_config():
    code, err, serve, _ = _main("--mcp-server", env={"AXROSS_MCP_TOOLS": "all"})
    assert code == 0, err
    assert serve.call_args.args[0].tool_groups == frozenset(G.GROUPS)


def test_edge_no_flag_keeps_the_default_config():
    code, err, serve, _ = _main("--mcp-server")
    assert code == 0, err
    assert serve.call_args.args[0].tool_groups == frozenset()


def test_happy_groups_reach_the_http_config():
    code, err, serve, serve_http = _main(
        "--mcp-server", "--mcp-http", "127.0.0.1:7331", "--mcp-tools", "metadata"
    )
    assert code == 0, err
    assert serve_http.call_args.args[0].tool_groups == frozenset({"metadata"})
    serve.assert_not_called()


# -- every group is wired ----------------------------------------------------------


def test_happy_every_group_has_a_builder_and_all_builds():
    assert set(G._BUILDERS) == set(G.GROUPS)
    tools = M._build_tools(
        LocalFS(), allow_write=True, root="/tmp", tool_groups=frozenset(G.GROUPS), allow_exec=True
    )
    groups = {t.group for t in tools}
    assert set(G.GROUPS) <= groups
    # exec needs its own flag, also under "all"
    without = M._build_tools(
        LocalFS(), allow_write=True, root="/tmp", tool_groups=frozenset(G.GROUPS)
    )
    assert set(G.GROUPS) - {t.group for t in without} == {"exec"}
    names = [t.name for t in tools]
    assert len(names) == len(set(names)), "tool names must be unique"


def test_sad_read_only_all_registers_no_mutating_tool():
    tools = M._build_tools(
        LocalFS(), allow_write=False, root="/tmp", tool_groups=frozenset(G.GROUPS)
    )
    assert [t.name for t in tools if t.write] == []


def test_edge_every_group_tool_has_a_strict_schema_and_a_known_timeout_class():
    tools = M._build_tools(
        LocalFS(), allow_write=True, root="/tmp", tool_groups=frozenset(G.GROUPS)
    )
    for tool in tools:
        assert tool.timeout_class in M.TIMEOUT_CLASSES, tool.name
        assert tool.timeout_seconds == M.TIMEOUT_CLASSES[tool.timeout_class], tool.name
        if tool.group in G.GROUPS and tool.name != "list_backends":
            assert tool.schema.get("additionalProperties") is False, tool.name
            assert tool.description and len(tool.description) > 40, tool.name
