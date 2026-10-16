"""``axross --mcp-list-tools`` prints a machine-readable manifest of the MCP
tools a start with the same flags would serve, without starting a server;
docs/mcp-tools.json is that manifest for ``--mcp-tools all --mcp-write
--mcp-allow-scripts --mcp-allow-exec`` and must stay in sync with the code."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from core import mcp_groups as G
from core import mcp_server as M

ROOT = Path(__file__).resolve().parents[1]
COMMITTED = ROOT / "docs" / "mcp-tools.json"
FULL_FLAGS = ("--mcp-tools", "all", "--mcp-write", "--mcp-allow-scripts", "--mcp-allow-exec")
REGENERATE = (
    "python main.py --mcp-list-tools --mcp-tools all --mcp-write --mcp-allow-scripts "
    "--mcp-allow-exec > docs/mcp-tools.json"
)


# Homes of the child processes; removed with this object when the run ends.
_HOMES = tempfile.TemporaryDirectory(prefix="axross-manifest-homes-")


def _env() -> dict:
    home = tempfile.mkdtemp(dir=_HOMES.name)
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AXROSS_") and k != "DBUS_SESSION_BUS_ADDRESS"
    }
    env.update(
        HOME=home,
        XDG_CONFIG_HOME=os.path.join(home, ".config"),
        XDG_DATA_HOME=os.path.join(home, ".local", "share"),
        XDG_CACHE_HOME=os.path.join(home, ".cache"),
        XDG_STATE_HOME=os.path.join(home, ".local", "state"),
        PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
        QT_QPA_PLATFORM="offscreen",
    )
    return env


def _cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--mcp-list-tools", *args],
        capture_output=True, text=True, timeout=120, env=env or _env(), cwd=ROOT,
    )


def _manifest(groups=G.GROUPS, write=True, scripts=True, exec_=True) -> dict:
    tools = M._build_tools(
        M.default_backend(), allow_write=write, root="/nonexistent-root",
        allow_scripts=scripts, tool_groups=frozenset(groups), allow_exec=exec_,
    )
    return G.tool_manifest(
        tools, groups=frozenset(groups), allow_write=write, allow_scripts=scripts, allow_exec=exec_
    )


# -- the manifest -------------------------------------------------------------------


def test_happy_manifest_describes_every_served_tool():
    manifest = _manifest()
    served = [t.name for t in M._build_tools(
        M.default_backend(), allow_write=True, root="/x", allow_scripts=True,
        tool_groups=frozenset(G.GROUPS), allow_exec=True)]
    assert [t["name"] for t in manifest["tools"]] == served
    for tool in manifest["tools"]:
        assert set(tool) == {
            "name", "group", "mutating", "required_flags", "transports", "timeout_class",
            "timeout_seconds", "description", "input_schema",
        }
        assert tool["input_schema"]["type"] == "object"
        assert manifest["timeout_classes"][tool["timeout_class"]] == tool["timeout_seconds"]
    assert manifest["generated_for"] == {
        "mcp_tools": sorted(G.GROUPS), "mcp_write": True, "mcp_allow_scripts": True,
        "mcp_allow_exec": True,
    }


def test_happy_required_flags_follow_group_and_mutation():
    tools = {t["name"]: t for t in _manifest()["tools"]}
    assert tools["list_dir"]["required_flags"] == []
    assert tools["write_file"]["required_flags"] == ["--mcp-write", "--mcp-root DIR"]
    assert tools["script_run"]["required_flags"] == ["--mcp-allow-scripts"]
    assert tools["script_run"]["transports"] == ["stdio"]
    assert tools["pack_formats"]["required_flags"] == ["--mcp-tools packer"]
    assert tools["pack"]["required_flags"] == ["--mcp-tools packer", "--mcp-write", "--mcp-root DIR"]
    assert tools["pack"]["mutating"] is True and tools["pack_formats"]["mutating"] is False
    assert tools["list_backends"]["group"] == "remote"
    assert tools["remote_exec"]["required_flags"] == ["--mcp-tools exec", "--mcp-allow-exec"]
    assert tools["remote_exec"]["mutating"] is True and tools["exec_backends"]["group"] == "exec"
    assert tools["read_file"]["transports"] == ["stdio", "http"]


def test_happy_groups_section_lists_their_tools():
    manifest = _manifest()
    assert set(manifest["groups"]) == {"core", "write", "scripts", *G.GROUPS}
    for name, group in manifest["groups"].items():
        assert group["description"]
        assert group["tools"] == [t["name"] for t in manifest["tools"] if t["group"] == name]


def test_edge_default_flags_list_only_the_file_tools():
    manifest = _manifest(groups=(), write=False, scripts=False)
    assert {t["group"] for t in manifest["tools"]} == {"core"}
    assert set(manifest["groups"]) == {"core"}


def test_edge_manifest_never_names_the_root():
    assert "/nonexistent-root" not in json.dumps(_manifest())


# -- the CLI ------------------------------------------------------------------------


def test_happy_cli_prints_the_manifest_without_starting_a_server():
    proc = _cli(*FULL_FLAGS)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == json.loads(json.dumps(_manifest()))


def test_happy_cli_honours_the_flags():
    proc = _cli("--mcp-tools", "packer")
    assert proc.returncode == 0, proc.stderr
    names = {t["name"] for t in json.loads(proc.stdout)["tools"]}
    assert "pack_formats" in names and "pack" not in names and "write_file" not in names


def test_happy_cli_honours_the_env_variables():
    env = _env()
    env.update(AXROSS_MCP_TOOLS="crypto", AXROSS_MCP_WRITE="1")
    proc = _cli(env=env)
    assert proc.returncode == 0, proc.stderr
    names = {t["name"] for t in json.loads(proc.stdout)["tools"]}
    assert {"encrypt", "decrypt", "write_file"} <= names


def test_sad_cli_unknown_group_exits_2():
    proc = _cli("--mcp-tools", "nope")
    assert proc.returncode == 2
    assert proc.stdout == "" and "nope" in proc.stderr


def test_sad_cli_scripts_with_http_is_refused_like_the_server():
    proc = _cli("--mcp-allow-scripts", "--mcp-http", "127.0.0.1:7331")
    # The server's own refusal, not argparse's usage text (which also
    # names --mcp-http and made this pass before --mcp-list-tools existed).
    assert proc.returncode == 2 and "stdio-only" in proc.stderr
    assert proc.stdout == ""


# -- the committed file -------------------------------------------------------------


def test_committed_manifest_is_in_sync_with_the_code():
    assert COMMITTED.exists(), f"docs/mcp-tools.json is missing; regenerate: {REGENERATE}"
    committed = json.loads(COMMITTED.read_text(encoding="utf-8"))
    current = json.loads(json.dumps(_manifest()))
    assert committed == current, f"docs/mcp-tools.json is stale; regenerate: {REGENERATE}"


def test_committed_manifest_is_the_cli_output_byte_for_byte():
    proc = _cli(*FULL_FLAGS)
    assert proc.returncode == 0, proc.stderr
    assert COMMITTED.read_text(encoding="utf-8") == proc.stdout


@pytest.mark.parametrize("group", G.GROUPS)
def test_edge_every_group_is_documented_in_the_committed_manifest(group):
    committed = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert committed["groups"][group]["tools"], group


def test_edge_script_tools_do_not_advertise_a_backend_argument():
    # The script tools work on the script directory and never read
    # ``backend``; with a registry (the remote group) the generic wiring
    # still offered it - a no-op argument a client would trust.
    tools = {t["name"]: t for t in _manifest()["tools"]}
    for name in ("script_list", "script_read", "script_write", "script_delete", "script_run"):
        assert "backend" not in tools[name]["input_schema"]["properties"], name
    assert "backend" in tools["read_file"]["input_schema"]["properties"]
