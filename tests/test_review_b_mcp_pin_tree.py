"""Review B, items 1 and 2: the files a host-run MCP server runs.

1 - a ``.pyc`` planted in ``__pycache__`` beside a pinned Python script ran
on the host: the pin listed only the module files of the script's folder,
and the agent's writes were refused only there.
2 - modules of a sub-package (``pkg/util.py``), new modules there and the
files a Node server ``require()``s (``lib.js``, ``node_modules``) were
neither pinned nor protected.

Now the whole folder of the server's file is walked (bounded: a walk that
does not see all of it refuses the start), every file in it is hashed, the
agent writes nothing below it, and Python servers start with a private
``PYTHONPYCACHEPREFIX`` (tests/test_review_b_mcp_pycache_prefix.py).
"""

from __future__ import annotations

import importlib.util
import json
import marshal
import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_client as C  # noqa: E402
from core import mcp_runner as R  # noqa: E402
from core import mcp_script_pin as PIN  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.agent_settings import AgentSettings  # noqa: E402

PYTHON = os.path.realpath(sys.executable)

_SERVER = '''import json, sys
import util
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "serverInfo": {"name": "mine", "version": str(util.X)}}}), flush=True)
    elif "id" in m:
        print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {"tools": []}}), flush=True)
'''


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.delenv(P.HOST_HOME_ENV, raising=False)
    monkeypatch.setattr(R, "launcher_place_problem", lambda *a, **k: "")
    PIN._GUARD_CACHE.clear()
    return home


@pytest.fixture
def folder(home):
    folder = home / "proj" / "srv"
    (folder / "pkg").mkdir(parents=True)
    (folder / "server.py").write_text(_SERVER)
    (folder / "util.py").write_text("X = 1\n")
    (folder / "pkg" / "__init__.py").write_text("")
    (folder / "pkg" / "util.py").write_text("X = 1\n")
    (folder / "server.js").write_text("require('./lib.js')\n")
    (folder / "lib.js").write_text("1\n")
    (folder / "node_modules" / "dep").mkdir(parents=True)
    (folder / "node_modules" / "dep" / "index.js").write_text("module.exports = 1\n")
    return folder


def _saved(*configs) -> list:
    settings = AgentSettings()
    settings.mcp_servers = list(configs)
    settings.save()
    PIN._GUARD_CACHE.clear()
    return AgentSettings.load().mcp_servers


def _py(folder) -> C.McpServerConfig:
    return C.McpServerConfig(name="py", command=(PYTHON, str(folder / "server.py")))


def _js(folder) -> C.McpServerConfig:
    return C.McpServerConfig(name="js", command=("/usr/bin/node", str(folder / "server.js")))


def _planted_pyc(folder: Path) -> Path:
    """A .pyc whose header matches util.py: Python would load it."""
    source = folder / "util.py"
    st = source.stat()
    code = marshal.dumps(compile("X = 666\n", "util.py", "exec"))
    target = folder / "__pycache__" / f"util.{sys.implementation.cache_tag}.pyc"
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack(
        "<III", 0, int(st.st_mtime) & 0xFFFFFFFF, st.st_size & 0xFFFFFFFF) + code)
    return target


# -- item 1: __pycache__ ------------------------------------------------------------------


def test_sad_a_planted_pyc_is_refused_to_the_agent_and_stops_the_start(folder, home):
    py, = _saved(_py(folder))
    target = folder / "__pycache__" / f"util.{sys.implementation.cache_tag}.pyc"
    refused = P.refusal(str(target))
    assert refused and "MCP server" in refused and "py" in refused
    assert P.refusal(str(folder / "__pycache__"), entry=True)
    _planted_pyc(folder)
    why, files = PIN.start_check(py)
    assert why and str(target) in files
    with pytest.raises(C.McpFilesChanged):
        C.McpClient(py)


def test_happy_a_python_server_never_reads_or_writes_its_folders_pycache(folder, home):
    # The user confirms the files with a stale .pyc in them: Python must
    # still compile util.py, not load the .pyc, and write none.
    _planted_pyc(folder)
    py, = _saved(_py(folder))
    client = C.McpClient(py)
    try:
        assert client.server_info["version"] == "1"
    finally:
        client.close()
    assert [p.name for p in (folder / "__pycache__").iterdir()] == [
        f"util.{sys.implementation.cache_tag}.pyc"]


def test_edge_the_private_pycache_prefix_lies_in_axross_state(home, monkeypatch):
    prefix = C.pycache_prefix()
    assert Path(prefix).is_relative_to(home / ".local" / "state" / "axross")
    assert P.refusal(os.path.join(prefix, "x.pyc"))


# -- item 2: the whole tree --------------------------------------------------------------


@pytest.mark.parametrize("rel", ["pkg/util.py", "pkg/new.py", "lib.js",
                                 "node_modules/dep/index.js", "node_modules/new/x.js",
                                 "README.md", "sub/deeper/x.py"])
def test_sad_the_agent_writes_nothing_below_a_pinned_servers_folder(folder, home, rel):
    _saved(_py(folder), _js(folder))
    assert P.refusal(str(folder / rel)), rel


@pytest.mark.parametrize("rel", ["pkg/util.py", "lib.js", "node_modules/dep/index.js"])
def test_sad_a_changed_file_anywhere_in_the_tree_stops_the_start(folder, home, rel):
    py, js = _saved(_py(folder), _js(folder))
    (folder / rel).write_text("changed = 1\n")
    for config in (py, js):
        why, files = PIN.start_check(config)
        assert why and files == [str(folder / rel)]


def test_sad_a_new_file_in_a_sub_package_stops_the_start(folder, home):
    py, = _saved(_py(folder))
    (folder / "pkg" / "new.py").write_text("import os\n")
    assert PIN.start_check(py)[1] == [str(folder / "pkg" / "new.py")]


def test_happy_files_outside_the_folder_stay_the_agents(folder, home):
    _saved(_py(folder))
    assert P.refusal(str(folder.parent / "other.py")) is None
    assert P.refusal(str(home / "notes.txt")) is None


def test_sad_a_walk_that_does_not_see_everything_refuses_the_start(folder, home, monkeypatch):
    monkeypatch.setattr(PIN, "MAX_FILES", 3)
    py, = _saved(_py(folder))
    assert py.pin["complete"] is False
    why, files = PIN.start_check(py)
    assert why and files == []
    with pytest.raises(C.McpClientError, match="more than"):
        C.McpClient(py)


def test_sad_a_tree_over_the_byte_limit_refuses_the_start(folder, home, monkeypatch):
    monkeypatch.setattr(PIN, "MAX_BYTES", 10)
    py, = _saved(_py(folder))
    assert py.pin["complete"] is False
    with pytest.raises(C.McpClientError, match="more than"):
        C.McpClient(py)


def test_edge_a_symlinked_folder_is_walked_and_protected(folder, home):
    elsewhere = home / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "mod.py").write_text("X = 1\n")
    os.symlink(elsewhere, folder / "linked")
    py, = _saved(_py(folder))
    assert str(folder / "linked" / "mod.py") in py.pin["files"]
    assert P.refusal(str(elsewhere / "mod.py"))
    (elsewhere / "mod.py").write_text("X = 2\n")
    assert PIN.start_check(py)[1] == [str(folder / "linked" / "mod.py")]


def test_edge_a_symlink_loop_ends_the_walk(folder, home):
    os.symlink(folder, folder / "pkg" / "loop")
    pin = PIN.compute(_py(folder).command)
    assert pin["complete"] is True
    assert str(folder / "server.py") in pin["files"]


def test_edge_a_fifo_in_the_tree_is_not_opened(folder, home):
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    os.mkfifo(folder / "pkg" / "x.py")
    pin = PIN.compute(_py(folder).command)
    assert pin["files"][str(folder / "pkg" / "x.py")] == "not-a-file"


def test_edge_settings_keep_the_roots_of_the_walk(folder, home):
    py, = _saved(_py(folder))
    raw = json.loads((home / ".config" / "axross" / "agent" / "settings.json").read_text())
    assert raw["mcp_servers"][0]["pin"]["roots"] == [str(folder)]
    assert PIN.clean(raw["mcp_servers"][0]["pin"])["roots"] == [str(folder)]
