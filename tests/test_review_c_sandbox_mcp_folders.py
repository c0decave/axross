"""Review C, round 1: a sandboxed agent and the folders of host-run MCP
servers.

The worker of a sandboxed agent refuses writes below the folder of an
enabled host-run MCP server only when it can read Agent Settings - which
the sandbox holds only when the tab's folder holds ``~/.config``. With
the folder ``~/proj`` and a server in ``~/proj/srv``, the agent rewrote
``server.py`` (only the pin noticed it at the next start, and asked).
Now the sandbox mounts those folders - and for a Node server the
``node_modules`` folders above it - read-only, like the other protected
places: the files stay out of reach whatever the worker knows.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as SB  # noqa: E402
from core import mcp_client as C  # noqa: E402
from core import mcp_runner as R  # noqa: E402
from core import mcp_script_pin as PIN  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.agent_settings import AgentSettings  # noqa: E402

PYTHON = os.path.realpath(sys.executable)


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.delenv(P.HOST_HOME_ENV, raising=False)
    monkeypatch.setattr(R, "launcher_place_problem", lambda *a, **k: "")
    PIN._GUARD_CACHE.clear()
    yield home
    PIN._GUARD_CACHE.clear()


def _saved(*configs):
    settings = AgentSettings()
    settings.mcp_servers = list(configs)
    settings.save()
    PIN._GUARD_CACHE.clear()


def _plan(proj):
    return {path: (rw, kind) for path, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(proj), True)}


def test_sad_a_host_run_servers_folder_is_read_only_in_the_sandbox(home):
    srv = home / "proj" / "srv"
    srv.mkdir(parents=True)
    (srv / "server.py").write_text("print(1)\n")
    _saved(C.McpServerConfig(name="py", command=(PYTHON, str(srv / "server.py"))))
    plan = _plan(home / "proj")
    assert plan[str(srv)][0] is False
    assert plan[str(home / "proj")][0] is True


def test_sad_the_node_modules_above_a_node_server_are_read_only_in_the_sandbox(home):
    srv = home / "proj" / "packages" / "srv"
    srv.mkdir(parents=True)
    (srv / "server.js").write_text("1\n")
    (home / "proj" / "node_modules").mkdir()
    _saved(C.McpServerConfig(name="js", command=("/usr/bin/node", str(srv / "server.js"))))
    plan = _plan(home / "proj")
    assert plan[str(srv)][0] is False
    assert plan[str(home / "proj" / "node_modules")] == (False, "bind")
    # A missing one: an empty read-only folder takes its place.
    assert plan[str(home / "proj" / "packages" / "node_modules")] == (False, "dir")


def test_happy_a_switched_off_or_sandboxed_server_leaves_its_folder_writable(home):
    srv = home / "proj" / "srv"
    srv.mkdir(parents=True)
    (srv / "server.py").write_text("print(1)\n")
    _saved(C.McpServerConfig(name="off", enabled=False,
                             command=(PYTHON, str(srv / "server.py"))),
           C.McpServerConfig(name="boxed", sandbox="Normal",
                             command=(PYTHON, str(srv / "server.py"))))
    assert str(srv) not in _plan(home / "proj")


def test_happy_a_server_outside_the_folder_adds_no_mount(home, tmp_path):
    srv = tmp_path / "elsewhere" / "srv"
    srv.mkdir(parents=True)
    (srv / "server.js").write_text("1\n")
    (home / "proj").mkdir()
    _saved(C.McpServerConfig(name="js", command=("/usr/bin/node", str(srv / "server.js"))))
    plan = _plan(home / "proj")
    assert not any(path.startswith(str(tmp_path / "elsewhere")) for path in plan)
    assert str(home / "proj" / "node_modules") not in plan
