"""Review B, item 1 follow-up: Python MCP servers run on this machine
without ``-B`` but with a private ``PYTHONPYCACHEPREFIX``.

The prefix (``$XDG_STATE_HOME/axross/mcp-pycache``) is where Python keeps
the byte code of a host-run server's modules, so no ``.pyc`` beside the
sources is loaded and the modules are not compiled again at each start.
That is safe only while the agent can never write there: its write guard
(core.protected_places) refuses every path below it - as written, through
``..``, through a symlink, before the folder exists, wherever
``XDG_STATE_HOME`` puts it - and axross uses the folder only when it is a
real folder of this user with mode 0700.
"""

from __future__ import annotations

import json
import os
import stat
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
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.delenv(P.HOST_HOME_ENV, raising=False)
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    monkeypatch.setattr(R, "launcher_place_problem", lambda *a, **k: "")
    PIN._GUARD_CACHE.clear()
    return home


def _prefix(home: Path) -> Path:
    return home / ".local" / "state" / "axross" / "mcp-pycache"


def _server(home: Path) -> C.McpServerConfig:
    folder = home / "proj" / "srv"
    folder.mkdir(parents=True)
    (folder / "server.py").write_text(_SERVER)
    (folder / "util.py").write_text("X = 1\n")
    settings = AgentSettings()
    settings.mcp_servers = [C.McpServerConfig(name="py", command=(PYTHON, str(folder / "server.py")))]
    settings.save()
    PIN._GUARD_CACHE.clear()
    return AgentSettings.load().mcp_servers[0]


# -- no -B: the byte code goes to the private prefix -------------------------------------


def test_happy_a_python_server_caches_its_byte_code_in_the_private_prefix(home, monkeypatch):
    started = []
    real = C._Stdio.__init__

    def spy(self, argv, env, *a, **k):
        started.append((list(argv), dict(env)))
        return real(self, argv, env, *a, **k)

    monkeypatch.setattr(C._Stdio, "__init__", spy)
    config = _server(home)
    client = C.McpClient(config)
    try:
        assert client.server_info["version"] == "1"
    finally:
        client.close()
    argv, env = started[0]
    assert "-B" not in argv and "PYTHONDONTWRITEBYTECODE" not in env
    assert env["PYTHONPYCACHEPREFIX"] == str(_prefix(home))
    cached = [p.name for p in _prefix(home).rglob("*.pyc")]
    assert any(n.startswith("util.") for n in cached), cached
    assert not (home / "proj" / "srv" / "__pycache__").exists()


# -- the agent never writes there ---------------------------------------------------------


def _refused(path, **kw) -> bool:
    PIN._GUARD_CACHE.clear()
    return bool(P.refusal(str(path), **kw))


@pytest.mark.parametrize("exists", [True, False])
def test_sad_the_agent_writes_nothing_below_the_prefix(home, exists):
    prefix = _prefix(home)
    if exists:
        C.pycache_prefix()
        assert prefix.is_dir()
    else:
        assert not prefix.exists()
    for path in (prefix / "x.pyc",
                 prefix / "home" / "u" / "proj" / "srv" / "util.cpython-311.pyc",
                 prefix / "new" / "deeper" / "x.pyc"):
        assert _refused(path), path
    assert _refused(prefix, entry=True)
    assert _refused(prefix.parent, entry=True)


def test_sad_dot_dot_does_not_lead_around_it(home):
    (home / "proj").mkdir()
    sneaky = str(home / "proj") + "/../.local/state/axross/./mcp-pycache/x.pyc"
    assert _refused(sneaky)
    assert _refused(str(home / "proj") + "/../.local/state/axross/mcp-pycache")


@pytest.mark.parametrize("exists", [True, False])
def test_sad_a_symlink_does_not_lead_around_it(home, exists):
    prefix = _prefix(home)
    if exists:
        C.pycache_prefix()
    proj = home / "proj"
    proj.mkdir()
    os.symlink(prefix, proj / "cache")             # to the prefix itself
    os.symlink(prefix.parent, proj / "state")      # to the folder holding it
    os.symlink(prefix / "x.pyc", proj / "x.pyc")   # to a file in it
    assert _refused(proj / "cache" / "x.pyc")
    assert _refused(proj / "state" / "mcp-pycache" / "x.pyc")
    assert _refused(proj / "x.pyc")


def test_sad_a_moved_state_folder_is_protected_too(home, tmp_path, monkeypatch):
    state = tmp_path / "work" / "state"   # outside the home, inside a granted root
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    prefix = Path(C.pycache_prefix())
    assert prefix == state / "axross" / "mcp-pycache"
    assert P.refusal(str(prefix / "x.pyc"), granted=(str(tmp_path / "work"),))
    assert P.refusal(str(prefix / "x.pyc"))


def test_sad_the_agents_write_tool_refuses_it(home):
    from core import mcp_server as M
    from core.local_fs import LocalFS

    prefix = Path(C.pycache_prefix())
    PIN._GUARD_CACHE.clear()
    tools = M._build_tools(LocalFS(), allow_write=True, root=str(home))
    for target in (prefix / "x.pyc", home / "proj" / ".." / ".local" / "state" / "axross"
                   / "mcp-pycache" / "y.pyc"):
        reply = M._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "write_file",
                        "arguments": {"path": str(target), "content": "x"}}},
            tools, cancels=M._CancelRegistry(), tasks=M._TaskRegistry())
        assert "does not change" in json.dumps(reply), reply
    assert list(prefix.iterdir()) == []


# -- the folder itself: 0700, this user's, a real folder ---------------------------------


def test_happy_the_prefix_is_made_0700_and_the_users(home):
    prefix = Path(C.pycache_prefix())
    st = os.lstat(prefix)
    assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
    assert st.st_uid == os.geteuid()


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o705, 0o777])
def test_sad_a_prefix_others_may_read_or_write_is_not_used(home, mode):
    prefix = _prefix(home)
    prefix.mkdir(parents=True)
    prefix.chmod(mode)
    with pytest.raises(C.McpClientError, match="byte-code folder"):
        C.pycache_prefix()
    assert stat.S_IMODE(os.lstat(prefix).st_mode) == mode  # not "repaired"


def test_sad_a_prefix_of_another_user_is_not_used(home, monkeypatch):
    from core import posix_compat

    prefix = _prefix(home)
    prefix.mkdir(parents=True, mode=0o700)
    # This process as another user (chown needs rights the test may lack).
    monkeypatch.setattr(posix_compat, "effective_uid", lambda: os.geteuid() + 4242)
    with pytest.raises(C.McpClientError, match="another user"):
        C.pycache_prefix()


def test_sad_a_symlink_in_place_of_the_prefix_is_not_used(home, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    prefix = _prefix(home)
    prefix.parent.mkdir(parents=True)
    os.symlink(elsewhere, prefix)
    with pytest.raises(C.McpClientError, match="byte-code folder"):
        C.pycache_prefix()


def test_sad_a_server_does_not_start_with_an_unusable_prefix(home):
    config = _server(home)
    _prefix(home).mkdir(parents=True)
    _prefix(home).chmod(0o755)
    with pytest.raises(C.McpClientError, match="byte-code folder"):
        C.McpClient(config)
