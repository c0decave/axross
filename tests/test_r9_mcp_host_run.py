"""Round-9 security: host-run MCP servers.

M2 - an agent allowed to change files under its MCP root rewrote the script
of the user's host-run server (``python3 ~/projects/my-mcp/server.py``) or
put a ``json.py`` beside it; axross ran it on the host at the next start.
Now the files are pinned (core.mcp_script_pin: SHA-256 of the script and
of the module files beside a Python script) when Settings saves the server,
a start with changed or unconfirmed files is refused, and the files of the
enabled host-run servers are protected places for the agent's writes.
L-M stdin - a server that stopped reading its input wedged the reader
thread (it answered pings with a blocking write), call_tool past its
timeout and close() for 20 s on the GUI thread.
L-M launchers - ``python -m timeit -s <code>``, ``-m pdb -c '!<code>'`` and
the standard library's own scripts counted as pure launchers.
L env - HOME, PYTHONPYCACHEPREFIX, BASH_FUNC_*, GIT_CONFIG_* … loaded code
without the Trusted mark. L venv - a venv-shaped folder holding a symlink
to /usr/bin/python3 passed the launcher place check (its .pth ran).
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_client as C  # noqa: E402
from core import mcp_runner as R  # noqa: E402
from core import mcp_script_pin as PIN  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.agent_settings import AgentSettings, settings_file  # noqa: E402

#: The interpreter itself, not a venv's link to it (a venv is no pure launcher).
PYTHON = os.path.realpath(sys.executable)

_SERVER = '''import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "serverInfo": {"name": "mine", "version": "0"}}}), flush=True)
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
def server(home):
    folder = home / "projects" / "my-mcp"
    folder.mkdir(parents=True)
    script = folder / "server.py"
    script.write_text(_SERVER)
    return script


def _evil(marker: Path) -> str:
    return f"open({str(marker)!r}, 'w').write('ran')\n" + _SERVER


def _saved(script: Path, **kw) -> C.McpServerConfig:
    """The server as Settings saves it, read back."""
    settings = AgentSettings()
    settings.mcp_servers = [C.McpServerConfig(name="mine", command=(PYTHON, str(script)), **kw)]
    settings.save()
    return AgentSettings.load().mcp_servers[0]


def _start(config):
    client = C.McpClient(config)
    try:
        return client.server_info
    finally:
        client.close()


# -- M2: the files a host-run server runs -------------------------------------------------


def test_sad_a_host_run_script_nobody_confirmed_does_not_start(server, tmp_path):
    marker = tmp_path / "RAN"
    server.write_text(_evil(marker))
    with pytest.raises(C.McpClientError, match="not confirmed"):
        C.McpClient(C.McpServerConfig(name="mine", command=(PYTHON, str(server))))
    assert not marker.exists()


def test_happy_a_confirmed_script_starts(server):
    config = _saved(server)
    assert list(config.pin["files"]) == [str(server)]
    assert config.pin["files"][str(server)].startswith("sha256:")
    assert _start(config)["name"] == "mine"


def test_sad_a_script_changed_after_it_was_confirmed_does_not_start(server, tmp_path):
    config = _saved(server)
    marker = tmp_path / "RAN"
    server.write_text(_evil(marker))
    with pytest.raises(C.McpClientError, match="changed since you confirmed") as caught:
        C.McpClient(config)
    assert str(server) in str(caught.value)
    assert not marker.exists()
    # Saving the settings again does not confirm the change ...
    settings = AgentSettings.load()
    settings.save()
    with pytest.raises(C.McpClientError, match="changed since you confirmed"):
        C.McpClient(AgentSettings.load().mcp_servers[0])
    assert not marker.exists()


def test_sad_a_module_put_beside_a_confirmed_python_script_stops_the_start(server, tmp_path):
    config = _saved(server)
    marker = tmp_path / "RAN"
    (server.parent / "json.py").write_text(
        f"open({str(marker)!r}, 'w').write('ran')\n"
        "import sys; del sys.modules['json']; sys.path.pop(0); import json as j; "
        "sys.modules['json'] = j\n")
    with pytest.raises(C.McpClientError, match="json.py"):
        C.McpClient(config)
    assert not marker.exists()
    (server.parent / "json.py").unlink()
    assert _start(config)["name"] == "mine"  # as confirmed again


def test_edge_a_package_folder_beside_the_script_counts_too(server):
    config = _saved(server)
    package = server.parent / "json"
    package.mkdir()
    (package / "__init__.py").write_text("")
    assert PIN.changed(config) == [str(package / "__init__.py")]
    (server.parent / "notes.txt").write_text("not a module")  # not code: not pinned
    assert PIN.changed(config) == [str(package / "__init__.py")]


def test_happy_a_new_command_saved_by_the_user_is_pinned_anew(server, home):
    config = _saved(server)
    other = server.parent.parent / "other" / "srv.py"
    other.parent.mkdir()
    other.write_text(_SERVER)
    settings = AgentSettings.load()
    settings.mcp_servers[0].command = (PYTHON, str(other))
    settings.save()
    again = AgentSettings.load().mcp_servers[0]
    assert str(other) in again.pin["files"] and str(server) not in again.pin["files"]
    assert config.pin != again.pin


def test_edge_settings_of_an_older_axross_are_pinned_once_at_load(server, home):
    path = settings_file()
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"version": 1, "mcp_servers": [
        {"name": "mine", "transport": "stdio", "command": [PYTHON, str(server)]}]}))
    loaded = AgentSettings.load().mcp_servers[0]
    assert loaded.pin["files"][str(server)].startswith("sha256:")
    assert json.loads(path.read_text())["mcp_servers"][0]["pin"] == loaded.pin


def test_edge_a_trusted_program_is_pinned_and_a_sandboxed_one_is_not(server, home):
    program = home / "bin" / "my-server"
    program.parent.mkdir()
    program.write_text("#!/bin/sh\n")
    trusted = C.McpServerConfig(name="t", command=(str(program), "serve"), trusted=True)
    assert PIN.needs_pin(trusted) and list(PIN.compute(trusted.command)["files"]) == [
        str(program)]
    boxed = C.McpServerConfig(name="b", command=(PYTHON, str(server)), sandbox="Normal")
    assert not PIN.needs_pin(boxed)
    assert not PIN.needs_pin(C.McpServerConfig(name="m", command=(PYTHON, "-m",
                                                                  "mcp_server_git")))


def test_edge_the_folder_listing_is_bounded(server, monkeypatch):
    monkeypatch.setattr(PIN, "MAX_FILES", 3)
    for i in range(6):
        (server.parent / f"m{i}.py").write_text(f"# {i}\n")
    pin = PIN.compute((PYTHON, str(server)))
    hashed = [v for v in pin["files"].values() if v.startswith("sha256:")]
    assert len(pin["files"]) == 7 and len(hashed) == 3 + 1 and pin["complete"] is False


def test_edge_a_fifo_in_place_of_the_script_never_blocks(server):
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    fifo = server.parent / "x.py"
    os.mkfifo(fifo)
    started = time.monotonic()
    pin = PIN.compute((PYTHON, str(server)))
    assert pin["files"][str(fifo)] == "not-a-file"
    assert time.monotonic() - started < 5


def test_sad_the_agent_does_not_write_the_files_of_an_enabled_host_run_server(server, home):
    _saved(server)
    PIN._GUARD_CACHE.clear()
    refused = P.refusal(str(server))
    assert refused and "MCP server runs" in refused
    assert "MCP server runs" in (P.refusal(str(server.parent / "json.py")) or "")
    assert "MCP server runs" in (P.refusal(str(server.parent / "json" / "__init__.py")) or "")
    assert "MCP server runs" in (P.refusal(str(server.parent), entry=True) or "")
    # what is no code of the server stays the agent's to change
    assert P.refusal(str(server.parent / "README.md")) is None
    assert P.refusal(str(server.parent / "sub" / "x.py")) is None


def test_happy_a_disabled_or_sandboxed_server_leaves_its_files_to_the_agent(server, home):
    _saved(server, enabled=False)
    PIN._GUARD_CACHE.clear()
    assert P.refusal(str(server)) is None
    _saved(server, sandbox="Normal")
    PIN._GUARD_CACHE.clear()
    assert P.refusal(str(server)) is None


def test_sad_the_mcp_server_write_tool_refuses_the_pinned_script(server, home):
    from core import mcp_server as M
    from core.local_fs import LocalFS

    _saved(server)
    PIN._GUARD_CACHE.clear()
    tools = M._build_tools(LocalFS(), allow_write=True, root=str(home / "projects"))
    for target in (server, server.parent / "json.py"):
        reply = M._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "write_file",
                        "arguments": {"path": str(target), "content": "print(1)\n"}}},
            tools, cancels=M._CancelRegistry(), tasks=M._TaskRegistry())
        text = json.dumps(reply)
        assert "MCP server runs" in text, text
    assert server.read_text() == _SERVER
    assert not (server.parent / "json.py").exists()


def test_happy_the_settings_page_confirms_the_files_again(server, home):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    from tests.test_agent_settings_dialog import _dialog

    _app = QApplication.instance() or QApplication([])  # noqa: F841

    config = _saved(server)
    server.write_text(_SERVER + "# reviewed change\n")
    with pytest.raises(C.McpClientError, match="changed since you confirmed"):
        C.McpClient(AgentSettings.load().mcp_servers[0])
    dialog = _dialog(settings_file())
    try:
        dialog.server_list.setCurrentRow(0)
        dialog.confirm_server_files()
        assert "1" in dialog.server_pin_label.text()
        assert dialog.save()
    finally:
        dialog.close()
        dialog.deleteLater()
    again = AgentSettings.load().mcp_servers[0]
    assert again.pin != config.pin
    assert _start(again)["name"] == "mine"


def test_sad_changed_files_are_reported_by_server_and_file(server):
    config = _saved(server)
    server.write_text(_SERVER + "# changed\n")
    pool = C.McpClientPool(token_lookup=lambda name: "")
    tools, errors = pool.tools([config])
    assert not tools and "changed since you confirmed" in errors[0]
    assert pool.take_unconfirmed() == {"mine": [str(server)]}
    assert pool.take_unconfirmed() == {}  # handed over once


def _dock_env(tmp_path, config):
    from tests.test_agent_tabs import Env

    (tmp_path / "env").mkdir()
    env = Env(tmp_path / "env")
    env.fake({"content": "never asked"})
    env.settings.mcp_servers = [config]
    env.mcp_pool = C.McpClientPool(token_lookup=lambda name: "")
    return env


def _until(predicate, seconds=10.0):
    from tests.test_agent_tabs import APP

    end = time.monotonic() + seconds
    while not predicate() and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.02)
    return predicate()


def test_happy_the_user_is_asked_and_yes_runs_the_server_with_its_files(server, tmp_path):
    env = _dock_env(tmp_path, _saved(server))
    try:
        dock = env.dock()
        asked = []
        dock.confirm_files = lambda name, files: asked.append((name, files)) or True
        server.write_text(_SERVER + "# my own change\n")
        tools, errors = dock.mcp_tools(["mine"])
        assert "changed since you confirmed" in errors[0]
        assert _until(lambda: asked and env.saved)
        assert asked == [("mine", [str(server)])]
        assert env.saved[-1].mcp_servers[0].pin["files"][str(server)] == \
            PIN.compute((PYTHON, str(server)))["files"][str(server)]
        tools, errors = dock.mcp_tools(["mine"])
        assert errors == []
    finally:
        env.close()
        env.mcp_pool.close_all()


def test_sad_not_now_keeps_it_off_and_is_not_asked_again(server, tmp_path):
    env = _dock_env(tmp_path, _saved(server))
    try:
        dock = env.dock()
        asked = []
        dock.confirm_files = lambda name, files: asked.append(name) and False
        server.write_text(_SERVER + "# someone's change\n")
        dock.mcp_tools(["mine"])
        assert _until(lambda: asked)
        _tools, errors = dock.mcp_tools(["mine"])
        _until(lambda: len(asked) > 1, 0.5)
        assert asked == ["mine"] and "changed since you confirmed" in errors[0]
        assert env.saved == []
    finally:
        env.close()
        env.mcp_pool.close_all()


# -- L-M: a server that stops reading its input ------------------------------------------

_STALLING = r'''import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "stall", "version": "0"}}}), flush=True)
        break
for i in range(10**7):  # never reads again; pings until the client stops reading
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": "p%d" % i, "method": "ping"}) + "\n")
    sys.stdout.flush()
'''


def _pinned(name: str, script: Path, **kw) -> C.McpServerConfig:
    config = C.McpServerConfig(name=name, command=(PYTHON, str(script)), **kw)
    config.pin = PIN.compute(config.command)
    return config


def test_sad_a_server_that_stops_reading_fails_the_call_within_its_timeout(home, tmp_path):
    script = tmp_path / "stall.py"
    script.write_text(_STALLING)
    client = C.McpClient(_pinned("stall", script, timeout=2))
    try:
        time.sleep(1.5)  # the answers to its pings fill the pipe
        box: dict = {}

        def call() -> None:
            started = time.monotonic()
            try:
                box["r"] = client.call_tool("t", {})
            except C.McpClientError as exc:
                box["r"] = exc
            box["t"] = time.monotonic() - started

        thread = threading.Thread(target=call, daemon=True)
        thread.start()
        thread.join(15)
        assert not thread.is_alive(), "call_tool blocked past its timeout"
        assert isinstance(box["r"], C.McpClientError) and box["t"] < 6
    finally:
        started = time.monotonic()
        client.close()
        assert time.monotonic() - started < C.CLOSE_WAIT + 1.5


_TERM = r'''import json, signal, sys, time
def term(*_):
    open({marker!r}, "w").write("term")
    sys.exit(0)
signal.signal(signal.SIGTERM, term)
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "initialize":
        print(json.dumps({{"jsonrpc": "2.0", "id": m["id"], "result": {{
            "protocolVersion": "2025-06-18", "capabilities": {{}},
            "serverInfo": {{"name": "term", "version": "0"}}}}}}), flush=True)
        break
while True:  # ignores the end of its input
    time.sleep(0.1)
'''


@pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="POSIX signals")
def test_edge_close_signals_first_and_returns_at_once(home, tmp_path):
    marker = tmp_path / "TERM"
    script = tmp_path / "term.py"
    script.write_text(_TERM.format(marker=str(marker)))
    client = C.McpClient(_pinned("term", script))
    started = time.monotonic()
    client.close()
    assert time.monotonic() - started < 2.5
    assert marker.read_text() == "term"


# -- L-M: inline code through Python's own modules -----------------------------------------


@pytest.mark.parametrize("line", [
    "python3 -m timeit -n1 -s import\\ os pass",
    "python3 /usr/lib/python3.11/timeit.py -n1 -s x pass",
    "python3 /usr/local/lib/python3.12/pdb.py -c c /srv/s.py",
    "python3 -m pdb -c !x -c c /srv/s.py",
    "/usr/bin/python3 -m http.server -b 0.0.0.0 -d / 8765",
    "/usr/bin/python3 -m pydoc -n 0.0.0.0 -p 8766",
    "/usr/bin/python3 -m webbrowser http://example.invalid/",
    "/usr/bin/python3 -m tarfile -e /abs/x.tar /home/u",
    "/usr/bin/python3 -m pickle /abs/x.pickle",
    "/usr/bin/python3 -m cProfile -m timeit pass",
    "/usr/bin/python3 -m unittest discover -s /abs/dir",
    "python3 -m mcp",
    "python3 -m my_module",
    "node --experimental-config-file /abs/cfg.json /abs/s.js",
    "node --experimental-config-file=/abs/cfg.json /abs/s.js",
    "node --experimental-default-config-file /abs/s.js",
    "node --experimental-sea-config /abs/sea.json",
])
def test_sad_inline_code_or_a_stdlib_tool_is_no_pure_launcher(line):
    assert not R.host_launcher(line.split())
    assert C.McpServerConfig(name="x", command=tuple(line.split())).host_run_problem()


@pytest.mark.parametrize("line", [
    "python3 -m mcp_server_git --repository /r", "python3 -m mcp_server_time",
    "python3 -u -m mcp_server_fetch", "python3 -m tools_mcp", "python3 -m my_mcp_server",
    "python3 /usr/lib/python3/dist-packages/srv/server.py", "python3 /srv/server.py",
    "node --no-warnings /srv/s.js",
])
def test_happy_mcp_server_packages_and_scripts_stay_pure_launchers(line):
    assert R.host_launcher(line.split())


# -- L: environment variables that load code ----------------------------------------------


@pytest.mark.parametrize("name", [
    "HOME", "PYTHONPYCACHEPREFIX", "PYTHONPLATLIBDIR", "BASH_FUNC_cut%%", "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_PARAMETERS", "GIT_SSH_COMMAND",
    "GIT_EXEC_PATH", "GIT_DIR", "XDG_CONFIG_HOME", "OPENSSL_CONF", "OPENSSL_MODULES", "PAGER",
    "PERLIO", "git_ssh_command",
])
def test_sad_an_environment_that_loads_code_needs_trusted(name):
    config = C.McpServerConfig(name="x", command=("/usr/bin/python3", "/srv/s.py"),
                               env={name: "/x"})
    assert name in R.code_env(config.env)
    assert "loads code" in config.host_run_problem()
    config.trusted = True
    assert config.host_run_problem() == ""


@pytest.mark.parametrize("name", ["LANG", "TZ", "LOG_LEVEL", "NODE_EXTRA_CA_CERTS"])
def test_happy_a_plain_environment_stays_a_pure_launcher(name):
    assert R.code_env({name: "x"}) == []


# -- L: a venv-shaped launcher ------------------------------------------------------------


def _venv(folder: Path) -> Path:
    (folder / "bin").mkdir(parents=True)
    (folder / "pyvenv.cfg").write_text("home = /usr/bin\n")
    site = folder / "lib" / "python3.11" / "site-packages"
    site.mkdir(parents=True)
    (site / "zz.pth").write_text("import os\n")
    python = folder / "bin" / "python3"
    python.symlink_to(PYTHON)
    return python


def test_sad_a_venv_interpreter_is_no_installed_launcher(tmp_path):
    python = _venv(tmp_path / "clone" / ".venv")
    (tmp_path / "clone" / ".venv").chmod(0o777)  # not root's alone (also when run as root)
    problem = R.launcher_place_problem(str(python))
    assert "virtual environment" in problem
    assert "virtual environment" in R.launcher_place_problem("python3", str(python.parent))
    config = C.McpServerConfig(name="x", command=(str(python), "/srv/s.py"))
    assert "virtual environment" in config.host_run_problem()
    config.trusted = True
    assert config.host_run_problem() == ""


def test_happy_a_version_managers_venv_counts_as_installed(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    python = _venv(home / ".pyenv" / "versions" / "srv-env")
    assert "virtual environment" not in R.launcher_place_problem(str(python))
