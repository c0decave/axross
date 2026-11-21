"""The MCP server runs without PyQt6: ``axross --mcp-server`` and ``axross-headless-mcp``
(core.mcp_cli), stdio and HTTP, every tool group.

Each run is a child Python whose import system refuses PyQt6 (a meta-path
finder that raises ImportError and records the attempt): an import of Qt
anywhere on the MCP path - at import time of a module the server loads, or
while it starts, lists its tools or answers a call - fails here, and in the
"mcp-headless" CI job (.github/workflows/python-app.yml), which runs this
file in an environment without PyQt6 installed at all.

Startup and tools/list must not even try to import Qt; a tool call may try
(file_type asks Qt's MIME database first and falls back when it is not
there) but must answer.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcp_names as N  # noqa: E402  (pure Python: no Qt)

#: Prepended to every child: blocks PyQt6 and reports what tried to import it.
BLOCK_QT = r'''
import atexit, sys
_tried = []
class _NoQt:
    def find_spec(self, name, path=None, target=None):
        if name == "PyQt6" or name.startswith("PyQt6."):
            _tried.append((name, len(_tried)))
            raise ImportError(f"PyQt6 is blocked on the MCP path: {name}")
        return None
sys.meta_path.insert(0, _NoQt())
for _name in [m for m in sys.modules if m == "PyQt6" or m.startswith("PyQt6.")]:
    del sys.modules[_name]
def _report():
    sys.stderr.write("QT-TRIED=" + ",".join(sorted({n for n, _ in _tried})) + "\n")
    sys.stderr.flush()
atexit.register(_report)
sys.path.insert(0, ROOT)
'''

#: The two commands: axross's (main.py) and axross-headless-mcp's (core.mcp_cli).
ENTRIES = {
    "axross": "sys.argv = ['axross', *ARGS]\nimport main\nsys.exit(main.main())\n",
    "axross-headless-mcp": "sys.argv = ['axross-headless-mcp', *ARGS]\nfrom core.mcp_cli import main\n"
                  "sys.exit(main())\n",
}
GROUP_TOOLS = {"metadata_read", "duplicates_scan", "pack_formats", "archive_list", "encrypt",
               "index_build", "file_type", "transfer_copy", "remote_profiles",
               "remote_exec", "agent_run", "extensions_list", "list_backends"}


def _code(entry: str, args: list[str]) -> str:
    return (BLOCK_QT.replace("sys.path.insert(0, ROOT)", f"sys.path.insert(0, {str(ROOT)!r})")
            + f"ARGS = {args!r}\n" + ENTRIES[entry])


def _env(home: Path, **extra) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("AXROSS_") and k not in ("DISPLAY", "WAYLAND_DISPLAY",
                                                        "QT_QPA_PLATFORM")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_DATA_HOME=str(home / ".local" / "share"),
               XDG_STATE_HOME=str(home / ".local" / "state"), XDG_CACHE_HOME=str(home / ".cache"),
               PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring", **extra)
    return env


def _qt_tried(stderr: str) -> list[str]:
    lines = [line for line in stderr.splitlines() if line.startswith("QT-TRIED=")]
    assert lines, f"the child did not report: {stderr[-3000:]}"
    return [n for n in lines[-1][len("QT-TRIED="):].split(",") if n]


@pytest.fixture
def data(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "notes.txt").write_text("no Qt here\n", encoding="utf-8")
    (folder / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"\0" * 64)
    return folder


def _stdio(tmp_path, entry, args, requests):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, "-c", _code(entry, args)],
        input="".join(json.dumps(r) + "\n" for r in requests), capture_output=True, text=True,
        timeout=180, env=_env(home), cwd=tmp_path)
    replies = {}
    for line in proc.stdout.splitlines():
        message = json.loads(line)
        if "id" in message:
            replies[message["id"]] = message
    return proc, replies


def _initialize(version="2025-11-25"):
    return [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": version, "capabilities": {},
                        "clientInfo": {"name": "no-qt", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]


@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_happy_start_and_tools_list_of_every_group_never_touch_qt(tmp_path, data, entry):
    args = ["--mcp-root", str(data), "--mcp-tools", "all", "--mcp-write", "--mcp-allow-exec"]
    if entry == "axross":
        args.insert(0, "--mcp-server")
    proc, replies = _stdio(tmp_path, entry, args, _initialize())
    assert replies[1]["result"]["protocolVersion"] == "2025-11-25", proc.stderr[-3000:]
    names = {N.internal(t["name"]) for t in replies[2]["result"]["tools"]}
    assert GROUP_TOOLS <= names, GROUP_TOOLS - names
    assert _qt_tried(proc.stderr) == []


@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_happy_the_manifest_of_every_group_never_touches_qt(tmp_path, entry):
    home = tmp_path / "home"
    home.mkdir()
    proc = subprocess.run(
        [sys.executable, "-c", _code(entry, ["--mcp-list-tools", "--mcp-tools", "all"])],
        capture_output=True, text=True, timeout=180, env=_env(home), cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert {"read_file", "remote_profiles", "agent_run"} <= {
        N.internal(t["name"]) for t in json.loads(proc.stdout)["tools"]}
    assert _qt_tried(proc.stderr) == []


def test_happy_tool_calls_of_the_groups_answer_without_qt(tmp_path, data):
    calls = [
        ("read_file", {"path": str(data / "notes.txt"), "encoding": "text"}),
        ("list_dir", {"path": str(data)}),
        ("grep", {"path": str(data), "pattern": "Qt"}),
        ("checksum", {"path": str(data / "notes.txt")}),
        ("file_type", {"path": str(data / "photo.jpg")}),
        ("metadata_read", {"path": str(data / "notes.txt")}),
        ("pack_formats", {}),
        ("remote_profiles", {}),
        ("extensions_list", {}),
        ("list_backends", {}),
        ("duplicates_scans", {}),
    ]
    requests = _initialize() + [
        {"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
         "params": {"name": name, "arguments": args}} for i, (name, args) in enumerate(calls)]
    proc, replies = _stdio(tmp_path, "axross-headless-mcp",
                           ["--mcp-root", str(data), "--mcp-tools", "all"], requests)
    for i, (name, _args) in enumerate(calls):
        reply = replies.get(10 + i)
        assert reply is not None, (name, proc.stderr[-3000:])
        assert "error" not in reply and reply["result"]["isError"] is False, (name, reply)
    assert "no Qt here" in replies[10]["result"]["content"][0]["text"]
    assert "Traceback" not in proc.stderr
    # Tried, refused, answered anyway: only the lookups that fall back.
    assert set(_qt_tried(proc.stderr)) <= {"PyQt6", "PyQt6.QtCore"}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_happy_http_without_qt(tmp_path, data):
    home = tmp_path / "home"
    home.mkdir()
    port, token = _free_port(), "no-qt-token-0123456789abcdef"
    proc = subprocess.Popen(
        [sys.executable, "-c", _code("axross-headless-mcp", ["--mcp-http", f"127.0.0.1:{port}",
                                                    "--mcp-root", str(data), "--mcp-tools",
                                                    "all"])],
        env=_env(home, AXROSS_MCP_HTTP_TOKEN=token), cwd=tmp_path, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)
    url = f"http://127.0.0.1:{port}/messages"

    def post(body, session=None):
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
        if session:
            headers.update({"Mcp-Session-Id": session, "MCP-Protocol-Version": "2025-11-25"})
        request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.headers.get("Mcp-Session-Id"), json.loads(raw) if raw else None

    try:
        deadline = time.time() + 90
        while True:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2).read()
                break
            except (OSError, urllib.error.URLError):
                assert proc.poll() is None, proc.communicate()[1][-3000:]
                assert time.time() < deadline, "the HTTP server did not come up"
                time.sleep(0.2)
        initialize, _initialized, listing = _initialize()
        session, init = post(initialize)
        assert init["result"]["protocolVersion"] == "2025-11-25"
        post(_initialized, session)
        _, tools = post(listing, session)
        assert {"read_file", "metadata_read", "agent_run"} <= {
            N.internal(t["name"]) for t in tools["result"]["tools"]}
        _, read = post({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "read_file", "arguments": {
                            "path": str(data / "notes.txt"), "encoding": "text"}}}, session)
        assert read["result"]["structuredContent"]["text"] == "no Qt here\n"
    finally:
        proc.terminate()
        try:
            _out, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            _out, err = proc.communicate()
    assert "Traceback" not in err and "PyQt6 is blocked" not in err
