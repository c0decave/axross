"""The official MCP Python SDK's client talks to axross's server.

Over stdio (the SDK starts ``main.py --mcp-server``) and over HTTP (its
streamable-HTTP client against ``core.mcp_http``), in the SDK's two connect
modes: ``auto`` (it probes ``server/discover`` of the 2026-07-28 revision
first, which axross does not speak, and falls back to initialize) and
``legacy`` (initialize at once). Both end in MCP 2025-11-25; the SDK checks
our structuredContent against our outputSchema, reads the annotations, and
gets a refused argument back as a tool error.

The SDK is not a dependency of axross (nor in its lock): the test runs the
client under ``$AXROSS_MCP_SDK_PYTHON`` - a Python with ``mcp`` 2.x
installed, e.g. ``uv venv /tmp/mcpsdk && uv pip install --python
/tmp/mcpsdk/bin/python 'mcp==2.3.0'`` - or under this interpreter when it
has the SDK, and is skipped otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from core import mcp_http
from core.local_fs import LocalFS

ROOT = Path(__file__).resolve().parents[1]
_TOKEN = "sdk-interop-token-0123456789abcdef"

CLIENT = r'''
import json, sys
import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
import httpx2

cfg = json.loads(sys.argv[1])


async def run(server, mode):
    out = {}
    async with Client(server, mode=mode) as client:
        out["version"] = client.protocol_version
        out["server"] = client.server_info.name if client.server_info else None
        tools = (await client.list_tools()).tools
        out["tools"] = sorted(t.name for t in tools)
        read = next(t for t in tools if t.name == "read_file")
        out["title"] = read.title
        out["annotations"] = read.annotations.model_dump(by_alias=True, exclude_none=True)
        result = await client.call_tool("read_file", {"path": cfg["file"], "encoding": "text"})
        out["text"] = result.structured_content["text"]
        out["stat"] = (await client.call_tool("stat", {"path": cfg["file"]})).structured_content
        out["bad_is_error"] = (await client.call_tool("stat", {"path": 5})).is_error
    return out


async def main():
    results = {}
    for mode in ("auto", "legacy"):
        if cfg["transport"] == "stdio":
            server = StdioServerParameters(command=cfg["command"][0], args=cfg["command"][1:],
                                           env=cfg["env"], cwd=cfg["cwd"])
        else:
            http = httpx2.AsyncClient(headers={"Authorization": "Bearer " + cfg["token"]})
            server = streamable_http_client(cfg["url"], http_client=http)
        results[mode] = await run(server, mode)
    print(json.dumps(results))


anyio.run(main)
'''


def _sdk_python() -> str | None:
    configured = os.environ.get("AXROSS_MCP_SDK_PYTHON")
    if configured:
        return configured if Path(configured).is_file() else None
    if importlib.util.find_spec("mcp") is not None:
        try:
            from mcp.client import Client  # noqa: F401
        except ImportError:
            return None
        return sys.executable
    return None


SDK = _sdk_python()
pytestmark = pytest.mark.skipif(
    SDK is None, reason="the MCP Python SDK 2.x is not installed (set AXROSS_MCP_SDK_PYTHON)")


def _run_client(tmp_path, cfg) -> dict:
    script = tmp_path / "sdk_client.py"
    script.write_text(CLIENT, encoding="utf-8")
    # -I: the client sees the SDK only, never this checkout.
    proc = subprocess.run([SDK, "-I", str(script), json.dumps(cfg)], capture_output=True,
                          text=True, timeout=180, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr[-4000:]
    return json.loads(proc.stdout.splitlines()[-1])


def _check(results, path):
    for mode, out in results.items():
        assert out["version"] == "2025-11-25", mode
        assert out["server"] == "axross-mcp"
        assert {"read_file", "stat", "metadata_read", "remote_profiles", "agent_run"} <= set(
            out["tools"]), mode
        assert out["title"] == "Read file"
        assert out["annotations"]["readOnlyHint"] is True
        assert out["annotations"]["openWorldHint"] is False
        assert out["text"] == "hello from the SDK\n"
        assert out["stat"]["name"] == path.name and out["stat"]["is_dir"] is False
        assert out["bad_is_error"] is True


@pytest.fixture
def data(tmp_path):
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "hello.txt").write_text("hello from the SDK\n", encoding="utf-8")
    return folder


def test_happy_the_sdk_client_over_stdio(tmp_path, data):
    home = tmp_path / "home"
    home.mkdir()
    cfg = {
        "transport": "stdio",
        "file": str(data / "hello.txt"),
        "command": [sys.executable, str(ROOT / "main.py"), "--mcp-server", "--mcp-root",
                    str(data), "--mcp-tools", "all"],
        "env": {"HOME": str(home), "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
                "XDG_CONFIG_HOME": str(home / ".config"),
                "XDG_STATE_HOME": str(home / ".state")},
        "cwd": str(ROOT),
    }
    _check(_run_client(tmp_path, cfg), data / "hello.txt")


def test_happy_the_sdk_client_over_http(tmp_path, data):
    from core import mcp_groups as G

    config = mcp_http.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                       root=str(data), auth_token=_TOKEN,
                                       tool_groups=frozenset(G.GROUPS))
    server = mcp_http.build_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cfg = {"transport": "http", "file": str(data / "hello.txt"), "token": _TOKEN,
               "url": f"http://127.0.0.1:{server.server_address[1]}/messages"}
        _check(_run_client(tmp_path, cfg), data / "hello.txt")
    finally:
        server.shutdown()
        server.server_close()
        forwarder = getattr(server, "_mcp_log_forwarder", None)
        if forwarder is not None:
            mcp_http._mcp._detach_log_forwarder(forwarder)
        thread.join(timeout=5)


NAMES_CLIENT = r'''
import json, sys
import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

cfg = json.loads(sys.argv[1])


async def main():
    server = StdioServerParameters(command=cfg["command"][0], args=cfg["command"][1:],
                                   env=cfg["env"], cwd=cfg["cwd"])
    out = {}
    async with Client(server, mode="legacy") as client:
        with anyio.fail_after(60):  # the SDK dropped such a response and waited forever
            listed = await client.call_tool("list_dir", {"path": cfg["folder"]})
            walked = await client.call_tool("walk", {"path": cfg["folder"]})
            entry = [e for e in json.loads(listed.content[0].text) if "_b64" in str(e)][0]
            read = await client.call_tool("read_file", {"path_b64": cfg["path_b64"]})
        out = {"entry": entry, "walk_error": walked.is_error,
               "read": read.structured_content}
    print(json.dumps(out))


anyio.run(main)
'''


@pytest.mark.skipif(sys.platform == "darwin", reason="APFS refuses names that are not UTF-8")
def test_sad_a_name_that_is_not_utf8_does_not_hang_the_sdk_client(tmp_path, data):
    import base64

    raw = os.fsencode(data) + b"/bad\xff.txt"
    with open(raw, "wb") as fh:
        fh.write(b"named in latin-1")
    home = tmp_path / "home"
    home.mkdir()
    cfg = {
        "command": [sys.executable, str(ROOT / "main.py"), "--mcp-server", "--mcp-root",
                    str(data)],
        "env": {"HOME": str(home), "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
                "XDG_CONFIG_HOME": str(home / ".config"), "XDG_STATE_HOME": str(home / ".state")},
        "cwd": str(ROOT),
        "folder": str(data),
        "path_b64": base64.b64encode(raw).decode(),
    }
    script = tmp_path / "names_client.py"
    script.write_text(NAMES_CLIENT, encoding="utf-8")
    proc = subprocess.run([SDK, "-I", str(script), json.dumps(cfg)], capture_output=True,
                          text=True, timeout=180, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr[-4000:]
    out = json.loads(proc.stdout.splitlines()[-1])
    assert out["entry"]["name"] == "bad\ufffd.txt"
    assert base64.b64decode(out["entry"]["name_b64"]) == b"bad\xff.txt"
    assert out["walk_error"] is False
    assert base64.b64decode(out["read"]["content_b64"]) == b"named in latin-1"

