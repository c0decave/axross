"""A tool that ran and failed answers a result flagged ``isError``.

Review round 6 (F4): in ``--mcp-server`` mode a failing tool (a missing
file, an existing folder, a refused path) answered the JSON-RPC error
-32603. The MCP specification puts tool execution errors into the RESULT
(``{"content": [...], "isError": true}``) so the model sees them; a
JSON-RPC error is for the protocol. Bad arguments stay -32602, an unknown
tool -32601.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent


def _call(tools, name, args):
    return M._handle_request(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": name, "arguments": args}},
        tools, cancels=M._CancelRegistry())


def _tools(root):
    return M._build_tools(LocalFS(), allow_write=True, root=str(root))


def test_happy_a_missing_file_is_a_result_flagged_iserror(tmp_path):
    resp = _call(_tools(tmp_path), "read_file", {"path": str(tmp_path / "missing.txt")})
    assert "error" not in resp
    result = resp["result"]
    assert result["isError"] is True
    assert result["content"][0]["type"] == "text"
    assert "missing.txt" in result["content"][0]["text"]
    assert result["_meta"]["type"] in ("FileNotFoundError", "OSError")


def test_sad_bad_arguments_stay_32602_and_an_unknown_tool_32601(tmp_path):
    tools = _tools(tmp_path)
    assert _call(tools, "read_file", {"path": 5})["error"]["code"] == M.ERR_INVALID_PARAMS
    assert _call(tools, "no_such_tool", {})["error"]["code"] == M.ERR_METHOD_NOT_FOUND


def test_edge_a_root_escape_is_a_result_too(tmp_path):
    (tmp_path / "root").mkdir()
    resp = _call(_tools(tmp_path / "root"), "read_file", {"path": str(tmp_path / "x")})
    assert resp["result"]["isError"] is True
    assert resp["result"]["_meta"]["type"] == "PermissionError"


def test_happy_the_stdio_server_answers_iserror(tmp_path):
    root = tmp_path / "w"
    root.mkdir()
    home = tmp_path / "h"
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_DATA_HOME=str(home / ".local/share"), XDG_CACHE_HOME=str(home / ".cache"),
               XDG_STATE_HOME=str(home / ".local/state"))
    proc = subprocess.Popen(
        [sys.executable, str(_ROOT / "main.py"), "--mcp-server", "--mcp-root", str(root),
         "--mcp-write"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env, text=True)
    try:
        def call(i, method, params):
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method,
                                         "params": params}) + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "t", "version": "1"}})
        resp = call(2, "tools/call", {"name": "mkdir", "arguments": {"path": str(root)}})
        assert resp["result"]["isError"] is True, resp
    finally:
        proc.stdin.close()
        proc.wait(20)
