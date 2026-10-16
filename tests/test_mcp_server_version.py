"""The MCP server reports axross's version, not a number typed in once.

Measured on a headless ``axross --mcp-server``: initialize answered
serverInfo {"name": "axross-mcp", "version": "0.1.0"} while the package
was 0.10.45. core/mcp_server.py carried SERVER_VERSION = "0.1.0", and
/health over HTTP reads the same constant. It is derived from
axross/_version.py now.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from axross._version import __version__  # noqa: E402
from core import mcp_server as M  # noqa: E402


def test_happy_the_constant_is_the_package_version():
    assert M.SERVER_VERSION == __version__


def test_happy_a_headless_server_reports_the_package_version(tmp_path):
    """``axross --mcp-server`` over stdio, as an LLM client starts it: no
    display, no Qt - initialize and tools/list answer, PyQt6 stays out."""
    import os
    import subprocess

    probe = (
        "import atexit, runpy, sys;"
        "atexit.register(lambda: sys.stderr.write('QT=%s\\n' % any(m.startswith('PyQt6') for m in sys.modules)));"
        "sys.argv = ['axross', '--mcp-server'];"
        "runpy.run_module('axross', run_name='__main__')"
    )
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY", "QT_QPA_PLATFORM")}
    env["HOME"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        input="".join(json.dumps(m) + "\n" for m in lines),
        capture_output=True, text=True, timeout=60, env=env,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    replies = {m.get("id"): m for m in map(json.loads, proc.stdout.splitlines())}
    assert replies[1]["result"]["serverInfo"] == {"name": "axross-mcp", "version": __version__}
    assert "list_dir" in [t["name"] for t in replies[2]["result"]["tools"]]
    assert "QT=False" in proc.stderr


def test_sad_the_version_is_not_the_old_placeholder():
    assert M.SERVER_VERSION != "0.1.0"


def test_edge_the_version_is_dotted_numbers():
    assert all(part.isdigit() for part in M.SERVER_VERSION.split(".")) and json.dumps(M.SERVER_VERSION)
