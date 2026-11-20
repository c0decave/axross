"""The headless MCP shows its logo: serverInfo carries ``icons`` from MCP
2025-11-25 on (clients such as VS Code show it), and server.json carries the
same icon for the official registry - checked against the registry's own
schema (tests/fixtures/mcp/server-schema-2025-12-11.json, from
modelcontextprotocol/registry internal/validators/schemas)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

jsonschema = pytest.importorskip("jsonschema")

SCHEMA = ROOT / "tests" / "fixtures" / "mcp" / "server-schema-2025-12-11.json"
LOGO = "https://raw.githubusercontent.com/c0decave/axross-headless-mcp/main/docs/assets/logo.png"


def _server_info(version: str) -> dict:
    tools = M._build_tools(LocalFS(), allow_write=False, root=None)
    reply = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": version}}, tools,
                              protocol=M.ProtocolState())
    return reply["result"]["serverInfo"]


def test_happy_a_2025_11_25_session_gets_the_logo():
    icons = _server_info("2025-11-25")["icons"]
    assert icons == [{"src": LOGO, "mimeType": "image/png", "sizes": ["400x400"]}]


@pytest.mark.parametrize("version", ["2025-06-18", "2024-11-05"])
def test_edge_older_revisions_get_no_icons(version):
    assert "icons" not in _server_info(version)


def test_happy_server_json_names_the_same_icon_and_passes_the_registry_schema():
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert server["$schema"] == schema["$id"]
    jsonschema.validate(server, schema)
    assert server["icons"] == [{"src": LOGO, "mimeType": "image/png", "sizes": ["400x400"]}]
