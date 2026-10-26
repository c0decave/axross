"""A changed token or secret value reaches the MCP server without a restart.

Found by the settings matrix (tests/test_settings_matrix_agent.py, the
secret mcp_server_token): Settings > Agent > MCP Servers, a new token typed
and saved, and the server still got the old one. The pool
(core.mcp_client.McpClientPool) kept a connected client while the server's
``signature()`` was unchanged - and the token (keyring) and the secret
environment values (keyring) are no part of it, so a client connected with
the old ones served every later task until axross restarted. A rotated
(revoked) token thus kept failing, and a corrected one was never used.

The pool now reconnects when the credentials it would connect with differ
from those of the held client (kept as a digest, never as text).
"""

from __future__ import annotations

import json
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mcp_client as C  # noqa: E402

SCRIPT = textwrap.dedent("""
    import json, os, sys
    def send(m):
        sys.stdout.write(json.dumps(m) + "\\n"); sys.stdout.flush()
    for line in sys.stdin:
        m = json.loads(line)
        if "id" not in m:
            continue
        if m.get("method") == "initialize":
            send({"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": "2024-11-05",
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "s", "version": "1"}}})
        else:
            send({"jsonrpc": "2.0", "id": m["id"], "result": {"tools": [
                {"name": "look", "description": os.environ.get("API_KEY", ""),
                 "inputSchema": {"type": "object"}}]}})
""")


class _Http:
    """An HTTP MCP endpoint that records the Authorization header of each request."""

    def __init__(self) -> None:
        self.auth: list = []
        auth = self.auth

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                auth.append(self.headers.get("Authorization"))
                if "id" not in body:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                result = ({"tools": [{"name": "look", "inputSchema": {"type": "object"}}]}
                          if body.get("method") == "tools/list" else
                          {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                           "serverInfo": {"name": "h", "version": "1"}})
                raw = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_DELETE(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def http():
    server = _Http()
    yield server
    server.close()


@pytest.fixture
def secrets(monkeypatch):
    values = {"API_KEY": "first"}
    monkeypatch.setattr(C, "get_secret", lambda name, var: values.get(var, ""))
    return values


def _http_config(http, **kw) -> C.McpServerConfig:
    return C.McpServerConfig(name="web", transport="http", url=http.url, bearer=True, **kw)


def _stdio_config(tmp_path) -> C.McpServerConfig:
    script = tmp_path / "server.py"
    script.write_text(SCRIPT)
    return C.McpServerConfig(name="prog", command=(sys.executable, str(script)),
                             secret_env=("API_KEY",), timeout=30)


# -- happy ---------------------------------------------------------------------------


def test_happy_a_new_token_is_sent_at_the_next_use(http) -> None:
    token = {"web": "old-token"}
    pool = C.McpClientPool(token_lookup=lambda name: token[name])
    try:
        tools, errors = pool.tools([_http_config(http)])
        assert [t.name for t in tools] == ["web__look"] and not errors
        assert http.auth[-1] == "Bearer old-token"
        token["web"] = "new-token"
        tools, errors = pool.tools([_http_config(http)])
        assert [t.name for t in tools] == ["web__look"] and not errors
        assert http.auth[-1] == "Bearer new-token"
    finally:
        pool.close_all()


def test_happy_a_new_secret_value_reaches_the_program(tmp_path, secrets) -> None:
    pool = C.McpClientPool()
    config = _stdio_config(tmp_path)
    try:
        assert pool.tools([config])[0][0].description.endswith(" first")
        secrets["API_KEY"] = "second"
        assert pool.tools([config])[0][0].description.endswith(" second")
    finally:
        pool.close_all()


# -- sad -----------------------------------------------------------------------------


def test_sad_a_removed_token_is_no_longer_sent(http) -> None:
    token = {"web": "old-token"}
    pool = C.McpClientPool(token_lookup=lambda name: token[name])
    try:
        pool.tools([_http_config(http)])
        token["web"] = ""
        pool.tools([_http_config(http)])
        assert http.auth[-1] is None
    finally:
        pool.close_all()


# -- edge ----------------------------------------------------------------------------


def test_edge_unchanged_credentials_keep_the_connection(http) -> None:
    pool = C.McpClientPool(token_lookup=lambda name: "same")
    try:
        pool.tools([_http_config(http)])
        held = pool._clients["web"][1]
        requests = len(http.auth)
        pool.tools([_http_config(http)])
        assert pool._clients["web"][1] is held and len(http.auth) == requests
    finally:
        pool.close_all()


def test_edge_no_credential_text_is_kept_in_the_pool(http) -> None:
    pool = C.McpClientPool(token_lookup=lambda name: "very-secret-token")
    try:
        pool.tools([_http_config(http)])
        held = pool._clients["web"]
        assert "very-secret-token" not in repr([held[0], *held[2:]])
    finally:
        pool.close_all()


def test_edge_keep_only_still_drops_a_changed_config(http) -> None:
    pool = C.McpClientPool(token_lookup=lambda name: "t")
    try:
        pool.tools([_http_config(http)])
        pool.keep_only([_http_config(http, timeout=5)])
        assert "web" not in pool._clients
    finally:
        pool.close_all()
