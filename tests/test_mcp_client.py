"""The MCP client: the agent's way to the tools of further MCP servers.

Checked against axross's own MCP server (stdio and Streamable HTTP) and
against small scripted servers for what axross's server never does:
pages of tools, server-sent events, a ping from the server, hanging,
dying, oversized tool lists.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from core import mcp_client as C

ROOT = Path(__file__).resolve().parent.parent

FAKE = textwrap.dedent("""
    import json, sys, time
    mode = sys.argv[1]
    def send(m):
        sys.stdout.write(json.dumps(m) + "\\n"); sys.stdout.flush()
    if mode == "die":
        sys.stderr.write("fatal: no config\\n"); sys.exit(3)
    for line in sys.stdin:
        m = json.loads(line)
        if "id" not in m:
            continue
        if mode == "hang":
            continue
        meth, i = m.get("method"), m["id"]
        if meth == "initialize":
            send({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2024-11-05",
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}})
        elif meth == "tools/list":
            if mode == "many":
                tools = [{"name": f"t{n}", "inputSchema": {"type": "object"}} for n in range(300)]
                send({"jsonrpc": "2.0", "id": i, "result": {"tools": tools}}); continue
            if mode == "odd":
                huge = {"type": "object", "properties": {"x": {"description": "y" * 70000}}}
                tools = [{"name": "big", "description": "d" * 5000, "inputSchema": huge},
                         {"name": "we/ird name", "inputSchema": {"type": "string"}},
                         {"name": "big"}, {"nope": 1}, "junk"]
                send({"jsonrpc": "2.0", "id": i, "result": {"tools": tools}}); continue
            cursor = (m.get("params") or {}).get("cursor")
            if cursor is None:
                send({"jsonrpc": "2.0", "id": i, "result": {"tools": [
                    {"name": "look", "inputSchema": {"type": "object"},
                     "annotations": {"readOnlyHint": True}}],
                    "nextCursor": "p2"}})
            else:
                send({"jsonrpc": "2.0", "id": i, "result": {"tools": [
                    {"name": "change", "inputSchema": {"type": "object"}}]}})
        elif meth == "tools/call":
            name = m["params"]["name"]
            if mode == "ping":
                send({"jsonrpc": "2.0", "id": "srv-1", "method": "ping"})
                pong = json.loads(sys.stdin.readline())
                ok = pong.get("id") == "srv-1" and pong.get("result") == {}
                send({"jsonrpc": "2.0", "id": i,
                      "result": {"content": [{"type": "text", "text": f"pong {ok}"}]}})
            elif name == "change":
                send({"jsonrpc": "2.0", "id": i, "result": {"isError": True,
                      "content": [{"type": "text", "text": "disk full"}]}})
            else:
                send({"jsonrpc": "2.0", "id": i, "result": {"content": [
                    {"type": "text", "text": json.dumps(m["params"]["arguments"])},
                    {"type": "image", "data": "x"}]}})
""")


@pytest.fixture
def fake_server(tmp_path):
    script = tmp_path / "fake_mcp.py"
    script.write_text(FAKE)

    def config(mode="normal", **kw):
        return C.McpServerConfig(name="fake", command=(sys.executable, str(script), mode), **kw)

    return config


def _own_stdio(root, **kw):
    env = {k: os.environ[k] for k in ("PYTHONUSERBASE",) if k in os.environ}
    env.update(PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring", QT_QPA_PLATFORM="offscreen")
    return C.McpServerConfig(
        name="own",
        command=(sys.executable, str(ROOT / "main.py"), "--mcp-server", "--mcp-root", str(root)),
        env=env,
        timeout=60,
        **kw,
    )


class _HttpOwn:
    def __init__(self, root):
        from core import mcp_http
        from core.local_fs import LocalFS

        self._mcp_http = mcp_http
        self.server = mcp_http.build_server(
            mcp_http.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0, root=str(root))
        )
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/messages"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        fwd = getattr(self.server, "_mcp_log_forwarder", None)
        if fwd is not None:
            self._mcp_http._mcp._detach_log_forwarder(fwd)


class _Scripted:
    """An HTTP MCP server that answers from a function."""

    def __init__(self, answer):
        seen = self.seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                headers = {k.lower(): v for k, v in self.headers.items()}
                seen.append((headers, body))
                status, headers, data = answer(body, headers)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(data)

            def do_DELETE(self):  # noqa: N802
                seen.append(({k.lower(): v for k, v in self.headers.items()}, "DELETE"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/mcp"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _rpc(ident, result):
    return json.dumps({"jsonrpc": "2.0", "id": ident, "result": result}).encode()


# -- happy ---------------------------------------------------------------------


def test_happy_stdio_reaches_axross_own_server(tmp_path):
    (tmp_path / "a.txt").write_text("hello from a")
    client = C.McpClient(_own_stdio(tmp_path))
    try:
        tools = {t.name: t for t in client.tools()}
        assert "own__read_file" in tools and "own__list_dir" in tools
        outcome, text = tools["own__read_file"].call(
            {"path": str(tmp_path / "a.txt"), "encoding": "text"}
        )
    finally:
        client.close()
    assert outcome == "ok" and "hello from a" in text


def test_happy_http_reaches_axross_own_server(tmp_path):
    (tmp_path / "b.txt").write_text("hello from b")
    server = _HttpOwn(tmp_path)
    try:
        client = C.McpClient(
            C.McpServerConfig(name="web", transport="http", url=server.url, timeout=30),
            token=server.server.auth_token,
        )
        tools = {t.name: t for t in client.tools()}
        outcome, text = tools["web__read_file"].call(
            {"path": str(tmp_path / "b.txt"), "encoding": "text"}
        )
        client.close()
    finally:
        server.close()
    assert outcome == "ok" and "hello from b" in text


def test_happy_pages_of_tools_and_the_confirm_policy(fake_server):
    client = C.McpClient(fake_server(confirm="writes"))
    try:
        tools = {t.name: t for t in client.tools()}
    finally:
        client.close()
    assert set(tools) == {"fake__look", "fake__change"}
    assert tools["fake__look"].write is False and tools["fake__change"].write is True
    assert not tools["fake__look"].always_ask


def test_happy_a_call_returns_text_and_marks_binary_parts(fake_server):
    client = C.McpClient(fake_server())
    try:
        look = next(t for t in client.tools() if t.name == "fake__look")
        outcome, text = look.call({"q": 1})
    finally:
        client.close()
    assert outcome == "ok" and '{"q": 1}' in text and "[image result, not shown]" in text


def test_happy_http_answers_as_server_sent_events_and_keeps_the_session():
    def answer(body, headers):
        if "id" not in body:
            return 202, {}, b""
        if body["method"] == "initialize":
            return 200, {"Content-Type": "application/json", "Mcp-Session-Id": "s-42"}, _rpc(
                body["id"], {"protocolVersion": "2025-03-26", "capabilities": {}})
        events = (
            b"event: message\ndata: "
            + json.dumps(
                {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}
            ).encode()
            + b"\n\n"
            b"data: "
            + _rpc(body["id"], {"tools": [{"name": "sse", "inputSchema": {"type": "object"}}]})
            + b"\n\n"
        )
        return 200, {"Content-Type": "text/event-stream"}, events

    server = _Scripted(answer)
    try:
        client = C.McpClient(
            C.McpServerConfig(name="sse", transport="http", url=server.url, timeout=10)
        )
        assert [t.name for t in client.tools()] == ["sse__sse"]
        client.close()
    finally:
        server.close()
    later = [h for h, b in server.seen[1:]]
    assert len(later) == 3 and all(h.get("mcp-session-id") == "s-42" for h in later)
    assert "mcp-session-id" not in server.seen[0][0]
    assert server.seen[-1][1] == "DELETE"
    assert server.seen[2][0].get("mcp-protocol-version") == "2025-03-26"


def test_happy_the_server_may_ping_during_a_call(fake_server):
    client = C.McpClient(fake_server("ping", timeout=10))
    try:
        tool = client.tools()[0]
        assert tool.call({}) == ("ok", "pong True")
    finally:
        client.close()


# -- sad -----------------------------------------------------------------------


def test_sad_a_missing_program_is_a_clear_error():
    with pytest.raises(C.McpClientError, match="cannot start"):
        C.McpClient(C.McpServerConfig(name="x", command=("/nonexistent/mcp-server",)))


def test_sad_a_dying_server_reports_its_last_words(fake_server):
    with pytest.raises(C.McpClientError, match="no config"):
        C.McpClient(fake_server("die"))


def test_sad_a_silent_server_times_out(fake_server):
    started = time.monotonic()
    with pytest.raises(C.McpClientError, match="no answer within"):
        C.McpClient(fake_server("hang", timeout=1))
    assert time.monotonic() - started < 10


def test_sad_a_tool_error_is_an_error_outcome(fake_server):
    client = C.McpClient(fake_server())
    try:
        change = next(t for t in client.tools() if t.name == "fake__change")
        assert change.call({}) == ("error", "error: disk full")
    finally:
        client.close()


def test_sad_http_refusal_and_the_token(monkeypatch):
    def answer(body, headers):
        if headers.get("authorization") != "Bearer sekrit":
            return 401, {}, b"no"
        return (
            200,
            {"Content-Type": "application/json"},
            _rpc(body.get("id"), {"protocolVersion": "x"}),
        )

    server = _Scripted(answer)
    try:
        config = C.McpServerConfig(
            name="auth", transport="http", url=server.url, bearer=True, timeout=5
        )
        with pytest.raises(C.McpClientError, match="HTTP 401"):
            C.McpClient(config, token="wrong")
        C.McpClient(config, token="sekrit").close()
    finally:
        server.close()


def test_sad_broken_configs_are_refused():
    assert C.McpServerConfig(name="bad name!").problems()
    assert C.McpServerConfig(name="x", transport="http", url="ftp://h").problems()
    assert C.McpServerConfig(name="x", transport="stdio").problems()
    assert (
        C.McpServerConfig.from_dict({"name": "x", "transport": "stdio", "command": "rm -rf /"})
        is None
    )
    assert C.McpServerConfig.from_dict("junk") is None
    good = C.McpServerConfig(name="ok", command=("srv",), env={"A": "1"}, confirm="writes")
    assert C.McpServerConfig.from_dict(good.to_dict()) == good


# -- edge ----------------------------------------------------------------------


def test_edge_tool_lists_are_bounded(fake_server):
    client = C.McpClient(fake_server("many"))
    try:
        assert len(client.tools()) == C.MAX_TOOLS
    finally:
        client.close()


def test_edge_odd_tools_are_cleaned(fake_server):
    client = C.McpClient(fake_server("odd"))
    try:
        tools = client.tools()
    finally:
        client.close()
    names = [t.name for t in tools]
    assert names == ["fake__big", "fake__we_ird_name"]
    big = tools[0]
    assert len(big.description) <= C.MAX_DESCRIPTION + len("[fake] ")
    assert big.schema == {"type": "object", "properties": {}}  # over the size limit
    assert tools[1].schema == {"type": "object", "properties": {}}  # not an object schema
    assert all(len(n) <= C.MAX_NAME for n in names)


def test_edge_the_pool_reuses_and_reconnects(fake_server):
    pool = C.McpClientPool(token_lookup=lambda name: "")
    config = fake_server()
    try:
        first, errors = pool.tools([config])
        again, _ = pool.tools([config])
        assert errors == [] and first[0].client is again[0].client
        assert pool.always_ask("fake__look") and first[0].write is True  # read-only, but "always"
        changed = fake_server(timeout=30)
        third, _ = pool.tools([changed])
        assert third[0].client is not first[0].client
        broken, errors = pool.tools([C.McpServerConfig(name="gone", command=("/nonexistent/x",))])
        assert broken == [] and errors and errors[0].startswith("gone:")
        pool.keep_only([])
        assert not pool.always_ask("fake__look")
    finally:
        pool.close_all()


def test_edge_switching_a_server_to_always_reloads_its_tools(fake_server):
    pool = C.McpClientPool(token_lookup=lambda name: "")
    try:
        first, _ = pool.tools([fake_server(confirm="writes")])
        look = next(t for t in first if t.name == "fake__look")
        assert look.write is False and not pool.always_ask("fake__look")
        again, _ = pool.tools([fake_server(confirm="always")])
        look = next(t for t in again if t.name == "fake__look")
        assert look.write is True and pool.always_ask("fake__look")
    finally:
        pool.close_all()
