"""The MCP server speaks 2025-11-25, 2025-06-18 and 2024-11-05.

initialize answers the client's revision when it is one of them and the
newest otherwise; each session is then answered in its revision's shape:
tool annotations (2025-03-26 on), tool ``title``, ``outputSchema`` and
``structuredContent`` (2025-06-18 on), arguments a tool refuses as a tool
error the model reads (2025-11-25), the ``MCP-Protocol-Version`` header on
HTTP (2025-06-18 on), no JSON-RPC batches. A 2024-11-05 session sees what
it always saw.
"""

from __future__ import annotations

import base64
import http.client
import io
import json
import re
import threading

import pytest

from core import mcp_groups as G
from core import mcp_http
from core import mcp_server as M
from core.local_fs import LocalFS

jsonschema = pytest.importorskip("jsonschema")

NEW = "2025-11-25"
JUNE = "2025-06-18"
OLD = "2024-11-05"


def _all_tools(root):
    return M._build_tools(LocalFS(), allow_write=True, root=str(root), allow_scripts=True,
                          tool_groups=frozenset(G.GROUPS), allow_exec=True)


def _session(tools, version):
    state = M.ProtocolState()
    reply = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": version}}, tools, protocol=state)
    return state, reply["result"]


def _call(tools, state, name, args, req_id=7):
    return M._handle_request({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                              "params": {"name": name, "arguments": args}}, tools, protocol=state)


# --- negotiation ------------------------------------------------------------------


@pytest.mark.parametrize("version", M.SUPPORTED_PROTOCOL_VERSIONS)
def test_happy_a_supported_revision_is_answered_as_asked(tmp_path, version):
    state, result = _session(_all_tools(tmp_path), version)
    assert result["protocolVersion"] == version == state.version


@pytest.mark.parametrize("asked", ["2025-03-26", "2099-01-01", "", None, 20250618])
def test_sad_any_other_revision_gets_the_newest(tmp_path, asked):
    _state, result = _session(_all_tools(tmp_path), asked)
    assert result["protocolVersion"] == NEW == M.PROTOCOL_VERSION


def test_edge_the_supported_list_is_newest_first_and_keeps_2024():
    assert M.SUPPORTED_PROTOCOL_VERSIONS == (NEW, JUNE, OLD)
    assert M.protocol_at_least(NEW, JUNE) and M.protocol_at_least(JUNE, "2025-03-26")
    assert not M.protocol_at_least(OLD, "2025-03-26") and not M.protocol_at_least(None, OLD)
    assert not M.protocol_at_least("2099-01-01", OLD)


def test_happy_server_info_grows_with_the_revision(tmp_path):
    tools = _all_tools(tmp_path)
    assert _session(tools, OLD)[1]["serverInfo"] == {"name": "axross-mcp",
                                                     "version": M.SERVER_VERSION}
    assert _session(tools, JUNE)[1]["serverInfo"]["title"] == "axross"
    info = _session(tools, NEW)[1]["serverInfo"]
    # Round 5: the website is the headless server's own repository (as server.json).
    assert info["websiteUrl"] == "https://github.com/c0decave/axross-headless-mcp" and info["description"]


# --- tools/list -------------------------------------------------------------------


def test_happy_a_2024_session_lists_tools_as_before(tmp_path):
    tools = _all_tools(tmp_path)
    state, _ = _session(tools, OLD)
    listing = M._handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, tools,
                                protocol=state)["result"]["tools"]
    assert all(set(t) == {"name", "description", "inputSchema"} for t in listing)


def test_happy_a_new_session_gets_titles_annotations_and_output_schemas(tmp_path):
    tools = _all_tools(tmp_path)
    state, _ = _session(tools, NEW)
    listing = {t["name"]: t for t in M._handle_request(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, tools, protocol=state
    )["result"]["tools"]}
    assert listing["read_file"]["title"] == "Read file"
    assert listing["read_file"]["annotations"] == {
        "title": "Read file", "readOnlyHint": True, "destructiveHint": False,
        "idempotentHint": True, "openWorldHint": False}
    assert listing["remove"]["annotations"]["destructiveHint"] is True
    assert listing["remote_exec"]["annotations"]["openWorldHint"] is True
    assert set(listing["stat"]["outputSchema"]["required"]) == {"name", "is_dir", "size",
                                                                "modified"}
    assert "outputSchema" not in listing["list_dir"]  # a list, not an object


def test_happy_every_tool_has_true_hints(tmp_path):
    for tool in _all_tools(tmp_path):
        assert tool.name in M._TOOL_HINTS, f"{tool.name}: classify it in _TOOL_HINTS"
        hints = tool.annotations
        assert set(hints) == {"title", "readOnlyHint", "destructiveHint", "idempotentHint",
                              "openWorldHint"}
        assert all(isinstance(hints[k], bool) for k in hints if k != "title")
        if tool.write:  # gated behind --mcp-write / scripts / exec: it changes things
            assert hints["readOnlyHint"] is False, tool.name
        if hints["readOnlyHint"]:
            assert hints["destructiveHint"] is False, tool.name
    # preview is served only where an image decoder (Qt or Pillow) exists.
    assert set(M._TOOL_HINTS) - {t.name for t in _all_tools(tmp_path)} <= {"preview"}, \
        "stale entries"


def test_edge_tool_names_follow_the_2025_11_25_rules(tmp_path):
    for tool in _all_tools(tmp_path):
        assert re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", tool.name), tool.name


def test_edge_output_schemas_are_object_schemas(tmp_path):
    for tool in _all_tools(tmp_path):
        if tool.output_schema is not None:
            jsonschema.validators.validator_for(tool.output_schema).check_schema(
                tool.output_schema)
            assert tool.output_schema["type"] == "object", tool.name


# --- tools/call -------------------------------------------------------------------


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "a.txt").write_bytes("héllo wörld\n".encode())
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.bin").write_bytes(bytes(range(256)) * 40)
    return tmp_path


@pytest.mark.parametrize(("name", "args"), [
    ("stat", {"path": "a.txt"}),
    ("stat", {"path": "sub"}),
    ("read_file", {"path": "a.txt"}),
    ("read_file", {"path": "a.txt", "encoding": "text"}),
    ("read_file", {"path": "a.txt", "encoding": "text", "offset": 2, "max_bytes": 3}),
    ("read_file", {"path": "sub/b.bin", "max_bytes": 10}),
    ("checksum", {"path": "a.txt"}),
    ("checksum", {"path": "sub/b.bin", "algorithm": "md5"}),
    ("walk", {"path": "."}),
    ("walk", {"path": ".", "max_entries": 1}),
])
def test_happy_structured_results_match_their_output_schema(tree, name, args):
    tools = _all_tools(tree)
    state, _ = _session(tools, JUNE)
    args = {k: (str(tree / v) if k == "path" else v) for k, v in args.items()}
    result = _call(tools, state, name, args)["result"]
    assert result["isError"] is False, result
    tool = next(t for t in tools if t.name == name)
    jsonschema.validate(result["structuredContent"], tool.output_schema)
    assert result["structuredContent"] == json.loads(result["content"][0]["text"])


def test_happy_structured_content_only_for_objects_and_new_sessions(tree):
    tools = _all_tools(tree)
    old, _ = _session(tools, OLD)
    assert "structuredContent" not in _call(tools, old, "stat", {"path": str(tree / "a.txt")})[
        "result"]
    new, _ = _session(tools, NEW)
    listed = _call(tools, new, "list_dir", {"path": str(tree)})["result"]
    assert "structuredContent" not in listed and json.loads(listed["content"][0]["text"])
    read = _call(tools, new, "read_file", {"path": str(tree / "a.txt")})["result"]
    assert base64.b64decode(read["structuredContent"]["content_b64"]) == "héllo wörld\n".encode()


def test_sad_refused_arguments_are_a_tool_error_from_2025_11_25(tree):
    tools = _all_tools(tree)
    new, _ = _session(tools, NEW)
    bad_schema = _call(tools, new, "stat", {"path": 5})
    assert bad_schema["result"]["isError"] is True and "error" not in bad_schema
    assert "failed schema" in bad_schema["result"]["content"][0]["text"]
    bad_value = _call(tools, new, "read_file", {"path": str(tree / "a.txt"), "encoding": "rot13"})
    assert bad_value["result"]["isError"] is True
    # Older sessions keep the JSON-RPC error they always got.
    june, _ = _session(tools, JUNE)
    assert _call(tools, june, "stat", {"path": 5})["error"]["code"] == M.ERR_INVALID_PARAMS
    # An unknown tool stays a protocol error (-32602, as MCP names it).
    assert _call(tools, new, "no_such_tool", {})["error"]["code"] == M.ERR_INVALID_PARAMS


# --- stdio ------------------------------------------------------------------------


def _serve(tmp_path, lines):
    out = io.StringIO()
    M.serve(M.ServerConfig(backend=LocalFS(), root=str(tmp_path), rate_limit_enabled=False,
                           stdin=io.StringIO("".join(json.dumps(x) + "\n" for x in lines)),
                           stdout=out))
    return [json.loads(line) for line in out.getvalue().splitlines()
            if "id" in json.loads(line)]


def test_happy_stdio_keeps_the_revision_of_its_initialize(tmp_path):
    replies = _serve(tmp_path, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": JUNE}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ])
    assert replies[0]["result"]["protocolVersion"] == JUNE
    assert all("title" in t and "annotations" in t for t in replies[1]["result"]["tools"])


def test_sad_stdio_refuses_a_batch(tmp_path):
    replies = _serve(tmp_path, [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": JUNE}},
        [{"jsonrpc": "2.0", "id": 2, "method": "ping"}, {"jsonrpc": "2.0", "id": 3,
                                                          "method": "ping"}],
        {"jsonrpc": "2.0", "id": 4, "method": "ping"},
    ])
    assert replies[1]["error"]["code"] == M.ERR_INVALID_REQUEST
    assert "batch" in replies[1]["error"]["message"] and replies[2]["result"] == {}


# --- HTTP -------------------------------------------------------------------------

_TOKEN = "revision-test-token-0123456789"


@pytest.fixture
def http_server(tmp_path):
    config = mcp_http.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                       root=str(tmp_path), auth_token=_TOKEN)
    server = mcp_http.build_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()
    forwarder = getattr(server, "_mcp_log_forwarder", None)
    if forwarder is not None:
        mcp_http._mcp._detach_log_forwarder(forwarder)
    thread.join(timeout=5)


def _http(port, method, body=None, **headers):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    hdrs = {"Content-Type": "application/json", "Authorization": f"Bearer {_TOKEN}"}
    hdrs.update({k.replace("_", "-"): v for k, v in headers.items()})
    conn.request(method, "/messages", body=None if body is None else json.dumps(body),
                 headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, resp.getheader("Mcp-Session-Id"), (json.loads(raw) if raw else None)


def _http_session(port, version):
    status, sid, body = _http(port, "POST", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                             "params": {"protocolVersion": version}})
    assert status == 200 and body["result"]["protocolVersion"] == version
    return sid


def test_happy_http_answers_requests_that_name_the_agreed_revision(http_server):
    sid = _http_session(http_server, NEW)
    status, _, _ = _http(http_server, "POST", {"jsonrpc": "2.0", "method":
                                               "notifications/initialized"},
                         Mcp_Session_Id=sid, MCP_Protocol_Version=NEW)
    assert status == 202
    status, _, body = _http(http_server, "POST", {"jsonrpc": "2.0", "id": 2,
                                                  "method": "tools/list"},
                            Mcp_Session_Id=sid, MCP_Protocol_Version=NEW)
    assert status == 200 and body["result"]["tools"][0]["annotations"]
    # Without the header the session's revision applies.
    status, _, body = _http(http_server, "POST", {"jsonrpc": "2.0", "id": 3, "method": "ping"},
                            Mcp_Session_Id=sid)
    assert status == 200 and body["result"] == {}


@pytest.mark.parametrize("claimed", ["2099-01-01", "2025-03-26", JUNE, "  "])
def test_sad_http_refuses_another_or_unknown_revision(http_server, claimed):
    sid = _http_session(http_server, NEW)
    status, _, body = _http(http_server, "POST", {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                            Mcp_Session_Id=sid, MCP_Protocol_Version=claimed)
    assert status == 400 and "MCP-Protocol-Version" in body["error"]
    # GET (the SSE stream) and DELETE check it as well.
    status, _, _ = _http(http_server, "GET", Mcp_Session_Id=sid, MCP_Protocol_Version=claimed,
                         Accept="text/event-stream")
    assert status == 400
    status, _, _ = _http(http_server, "DELETE", Mcp_Session_Id=sid, MCP_Protocol_Version=claimed)
    assert status == 400
    status, _, _ = _http(http_server, "DELETE", Mcp_Session_Id=sid, MCP_Protocol_Version=NEW)
    assert status == 204


def test_sad_http_refuses_a_batch(http_server):
    sid = _http_session(http_server, JUNE)
    status, _, body = _http(http_server, "POST", [{"jsonrpc": "2.0", "id": 2, "method": "ping"}],
                            Mcp_Session_Id=sid, MCP_Protocol_Version=JUNE)
    assert status == 400 and "batch" in body["error"]


def test_edge_a_2024_http_session_needs_no_header(http_server):
    sid = _http_session(http_server, OLD)
    status, _, body = _http(http_server, "POST", {"jsonrpc": "2.0", "id": 2,
                                                  "method": "tools/list"}, Mcp_Session_Id=sid)
    assert status == 200 and set(body["result"]["tools"][0]) == {"name", "description",
                                                                 "inputSchema"}


def test_edge_the_header_constant_is_the_spec_name():
    assert mcp_http.PROTOCOL_VERSION_HEADER.lower() == "mcp-protocol-version"
