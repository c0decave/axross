"""A malformed MCP request gets an error answer; the server keeps serving.

Found by tests/test_fuzz_mcp.py:

* ``tools/call`` with ``params._meta`` that is not an object raised
  AttributeError (``meta.get``) and ``notifications/cancelled`` with a
  list ``requestId`` raised TypeError (an unhashable dict key) out of
  ``_dispatch``.
* A body that is valid JSON syntax but not decodable - invalid UTF-8,
  nesting deeper than the C stack (RecursionError), an integer above
  Python's digit limit (ValueError) - escaped ``json.loads``: only
  JSONDecodeError was caught.

On the stdio transport each of these ended ``serve()`` - one bad line
from the client killed the server; on the HTTP transport the handler
thread died and the client got no answer at all.
"""

from __future__ import annotations

import io
import json
import socket
import sys
import tempfile
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_http  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

_PING = b'{"jsonrpc":"2.0","id":7,"method":"ping"}'

_BAD_BODIES = {
    "invalid-utf8": b'{"jsonrpc":"2.0","id":1,"method":"\xff"}',
    "deep-array": b"[" * 200_000 + b"]" * 200_000,
    "deep-object": b'{"a":' * 100_000 + b"1" + b"}" * 100_000,
    "huge-int": b'{"jsonrpc":"2.0","id":1' + b"0" * 5000 + b',"method":"ping"}',
}


@pytest.fixture
def tools():
    root = tempfile.mkdtemp()
    try:
        yield root, M._build_tools(LocalFS(), allow_write=False, root=root)
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)


# -- dispatcher --------------------------------------------------------------


def test_happy_tools_call_with_progress_meta(tools):
    root, ts = tools
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_dir", "arguments": {"path": root}, "_meta": {"progressToken": 5}},
    }
    resp = M._handle_request(req, ts)
    assert "result" in resp, resp


@pytest.mark.parametrize("meta", [1.5, "x", [1], True], ids=["float", "str", "list", "bool"])
def test_sad_meta_that_is_not_an_object(tools, meta):
    root, ts = tools
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_dir", "arguments": {"path": root}, "_meta": meta},
    }
    resp = M._handle_request(req, ts)
    assert resp["error"]["code"] == M.ERR_INVALID_PARAMS
    assert "_meta" in resp["error"]["message"]


@pytest.mark.parametrize("target", [[1], {"a": 1}, 1.5, True, None])
def test_edge_cancel_with_an_id_that_cannot_be_one(tools, target):
    _root, ts = tools
    cancels = M._CancelRegistry()
    event = cancels.register(1)
    req = {
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": target},
    }
    assert M._handle_request(req, ts, cancels=cancels) is None
    assert not event.is_set()


def test_happy_cancel_reaches_the_request(tools):
    _root, ts = tools
    cancels = M._CancelRegistry()
    event = cancels.register("r1")
    req = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": "r1"}}
    assert M._handle_request(req, ts, cancels=cancels) is None
    assert event.is_set()


# -- stdio transport ----------------------------------------------------------


def _serve_stdio(data: bytes) -> list[dict]:
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    out = io.StringIO()
    root = tempfile.mkdtemp()
    try:
        rc = M.serve(M.ServerConfig(backend=LocalFS(), root=root, stdin=stdin, stdout=out))
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)
    assert rc == 0
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def test_happy_stdio_answers_ping():
    assert _serve_stdio(_PING + b"\n") == [{"jsonrpc": "2.0", "id": 7, "result": {}}]


@pytest.mark.parametrize("body", list(_BAD_BODIES.values()), ids=list(_BAD_BODIES))
def test_sad_stdio_bad_line_is_a_parse_error_and_the_next_line_is_served(body):
    answers = _serve_stdio(body + b"\n" + _PING + b"\n")
    assert answers[0]["error"]["code"] == M.ERR_PARSE
    assert answers[0]["id"] is None
    assert answers[1] == {"jsonrpc": "2.0", "id": 7, "result": {}}


def test_edge_stdio_meta_not_an_object_then_ping():
    bad = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_dir","_meta":3}}'
    answers = _serve_stdio(bad + b"\n" + _PING + b"\n")
    assert answers[0]["error"]["code"] == M.ERR_INVALID_PARAMS
    assert answers[1]["id"] == 7


def test_edge_stdio_text_stream_without_a_byte_buffer():
    out = io.StringIO()
    stdin = io.StringIO(_PING.decode() + "\n")
    assert M.serve(M.ServerConfig(backend=LocalFS(), stdin=stdin, stdout=out)) == 0
    assert json.loads(out.getvalue())["id"] == 7


# -- HTTP transport -----------------------------------------------------------


@pytest.fixture
def http_port():
    config = mcp_http.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0)
    server = mcp_http.build_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post(port: int, body: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(
            b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    return data


@pytest.mark.parametrize("body", list(_BAD_BODIES.values()), ids=list(_BAD_BODIES))
def test_sad_http_bad_body_is_a_400(http_port, body):
    answer = _post(http_port, body)
    assert answer.startswith(b"HTTP/1.0 400 "), answer[:120]
    assert b"invalid JSON" in answer


def test_happy_http_initialize_still_works(http_port):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode()
    assert _post(http_port, body).startswith(b"HTTP/1.0 200 ")
