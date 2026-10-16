"""Fuzz: axross's own MCP server against a hostile client.

Three layers, each held to "answer or refuse, never die":

* the JSON-RPC dispatcher (``mcp_server._handle_request``) with
  structurally mutated requests - wrong types for id / method / params /
  _meta / arguments / requestId, absurd numbers, traversal paths;
* the stdio transport (``mcp_server.serve``) with byte-mutated request
  lines - it must answer every line and keep reading;
* the HTTP transport (``mcp_http``) with byte-mutated raw HTTP requests
  and a slow-loris client - every connection gets an answer or is closed,
  no handler thread dies with an exception, and the server stays up.

The tools run read-only against a temporary directory.
"""

from __future__ import annotations

import io
import json
import os
import random
import shutil
import socket
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import iterations, mutants, run_bounded  # noqa: E402

from core import mcp_http  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.fixture(scope="module")
def root():
    tmp = Path(tempfile.mkdtemp()).resolve()
    (tmp / "a.txt").write_text("hello\n")
    (tmp / "sub").mkdir()
    (tmp / "sub" / "b.bin").write_bytes(b"\x00\xff" * 100)
    try:
        yield str(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# -- dispatcher ---------------------------------------------------------------

_METHODS = [
    "initialize",
    "ping",
    "notifications/initialized",
    "notifications/cancelled",
    "tools/list",
    "tools/call",
    "logging/setLevel",
    "resources/list",
    "resources/read",
    "resources/templates/list",
    "tasks/start",
    "tasks/status",
    "tasks/cancel",
    "tasks/list",
    "completion/complete",
    "nope",
]
_PARAM_KEYS = [
    "name",
    "arguments",
    "_meta",
    "protocolVersion",
    "requestId",
    "level",
    "uri",
    "taskId",
    "cursor",
]
_ARG_KEYS = [
    "path",
    "pattern",
    "max_depth",
    "offset",
    "length",
    "encoding",
    "limit",
    "backend",
    "query",
    "recursive",
    "max_results",
    "algorithm",
    "version_id",
]


def _weird(root: str) -> list:
    return [
        None,
        True,
        0,
        -1,
        2**70,
        1.5,
        float("nan"),
        "",
        "\x00",
        "../../..",
        "/",
        root,
        root + "/a.txt",
        root + "/../../etc/passwd",
        "axross://" + root + "/a.txt",
        "\ud800",
        "x" * 5000,
        [],
        [1],
        {},
        {"a": {"b": [None]}},
    ]


def _random_request(rng: random.Random, names: list[str], weird: list) -> dict:
    req: dict = {"jsonrpc": rng.choice(["2.0", "2.0", "1.0", None])}
    req["method"] = rng.choice(_METHODS + weird[:8])
    if rng.random() < 0.85:
        params: object = {
            k: rng.choice(weird + names) for k in rng.sample(_PARAM_KEYS, rng.randint(0, 4))
        }
        if rng.random() < 0.6:
            params["name"] = rng.choice(names)
            args = {k: rng.choice(weird) for k in rng.sample(_ARG_KEYS, rng.randint(0, 4))}
            params["arguments"] = rng.choice([args, args, args, [], "x", None])
    else:
        params = rng.choice([None, [], "x", 1, [{}]])
    req["params"] = params
    if rng.random() < 0.9:
        req["id"] = rng.choice([1, "a", None, 1.5, True, [], {}, 2**70])
    return req


def test_sad_dispatcher_answers_every_mutated_request(root):
    tools = M._build_tools(LocalFS(), allow_write=False, root=root)
    names = [t.name for t in tools]
    resources = M._build_resources(LocalFS(), root=root)
    cancels, tasks, fwd = M._CancelRegistry(), M._TaskRegistry(), M._LogForwarder()
    weird = _weird(root)
    rng = random.Random(0x6D6370)
    for n in range(iterations(1500)):
        req = _random_request(rng, names, weird)

        def call(req=req):
            return M._handle_request(
                req,
                tools,
                cancels=cancels,
                resources=resources,
                log_forwarder=fwd,
                tasks=tasks,
                session_id="fuzz",
            )

        resp, exc = run_bounded(call, timeout=30.0)
        assert exc is None, f"request {n} {req!r:.300} raised {exc!r}"
        if resp is None:
            continue
        assert resp.get("jsonrpc") == "2.0"
        assert ("result" in resp) != ("error" in resp), resp
        json.dumps(resp)  # the transport must be able to send it


# Argument names of the capability-group tools (--mcp-tools all).
_GROUP_ARG_KEYS = [
    "path",
    "recursive",
    "max_files",
    "format",
    "out",
    "max_bytes",
    "use_file_command",
    "mismatches_only",
    "algorithm",
    "rehash",
    "scan_id",
    "max_groups",
    "dry_run",
    "prune",
    "folder",
    "names",
    "archive_name",
    "level",
    "password",
    "encrypt_names",
    "max_entries",
    "dest_dir",
    "passphrase",
    "src",
    "dst",
    "src_backend",
    "dst_backend",
    "overwrite",
    "resumable",
    "max_file_bytes",
    "profile",
    "backend",
    "ext_id",
]


def test_sad_group_tools_answer_every_malformed_call(tmp_path, monkeypatch):
    # Every tool of every group, mutating ones included, against arguments
    # of the wrong type, out of range, traversal paths and unknown keys:
    # each call is answered (result or JSON-RPC error), none kills the
    # dispatcher, and nothing is written outside the root.
    from core import credentials
    from core import mcp_groups as G

    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)
    from core import llm_profiles

    # agent_run finds no LLM profile: no fuzzed call reaches a model.
    monkeypatch.setattr(llm_profiles, "SETTINGS_FILE", tmp_path / "no-llm.json")
    outside = tmp_path  # a private parent: only this test writes here
    (tmp_path / "root" / "sub").mkdir(parents=True)
    (tmp_path / "root" / "a.txt").write_text("hello\n")
    (tmp_path / "root" / "sub" / "b.bin").write_bytes(b"\x00\xff" * 100)
    (tmp_path / "secret.txt").write_text("outside the root\n")
    root = str(tmp_path / "root")
    before = {p: p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    tools = M._build_tools(
        LocalFS(), allow_write=True, root=root, tool_groups=frozenset(G.GROUPS)
    )
    names = [t.name for t in tools if t.group in G.GROUPS]
    weird = _weird(root) + [["a", "../x"], {"x": 1}, "profile:nope", "local", 0.0, -(2**31)]
    # Well-formed calls, one field of which is then mutated, so most
    # calls get past the schema and into the handlers.
    base = {
        "metadata_read": {"path": root},
        "metadata_export": {"path": root, "format": "csv"},
        "metadata_export_file": {"path": root, "out": root + "/m.json"},
        "metadata_remove": {"path": root + "/a.txt"},
        "duplicates_scan": {"path": root},
        "duplicates_scans": {},
        "duplicates_groups": {"path": root},
        "duplicates_dedupe": {"path": root},
        "pack_formats": {},
        "pack": {"folder": root, "names": ["a.txt"], "archive_name": "fz"},
        "archive_list": {"path": root + "/a.txt"},
        "archive_extract": {"path": root + "/a.txt"},
        "encrypt": {"path": root + "/a.txt", "passphrase": "p"},
        "decrypt": {"path": root + "/a.txt", "passphrase": "p"},
        "index_build": {"path": root},
        "file_type": {"path": root + "/a.txt"},
        "file_type_scan": {"path": root},
        "transfer_copy": {"src": root + "/a.txt", "dst": root + "/sub/c.txt"},
        "transfer_move": {"src": root + "/sub/c.txt", "dst": root + "/c.txt"},
        "remote_profiles": {},
        "remote_open": {"profile": "nope"},
        "remote_close": {"backend": "profile:nope"},
        "list_backends": {},
        "extensions_list": {},
        "extensions_info": {"ext_id": "bundled:nope"},
        "agent_run": {"task": "summarise a.txt", "groups": ["filetype"]},
    }
    assert set(names) <= set(base), sorted(set(names) - set(base))
    shaped = {
        str: [w for w in weird if isinstance(w, str)]
        + [root + "/sub", root + "/sub/b.bin", root + "/../" + os.path.basename(root) + "/a.txt"],
        list: [[], ["../x"], ["a.txt", "a.txt"], ["\x00"], ["x" * 300], ["sub"], [".."]],
    }
    rng = random.Random(0x67727073)
    cancels, tasks = M._CancelRegistry(), M._TaskRegistry()
    for n in range(iterations(600)):
        name = rng.choice(names)
        if rng.random() < 0.6:
            args = dict(base[name])
            key = rng.choice(list(args) or _GROUP_ARG_KEYS) if rng.random() < 0.7 else (
                rng.choice(_GROUP_ARG_KEYS)
            )
            if key in args and rng.random() < 0.15:
                del args[key]
            elif key in args and rng.random() < 0.8:
                # Same type, hostile value: gets past the schema's type check.
                args[key] = rng.choice(shaped.get(type(args[key]), weird))
            else:
                args[key] = rng.choice(weird)
        else:
            args = {k: rng.choice(weird) for k in rng.sample(_GROUP_ARG_KEYS, rng.randint(0, 5))}
        req = {
            "jsonrpc": "2.0",
            "id": n,
            "method": rng.choice(["tools/call", "tools/call", "tasks/start"]),
            "params": {"name": name, "arguments": args},
        }

        def call(req=req):
            return M._handle_request(req, tools, cancels=cancels, tasks=tasks, session_id="fz")

        resp, exc = run_bounded(call, timeout=30.0)
        assert exc is None, f"call {n} {req!r:.300} raised {exc!r}"
        assert resp is not None and resp.get("jsonrpc") == "2.0"
        assert ("result" in resp) != ("error" in resp), resp
        json.dumps(resp)
    deadline = time.monotonic() + 30
    while any(t.status == "running" for t in tasks.list_scope("fz")):
        assert time.monotonic() < deadline, "a fuzzed task never finished"
        time.sleep(0.05)
    after = {p: p.stat().st_mtime_ns for p in outside.iterdir()}
    assert set(after) == set(before), "a group tool wrote outside the root"
    secret = outside / "secret.txt"
    assert after[secret] == before[secret] and secret.read_text() == "outside the root\n"


# -- stdio transport ----------------------------------------------------------

_LINES = [
    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}',
    b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    b'{"jsonrpc":"2.0","id":"x","method":"tools/call","params":'
    b'{"name":"list_dir","arguments":{"path":"ROOT"},"_meta":{"progressToken":1}}}',
    b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":'
    b'{"name":"read_file","arguments":{"path":"ROOT/a.txt","length":3}}}',
    b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":4}}',
    b'{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"axross://ROOT/a.txt"}}',
]
_SENTINEL = b'{"jsonrpc":"2.0","id":"sentinel","method":"ping"}'


def _stdio_corpus(root: str) -> list[bytes]:
    return [line.replace(b"ROOT", root.encode()) for line in _LINES]


def test_happy_stdio_corpus(root):
    data = b"\n".join(_stdio_corpus(root) + [_SENTINEL]) + b"\n"
    out = io.StringIO()
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    cfg = M.ServerConfig(backend=LocalFS(), root=root, stdin=stdin, stdout=out)
    assert M.serve(cfg) == 0
    answers = [json.loads(x) for x in out.getvalue().splitlines()]
    assert all("result" in a for a in answers if a.get("id") is not None), answers
    assert answers[-1]["id"] == "sentinel"


def test_sad_stdio_survives_mutated_lines(root):
    lines = list(mutants(_stdio_corpus(root), seed=0x5354, per_entry=iterations(100)))
    data = b"\n".join(lines + [_SENTINEL]) + b"\n"
    out = io.StringIO()
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    cfg = M.ServerConfig(
        backend=LocalFS(), root=root, stdin=stdin, stdout=out, rate_limit_enabled=False
    )
    rc, exc = run_bounded(lambda: M.serve(cfg), timeout=120.0)
    assert exc is None, f"serve() died: {exc!r}"
    assert rc == 0
    answers = [json.loads(x) for x in out.getvalue().splitlines() if x.strip()]
    assert answers and answers[-1].get("id") == "sentinel", answers[-3:]


# -- HTTP transport -----------------------------------------------------------


@pytest.fixture
def http_server(root):
    config = mcp_http.HTTPServerConfig(
        backend=LocalFS(),
        host="127.0.0.1",
        port=0,
        root=root,
        rate_limit_enabled=False,
        http_ip_rate_enabled=False,
    )
    server = mcp_http.build_server(config)
    crashes: list[str] = []

    def record(request, client_address):  # replaces the stderr traceback
        import traceback

        crashes.append(traceback.format_exc())

    server.handle_error = record
    server.RequestHandlerClass.timeout = 2.0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], crashes
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _exchange(port: int, raw: bytes, timeout: float = 10.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        try:
            s.sendall(raw)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # the server may answer and close before reading it all
        data = b""
        try:
            while chunk := s.recv(65536):
                data += chunk
        except ConnectionResetError:
            pass
    return data


def _http(method: str, path: str, body: bytes = b"", headers: bytes = b"") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n".encode()
        + headers
        + (b"Content-Type: application/json\r\nContent-Length: %d\r\n" % len(body) if body else b"")
        + b"\r\n"
        + body
    )


def _http_corpus(root: str) -> list[bytes]:
    init = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    return [
        _http("POST", "/messages", init),
        _http("GET", "/health"),
        _http("GET", "/messages", headers=b"Accept: text/event-stream\r\nMcp-Session-Id: x\r\n"),
        _http("DELETE", "/messages", headers=b"Mcp-Session-Id: abc\r\n"),
        _http("POST", "/messages", _stdio_corpus(root)[1], headers=b"Mcp-Session-Id: abc\r\n"),
    ]


def _health_ok(port: int) -> bool:
    return _exchange(port, _http("GET", "/health")).startswith(b"HTTP/1.0 200 ")


def test_happy_http_corpus(http_server, root):
    port, crashes = http_server
    for raw in _http_corpus(root):
        assert _exchange(port, raw).startswith(b"HTTP/1.0 "), raw[:60]
    assert not crashes


def test_sad_http_survives_mutated_requests(http_server, root):
    port, crashes = http_server
    corpus = _http_corpus(root)
    for n, raw in enumerate(mutants(corpus, seed=0x48545450, per_entry=iterations(150))):
        answer, exc = run_bounded(lambda raw=raw: _exchange(port, raw), timeout=15.0)
        assert exc is None or isinstance(exc, OSError), f"mutant {n}: {exc!r}"
        request_line = raw.split(b"\n", 1)[0]
        if answer and b" HTTP/" in request_line:
            # (a request line without a version is HTTP/0.9: the stdlib
            # answers it with a bare body, as the protocol says)
            assert answer.startswith(b"HTTP/"), f"mutant {n} {raw[:80]!r}: {answer[:80]!r}"
    time.sleep(0.2)  # let the last handler thread finish
    assert not crashes, crashes[0]
    assert _health_ok(port)


def test_sad_http_mutated_bodies_in_a_live_session(http_server, root):
    port, crashes = http_server
    init = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    answer = _exchange(port, _http("POST", "/messages", init))
    head = answer.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    sid = next(
        line.split(":", 1)[1].strip()
        for line in head.split("\r\n")
        if line.lower().startswith("mcp-session-id:")
    )
    hdr = f"Mcp-Session-Id: {sid}\r\n".encode()
    seed = zlib.crc32(b"session-bodies")
    for n, body in enumerate(mutants(_stdio_corpus(root), seed=seed, per_entry=iterations(60))):
        if not body:
            continue
        raw = _http("POST", "/messages", body, headers=hdr)
        answer, exc = run_bounded(lambda raw=raw: _exchange(port, raw), timeout=40.0)
        assert exc is None, f"body {n} {body[:80]!r}: {exc!r}"
        assert answer.startswith(b"HTTP/1.0 "), f"body {n} {body[:80]!r}: {answer[:80]!r}"
    time.sleep(0.2)
    assert not crashes, crashes[0]
    assert _health_ok(port)


def test_edge_http_slow_loris_does_not_block_others(http_server):
    port, crashes = http_server
    slow = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        slow.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Le")
        assert _health_ok(port)  # served while the slow client hangs
        started = time.monotonic()
        rest = b""
        try:
            while chunk := slow.recv(4096):
                rest += chunk
        except OSError:
            pass
        # The server drops it after its connection timeout (2 s here).
        assert time.monotonic() - started < 8.0
    finally:
        slow.close()
    assert not crashes
