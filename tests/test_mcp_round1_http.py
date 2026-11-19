"""Round 1 of the adversarial review of the headless MCP server: HTTP.

- H3: a session that ends (DELETE, idle eviction) cancels and forgets its
  tasks - their results no longer pin memory.
- H4: the bearer token is written only once the socket is bound (a second
  server on a busy port overwrote the running one's token), its file names
  the host, and it is removed when the server stops.
- M6: at the session cap an initialize evicts the session idle longest
  instead of locking everyone out; one client holds at most
  MAX_SESSIONS_PER_CLIENT; the rate bucket is the client's, not a fresh
  one per session.
- LOW: POST needs Content-Type application/json; mTLS checks Origin; a new
  SSE stream without Last-Event-ID does not re-send; a client's response
  object is 202; the listen backlog is not 5; a reset connection is no
  traceback; /health needs no client certificate.
"""

from __future__ import annotations

import http.client
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from core import mcp_http
from core import mcp_server as M
from core.local_fs import LocalFS

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "round1-http-token-0123456789abcdef"


@pytest.fixture
def server(tmp_path):
    config = mcp_http.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                       root=str(tmp_path), auth_token=TOKEN)
    srv = mcp_http.build_server(config)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    fwd = getattr(srv, "_mcp_log_forwarder", None)
    if fwd is not None:
        M._detach_log_forwarder(fwd)
    thread.join(timeout=5)


def _http(srv, method, body=None, headers=None, path="/messages"):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    hdrs = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
    hdrs.update(headers or {})
    payload = body if isinstance(body, (bytes, str)) or body is None else json.dumps(body)
    conn.request(method, path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        data = json.loads(raw) if raw else None
    except ValueError:
        data = raw
    return resp.status, resp.getheader("Mcp-Session-Id"), data


def _init(srv):
    status, sid, _ = _http(srv, "POST", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                         "params": {"protocolVersion": "2025-11-25"}})
    assert status == 200
    return sid


def _handler(srv):
    return srv.RequestHandlerClass


# --- H3 --------------------------------------------------------------------------


def test_happy_delete_cancels_and_forgets_the_sessions_tasks(server, tmp_path):
    release = threading.Event()
    seen_cancel = threading.Event()

    def handler(args, ctx):
        while not release.is_set():
            if ctx.is_cancelled:
                seen_cancel.set()
                ctx.check_cancel()
            time.sleep(0.01)
        return {"big": "x" * 1000}

    _handler(server)._tools = [M._Tool(name="slow", description="", schema={"type": "object"},
                                       handler=handler, timeout_seconds=60)]
    sid = _init(server)
    status, _, started = _http(server, "POST", {"jsonrpc": "2.0", "id": 2,
                                                "method": "axross/tasks/start",
                                                "params": {"name": "slow"}},
                               {"Mcp-Session-Id": sid})
    assert status == 200, started
    tasks = _handler(server)._tasks
    assert tasks.running_count() == 1
    assert _http(server, "DELETE", headers={"Mcp-Session-Id": sid})[0] == 204
    assert seen_cancel.wait(5)
    assert tasks.list_all() == [] and tasks.running_count() == 0
    release.set()


# --- H4 --------------------------------------------------------------------------


def _cli_env(tmp_path):
    import os

    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_")}
    run = tmp_path / "run"
    run.mkdir(mode=0o700, exist_ok=True)
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_STATE_HOME=str(home / ".state"), XDG_RUNTIME_DIR=str(run))
    return env, run / "axross"


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_sad_a_second_server_on_a_busy_port_leaves_the_token_alone(tmp_path):
    env, folder = _cli_env(tmp_path)
    port = _free_port()
    cmd = [sys.executable, str(ROOT / "main.py"), "--mcp-http", f"127.0.0.1:{port}",
           "--mcp-root", str(tmp_path)]
    first = subprocess.Popen(cmd, env=env, cwd=ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    token_file = folder / f"mcp-http-127.0.0.1-{port}.token"
    try:
        deadline = time.time() + 60
        while not token_file.exists():
            assert first.poll() is None and time.time() < deadline, "first server did not start"
            time.sleep(0.1)
        token = token_file.read_text()
        second = subprocess.run(cmd, env=env, cwd=ROOT, capture_output=True, text=True,
                                timeout=60)
        assert second.returncode == 2 and "in use" in second.stderr
        assert "Token:" not in second.stderr  # nothing handed out for a server that failed
        assert token_file.read_text() == token
    finally:
        first.terminate()
        first.wait(30)
    assert not token_file.exists()  # SIGTERM ran the clean-up


def test_edge_token_file_names_the_host():
    assert mcp_http.token_file_name(7331, "127.0.0.1") == "mcp-http-127.0.0.1-7331.token"
    assert mcp_http.token_file_name(7331, "::1") == "mcp-http-__1-7331.token"
    assert mcp_http.token_file_name(7331) == "mcp-http-7331.token"


# --- M6 ------------------------------------------------------------------------------


def test_happy_at_the_cap_the_longest_idle_session_makes_room(monkeypatch):
    monkeypatch.setattr(mcp_http, "SESSION_EVICTABLE_AFTER_SECONDS", 0.0)
    registry = mcp_http._SessionRegistry(idle_seconds=3600.0, max_sessions=2)
    a = registry.create("x")
    time.sleep(0.01)
    registry.create("y")
    registry.create("z")  # evicts a, idle longest
    assert registry.get(a.session_id) is None and a.closed.is_set()


def test_sad_a_session_that_streams_or_works_is_not_evicted(monkeypatch):
    monkeypatch.setattr(mcp_http, "SESSION_EVICTABLE_AFTER_SECONDS", 0.0)
    registry = mcp_http._SessionRegistry(idle_seconds=3600.0, max_sessions=1)
    a = registry.create("x")
    a.sse_stream = (threading.Event(), threading.Event())
    a.cancels.register("call")  # works: never evicted
    with pytest.raises(mcp_http.SessionLimitError):
        registry.create("y")
    # Round 4: a session that only holds its stream makes room at the cap
    # (one client held every session that way), after all idle ones.
    a.cancels.unregister("call")
    registry.create("y")
    assert a.closed.is_set()


def test_sad_one_client_cannot_hold_every_session(monkeypatch):
    monkeypatch.setattr(mcp_http, "MAX_SESSIONS_PER_CLIENT", 2)
    registry = mcp_http._SessionRegistry(idle_seconds=3600.0)
    registry.create("churner")
    registry.create("churner")
    with pytest.raises(mcp_http.SessionLimitError):
        registry.create("churner")  # none idle long enough to make room
    registry.create("someone else")


def test_happy_at_the_client_cap_its_own_idle_session_makes_room(monkeypatch):
    # On loopback every local client is one "client" (address + token): a
    # churner's sessions left behind must not lock the others out for long.
    monkeypatch.setattr(mcp_http, "MAX_SESSIONS_PER_CLIENT", 2)
    monkeypatch.setattr(mcp_http, "SESSION_EVICTABLE_AFTER_SECONDS", 0.0)
    registry = mcp_http._SessionRegistry(idle_seconds=3600.0)
    first = registry.create("local")
    time.sleep(0.01)
    registry.create("local")
    registry.create("local")
    assert registry.get(first.session_id) is None


def test_sad_a_new_session_brings_no_fresh_rate_bucket():
    # Round 3: each session has a bucket of its own (one flooding session
    # no longer starves the client's others), and the client's shared
    # bucket - FAIR_SHARE_SESSIONS times the size - bounds them all: new
    # sessions bring no budget past it.
    registry = mcp_http._SessionRegistry(idle_seconds=3600.0, rate_burst=2,
                                         rate_refill_per_sec=0.0)
    taken = 0
    for _ in range(mcp_http.FAIR_SHARE_SESSIONS + 3):
        session = registry.create("c")
        while session.rate_limiter.try_acquire():
            taken += 1
    # Round 4: each session keeps a small reserve of its own as well (a
    # quiet session is never starved by many flooding ones): bounded.
    sessions = mcp_http.FAIR_SHARE_SESSIONS + 3
    assert taken <= 2 * mcp_http.FAIR_SHARE_SESSIONS + sessions * mcp_http.FAIR_RESERVE_BURST
    assert registry.create("other").rate_limiter.try_acquire()


# --- LOW ------------------------------------------------------------------------------


def test_sad_post_without_json_content_type_is_refused(server):
    status, _, _ = _http(server, "POST", {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                          "params": {}}, {"Content-Type": "text/plain"})
    assert status == 415


def test_happy_a_clients_response_object_gets_202(server):
    sid = _init(server)
    status, _, body = _http(server, "POST", {"jsonrpc": "2.0", "id": 5, "result": {}},
                            {"Mcp-Session-Id": sid})
    assert status == 202 and body is None


def test_happy_a_new_stream_without_last_event_id_does_not_resend(server):
    sid = _init(server)
    sess = _handler(server)._sessions.get(sid)
    sink = mcp_http._QueueSink(sess)
    sink.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                           "params": {"data": "one"}}) + "\n")

    def read_stream(extra=b""):
        sock = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=5)
        sock.sendall(b"GET /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n"
                     + f"Mcp-Session-Id: {sid}\r\nAuthorization: Bearer {TOKEN}\r\n".encode()
                     + extra + b"\r\n")
        sock.settimeout(1.0)
        data = b""
        try:
            while b"one" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        sock.close()
        return data

    assert b"one" in read_stream()  # never delivered: sent on the first stream
    time.sleep(0.5)  # the first stream notices it is superseded
    assert b"one" not in read_stream()  # delivered already: not again
    assert b"one" in read_stream(b"Last-Event-ID: 0\r\n")  # asked for: replayed


def test_edge_backlog_and_reset_connections():
    assert mcp_http._ThreadingServer.request_queue_size >= 64

    class Fake:
        pass

    srv = Fake()
    try:
        raise ConnectionResetError("reset by peer")
    except ConnectionResetError:
        # one log line, no traceback on stderr
        mcp_http._ThreadingServer.handle_error(srv, None, ("1.2.3.4", 1))


def test_sad_mtls_origin_must_match():
    class H:
        _local_only = False

        def __init__(self, origin, host):
            self.headers = _Headers({"Origin": origin, "Host": host})
            self.sent = None

        def _send_error(self, status, msg):
            self.sent = status

    check = mcp_http._McpHTTPHandler._check_local_origin
    bad = H("https://evil.example", "mcp.example:7331")
    assert check(bad) is False and bad.sent == 403
    good = H("https://mcp.example:7331", "mcp.example:7331")
    assert check(good) is True


class _Headers(dict):
    def get_all(self, name):
        return [self[name]] if name in self else []


def test_happy_health_needs_no_client_certificate_but_the_rest_does(tmp_path):
    import shutil
    import ssl

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not available")
    key, crt = str(tmp_path / "k.pem"), str(tmp_path / "c.pem")
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", crt, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    srv = mcp_http.build_server(mcp_http.HTTPServerConfig(
        backend=LocalFS(), host="127.0.0.1", port=0, cert_file=crt, key_file=key, ca_file=crt))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    def get(path, with_cert):
        ctx = ssl.create_default_context(cafile=crt)
        ctx.check_hostname = False
        if with_cert:
            ctx.load_cert_chain(crt, key)
        with socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                            "Connection: close\r\n\r\n".encode())
                return tls.recv(4096).split(b"\r\n", 1)[0]

    try:
        assert b"200" in get("/health", with_cert=False)
        assert b"401" in get("/messages", with_cert=False)
        assert b"406" in get("/messages", with_cert=True)  # past the certificate check
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)
