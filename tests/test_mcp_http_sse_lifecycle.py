"""An SSE stream ends with its session, and a session has one stream.

Before: ``DELETE /messages`` and idle eviction only removed the session
from the registry; ``_serve_sse`` kept its own reference and looped on
``queue.get`` + keepalive forever, so the handler thread lived as long as
the client kept reading. Every further ``GET /messages`` for the same
session started one more such thread, without any bound, so one local
client could pin an unbounded number of threads.

Now a session's stream ends when the session is dropped or evicted, and a
new stream for a session supersedes (ends) the previous one.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
import unittest

from core import mcp_http
from core.local_fs import LocalFS

_INIT = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }
)
# Far below the 15 s keepalive: a stream that is still open after this
# long was not ended by the server.
_EOF_WAIT = 3.0


def _stream_threads() -> int:
    return sum(1 for t in threading.enumerate() if "process_request" in t.name and t.is_alive())


# A plain-HTTP server demands a bearer token (see test_mcp_http_bearer_token).
_TOKEN = "sse-test-token-0123456789abcdef"


class _Server:
    def __init__(self, **overrides) -> None:
        overrides.setdefault("auth_token", _TOKEN)
        config = mcp_http.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0, **overrides)
        self.server = mcp_http.build_server(config)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.sockets: list[socket.socket] = []

    def close(self) -> None:
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        self.server.shutdown()
        self.server.server_close()
        fwd = getattr(self.server, "_mcp_log_forwarder", None)
        if fwd is not None:
            mcp_http._mcp._detach_log_forwarder(fwd)
        self.thread.join(timeout=5)

    def request(self, method: str, headers: dict[str, str] | None = None, body: str | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Content-Type": "application/json", "Authorization": f"Bearer {_TOKEN}"}
        hdrs.update(headers or {})
        conn.request(method, "/messages", body=body, headers=hdrs)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp

    def initialize(self) -> str:
        resp = self.request("POST", body=_INIT)
        assert resp.status == 200, resp.status
        return resp.getheader("Mcp-Session-Id")

    def session(self, sid: str):
        return self.server.RequestHandlerClass._sessions.get(sid)

    def open_sse(self, sid: str, last_event_id: int | None = None) -> tuple["_Stream", int]:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.sockets.append(sock)
        extra = f"Last-Event-ID: {last_event_id}\r\n" if last_event_id is not None else ""
        sock.sendall(
            (
                f"GET /messages HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                f"Accept: text/event-stream\r\nMcp-Session-Id: {sid}\r\n"
                f"Authorization: Bearer {_TOKEN}\r\n{extra}\r\n"
            ).encode("ascii")
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        status = int(head.split(b" ", 2)[1])
        stream = _Stream(sock, head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b"")
        return stream, status


class _Stream:
    def __init__(self, sock: socket.socket, pending: bytes) -> None:
        self.sock = sock
        self.pending = pending


def _read(stream: _Stream, timeout: float, until: bytes | None = None) -> tuple[bool, bytes]:
    """(reached EOF, data) after reading for at most *timeout* seconds."""
    sock = stream.sock
    data, stream.pending = stream.pending, b""
    deadline = time.monotonic() + timeout
    while True:
        if until is not None and until in data:
            return False, data
        left = deadline - time.monotonic()
        if left <= 0:
            return False, data
        sock.settimeout(left)
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            return False, data
        except ConnectionResetError:
            return True, data
        if not chunk:
            return True, data
        data += chunk


def _emit(sess, method: str) -> None:
    mcp_http._QueueSink(sess).write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")


class SseLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = _Server()
        self.addCleanup(self.srv.close)

    def test_happy_events_reach_the_open_stream(self) -> None:
        sid = self.srv.initialize()
        sock, status = self.srv.open_sse(sid)
        self.assertEqual(status, 200)
        time.sleep(0.2)
        _emit(self.srv.session(sid), "notifications/one")
        eof, data = _read(sock, _EOF_WAIT, until=b"notifications/one")
        self.assertFalse(eof)
        self.assertIn(b"notifications/one", data)

    def test_happy_delete_ends_the_open_stream(self) -> None:
        sid = self.srv.initialize()
        sock, status = self.srv.open_sse(sid)
        self.assertEqual(status, 200)
        time.sleep(0.2)
        self.assertEqual(self.srv.request("DELETE", {"Mcp-Session-Id": sid}).status, 204)
        eof, _ = _read(sock, _EOF_WAIT)
        self.assertTrue(eof, "SSE stream still open after DELETE")

    def test_sad_stream_for_a_deleted_session_is_refused(self) -> None:
        sid = self.srv.initialize()
        self.srv.request("DELETE", {"Mcp-Session-Id": sid})
        _sock, status = self.srv.open_sse(sid)
        self.assertEqual(status, 404)

    def test_sad_a_second_stream_supersedes_the_first(self) -> None:
        sid = self.srv.initialize()
        first, _ = self.srv.open_sse(sid)
        time.sleep(0.2)
        second, status = self.srv.open_sse(sid)
        self.assertEqual(status, 200)
        eof, _ = _read(first, _EOF_WAIT)
        self.assertTrue(eof, "first SSE stream still open after a second one")
        _emit(self.srv.session(sid), "notifications/two")
        eof, data = _read(second, _EOF_WAIT, until=b"notifications/two")
        self.assertFalse(eof)
        self.assertIn(b"notifications/two", data)

    def test_edge_many_streams_for_one_session_keep_one_thread(self) -> None:
        sid = self.srv.initialize()
        base = _stream_threads()
        socks = []
        for _ in range(12):
            sock, status = self.srv.open_sse(sid)
            self.assertEqual(status, 200)
            socks.append(sock)
        for sock in socks[:-1]:
            eof, _ = _read(sock, _EOF_WAIT)
            self.assertTrue(eof)
        deadline = time.monotonic() + _EOF_WAIT
        while _stream_threads() > base + 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertLessEqual(_stream_threads(), base + 1)

    def test_edge_reconnect_replays_what_the_old_stream_did_not_send(self) -> None:
        sid = self.srv.initialize()
        first, _ = self.srv.open_sse(sid)
        _read(first, 0.2)
        sess = self.srv.session(sid)
        _emit(sess, "notifications/a")
        _, data = _read(first, _EOF_WAIT, until=b"notifications/a")
        self.assertIn(b"id: 1", data)
        second, _ = self.srv.open_sse(sid, last_event_id=1)
        _emit(sess, "notifications/b")
        _, data = _read(second, _EOF_WAIT, until=b"notifications/b")
        self.assertIn(b"id: 2", data)
        self.assertNotIn(b"notifications/a", data)


class SseEvictionTest(unittest.TestCase):
    def test_edge_idle_eviction_ends_the_open_stream(self) -> None:
        srv = _Server(session_idle_seconds=0.3)
        self.addCleanup(srv.close)
        sid = srv.initialize()
        sock, status = srv.open_sse(sid)
        self.assertEqual(status, 200)
        time.sleep(0.5)
        srv.initialize()  # create() evicts idle sessions
        eof, _ = _read(sock, _EOF_WAIT)
        self.assertTrue(eof, "SSE stream outlived its evicted session")


if __name__ == "__main__":
    unittest.main()
