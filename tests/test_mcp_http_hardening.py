"""MCP HTTP transport hardening: DNS-rebinding, session flood, TLS handshake."""
from __future__ import annotations

import http.client
import json
import socket
import threading
import time
import unittest

from core import mcp_http
from core.local_fs import LocalFS


# A plain-HTTP server demands a bearer token (see test_mcp_http_bearer_token).
_TOKEN = "hardening-test-token-0123456789abcdef"


def _start(**overrides):
    overrides.setdefault("auth_token", _TOKEN)
    config = mcp_http.HTTPServerConfig(
        backend=LocalFS(), host="127.0.0.1", port=0, **overrides
    )
    server = mcp_http.build_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


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


def _post(port: int, headers: dict[str, str] | None = None, body: str = _INIT):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Content-Type": "application/json", "Authorization": f"Bearer {_TOKEN}"}
    hdrs.update(headers or {})
    conn.request("POST", "/messages", body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


class HostAndOriginTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server, self.thread = _start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        _stop(self.server, self.thread)

    def test_loopback_host_is_served(self) -> None:
        status, _ = _post(self.port, {"Host": f"127.0.0.1:{self.port}"})
        self.assertEqual(status, 200)
        status, _ = _post(self.port, {"Host": f"localhost:{self.port}"})
        self.assertEqual(status, 200)

    def test_rebound_foreign_host_is_refused(self) -> None:
        status, _ = _post(self.port, {"Host": f"evil.example:{self.port}"})
        self.assertEqual(status, 403)

    def test_browser_origin_is_refused(self) -> None:
        status, _ = _post(
            self.port,
            {"Host": f"127.0.0.1:{self.port}", "Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)

    def test_loopback_origin_is_served(self) -> None:
        status, _ = _post(
            self.port,
            {"Host": f"localhost:{self.port}", "Origin": f"http://localhost:{self.port}"},
        )
        self.assertEqual(status, 200)

    def test_health_also_checks_host(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/health", headers={"Host": "evil.example"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()


class HostParsingTest(unittest.TestCase):
    def test_host_allowed(self) -> None:
        ok = mcp_http._loopback_host_header
        self.assertTrue(ok("localhost"))
        self.assertTrue(ok("localhost:7331"))
        self.assertTrue(ok("127.0.0.1:1"))
        self.assertTrue(ok("[::1]:7331"))
        self.assertTrue(ok("LOCALHOST"))

    def test_host_rejected(self) -> None:
        bad = mcp_http._loopback_host_header
        hostile = ("evil.example", "127.0.0.1.evil.example", "", "localhost.evil", "10.0.0.1:80")
        for value in hostile:
            self.assertFalse(bad(value), value)


class SessionFloodTest(unittest.TestCase):
    def test_session_count_is_capped(self) -> None:
        server, thread = _start(http_ip_rate_enabled=False)
        try:
            port = server.server_address[1]
            statuses = [_post(port)[0] for _ in range(mcp_http.MAX_SESSIONS + 5)]
            self.assertEqual(statuses[: mcp_http.MAX_SESSIONS], [200] * mcp_http.MAX_SESSIONS)
            self.assertTrue(all(s == 503 for s in statuses[mcp_http.MAX_SESSIONS :]))
        finally:
            _stop(server, thread)

    def test_idle_sessions_are_evicted_on_create(self) -> None:
        registry = mcp_http._SessionRegistry(idle_seconds=0.0)
        first = registry.create()
        time.sleep(0.01)
        registry.create()
        self.assertIsNone(registry.get(first.session_id))

    def test_cap_applies_after_eviction(self) -> None:
        registry = mcp_http._SessionRegistry(idle_seconds=3600.0, max_sessions=2)
        registry.create()
        registry.create()
        with self.assertRaises(mcp_http.SessionLimitError):
            registry.create()


class MalformedRequestTest(unittest.TestCase):
    def test_non_object_params_do_not_kill_the_connection(self) -> None:
        server, thread = _start()
        try:
            port = server.server_address[1]
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [1]})
            status, _ = _post(port, body=body)
            self.assertLess(status, 500)
        finally:
            _stop(server, thread)


class RequestShapeTest(unittest.TestCase):
    def _call(self, req):
        from core import mcp_server as M

        return M._handle_request(req, [], None, None, None, None, None)

    def test_list_id_is_an_invalid_request_not_a_crash(self) -> None:
        resp = self._call({"jsonrpc": "2.0", "id": [1], "method": "ping"})
        self.assertEqual(resp["error"]["code"], -32600)

    def test_non_object_params_error(self) -> None:
        resp = self._call({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": [1]})
        self.assertEqual(resp["error"]["code"], -32602)

    def test_malformed_notification_gets_no_reply(self) -> None:
        self.assertIsNone(self._call({"jsonrpc": "2.0", "method": "x", "params": 5}))


class TlsFlagsTest(unittest.TestCase):
    def test_partial_tls_flags_are_an_error(self) -> None:
        cfg = mcp_http.HTTPServerConfig(
            backend=LocalFS(), cert_file="/x/cert", key_file="/x/key"
        )
        with self.assertRaises(ValueError):
            mcp_http.build_server(cfg)


class HandshakeTest(unittest.TestCase):
    def test_idle_tcp_client_does_not_block_accept(self) -> None:
        import os
        import shutil
        import ssl
        import subprocess
        import tempfile

        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("openssl not available")
        tmp = tempfile.mkdtemp()
        try:
            key, crt = os.path.join(tmp, "k.pem"), os.path.join(tmp, "c.pem")
            subprocess.run(
                [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                 "-out", crt, "-days", "1", "-subj", "/CN=localhost"],
                check=True, capture_output=True,
            )
            cfg = mcp_http.HTTPServerConfig(
                backend=LocalFS(), host="127.0.0.1", port=0,
                cert_file=crt, key_file=key, ca_file=crt,
            )
            server = mcp_http.build_server(cfg)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            stall = socket.create_connection(("127.0.0.1", port))  # sends nothing
            try:
                ctx = ssl.create_default_context(cafile=crt)
                ctx.check_hostname = False
                ctx.load_cert_chain(crt, key)
                started = time.monotonic()
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                    with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                        tls.sendall(
                            b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                        )
                        reply = tls.recv(4096)
                self.assertIn(b"200", reply.split(b"\r\n", 1)[0])
                self.assertLess(time.monotonic() - started, 4.0)
            finally:
                stall.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
