"""A plain-HTTP (loopback) MCP server demands a bearer token.

``--mcp-http 127.0.0.1:PORT``
without mTLS accepted every local process without any credential - even
with ``--mcp-tools remote,exec --mcp-allow-exec``. Another user on the
machine could open the saved profiles, run commands on the servers and
write into the MCP root. The Host/Origin check only stops browsers.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path

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


class BearerTokenTest(unittest.TestCase):
    def start(self, **overrides):
        self.root = tempfile.mkdtemp()
        config = mcp_http.HTTPServerConfig(
            backend=LocalFS(), host="127.0.0.1", port=0, root=self.root, **overrides
        )
        server = mcp_http.build_server(config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            fwd = getattr(server, "_mcp_log_forwarder", None)
            if fwd is not None:
                mcp_http._mcp._detach_log_forwarder(fwd)
            thread.join(timeout=5)

        self.addCleanup(stop)
        self.port = server.server_address[1]
        return server

    def request(self, method, path="/messages", body=None, token=None, extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        headers.update(extra or {})
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp, data

    def test_happy_the_right_token_gets_a_session_and_writes(self) -> None:
        server = self.start(allow_write=True)
        token = server.auth_token
        self.assertGreaterEqual(len(token), 32)
        resp, _ = self.request("POST", body=_INIT, token=token)
        self.assertEqual(resp.status, 200)
        sid = resp.getheader("Mcp-Session-Id")
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {
                    "path": os.path.join(self.root, "ok.txt"),
                    "content_b64": base64.b64encode(b"x").decode(),
                },
            },
        }
        resp, _ = self.request(
            "POST", body=json.dumps(call), token=token, extra={"Mcp-Session-Id": sid}
        )
        self.assertEqual(resp.status, 200)
        self.assertTrue(os.path.exists(os.path.join(self.root, "ok.txt")))

    def test_sad_no_or_a_wrong_token_is_refused_before_anything_runs(self) -> None:
        self.start(allow_write=True)
        for token in (None, "wrong", ""):
            with self.subTest(token=token):
                resp, _ = self.request("POST", body=_INIT, token=token)
                self.assertEqual(resp.status, 401)
                self.assertIsNone(resp.getheader("Mcp-Session-Id"))
                self.assertIn("Bearer", resp.getheader("WWW-Authenticate") or "")
        for method, extra in (
            ("GET", {"Accept": "text/event-stream", "Mcp-Session-Id": "x"}),
            ("DELETE", {"Mcp-Session-Id": "x"}),
        ):
            with self.subTest(method=method):
                resp, _ = self.request(method, extra=extra)
                self.assertEqual(resp.status, 401)

    def test_edge_health_needs_no_token_and_a_given_token_is_used(self) -> None:
        server = self.start(auth_token="t" * 40)
        self.assertEqual(server.auth_token, "t" * 40)
        resp, _ = self.request("GET", path="/health")
        self.assertEqual(resp.status, 200)
        resp, _ = self.request("POST", body=_INIT, token="t" * 40)
        self.assertEqual(resp.status, 200)


class PublishTokenTest(unittest.TestCase):
    def test_happy_token_file_is_private(self) -> None:
        base = Path(tempfile.mkdtemp())
        path = mcp_http.publish_token("secret-token", 7331, directory=base / "axross")
        self.assertEqual(path.read_text(), "secret-token\n")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_sad_a_symlink_in_place_of_the_file_is_not_followed(self) -> None:
        base = Path(tempfile.mkdtemp())
        folder = base / "axross"
        folder.mkdir(mode=0o700)
        victim = base / "victim"
        victim.write_text("keep")
        (folder / "mcp-http-7331.token").symlink_to(victim)
        path = mcp_http.publish_token("secret-token", 7331, directory=folder)
        self.assertEqual(victim.read_text(), "keep")
        self.assertFalse(path.is_symlink())
        self.assertEqual(path.read_text(), "secret-token\n")

    def test_edge_default_directory_is_the_private_runtime_dir(self) -> None:
        runtime = Path(tempfile.mkdtemp())
        os.chmod(runtime, 0o700)
        old = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = str(runtime)
        try:
            path = mcp_http.publish_token("tok", 7400)
        finally:
            if old is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = old
        self.assertEqual(path, runtime / "axross" / "mcp-http-7400.token")


class CommandLineTokenTest(unittest.TestCase):
    """``axross --mcp-server --mcp-http HOST:PORT`` always serves with a token."""

    def run_main(self, *argv, env=None):
        from tests.test_mcp_write_root import _main_in_process

        code, err, _serve, serve_http = _main_in_process("--mcp-server", *argv, env=env)
        self.assertEqual(code, 0, err)
        return err, serve_http.call_args.args[0]

    def test_happy_plain_http_gets_a_fresh_token_shown_once(self) -> None:
        err, config = self.run_main("--mcp-http", "127.0.0.1:7331")
        self.assertGreaterEqual(len(config.auth_token or ""), 32)
        self.assertIn(config.auth_token, err)
        self.assertIn("Authorization: Bearer", err)

    def test_sad_mtls_without_the_variable_needs_no_token(self) -> None:
        _err, config = self.run_main(
            "--mcp-http", "127.0.0.1:7331", "--mcp-cert", "c", "--mcp-key", "k", "--mcp-ca", "a"
        )
        self.assertIsNone(config.auth_token)

    def test_edge_the_variable_sets_a_stable_token(self) -> None:
        _err, config = self.run_main(
            "--mcp-http", "127.0.0.1:7331", env={"AXROSS_MCP_HTTP_TOKEN": "  stable-token-1234  "}
        )
        self.assertEqual(config.auth_token, "stable-token-1234")


if __name__ == "__main__":
    unittest.main()
