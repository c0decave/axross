"""``--mcp-http`` refusals are one line with exit 2, and IPv6 works.

A non-loopback host without TLS and a
partial --mcp-cert/--mcp-key/--mcp-ca set ended in a Python traceback
(the ValueError of build_server), and "[::1]:7331" was refused with
"port ':1]:7331' is not an integer".
"""

from __future__ import annotations

import socket
import threading
import unittest
from unittest import mock

from core import mcp_http


def _main(*argv):
    from tests.test_mcp_write_root import _main_in_process

    return _main_in_process("--mcp-server", *argv)


class McpHttpAddressTest(unittest.TestCase):
    def test_happy_ipv6_loopback_in_brackets_is_parsed(self) -> None:
        code, err, _serve, serve_http = _main("--mcp-http", "[::1]:7331")
        self.assertEqual(code, 0, err)
        config = serve_http.call_args.args[0]
        self.assertEqual((config.host, config.port), ("::1", 7331))

    def test_sad_refusals_are_one_line_with_exit_2_and_no_token(self) -> None:
        cases = (
            (("--mcp-http", "0.0.0.0:7331"), "non-loopback"),
            (("--mcp-http", "127.0.0.1:7331", "--mcp-cert", "/x/c"), "together"),
            (("--mcp-http", "::1:7331"), "brackets"),
            (("--mcp-http", "127.0.0.1:99999"), "1..65535"),
        )
        for argv, needle in cases:
            with self.subTest(argv=argv):
                with mock.patch.object(mcp_http, "publish_token") as publish:
                    code, err, _serve, serve_http = _main(*argv)
                self.assertEqual(code, 2, err)
                self.assertEqual(len(err.strip().splitlines()), 1, err)
                self.assertIn(needle, err)
                self.assertNotIn("Traceback", err)
                serve_http.assert_not_called()
                publish.assert_not_called()  # no token handed out for nothing

    def test_edge_a_port_in_use_is_one_line_too(self) -> None:
        code, err = _run_bind_conflict()
        self.assertEqual(code, 2, err)
        self.assertIn("Address already in use", err)
        self.assertNotIn("Traceback", err)

    def test_edge_ipv6_server_binds_and_answers(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("no IPv6")
        try:
            server = mcp_http.build_server(
                mcp_http.HTTPServerConfig(backend=None, host="::1", port=0)
            )
        except OSError as exc:  # IPv6 loopback switched off on this host
            self.skipTest(f"::1 not bindable: {exc}")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            import http.client

            conn = http.client.HTTPConnection("::1", server.server_address[1], timeout=5)
            conn.request("GET", "/health")
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            fwd = getattr(server, "_mcp_log_forwarder", None)
            if fwd is not None:
                mcp_http._mcp._detach_log_forwarder(fwd)


def _run_bind_conflict():
    """main() with a real serve_http whose bind fails."""
    import contextlib
    import io
    import os
    import sys

    import main as axross_main

    stderr = io.StringIO()
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_MCP")}
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            mock.patch.object(sys, "argv", ["main.py", "--mcp-server", "--mcp-http", "127.0.0.1:7"])
        )
        stack.enter_context(mock.patch.dict(os.environ, clean_env, clear=True))
        stack.enter_context(mock.patch.object(axross_main, "setup_logging"))
        stack.enter_context(mock.patch.object(axross_main, "_install_excepthook"))
        stack.enter_context(mock.patch("core.i18n.install"))
        stack.enter_context(mock.patch("core.tmpfs_detect.apply_tempdir_preference"))
        stack.enter_context(mock.patch.object(mcp_http, "publish_token"))
        stack.enter_context(
            mock.patch.object(
                mcp_http, "serve_http", side_effect=OSError(98, "Address already in use")
            )
        )
        stack.enter_context(contextlib.redirect_stderr(stderr))
        code = axross_main.main()
    return code, stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
