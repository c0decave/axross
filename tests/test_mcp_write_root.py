"""--mcp-write must name its root: $HOME as a writable root is a persistence vector."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    env.pop("AXROSS_MCP_WRITE", None)
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "main.py"), *args],
        input=stdin, capture_output=True, text=True, timeout=60, env=env, cwd=ROOT,
    )


class McpWriteRootTest(unittest.TestCase):
    def test_write_without_root_is_refused(self) -> None:
        proc = _run("--mcp-server", "--mcp-write")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("--mcp-root", proc.stderr)

    def test_write_via_env_without_root_is_refused(self) -> None:
        env = dict(os.environ, AXROSS_MCP_WRITE="1", AXROSS_MCP="1", QT_QPA_PLATFORM="offscreen")
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py")],
            input="", capture_output=True, text=True, timeout=60, env=env, cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_write_with_explicit_root_starts(self) -> None:
        proc = _run("--mcp-server", "--mcp-write", "--mcp-root", tempfile.mkdtemp())
        self.assertEqual(proc.returncode, 0, proc.stderr)  # EOF on stdin ends the server

    def test_read_only_default_still_starts(self) -> None:
        proc = _run("--mcp-server")
        self.assertEqual(proc.returncode, 0, proc.stderr)


def _main_in_process(*argv: str, env: dict | None = None):
    """Run main.main() in this process with both MCP transports mocked.

    Returns ``(exit_code, stderr_text, serve_mock, serve_http_mock)`` so a
    test can tell "refused before any server started" from "started".
    Boot steps with process-wide side effects (root logging handlers,
    sys.excepthook, the active translator, the tmpfs temp directory) are
    stubbed out.
    """
    import contextlib
    import io
    from unittest import mock

    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    import main as axross_main
    from core import mcp_http as MH
    from core import mcp_server as M

    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_MCP")}
    clean_env.update(env or {})
    stderr = io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.object(sys, "argv", ["main.py", *argv]))
        stack.enter_context(mock.patch.dict(os.environ, clean_env, clear=True))
        stack.enter_context(mock.patch.object(axross_main, "setup_logging"))
        stack.enter_context(mock.patch.object(axross_main, "_install_excepthook"))
        stack.enter_context(mock.patch("core.i18n.install"))
        # main() would point tempfile at tmpfs for the rest of the process.
        stack.enter_context(mock.patch("core.tmpfs_detect.apply_tempdir_preference"))
        serve = stack.enter_context(mock.patch.object(M, "serve", return_value=0))
        serve_http = stack.enter_context(mock.patch.object(MH, "serve_http"))
        # The bearer token file of --mcp-http stays out of the runtime dir.
        stack.enter_context(
            mock.patch.object(MH, "publish_token", return_value=Path("/nonexistent/token"))
        )
        stack.enter_context(contextlib.redirect_stderr(stderr))
        code = axross_main.main()
    return code, stderr.getvalue(), serve, serve_http


class InProcessMainSideEffectsTest(unittest.TestCase):
    def test_in_process_main_leaves_the_temp_directory_alone(self) -> None:
        # main() routes tempfile to tmpfs (core.tmpfs_detect); run in the
        # test process that moved every later test's temp files and broke
        # the suite's home-isolation check.
        import tempfile

        before = tempfile.tempdir
        _main_in_process("--mcp-server")
        self.assertEqual(tempfile.tempdir, before)


class McpAllowScriptsTransportTest(unittest.TestCase):
    """--mcp-allow-scripts is a stdio-only switch; HTTP must refuse it loudly."""

    def test_allow_scripts_with_http_is_refused_before_any_server_starts(self) -> None:
        code, err, serve, serve_http = _main_in_process(
            "--mcp-server", "--mcp-allow-scripts", "--mcp-http", "127.0.0.1:7331"
        )
        self.assertEqual(code, 2, err)
        self.assertIn("--mcp-allow-scripts", err)
        self.assertIn("--mcp-http", err)
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        serve_http.assert_not_called()
        serve.assert_not_called()

    def test_allow_scripts_with_http_via_env_activation_is_refused(self) -> None:
        # Edge: the server is switched on through AXROSS_MCP=1 instead of
        # --mcp-server; the transport check must not depend on which one.
        code, err, serve, serve_http = _main_in_process(
            "--mcp-allow-scripts", "--mcp-http", "127.0.0.1:7331", env={"AXROSS_MCP": "1"}
        )
        self.assertEqual(code, 2, err)
        serve_http.assert_not_called()
        serve.assert_not_called()

    def test_allow_scripts_with_malformed_http_address_is_still_refused(self) -> None:
        # Edge: the combination is refused even when the address would
        # also have been rejected — the refusal names the real problem.
        code, err, serve, serve_http = _main_in_process(
            "--mcp-server", "--mcp-allow-scripts", "--mcp-http", "no-port"
        )
        self.assertEqual(code, 2, err)
        self.assertIn("--mcp-allow-scripts", err)
        serve_http.assert_not_called()

    def test_allow_scripts_on_stdio_is_still_accepted(self) -> None:
        code, err, serve, serve_http = _main_in_process("--mcp-server", "--mcp-allow-scripts")
        self.assertEqual(code, 0, err)
        serve.assert_called_once()
        self.assertTrue(serve.call_args.args[0].allow_scripts)
        serve_http.assert_not_called()

    def test_http_without_allow_scripts_still_starts(self) -> None:
        code, err, serve, serve_http = _main_in_process(
            "--mcp-server", "--mcp-http", "127.0.0.1:7331"
        )
        self.assertEqual(code, 0, err)
        serve_http.assert_called_once()
        config = serve_http.call_args.args[0]
        self.assertEqual((config.host, config.port), ("127.0.0.1", 7331))
        serve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
