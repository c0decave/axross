"""--mcp-write must name its root: $HOME as a writable root is a persistence vector."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
