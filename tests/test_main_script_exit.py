"""``axross --script``: the script's sys.exit() is the process's exit, as with
``python script.py`` - a status, or a message on stderr and status 1."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _run_script(source: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "job.py"
        script.write_text(source, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(_ROOT / "main.py"), "--script", str(script)],
            cwd=str(_ROOT),
            env=dict(os.environ),  # conftest's home of its own
            capture_output=True,
            text=True,
            timeout=120,
        )


class ScriptExitTest(unittest.TestCase):
    def test_happy_an_exit_status_is_the_process_status(self) -> None:
        for source, code in (("pass\n", 0), ("import sys\nsys.exit(3)\n", 3)):
            with self.subTest(source=source):
                proc = _run_script(source)
                self.assertEqual(proc.returncode, code, proc.stderr[-2000:])
                self.assertNotIn("Traceback", proc.stderr)

    def test_sad_an_exit_message_goes_to_stderr_with_status_1(self) -> None:
        proc = _run_script("import sys\nsys.exit('no input given')\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no input given", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)  # was: ValueError from int()

    def test_edge_exit_none_and_non_int_values(self) -> None:
        for source, code, said in (
            ("raise SystemExit\n", 0, ""),
            ("import sys\nsys.exit(None)\n", 0, ""),
            ("import sys\nsys.exit(2.5)\n", 1, "2.5"),  # python: not a status
        ):
            with self.subTest(source=source):
                proc = _run_script(source)
                self.assertEqual(proc.returncode, code, proc.stderr[-2000:])
                self.assertIn(said, proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
