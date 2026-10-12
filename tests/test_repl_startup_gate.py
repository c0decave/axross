"""startup.py runs only when scripts are allowed and the file is the user's own."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from PyQt6.QtWidgets import QApplication

from core import security_mode


class StartupGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import repl_widget

        self.repl_widget = repl_widget
        self.dir = Path(tempfile.mkdtemp(prefix="axross-startup-"))
        repl_widget.HISTORY_PATH = self.dir / "history"
        self.marker = self.dir / "ran"
        self.script = self.dir / "startup.py"
        self.script.write_text(f"open({str(self.marker)!r}, 'w').write('x')\n")
        os.chmod(self.script, 0o600)

    def _open(self):
        return self.repl_widget.ReplWidget(startup_path=self.script)

    def test_owned_private_file_runs(self) -> None:
        self._open()
        self.assertTrue(self.marker.exists())

    def test_paranoid_mode_blocks_it(self) -> None:
        with mock.patch.object(
            security_mode, "current_policy", return_value=security_mode.PARANOID
        ):
            self._open()
        self.assertFalse(self.marker.exists())

    def test_group_or_world_writable_is_refused(self) -> None:
        os.chmod(self.script, 0o666)
        w = self._open()
        self.assertFalse(self.marker.exists())
        self.assertIn("writable", w.toPlainText())

    def test_symlink_is_refused(self) -> None:
        real = self.dir / "real.py"
        real.write_text(self.script.read_text())
        link = self.dir / "link.py"
        link.symlink_to(real)
        self.script = link
        self._open()
        self.assertFalse(self.marker.exists())

    def test_missing_file_is_silent(self) -> None:
        self.script.unlink()
        self._open()
        self.assertFalse(self.marker.exists())


if __name__ == "__main__":
    unittest.main()
