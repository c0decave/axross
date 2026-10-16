"""column_prefs.json with absurd numbers does not stop a pane from opening.

Found in review: ``column_prefs.load`` coerced widths and hidden columns
with ``int()`` and caught only TypeError / ValueError. ``1e400`` (JSON
infinity) raised OverflowError out of ``load``; a width of ``10**30``
loaded fine and then raised OverflowError in ``header.resizeSection``.
Both run in ``FilePaneWidget.__init__``, so the main window - which builds
a pane at start - did not open until the file was deleted.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui import column_prefs as CP  # noqa: E402


def _write(path: Path, widths: str, hidden: str = "[]") -> None:
    path.write_text(f'{{"version": {CP.VERSION}, "widths": {widths}, "hidden": {hidden}}}')


class LoadNumbersTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = self.dir / "column_prefs.json"

    def test_happy_plain_widths_load(self) -> None:
        _write(self.path, '{"1": 90, "2": 150}', "[3]")
        prefs = CP.load(self.path)
        self.assertEqual((prefs.widths, prefs.hidden), ({1: 90, 2: 150}, {3}))

    def test_sad_infinite_numbers_are_dropped(self) -> None:
        _write(self.path, '{"1": 1e400, "2": 150}', "[1e400, 3]")
        prefs = CP.load(self.path)
        self.assertEqual((prefs.widths, prefs.hidden), ({2: 150}, {3}))

    def test_edge_widths_no_screen_can_show_are_dropped(self) -> None:
        _write(self.path, json.dumps({"1": 10**30, "2": -5, "3": 150, "4": CP.MAX_WIDTH}))
        self.assertEqual(CP.load(self.path).widths, {3: 150, 4: CP.MAX_WIDTH})


class WindowStartTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def test_sad_the_window_opens_over_absurd_column_widths(self) -> None:
        from PyQt6.QtGui import QCloseEvent

        from ui import main_window as MW

        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        prefs = home / "column_prefs.json"
        _write(prefs, json.dumps({"1": 10**30}))
        with mock.patch.object(CP, "DEFAULT_PATH", prefs), \
                mock.patch.object(MW.MainWindow, "_SESSION_FILE", home / "session.json"), \
                mock.patch.object(MW.MainWindow, "_RECENTS_FILE", home / "recents.json"), \
                mock.patch("pathlib.Path.home", return_value=home):
            win = MW.MainWindow()
            self.addCleanup(win.deleteLater)
            self.assertTrue(win._panes)
            win.closeEvent(QCloseEvent())


if __name__ == "__main__":
    unittest.main()
