"""Ctrl+Alt+L asks before a layout switch closes shells or connections.

Cycling the layout preset tears every pane down
- a running shell in a terminal pane was killed and remote panes were
disconnected - with no question asked, on a key chord that is easy to hit
by accident.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class LayoutCycleConfirmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        from ui import main_window as MW

        self.MW = MW
        self.Yes = QMessageBox.StandardButton.Yes
        self.No = QMessageBox.StandardButton.No
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        env = mock.patch.dict(os.environ, {"SHELL": "/bin/sh"})
        env.start()
        self.addCleanup(env.stop)
        with mock.patch("pathlib.Path.home", return_value=Path(self.home)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.asked: list = []
        self.answer = self.No

    def ask(self, *args, **_kw):
        self.asked.append(args[2])
        return self.answer

    def add_shell(self):
        term = self.win._preset_make_terminal_pane("local", cwd=self.home)
        self.win._root_splitter.addWidget(term)
        return term

    def cycle(self):
        with mock.patch.object(self.MW.QMessageBox, "question", side_effect=self.ask):
            self.win.cycle_layout_preset(forward=True)

    def test_happy_no_keeps_the_layout_and_the_running_shell(self) -> None:
        term = self.add_shell()
        panes_before = list(self.win._panes)
        self.cycle()
        self.assertEqual(len(self.asked), 1)
        self.assertIn("1 shell", self.asked[0])
        self.assertTrue(term.is_running)
        self.assertIn(term, self.win._terminal_panes)
        self.assertEqual(self.win._panes, panes_before)

    def test_sad_yes_switches_and_closes_the_shell(self) -> None:
        term = self.add_shell()
        self.answer = self.Yes
        self.cycle()
        self.assertEqual(len(self.asked), 1)
        self.assertFalse(term.is_running)
        self.assertNotIn(term, self.win._terminal_panes)

    def test_edge_nothing_to_lose_switches_without_a_question(self) -> None:
        before = getattr(self.win, "_current_preset_name", None)
        self.cycle()
        self.assertEqual(self.asked, [])
        self.assertNotEqual(getattr(self.win, "_current_preset_name", None), before)

    def test_edge_a_remote_pane_is_named_in_the_question(self) -> None:
        pane = self.win._panes[0]
        profile = mock.Mock()
        profile.name = "srv"
        self.win._pane_profiles[pane] = profile
        self.addCleanup(self.win._pane_profiles.clear)
        self.cycle()
        self.assertEqual(len(self.asked), 1)
        self.assertIn("1 connection", self.asked[0])
        self.assertIn(pane, self.win._panes)

    # -- View > Layout Preset > <preset> (review round 6, F1/F2) -------------
    # The menu entries went straight to apply_layout_preset: a running shell
    # and remote connections were closed unasked. And every pane of the new
    # layout opened the home folder instead of the folders the user was in.

    def menu_entry(self, name: str):
        from PyQt6.QtGui import QAction

        from ui.layout_presets import preset_label

        label = preset_label(name).replace("&", "")
        return next(a for a in self.win.findChildren(QAction)
                    if a.text().replace("&", "") == label)

    def pick(self, name: str):
        with mock.patch.object(self.MW.QMessageBox, "question", side_effect=self.ask):
            self.menu_entry(name).trigger()

    def test_sad_the_menu_entry_asks_before_closing_a_running_shell(self) -> None:
        term = self.add_shell()
        panes_before = list(self.win._panes)
        self.pick("dual")
        self.assertEqual(len(self.asked), 1)
        self.assertTrue(term.is_running)
        self.assertIn(term, self.win._terminal_panes)
        self.assertEqual(self.win._panes, panes_before)
        self.answer = self.Yes
        self.pick("dual")
        self.assertEqual(len(self.asked), 2)
        self.assertNotIn(term, self.win._terminal_panes)

    def test_happy_the_new_layout_keeps_the_folders_of_the_active_and_target_pane(self) -> None:
        a = Path(self.home) / "a"
        b = Path(self.home) / "b"
        a.mkdir()
        b.mkdir()
        self.pick("dual")
        first, second = self.win._panes[:2]
        first.navigate(str(a))
        second.navigate(str(b))
        self.win._set_active_pane(first)
        self.win._target_pane = second
        self.pick("quad-files")
        self.assertEqual(self.asked, [])
        paths = [p.current_path for p in self.win._panes]
        self.assertEqual(len(paths), 4)
        self.assertEqual(paths[:2], [str(a), str(b)])

    def test_edge_a_remote_active_pane_is_not_carried(self) -> None:
        from ui.layout_presets import _carried_paths

        from types import SimpleNamespace

        from core.local_fs import LocalFS

        remote = SimpleNamespace(backend=mock.Mock(), current_path=self.home)
        local = SimpleNamespace(backend=LocalFS(), current_path=self.home)
        owner = SimpleNamespace(_active_pane=remote, _target_pane=local)
        self.assertEqual(_carried_paths(owner), [None, self.home])


if __name__ == "__main__":
    unittest.main()
