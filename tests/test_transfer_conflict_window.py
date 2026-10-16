"""F5 / F6 / drag & drop between two panes ask before replacing a file.

Measured before: copying ``f.txt`` from one local pane into a folder that
already holds an ``f.txt`` replaced it without a word, and a move then
deleted the source as well. Now the window checks the destination off the
GUI thread, asks per conflicting name (Overwrite / Skip / Rename /
Overwrite if newer, each optionally for all remaining, or Cancel), and
only then queues the jobs.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _Window(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui import main_window as MW

        self.MW = MW
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        env = mock.patch.dict(
            os.environ, {"AXROSS_OPERATION_JOURNAL": str(self.tmp / "operations.jsonl")}
        )
        env.start()
        self.addCleanup(env.stop)
        p = mock.patch.object(CP, "DEFAULT_PATH", self.tmp / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        home = self.tmp / "home"
        home.mkdir()
        with mock.patch("pathlib.Path.home", return_value=home):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.win._reconnect_timer.stop()
        for pane in list(self.win._panes)[1:]:
            self.win._close_pane(pane)
        self.a = self.tmp / "a"
        self.b = self.tmp / "b"
        self.a.mkdir()
        self.b.mkdir()
        self.left = self.win._panes[0]
        self.left.navigate(str(self.a))
        self.right = self.win._add_pane_to_splitter(
            self.win._root_splitter, type(self.left.backend)()
        )
        self.right.navigate(str(self.b))
        self.win._set_active_pane(self.left)
        self.win._set_target_pane(self.right)
        self.asked: list = []

    def wait_for(self, predicate, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def settle(self) -> None:
        """Let the destination check, the prompt and every queued job finish."""
        from core.transfer_worker import TransferStatus

        def idle() -> bool:
            if getattr(self.win, "_conflict_checks", None):
                return False
            jobs = list(self.win._transfer_manager._jobs.values())
            return all(
                j.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs
            )

        self.assertTrue(self.wait_for(idle))
        self.wait_for(lambda: False, timeout=0.2)
        self.assertTrue(self.wait_for(idle))

    def answer(self, *answers):
        """Patch the prompt; each call pops the next ``(action, apply_all)``."""
        queue = list(answers)

        def ask(_win, conflict, remaining):
            self.asked.append((conflict.name, remaining))
            return queue.pop(0) if queue else None

        p = mock.patch.object(self.MW.MainWindow, "_ask_transfer_conflict", ask, create=True)
        p.start()
        self.addCleanup(p.stop)

    def copy(self, *names) -> None:
        self.win._transfer_from_pane(self.left, [str(self.a / n) for n in names])
        self.settle()

    def move(self, *names) -> None:
        self.win._move_from_pane(self.left, [str(self.a / n) for n in names])
        self.settle()


class ConflictPromptTest(_Window):
    def setUp(self) -> None:
        super().setUp()
        (self.a / "f.txt").write_text("new")
        (self.b / "f.txt").write_text("old")

    def test_sad_skip_keeps_the_existing_file(self) -> None:
        from core.transfer_conflicts import ConflictAction

        self.answer((ConflictAction.SKIP, False))
        self.copy("f.txt")
        self.assertEqual(self.asked, [("f.txt", 0)])
        self.assertEqual((self.b / "f.txt").read_text(), "old")

    def test_happy_overwrite_replaces_it(self) -> None:
        from core.transfer_conflicts import ConflictAction

        self.answer((ConflictAction.OVERWRITE, False))
        self.copy("f.txt")
        self.assertEqual((self.b / "f.txt").read_text(), "new")

    def test_happy_rename_keeps_both(self) -> None:
        from core.transfer_conflicts import ConflictAction

        self.answer((ConflictAction.RENAME, False))
        self.copy("f.txt")
        self.assertEqual((self.b / "f.txt").read_text(), "old")
        self.assertEqual((self.b / "f (1).txt").read_text(), "new")

    def test_sad_cancel_queues_nothing_at_all(self) -> None:
        (self.a / "g.txt").write_text("free name")
        self.answer(None)
        self.copy("f.txt", "g.txt")
        self.assertEqual((self.b / "f.txt").read_text(), "old")
        self.assertFalse((self.b / "g.txt").exists())
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])

    def test_sad_a_skipped_move_keeps_its_source(self) -> None:
        from core.transfer_conflicts import ConflictAction

        self.answer((ConflictAction.SKIP, False))
        self.move("f.txt")
        self.assertEqual((self.a / "f.txt").read_text(), "new")
        self.assertEqual((self.b / "f.txt").read_text(), "old")

    def test_happy_drag_and_drop_asks_too(self) -> None:
        from core.transfer_conflicts import ConflictAction

        self.answer((ConflictAction.SKIP, False))
        self.win._on_drop_transfer(
            [str(self.a / "f.txt")], self.right, str(id(self.left)), True
        )
        self.settle()
        self.assertEqual(self.asked, [("f.txt", 0)])
        self.assertEqual((self.a / "f.txt").read_text(), "new")
        self.assertEqual((self.b / "f.txt").read_text(), "old")

    def test_edge_no_conflict_does_not_ask(self) -> None:
        (self.a / "g.txt").write_text("free name")
        self.answer()
        self.copy("g.txt")
        self.assertEqual(self.asked, [])
        self.assertEqual((self.b / "g.txt").read_text(), "free name")

    def test_edge_overwrite_if_newer_keeps_a_newer_destination(self) -> None:
        from core.transfer_conflicts import ConflictAction

        t = time.time() - 3600
        os.utime(self.a / "f.txt", (t, t))
        self.answer((ConflictAction.OVERWRITE_IF_NEWER, False))
        self.move("f.txt")
        self.assertEqual((self.b / "f.txt").read_text(), "old")
        self.assertEqual((self.a / "f.txt").read_text(), "new")

    def test_sad_an_unreadable_destination_queues_nothing(self) -> None:
        self.answer()
        with mock.patch("core.transfer_conflicts.scan_conflicts",
                        side_effect=OSError("listing refused")), \
                mock.patch("ui.main_window.QMessageBox.warning") as warn:
            self.copy("f.txt")
        self.assertTrue(warn.called)
        self.assertIn("listing refused", str(warn.call_args))
        self.assertEqual((self.b / "f.txt").read_text(), "old")
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])


class FolderMergeTest(_Window):
    def setUp(self) -> None:
        super().setUp()
        for side, text in ((self.a, "new"), (self.b, "old")):
            (side / "d" / "e").mkdir(parents=True)
            (side / "d" / "x.txt").write_text(text)
            (side / "d" / "e" / "y.txt").write_text(text)
        (self.a / "d" / "only-new.txt").write_text("new")
        (self.b / "d" / "only-old.txt").write_text("old")

    def test_happy_apply_to_all_answers_every_remaining_conflict(self) -> None:
        from core.transfer_conflicts import ConflictAction

        self.answer((ConflictAction.SKIP, True))
        self.copy("d")
        self.assertEqual(len(self.asked), 1)
        self.assertEqual(self.asked[0][1], 1)  # one more conflict after this one
        self.assertEqual((self.b / "d" / "x.txt").read_text(), "old")
        self.assertEqual((self.b / "d" / "e" / "y.txt").read_text(), "old")
        self.assertEqual((self.b / "d" / "only-new.txt").read_text(), "new")
        self.assertEqual((self.b / "d" / "only-old.txt").read_text(), "old")

    def test_edge_each_conflict_inside_a_merged_folder_is_asked(self) -> None:
        from core.transfer_conflicts import ConflictAction

        # Asked depth first in name order: d/e/y.txt, then d/x.txt.
        self.answer((ConflictAction.OVERWRITE, False), (ConflictAction.RENAME, False))
        self.copy("d")
        self.assertEqual(self.asked, [("y.txt", 1), ("x.txt", 0)])
        texts = {
            p.relative_to(self.b).as_posix(): p.read_text()
            for p in self.b.rglob("*.txt")
        }
        self.assertEqual(
            texts,
            {
                "d/e/y.txt": "new",
                "d/x.txt": "old",
                "d/x (1).txt": "new",
                "d/only-new.txt": "new",
                "d/only-old.txt": "old",
            },
        )

    def test_sad_a_move_merge_with_a_skip_keeps_the_skipped_source(self) -> None:
        from core.transfer_conflicts import ConflictAction

        self.answer((ConflictAction.SKIP, True))
        self.move("d")
        self.assertEqual((self.a / "d" / "x.txt").read_text(), "new")
        self.assertEqual((self.a / "d" / "e" / "y.txt").read_text(), "new")
        self.assertFalse((self.a / "d" / "only-new.txt").exists())
        self.assertEqual((self.b / "d" / "only-new.txt").read_text(), "new")


class ConflictDialogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def conflict(self, *, dest_is_dir=False):
        from core.transfer_conflicts import TransferConflict

        return TransferConflict(
            name="f.txt", source_path="/a/f.txt", dest_path="/b/f.txt", dest_dir="/b",
            source_is_dir=False, dest_is_dir=dest_is_dir,
            source_size=3, dest_size=4, source_mtime=2.0e9, dest_mtime=1.0e9,
        )

    def click(self, dialog, button, apply_all=False):
        dialog.apply_all.setChecked(apply_all)
        dialog.buttons[button].click()
        return dialog.result_choice()

    def test_happy_each_button_returns_its_action(self) -> None:
        from core.transfer_conflicts import ConflictAction
        from ui.transfer_conflict_dialog import TransferConflictDialog

        for action in ConflictAction:
            with self.subTest(action=action):
                dialog = TransferConflictDialog(self.conflict(), remaining=2)
                self.assertEqual(self.click(dialog, action, apply_all=True), (action, True))
                dialog.deleteLater()

    def test_sad_cancel_returns_none(self) -> None:
        from ui.transfer_conflict_dialog import TransferConflictDialog

        dialog = TransferConflictDialog(self.conflict(), remaining=0)
        dialog.reject()
        self.assertIsNone(dialog.result_choice())
        self.assertTrue(dialog.apply_all.isHidden())
        dialog.deleteLater()

    def test_edge_a_folder_in_the_way_cannot_be_overwritten(self) -> None:
        from core.transfer_conflicts import ConflictAction
        from ui.transfer_conflict_dialog import TransferConflictDialog

        dialog = TransferConflictDialog(self.conflict(dest_is_dir=True), remaining=0)
        self.assertFalse(dialog.buttons[ConflictAction.OVERWRITE].isEnabled())
        self.assertFalse(dialog.buttons[ConflictAction.OVERWRITE_IF_NEWER].isEnabled())
        self.assertTrue(dialog.buttons[ConflictAction.RENAME].isEnabled())
        dialog.deleteLater()


if __name__ == "__main__":
    unittest.main()
