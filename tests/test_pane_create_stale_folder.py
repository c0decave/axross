"""New Folder / New File / New Symlink / New Hardlink / Create XLink create
the entry in the folder the pane showed when the action started.

Found in review (round 2), the same defect class round 1 fixed for Rename,
Encrypt and Decrypt: each of these read ``_current_path`` only after its
input dialog closed. A folder load that finished while the dialog was open
moved ``_current_path``, so the entry appeared in the other folder - and a
symlink with a relative target then pointed at a different file there.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_pane_stale_targets import _Base  # noqa: E402


class CreateDuringFolderLoadTest(_Base):
    def start_slow_navigation_to_b(self):
        gate = self.fs.hold(str(self.root / "b"))
        self.pane.navigate_async(str(self.root / "b"))
        self.assertTrue(self.pane.is_loading)
        return gate

    def get_text(self, *answers):
        """getText stand-in: the folder load finishes during the first prompt."""
        gate = self.start_slow_navigation_to_b()
        queue = iter(answers)

        def fake(*_args, **_kwargs):
            value = next(queue)
            if not gate.is_set():
                return self.finish_load_then(gate, value)()
            return value

        return mock.patch("PyQt6.QtWidgets.QInputDialog.getText", side_effect=fake)

    # -- New Folder (F7, end to end through the key handler) -------------

    def test_happy_f7_without_navigation_creates_in_the_current_folder(self) -> None:
        from PyQt6.QtCore import Qt

        self.pane._table.setFocus()
        with mock.patch("PyQt6.QtWidgets.QInputDialog.getText", return_value=("new", True)):
            self.press(Qt.Key.Key_F7)
        self.assertTrue((self.root / "new").is_dir())

    def test_sad_f7_finishing_after_a_folder_change_creates_where_it_was_asked(self) -> None:
        from PyQt6.QtCore import Qt

        self.pane._table.setFocus()
        with self.get_text(("new", True)):
            self.press(Qt.Key.Key_F7)
        self.assertTrue((self.root / "new").is_dir())
        self.assertFalse((self.root / "b" / "new").exists())

    def test_edge_f7_name_taken_is_checked_in_the_folder_it_was_asked_in(self) -> None:
        from PyQt6.QtCore import Qt

        # exists.txt is taken in the root only.
        self.pane._table.setFocus()
        with self.get_text(("exists.txt", True)), mock.patch(
            "ui.file_pane.QMessageBox.warning"
        ) as warning:
            self.press(Qt.Key.Key_F7)
        warning.assert_called_once()
        self.assertEqual((self.root / "exists.txt").read_text(), "root exists")
        self.assertFalse((self.root / "b" / "exists.txt").exists())

    # -- New File ---------------------------------------------------------

    def test_sad_new_file_lands_in_the_folder_it_was_asked_in(self) -> None:
        with self.get_text(("new.txt", True)):
            self.pane._create_empty_file()
        self.assertEqual((self.root / "new.txt").read_bytes(), b"")
        self.assertFalse((self.root / "b" / "new.txt").exists())

    # -- New Symlink: a relative target resolves next to the link ---------

    def test_sad_symlink_points_at_the_file_next_to_where_it_was_asked(self) -> None:
        with self.get_text(("top.txt", True), ("ln", True)):
            self.pane._create_symlink()
        self.assertEqual((self.root / "ln").read_text(), "root copy")
        self.assertFalse((self.root / "b" / "ln").is_symlink())

    def test_sad_hardlink_lands_in_the_folder_it_was_asked_in(self) -> None:
        target = str(self.root / "top.txt")
        with self.get_text((target, True), ("hl", True)):
            self.pane._create_hardlink()
        self.assertEqual((self.root / "hl").read_text(), "root copy")
        self.assertFalse((self.root / "b" / "hl").exists())

    # -- Create XLink -----------------------------------------------------

    def test_sad_xlink_lands_in_the_folder_it_was_asked_in(self) -> None:
        from ui.create_xlink_dialog import CreateXlinkDialog

        gate = self.start_slow_navigation_to_b()
        with mock.patch.object(
            CreateXlinkDialog, "exec", side_effect=self.finish_load_then(gate, 1)
        ), mock.patch.object(CreateXlinkDialog, "name", return_value="link"), mock.patch.object(
            CreateXlinkDialog, "target_url", return_value="sftp://host/x"
        ), mock.patch.object(CreateXlinkDialog, "display_name", return_value=""), mock.patch(
            "ui.file_pane.QMessageBox.critical"
        ) as critical:
            self.pane._create_xlink()
        critical.assert_not_called()
        self.assertEqual(
            [p.name for p in self.root.glob("link*")], ["link.axlink"]
        )
        self.assertEqual(list((self.root / "b").glob("link*")), [])

    def test_edge_cancelled_dialog_creates_nothing_anywhere(self) -> None:
        with self.get_text(("", False)):
            self.pane._create_folder()
        before_root = sorted(p.name for p in self.root.iterdir())
        self.assertNotIn("", before_root)
        self.assertEqual(sorted(p.name for p in (self.root / "b").iterdir()), ["top.txt"])



class DirSizeDuringFolderLoadTest(_Base):
    """Calculate Size measures the folder that was selected when it started;
    a folder load finishing while the size is walked in the background must
    not make it measure another folder."""

    def run_size(self, *, load_finishes: bool):
        self.select("b")
        gate = self.fs.hold(str(self.root / "b"))
        if load_finishes:
            self.pane.navigate_async(str(self.root / "b"))
        with mock.patch("ui.file_pane.QMessageBox.information") as info:
            self.pane._calculate_dir_size()
            gate.set()  # the load (if any) and the walk both go on now
            self.assertTrue(self.settle())
            end = time.time() + 5
            while not info.called and time.time() < end:
                self.app.processEvents()
                time.sleep(0.005)
        return info.call_args[0][2]

    def test_happy_size_of_the_selected_folder(self) -> None:
        self.assertEqual(self.run_size(load_finishes=False), "b: 6 B")

    def test_sad_a_load_finishing_in_the_pump_does_not_change_what_is_measured(self) -> None:
        self.assertEqual(self.run_size(load_finishes=True), "b: 6 B")

    def test_edge_nothing_selected_measures_nothing(self) -> None:
        with mock.patch("ui.file_pane.QMessageBox.information") as info:
            self.pane._calculate_dir_size()
        info.assert_not_called()


if __name__ == "__main__":
    unittest.main()
