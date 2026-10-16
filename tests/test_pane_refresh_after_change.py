"""After an operation changes a folder, the pane reloads it off the GUI thread.

Before: every post-operation refresh (new folder, rename, delete, undo,
F5, and the debounced refresh of transfer targets during a running batch)
listed the folder synchronously on the GUI thread - a frozen window for
the duration of a remote listing, every debounce interval while a batch
runs. ``refresh_after_change`` loads in the background instead. It never
cuts off a navigation to another folder (the synchronous refresh did
not either), and it restarts a load of the same folder that may have
started before the change.
"""

from __future__ import annotations

import time
import unittest
from unittest import mock

from tests.test_pane_async_navigation import _Base


class RefreshAfterChangeTest(_Base):
    def test_happy_returns_at_once_and_shows_the_change(self) -> None:
        gate = self.fs.hold(str(self.root))
        (self.root / "made.txt").write_text("x")
        start = time.time()
        self.pane.refresh_after_change()
        self.assertLess(time.time() - start, 0.3)  # listing is held: GUI not blocked
        self.assertTrue(self.pane.is_loading)
        gate.set()
        self.assertTrue(self.settle())
        self.assertIn("made.txt", self.names())
        self.assertEqual(self.pane.current_path, str(self.root))

    def test_happy_new_folder_command_does_not_block(self) -> None:
        gate = self.fs.hold(str(self.root))
        with mock.patch("PyQt6.QtWidgets.QInputDialog.getText", return_value=("fresh", True)):
            start = time.time()
            self.pane._create_folder()
            self.assertLess(time.time() - start, 0.3)
        gate.set()
        self.assertTrue(self.settle())
        self.assertIn("fresh", self.names())

    def test_sad_a_navigation_elsewhere_is_not_cut_off(self) -> None:
        gate = self.fs.hold(self.p("a"))
        self.pane.navigate_async(self.p("a"))
        calls = len(self.fs.calls)
        self.pane.refresh_after_change()
        time.sleep(0.05)
        self.assertEqual(len(self.fs.calls), calls)  # no reload of the old folder
        gate.set()
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, self.p("a"))

    def test_edge_a_load_of_the_same_folder_is_restarted(self) -> None:
        # A quiet refresh that started BEFORE the change may miss it.
        stale_gate = self.fs.hold(str(self.root))
        self.pane.refresh_async(quiet=True)
        time.sleep(0.05)  # the stale listing is now inside list_dir, held
        (self.root / "late.txt").write_text("x")
        self.fs.gates.pop(str(self.root))
        self.pane.refresh_after_change()
        stale_gate.set()
        self.assertTrue(self.settle())
        time.sleep(0.1)
        self.app.processEvents()
        self.assertIn("late.txt", self.names())

    def test_edge_transfer_debounce_uses_the_background_refresh(self) -> None:
        from ui.main_window import MainWindow

        fake = mock.MagicMock()
        fake._transfer_target_panes = {self.pane}
        fake._panes = [self.pane]
        with mock.patch.object(type(self.pane), "refresh", side_effect=AssertionError("sync")):
            MainWindow._do_debounced_refresh(fake)
            MainWindow._on_all_transfers_finished(fake)
        self.assertTrue(self.settle())


if __name__ == "__main__":
    unittest.main()


class RefreshKeepsTheSelectionTest(_Base):
    """A reload of the same folder - F5, an operation, the watcher - kept no
    selection: the model reset dropped it, and the user's choice was gone
    whenever a file appeared in the folder."""

    def select(self, *names: str) -> None:
        from PyQt6.QtCore import QItemSelectionModel

        sel = self.pane._table.selectionModel()
        sel.clearSelection()
        for row in range(self.pane._proxy.rowCount()):
            index = self.pane._proxy.index(row, 0)
            if index.data() in names:
                sel.select(
                    index,
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )
                sel.setCurrentIndex(index, QItemSelectionModel.SelectionFlag.NoUpdate)

    def selected(self) -> list[str]:
        return sorted(i.name for i in self.pane.selected_file_items())

    def test_happy_a_refresh_keeps_the_selected_files(self) -> None:
        self.select("top.txt", "a")
        (self.root / "new.txt").write_text("x")
        self.pane.refresh_async(quiet=True)
        self.assertTrue(self.settle())
        self.assertIn("new.txt", self.names())
        self.assertEqual(self.selected(), ["a", "top.txt"])
        current = self.pane._table.selectionModel().currentIndex()
        self.assertIn(current.data(), ("a", "top.txt"))

    def test_sad_a_removed_file_leaves_the_selection(self) -> None:
        self.select("top.txt", "a")
        (self.root / "top.txt").unlink()
        self.pane.refresh_async(quiet=True)
        self.assertTrue(self.settle())
        self.assertEqual(self.selected(), ["a"])

    def test_edge_another_folder_starts_with_no_selection(self) -> None:
        self.select("a")
        self.pane.navigate_async(self.p("b"))
        self.assertTrue(self.settle())
        self.assertEqual(self.selected(), [])
