"""Mouse buttons in the file pane: side button = history, wheel click = open."""

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


class PaneMouseButtonsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.local_fs import LocalFS
        from ui import column_prefs as CP
        from ui.file_pane import FilePaneWidget

        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / "sub" / "deep").mkdir(parents=True)
        (self.root / "note.txt").write_text("hello", encoding="utf-8")
        patcher = mock.patch.object(CP, "DEFAULT_PATH", self.root / "column_prefs.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.pane = FilePaneWidget(LocalFS())
        self.addCleanup(self.pane.deleteLater)
        self.pane.resize(900, 500)
        self.pane.show()
        self.pane.navigate(str(self.root))
        self.app.processEvents()

    def _settle(self) -> None:
        """Navigation from the UI loads in the background: wait for it."""
        import time

        end = time.time() + 3
        while time.time() < end:
            self.app.processEvents()
            if not self.pane.is_loading:
                return
            time.sleep(0.002)

    def _row_pos(self, name: str):
        proxy = self.pane._proxy
        for row in range(proxy.rowCount()):
            idx = proxy.index(row, 0)
            if proxy.data(idx) == name:
                return self.pane._table.visualRect(idx).center()
        self.fail(f"row {name!r} not listed")

    def _click(self, button, pos) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        QTest.mouseClick(self.pane._table.viewport(), button, Qt.KeyboardModifier.NoModifier, pos)
        self._settle()

    def test_back_button_goes_back_in_history(self) -> None:
        from PyQt6.QtCore import Qt

        self.pane.navigate(str(self.root / "sub"))
        self._click(Qt.MouseButton.BackButton, self.pane._table.viewport().rect().center())
        self.assertEqual(self.pane.current_path, str(self.root))

    def test_forward_button_goes_forward_again(self) -> None:
        from PyQt6.QtCore import Qt

        self.pane.navigate(str(self.root / "sub"))
        pos = self.pane._table.viewport().rect().center()
        self._click(Qt.MouseButton.BackButton, pos)
        self.assertEqual(self.pane.current_path, str(self.root))
        self._click(Qt.MouseButton.ForwardButton, pos)
        self.assertEqual(self.pane.current_path, str(self.root / "sub"))

    def test_back_with_no_history_does_nothing(self) -> None:
        from PyQt6.QtCore import Qt

        self.pane._history = [str(self.root)]
        self.pane._history_pos = 0
        self._click(Qt.MouseButton.BackButton, self.pane._table.viewport().rect().center())
        self.assertEqual(self.pane.current_path, str(self.root))

    def test_back_button_works_on_the_pane_outside_the_table(self) -> None:
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        self.pane.navigate(str(self.root / "sub"))
        no_mods = Qt.KeyboardModifier.NoModifier
        QTest.mouseClick(self.pane._status, Qt.MouseButton.BackButton, no_mods, QPoint(2, 2))
        self._settle()
        self.assertEqual(self.pane.current_path, str(self.root))

    def test_wheel_click_opens_the_directory_under_the_mouse(self) -> None:
        from PyQt6.QtCore import Qt

        self._click(Qt.MouseButton.MiddleButton, self._row_pos("sub"))
        self.assertEqual(self.pane.current_path, str(self.root / "sub"))

    def test_wheel_click_opens_without_selecting_first(self) -> None:
        from PyQt6.QtCore import Qt

        self.pane._table.clearSelection()
        self._click(Qt.MouseButton.MiddleButton, self._row_pos("sub"))
        self.assertEqual(self.pane.current_path, str(self.root / "sub"))

    def test_wheel_click_opens_the_row_under_the_mouse_not_the_selected_one(self) -> None:
        from PyQt6.QtCore import Qt

        self.pane._table.selectRow(self.pane._proxy.rowCount() - 1)
        self._click(Qt.MouseButton.MiddleButton, self._row_pos("sub"))
        self.assertEqual(self.pane.current_path, str(self.root / "sub"))

    def test_wheel_click_on_a_file_uses_the_double_click_path(self) -> None:
        from PyQt6.QtCore import Qt

        with mock.patch.object(self.pane, "_on_double_click") as opened:
            self._click(Qt.MouseButton.MiddleButton, self._row_pos("note.txt"))
        opened.assert_called_once()
        item = self.pane._model.get_item(self.pane._proxy.mapToSource(opened.call_args[0][0]).row())
        self.assertEqual(item.name, "note.txt")

    def test_wheel_click_on_empty_space_is_a_noop(self) -> None:
        from PyQt6.QtCore import QPoint, Qt

        before = self.pane.current_path
        vp = self.pane._table.viewport()
        self._click(Qt.MouseButton.MiddleButton, QPoint(vp.width() // 2, vp.height() - 3))
        self.assertEqual(self.pane.current_path, before)

    def test_left_click_still_selects_and_does_not_navigate(self) -> None:
        from PyQt6.QtCore import Qt

        self._click(Qt.MouseButton.LeftButton, self._row_pos("sub"))
        self.assertEqual(self.pane.current_path, str(self.root))
        self.assertEqual(len(self.pane._table.selectionModel().selectedRows()), 1)


if __name__ == "__main__":
    unittest.main()
