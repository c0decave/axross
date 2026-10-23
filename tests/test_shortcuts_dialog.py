"""F1 help: scrollable, searchable with '/', complete; Ctrl+Shift+B bookmarks.

Before: F1 opened a QMessageBox with the whole table as HTML - no scroll
area, so everything below the screen edge was out of reach, no search,
German text in the code, F8 described as delete although the window binds
it to "Add Current Directory", and eight window shortcuts missing.
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

import core.bookmarks as BM  # noqa: E402


class _Qt(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


def _key(widget, key, mods=None) -> None:
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    QTest.keyClick(widget, key, mods or Qt.KeyboardModifier.NoModifier)


class ShortcutsDialogTest(_Qt):
    def _dlg(self):
        from ui.shortcuts_dialog import ShortcutsDialog

        dlg = ShortcutsDialog()
        self.addCleanup(dlg.deleteLater)
        dlg.resize(500, 300)
        dlg.show()
        self.app.processEvents()
        return dlg

    def _visible_rows(self, dlg) -> list[tuple[str, str]]:
        tree = dlg.tree
        rows = []
        for i in range(tree.topLevelItemCount()):
            section = tree.topLevelItem(i)
            for j in range(section.childCount()):
                item = section.child(j)
                if not item.isHidden():
                    rows.append((item.text(0), item.text(1)))
        return rows

    def test_happy_a_long_list_scrolls_with_the_keyboard(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self._dlg()
        bar = dlg.tree.verticalScrollBar()
        self.assertGreater(bar.maximum(), 0)  # more rows than fit: a scroll area
        dlg.tree.setFocus()
        _key(dlg.tree, Qt.Key.Key_End)
        self.app.processEvents()
        last = dlg.tree.currentItem()
        self.assertEqual(last.text(1), "Rearrange panes")  # the last row of the list
        self.assertEqual(bar.value(), bar.maximum())
        self.assertTrue(dlg.tree.viewport().rect().contains(dlg.tree.visualItemRect(last)))
        _key(dlg.tree, Qt.Key.Key_Home)
        self.app.processEvents()
        self.assertEqual(bar.value(), 0)

    def test_happy_slash_focuses_the_search_and_typing_filters(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        dlg = self._dlg()
        dlg.tree.setFocus()
        _key(dlg.tree, Qt.Key.Key_Slash)
        self.app.processEvents()
        self.assertTrue(dlg.search.hasFocus())
        self.assertEqual(dlg.search.text(), "")  # the '/' is not typed into it
        QTest.keyClicks(dlg.search, "zoom")
        self.assertEqual(
            self._visible_rows(dlg), [("Ctrl+= / Ctrl+- / Ctrl+0", "Zoom in / out / reset")]
        )

    def test_happy_search_matches_keys_and_section_names(self) -> None:
        dlg = self._dlg()
        dlg.search.setText("f8")
        self.assertEqual(
            self._visible_rows(dlg), [("F8 / Ctrl+Shift+B", "Bookmark the current folder")]
        )
        dlg.search.setText("pane management")
        self.assertGreaterEqual(len(self._visible_rows(dlg)), 7)

    def test_sad_no_match_shows_a_hint_and_no_rows(self) -> None:
        dlg = self._dlg()
        dlg.search.setText("no-such-shortcut")
        self.assertEqual(self._visible_rows(dlg), [])
        self.assertTrue(dlg.empty_hint.isVisibleTo(dlg))
        dlg.search.setText("")
        self.assertFalse(dlg.empty_hint.isVisibleTo(dlg))
        self.assertEqual(len(self._visible_rows(dlg)), sum(1 for _ in dlg.entries))

    def test_edge_escape_clears_the_search_first_then_closes(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self._dlg()
        dlg.search.setFocus()
        dlg.search.setText("tab")
        _key(dlg.search, Qt.Key.Key_Escape)
        self.assertEqual(dlg.search.text(), "")
        self.assertTrue(dlg.isVisible())
        _key(dlg.search, Qt.Key.Key_Escape)
        self.assertFalse(dlg.isVisible())

    def test_edge_escape_in_the_list_clears_an_active_search_first(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self._dlg()
        dlg.search.setText("bookmark")
        dlg.tree.setFocus()
        self.app.processEvents()
        _key(dlg.tree, Qt.Key.Key_Escape)
        self.assertEqual(dlg.search.text(), "")
        self.assertTrue(dlg.isVisible())
        _key(dlg.tree, Qt.Key.Key_Escape)
        self.assertFalse(dlg.isVisible())

    def test_sad_the_close_button_closes_even_with_an_active_search(self) -> None:
        from PyQt6.QtWidgets import QDialogButtonBox

        dlg = self._dlg()
        dlg.search.setText("tab")
        box = dlg.findChild(QDialogButtonBox)
        box.button(QDialogButtonBox.StandardButton.Close).click()
        self.assertFalse(dlg.isVisible())

    def test_edge_down_from_the_search_moves_into_the_list(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self._dlg()
        dlg.search.setFocus()
        dlg.search.setText("copy")
        _key(dlg.search, Qt.Key.Key_Down)
        self.assertTrue(dlg.tree.hasFocus())
        self.assertFalse(dlg.tree.currentItem().isHidden())
        self.assertIsNotNone(dlg.tree.currentItem().parent())  # a row, not a section

    def test_edge_the_text_is_english(self) -> None:
        from ui.shortcuts_dialog import SHORTCUTS

        text = " ".join(f"{s} {d}" for s, _k, d in SHORTCUTS)
        for word in ("Umbenennen", "Löschen", "Kopieren", "Verzeichnis", "Lesezeichen", "Auswahl"):
            self.assertNotIn(word, text)

    def test_sad_return_in_the_search_does_not_close_the_dialog(self) -> None:
        from PyQt6.QtCore import Qt

        dlg = self._dlg()
        dlg.search.setFocus()
        dlg.search.setText("copy")
        _key(dlg.search, Qt.Key.Key_Return)
        self.assertTrue(dlg.isVisible())

    def test_edge_slash_works_from_the_close_button_too(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QPushButton

        dlg = self._dlg()
        button = dlg.findChild(QPushButton)
        button.setFocus()
        _key(button, Qt.Key.Key_Slash)
        self.assertTrue(dlg.search.hasFocus())

    def test_happy_the_search_finds_the_translated_text(self) -> None:
        from unittest import mock

        from ui import shortcuts_dialog as SD

        with mock.patch.object(
            SD, "tr", side_effect=lambda t: "Aktualisieren" if t == "Refresh" else t
        ):
            dlg = self._dlg()
        dlg.search.setText("aktualis")
        self.assertEqual(self._visible_rows(dlg), [("Ctrl+R", "Aktualisieren")])


class MainWindowShortcutsTest(_Qt):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        cls._orig = BM.BOOKMARKS_FILE
        BM.BOOKMARKS_FILE = Path(cls._home) / "bookmarks.json"
        from ui.main_window import MainWindow

        cls.win = MainWindow()
        cls.win.show()
        cls.app.processEvents()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.win.close()
        cls.win.deleteLater()
        BM.BOOKMARKS_FILE = cls._orig
        cls._patch.stop()
        shutil.rmtree(cls._home, ignore_errors=True)

    def _window_shortcuts(self) -> set[str]:
        from PyQt6.QtGui import QAction, QKeySequence

        fmt = QKeySequence.SequenceFormat.PortableText
        return {ks.toString(fmt) for a in self.win.findChildren(QAction) for ks in a.shortcuts()}

    def test_happy_every_window_shortcut_is_listed_in_the_help(self) -> None:
        from ui.shortcuts_dialog import SHORTCUTS

        listed = {k for _s, keys, _d in SHORTCUTS for k in keys}
        bound = self._window_shortcuts()
        self.assertGreater(len(bound), 20)
        self.assertEqual(sorted(bound - listed), [])

    def test_happy_ctrl_shift_b_bookmarks_the_active_folder(self) -> None:
        from PyQt6.QtCore import Qt

        self.assertIn("Ctrl+Shift+B", self._window_shortcuts())
        pane = self.win._active_pane
        calls = []
        with mock.patch.object(
            self.win, "_on_bookmark_request", side_effect=lambda *a: calls.append(a)
        ):
            pane._table.setFocus()
            self.app.processEvents()
            _key(
                pane._table,
                Qt.Key.Key_B,
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
            )
            self.app.processEvents()
        # The pane is passed along so a remote bookmark keeps its profile.
        self.assertEqual(calls, [(pane.current_path, pane.backend.name, pane)])

    def test_sad_f8_still_bookmarks_and_does_not_delete(self) -> None:
        from PyQt6.QtCore import Qt

        pane = self.win._active_pane
        calls = []
        with (
            mock.patch.object(
                self.win, "_on_bookmark_request", side_effect=lambda *a: calls.append("bookmark")
            ),
            mock.patch.object(pane, "_delete_selected", side_effect=lambda: calls.append("delete")),
        ):
            pane._table.setFocus()
            self.app.processEvents()
            _key(pane._table, Qt.Key.Key_F8)
            self.app.processEvents()
        self.assertEqual(calls, ["bookmark"])

    def test_edge_f1_opens_the_dialog_not_a_message_box(self) -> None:
        from ui import shortcuts_dialog

        with (
            mock.patch.object(shortcuts_dialog.ShortcutsDialog, "exec", return_value=0) as ex,
            mock.patch("ui.main_window.QMessageBox.information") as box,
        ):
            self.win._show_shortcuts()
        ex.assert_called_once()
        box.assert_not_called()

    def test_edge_closed_help_dialogs_do_not_pile_up(self) -> None:
        from PyQt6.QtWidgets import QDialog

        from ui import shortcuts_dialog
        from ui.settings_dialog import SettingsDialog

        def children():
            self.app.processEvents()
            from PyQt6.QtCore import QCoreApplication, QEvent

            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
            return [
                d
                for d in self.win.findChildren(QDialog)
                if isinstance(d, (shortcuts_dialog.ShortcutsDialog, SettingsDialog))
            ]

        before = len(children())
        with (
            mock.patch.object(shortcuts_dialog.ShortcutsDialog, "exec", return_value=0),
            mock.patch.object(SettingsDialog, "exec", return_value=0),
        ):
            for _ in range(3):
                self.win._show_shortcuts()
                self.win._show_llm_profiles()
        self.assertEqual(len(children()), before)


if __name__ == "__main__":
    unittest.main()
