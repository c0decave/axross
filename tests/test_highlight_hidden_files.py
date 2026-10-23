"""Highlight Hidden Files (Edit > Settings > Appearance; once View > Highlight
Hidden Files): hidden entries look different from the rest.

Operator: *„option einbauen, dass versteckte dateien gesondert
hervorgehoben werden, per default an."* With Show Hidden Files on, a dotfile
and a plain file looked the same. Now a hidden entry (dot name or the
backend's hidden flag, ``FileItem.is_hidden``) is drawn in italics and in the
theme's muted text colour - the colour only where it stays readable (WCAG AA,
4.5:1 against both row backgrounds), italics always. One window-wide switch,
on by default, kept in session.json like Show Hidden Files.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from models.file_item import FileItem  # noqa: E402


def _item(name: str, *, attr_hidden: bool = False, is_dir: bool = False) -> FileItem:
    return FileItem(
        name=name, size=1, modified=datetime(2026, 1, 1), permissions=0o644,
        is_dir=is_dir, attr_hidden=attr_hidden,
    )


def _destroy(win) -> None:
    from PyQt6 import sip
    from PyQt6.QtCore import QCoreApplication, QEvent

    if win is None or sip.isdeleted(win):
        return
    win.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


class _QtCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


# --- the colour rule --------------------------------------------------------


class MutedColourTest(_QtCase):
    def palette(self, base: str, alt: str, muted: str):
        from PyQt6.QtGui import QColor, QPalette

        pal = QPalette()
        pal.setColor(QPalette.ColorRole.Base, QColor(base))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(alt))
        pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(muted))
        return pal

    def test_happy_a_readable_muted_colour_is_used(self) -> None:
        from ui.themes import hidden_entry_color

        colour = hidden_entry_color(self.palette("#1b1e25", "#232731", "#9aa1b2"))
        self.assertIsNotNone(colour)
        self.assertEqual(colour.name(), "#9aa1b2")

    def test_sad_an_unreadable_muted_colour_is_not_used(self) -> None:
        from ui.themes import hidden_entry_color

        # Light grey on white: about 2.3:1, below WCAG AA.
        self.assertIsNone(hidden_entry_color(self.palette("#ffffff", "#f5f5f5", "#a0a0a0")))

    def test_edge_the_alternate_row_counts_too(self) -> None:
        from ui.themes import hidden_entry_color

        # Readable on the base row (#ffffff, 4.6:1) but not on a darker
        # alternate row (#d0d0d0) - the lower of the two decides.
        self.assertIsNone(hidden_entry_color(self.palette("#ffffff", "#d0d0d0", "#757575")))

    def test_edge_every_shipped_theme_gets_a_readable_colour(self) -> None:
        from ui import themes

        for resolved in ("modern-dark", "modern-light", "classic", "hacker", "amber"):
            with self.subTest(theme=resolved):
                tokens = themes.palette_tokens_for(resolved)
                self.assertIsNotNone(tokens)
                colour = themes.hidden_entry_color(themes.qpalette_for(tokens))
                self.assertIsNotNone(colour, resolved)
                self.assertEqual(colour.name(), tokens["text_muted"].lower())

    def test_contrast_math(self) -> None:
        from ui.themes import contrast_ratio

        self.assertAlmostEqual(contrast_ratio("#000000", "#ffffff"), 21.0, places=1)
        self.assertAlmostEqual(contrast_ratio("#777777", "#777777"), 1.0, places=3)


# --- the model --------------------------------------------------------------


class _ModelCase(_QtCase):
    def setUp(self) -> None:
        from models.file_table_model import FileTableModel

        self.model = FileTableModel()
        self.model.set_items([
            _item(".."), _item(".env"), _item("desktop.ini", attr_hidden=True),
            _item("plain.txt"), _item(".git", is_dir=True),
        ])

    def roles(self, name: str, column: int = 0):
        from PyQt6.QtCore import Qt

        for row in range(self.model.rowCount()):
            if self.model.get_item(row).name == name:
                idx = self.model.index(row, column)
                return (
                    self.model.data(idx, Qt.ItemDataRole.FontRole),
                    self.model.data(idx, Qt.ItemDataRole.ForegroundRole),
                )
        self.fail(f"{name} not in the model")


class ModelRolesTest(_ModelCase):

    def test_happy_dot_names_and_flagged_entries_are_italic_by_default(self) -> None:
        self.assertTrue(self.model.highlight_hidden)
        for name in (".env", "desktop.ini", ".git"):
            with self.subTest(name=name):
                font, _ = self.roles(name)
                self.assertIsNotNone(font)
                self.assertTrue(font.italic())

    def test_happy_every_column_of_a_hidden_row_is_marked(self) -> None:
        from models.file_table_model import COLUMNS

        for column in range(len(COLUMNS)):
            with self.subTest(column=column):
                font, _ = self.roles(".env", column)
                self.assertTrue(font is not None and font.italic())

    def test_happy_the_colour_follows_the_application_palette(self) -> None:
        from PyQt6.QtWidgets import QApplication

        from ui import themes

        old = QApplication.palette()
        self.addCleanup(QApplication.setPalette, old)
        tokens = themes.palette_tokens_for("modern-dark")
        QApplication.setPalette(themes.qpalette_for(tokens))
        _, brush = self.roles(".env")
        self.assertIsNotNone(brush)
        self.assertEqual(brush.color().name(), tokens["text_muted"])
        tokens = themes.palette_tokens_for("hacker")
        QApplication.setPalette(themes.qpalette_for(tokens))
        _, brush = self.roles(".env")
        self.assertEqual(brush.color().name(), tokens["text_muted"])

    def test_sad_plain_entries_and_dot_dot_keep_the_default_look(self) -> None:
        for name in ("plain.txt", ".."):
            with self.subTest(name=name):
                self.assertEqual(self.roles(name), (None, None))

    def test_sad_switched_off_nothing_is_marked(self) -> None:
        self.model.highlight_hidden = False
        for name in (".env", "desktop.ini", "plain.txt"):
            with self.subTest(name=name):
                self.assertEqual(self.roles(name), (None, None))

    def test_edge_flipping_the_switch_repaints_every_row(self) -> None:
        seen: list[tuple[int, int, int, int]] = []
        self.model.dataChanged.connect(
            lambda tl, br, _roles=None: seen.append((tl.row(), tl.column(), br.row(), br.column()))
        )
        self.model.highlight_hidden = False
        self.assertEqual(seen, [(0, 0, self.model.rowCount() - 1, self.model.columnCount() - 1)])
        self.model.highlight_hidden = False  # unchanged: no repaint
        self.assertEqual(len(seen), 1)

    def test_edge_an_empty_model_flips_without_a_signal(self) -> None:
        from models.file_table_model import FileTableModel

        empty = FileTableModel()
        seen: list = []
        empty.dataChanged.connect(lambda *a: seen.append(a))
        empty.highlight_hidden = False
        self.assertEqual(seen, [])
        self.assertFalse(empty.highlight_hidden)


class ModelColourOverrideTest(_ModelCase):
    """Operator: *„farbe fuer hidden entry soll auch definierbar sein"*."""

    def test_happy_a_chosen_colour_wins_over_the_theme(self) -> None:
        self.model.hidden_color = "#ff8800"
        _, brush = self.roles(".env")
        self.assertEqual(brush.color().name(), "#ff8800")
        font, _ = self.roles(".env")
        self.assertTrue(font.italic())

    def test_happy_it_wins_even_where_the_theme_colour_is_unreadable(self) -> None:
        from PyQt6.QtGui import QColor, QPalette
        from PyQt6.QtWidgets import QApplication

        old = QApplication.palette()
        self.addCleanup(QApplication.setPalette, old)
        pal = QPalette(old)
        pal.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor("#ffffff"))
        pal.setColor(QPalette.ColorRole.PlaceholderText, QColor("#eeeeee"))
        QApplication.setPalette(pal)
        _, brush = self.roles(".env")
        self.assertIsNone(brush)
        self.model.hidden_color = "#204a87"
        _, brush = self.roles(".env")
        self.assertEqual(brush.color().name(), "#204a87")

    def test_sad_a_malformed_colour_is_refused_and_the_old_one_kept(self) -> None:
        self.model.hidden_color = "#123456"
        for bad in ("red", "#12345", "#1234567", "#gggggg", "", "#12345\n", 42):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.model.hidden_color = bad
                self.assertEqual(self.model.hidden_color, "#123456")

    def test_edge_none_returns_to_the_theme_colour_and_case_is_normalised(self) -> None:
        self.model.hidden_color = "#AABBCC"
        self.assertEqual(self.model.hidden_color, "#aabbcc")
        self.model.hidden_color = None
        self.assertIsNone(self.model.hidden_color)
        self.assertEqual(self.roles(".env")[1], self.model._hidden_foreground())

    def test_edge_a_colour_change_repaints_and_a_same_value_does_not(self) -> None:
        seen: list = []
        self.model.dataChanged.connect(lambda *a: seen.append(a))
        self.model.hidden_color = "#010203"
        self.model.hidden_color = "#010203"
        self.assertEqual(len(seen), 1)

    def test_sad_the_switch_off_also_hides_a_chosen_colour(self) -> None:
        self.model.hidden_color = "#ff8800"
        self.model.highlight_hidden = False
        self.assertEqual(self.roles(".env"), (None, None))


# --- the window switch ------------------------------------------------------


class _WindowCase(_QtCase):
    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui import main_window as MW

        self.MW = MW
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.session = self.home / "session.json"
        for target, name, value in (
            (MW.MainWindow, "_SESSION_FILE", self.session),
            (MW.MainWindow, "_RECENTS_FILE", self.home / "recents.json"),
            (CP, "DEFAULT_PATH", self.home / "cols.json"),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.folder = self.home / "data"
        self.folder.mkdir()
        (self.folder / ".dotfile").write_text("d")
        (self.folder / "plain.txt").write_text("p")
        self.windows: list = []

    def tearDown(self) -> None:
        from PyQt6.QtGui import QCloseEvent

        for win in self.windows:
            win.closeEvent(QCloseEvent())
            _destroy(win)

    def make_window(self):
        with mock.patch("pathlib.Path.home", return_value=self.home):
            win = self.MW.MainWindow()
        self.windows.append(win)
        return win

    def settle(self, pane, timeout: float = 5.0) -> None:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if not pane.is_loading:
                return
            time.sleep(0.005)
        self.fail("pane did not finish loading")

    def states(self, win) -> list[bool]:
        return [p._model.highlight_hidden for p in win._panes]

    def settings(self, win):
        """Edit > Settings… of *win*, closed with the test."""
        from ui.settings_dialog import SettingsDialog

        # A child of the window: it goes with the window in tearDown.
        return SettingsDialog(win, window=win)


class WindowSwitchTest(_WindowCase):
    def test_happy_on_by_default_in_settings_appearance(self) -> None:
        win = self.make_window()
        page = self.settings(win).page("appearance")
        self.assertTrue(page.highlight_check.isChecked())
        self.assertIn("Highlight hidden files", page.highlight_check.text())
        self.assertEqual(self.states(win), [True])

    def test_happy_switching_it_off_in_settings_reaches_the_panes_and_is_stored(self) -> None:
        win = self.make_window()
        dialog = self.settings(win)
        dialog.page("appearance").highlight_check.setChecked(False)
        self.assertTrue(dialog.apply())
        self.assertEqual(self.states(win), [False])
        self.assertIs(json.loads(self.session.read_text())["window"]["highlight_hidden"], False)

    def test_happy_toggling_reaches_every_pane_and_new_panes_follow(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        win.set_highlight_hidden(False, store=False)
        self.assertEqual(self.states(win), [False, False])
        win._split_pane(Qt.Orientation.Horizontal)
        self.assertEqual(self.states(win), [False, False, False])
        preset_pane = win._preset_make_file_pane()
        self.addCleanup(preset_pane.deleteLater)
        self.assertFalse(preset_pane._model.highlight_hidden)
        self.assertIn(preset_pane, win._panes)
        win.set_highlight_hidden(True, store=False)
        self.assertEqual(self.states(win), [True, True, True, True])

    def test_sad_highlight_does_not_change_which_entries_are_listed(self) -> None:
        win = self.make_window()
        pane = win._panes[0]
        self.settle(pane)
        pane.navigate(str(self.folder))
        self.app.processEvents()
        before = pane._proxy.rowCount()
        win.set_highlight_hidden(False, store=False)
        self.assertEqual(pane._proxy.rowCount(), before)
        self.assertTrue(pane._proxy.show_hidden)


class WindowColourTest(_WindowCase):
    """Settings > Appearance > Hidden files colour (was View > Hidden Files
    Colour)."""

    def colours(self, win) -> list:
        return [p._model.hidden_color for p in win._panes]

    def test_happy_theme_colour_by_default_and_a_chosen_one_reaches_every_pane(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QColor

        win = self.make_window()
        dialog = self.settings(win)
        page = dialog.page("appearance")
        self.assertTrue(page.theme_colour_radio.isChecked())
        win._split_pane(Qt.Orientation.Horizontal)
        yellow = QColor("#ffcc00")
        with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=yellow):
            page.colour_button.click()
        self.assertTrue(page.own_colour_radio.isChecked())
        self.assertEqual(self.colours(win), [None, None])  # not before OK / Apply
        self.assertTrue(dialog.apply())
        self.assertEqual(self.colours(win), ["#ffcc00", "#ffcc00"])
        win._split_pane(Qt.Orientation.Horizontal)
        self.assertEqual(self.colours(win), ["#ffcc00"] * 3)
        page.theme_colour_radio.click()
        self.assertTrue(dialog.apply())
        self.assertEqual(self.colours(win), [None] * 3)
        self.assertIsNone(json.loads(self.session.read_text())["window"]["hidden_color"])

    def test_sad_a_cancelled_colour_dialog_changes_nothing(self) -> None:
        from PyQt6.QtGui import QColor

        win = self.make_window()
        dialog = self.settings(win)
        page = dialog.page("appearance")
        with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor()):
            page.colour_button.click()
        self.assertTrue(page.theme_colour_radio.isChecked())
        self.assertFalse(dialog.page("appearance").is_dirty())
        self.assertEqual(self.colours(win), [None])

    def test_sad_an_unreadable_colour_asks_first_and_no_keeps_the_old(self) -> None:
        from PyQt6.QtGui import QColor
        from PyQt6.QtWidgets import QMessageBox

        from ui import themes

        win = self.make_window()
        with mock.patch.object(themes, "system_scheme", return_value="dark"):
            win._apply_theme("modern")
        surface = themes.palette_tokens_for("modern-dark")["surface"]
        page = self.settings(win).page("appearance")
        with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor(surface)), \
                mock.patch("ui.settings_dialog.QMessageBox.question",
                           return_value=QMessageBox.StandardButton.No) as asked:
            page.choose_colour()
        asked.assert_called_once()
        self.assertIsNone(page.colour())
        with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor(surface)), \
                mock.patch("ui.settings_dialog.QMessageBox.question",
                           return_value=QMessageBox.StandardButton.Yes):
            page.choose_colour()
        self.assertEqual(page.colour(), surface)

    def test_edge_a_readable_colour_is_not_questioned(self) -> None:
        from PyQt6.QtGui import QColor

        from ui import themes

        win = self.make_window()
        with mock.patch.object(themes, "system_scheme", return_value="dark"):
            win._apply_theme("modern")
        page = self.settings(win).page("appearance")
        white = QColor("#ffffff")
        with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=white), \
                mock.patch("ui.settings_dialog.QMessageBox.question") as asked:
            page.choose_colour()
        asked.assert_not_called()
        self.assertEqual(page.colour(), "#ffffff")


class PersistenceTest(_WindowCase):
    def test_happy_a_chosen_colour_survives_a_restart(self) -> None:
        win = self.make_window()
        win.set_hidden_color("#12ab34", store=False)
        win._save_session()
        self.assertEqual(json.loads(self.session.read_text())["window"]["hidden_color"], "#12ab34")
        again = self.make_window()
        self.assertEqual([p._model.hidden_color for p in again._panes], ["#12ab34"])
        self.assertEqual(again.current_window_prefs().hidden_color, "#12ab34")

    def test_sad_a_garbage_colour_in_the_session_falls_back_to_the_theme(self) -> None:
        for bad in ("javascript:", "#12", 7, ["#ffffff"]):
            with self.subTest(bad=bad):
                self.session.write_text(json.dumps({"window": {"hidden_color": bad}}))
                win = self.make_window()
                self.assertEqual([p._model.hidden_color for p in win._panes], [None])
                self.assertIsNone(win.current_window_prefs().hidden_color)

    def test_edge_the_theme_colour_is_saved_as_null(self) -> None:
        win = self.make_window()
        win._save_session()
        self.assertIsNone(json.loads(self.session.read_text())["window"]["hidden_color"])

    def test_happy_the_switch_survives_a_restart(self) -> None:
        win = self.make_window()
        win.set_highlight_hidden(False, store=False)
        win._save_session()
        self.assertIs(json.loads(self.session.read_text())["window"]["highlight_hidden"], False)
        again = self.make_window()
        self.assertFalse(again.current_window_prefs().highlight_hidden)
        self.assertEqual(self.states(again), [False])

    def test_sad_a_garbage_value_keeps_the_default_on(self) -> None:
        self.session.write_text(json.dumps({"window": {"highlight_hidden": "nope"}}))
        win = self.make_window()
        self.assertTrue(win.current_window_prefs().highlight_hidden)

    def test_edge_an_old_session_without_the_key_starts_highlighted(self) -> None:
        self.session.write_text(json.dumps({"window": {"show_hidden": False}}))
        win = self.make_window()
        self.assertTrue(win.current_window_prefs().highlight_hidden)
        self.assertFalse(win._hidden_action.isChecked())

    def test_edge_restoring_a_layout_brings_the_switch_back(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win.set_highlight_hidden(False, store=False)
        win._split_pane(Qt.Orientation.Horizontal)
        win._save_session()
        win.set_highlight_hidden(True, store=False)
        self.assertTrue(win.restore_layout_on_start())
        self.assertFalse(win.current_window_prefs().highlight_hidden)
        self.assertEqual(self.states(win), [False, False])


# --- e2e: the pixels on screen ----------------------------------------------


class RenderedRowsTest(_WindowCase):
    """The real window, offscreen, under each theme: the dotfile's text is
    drawn in another colour than the plain file's, and stays readable."""

    def row_text_colour(self, pane, name: str):
        from tests import theme_audit as TA

        view = pane._table
        proxy, model = pane._proxy, pane._model
        for row in range(proxy.rowCount()):
            item = model.get_item(proxy.mapToSource(proxy.index(row, 0)).row())
            if item is not None and item.name == name:
                rect = view.visualRect(proxy.index(row, 0))
                img = view.viewport().grab().toImage()
                bg = TA._rgb(img, rect.right() - 2, rect.center().y())  # name cell, past the text
                # The Size cell: every column of a hidden row is marked, and
                # this one has no icon (a tinted icon would win the race).
                text = view.visualRect(proxy.index(row, 1))
                found, _ratio = TA._best_text_pixel(
                    img, bg, text.left() + 1, text.top() + 1, text.right() - 1, text.bottom() - 1
                )
                self.assertIsNotNone(found, f"no text pixels for {name}")
                return found, bg
        self.fail(f"{name} is not listed")

    def test_e2e_hidden_rows_render_differently_and_readably(self) -> None:
        from tests import theme_audit as TA

        for theme in ("modern-dark", "modern-light", "hacker"):
            with self.subTest(theme=theme):
                from ui import themes

                # Each theme from a fresh start: closing the window before
                # stored its switch (off) and colour in session.json.
                self.session.unlink(missing_ok=True)
                win = self.make_window()
                self.assertTrue(win.current_window_prefs().highlight_hidden)
                scheme = theme.split("-")[1] if theme.startswith("modern") else None
                with mock.patch.object(themes, "system_scheme", return_value=scheme):
                    win._apply_theme("modern" if scheme else theme)
                # A pane from the window's own factory, shown on its own: the
                # offscreen main window leaves the central table no height.
                pane = win._new_file_pane(win._panes[0].backend)
                win._panes.append(pane)
                pane.setParent(None)
                pane.resize(700, 300)
                pane.show()
                self.settle(pane)
                pane.navigate(str(self.folder))
                pane._table.clearSelection()
                self.app.processEvents()
                (hidden_fg, hidden_bg) = self.row_text_colour(pane, ".dotfile")
                (plain_fg, _plain_bg) = self.row_text_colour(pane, "plain.txt")
                self.assertNotEqual(hidden_fg, plain_fg)
                self.assertGreaterEqual(TA.contrast(hidden_fg, hidden_bg), 4.5)
                self.assertGreater(pane._table.viewport().height(), 100)
                win.set_hidden_color("#ff00ff", store=False)
                self.app.processEvents()
                (chosen_fg, _) = self.row_text_colour(pane, ".dotfile")
                self.assertEqual(chosen_fg, (255, 0, 255))
                win.set_highlight_hidden(False, store=False)
                self.app.processEvents()
                (off_fg, _) = self.row_text_colour(pane, ".dotfile")
                self.assertEqual(off_fg, plain_fg)
                pane.close()
                win.close()


if __name__ == "__main__":
    unittest.main()


class RenderedTilesTest(_WindowCase):
    """Round-2 verification: Thumbnail View draws the names itself; hidden
    entries must stand out there too (they were drawn like every other)."""

    def tile_text_colour(self, pane, name: str):
        from tests import theme_audit as TA

        view = pane.thumbnail_view
        proxy, model = pane._proxy, pane._model
        for row in range(proxy.rowCount()):
            index = proxy.index(row, 0)
            item = model.get_item(proxy.mapToSource(index).row())
            if item is not None and item.name == name:
                rect = view.visualRect(index)
                img = view.viewport().grab().toImage()
                text_top = rect.bottom() - 34
                bg = TA._rgb(img, rect.left() + 2, text_top + 4)
                found, _ratio = TA._best_text_pixel(
                    img, bg, rect.left() + 6, text_top, rect.right() - 6, rect.bottom() - 6)
                self.assertIsNotNone(found, f"no text pixels for {name}")
                return found
        self.fail(f"{name} is not listed")

    def test_e2e_hidden_names_stand_out_in_thumbnail_view(self) -> None:
        win = self.make_window()
        pane = win._new_file_pane(win._panes[0].backend)
        win._panes.append(pane)
        pane.setParent(None)
        pane.resize(700, 400)
        pane.show()
        self.settle(pane)
        pane.navigate(str(self.folder))
        self.settle(pane)
        pane.set_view_mode("thumbnails")
        pane._table.clearSelection()
        self.app.processEvents()
        win.set_hidden_color("#ff00ff", store=False)
        self.app.processEvents()
        self.assertEqual(self.tile_text_colour(pane, ".dotfile"), (255, 0, 255))
        plain = self.tile_text_colour(pane, "plain.txt")
        self.assertNotEqual(plain, (255, 0, 255))
        win.set_highlight_hidden(False, store=False)
        self.app.processEvents()
        self.assertEqual(self.tile_text_colour(pane, ".dotfile"), plain)
        pane.close()
