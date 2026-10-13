"""Icons follow the theme: tinted glyphs in Hacker / Amber, own glyphs everywhere."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui import themes  # noqa: E402


class TintMappingTest(unittest.TestCase):
    def test_hacker_and_amber_have_their_foreground_as_tint(self) -> None:
        self.assertEqual(themes.icon_tint_for("hacker"), "#00ff41")
        self.assertEqual(themes.icon_tint_for("amber"), "#ff8c00")
        self.assertIn("color: #00ff41;", themes.HACKER_THEME)
        self.assertIn("color: #ff8c00;", themes.AMBER_THEME)

    def test_other_themes_keep_the_regular_palette(self) -> None:
        for resolved in ("classic", "dark", "light", "modern-light", "modern-dark", "nonsense"):
            self.assertIsNone(themes.icon_tint_for(resolved), resolved)


def _dominant(pixmap) -> str:
    """Most frequent opaque colour of a pixmap, as #rrggbb."""
    img = pixmap.toImage()
    counts: dict[str, int] = {}
    for x in range(img.width()):
        for y in range(img.height()):
            c = img.pixelColor(x, y)
            if c.alpha() > 200:
                counts[c.name()] = counts.get(c.name(), 0) + 1
    return max(counts, key=counts.get) if counts else ""


class _QtCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import icon_provider as ip

        self.ip = ip
        ip.set_tint(None)
        ip.set_monochrome(False)
        self.addCleanup(ip.set_tint, None)
        self.addCleanup(ip.set_monochrome, False)


class ProviderTintTest(_QtCase):
    def _px(self, name: str) -> str:
        return _dominant(self.ip.icon(name).pixmap(32, 32))

    def test_default_icons_keep_their_palette_colour(self) -> None:
        self.assertEqual(self._px("folder").lower(), "#f5a623")

    def test_tint_recolours_every_icon(self) -> None:
        self.ip.set_tint("#00ff41")
        for name in ("folder", "bookmark", "refresh", "close-pane"):
            self.assertEqual(self._px(name).lower(), "#00ff41", name)

    def test_clearing_the_tint_restores_the_palette(self) -> None:
        self.ip.set_tint("#00ff41")
        self.ip.set_tint(None)
        self.assertEqual(self._px("folder").lower(), "#f5a623")

    def test_tint_wins_over_monochrome(self) -> None:
        self.ip.set_monochrome(True)
        self.ip.set_tint("#ff8c00")
        self.assertEqual(self._px("shell").lower(), "#ff8c00")

    def test_entry_icon_uses_terminal_glyphs_only_when_tinted(self) -> None:
        plain = self.ip.entry_icon(True).pixmap(32, 32).toImage()
        self.ip.set_tint("#00ff41")
        matrix = self.ip.entry_icon(True).pixmap(32, 32).toImage()
        self.assertNotEqual(plain, matrix)
        self.assertNotEqual(
            self.ip.entry_icon(True).pixmap(32, 32).toImage(),
            self.ip.entry_icon(False).pixmap(32, 32).toImage(),
        )

    def test_theme_glyphs_are_not_user_pickable(self) -> None:
        self.assertNotIn("folder-matrix", self.ip.available_icons())
        self.assertNotIn("file-matrix", self.ip.bookmark_icon_names())
        self.assertTrue(self.ip.has_icon("folder-matrix"))

    def test_unknown_name_still_falls_back_under_a_tint(self) -> None:
        self.ip.set_tint("#00ff41")
        self.assertFalse(self.ip.icon("no-such-icon").isNull())


class FileModelIconTest(_QtCase):
    def _model(self):
        from datetime import datetime

        from models.file_item import FileItem
        from models.file_table_model import FileTableModel

        m = FileTableModel()
        m.set_items(
            [
                FileItem(name="d", is_dir=True, modified=datetime(2026, 1, 1)),
                FileItem(name="f", is_dir=False, modified=datetime(2026, 1, 1)),
            ]
        )
        return m

    def _icon(self, model, row):
        from PyQt6.QtCore import Qt

        return model.data(model.index(row, 0), Qt.ItemDataRole.DecorationRole)

    def test_rows_use_our_glyphs_not_the_system_icons(self) -> None:
        m = self._model()
        self.assertEqual(_dominant(self._icon(m, 0).pixmap(32, 32)).lower(), "#f5a623")
        self.assertEqual(_dominant(self._icon(m, 1).pixmap(32, 32)).lower(), "#95a5a6")

    def test_rows_follow_the_tint_on_the_next_paint(self) -> None:
        m = self._model()
        self.ip.set_tint("#00ff41")
        self.assertEqual(_dominant(self._icon(m, 0).pixmap(32, 32)).lower(), "#00ff41")
        self.assertEqual(_dominant(self._icon(m, 1).pixmap(32, 32)).lower(), "#00ff41")


class MainWindowIconTest(_QtCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        from ui.main_window import MainWindow

        cls.win = MainWindow()
        cls.win.resize(1100, 600)
        cls.win.show()
        cls.app.processEvents()

    @classmethod
    def tearDownClass(cls) -> None:
        # Never closeEvent: it would persist the session.
        cls.win.deleteLater()
        cls._patch.stop()
        __import__("shutil").rmtree(cls._home, ignore_errors=True)

    def tearDown(self) -> None:
        self.win._apply_theme("modern")

    def _toolbar_action(self, name: str):
        from PyQt6.QtWidgets import QToolBar

        for tb in self.win.findChildren(QToolBar):
            for a in tb.actions():
                if a.property("axIcon") == name:
                    return a
        return None

    def test_toolbar_has_a_bookmarks_button(self) -> None:
        act = self._toolbar_action("bookmark")
        self.assertIsNotNone(act)
        self.assertIn("F12", act.toolTip())
        self.assertFalse(act.icon().isNull())

    def test_bookmarks_button_toggles_the_sidebar_and_stays_in_sync(self) -> None:
        act = self._toolbar_action("bookmark")
        dock = self.win._bookmark_sidebar
        start = dock.isVisible()
        act.trigger()
        self.app.processEvents()
        self.assertNotEqual(dock.isVisible(), start)
        self.assertEqual(act.isChecked(), dock.isVisible())
        # toggled from elsewhere (F12 / menu / the dock's X)
        dock.toggleViewAction().trigger()
        self.app.processEvents()
        self.assertEqual(dock.isVisible(), start)
        self.assertEqual(act.isChecked(), start)

    def test_hacker_and_amber_tint_every_icon_and_other_themes_clear_it(self) -> None:
        for theme, tint in (("hacker", "#00ff41"), ("amber", "#ff8c00")):
            self.win._apply_theme(theme)
            self.assertEqual(self.ip_tint(), tint, theme)
            shell = self._toolbar_action("shell")
            self.assertEqual(_dominant(shell.icon().pixmap(22, 22)).lower(), tint, theme)
        for theme in ("classic", "light", "modern"):
            self.win._apply_theme(theme)
            self.assertIsNone(self.ip_tint(), theme)

    def test_monochrome_on_a_plain_theme_uses_the_palette_text_colour(self) -> None:
        self.win._apply_theme("classic")
        self.win._toggle_monochrome_icons(True)
        try:
            from PyQt6.QtGui import QPalette

            expected = self.app.palette().color(QPalette.ColorRole.WindowText).name()
            self.assertEqual(self.ip_tint(), expected)
        finally:
            self.win._toggle_monochrome_icons(False)
        self.assertIsNone(self.ip_tint())

    def test_open_file_lists_repaint_with_the_theme(self) -> None:
        pane = self.win._panes[0]
        import time

        from PyQt6.QtCore import Qt

        end = time.time() + 3  # the start pane loads its folder in the background
        while pane.is_loading and time.time() < end:
            self.app.processEvents()
            time.sleep(0.002)

        self.win._apply_theme("hacker")
        model = pane._model
        self.assertGreater(model.rowCount(), 0, "start pane lists nothing")
        icon = model.data(model.index(0, 0), Qt.ItemDataRole.DecorationRole)
        self.assertEqual(_dominant(icon.pixmap(32, 32)).lower(), "#00ff41")

    @staticmethod
    def ip_tint():
        from ui import icon_provider as ip

        return ip.get_tint()


if __name__ == "__main__":
    unittest.main()
