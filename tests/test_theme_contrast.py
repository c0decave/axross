"""No theme may render text that is hard to read.

Every common control (and the real archive tree, which started this:
green text on a white alternate row in Hacker mode) is rendered under
every theme and its text colour is measured against the row / widget
background (WCAG contrast ratio).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests import theme_audit as TA  # noqa: E402

# WCAG AA for normal text. The native light theme is the desktop's own
# look (selection colours come from the platform style), so it only has
# to clear the large-text bound.
MIN_RATIO = 4.5
MIN_RATIO_NATIVE = 3.0


class ContrastMathTest(unittest.TestCase):
    def test_black_on_white_is_21(self) -> None:
        self.assertAlmostEqual(TA.contrast((0, 0, 0), (255, 255, 255)), 21.0, places=1)

    def test_identical_colours_are_1(self) -> None:
        self.assertAlmostEqual(TA.contrast((10, 200, 10), (10, 200, 10)), 1.0, places=3)

    def test_matrix_green_on_white_is_far_below_the_bound(self) -> None:
        self.assertLess(TA.contrast((0, 255, 65), (255, 255, 255)), 1.5)

    def test_symmetric(self) -> None:
        a, b = (12, 34, 56), (200, 210, 220)
        self.assertEqual(TA.contrast(a, b), TA.contrast(b, a))


class _QtCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


class DetectorTest(_QtCase):
    """The harness must catch the bug it exists for (positive control) and
    stay quiet on a healthy view (negative control)."""

    def setUp(self) -> None:
        # Other tests leave an application stylesheet / palette behind; the
        # controls below must see only the palette set on them.
        # Restyles with the collector paused: a collection during the walk
        # frees widgets Qt still visits (see ui.themes.collection_paused).
        from ui import themes

        app = self.app
        saved = (app.styleSheet(), app.palette())
        with themes.collection_paused():
            app.setStyleSheet("")

        def restore() -> None:
            with themes.collection_paused():
                app.setStyleSheet(saved[0])
                app.setPalette(saved[1])

        self.addCleanup(restore)

    def _tree(self, text: str, base: str, alt: str):
        from PyQt6.QtGui import QColor, QPalette, QStandardItem, QStandardItemModel
        from PyQt6.QtWidgets import QTreeView

        view = QTreeView()
        model = QStandardItemModel()
        for i in range(6):
            model.appendRow(QStandardItem(f"member_{i}.bin"))
        view.setModel(model)
        view.setAlternatingRowColors(True)
        pal = view.palette()
        pal.setColor(QPalette.ColorRole.Base, QColor(base))
        pal.setColor(QPalette.ColorRole.AlternateBase, QColor(alt))
        pal.setColor(QPalette.ColorRole.Text, QColor(text))
        view.setPalette(pal)
        view.resize(320, 200)
        view.show()
        self.app.processEvents()
        self.addCleanup(view.deleteLater)
        return view

    def test_green_on_a_white_alternate_row_is_flagged(self) -> None:
        ratio, _bg, _fg = TA.measure_widget(self._tree("#00ff41", "#0a0a0a", "#ffffff"))
        self.assertIsNotNone(ratio)
        self.assertLess(ratio, 2.0)

    def test_green_on_black_rows_passes(self) -> None:
        ratio, _bg, _fg = TA.measure_widget(self._tree("#00ff41", "#0a0a0a", "#0d0d0d"))
        self.assertGreater(ratio, 10.0)


class EveryThemeIsReadableTest(_QtCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        from ui.main_window import MainWindow

        cls.win = MainWindow()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.win._apply_theme("modern")
        cls.win.deleteLater()
        cls._patch.stop()
        __import__("shutil").rmtree(cls._home, ignore_errors=True)

    def test_all_controls_in_all_themes_meet_the_contrast_bound(self) -> None:
        failures: list[str] = []
        measured = 0
        for theme in TA.THEMES:
            bound = MIN_RATIO_NATIVE if theme == "default" else MIN_RATIO
            for name, (ratio, bg, fg) in TA.audit(theme, self.win, self._home).items():
                if ratio is None:
                    continue
                measured += 1
                if ratio < bound:
                    failures.append(f"{theme:13} {name:34} {ratio:4.1f} (text {fg} on {bg})")
        self.assertGreater(measured, 100, "the audit measured suspiciously little")
        self.assertEqual(failures, [], "unreadable text:\n" + "\n".join(failures))

    def test_the_real_archive_tree_is_part_of_the_audit_and_readable_everywhere(self) -> None:
        for theme in TA.THEMES:
            res = TA.audit(theme, self.win, self._home)
            ratio, bg, fg = res["ArchivePaneWidget tree (real zip)"]
            self.assertIsNotNone(ratio, theme)
            self.assertGreaterEqual(ratio, 3.0, f"{theme}: {fg} on {bg}")

    def test_palette_tokens_cover_every_dark_theme_and_not_the_native_one(self) -> None:
        from ui import themes

        for resolved in ("classic", "dark", "hacker", "amber", "modern-dark", "modern-light"):
            tokens = themes.palette_tokens_for(resolved)
            self.assertIsNotNone(tokens, resolved)
            themes.qpalette_for(tokens)  # every key the palette needs is present
        self.assertIsNone(themes.palette_tokens_for("default"))

    def test_the_hacker_palette_has_a_dark_alternate_row(self) -> None:
        from ui import themes

        tokens = themes.palette_tokens_for("hacker")
        self.assertEqual(tokens["surface_alt"], "#0d0d0d")
        self.assertEqual(tokens["text"], "#00ff41")


class SecondaryTextSelectionAndDisabledTest(_QtCase):
    """UX review round 7: the Light Mode hint "No transfers yet…" was the
    palette's disabled grey (1.9:1), Fusion's selection 3.7:1, and a
    disabled button in a dark theme looked like an enabled one."""

    def test_happy_the_idle_hint_uses_the_muted_role_readable_in_every_theme(self) -> None:
        from ui import themes

        source = (Path(__file__).resolve().parent.parent / "ui/transfer_dock.py").read_text()
        self.assertIn('self._idle_label.setProperty("role", "muted")', source)
        self.assertNotIn("self._idle_label.setEnabled(False)", source)
        backgrounds = {"default": "#efefef", "classic": "#1e1e2e", "hacker": "#0a0a0a",
                       "amber": "#0a0a0a"}
        for theme, background in backgrounds.items():
            css = themes.stylesheet_for(theme, None)
            colours = re.findall(r'QLabel\[role="muted"\] \{\s*color: (#[0-9a-fA-F]{6})', css)
            self.assertTrue(colours, theme)
            self.assertGreaterEqual(themes.contrast_ratio(colours[-1], background), 4.5, theme)

    def test_happy_a_weak_desktop_selection_is_darkened_to_readable(self) -> None:
        from PyQt6.QtGui import QColor, QPalette

        from ui import themes

        pal = QPalette()
        role = QPalette.ColorRole
        pal.setColor(role.Highlight, QColor("#308cc6"))  # Fusion's own
        pal.setColor(role.HighlightedText, QColor("#ffffff"))
        self.assertLess(themes.contrast_ratio("#ffffff", "#308cc6"), 4.5)
        fixed = themes.readable_palette(pal)
        for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
            ratio = themes.contrast_ratio(fixed.color(group, role.HighlightedText).name(),
                                          fixed.color(group, role.Highlight).name())
            self.assertGreaterEqual(ratio, 4.5)

    def test_sad_a_disabled_button_differs_from_an_enabled_one_in_dark_themes(self) -> None:
        from ui import themes

        for theme in ("classic", "hacker", "amber", "modern-dark", "modern-light"):
            css = themes.stylesheet_for(theme, None)
            rule = re.search(r"QPushButton:disabled[^{]*\{([^}]*)\}", css)
            self.assertIsNotNone(rule, theme)
            body = rule.group(1)
            self.assertIn("background-color: transparent", body, theme)
            self.assertIn("dashed", body, theme)
            self.assertIn("color:", body, theme)

    def test_edge_a_readable_selection_is_left_alone(self) -> None:
        from PyQt6.QtGui import QColor, QPalette

        from ui import themes

        pal = QPalette()
        role = QPalette.ColorRole
        pal.setColor(role.Highlight, QColor("#1d4f91"))
        pal.setColor(role.HighlightedText, QColor("#ffffff"))
        self.assertEqual(themes.readable_palette(pal).color(role.Highlight).name(), "#1d4f91")
        # a light selection under dark text gets lighter, not darker
        pal.setColor(role.Highlight, QColor("#6f6f6f"))
        pal.setColor(role.HighlightedText, QColor("#000000"))
        fixed = themes.readable_palette(pal)
        self.assertGreaterEqual(
            themes.contrast_ratio("#000000", fixed.color(role.Highlight).name()), 4.5)


if __name__ == "__main__":
    unittest.main()
