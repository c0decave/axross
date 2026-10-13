"""Per-bookmark colour and the hand-drawn emoji-style SVG set."""
from __future__ import annotations

import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def _colours(pixmap) -> dict[str, int]:
    img = pixmap.toImage()
    counts: dict[str, int] = {}
    for x in range(img.width()):
        for y in range(img.height()):
            c = img.pixelColor(x, y)
            if c.alpha() > 200:
                counts[c.name()] = counts.get(c.name(), 0) + 1
    return counts


def _dominant(pixmap) -> str:
    counts = _colours(pixmap)
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


class ColourOverrideTest(_QtCase):
    def _px(self, name, colour=None) -> str:
        return _dominant(self.ip.icon(name, 32, colour).pixmap(32, 32)).lower()

    def test_explicit_colour_recolours_the_icon(self) -> None:
        self.assertEqual(self._px("bookmark", "#ff0000"), "#ff0000")
        self.assertEqual(self._px("folder", "#00aa00"), "#00aa00")

    def test_no_colour_keeps_the_default(self) -> None:
        self.assertEqual(self._px("folder"), "#f5a623")
        self.assertEqual(self._px("folder", ""), "#f5a623")
        self.assertEqual(self._px("folder", None), "#f5a623")

    def test_the_cache_does_not_mix_colours(self) -> None:
        self.assertEqual(self._px("star", "#ff0000"), "#ff0000")
        self.assertEqual(self._px("star", "#0000ff"), "#0000ff")
        self.assertEqual(self._px("star"), "#f39c12")

    def test_explicit_colour_beats_a_theme_tint_and_monochrome(self) -> None:
        self.ip.set_tint("#00ff41")
        self.assertEqual(self._px("star", "#ff0000"), "#ff0000")
        self.assertEqual(self._px("star"), "#00ff41")
        self.ip.set_tint(None)
        self.ip.set_monochrome(True)
        self.assertEqual(self._px("star", "#ff0000"), "#ff0000")

    def test_invalid_colours_are_ignored_and_cannot_inject_svg(self) -> None:
        for bad in ("red", "#fff", '#ff0000" onload="x', "#gggggg", "#ff00000", "javascript:1"):
            self.assertEqual(self._px("folder", bad), "#f5a623", bad)

    def test_uppercase_hex_is_accepted(self) -> None:
        self.assertEqual(self._px("folder", "#FF0000"), "#ff0000")

    def test_palette_is_valid_unique_and_named(self) -> None:
        pal = self.ip.BOOKMARK_COLORS
        self.assertGreaterEqual(len(pal), 10)
        for name, hexv in pal:
            self.assertTrue(name)
            self.assertRegex(hexv, r"^#[0-9a-f]{6}$")
        self.assertEqual(len({h for _n, h in pal}), len(pal))
        self.assertEqual(len({n for n, _h in pal}), len(pal))


EMOJI = (
    "smile sad sun moon coffee gift award anchor bell camera book headphones gamepad "
    "umbrella droplet leaf flame rocket bug skull ghost paw gem crown trophy target "
    "compass map-pin"
).split()


class EmojiSetTest(_QtCase):
    def test_every_emoji_icon_exists_and_is_pickable(self) -> None:
        picks = self.ip.bookmark_icon_names()
        for name in EMOJI:
            self.assertTrue(self.ip.has_icon(name), name)
            self.assertIn(name, picks, name)
            self.assertIn(name, self.ip.available_icons(), name)

    def test_every_emoji_svg_is_valid_and_draws_something(self) -> None:
        from PyQt6.QtCore import QByteArray
        from PyQt6.QtSvg import QSvgRenderer

        for name in EMOJI:
            renderer = QSvgRenderer(QByteArray(self.ip.ICONS[name].encode()))
            self.assertTrue(renderer.isValid(), name)
            px = self.ip.icon(name).pixmap(32, 32)
            self.assertGreater(sum(_colours(px).values()), 40, f"{name} draws almost nothing")

    def test_emoji_icons_have_visible_default_colours_not_black(self) -> None:
        for name in EMOJI:
            dom = _dominant(self.ip.icon(name).pixmap(32, 32)).lower()
            self.assertNotEqual(dom, "#000000", name)

    def test_emoji_icons_follow_a_tint_and_stay_line_art(self) -> None:
        self.ip.set_tint("#00ff41")
        for name in EMOJI:
            self.assertEqual(_dominant(self.ip.icon(name).pixmap(32, 32)).lower(), "#00ff41", name)
            self.assertNotIn("<text", self.ip.ICONS[name])

    def test_no_unicode_emoji_characters_anywhere_in_the_icon_names_or_sources(self) -> None:
        astral = re.compile("[\U0001F000-\U0001FFFF☀-➿]")
        for name, svg in self.ip.ICONS.items():
            self.assertIsNone(astral.search(name), name)
            self.assertIsNone(astral.search(svg), name)

    def test_the_icon_picker_shows_the_new_icons(self) -> None:
        from ui.bookmark_edit_dialog import _IconGridPicker

        picker = _IconGridPicker("flame")
        self.assertEqual(picker.selected_name, "flame")
        self.assertIn("rocket", picker._buttons)


if __name__ == "__main__":
    unittest.main()
