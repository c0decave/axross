"""Theme registry: modern (default, light/dark) next to the classic themes."""
from __future__ import annotations

import re
import unittest

from ui import themes


def _luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


class DefaultsTest(unittest.TestCase):
    def test_modern_is_the_default(self) -> None:
        self.assertEqual(themes.DEFAULT_THEME, "modern")

    def test_every_listed_theme_resolves_to_css(self) -> None:
        for theme_id, _label in themes.THEME_CHOICES:
            css = themes.stylesheet_for(theme_id, system_scheme="dark")
            self.assertIsInstance(css, str, theme_id)

    def test_classic_keeps_the_old_dark_stylesheet(self) -> None:
        self.assertEqual(
            themes.stylesheet_for("classic", system_scheme="light").strip()[:40],
            themes.DARK_THEME.strip()[:40],
        )


class ResolutionTest(unittest.TestCase):
    def test_modern_follows_system_scheme(self) -> None:
        self.assertEqual(themes.resolve("modern", "dark"), "modern-dark")
        self.assertEqual(themes.resolve("modern", "light"), "modern-light")

    def test_explicit_variant_ignores_system_scheme(self) -> None:
        self.assertEqual(themes.resolve("modern-light", "dark"), "modern-light")

    def test_unknown_scheme_falls_back_to_dark(self) -> None:
        self.assertEqual(themes.resolve("modern", "bogus"), "modern-dark")
        self.assertEqual(themes.resolve("modern", None), "modern-dark")

    def test_unknown_theme_falls_back_to_default(self) -> None:
        self.assertEqual(themes.normalize("no-such-theme"), "modern")
        self.assertEqual(themes.normalize(None), "modern")
        self.assertEqual(themes.normalize(42), "modern")  # type: ignore[arg-type]

    def test_legacy_ids_are_kept(self) -> None:
        for legacy in ("default", "dark", "hacker", "amber"):
            self.assertEqual(themes.normalize(legacy), legacy)

    def test_pane_family_for_header_colors(self) -> None:
        self.assertEqual(themes.pane_family("modern-dark"), "modern-dark")
        self.assertEqual(themes.pane_family("classic"), "dark")


class ModernPaletteTest(unittest.TestCase):
    def test_text_contrast_meets_wcag_aa(self) -> None:
        for name, tok in (("light", themes.MODERN_LIGHT), ("dark", themes.MODERN_DARK)):
            for fg in ("text", "text_muted", "accent_text_on_surface"):
                for bg in ("bg", "surface"):
                    self.assertGreaterEqual(
                        _contrast(tok[fg], tok[bg]),
                        4.5,
                        f"{name}: {fg} on {bg}",
                    )
            self.assertGreaterEqual(
                _contrast(tok["accent_fg"], tok["accent"]), 4.5, f"{name}: accent button"
            )

    def test_stylesheet_has_no_unresolved_tokens(self) -> None:
        for tokens in (themes.MODERN_LIGHT, themes.MODERN_DARK):
            css = themes.build_modern_qss(tokens)
            self.assertNotRegex(css, r"\{\{|\$\{|%\(")
            self.assertTrue(re.search(r"QTableView", css))
            self.assertIn(tokens["accent"], css)

    def test_missing_token_is_an_error(self) -> None:
        broken = dict(themes.MODERN_DARK)
        del broken["accent"]
        with self.assertRaises(KeyError):
            themes.build_modern_qss(broken)

    def test_muted_role_rule_present_everywhere(self) -> None:
        for theme_id, _ in themes.THEME_CHOICES:
            css = themes.stylesheet_for(theme_id, system_scheme="dark")
            self.assertIn('[role="muted"]', css, theme_id)


class PaletteTest(unittest.TestCase):
    def test_tokens_for_modern_only(self) -> None:
        self.assertIs(themes.tokens_for("modern-dark"), themes.MODERN_DARK)
        self.assertIs(themes.tokens_for("modern-light"), themes.MODERN_LIGHT)
        self.assertIsNone(themes.tokens_for("classic"))
        self.assertIsNone(themes.tokens_for("hacker"))

    def test_qpalette_matches_tokens(self) -> None:
        try:
            from PyQt6.QtGui import QPalette
        except ImportError:
            self.skipTest("PyQt6 not installed")
        palette = themes.qpalette_for(themes.MODERN_DARK)
        self.assertEqual(
            palette.color(QPalette.ColorRole.Window).name(), themes.MODERN_DARK["bg"]
        )
        self.assertEqual(
            palette.color(QPalette.ColorRole.Base).name(), themes.MODERN_DARK["surface"]
        )


class CompactTest(unittest.TestCase):
    def test_compact_appends(self) -> None:
        plain = themes.stylesheet_for("modern", "dark")
        compact = themes.stylesheet_for("modern", "dark", compact=True)
        self.assertTrue(compact.startswith(plain))
        self.assertGreater(len(compact), len(plain))


if __name__ == "__main__":
    unittest.main()
