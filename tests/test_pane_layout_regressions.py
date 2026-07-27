from __future__ import annotations

import re
import unittest

from ui.layout_utils import (
    detect_drop_zone,
    equal_split_sizes,
    sanitize_splitter_sizes,
    splitter_axis_for_zone,
)


class PaneLayoutRegressionTests(unittest.TestCase):
    def test_detect_drop_zone_prefers_nearest_edge(self) -> None:
        self.assertEqual(detect_drop_zone(5, 50, 100, 100), "left")
        self.assertEqual(detect_drop_zone(95, 50, 100, 100), "right")
        self.assertEqual(detect_drop_zone(50, 5, 100, 100), "top")
        self.assertEqual(detect_drop_zone(50, 95, 100, 100), "bottom")

    def test_splitter_axis_for_zone_rejects_unknown_values(self) -> None:
        self.assertEqual(splitter_axis_for_zone("left"), "horizontal")
        self.assertEqual(splitter_axis_for_zone("right"), "horizontal")
        self.assertEqual(splitter_axis_for_zone("top"), "vertical")
        self.assertEqual(splitter_axis_for_zone("bottom"), "vertical")
        self.assertIsNone(splitter_axis_for_zone("center"))

    def test_equal_split_sizes_uses_fallback_when_layout_extent_is_zero(self) -> None:
        self.assertEqual(equal_split_sizes(0, 2, fallback_extent=600), [300, 300])
        self.assertEqual(equal_split_sizes(0, 3), [100, 100, 100])
        self.assertEqual(equal_split_sizes(90, 3), [30, 30, 30])

    def test_sanitize_splitter_sizes_clamps_zero_and_rejects_bad_data(self) -> None:
        self.assertEqual(sanitize_splitter_sizes([0, 250], 2), [100, 250])
        self.assertEqual(sanitize_splitter_sizes([], 0), [])
        self.assertIsNone(sanitize_splitter_sizes([100], 2))
        self.assertIsNone(sanitize_splitter_sizes(["100", 200], 2))
        self.assertIsNone(sanitize_splitter_sizes("100,200", 2))


_LINE_RE = re.compile(r'<line x1="(\d+)" y1="(\d+)" x2="(\d+)" y2="(\d+)"')


def _divider_orientation(svg: str) -> str:
    """Orientation of the single divider ``<line>`` inside a split icon.

    Returns ``"vertical"`` for a top-to-bottom stroke (a box cut into a
    LEFT and a RIGHT half) and ``"horizontal"`` for a left-to-right
    stroke (a box cut into a TOP and a BOTTOM half).
    """
    match = _LINE_RE.search(svg)
    if match is None:
        raise AssertionError(f"no divider <line> found in icon svg: {svg!r}")
    x1, y1, x2, y2 = (int(g) for g in match.groups())
    if x1 == x2 and y1 != y2:
        return "vertical"
    if y1 == y2 and x1 != x2:
        return "horizontal"
    raise AssertionError(f"divider is neither axis-aligned nor a line: {match.group(0)!r}")


class SplitIconOrientationTests(unittest.TestCase):
    """The split-pane icons must depict the layout their action produces.

    Measured Qt behaviour (PyQt6, offscreen), which is what the toolbar
    actions in ui/main_window.py hand to ``_split_pane``:

        QSplitter(Qt.Orientation.Horizontal) -> children at (0,0), (212,0)
            => panes SIDE BY SIDE  => the divider between them is VERTICAL
        QSplitter(Qt.Orientation.Vertical)   -> children at (0,0), (0,202)
            => panes STACKED       => the divider between them is HORIZONTAL

    "Split Horizontal" triggers the Horizontal orientation, so its icon
    has to show a vertical divider — and vice versa. The two glyph
    bodies were swapped, so both buttons showed the opposite of what
    they do.
    """

    def setUp(self) -> None:
        try:
            from ui.icon_provider import ICONS
        except ImportError as exc:  # pragma: no cover - PyQt6 absent
            raise unittest.SkipTest(f"PyQt6 not available: {exc}") from exc
        self.icons = ICONS

    def test_split_h_icon_shows_a_vertical_divider(self) -> None:
        # "Split Horizontal" => Qt.Orientation.Horizontal => side by side.
        self.assertEqual(_divider_orientation(self.icons["split-h"]), "vertical")

    def test_split_v_icon_shows_a_horizontal_divider(self) -> None:
        # "Split Vertical" => Qt.Orientation.Vertical => stacked.
        self.assertEqual(_divider_orientation(self.icons["split-v"]), "horizontal")

    def test_the_two_split_icons_are_not_identical(self) -> None:
        # Guards against a "fix" that copies one body over the other.
        self.assertNotEqual(self.icons["split-h"], self.icons["split-v"])

    def test_divider_orientation_helper_rejects_a_diagonal(self) -> None:
        # Sad path for the helper itself: a diagonal stroke is neither
        # orientation and must not be silently classified as one.
        with self.assertRaises(AssertionError):
            _divider_orientation('<line x1="3" y1="3" x2="21" y2="21"/>')


if __name__ == "__main__":
    unittest.main()
