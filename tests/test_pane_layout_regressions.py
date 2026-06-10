from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
