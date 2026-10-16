"""File pane column layout: Name takes the free width, widths persist sanely."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui import column_prefs as CP  # noqa: E402


class LegacyPrefsMigrationTest(unittest.TestCase):
    """Unversioned files persisted the stretch artefact of the last column."""

    def _write(self, payload: dict) -> Path:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        p = Path(d) / "column_prefs.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    def test_legacy_file_drops_name_and_last_column_widths(self) -> None:
        p = self._write({"widths": {"0": 352, "2": 150, "4": 988}, "hidden": [3]})
        prefs = CP.load(p)
        self.assertEqual(prefs.widths, {2: 150})
        self.assertEqual(prefs.hidden, {3})

    def test_versioned_file_keeps_its_widths(self) -> None:
        p = self._write({"version": CP.VERSION, "widths": {"4": 140, "2": 150}, "hidden": []})
        self.assertEqual(CP.load(p).widths, {4: 140, 2: 150})

    def test_save_writes_the_version_and_roundtrips(self) -> None:
        p = self._write({})
        CP.save(CP.ColumnPrefs(widths={1: 90}, hidden={2}), p)
        self.assertEqual(json.loads(p.read_text())["version"], CP.VERSION)
        again = CP.load(p)
        self.assertEqual((again.widths, again.hidden), ({1: 90}, {2}))

    def test_garbage_and_missing_file_give_defaults(self) -> None:
        p = self._write({})
        p.write_text("not json", encoding="utf-8")
        self.assertEqual(CP.load(p).widths, {})
        self.assertEqual(CP.load(p.with_name("missing.json")).widths, {})


class ColumnOrderPrefsTest(unittest.TestCase):
    def _path(self) -> Path:
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return Path(d) / "column_prefs.json"

    def test_order_roundtrips(self) -> None:
        p = self._path()
        CP.save(CP.ColumnPrefs(order=[0, 2, 1, 3, 4]), p)
        self.assertEqual(CP.load(p).order, [0, 2, 1, 3, 4])

    def test_files_without_an_order_load_with_an_empty_one(self) -> None:
        p = self._path()
        p.write_text(json.dumps({"version": CP.VERSION, "widths": {}, "hidden": []}))
        self.assertEqual(CP.load(p).order, [])

    def test_garbage_orders_are_dropped(self) -> None:
        p = self._path()
        for bad in ("x", [1, "a"], [1.5, 2], [True, False], {"a": 1}, None):
            p.write_text(json.dumps({"version": CP.VERSION, "order": bad}))
            self.assertEqual(CP.load(p).order, [], bad)


class _PaneTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def _pane(self, prefs_payload: dict | None = None):
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        prefs_path = Path(d) / "column_prefs.json"
        if prefs_payload is not None:
            prefs_path.write_text(json.dumps(prefs_payload), encoding="utf-8")
        patcher = mock.patch.object(CP, "DEFAULT_PATH", prefs_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        return pane, prefs_path

    def _pane_from(self, path: Path):
        """A second pane reading the prefs file of an earlier one."""
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        return pane, path

    def _widths(self, pane):
        h = pane._table.horizontalHeader()
        return [h.sectionSize(c) for c in range(pane._model.columnCount())]

    def _show(self, pane, width: int) -> None:
        pane.resize(width, 500)
        pane.show()
        self.app.processEvents()


class PaneColumnLayoutTest(_PaneTestBase):
    def test_name_takes_all_free_width_on_a_wide_pane(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 2000)
        w = self._widths(pane)
        self.assertGreater(w[0], 2000 * 0.5, w)
        self.assertLess(w[4], 400, w)

    def test_name_follows_the_pane_when_it_grows(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 1000)
        before = self._widths(pane)[0]
        self._show(pane, 1800)
        self.assertGreater(self._widths(pane)[0], before + 600)

    def test_legacy_prefs_cannot_blow_up_the_owner_column(self) -> None:
        pane, _ = self._pane({"widths": {"0": 352, "4": 988}, "hidden": []})
        self._show(pane, 1900)
        w = self._widths(pane)
        self.assertLess(w[4], 400, w)
        self.assertGreater(w[0], w[4] * 2, w)

    def test_stored_width_of_a_regular_column_is_applied(self) -> None:
        pane, _ = self._pane({"version": CP.VERSION, "widths": {"4": 220}, "hidden": []})
        self._show(pane, 1500)
        self.assertEqual(self._widths(pane)[4], 220)

    def test_growing_the_window_never_writes_prefs(self) -> None:
        pane, path = self._pane()
        self._show(pane, 900)
        self._show(pane, 2100)
        self.assertFalse(path.exists(), path.read_text() if path.exists() else "")

    def test_user_resize_of_owner_persists_and_name_gives_way(self) -> None:
        pane, path = self._pane()
        self._show(pane, 1600)
        name_before = self._widths(pane)[0]
        pane._table.horizontalHeader().resizeSection(4, 300)
        self.app.processEvents()
        self.assertEqual(json.loads(path.read_text())["widths"]["4"], 300)
        self.assertLess(self._widths(pane)[0], name_before)

    def test_every_column_has_a_draggable_divider(self) -> None:
        from PyQt6.QtWidgets import QHeaderView

        pane, _ = self._pane()
        h = pane._table.horizontalHeader()
        modes = [h.sectionResizeMode(c) for c in range(pane._model.columnCount())]
        self.assertTrue(all(m == QHeaderView.ResizeMode.Interactive for m in modes), modes)
        self.assertFalse(h.stretchLastSection())

    def test_columns_always_fill_the_viewport_exactly(self) -> None:
        pane, _ = self._pane()
        for width in (900, 1500, 2300, 700):
            self._show(pane, width)
            h = pane._table.horizontalHeader()
            self.assertEqual(
                sum(self._widths(pane)), pane._table.viewport().width(), f"at {width}px"
            )
            self.assertEqual(h.length(), pane._table.viewport().width())

    def test_dragging_the_name_divider_takes_the_space_from_the_next_column(self) -> None:
        pane, path = self._pane()
        self._show(pane, 1600)
        before = self._widths(pane)
        pane._table.horizontalHeader().resizeSection(0, before[0] + 20)
        self.app.processEvents()
        after = self._widths(pane)
        self.assertEqual(after[0], before[0] + 20)
        self.assertEqual(after[1], before[1] - 20)
        self.assertEqual(sum(after), pane._table.viewport().width())
        # the neighbour's new width is a user choice and persists; Name's is derived
        saved = json.loads(path.read_text())["widths"]
        self.assertEqual(saved["1"], after[1])
        self.assertNotIn("0", saved)

    def test_dragging_the_name_divider_back_gives_the_space_back(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 1600)
        before = self._widths(pane)
        h = pane._table.horizontalHeader()
        h.resizeSection(0, before[0] + 20)
        h.resizeSection(0, before[0])
        self.app.processEvents()
        self.assertEqual(self._widths(pane), before)

    def test_name_cannot_squeeze_the_next_column_below_its_minimum(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 1600)
        h = pane._table.horizontalHeader()
        h.resizeSection(0, 10_000)
        self.app.processEvents()
        w = self._widths(pane)
        self.assertGreaterEqual(w[1], h.minimumSectionSize())
        self.assertEqual(sum(w), pane._table.viewport().width())

    def test_hidden_neighbour_is_skipped(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 1600)
        pane._toggle_column(1, False)
        self.app.processEvents()
        before = self._widths(pane)
        pane._table.horizontalHeader().resizeSection(0, before[0] + 60)
        self.app.processEvents()
        after = self._widths(pane)
        self.assertEqual(after[2], before[2] - 60)
        self.assertEqual(
            sum(w for c, w in enumerate(after) if not pane._table.isColumnHidden(c)),
            pane._table.viewport().width(),
        )

    def test_showing_or_hiding_a_column_refits_name(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 1600)
        pane._toggle_column(4, False)
        self.app.processEvents()
        visible = lambda: sum(  # noqa: E731
            w for c, w in enumerate(self._widths(pane)) if not pane._table.isColumnHidden(c)
        )
        self.assertEqual(visible(), pane._table.viewport().width())
        pane._toggle_column(4, True)
        self.app.processEvents()
        self.assertEqual(visible(), pane._table.viewport().width())

    def test_moving_a_column_is_saved_and_restored(self) -> None:
        pane, path = self._pane()
        self._show(pane, 1600)
        h = pane._table.horizontalHeader()
        h.moveSection(h.visualIndex(4), 1)  # Owner next to Name
        self.app.processEvents()
        order = [h.logicalIndex(v) for v in range(h.count())]
        self.assertEqual(json.loads(path.read_text())["order"], order)
        pane2, _ = self._pane_from(path)
        self._show(pane2, 1600)
        h2 = pane2._table.horizontalHeader()
        self.assertEqual([h2.logicalIndex(v) for v in range(h2.count())], order)
        self.assertEqual(sum(self._widths(pane2)), pane2._table.viewport().width())

    def test_an_invalid_saved_order_is_ignored(self) -> None:
        for bad in ([0, 0, 1, 2, 3], [0, 1], [4, 3, 2, 1, 9], []):
            pane, _ = self._pane({"version": CP.VERSION, "order": bad})
            h = pane._table.horizontalHeader()
            self.assertEqual([h.logicalIndex(v) for v in range(h.count())], [0, 1, 2, 3, 4], bad)

    def test_restoring_the_order_does_not_rewrite_the_prefs_file(self) -> None:
        pane, path = self._pane({"version": CP.VERSION, "order": [0, 2, 1, 3, 4]})
        stamp = path.read_text()
        self._show(pane, 1200)
        self.assertEqual(path.read_text(), stamp)

    def test_moving_name_to_the_end_does_not_break_the_layout(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 1600)
        h = pane._table.horizontalHeader()
        h.moveSection(h.visualIndex(0), pane._model.columnCount() - 1)
        self.app.processEvents()
        h.resizeSection(0, self._widths(pane)[0] + 50)  # no neighbour to take from: no crash
        self.app.processEvents()
        self.assertEqual(sum(self._widths(pane)), pane._table.viewport().width())

    def test_regular_columns_have_usable_defaults(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 1500)
        w = self._widths(pane)
        self.assertGreaterEqual(min(w[1:]), 60, w)

    def test_divider_double_click_fits_a_column_to_its_content(self) -> None:
        from datetime import datetime

        from models.file_item import FileItem

        pane, _ = self._pane()
        pane._model.set_items(
            [
                FileItem(
                    name="a",
                    is_dir=False,
                    size=1,
                    modified=datetime(2026, 1, 1),
                    owner="averyveryverylongownername",
                    group="grp",
                ),
            ]
        )
        self._show(pane, 1500)
        pane._table.horizontalHeader().resizeSection(4, 60)
        pane._table.horizontalHeader().sectionHandleDoubleClicked.emit(4)
        self.app.processEvents()
        self.assertGreater(self._widths(pane)[4], 150)

    def test_narrow_pane_keeps_name_visible(self) -> None:
        pane, _ = self._pane()
        self._show(pane, 420)
        self.assertGreaterEqual(self._widths(pane)[0], 60)


class NameFitsBeforeOtherColumnsTest(_PaneTestBase):
    """A long file name was cut while Owner, Permissions and Modified kept
    their full default widths (500 px together) around much shorter text:
    Name only ever got what they left. The other columns now give up their
    slack - never more - before a name is cut."""

    LONG = "holiday-photos-2026-summer-lake-and-mountains.jpg"

    def _items(self, pane, names):
        from datetime import datetime

        from models.file_item import FileItem

        pane._model.set_items(
            [
                FileItem(name=n, size=12, modified=datetime(2026, 1, 1), owner="al", group="al")
                for n in names
            ]
        )
        self.app.processEvents()

    def _name_need(self, pane) -> int:
        return pane._table.sizeHintForColumn(0)

    def _floor(self, pane, col: int) -> int:
        h = pane._table.horizontalHeader()
        return max(
            h.minimumSectionSize(),
            pane._table.sizeHintForColumn(col),
            h.sectionSizeHint(col),
        )

    # --- happy --------------------------------------------------------------

    def test_happy_a_long_name_takes_the_slack_of_the_other_columns(self) -> None:
        pane, _ = self._pane()
        self._items(pane, [self.LONG, "a.txt"])
        self._show(pane, 760)
        w = self._widths(pane)
        self.assertGreaterEqual(w[0], self._name_need(pane), w)
        self.assertLess(w[4], 150, w)  # Owner gave up space for the name
        self.assertEqual(sum(w), pane._table.viewport().width())

    def test_happy_the_columns_grow_back_once_the_name_fits(self) -> None:
        pane, _ = self._pane()
        self._items(pane, [self.LONG])
        self._show(pane, 760)
        self._show(pane, 2000)
        w = self._widths(pane)
        self.assertEqual(w[1:], [90, 150, 110, 150], w)  # the defaults again

    # --- sad ----------------------------------------------------------------

    def test_sad_no_column_is_squeezed_below_its_own_content(self) -> None:
        pane, _ = self._pane()
        self._items(pane, [self.LONG * 3])
        self._show(pane, 640)
        w = self._widths(pane)
        for col in range(1, 5):
            self.assertGreaterEqual(w[col], self._floor(pane, col), (col, w))
        self.assertEqual(sum(w), pane._table.viewport().width())

    def test_sad_making_room_for_a_name_never_writes_prefs(self) -> None:
        pane, path = self._pane()
        self._items(pane, [self.LONG])
        self._show(pane, 700)
        self._show(pane, 1400)
        self.assertFalse(path.exists(), path.read_text() if path.exists() else "")

    # --- edge ---------------------------------------------------------------

    def test_edge_a_longer_name_arriving_later_refits(self) -> None:
        pane, _ = self._pane()
        self._items(pane, ["a.txt"])
        self._show(pane, 760)
        self._items(pane, [self.LONG])
        self._show(pane, 760)
        self.assertGreaterEqual(self._widths(pane)[0], self._name_need(pane))

    def test_edge_a_pane_not_yet_shown_keeps_its_stored_widths(self) -> None:
        # Before it is shown a pane has no real width; making room for a
        # name there cut a stored width (a regression test caught it).
        pane, _ = self._pane({"version": CP.VERSION, "widths": {"1": 222}, "hidden": []})
        self._items(pane, [self.LONG * 2])
        self.assertEqual(self._widths(pane)[1], 222)

    def test_edge_short_names_leave_the_stored_widths_alone(self) -> None:
        pane, _ = self._pane({"version": CP.VERSION, "widths": {"4": 220}, "hidden": []})
        self._items(pane, ["a.txt", "b.txt"])
        self._show(pane, 900)
        self.assertEqual(self._widths(pane)[4], 220)


if __name__ == "__main__":
    unittest.main()
