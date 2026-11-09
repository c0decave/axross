"""A column that steps aside for a long name never comes back below its
header label (UX review round 7, M1).

At 1280x800 with the tour offer bar the German "Eigentümer" column came
back at 75 px, drawn as "igentüme", and the columns jumped on a refresh:
the floor was QHeaderView.sectionSizeHint(), which is 0 for a hidden
column, so a column that had stepped aside was measured by its content
only. The floor now measures the label in the header's real style sheet
font, with its padding and room for a sort arrow - the same for a shown
and a hidden column.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui import column_prefs as CP  # noqa: E402

# What the themes give the header (ui/themes.py): bold label, wide padding.
HEADER_CSS = "QHeaderView::section { padding: 6px 8px; font-weight: 600; }"


class HeaderLabelFloorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core import i18n

        i18n.install("de")
        self.addCleanup(i18n.install, "en")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.root = Path(d)
        prefs = self.root / "column_prefs.json"
        prefs.write_text(json.dumps({"version": CP.VERSION, "widths": {}, "hidden": []}))
        patcher = mock.patch.object(CP, "DEFAULT_PATH", prefs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _pane(self):
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(LocalFS())
        pane.setStyleSheet(HEADER_CSS)
        self.addCleanup(pane.deleteLater)
        return pane

    def _items(self, pane, names) -> None:
        from datetime import datetime

        from models.file_item import FileItem

        pane._model.set_items(
            [
                FileItem(name=n, size=12, modified=datetime(2026, 1, 1), owner="root", group="root")
                for n in names
            ]
        )
        self.app.processEvents()

    def _show(self, pane, width: int) -> None:
        pane.resize(width, 500)
        pane.show()
        self.app.processEvents()
        self.app.processEvents()

    def _drawn_label_need(self, pane, col: int) -> int:
        """Width the style needs to draw the label of *col* with an arrow."""
        from PyQt6.QtCore import QSize, Qt
        from PyQt6.QtWidgets import QStyle, QStyleOptionHeader

        header = pane._table.horizontalHeader()
        opt = QStyleOptionHeader()
        opt.initFrom(header)
        opt.orientation = Qt.Orientation.Horizontal
        opt.text = str(pane._model.headerData(col, Qt.Orientation.Horizontal))
        opt.sortIndicator = QStyleOptionHeader.SortIndicator.SortDown
        return header.style().sizeFromContents(
            QStyle.ContentsType.CT_HeaderSection, opt, QSize(), header
        ).width()

    # --- happy --------------------------------------------------------------

    def test_happy_every_shown_column_is_at_least_as_wide_as_its_label(self) -> None:
        pane = self._pane()
        self._items(pane, ["Documents", "backup.tar.gz", "todo.txt"])
        header = pane._table.horizontalHeader()
        for width in range(420, 900, 20):
            self._show(pane, width)
            for col in range(1, pane._model.columnCount()):
                if header.isSectionHidden(col):
                    continue
                self.assertGreaterEqual(
                    header.sectionSize(col), self._drawn_label_need(pane, col), (width, col)
                )

    # --- sad ----------------------------------------------------------------

    def test_sad_a_hidden_column_is_measured_by_its_label_not_zero(self) -> None:
        pane = self._pane()
        self._items(pane, ["Documents", "todo.txt"])
        self._show(pane, 1400)
        pane._table.setColumnHidden(4, True)  # as when Eigentümer stepped aside
        self.assertGreaterEqual(pane._column_floor(4), self._drawn_label_need(pane, 4))

    def test_sad_a_refresh_does_not_bring_a_squeezed_column_back(self) -> None:
        # The reported case: German, a pane about 510 px wide, a refresh.
        pane = self._pane()
        names = ["Documents", "Pictures", "Projects", "backup.tar.gz", "todo.txt"]
        self._items(pane, names)
        self._show(pane, 520)
        header = pane._table.horizontalHeader()
        before = [header.sectionSize(c) for c in range(5)]
        hidden_before = [header.isSectionHidden(c) for c in range(5)]
        self._items(pane, names + ["zz"])
        pane._content_widths_changed()
        self.app.processEvents()
        self.app.processEvents()
        self.assertEqual([header.isSectionHidden(c) for c in range(5)], hidden_before)
        self.assertEqual([header.sectionSize(c) for c in range(5)], before)

    # --- edge ---------------------------------------------------------------

    def test_edge_the_label_width_is_the_same_shown_or_hidden(self) -> None:
        pane = self._pane()
        self._items(pane, ["a.txt"])
        self._show(pane, 1400)
        shown = pane._label_width(4)
        pane._table.setColumnHidden(4, True)
        self.assertEqual(pane._label_width(4), shown)
        self.assertGreater(shown, pane._table.fontMetrics().horizontalAdvance("Eigentümer"))


if __name__ == "__main__":
    unittest.main()
