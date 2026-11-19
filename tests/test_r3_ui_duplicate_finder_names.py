"""Round 3: the Duplicate Finder's details line under the list cut a long
path without blanks at the window's edge - a QLabel wraps at blanks only
(the window had been kept from widening in round 1). It wraps inside the
path now, and the whole line is shown. (A name with a bidi override never
reaches the index: core.cas refuses such paths.)"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.test_cas_dialog_view import _Base  # noqa: E402


class DuplicateFinderDetails(_Base):
    def test_edge_a_long_path_in_the_details_wraps_instead_of_being_cut(self) -> None:
        from ui.elided_label import WrapAnywhereLabel

        deep = self.tree / ("x" * 200)
        deep.mkdir()
        (deep / "a.bin").write_bytes(b"same content\n")
        self._write("b.bin")
        dlg = self._dialog()
        dlg.resize(700, 500)
        dlg.show()
        self.app.processEvents()
        self.assertIsInstance(dlg._details, WrapAnywhereLabel)
        row = self._row(dlg, deep / "a.bin")
        dlg._tree.setCurrentItem(row)
        self.app.processEvents()
        details = dlg._details
        self.assertTrue(details.text().startswith(str(deep / "a.bin")))
        self.assertLessEqual(details.width(), dlg.width())
        self.assertGreaterEqual(details.height(), details.heightForWidth(details.width()))
        self.assertLessEqual(dlg.width(), 1000)
        dlg.close()


def test_happy_a_muted_wrapped_value_is_muted_in_every_theme():
    """The details line and Show Checksum's path are muted (role="muted"):
    the themes style QLabel[role="muted"], which a WrapAnywhereLabel is not."""
    from PyQt6.QtGui import QPalette
    from PyQt6.QtWidgets import QApplication

    from ui import themes
    from ui.elided_label import WrapAnywhereLabel

    app = QApplication.instance() or QApplication([])
    before = app.styleSheet()
    try:
        modern = [themes.build_modern_qss(tokens) for tokens in themes._MODERN_VARIANTS.values()]
        for css in [themes._CLASSIC_MUTED_DARK, themes._CLASSIC_MUTED_LIGHT, *modern]:
            app.setStyleSheet(css)
            label = WrapAnywhereLabel("/srv/data/a.bin")
            label.setProperty("role", "muted")
            label.ensurePolished()
            plain = WrapAnywhereLabel("/srv/data/a.bin")
            plain.ensurePolished()
            role = QPalette.ColorRole.WindowText
            assert label.palette().color(role) != plain.palette().color(role), css[:60]
            label.deleteLater()
            plain.deleteLater()
    finally:
        app.setStyleSheet(before)
