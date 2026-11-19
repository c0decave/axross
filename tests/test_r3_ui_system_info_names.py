"""Round 3: System Information showed what a device reports about itself
as it is. A USB stick, a Bluetooth adapter or a monitor names itself
(its product string, its EDID name): one named ``Keyboard\\u202egnp.exe``
read reversed on the Overview, in the field grids and in the tables,
where every list of axross shows a bidi override as U+FFFD. The values
copied and saved stay as the machine reported them."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"
NAME = f"Keyboard{RLO}gnp.exe"


def test_sad_a_device_name_in_a_table_is_defused():
    from ui.system_info_window import FitTree

    tree = FitTree({"columns": ["Device", "Vendor"], "rows": [[NAME, "ACME"]]})
    assert tree.topLevelItem(0).text(0) == "Keyboard\ufffdgnp.exe"
    tree.deleteLater()


def test_sad_a_device_name_in_a_field_grid_and_a_small_line_is_defused():
    from ui.system_info_window import FieldGrid, small

    grid = FieldGrid([{"label": "Model", "value": NAME}])
    texts = [w.text() for w in grid.findChildren(QLabel)]
    assert "Keyboard\ufffdgnp.exe" in texts
    assert not [t for t in texts if RLO in t]
    assert small(NAME).text() == "Keyboard\ufffdgnp.exe"
    grid.deleteLater()


def test_happy_plain_values_stay_as_they_are():
    from ui.system_info_window import small

    assert small("Intel(R) Core(TM) i7 · 3.2 GHz").text() == "Intel(R) Core(TM) i7 · 3.2 GHz"
