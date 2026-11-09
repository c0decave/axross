"""View > Layout Preset names the layouts, not their ids.

The product review found the submenu listing "single", "dual",
"quad-files", "dev-shells": the ids the code and the saved state use,
untranslated and with a hyphen in them.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _preset_menu(window):
    view = next(a.menu() for a in window.menuBar().actions() if a.text() == "&View")
    return next(a.menu() for a in view.actions() if a.text() == "La&yout Preset")


def test_happy_every_preset_has_a_name():
    from ui.layout_presets import PRESET_LABELS, PRESET_ORDER, PRESETS, preset_label

    assert set(PRESET_LABELS) == set(PRESETS) == set(PRESET_ORDER)
    for name in PRESET_ORDER:
        assert preset_label(name) != name
        assert "-" not in preset_label(name)


def test_happy_the_menu_shows_the_names_and_applies_the_preset(window, monkeypatch):
    from ui.layout_presets import PRESET_LABELS, PRESET_ORDER

    menu = _preset_menu(window)
    # UX round 7 (L8): every submenu entry gets a mnemonic ("&"), so compare
    # the shown names.
    texts = [a.text().replace("&", "") for a in menu.actions() if not a.isSeparator()]
    assert texts[: len(PRESET_ORDER)] == [PRESET_LABELS[n] for n in PRESET_ORDER]
    assert not set(PRESET_ORDER) & set(texts)

    applied = []
    monkeypatch.setattr(window, "apply_layout_preset", applied.append)
    next(a for a in menu.actions() if a.text().replace("&", "") == "Four File Panes").trigger()
    assert applied == ["quad-files"]


def test_edge_an_unknown_preset_keeps_its_id():
    from ui.layout_presets import preset_label

    assert preset_label("custom-thing") == "custom-thing"


def test_happy_the_cycle_hint_names_the_layout(window):
    window.cycle_layout_preset(forward=True)
    pump()
    assert window.statusBar().currentMessage() == "Layout: Two File Panes"
