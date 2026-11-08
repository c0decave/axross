"""No Settings page scrolls sideways at the dialog's default size.

The product review measured Edit > Settings… at its 980 x 660 default:
Analysis needed 40 px more (the cache folder, a label as wide as its
path), Agent 37 px (a check box with its explanation in brackets, combo
boxes as wide as their longest entry) and Voice 50 px (the voice, its
download state and the buttons in one row).
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

from PyQt6.QtWidgets import QComboBox  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def stores(tmp_path, monkeypatch):
    from core import analysis_settings as AS

    # A long home folder, as on the reviewer's machine: the path has no
    # space a label could wrap at.
    deep = tmp_path / ("a-rather-long-folder-name-" * 6) / "axross" / "analysis-cache"
    monkeypatch.setattr(AS, "cache_dir", lambda: deep)
    # The default size on a screen it fits: since review round 4 the
    # dialog is capped at a smaller screen (offscreen is 800x600).
    from PyQt6.QtCore import QRect

    from ui import screen_fit

    monkeypatch.setattr(screen_fit, "available_geometry",
                        lambda widget=None: QRect(0, 0, 1280, 800))
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


def _overflow(stores) -> dict[str, int]:
    win = stores.make_window()
    dialog = stores.settings_dialog(win)
    dialog.show()
    pump()
    assert (dialog.width(), dialog.height()) == (980, 660)
    out = {}
    for page_id in dialog.page_ids():
        dialog.show_page(page_id)
        pump(0.05)
        bar = dialog._scrolls[page_id].horizontalScrollBar()
        out[page_id] = bar.maximum()
    dialog.reject()
    return out


def test_happy_no_page_scrolls_sideways_at_the_default_size(stores):
    overflow = _overflow(stores)
    assert {"analysis", "agent", "voice"} <= set(overflow)
    assert {page: px for page, px in overflow.items() if px} == {}


def test_happy_no_page_scrolls_sideways_in_german_either(stores):
    from core import i18n

    i18n.install("de")
    try:
        overflow = _overflow(stores)
    finally:
        i18n.install(i18n.DEFAULT_LANGUAGE)
    assert {page: px for page, px in overflow.items() if px} == {}


def test_edge_the_cache_folder_is_shown_whole_and_can_be_copied(stores):
    from core import analysis_settings as AS

    win = stores.make_window()
    page = stores.settings_dialog(win, "analysis").page("analysis")
    assert page.cache_location.text() == str(AS.cache_dir())
    assert page.cache_location.isReadOnly()


def test_edge_a_narrowed_combo_still_lists_its_entries_whole(stores):
    from ui.agent_settings_dialog import LEVEL_LABELS

    win = stores.make_window()
    page = stores.settings_dialog(win, "agent").page("agent")
    combo: QComboBox = page.level_combo
    assert combo.minimumSizeHint().width() < combo.fontMetrics().horizontalAdvance(
        max(LEVEL_LABELS.values(), key=len))
    assert sorted(combo.itemText(i) for i in range(combo.count())) == sorted(
        LEVEL_LABELS.values())
    # The explanation the check box carried is still on the page.
    assert page.bypass_check.text().startswith("Bypass may be chosen")
    assert "without asking" in page.bypass_check.toolTip()
