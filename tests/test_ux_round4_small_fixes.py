"""The small findings of UX review round 4.

- Zoom Out showed the close cross "x"; Move Pane Left, Cycle Previous and
  Previous Pane / Area pointed right.
- The Workspace menu had no mnemonics and its entries no icons.
- F1 did nothing in the Keyboard Shortcuts window.
- A new German user started with the tags "Important" and "Review later".
- The Compare Panes summary was cut off beside the buttons.
- About said "Datei > Connection Manager…." and sent protocol names
  through the catalogue.
- The duplicate finder had two names: "Duplicate Finder…" (View) and
  "Find Duplicate Files…" (right click, Actions).
"""

from __future__ import annotations

import collections
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()


@pytest.fixture(params=["en", "de"])
def window(request, tmp_path, monkeypatch):
    from core import i18n

    stores = isolate(tmp_path, monkeypatch)
    i18n.install(request.param)
    win = stores.make_window()
    win.show()
    APP.processEvents()
    yield win
    stores.restore()
    i18n.install("en")


def _mnemonic(text: str) -> str | None:
    m = re.search(r"&([^&])", text.replace("&&", ""))
    return m.group(1).lower() if m else None


def _plain_icon_name(win, source: str) -> str:
    return win._PLAIN_MENU_ICONS[source]


def test_happy_zoom_out_is_a_minus_and_left_points_left(window):
    from ui.icon_provider import icon

    icons = window._PLAIN_MENU_ICONS
    assert icons["Zoom &Out"] == "minus" and not icon("minus").isNull()
    for entry in ("Move Pane &Left", "Cycle Previous", "Focus Previous Area",
                  "&Previous Pane\tShift+Tab"):
        assert icons[entry] == "chevrons-left", entry
    assert not icon("chevrons-left").isNull()


def test_happy_the_workspace_menu_has_mnemonics_and_icons(window):
    menu = window._workspace_menu
    menu.aboutToShow.emit()
    entries = [a for a in menu.actions()
               if not a.isSeparator() and a.text() and not a.isCheckable()]
    letters = collections.Counter(_mnemonic(a.text()) for a in entries)
    assert None not in letters, [a.text() for a in entries if _mnemonic(a.text()) is None]
    assert max(letters.values()) == 1, letters
    assert all(not a.icon().isNull() for a in entries), [a.text() for a in entries
                                                        if a.icon().isNull()]
    new = window._new_workspace_menu
    sub = [_mnemonic(a.text()) for a in new.actions() if a.text()]
    assert None not in sub and len(set(sub)) == len(sub)


def test_sad_f1_in_keyboard_shortcuts_opens_the_handbook(window, monkeypatch):
    from ui import handbook
    from ui.shortcuts_dialog import ShortcutsDialog

    opened = []
    monkeypatch.setattr(handbook, "open_handbook_for", lambda w, topic: opened.append(topic))
    dialog = ShortcutsDialog(window)
    try:
        dialog.help_shortcut.activated.emit()
        assert opened == ["handbook"]
    finally:
        dialog.deleteLater()


def test_edge_new_tags_are_in_the_interface_language(tmp_path):
    from core import i18n
    from core.tags import TagStore

    i18n.install("de")
    try:
        names = [t.name for t in TagStore(tmp_path / "tags.json").tags()]
    finally:
        i18n.install("en")
    assert names == ["Wichtig", "Später ansehen"]
    # A saved file keeps its names, whatever the language.
    (tmp_path / "old.json").write_text(json.dumps(
        {"tags": [{"name": "Important", "color": "#d9534f"}], "items": []}), encoding="utf-8")
    i18n.install("de")
    try:
        assert [t.name for t in TagStore(tmp_path / "old.json").tags()] == ["Important"]
    finally:
        i18n.install("en")


def test_edge_the_compare_summary_wraps_on_a_row_of_its_own():
    from ui import compare_dialog

    source = Path(compare_dialog.__file__).read_text(encoding="utf-8")
    assert "self._summary.setWordWrap(True)" in source
    assert "actions.addWidget(self._summary)" not in source


def test_edge_about_has_no_double_stop_and_keeps_protocol_names(window):
    text = window.about_html()
    assert "…." not in text and ".." not in text.replace("...", "")
    assert "<b>SFTP / SCP</b>" in text
    if "Profil" in text:
        assert "je Profile" not in text and "pro Profil" in text


def test_happy_one_name_for_the_duplicate_finder():
    german = json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))
    pane = (ROOT / "ui/file_pane.py").read_text(encoding="utf-8")
    assert "Find Duplicate Fi" not in pane and 'tr("Dup&licate Finder…")' in pane
    def bare(text):
        return text.replace("&", "")

    assert bare(german["Dup&licate Finder…"]) == bare(german["&Duplicate Finder…"])
