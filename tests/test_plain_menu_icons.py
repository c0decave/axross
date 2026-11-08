"""Every plain menu entry has an icon, in English and in German.

The feature audit listed the entries that open a window; the rest (Import
SSH Config, Zoom, Quit, About, the pane moves, ...) still had none. Theme
and layout choices are radio entries with a check mark and stay without.
The icons are matched by translated text, so a German menu needs them too.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: Entries that legitimately carry no icon: dynamic or state texts.
NO_ICON = ("No file pane is active", "Kein Datei-Pane ist aktiv")


def _missing(window) -> list[str]:
    out = []

    def walk(menu, path):
        for action in menu.actions():
            if action.isSeparator():
                continue
            name = f"{path} > {action.text().replace('&', '')}"
            if action.menu() is not None:
                walk(action.menu(), name)
            elif (action.icon().isNull() and action.isVisible() and not action.isCheckable()
                  and not any(n in name for n in NO_ICON)):
                out.append(name)
    for action in window.menuBar().actions():
        if action.menu() is not None:
            walk(action.menu(), action.text().replace("&", ""))
    return out


@pytest.mark.parametrize("language", ["en", "de"])
def test_happy_every_plain_menu_entry_has_an_icon(language, tmp_path, monkeypatch):
    for var, sub in (("HOME", ""), ("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", "d"),
                     ("XDG_STATE_HOME", "s"), ("XDG_CACHE_HOME", "c")):
        monkeypatch.setenv(var, str(tmp_path / sub))
    from core import i18n

    i18n.install(language)
    try:
        from ui.main_window import MainWindow

        monkeypatch.setattr(MainWindow, "_SESSION_FILE", tmp_path / "session.json")
        monkeypatch.setattr(MainWindow, "_RECENTS_FILE", tmp_path / "recents.json")
        window = MainWindow()
        window._reconnect_timer.stop()
        try:
            window._populate_bookmarks_menu()
            assert _missing(window) == []
        finally:
            window._quit_with_transfers = True
            window.close()
            window.deleteLater()
    finally:
        i18n.install("en")
