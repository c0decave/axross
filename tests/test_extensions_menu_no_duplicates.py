"""The Extensions menu names each tool once.

Reported: with the bundled extensions on, Media Player, Folder Treemap and
Drives Overview were listed twice - once as the window's own tool entry
(translated), once as their panel's show/hide toggle (English in German:
the panel titles were not translated). The window's entry, which also
switches a tool on, is the one kept; the panels' titles are translated.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

BUNDLED = ("system_info", "drives_overview", "folder_treemap", "media_player",
           "audio_mixer", "bluetooth")


def pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture(params=["en", "de"])
def window(request, tmp_path, monkeypatch):
    from core import extensions, i18n

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    i18n.install(request.param)
    for name in BUNDLED:
        extensions.set_enabled(f"bundled:{name}", True)
    win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.show()
    pump()
    try:
        yield win
    finally:
        if not sip.isdeleted(win):
            win.close()
            win.deleteLater()
        pump(0.05)
        i18n.install("en")


def _norm(text: str) -> str:
    return text.replace("&", "").rstrip("…").rstrip(".").strip().casefold()


def test_happy_no_tool_is_listed_twice(window):
    menu = window.extensions_menu
    menu.aboutToShow.emit()
    texts = [_norm(a.text()) for a in menu.actions() if not a.isSeparator() and a.isVisible()]
    loaded = window.extension_host.loaded_ids()
    for name in ("media_player", "folder_treemap", "drives_overview"):
        assert f"bundled:{name}" in loaded
    assert len(texts) == len(set(texts)), texts


def test_happy_each_tool_panel_keeps_one_entry_that_shows_it(window):
    from core.i18n import tr

    menu = window.extensions_menu
    texts = [a.text() for a in menu.actions()]
    for title in ("Media Player", "Folder Treemap", "Drives Overview"):
        assert texts.count(tr(title)) == 1, (title, texts)
    # the panels' own titles are translated too
    for ext_id, title in (("bundled:folder_treemap", "Folder Treemap"),
                          ("bundled:drives_overview", "Drives Overview")):
        docks = window.extension_host.docks(ext_id)
        assert [d.windowTitle() for d in docks] == [tr(title)]
