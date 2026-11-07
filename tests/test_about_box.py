"""Help > About axross: today's features, in the interface language.

The product review found the About box hard-coded in English and out of
date: no Agent or MCP dock, no Bluetooth, Audio Mixer or System
Information.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from axross._version import __version__  # noqa: E402

APP = QApplication.instance() or QApplication([])
GERMAN = Path(__file__).resolve().parent.parent / "resources" / "i18n" / "de.json"


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def make_window(monkeypatch):
    from core import i18n
    from ui.main_window import MainWindow

    made = []

    def build(language: str):
        monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator(language))
        win = MainWindow()
        win._reconnect_timer.stop()
        made.append(win)
        return win

    yield build
    for win in made:
        win.close()
        win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _plain(html_text: str) -> str:
    return re.sub(r"<[^>]+>", " ", html_text)


def test_happy_about_names_todays_features_and_the_version(make_window):
    win = make_window("en")
    dialog = win.about_dialog()
    title, text = dialog.windowTitle(), dialog.html
    assert title == f"About axross {__version__}"
    plain = _plain(text)
    assert __version__ in plain
    for name in ("Agent", "MCP server", "Bluetooth", "Audio Mixer", "System Information",
                 "Media Player", "Bookmarks", "Analysis (sift)", "SFTP / SCP"):
        assert name in plain, name


def test_happy_about_speaks_german(make_window):
    win = make_window("de")
    dialog = win.about_dialog()
    title, text = dialog.windowTitle(), dialog.html
    assert title == f"Über axross {__version__}"
    plain = _plain(text)
    for german in ("Protokolle", "Funktionen", "Systeminformationen", "Warteschlange"):
        assert german in plain, german


def test_edge_every_text_of_the_about_box_has_a_german_entry():
    from ui.main_window import MainWindow

    catalogue = json.loads(GERMAN.read_text(encoding="utf-8"))
    texts = [what for _name, what in MainWindow._ABOUT_PROTOCOLS]
    texts += list(MainWindow._ABOUT_FEATURES)
    for pairs in (MainWindow._ABOUT_PANELS, MainWindow._ABOUT_TOOLS):
        texts += [t for pair in pairs for t in pair]
    texts += ["About axross {version}", "Protocols", "Features", "Panels", "Tools"]
    assert [t for t in texts if t not in catalogue] == []


def test_sad_a_translation_is_text_not_markup(make_window, monkeypatch, tmp_path):
    from core import i18n

    win = make_window("en")
    (tmp_path / "de.json").write_text(json.dumps({"Protocols": "<b>Proto</b> & co"}),
                                      encoding="utf-8")
    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de", tmp_path))
    text = win.about_html()
    assert "&lt;b&gt;Proto&lt;/b&gt; &amp; co" in text
