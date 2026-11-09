"""Only languages whose catalogue covers the interface are offered.

The product review found Settings > General > Language offering seven
languages while five catalogues were empty and the German one had 88
entries - and the language was picked by itself from LANG or the time
zone. A machine in Paris got English menus labelled as French; a German
one got menus half German, half English.

Now a language is offered (and picked from the locale or the zone) only
when its catalogue reaches core.i18n.MIN_CATALOGUE_ENTRIES, and German
covers the whole menu bar, the Settings pages and Qt's own buttons.
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

from core import i18n  # noqa: E402

GERMAN = Path(__file__).resolve().parent.parent / "resources" / "i18n" / "de.json"


def _catalogue(tmp_path, lang: str, count: int) -> Path:
    (tmp_path / f"{lang}.json").write_text(
        json.dumps({f"Label {n}": f"Etikett {n}" for n in range(count)}), encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------
# Which languages are offered
# --------------------------------------------------------------------------


def test_happy_english_and_german_are_offered_the_empty_catalogues_are_not():
    offered = i18n.available_languages()
    assert list(offered)[:2] == ["en", "de"]
    for lang in ("fr", "es", "pl", "sv", "nb"):
        assert lang not in offered, f"{lang} has {i18n.catalogue_size(lang)} entries"


def test_edge_a_catalogue_is_offered_from_the_threshold_on(tmp_path):
    limit = i18n.MIN_CATALOGUE_ENTRIES
    _catalogue(tmp_path, "fr", limit - 1)
    _catalogue(tmp_path, "pl", limit)
    offered = i18n.available_languages(tmp_path)
    assert "fr" not in offered
    assert offered["pl"] == "Polski"
    assert "en" in offered


def test_sad_a_missing_or_corrupt_catalogue_is_not_offered(tmp_path):
    (tmp_path / "es.json").write_text("{not json", encoding="utf-8")
    offered = i18n.available_languages(tmp_path)
    assert set(offered) == {"en"}


# --------------------------------------------------------------------------
# Which language is picked
# --------------------------------------------------------------------------


def test_happy_a_french_locale_gets_english_not_empty_french():
    assert i18n.detect_language(configured=None, env={"LANG": "fr_FR.UTF-8"}, timezone=None) == "en"
    assert i18n.detect_language(configured=None, env={}, timezone="Europe/Paris") == "en"
    # a stored choice from before is not honoured either
    assert i18n.detect_language(configured="sv", env={}, timezone=None) == "en"


def test_happy_german_is_still_picked():
    assert i18n.detect_language(configured=None, env={"LANG": "de_DE.UTF-8"}, timezone=None) == "de"
    assert i18n.detect_language(
        configured=None, env={"LANG": "C"}, timezone="Europe/Berlin") == "de"


def test_edge_a_lower_language_falls_through_to_the_next_signal():
    """A French setting under a German locale: the locale still counts."""
    assert i18n.detect_language(
        configured="fr", env={"LANG": "de_DE.UTF-8"}, timezone=None) == "de"


# --------------------------------------------------------------------------
# The German catalogue covers the menu bar
# --------------------------------------------------------------------------

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialogButtonBox  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


#: Submenus whose entries are the user's data (profile names), not labels.
_DATA_MENUS = {"New Agent Tab from &Profile"}
_DATA_TEXT = re.compile(r"^&?Workspace \d+$")


def _menu_texts(window) -> list[tuple[str, str]]:
    """(path, text) of every menu-bar entry, submenus included, in order."""
    out: list[tuple[str, str]] = []

    def walk(menu, path: str) -> None:
        menu.aboutToShow.emit()
        for action in menu.actions():
            if action.isSeparator():
                continue
            out.append((path, action.text()))
            if action.menu() is not None:
                walk(action.menu(), f"{path} > {action.text()}")

    for top in window.menuBar().actions():
        out.append(("", top.text()))
        walk(top.menu(), top.text())
    return out


def _window_texts(language: str) -> list[tuple[str, str]]:
    from ui.main_window import MainWindow

    i18n.install(language)
    try:
        win = MainWindow()
        win._reconnect_timer.stop()
        win.show()
        pump()
        try:
            return _menu_texts(win)
        finally:
            win.close()
            win.deleteLater()
            APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
            pump()
    finally:
        i18n.install(i18n.DEFAULT_LANGUAGE)


@pytest.fixture(scope="module")
def menus():
    return _window_texts("en"), _window_texts("de")


def test_happy_every_menu_bar_entry_has_a_german_entry(menus):
    english, german = menus
    assert len(english) == len(german), "the German menus have other entries"
    catalogue = json.loads(GERMAN.read_text(encoding="utf-8"))
    untranslated = []
    for (en_path, en_text), (_de_path, de_text) in zip(english, german):
        if any(en_path.endswith(menu) for menu in _DATA_MENUS) or _DATA_TEXT.match(en_text):
            continue
        # A text the same in both languages must be a deliberate entry
        # ("Shell" stays "Shell"), not one the catalogue lacks.
        # ui/mnemonics.py adds a free "&" letter to entries without one, so
        # the shown text can carry an "&" its catalogue key has not.
        bare = en_text.replace("&", "")
        if en_text == de_text and en_text not in catalogue and bare not in catalogue:
            untranslated.append(f"{en_path} > {en_text}")
    assert untranslated == [], "\n".join(untranslated)


def test_happy_the_settings_pages_have_german_titles():
    from ui.agent_settings_dialog import AGENT_TABS
    from ui.settings_dialog import _BUILTIN
    from ui.voice_settings_page import VoicePage

    catalogue = json.loads(GERMAN.read_text(encoding="utf-8"))
    titles = [title for title, *_rest in _BUILTIN.values()]
    titles += [title for _id, title in AGENT_TABS] + [VoicePage.TITLE, "Settings"]
    assert [t for t in titles if t not in catalogue] == []


def test_happy_qt_standard_buttons_speak_german():
    from ui.qt_translations import CatalogueTranslator

    i18n.install("de")
    translator = CatalogueTranslator()
    APP.installTranslator(translator)
    try:
        box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Close
        )
        texts = sorted(b.text().replace("&", "") for b in box.buttons())
        assert texts == ["Abbrechen", "OK", "Schließen", "Übernehmen"]
        # Other Qt texts are left to Qt, not blanked.
        from PyQt6.QtCore import QCoreApplication

        assert QCoreApplication.translate("QLineEdit", "&Undo") == "&Undo"
    finally:
        APP.removeTranslator(translator)
        i18n.install(i18n.DEFAULT_LANGUAGE)


def test_edge_english_installs_no_qt_translator():
    from ui.qt_translations import install_qt_translator

    i18n.install(i18n.DEFAULT_LANGUAGE)
    assert install_qt_translator(APP) is None


def test_happy_the_language_picker_lists_only_the_offered_languages(monkeypatch):
    from ui.settings_dialog import GeneralPage

    class _Prefs:
        restore_layout_on_start = False

    class _Window:
        def current_window_prefs(self):
            return _Prefs()

    page = GeneralPage(_Window())
    codes = [page.language_combo.itemData(i) for i in range(page.language_combo.count())]
    assert codes == ["", *i18n.available_languages()]
    assert "fr" not in codes and "de" in codes
