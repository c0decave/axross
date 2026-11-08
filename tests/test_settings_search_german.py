"""Settings search finds a page by the German word for its keyword.

Review round 3 (UX): in German, Edit > Settings… > "Find a setting" only
matched the page's widget texts and the English keyword list. A German
user typing "Farbschema", "dunkel", "Symbolleiste", "Lautsprecher" or
"Protokollierung" found nothing - those words name the setting only in
the keyword list, which was searched in English alone. Each keyword is
now searched in English and through tr() in the interface language.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.fixture
def german():
    from core import i18n

    i18n.install("de")
    yield
    i18n.install(i18n.DEFAULT_LANGUAGE)


def _dialog(stores):
    win = stores.make_window()
    return stores.settings_dialog(win)


def test_happy_german_keywords_find_their_page(stores, german):
    dialog = _dialog(stores)
    for word, page in (("Farbschema", "appearance"), ("dunkel", "appearance"),
                       ("Symbolleiste", "toolbar"), ("Lautsprecher", "audio"),
                       ("Kopfhörer", "audio"), ("Protokollierung", "logging"),
                       ("Erweiterungen", "extensions"), ("Zugriff", "agent")):
        dialog.apply_filter(word)
        assert page in dialog.visible_page_ids(), (word, dialog.visible_page_ids())
    dialog.reject()


def test_happy_english_keywords_still_work_in_german(stores, german):
    """Someone who knows the English name keeps finding it."""
    dialog = _dialog(stores)
    for word, page in (("headphones", "audio"), ("tint", "toolbar"), ("dark", "appearance")):
        dialog.apply_filter(word)
        assert page in dialog.visible_page_ids(), word
    dialog.reject()


def test_sad_a_word_no_page_has_still_finds_nothing_in_german(stores, german):
    dialog = _dialog(stores)
    dialog.apply_filter("Quarkstrudel")
    assert dialog.visible_page_ids() == []
    assert not dialog.no_match_label.isHidden()
    dialog.reject()


def test_edge_case_and_umlauts_do_not_matter(stores, german):
    dialog = _dialog(stores)
    dialog.apply_filter("  KOPFHÖRER ")
    assert "audio" in dialog.visible_page_ids()
    dialog.reject()
