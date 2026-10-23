"""The Voice settings page (ui.voice_settings_page.VoicePage): a page widget
of its own - load, validate, apply, save - shown in Agent Settings."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QKeySequence  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import llm_profiles as LP  # noqa: E402
from core import voice_settings as VS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _page(settings=None):
    from ui.voice_settings_page import VoicePage

    return VoicePage(settings=settings)


def _select(combo, data):
    index = combo.findData(data)
    assert index >= 0, data
    combo.setCurrentIndex(index)


def test_happy_the_page_shows_the_settings():
    s = VS.VoiceSettings(output_enabled=True, language="de", gender="female",
                         input_mode="conversation", hotkey="Ctrl+Shift+V",
                         after_recognition="send", silence_seconds=2.0)
    page = _page(s)
    assert page.TITLE == "Voice"
    assert page.output_check.isChecked()
    assert page.language_combo.currentData() == "de"
    assert page.gender_combo.currentData() == "female"
    assert page.mode_combo.currentData() == "conversation"
    assert page.hotkey_edit.keySequence().toString(QKeySequence.SequenceFormat.PortableText) \
        == "Ctrl+Shift+V"
    assert page.after_combo.currentData() == "send"
    assert page.silence_spin.value() == 2.0


@pytest.mark.parametrize("field,widget,value", [
    ("language", "language_combo", "en"), ("gender", "gender_combo", "female"),
    ("input_mode", "mode_combo", "toggle"), ("after_recognition", "after_combo", "send"),
])
def test_happy_every_choice_reaches_the_settings(field, widget, value):
    page = _page()
    _select(getattr(page, widget), value)
    assert page.apply(VS.VoiceSettings()).get(field) == value


def test_happy_hotkey_silence_and_output_reach_the_settings():
    page = _page()
    page.hotkey_edit.setKeySequence(QKeySequence("F7"))
    page.silence_spin.setValue(0.8)
    page.output_check.setChecked(True)
    s = page.apply(VS.VoiceSettings())
    assert (s.hotkey, s.silence_seconds, s.output_enabled) == ("F7", 0.8, True)


def test_happy_save_writes_the_file(tmp_path):
    path = tmp_path / "voice.json"
    page = _page()
    _select(page.language_combo, "de")
    assert page.save(path)
    assert json.loads(path.read_text())["language"] == "de"


def test_sad_a_hold_key_that_types_is_refused(tmp_path):
    path = tmp_path / "voice.json"
    page = _page()
    page.hotkey_edit.setKeySequence(QKeySequence("A"))
    assert page.problems()
    assert not page.save(path)
    assert not path.exists()


def test_sad_an_empty_hold_key_is_refused():
    page = _page()
    page.hotkey_edit.clear()
    assert page.problems()


def test_edge_constructing_the_page_touches_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _page()
    assert not (tmp_path / ".config").exists()


def test_edge_load_replaces_what_the_page_shows():
    page = _page(VS.VoiceSettings(language="de"))
    page.load(VS.VoiceSettings(language="en"))
    assert page.language_combo.currentData() == "en"


# -- the page in Edit > Settings… -------------------------------------------------------------


def test_happy_the_page_protocol_dirty_save_and_apply(tmp_path):
    from ui.voice_settings_page import VoicePage

    path = tmp_path / "voice.json"
    applied = []
    page = VoicePage(settings=VS.VoiceSettings(), path=path,
                     after_save=lambda s: applied.append(s.input_mode))
    assert not page.is_dirty()
    _select(page.mode_combo, "toggle")
    assert page.is_dirty()
    assert page.save()
    assert not page.is_dirty()
    assert VS.VoiceSettings.load(path).input_mode == "toggle" and applied == ["toggle"]


@pytest.fixture
def stores(tmp_path, monkeypatch):
    from tests.settings_testkit import isolate

    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


def test_happy_e2e_the_settings_dialog_has_voice_after_agent_and_applies_it(stores):
    win = stores.make_window()
    dialog = stores.settings_dialog(win)
    ids = dialog.page_ids()
    assert ids.index("voice") == ids.index("agent") + 1
    page = dialog.page("voice")
    _select(page.mode_combo, "toggle")
    assert dialog.dirty_page_ids() == ["voice"]
    assert dialog.apply(), dialog.error_text()
    assert VS.VoiceSettings.load().input_mode == "toggle"
    dock = win._agent_dock
    assert dock.voice.settings.input_mode == "toggle"
    assert dock.current_tab().mic_button.isCheckable()


def test_sad_e2e_the_settings_dialog_refuses_a_typing_hold_key(stores):
    win = stores.make_window()
    dialog = stores.settings_dialog(win)
    dialog.page("voice").hotkey_edit.setKeySequence(QKeySequence("B"))
    assert not dialog.apply()
    assert "hold key" in dialog.error_text()
    assert not VS.settings_file().exists()


def test_edge_agent_settings_keep_no_voice_tab_of_their_own():
    from ui.agent_settings_dialog import AGENT_TABS

    assert "voice" not in {tab_id for tab_id, _title in AGENT_TABS}
