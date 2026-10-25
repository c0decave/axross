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
    s = VS.VoiceSettings(output_enabled=True, language="de", voice_de="piper-de-kerstin",
                         input_mode="conversation", hotkey="Ctrl+Shift+V",
                         after_recognition="send", silence_seconds=2.0)
    page = _page(s)
    assert page.TITLE == "Voice"
    assert page.output_check.isChecked()
    assert page.language_combo.currentData() == "de"
    assert page.voice_combos["de"].currentData() == "piper-de-kerstin"
    assert page.voice_combos["en"].currentData() == "piper-en-ryan"
    assert page.mode_combo.currentData() == "conversation"
    assert page.hotkey_edit.keySequence().toString(QKeySequence.SequenceFormat.PortableText) \
        == "Ctrl+Shift+V"
    assert page.after_combo.currentData() == "send"
    assert page.silence_spin.value() == 2.0


@pytest.mark.parametrize("field,widget,value", [
    ("language", "language_combo", "en"),
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


# -- the voices and how they speak ------------------------------------------------------------

import threading  # noqa: E402
import time  # noqa: E402

from PyQt6.QtCore import QObject, Qt, pyqtSignal  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402

from core import voice_models as VM  # noqa: E402


def pump(until, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if until():
            return True
        time.sleep(0.01)
    return False


class FakePreview(QObject):
    busy_changed = pyqtSignal(str)
    message = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.plays: list[tuple[str, dict]] = []
        self.stops = 0
        self.shut = False
        self.playing_voice = ""

    def play(self, voice_id, tuning):
        self.plays.append((voice_id, dict(tuning)))
        self.playing_voice = voice_id
        self.busy_changed.emit(voice_id)
        self.message.emit(f"speaking {voice_id}")
        return True

    def stop(self, *, quiet=False):
        self.stops += 1
        self.playing_voice = ""
        self.busy_changed.emit("")

    def shutdown(self):
        self.shut = True


def _tuned_page(settings=None, *, ready=("piper-en-ryan",), downloader=None):
    from ui.voice_settings_page import VoicePage

    previews = []

    def factory():
        previews.append(FakePreview())
        return previews[-1]

    ready = set(ready)
    page = VoicePage(settings=settings, model_ready=lambda m: m.id in ready,
                     downloader=downloader, preview_factory=factory)
    page.previews, page.ready = previews, ready
    return page


def _steps(name, value):
    return round(value / VS.TUNING[name].step)


def test_happy_each_language_shows_its_voices_with_their_download_state():
    page = _tuned_page()
    for lang, combo in page.voice_combos.items():
        assert [combo.itemData(i) for i in range(combo.count())] == list(VS.VOICES[lang])
        assert combo.itemText(0) == VM.model(VS.VOICES[lang][0]).title
    assert page.voice_states["en"].text() == "Downloaded"
    assert page.download_buttons["en"].isHidden()
    assert page.voice_states["de"].text().startswith("Not downloaded")
    assert "109 MB" in page.voice_states["de"].text()  # Thorsten high: 113 895 201 bytes
    assert not page.download_buttons["de"].isHidden()
    assert [page.voice_tabs.tabText(i) for i in range(page.voice_tabs.count())] == \
        ["German", "English"]


def test_happy_the_sliders_show_the_saved_tuning_and_their_ranges():
    s = VS.VoiceSettings(voice_de="piper-de-kerstin")
    s.set("tuning", {"piper-de-kerstin": {"speed": 1.5, "pitch": -2.0, "volume": 0.6,
                                          "pause": 0.8}})
    page = _tuned_page(s)
    sliders = page.sliders["de"]
    assert sliders["speed"].value() == _steps("speed", 1.5)
    assert sliders["pitch"].value() == _steps("pitch", -2.0)
    for name, t in VS.TUNING.items():
        assert (sliders[name].minimum(), sliders[name].maximum()) == (
            _steps(name, t.low), _steps(name, t.high)), name
    labels = page.slider_labels["de"]
    assert labels["speed"].text() == "1.50×"
    assert labels["pitch"].text() == "-2.0 semitones"
    assert labels["volume"].text() == "60 %"
    assert labels["pause"].text() == "0.80 s"
    assert page.sliders["en"]["speed"].value() == _steps("speed", 1.0)  # ryan: defaults


def test_happy_moving_sliders_reaches_the_settings():
    page = _tuned_page()
    en = page.sliders["en"]
    en["speed"].setValue(_steps("speed", 1.25))
    en["pitch"].setValue(_steps("pitch", 3.5))
    en["expressiveness"].setValue(_steps("expressiveness", 0.4))
    en["rhythm"].setValue(_steps("rhythm", 1.6))
    en["volume"].setValue(_steps("volume", 0.7))
    en["pause"].setValue(_steps("pause", 1.0))
    s = page.apply(VS.VoiceSettings())
    assert s.tuning == {"piper-en-ryan": {"speed": 1.25, "pitch": 3.5, "expressiveness": 0.4,
                                          "rhythm": 1.6, "volume": 0.7, "pause": 1.0}}
    assert page.slider_labels["en"]["pitch"].text() == "+3.5 semitones"


def test_happy_switching_the_voice_shows_that_voices_own_tuning():
    page = _tuned_page()
    combo, speed = page.voice_combos["en"], page.sliders["en"]["speed"]
    speed.setValue(_steps("speed", 1.5))
    _select(combo, "piper-en-lessac")
    assert speed.value() == _steps("speed", 1.0)
    speed.setValue(_steps("speed", 0.75))
    _select(combo, "piper-en-ryan")
    assert speed.value() == _steps("speed", 1.5)  # the unsaved value is kept per voice
    s = page.apply(VS.VoiceSettings())
    assert s.voice_en == "piper-en-ryan"
    assert s.tuning_for("piper-en-ryan")["speed"] == 1.5
    assert s.tuning_for("piper-en-lessac")["speed"] == 0.75


def test_happy_reset_one_value_and_reset_all():
    page = _tuned_page()
    en = page.sliders["en"]
    en["speed"].setValue(_steps("speed", 2.0))
    en["pitch"].setValue(_steps("pitch", -6.0))
    QTest.mouseClick(page.reset_buttons["en"]["speed"], Qt.MouseButton.LeftButton)
    assert en["speed"].value() == _steps("speed", 1.0)
    assert en["pitch"].value() == _steps("pitch", -6.0)
    QTest.mouseClick(page.reset_all_buttons["en"], Qt.MouseButton.LeftButton)
    assert page.apply(VS.VoiceSettings()).tuning == {}


def test_happy_tuning_makes_the_page_dirty_and_back_clean():
    page = _tuned_page()
    assert not page.is_dirty()
    page.sliders["de"]["volume"].setValue(_steps("volume", 0.5))
    assert page.is_dirty()
    page.sliders["de"]["volume"].setValue(_steps("volume", 1.0))
    assert not page.is_dirty()
    _select(page.voice_combos["de"], "piper-de-kerstin")
    assert page.is_dirty()


def test_happy_listen_speaks_with_the_unsaved_tuning_and_a_second_click_stops():
    page = _tuned_page()
    page.sliders["en"]["pitch"].setValue(_steps("pitch", 2.0))
    listen = page.listen_buttons["en"]
    QTest.mouseClick(listen, Qt.MouseButton.LeftButton)
    preview = page.previews[0]
    assert preview.plays == [("piper-en-ryan", {**VS.default_tuning(), "pitch": 2.0})]
    assert listen.text() == "Stop"
    assert page.listen_buttons["de"].text() == "Listen"
    assert page.voice_messages["en"].text() == "speaking piper-en-ryan"
    QTest.mouseClick(listen, Qt.MouseButton.LeftButton)
    assert preview.stops == 1 and listen.text() == "Listen"


def test_happy_listen_in_the_other_language_moves_the_stop_button():
    page = _tuned_page(ready=("piper-en-ryan", "piper-de-thorsten"))
    QTest.mouseClick(page.listen_buttons["en"], Qt.MouseButton.LeftButton)
    QTest.mouseClick(page.listen_buttons["de"], Qt.MouseButton.LeftButton)
    preview = page.previews[0]
    assert [v for v, _t in preview.plays] == ["piper-en-ryan", "piper-de-thorsten"]
    assert page.listen_buttons["de"].text() == "Stop"
    assert page.listen_buttons["en"].text() == "Listen"
    assert len(page.previews) == 1  # one preview, made on the first Listen


def test_sad_listen_to_a_missing_voice_says_so_in_its_tab():
    from tests.test_voice_controller import FakePlayer, FakeTTS
    from ui import voice as V
    from ui.voice_settings_page import VoicePage

    tts = FakeTTS()
    page = VoicePage(model_ready=lambda m: False, preview_factory=lambda: V.VoicePreview(
        worker=tts, player=FakePlayer(), packages=lambda: (True, True),
        model_ready=lambda m: False, probe_cached=lambda: None))
    QTest.mouseClick(page.listen_buttons["de"], Qt.MouseButton.LeftButton)
    assert "not downloaded" in page.voice_messages["de"].text()
    assert page.listen_buttons["de"].text() == "Listen" and tts.requests == []
    page.shutdown()


def test_happy_download_runs_off_the_gui_thread_and_the_voice_is_ready_after():
    calls = []

    def downloader(model, progress, cancel):
        calls.append((model.id, threading.current_thread() is threading.main_thread()))
        progress(model.size // 2, model.size)
        page.ready.add(model.id)
        return VM.model_dir(model)

    page = _tuned_page(downloader=downloader)
    QTest.mouseClick(page.download_buttons["de"], Qt.MouseButton.LeftButton)
    assert pump(lambda: page.voice_states["de"].text() == "Downloaded")
    assert calls == [("piper-de-thorsten", False)]
    assert page.download_buttons["de"].isHidden()
    assert "downloaded and verified" in page.voice_messages["de"].text()


def test_sad_a_failed_download_is_named_and_can_be_tried_again():
    def downloader(model, progress, cancel):
        raise VM.DownloadError("the SHA-256 differs from the pinned one - refused")

    page = _tuned_page(downloader=downloader)
    QTest.mouseClick(page.download_buttons["de"], Qt.MouseButton.LeftButton)
    assert pump(lambda: "refused" in page.voice_messages["de"].text())
    assert page.voice_states["de"].text().startswith("Not downloaded")
    assert page.download_buttons["de"].text() == "Download"
    assert page.download_buttons["de"].isEnabled()


def test_edge_a_second_click_cancels_the_download():
    started = threading.Event()

    def downloader(model, progress, cancel):
        started.set()
        while not cancel.wait(0.01):
            pass
        raise VM.DownloadCancelled("cancelled")

    page = _tuned_page(downloader=downloader)
    button = page.download_buttons["de"]
    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
    assert started.wait(5)
    assert button.text() == "Cancel"
    assert not page.download_buttons["en"].isEnabled()  # one download at a time
    QTest.mouseClick(button, Qt.MouseButton.LeftButton)
    assert pump(lambda: "cancelled" in page.voice_messages["de"].text().lower())
    assert button.text() == "Download"


def test_edge_switching_to_a_voice_shows_its_own_download_state():
    page = _tuned_page(ready=("piper-en-ryan",))
    _select(page.voice_combos["en"], "piper-en-lessac")
    assert page.voice_states["en"].text().startswith("Not downloaded")
    assert not page.download_buttons["en"].isHidden()


def test_edge_closing_the_dialog_stops_listening_and_downloading():
    cancelled = []

    def downloader(model, progress, cancel):
        while not cancel.wait(0.01):
            pass
        cancelled.append(1)
        raise VM.DownloadCancelled("cancelled")

    page = _tuned_page(downloader=downloader)
    QTest.mouseClick(page.listen_buttons["en"], Qt.MouseButton.LeftButton)
    QTest.mouseClick(page.download_buttons["de"], Qt.MouseButton.LeftButton)
    page.shutdown()
    assert page.previews[0].shut
    assert pump(lambda: cancelled)


def test_edge_constructing_the_page_makes_no_preview():
    page = _tuned_page()
    assert page.previews == []


def test_edge_a_hand_edited_value_between_steps_is_kept_until_moved():
    s = VS.VoiceSettings()
    s.set("tuning", {"piper-en-ryan": {"speed": 1.23}})
    page = _tuned_page(s)
    assert page.sliders["en"]["speed"].value() == _steps("speed", 1.25)
    assert not page.is_dirty()
    assert page.apply(VS.VoiceSettings()).tuning_for("piper-en-ryan")["speed"] == 1.23


# -- end to end: the real Settings dialog -------------------------------------------------------


def test_happy_e2e_tune_listen_and_save_reaches_voice_json_and_the_dock(stores):
    from core import multimedia_probe as MPROBE
    from tests.test_voice_controller import FakePlayer, FakeTTS
    from ui import voice as V
    from ui.settings_dialog import QDialogButtonBox

    win = stores.make_window()
    dialog = stores.settings_dialog(win, "voice")
    page = dialog.page("voice")
    tts, player = FakeTTS(), FakePlayer()
    page.preview_factory = lambda: V.VoicePreview(
        worker=tts, player=player, packages=lambda: (True, True), model_ready=lambda m: True,
        probe_cached=lambda: MPROBE.ProbeResult(True))
    dialog.show()
    tabs = page.voice_tabs
    QTest.mouseClick(tabs.tabBar(), Qt.MouseButton.LeftButton,
                     pos=tabs.tabBar().tabRect(1).center())
    assert tabs.currentIndex() == 1  # English
    combo = page.voice_combos["en"]
    combo.setFocus()
    QTest.keyClick(combo, Qt.Key.Key_Down)
    assert combo.currentData() == "piper-en-lessac"
    speed, pitch = page.sliders["en"]["speed"], page.sliders["en"]["pitch"]
    for _ in range(5):
        QTest.keyClick(speed, Qt.Key.Key_Right)  # five steps of 0.05
    for _ in range(3):
        QTest.keyClick(pitch, Qt.Key.Key_Left)  # three half semitones down
    assert page.slider_labels["en"]["speed"].text() == "1.25×"
    QTest.mouseClick(page.listen_buttons["en"], Qt.MouseButton.LeftButton)
    assert pump(lambda: player.chunks)
    req = tts.requests[0]
    assert req["voice"].endswith("en_US-lessac-medium.onnx")
    assert (req["speed"], req["pitch"]) == (1.25, -1.5)
    assert not VS.settings_file().exists()  # Listen saves nothing
    player.finish()
    assert pump(lambda: page.listen_buttons["en"].text() == "Listen")
    QTest.mouseClick(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok),
                     Qt.MouseButton.LeftButton)
    stored = json.loads(VS.settings_file().read_text())
    assert stored["voice_en"] == "piper-en-lessac"
    assert stored["tuning"] == {"piper-en-lessac": {**VS.default_tuning(), "speed": 1.25,
                                                    "pitch": -1.5}}
    voice = win._agent_dock.voice  # the dock speaks as saved
    assert voice.settings.voice("en") == "piper-en-lessac"
    dock_tts = FakeTTS()
    voice._tts, voice._packages = dock_tts, lambda: (True, True)
    voice._model_ready = lambda m: True
    voice.settings.output_enabled = True
    assert voice.speak_answer("The file is there and it is fine.")
    assert pump(lambda: dock_tts.requests)
    assert dock_tts.requests[0]["speed"] == 1.25 and dock_tts.requests[0]["pitch"] == -1.5
    voice.stop_speaking()
