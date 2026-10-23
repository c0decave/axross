"""Talking with the Agent dock, end to end with real widgets offscreen: the
microphone button in its three modes and the hold key, recognised text in
the task field or sent, answers and refusals spoken, Stop, the speaker
switch, paranoid mode, and one hidden phrase. The model is the scripted
fake LLM server; the sound card and the voice worker are fakes with the
real interfaces (tests/test_voice_controller.py)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402

from core import security_mode  # noqa: E402
from core import voice_settings as VS  # noqa: E402
from tests.test_agent_loop import _call  # noqa: E402
from tests.test_agent_tabs import APP, Env, wait_idle  # noqa: E402
from tests.test_voice_controller import (  # noqa: E402
    FakePlayer,
    FakeRecorder,
    FakeSTT,
    FakeTTS,
    pump,
    quiet,
    speech,
)
from ui import voice as V  # noqa: E402


class VoiceEnv(Env):
    def __init__(self, tmp_path):
        super().__init__(tmp_path)
        self.voice_settings = VS.VoiceSettings()
        self.saved = []
        self.tts, self.stt, self.player = FakeTTS(), FakeSTT(), FakePlayer()
        self.ready = {"piper-de-thorsten", "piper-en-ryan", "whisper-base"}

    def dock(self):
        from ui.agent_dock import AgentDock

        original = AgentDock.__init__
        env = self

        def make_voice(dock):
            return V.VoiceController(
                dock,
                settings_loader=lambda: env.voice_settings,
                settings_saver=env.saved.append,
                tts_worker=env.tts, stt_worker=env.stt, recorder_factory=FakeRecorder,
                player=env.player, profile_provider=dock.voice_profile,
                packages=lambda: (True, True), model_ready=lambda m: m.id in env.ready,
            )

        self.voice_factory = make_voice
        AgentDock.__init__ = lambda d, *a, **kw: original(d, *a, voice_factory=make_voice, **kw)
        try:
            return super().dock()
        finally:
            AgentDock.__init__ = original


@pytest.fixture
def env(tmp_path):
    e = VoiceEnv(tmp_path)
    yield e
    e.close()


def _recorder():
    return FakeRecorder.made[-1]


def _speak_into(*pieces):
    for piece in pieces:
        _recorder().data.emit(piece)


# -- the microphone ------------------------------------------------------------------------------


def test_happy_push_to_talk_puts_the_text_into_the_task_field(env):
    server = env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    FakeRecorder.made.clear()
    QTest.mousePress(tab.mic_button, Qt.MouseButton.LeftButton)
    assert tab.dock.voice.listening()
    _speak_into(quiet(0.3), speech(0.6))
    QTest.mouseRelease(tab.mic_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: tab.input.toPlainText())
    assert tab.input.toPlainText() == "Zeig mir die Logs"
    assert server.requests == [] and not tab.busy()


def test_happy_send_at_once_runs_the_task(env):
    server = env.fake({"content": "Die Logs sind leer."})
    env.voice_settings.set("after_recognition", "send")
    tab = env.dock().current_tab()
    QTest.mousePress(tab.mic_button, Qt.MouseButton.LeftButton)
    _speak_into(quiet(0.3), speech(0.6))
    QTest.mouseRelease(tab.mic_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: server.requests)
    wait_idle(tab)
    assert server.requests[0]["messages"][-1]["content"].endswith("Zeig mir die Logs")


def test_happy_toggle_mode_click_on_click_off(env):
    env.fake({"content": "ok"})
    env.voice_settings.set("input_mode", "toggle")
    tab = env.dock().current_tab()
    QTest.mouseClick(tab.mic_button, Qt.MouseButton.LeftButton)
    assert tab.dock.voice.listening() and tab.mic_button.isChecked()
    _speak_into(quiet(0.3), speech(0.6))
    QTest.mouseClick(tab.mic_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: tab.input.toPlainText() == "Zeig mir die Logs")
    assert not tab.mic_button.isChecked()


def test_happy_conversation_mode_listens_again_after_the_spoken_answer(env):
    server = env.fake({"content": "Ich habe die Logs gelesen."})
    env.voice_settings.set("input_mode", "conversation")
    env.voice_settings.set("output_enabled", True)
    env.voice_settings.set("silence_seconds", 0.5)
    tab = env.dock().current_tab()
    FakeRecorder.made.clear()
    QTest.mouseClick(tab.mic_button, Qt.MouseButton.LeftButton)
    _speak_into(quiet(0.3), speech(0.6), quiet(0.6))
    assert pump(lambda: server.requests)
    wait_idle(tab)
    assert pump(lambda: any(r["lang"] == "de" and "Logs" in str(r["sentences"])
                            for r in env.tts.requests))
    assert pump(lambda: env.player.chunks)
    env.player.finish()
    assert pump(lambda: len(FakeRecorder.made) == 2 and tab.dock.voice.listening())
    QTest.mouseClick(tab.mic_button, Qt.MouseButton.LeftButton)  # ends the conversation
    assert not tab.dock.voice.listening()


def test_happy_the_hold_key_talks(env):
    env.fake({"content": "ok"})
    env.voice_settings.set("hotkey", "F8")
    tab = env.dock().current_tab()
    tab.dock.show()
    QTest.keyPress(tab.input, Qt.Key.Key_F8)
    assert tab.dock.voice.listening()
    _speak_into(quiet(0.3), speech(0.6))
    QTest.keyRelease(tab.input, Qt.Key.Key_F8)
    assert pump(lambda: tab.input.toPlainText() == "Zeig mir die Logs")


def test_sad_paranoid_mode_disables_the_microphone(env):
    env.fake({"content": "ok"})
    old = security_mode.current_policy().name
    security_mode.set_policy("paranoid")
    try:
        tab = env.dock().current_tab()
        assert not tab.mic_button.isEnabled()
        assert "paranoid" in tab.mic_button.toolTip()
        FakeRecorder.made.clear()
        QTest.keyPress(tab.input, Qt.Key.Key_F9)
        assert FakeRecorder.made == []
    finally:
        security_mode.set_policy(old)


def test_edge_voice_text_never_answers_a_confirmation(env):
    """Tool confirmations stay click-only: text heard while a task runs goes
    into the task field, nothing is sent or confirmed by it."""
    env.fake({"tool_calls": [_call("write_file", {"path": str(env.root / "a.txt"),
                                                  "content": "x"})]}, {"content": "done"})
    env.answer = False
    tab = env.dock().current_tab()
    tab.allow_write.setChecked(True)
    tab.input.setPlainText("schreib a.txt")
    tab.send()
    tab.dock.voice.transcribed.emit("ja")
    wait_idle(tab)
    assert env.asked and len(env.asked) == 1
    assert "ja" in tab.input.toPlainText()
    assert not (env.root / "a.txt").exists()


# -- speaking -------------------------------------------------------------------------------------


def test_happy_the_answer_is_read_aloud_and_shown_without_braces(env):
    env.fake({"content": "Der {Pull Request} ist offen."})
    env.voice_settings.set("output_enabled", True)
    tab = env.dock().current_tab()
    tab.input.setPlainText("Status?")
    tab.send()
    wait_idle(tab)
    assert pump(lambda: env.tts.requests)
    assert "Der Pull Request ist offen." in tab.transcript.toPlainText()
    assert "{" not in tab.transcript.toPlainText()
    assert ["en", "Pull Request"] in [list(p) for p in env.tts.requests[-1]["sentences"][0]]


def test_happy_the_voice_prompt_asks_for_braces_only_with_voice_on(env):
    server = env.fake({"content": "a"}, {"content": "b"})
    tab = env.dock().current_tab()
    tab.input.setPlainText("eins")
    tab.send()
    wait_idle(tab)
    assert "{" not in server.requests[0]["messages"][0]["content"].split("read aloud")[0][-5:]
    assert "read aloud" not in server.requests[0]["messages"][0]["content"]
    tab.speaker_button.setChecked(True)
    tab.input.setPlainText("zwei")
    tab.send()
    wait_idle(tab)
    assert "read aloud" in server.requests[1]["messages"][0]["content"]


def test_sad_with_the_speaker_off_nothing_is_spoken(env):
    env.fake({"content": "Ich bin fertig."})
    tab = env.dock().current_tab()
    tab.input.setPlainText("los")
    tab.send()
    wait_idle(tab)
    pump(lambda: False, 0.1)
    assert env.tts.requests == []


def test_happy_a_refusal_is_spoken(env):
    env.fake({"tool_calls": [_call("write_file", {"path": str(env.root / "a.txt"),
                                                  "content": "x"})]}, {"content": "Geht nicht."})
    env.voice_settings.set("output_enabled", True)
    env.voice_settings.set("language", "de")
    tab = env.dock().current_tab()
    tab.read_only_check.setChecked(True)
    tab.input.setPlainText("schreib was")
    tab.send()
    wait_idle(tab)
    assert pump(lambda: any("read only" in str(r["sentences"]) for r in env.tts.requests))


def test_happy_stop_ends_the_speech(env):
    env.fake({"content": "Ein Satz. Noch ein Satz."})
    env.voice_settings.set("output_enabled", True)
    tab = env.dock().current_tab()
    tab.input.setPlainText("rede")
    tab.send()
    wait_idle(tab)
    assert pump(lambda: env.player.chunks)
    assert tab.stop_button.isEnabled()
    QTest.mouseClick(tab.stop_button, Qt.MouseButton.LeftButton)
    assert env.player.stops >= 1 and not tab.dock.voice.speaking()


def test_edge_typing_stops_the_speech(env):
    env.fake({"content": "Ein Satz."})
    env.voice_settings.set("output_enabled", True)
    tab = env.dock().current_tab()
    tab.input.setPlainText("rede")
    tab.send()
    wait_idle(tab)
    assert pump(lambda: env.player.chunks)
    QTest.keyClick(tab.input, Qt.Key.Key_A)
    assert env.player.stops >= 1


def test_happy_the_speaker_switch_is_saved_and_every_tab_follows(env):
    env.fake({"content": "ok"})
    dock = env.dock()
    first = dock.current_tab()
    second = dock.new_tab()
    first.speaker_button.setChecked(True)
    assert env.saved[-1].output_enabled is True
    assert second.speaker_button.isChecked()


# -- one hidden phrase -------------------------------------------------------------------


def test_happy_the_typed_phrase_is_not_sent_and_shows_the_lens(env):
    server = env.fake({"content": "never"})
    tab = env.dock().current_tab()
    before = tab.transcript.toPlainText()
    tab.input.setPlainText("Open the podbay doors HAL.")
    QTest.keyClick(tab.input, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
    assert tab.input.toPlainText() == ""
    assert not tab.lens.isHidden()
    assert server.requests == [] and not tab.busy()
    assert tab.transcript.toPlainText() == before and tab.session.transcript == []
    assert tab._history == []
    assert env.tts.requests and env.tts.requests[-1]["voice"].endswith("en_US-ryan-medium.onnx")
    assert pump(lambda: env.player.chunks)
    env.player.finish()
    assert pump(lambda: tab.lens.isHidden(), 5.0)


def test_sad_a_sentence_about_pods_is_sent(env):
    server = env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    tab.input.setPlainText("list the pods behind the bay doors")
    tab.send()
    wait_idle(tab)
    assert server.requests and tab.lens.isHidden()


def test_edge_the_spoken_phrase_shows_the_lens_too(env):
    server = env.fake({"content": "never"})
    env.stt.text = "Open the pod bay doors, Hal."
    tab = env.dock().current_tab()
    tab.dock.show()
    QTest.mousePress(tab.mic_button, Qt.MouseButton.LeftButton)
    _speak_into(quiet(0.3), speech(0.6))
    QTest.mouseRelease(tab.mic_button, Qt.MouseButton.LeftButton)
    assert pump(lambda: not tab.lens.isHidden())
    assert tab.input.toPlainText() == "" and server.requests == []
    APP.processEvents()


def test_happy_the_lens_is_drawn_red_and_glows_with_the_level(env):
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    lens = tab.lens

    def heart():
        image = lens.grab().toImage()
        return image.pixelColor(image.width() // 2, image.height() // 2)

    lens.start("")
    lens.set_level(0.0)
    for _ in range(10):
        lens._tick()
    dim = heart()
    lens.set_level(1.0)
    for _ in range(10):
        lens._tick()
    bright = heart()
    assert bright.red() > 200 and bright.red() > bright.blue() + 100
    assert bright.green() > dim.green()  # the eye's heart turns hotter
    lens.finish()
    for _ in range(20):
        lens._tick()
    assert lens.isHidden() and lens.alpha == 0.0
