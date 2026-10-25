"""The Agent dock's voice (ui.voice.VoiceController) with the sound card
and the worker replaced by fakes that keep the same interfaces."""

from __future__ import annotations

import array
import base64
import logging
import math
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import llm_profiles as LP  # noqa: E402
from core import security_mode  # noqa: E402
from core import voice_settings as VS  # noqa: E402
from ui import voice as V  # noqa: E402

APP = QApplication.instance() or QApplication([])


def speech(seconds=0.8, amplitude=9000) -> bytes:
    n = int(seconds * 16000)
    return array.array("h", (int(amplitude * math.sin(2 * math.pi * 220 * i / 16000))
                             for i in range(n))).tobytes()


def quiet(seconds) -> bytes:
    return b"\0\0" * int(seconds * 16000)


class FakeRecorder(QObject):
    data = pyqtSignal(bytes)
    made: list = []

    def __init__(self):
        super().__init__()
        self.started = self.stopped = False
        FakeRecorder.made.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


class FakePlayer(QObject):
    level = pyqtSignal(float)
    drained = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.chunks: list[tuple[bytes, int]] = []
        self.playing = False
        self.stops = 0

    def enqueue(self, pcm, rate):
        self.chunks.append((pcm, rate))
        self.playing = True
        self.level.emit(0.7)

    def busy(self):
        return self.playing

    def finish(self):
        self.playing = False
        self.drained.emit()

    def stop(self):
        self.stops += 1
        self.playing = False


class FakeTTS:
    def __init__(self, *, hold=None):
        self.requests: list[dict] = []
        self.kills = 0
        self.hold = hold  # a threading.Event the call waits for

    def call(self, request, *, timeout, on_event=None, cancel=None, **_kw):
        self.requests.append(request)
        on_event({"event": "audio", "rate": 22050, "pcm": base64.b64encode(b"\1\0" * 50).decode()})
        if self.hold is not None:
            while not self.hold.wait(0.02):
                if cancel is not None and cancel.is_set():
                    from core.voice_worker import VoiceWorkerCancelled

                    raise VoiceWorkerCancelled("cancelled")
        return {"ok": True, "done": True}

    def kill(self):
        self.kills += 1

    def close(self):
        pass


class FakeSTT:
    def __init__(self, text="Zeig mir die Logs"):
        self.text = text
        self.requests: list[dict] = []

    def call(self, request, *, timeout, **_kw):
        self.requests.append(request)
        return {"ok": True, "text": self.text, "language": "de"}

    def kill(self):
        pass

    def close(self):
        pass


def pump(until, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if until():
            return True
        time.sleep(0.01)
    return False


class Env:
    def __init__(self, tmp_path, **settings):
        self.settings = VS.VoiceSettings(output_enabled=True)
        for key, value in settings.items():
            self.settings.set(key, value)
        self.saved = []
        self.tts, self.stt, self.player = FakeTTS(), FakeSTT(), FakePlayer()
        self.packages = (True, True)
        self.ready = set()  # model ids "downloaded"
        self.profile = LP.LLMProfile(name="p", provider="openai", endpoint="http://127.0.0.1:1/v1")
        self.asked = []
        self.consent = True
        self.server_calls = []
        self.notices, self.texts, self.states = [], [], []
        self.ctl = V.VoiceController(
            settings_loader=lambda: self.settings,
            settings_saver=self.saved.append,
            tts_worker=self.tts, stt_worker=self.stt,
            recorder_factory=FakeRecorder, player=self.player,
            profile_provider=lambda: (self.profile, "sk-key"),
            confirm_remote=lambda p, h: self.asked.append(h) or self.consent,
            packages=lambda: self.packages,
            model_ready=lambda m: m.id in self.ready,
            server_transcribe=lambda p, k, pcm, language=None: (
                self.server_calls.append((k, len(pcm), language)) or "vom Server"),
        )
        self.ctl.notice.connect(self.notices.append)
        self.ctl.transcribed.connect(self.texts.append)
        self.ctl.state_changed.connect(self.states.append)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.ctl.shutdown()


# -- speaking ----------------------------------------------------------------------------------


def test_happy_a_german_answer_is_spoken_with_english_terms(env):
    env.ready = {"piper-de-thorsten"}
    assert env.ctl.speak_answer("Ich habe den Server neu gestartet.\n```\nls\n```")
    assert pump(lambda: env.player.chunks)
    req = env.tts.requests[0]
    assert req["lang"] == "de" and req["voice"].endswith("de_DE-thorsten-high.onnx")
    assert ["en", "Server"] in [list(p) for p in req["sentences"][0]]
    assert any("Code" in t for s in req["sentences"] for _k, t in s)
    assert env.ctl.state == "speaking"
    finished = []
    env.ctl.speaking_finished.connect(lambda: finished.append(1))
    env.player.finish()
    assert pump(lambda: finished)
    assert env.ctl.state == "idle"


def test_happy_english_answer_female_voice(env):
    env.settings.set("voice_en", "piper-en-lessac")
    env.ready = {"piper-en-lessac"}
    assert env.ctl.speak_answer("I have read the file and it is fine.")
    assert pump(lambda: env.tts.requests)
    assert env.tts.requests[0]["voice"].endswith("en_US-lessac-medium.onnx")
    assert env.tts.requests[0]["lang"] == "en"


def test_happy_each_language_speaks_with_its_own_voice(env):
    env.settings.set("voice_de", "piper-de-kerstin")
    env.ready = {"piper-de-kerstin", "piper-en-ryan"}
    assert env.ctl.speak_answer("Ich habe die Datei gelesen, sie ist in Ordnung.")
    assert env.ctl.speak_answer("I have read the file and it is fine.")
    assert pump(lambda: len(env.tts.requests) == 2)
    voices = [r["voice"].rsplit("/", 1)[1] for r in env.tts.requests]
    assert voices == ["de_DE-kerstin-low.onnx", "en_US-ryan-medium.onnx"]


def test_happy_a_spoken_answer_carries_how_its_voice_speaks(env):
    tuned = {**VS.default_tuning(), "speed": 1.4, "pitch": -2.0, "expressiveness": 0.5,
             "rhythm": 1.5, "volume": 0.6, "pause": 0.8}
    env.settings.set("tuning", {"piper-en-lessac": tuned,
                                "piper-de-thorsten": {"speed": 0.7}})
    env.settings.set("voice_en", "piper-en-lessac")
    env.ready = {"piper-en-lessac", "piper-de-thorsten"}
    assert env.ctl.speak_answer("I have read the file and it is fine.")
    assert pump(lambda: env.tts.requests)
    req = env.tts.requests[0]
    assert {k: req[k] for k in VS.TUNING} == tuned


def test_happy_phrases_speak_with_the_tuning_too(env):
    env.settings.set("language", "de")
    env.settings.set("tuning", {"piper-de-thorsten": {"pitch": 3.0}})
    env.ready = {"piper-de-thorsten"}
    assert env.ctl.say_refusal("read_only")
    assert pump(lambda: env.tts.requests)
    assert env.tts.requests[0]["pitch"] == 3.0 and env.tts.requests[0]["speed"] == 1.0


def test_edge_saved_tuning_takes_effect_with_the_next_answer(env):
    env.ready = {"piper-en-ryan"}
    env.settings = VS.VoiceSettings(output_enabled=True, language="en")
    env.ctl.reload()
    newer = VS.VoiceSettings(output_enabled=True, language="en")
    newer.set("tuning", {"piper-en-ryan": {"speed": 2.0}})
    env.settings = newer  # the Voice page saved, the dock reloads
    env.ctl.reload()
    assert env.ctl.speak_answer("The file is there.")
    assert pump(lambda: env.tts.requests)
    assert env.tts.requests[0]["speed"] == 2.0


def test_sad_output_off_says_nothing(env):
    env.settings.set("output_enabled", False)
    env.ready = {"piper-de-thorsten"}
    assert not env.ctl.speak_answer("Hallo, das ist ein Test.")
    assert not env.ctl.say_refusal("read_only")
    assert env.tts.requests == []


def test_sad_missing_packages_say_so_once(env):
    env.packages = (False, False)
    assert not env.ctl.speak_answer("Die Datei ist da.")
    assert not env.ctl.speak_answer("Die Datei ist da.")
    assert len(env.notices) == 1 and "axross[voice]" in env.notices[0]


def test_sad_a_voice_not_downloaded_names_it(env):
    assert not env.ctl.speak_answer("Die Datei ist da und gut.")
    assert "Thorsten" in env.notices[0] and "Features" in env.notices[0]


def test_edge_stop_ends_speech_and_drops_late_audio(env):
    import threading

    env.tts.hold = threading.Event()
    env.ready = {"piper-de-thorsten"}
    env.ctl.speak_answer("Erster Satz ist hier. Zweiter Satz ist dort.")
    assert pump(lambda: env.player.chunks)
    env.ctl.stop_speaking()
    assert env.tts.kills == 1 and env.player.stops >= 1
    assert env.ctl.state == "idle" and not env.ctl.speaking()
    env.tts.hold.set()
    APP.processEvents()
    env.ctl._bridge.audio.emit(0, b"\1\0", 22050)  # a chunk of the stopped speech
    pump(lambda: False, 0.1)
    assert len(env.player.chunks) == 1


def test_happy_refusal_in_the_phrase_language(env):
    env.settings.set("language", "de")
    env.ready = {"piper-de-thorsten"}
    assert env.ctl.say_refusal("read_only")
    assert pump(lambda: env.tts.requests)
    parts = env.tts.requests[0]["sentences"][0]
    assert ["en", "Files read only"] in [list(p) for p in parts]


def test_happy_refusal_english(env):
    env.settings.set("language", "en")
    env.ready = {"piper-en-ryan"}
    assert env.ctl.say_refusal("permission")
    assert pump(lambda: env.tts.requests)
    assert "permission denied" in env.tts.requests[0]["sentences"][0][0][1]


def test_happy_the_first_voice_input_greets(env):
    env.settings.set("language", "en")
    env.ready = {"whisper-base", "piper-en-ryan"}
    _record(env, quiet(0.3), speech(0.6))
    env.ctl.stop_listening()
    assert pump(lambda: env.texts and env.tts.requests)
    assert "nice day" in env.tts.requests[0]["sentences"][-1][0][1]


def test_happy_greeting_once_per_session(env):
    env.settings.set("language", "en")
    env.ready = {"piper-en-ryan"}
    assert env.ctl.greet()
    assert not env.ctl.greet()
    assert "nice day" in env.tts.requests[0]["sentences"][0][0][1] or any(
        "nice day" in s[0][1] for s in env.tts.requests[0]["sentences"])


def test_edge_turning_output_on_saves_and_greets(env):
    env.settings.set("output_enabled", False)
    env.settings.set("language", "de")
    env.ready = {"piper-de-thorsten"}
    env.ctl.set_output_enabled(True)
    assert env.saved and env.saved[-1].output_enabled is True
    assert pump(lambda: env.tts.requests)
    env.ctl.set_output_enabled(False)
    assert env.ctl.state == "idle"


# -- listening -----------------------------------------------------------------------------------


def _record(env, *pieces, auto=False):
    FakeRecorder.made.clear()
    assert env.ctl.start_listening(auto_stop=auto)
    rec = FakeRecorder.made[-1]
    for piece in pieces:
        rec.data.emit(piece)
    return rec


def test_happy_push_to_talk_local_recognition(env):
    env.ready = {"whisper-base"}
    env.settings.set("output_enabled", False)
    rec = _record(env, quiet(0.3), speech(0.8))
    assert env.ctl.state == "listening"
    env.ctl.stop_listening()
    assert rec.stopped
    assert pump(lambda: env.texts)
    assert env.texts == ["Zeig mir die Logs"]
    req = env.stt.requests[0]
    assert req["model"].endswith("whisper-base") and req["language"] is None
    assert len(base64.b64decode(req["pcm"])) == len(quiet(0.3) + speech(0.8))


def test_happy_toggle_ends_on_silence(env):
    env.ready = {"whisper-base"}
    env.settings.set("silence_seconds", 0.5)
    env.settings.set("language", "de")
    _record(env, quiet(0.3), speech(0.8), quiet(0.6), auto=True)
    assert pump(lambda: env.texts)
    assert env.stt.requests[0]["language"] == "de"


def test_sad_too_short_or_silent_is_nothing(env):
    env.ready = {"whisper-base"}
    _record(env, quiet(0.2))
    env.ctl.stop_listening()
    assert env.notices[-1] == "Nothing was heard."
    assert env.stt.requests == []


def test_sad_paranoid_mode_keeps_the_microphone_off(env):
    old = security_mode.current_policy().name
    security_mode.set_policy("paranoid")
    try:
        FakeRecorder.made.clear()
        assert not env.ctl.start_listening()
        assert FakeRecorder.made == []
        assert "paranoid" in env.notices[-1]
    finally:
        security_mode.set_policy(old)


def test_sad_recognition_model_missing(env):
    _record(env, quiet(0.3), speech(0.8))
    env.ctl.stop_listening()
    assert "Whisper base" in env.notices[-1]
    assert env.ctl.state == "idle"


def test_edge_new_input_stops_speech(env):
    env.ready = {"piper-de-thorsten", "whisper-base"}
    env.ctl.speak_answer("Ein langer Satz wird gesprochen.")
    assert pump(lambda: env.player.chunks)
    _record(env)
    assert env.player.stops >= 1 and env.ctl.state == "listening"


def test_happy_server_recognition_asks_once_for_a_remote_server(env):
    env.profile = LP.LLMProfile(name="p", provider="openai", endpoint="http://127.0.0.1:1/v1",
                                stt_engine="server", stt_endpoint="https://stt.example.org/v1")
    _record(env, quiet(0.3), speech(0.6))
    env.ctl.stop_listening()
    assert pump(lambda: env.texts)
    assert env.asked == ["stt.example.org"]
    assert env.server_calls[0][0] == "sk-key"
    _record(env, quiet(0.3), speech(0.6))
    env.ctl.stop_listening()
    assert pump(lambda: len(env.texts) == 2)
    assert env.asked == ["stt.example.org"]


def test_sad_server_recognition_refused_consent_sends_nothing(env):
    env.consent = False
    env.profile = LP.LLMProfile(name="p", provider="openai", endpoint="http://127.0.0.1:1/v1",
                                stt_engine="server", stt_endpoint="https://stt.example.org/v1")
    _record(env, quiet(0.3), speech(0.6))
    env.ctl.stop_listening()
    pump(lambda: False, 0.2)
    assert env.server_calls == [] and env.texts == []


# -- one fixed line ------------------------------------------------------------------------------


def test_happy_the_phrase_plays_the_line_and_is_not_passed_on(env, caplog):
    caplog.set_level(logging.DEBUG)
    env.ready = {"whisper-base", "piper-en-ryan"}
    env.stt.text = "Open the podbay doors, HAL."
    started, finished = [], []
    env.ctl.line_started.connect(lambda: started.append(1))
    env.ctl.line_finished.connect(lambda: finished.append(1))
    _record(env, quiet(0.3), speech(0.6))
    env.ctl.stop_listening()
    assert pump(lambda: env.player.chunks)
    assert env.texts == [] and started == [1]
    assert len(env.tts.requests) == 1  # no greeting before it
    req = env.tts.requests[-1]
    assert req["voice"].endswith("en_US-ryan-medium.onnx") and req["length_scale"] == 1.15
    assert not set(VS.TUNING) & set(req)  # the fixed line speaks as it always did
    # Lower and slower: stretched as if played at 0.9 x 22050 Hz.
    assert env.player.chunks[-1][1] == 22050
    assert abs(len(env.player.chunks[-1][0]) // 2 - 50 / 0.9) <= 1
    env.player.finish()
    assert pump(lambda: finished)
    assert caplog.records == []
    assert env.notices == []


def test_edge_the_line_without_its_voice_still_shows_and_ends(env):
    started, finished, levels = [], [], []
    env.ctl.line_started.connect(lambda: started.append(1))
    env.ctl.line_finished.connect(lambda: finished.append(1))
    env.ctl.level.connect(levels.append)
    env.ctl.play_line()
    assert started == [1]
    assert pump(lambda: finished, 8.0)
    assert len([v for v in levels if v > 0]) > 10
    assert env.notices == [] and env.tts.requests == []


def test_edge_stop_drops_a_recording_still_being_recognised(env):
    import threading

    gate = threading.Event()
    real_call = env.stt.call

    def slow_call(request, **kw):
        gate.wait(5)
        return real_call(request, **kw)

    env.stt.call = slow_call
    env.ready = {"whisper-base"}
    _record(env, quiet(0.3), speech(0.6))
    env.ctl.stop_listening()
    assert env.ctl.state == "transcribing"
    env.ctl.cancel_listening()
    assert env.ctl.state == "idle"
    gate.set()
    pump(lambda: False, 0.3)
    assert env.texts == []


def test_sad_no_sound_device_is_said_once_and_speech_ends(env):
    env.ready = {"piper-de-thorsten"}
    finished = []
    env.ctl.speaking_finished.connect(lambda: finished.append(1))
    env.ctl.speak_answer("Die Datei ist da und gut.")
    assert pump(lambda: env.player.chunks)
    env.player.failed.emit("No audio output found")
    env.player.failed.emit("No audio output found")
    env.player.finish()
    assert pump(lambda: finished)
    assert [n for n in env.notices if "No sound" in n] == ["No sound: No audio output found"]


def test_edge_a_greeting_whose_voice_is_missing_comes_later(env):
    env.settings.set("language", "en")
    assert not env.ctl.greet()
    env.ready = {"piper-en-ryan"}
    assert env.ctl.greet()
    assert not env.ctl.greet()
