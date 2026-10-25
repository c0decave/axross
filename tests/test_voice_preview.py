"""Listen on the Voice settings page (ui.voice.VoicePreview): one sample
sentence pair in one voice, with the page's unsaved tuning, through the
voice worker and the output player - the worker and the sound card
replaced by fakes with the same interfaces."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import multimedia_probe as MPROBE  # noqa: E402
from core import voice_settings as VS  # noqa: E402
from core import voice_text as VT  # noqa: E402
from tests.test_voice_controller import FakePlayer, FakeTTS, pump  # noqa: E402
from ui import voice as V  # noqa: E402

APP = QApplication.instance() or QApplication([])


class FailingTTS(FakeTTS):
    def call(self, request, **_kw):
        self.requests.append(request)
        return {"ok": False, "error": "RuntimeError: the model is broken"}


class Env:
    def __init__(self, *, probe=MPROBE.ProbeResult(True), tts=None):
        self.tts = tts or FakeTTS()
        self.player = FakePlayer()
        self.packages = (True, True)
        self.ready = {"piper-en-ryan", "piper-de-kerstin"}
        self.probe = probe
        self.waiting: list = []  # probe_async callbacks not answered yet
        self.busy: list[str] = []
        self.messages: list[str] = []
        self.preview = V.VoicePreview(
            worker=self.tts, player=self.player, packages=lambda: self.packages,
            model_ready=lambda m: m.id in self.ready, probe_cached=lambda: self.probe,
            probe_async=lambda on_done, context=None: self.waiting.append(on_done))
        self.preview.busy_changed.connect(self.busy.append)
        self.preview.message.connect(self.messages.append)


@pytest.fixture
def env():
    e = Env()
    yield e
    e.preview.shutdown()


TUNED = {**VS.default_tuning(), "speed": 1.5, "pitch": 2.0, "volume": 0.5}


def test_happy_listen_speaks_the_sample_with_the_unsaved_tuning(env):
    assert env.preview.play("piper-en-ryan", TUNED)
    assert pump(lambda: env.player.chunks)
    req = env.tts.requests[0]
    assert req["op"] == "speak" and req["lang"] == "en"
    assert req["voice"].endswith("en_US-ryan-medium.onnx")
    assert {k: req[k] for k in VS.TUNING} == TUNED
    spoken = " ".join(t for s in req["sentences"] for _k, t in s)
    assert spoken == " ".join(VT.split_sentences(VT.sample_phrase("en")))
    assert len(req["sentences"]) == 2  # the pause between sentences is heard too
    assert env.busy == ["piper-en-ryan"] and env.preview.playing_voice == "piper-en-ryan"
    env.player.finish()
    assert pump(lambda: env.busy[-1:] == [""])
    assert env.preview.playing_voice == ""
    assert "played" in env.messages[-1].lower()


def test_happy_a_german_voice_says_the_german_sample(env):
    assert env.preview.play("piper-de-kerstin", VS.default_tuning())
    assert pump(lambda: env.tts.requests)
    req = env.tts.requests[0]
    assert req["lang"] == "de" and req["voice"].endswith("de_DE-kerstin-low.onnx")
    assert "klinge" in " ".join(t for s in req["sentences"] for _k, t in s)


def test_happy_listen_does_not_block_the_gui_thread():
    hold = threading.Event()
    e = Env(tts=FakeTTS(hold=hold))
    try:
        start = time.monotonic()
        assert e.preview.play("piper-en-ryan", VS.default_tuning())
        assert time.monotonic() - start < 0.5  # the synthesis waits in its thread
        assert pump(lambda: e.tts.requests)
        assert e.preview.playing_voice == "piper-en-ryan"
    finally:
        hold.set()
        e.preview.shutdown()


def test_happy_stop_ends_the_sample_at_once():
    hold = threading.Event()
    e = Env(tts=FakeTTS(hold=hold))
    try:
        e.preview.play("piper-en-ryan", VS.default_tuning())
        assert pump(lambda: e.player.chunks)
        e.preview.stop()
        assert e.tts.kills == 1 and e.player.stops >= 1
        assert e.busy[-1] == "" and e.preview.playing_voice == ""
        chunks = len(e.player.chunks)
        hold.set()  # the cancelled synthesis' late audio is dropped
        pump(lambda: False, 0.3)
        assert len(e.player.chunks) == chunks
        assert e.messages[-1] == "Stopped."
    finally:
        hold.set()
        e.preview.shutdown()


def test_sad_a_voice_not_downloaded_says_so_and_speaks_nothing(env):
    env.ready = set()
    assert not env.preview.play("piper-en-ryan", VS.default_tuning())
    assert env.tts.requests == [] and env.busy == []
    assert "not downloaded" in env.messages[-1] and "Download" in env.messages[-1]


def test_sad_without_the_voice_packages_it_says_how_to_get_them(env):
    env.packages = (False, False)
    assert not env.preview.play("piper-en-ryan", VS.default_tuning())
    assert "axross[voice]" in env.messages[-1] and env.tts.requests == []


def test_sad_audio_that_failed_its_check_is_named():
    e = Env(probe=MPROBE.ProbeResult(False, "the audio server did not answer"))
    try:
        assert not e.preview.play("piper-en-ryan", VS.default_tuning())
        assert e.tts.requests == []
        assert e.messages[-1] == MPROBE.unavailable_text(e.probe)
        assert "the audio server did not answer" in e.messages[-1]
    finally:
        e.preview.shutdown()


def test_sad_a_failing_worker_is_reported_and_the_preview_is_idle_again():
    e = Env(tts=FailingTTS())
    try:
        assert e.preview.play("piper-en-ryan", VS.default_tuning())
        assert pump(lambda: e.busy[-1:] == [""])
        assert "the model is broken" in e.messages[-1]
    finally:
        e.preview.shutdown()


@pytest.mark.parametrize("voice", ["nope", "whisper-base", ""])
def test_sad_an_unknown_voice_is_refused(env, voice):
    assert not env.preview.play(voice, VS.default_tuning())
    assert env.tts.requests == [] and env.messages


def test_sad_a_tuning_outside_its_range_is_refused_before_the_worker(env):
    assert not env.preview.play("piper-en-ryan", {**VS.default_tuning(), "speed": 7.0})
    assert env.tts.requests == [] and "speed" in env.messages[-1]


def test_edge_audio_still_being_checked_waits_and_then_speaks():
    e = Env(probe=None)
    try:
        assert e.preview.play("piper-en-ryan", VS.default_tuning())
        assert e.tts.requests == [] and e.busy == ["piper-en-ryan"]
        assert "Checking the audio" in e.messages[-1]
        e.probe = MPROBE.ProbeResult(True)
        e.waiting.pop()(e.probe)
        assert pump(lambda: e.tts.requests)
    finally:
        e.preview.shutdown()


def test_edge_an_audio_check_answered_after_stop_speaks_nothing():
    e = Env(probe=None)
    try:
        e.preview.play("piper-en-ryan", VS.default_tuning())
        e.preview.stop()
        e.waiting.pop()(MPROBE.ProbeResult(True))
        pump(lambda: False, 0.2)
        assert e.tts.requests == []
    finally:
        e.preview.shutdown()


def test_edge_an_audio_check_that_fails_later_is_named():
    e = Env(probe=None)
    try:
        e.preview.play("piper-en-ryan", VS.default_tuning())
        result = MPROBE.ProbeResult(False, "no audio server")
        e.waiting.pop()(result)
        assert e.messages[-1] == MPROBE.unavailable_text(result) and e.busy[-1] == ""
    finally:
        e.preview.shutdown()


def test_edge_listening_to_another_voice_stops_the_first():
    hold = threading.Event()
    e = Env(tts=FakeTTS(hold=hold))
    try:
        e.preview.play("piper-en-ryan", VS.default_tuning())
        assert pump(lambda: e.tts.requests)
        e.preview.play("piper-de-kerstin", VS.default_tuning())
        assert e.tts.kills == 1 and e.preview.playing_voice == "piper-de-kerstin"
        hold.set()
        assert pump(lambda: len(e.tts.requests) == 2)
        assert e.tts.requests[1]["lang"] == "de"
    finally:
        hold.set()
        e.preview.shutdown()


def test_edge_no_sound_device_ends_the_sample_with_the_reason(env):
    env.preview.play("piper-en-ryan", VS.default_tuning())
    assert pump(lambda: env.player.chunks)
    env.player.failed.emit("No audio output found")
    env.player.finish()
    assert pump(lambda: env.busy[-1:] == [""])
    assert "No audio output found" in " ".join(env.messages)
    assert not env.messages[-1].lower().startswith("played")


def test_edge_constructing_a_preview_starts_no_child():
    tts = FakeTTS()
    preview = V.VoicePreview(worker=tts, player=FakePlayer())
    assert tts.requests == [] and preview.playing_voice == ""
    preview.shutdown()


def test_edge_shutdown_closes_the_worker(env):
    closed = []
    env.tts.close = lambda: closed.append(1)
    env.preview.shutdown()
    assert closed == [1]


def test_happy_the_sample_audio_is_what_the_worker_sent(env):
    env.preview.play("piper-en-ryan", VS.default_tuning())
    assert pump(lambda: env.player.chunks)
    pcm, rate = env.player.chunks[0]
    assert rate == 22050 and pcm == b"\1\0" * 50  # FakeTTS's one event, decoded
