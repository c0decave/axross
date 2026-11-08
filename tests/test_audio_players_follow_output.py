"""The Agent's voice and the Arcade follow a new output from the Audio Mixer.

Both players listened to the mixer's notifier but only set the volume:
the voice kept the sink it had opened on the old device for every
answer after, the Arcade for the whole session - although docs/USAGE.md
promises "running players follow at once". Now the voice closes its
sink when it is silent (while it speaks: when the utterance has ended),
so the next one opens on the new output; the Arcade closes its sink and
opens it on the new output at once, the sounds carry on.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)
from PyQt6.QtCore import QObject  # noqa: E402
from PyQt6.QtMultimedia import QAudio  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import audio_route as AR  # noqa: E402
from core import audio_settings as AS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class FakeIO:
    def __init__(self, sink):
        self.sink = sink

    def write(self, data):
        self.sink.buffered += len(data)
        self.sink.written += len(data)
        return len(data)


class FakeSink(QObject):
    """A QAudioSink's interface (a QObject, as the player checks)."""

    def __init__(self, device, size=1 << 16):
        super().__init__()
        self.device, self.size = device, size
        self.buffered = self.written = 0
        self.stopped = False
        self.volume = None

    def bytesFree(self):  # noqa: N802 - Qt API
        return self.size - self.buffered

    def bufferSize(self):  # noqa: N802 - Qt API
        return self.size

    def state(self):
        return QAudio.State.ActiveState if self.buffered else QAudio.State.IdleState

    def setVolume(self, v):  # noqa: N802 - Qt API
        self.volume = v

    def stop(self):
        self.stopped = True


@pytest.fixture(autouse=True)
def _route():
    AR.forget()
    AR.publish(AS.AudioSettings())
    yield
    AR.forget()


def _save(**values) -> None:
    AR.publish(AS.AudioSettings(**values))


@pytest.fixture
def voice(monkeypatch):
    from ui import voice as V

    opened: list[FakeSink] = []

    def qt_sink(rate, device_id=None, volume=None):
        sink = FakeSink(AR.source_output_id("voice") if device_id is None else device_id)
        opened.append(sink)
        return sink, FakeIO(sink), rate
    monkeypatch.setattr(V, "_qt_sink", qt_sink)
    player = V.QtPlayer()                       # the Agent's voice: no sink_factory of its own
    player.opened = opened
    yield player
    player.stop()
    AR.notifier().changed.disconnect(player._mixer_changed)


def _say(player) -> None:
    player.enqueue(b"\0\1" * 1600, 16000)


def test_sad_a_silent_voice_takes_the_new_output_for_the_next_answer(voice):
    _save(voice_output="speakers")
    _say(voice)
    first = voice.opened[-1]
    first.buffered = 0                          # played out: silent
    voice._push()
    assert not voice.busy()
    _save(voice_output="speakers", voice_volume=40)  # only the volume: the sink stays
    assert voice._sink is first and not first.stopped and first.volume == pytest.approx(0.4)
    _save(voice_output="headset")
    assert first.stopped and voice._sink is None   # closed at once
    _say(voice)
    assert [s.device for s in voice.opened] == ["speakers", "headset"]


def test_sad_a_speaking_voice_finishes_on_the_old_output_then_follows(voice):
    _save(voice_output="speakers")
    _say(voice)
    first = voice.opened[-1]
    assert voice.busy()
    _save(voice_output="headset")
    assert voice._sink is first and not first.stopped   # the sentence is not cut off
    first.buffered = 0                          # the utterance ends
    voice._push()
    assert first.stopped and voice._sink is None
    _say(voice)
    assert voice.opened[-1].device == "headset"


# --- the Arcade ------------------------------------------------------------------------------


@pytest.fixture
def arcade(monkeypatch, tmp_path):
    from ui import arcade_audio as AA

    monkeypatch.setattr(AA, "CACHE", tmp_path)
    opened: list[FakeSink] = []

    def open_sink(rate, device_id, volume, buffer_bytes):
        sink = FakeSink(device_id, size=buffer_bytes)
        sink.volume = volume
        opened.append(sink)
        return sink, FakeIO(sink)
    monkeypatch.setattr(AA, "open_sink", open_sink)
    audio = AA.ArcadeAudio()
    audio.opened = opened
    yield audio
    getattr(audio, "close", audio.stop)()


def test_sad_the_arcade_moves_to_the_new_output_at_once(arcade):
    import array

    _save(games_output="speakers")
    arcade._ensure_sink()
    first = arcade.opened[-1]
    _save(games_output="speakers", games_volume=30)     # only the volume: the same sink
    assert arcade._sink is first and first.volume == pytest.approx(0.3)
    with arcade._lock:
        arcade._music = array.array("h", [1000] * 4000)     # music playing
    _save(games_output="headset", games_volume=30)
    assert first.stopped
    assert [s.device for s in arcade.opened] == ["speakers", "headset"]
    now = arcade.opened[-1]
    assert arcade._sink is now and now.volume == pytest.approx(0.3)
    assert arcade._timer.isActive()
    arcade._pump()
    assert now.written > 0 and arcade._music is not None    # the music goes on, there
