"""ui/arcade_audio's latency: a small sink buffer topped up closed-loop.

The sink here is a clock: it plays (consumes) what was queued as the
test advances time, counts underruns and keeps everything written. No
audio device is needed (there is none in CI)."""

from __future__ import annotations

import array
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.arcade import sound as S  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _own_cache(tmp_path_factory, monkeypatch):
    """Rendered effects go to a cache of the test session, not ~/.cache."""
    from ui import arcade_audio as AA

    monkeypatch.setattr(AA, "CACHE", tmp_path_factory.getbasetemp() / "arcade-cache")


class ClockSink:
    def __init__(self, size: int):
        self.size = size
        self.queued = 0
        self.played = 0                  # frames played so far
        self.underruns = 0
        self.stream = array.array("h")   # everything written, in order
        self.most = 0

    def bufferSize(self):  # noqa: N802 - Qt's name
        return self.size

    def bytesFree(self):  # noqa: N802 - Qt's name
        return self.size - self.queued

    def setVolume(self, _v):  # noqa: N802 - Qt's name
        pass

    def stop(self):
        pass

    def play_for(self, ms: float) -> None:
        n = int(S.RATE * ms / 1000) * 2
        if n > self.queued:
            self.underruns += 1
        took = min(n, self.queued)
        self.queued -= took
        self.played += took // 2


class ClockIO:
    def __init__(self, sink: ClockSink):
        self.sink = sink

    def write(self, data: bytes) -> int:
        take = min(len(data), self.sink.bytesFree())
        self.sink.queued += take
        self.sink.most = max(self.sink.most, self.sink.queued)
        self.sink.stream.frombytes(bytes(data[:take]))
        return take


def _audio(sink):
    from ui.arcade_audio import ArcadeAudio

    audio = ArcadeAudio(sink_factory=lambda: (sink, ClockIO(sink)))
    end = time.monotonic() + 30
    while len(audio._effects) < len(S.EFFECTS) and time.monotonic() < end:
        time.sleep(0.02)
    audio._ensure_sink()
    audio._timer.stop()                  # the test is the clock
    return audio


def test_happy_the_sink_buffer_is_small():
    from ui import arcade_audio as AA

    assert 20 <= AA.LEAD_MS <= 60 and AA.PUMP_MS <= 10
    assert AA.lead_bytes() == int(S.RATE * AA.LEAD_MS / 1000) * 2


def test_happy_an_effect_is_heard_within_the_buffer_not_a_quarter_second_later():
    from ui import arcade_audio as AA

    sink = ClockSink(AA.lead_bytes())
    audio = _audio(sink)
    audio._music = array.array("h", [0] * 4000)           # silent music: the queue is kept full - the worst case
    for _ in range(40):
        audio._pump()
        sink.play_for(AA.PUMP_MS)
    assert sink.most <= sink.size                          # at the buffer, never above
    asked_at = sink.played
    audio.play("key")                    # pumps at once
    for _ in range(40):
        sink.play_for(AA.PUMP_MS)
        audio._pump()
    start = next(i for i, s in enumerate(sink.stream) if s)
    latency = (start - asked_at) / S.RATE
    assert 0 <= latency <= 0.06, latency
    assert sink.underruns == 0
    audio.stop()


def test_happy_a_short_stall_is_no_gap_and_a_long_one_does_not_pile_up():
    from ui import arcade_audio as AA

    sink = ClockSink(AA.lead_bytes())
    audio = _audio(sink)
    audio._music = array.array("h", [1000] * S.RATE)      # music running
    audio._pump()
    sink.play_for(AA.LEAD_MS * 0.6)       # the GUI thread busy for 30 ms
    assert sink.underruns == 0
    audio._pump()
    assert sink.queued == sink.size
    sink.play_for(AA.LEAD_MS * 3)         # a long stall: one gap ...
    assert sink.underruns == 1
    for _ in range(20):
        audio._pump()
        sink.play_for(AA.PUMP_MS)
    assert sink.most <= sink.size and sink.underruns == 1  # ... and no queue piling up after it
    audio.stop()


def test_happy_an_effect_asked_for_before_rendering_ended_still_plays_when_fresh(monkeypatch):
    from ui import arcade_audio as AA

    sink = ClockSink(AA.lead_bytes())
    audio = _audio(sink)
    rendered = audio._effects
    audio._effects = {}
    audio.play("key")
    audio.play("gem")
    audio._waiting[1] = ("gem", 1.0, time.monotonic() - AA.FRESH_S - 1)     # a stale one
    audio._effects = rendered
    audio.mix(10)
    assert len(audio._playing) == 1 and not audio._waiting
    audio.stop()


def test_happy_many_voices_are_limited_not_wrapped():
    from ui import arcade_audio as AA

    sink = ClockSink(AA.lead_bytes())
    audio = _audio(sink)
    for _ in range(AA.MAX_VOICES + 3):
        audio.play("crash")
    assert len(audio._playing) <= AA.MAX_VOICES
    out = audio.mix(2000)
    assert max(abs(x) for x in out) <= 32767 and max(out) > 20000
    audio.stop()


def test_sad_audio_still_starting_is_tried_again_not_given_up(monkeypatch):
    from ui import arcade_audio as AA
    from ui.voice import AudioPending

    tries = []

    def pending(*_a):
        tries.append(1)
        if len(tries) == 1:
            raise AudioPending("starting")
        sink = ClockSink(AA.lead_bytes())
        return sink, ClockIO(sink)
    monkeypatch.setattr(AA, "open_sink", pending)
    audio = AA.ArcadeAudio()
    audio.play("bit")
    assert not audio._failed and audio._sink is None and audio._retry.isActive()
    audio._ensure_sink()                  # the retry
    assert audio._sink is not None and audio._timer.isActive()
    audio.stop()


def test_happy_music_starts_without_waiting_for_an_effect(tmp_path, monkeypatch):
    from ui import arcade_audio as AA

    monkeypatch.setattr(AA, "CACHE", tmp_path)
    sink = ClockSink(AA.lead_bytes())
    opened = []

    def factory():
        opened.append(1)
        return sink, ClockIO(sink)
    audio = AA.ArcadeAudio(sink_factory=factory)
    audio.music(3)
    assert opened                          # the sink is open for the music alone
    audio.stop()


def test_happy_nothing_is_written_while_nothing_sounds_and_an_effect_then_starts_at_once():
    from ui import arcade_audio as AA

    sink = ClockSink(AA.lead_bytes())
    audio = _audio(sink)
    for _ in range(10):
        audio._pump()
        sink.play_for(AA.PUMP_MS)
    assert len(sink.stream) == 0
    asked_at = sink.played
    audio.play("bit")
    start = next(i for i, s in enumerate(sink.stream) if s)
    assert (start - asked_at) / S.RATE < 0.005
    audio.stop()
