"""The Arcade's sound against the sink Qt 6.10+ really is: PulseAudio's own
thread pulls fixed requests out of the QAudioSink's ring and fills what
the ring cannot give with silence (QPlatformAudioSinkStream::process,
Qt 6.11). The ring used to be 50 ms, refilled from the GUI thread: any
stall of that thread past ~30 ms put silence into the music - the
stutter. Simulated here on a fixed clock: the pulls, the 5 ms pump, and
the GUI thread stalling now and then."""

from __future__ import annotations

import array
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.arcade import sound as S  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _own_cache(tmp_path_factory, monkeypatch):
    from ui import arcade_audio as AA

    monkeypatch.setattr(AA, "CACHE", tmp_path_factory.getbasetemp() / "arcade-cache")


class PullSink:
    """Qt 6.11's PulseAudio sink: a ring of *size* bytes; every *period_ms*
    the server pulls *request* frames, short pulls are padded with
    silence (counted)."""

    def __init__(self, size: int, request: int, period_ms: float):
        self.size, self.request, self.period = size, request, period_ms / 1000
        self.ring = array.array("h")
        self.now = 0.0
        self.next_pull = self.period
        self.silence = 0
        self.out = array.array("h")              # what the server played
        self.most = 0

    def advance(self, seconds: float) -> None:
        end = self.now + seconds
        while self.next_pull <= end:
            take = self.ring[:self.request]
            del self.ring[:self.request]
            self.out.extend(take)
            if len(take) < self.request:
                self.silence += self.request - len(take)
                self.out.extend([0] * (self.request - len(take)))
            self.next_pull += self.period
        self.now = end

    def bufferSize(self):  # noqa: N802 - Qt's name
        return self.size

    def bytesFree(self):  # noqa: N802 - Qt's name
        return self.size - 2 * len(self.ring)

    def setVolume(self, _v):  # noqa: N802 - Qt's name
        pass

    def stop(self):
        pass


class PullIO:
    def __init__(self, sink: PullSink):
        self.sink = sink

    def write(self, data: bytes) -> int:
        samples = array.array("h")
        samples.frombytes(bytes(data))
        room = (self.sink.size - 2 * len(self.sink.ring)) // 2
        self.sink.ring.extend(samples[:room])
        self.sink.most = max(self.sink.most, 2 * len(self.sink.ring))
        return 2 * min(len(samples), room)


def _audio(monkeypatch, request: int, period_ms: float):
    """An ArcadeAudio opening its sink the way it does in axross - the size
    it asks for is the ring it gets."""
    from ui import arcade_audio as AA

    made = {}

    def open_sink(_rate, _device, _volume, buffer_bytes):
        made["sink"] = sink = PullSink(buffer_bytes, request, period_ms)
        return sink, PullIO(sink)
    monkeypatch.setattr(AA, "open_sink", open_sink)
    audio = AA.ArcadeAudio()
    end = time.monotonic() + 30
    while len(audio._effects) < len(S.EFFECTS) and time.monotonic() < end:
        time.sleep(0.02)
    audio._ensure_sink()
    audio._timer.stop()                          # the test is the clock
    return audio, made["sink"]


def _play(audio, sink, seconds: float, *, stall_every: float = 0.5, stall: float = 0.04) -> None:
    """*seconds* of the event loop: the pump every 5 ms, and the GUI thread
    busy for *stall* every *stall_every* seconds."""
    from ui import arcade_audio as AA

    t, next_stall = 0.0, stall_every
    step = AA.PUMP_MS / 1000
    while t < seconds:
        if t >= next_stall:
            sink.advance(stall)
            t += stall
            next_stall += stall_every
        audio._pump()
        sink.advance(step)
        t += step


@pytest.mark.parametrize("pull, period_ms", [(441, 20.0), (1024, 46.44)])
def test_safety_the_music_has_no_gaps_when_the_gui_thread_stalls_40_ms(monkeypatch, pull, period_ms):
    audio, sink = _audio(monkeypatch, pull, period_ms)
    try:
        audio._music = array.array("h", [3000] * S.RATE)        # music running
        _play(audio, sink, 0.2, stall_every=10)                   # started
        sink.silence = 0
        _play(audio, sink, 6.0)                                   # 12 stalls of 40 ms
        assert sink.silence == 0, f"{sink.silence / S.RATE * 1000:.0f} ms of silence in the music"
    finally:
        audio.stop()


def test_happy_an_effect_still_comes_soon_and_the_queue_does_not_grow(monkeypatch):
    from ui import arcade_audio as AA

    audio, sink = _audio(monkeypatch, 441, 20.0)
    try:
        audio._music = array.array("h", [0] * S.RATE)            # silent music: the queue kept full
        _play(audio, sink, 1.0, stall_every=10)
        assert sink.most <= AA.FILL_MS / 1000 * S.RATE * 2 + 2    # FILL_MS queued, not the whole ring
        asked_at = len(sink.out)
        audio.play("key")
        _play(audio, sink, 0.5, stall_every=10)
        start = next(i for i in range(asked_at, len(sink.out)) if sink.out[i])
        latency = (start - asked_at) / S.RATE
        assert latency <= AA.FILL_MS / 1000 + period_s(441, 20.0), latency
    finally:
        audio.stop()


def period_s(request: int, period_ms: float) -> float:
    return max(request / S.RATE, period_ms / 1000)
