"""The speaker (ui.voice.QtPlayer) with QAudioSink replaced by a fake that
keeps its interface: chunks are pushed as the sink has room, a device that
wants another rate gets resampled sound, a missing device is reported and
never hangs the voice."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtMultimedia import QAudio  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from ui import voice as V  # noqa: E402

APP = QApplication.instance() or QApplication([])


class FakeIO:
    def __init__(self, sink):
        self.sink = sink

    def write(self, data):
        self.sink.written += data
        self.sink.buffered += len(data)
        return len(data)


class FakeSink:
    def __init__(self, device_rate, size=4000):
        self.device_rate = device_rate
        self.size = size
        self.buffered = 0
        self.written = b""
        self.stopped = False

    def bytesFree(self):  # noqa: N802 - Qt API
        return self.size - self.buffered

    def bufferSize(self):  # noqa: N802 - Qt API
        return self.size

    def state(self):
        return QAudio.State.ActiveState if self.buffered else QAudio.State.IdleState

    def play(self, n):
        """The sound card took *n* bytes out of the buffer."""
        self.buffered = max(0, self.buffered - n)

    def stop(self):
        self.stopped = True

    def deleteLater(self):  # noqa: N802 - Qt API
        pass


def _factory(device_rate=None, fail=None):
    made = []

    def factory(rate):
        if fail:
            raise OSError(fail)
        sink = FakeSink(device_rate or rate)
        made.append((rate, sink))
        return sink, FakeIO(sink), sink.device_rate

    factory.made = made
    return factory


def _drain(player, sink, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        sink.play(2000)
        APP.processEvents()
        time.sleep(0.01)
        if not player.busy():
            for _ in range(10):  # the timer's next tick says drained
                APP.processEvents()
                time.sleep(0.01)
            return True
    return False


def test_happy_chunks_play_as_the_sink_has_room_then_drained():
    factory = _factory()
    player = V.QtPlayer(sink_factory=factory)
    drained, levels = [], []
    player.drained.connect(lambda: drained.append(1))
    player.level.connect(levels.append)
    player.enqueue(b"\x10\x00" * 5000, 22050)
    sink = factory.made[0][1]
    assert player.busy() and len(sink.written) == 4000  # the first buffer full
    assert _drain(player, sink)
    assert sink.written == b"\x10\x00" * 5000
    assert drained == [1] and levels[-1] == 0.0


def test_happy_a_device_with_another_rate_gets_resampled_sound():
    factory = _factory(device_rate=44100)
    player = V.QtPlayer(sink_factory=factory)
    player.enqueue(b"\x10\x00" * 2205, 22050)  # 0.1 s
    sink = factory.made[0][1]
    assert _drain(player, sink)
    assert abs(len(sink.written) // 2 - 4410) <= 1


def test_sad_no_audio_output_is_reported_and_never_hangs():
    player = V.QtPlayer(sink_factory=_factory(fail="No audio output found"))
    failed, drained = [], []
    player.failed.connect(failed.append)
    player.drained.connect(lambda: drained.append(1))
    player.enqueue(b"\x10\x00" * 100, 22050)
    assert failed == ["No audio output found"] and drained == [1]
    assert not player.busy()


def test_edge_a_new_rate_waits_for_the_old_sound_then_reopens():
    factory = _factory()
    player = V.QtPlayer(sink_factory=factory)
    player.enqueue(b"\x01\x00" * 100, 22050)
    player.enqueue(b"\x02\x00" * 100, 16000)
    first = factory.made[0][1]
    assert len(factory.made) == 1  # the 22050 piece still plays
    assert _drain(player, first) or len(factory.made) == 2
    second = factory.made[-1][1]
    _drain(player, second)
    assert [rate for rate, _s in factory.made] == [22050, 16000]
    assert first.stopped and second.written == b"\x02\x00" * 100


def test_edge_stop_drops_everything_and_closes():
    factory = _factory()
    player = V.QtPlayer(sink_factory=factory)
    player.enqueue(b"\x10\x00" * 50000, 22050)
    player.stop()
    assert not player.busy() and factory.made[0][1].stopped
