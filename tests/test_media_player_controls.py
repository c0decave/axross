"""The Media Player's controls: seeking, drag & drop, playlists, shuffle and
repeat, volume, keyboard and the current-track display.

Operator: *„ist der media player auch schon geprüft? hat er alle funktionen
die ein mediaplayer haben sollte? plalists, reinziehen von songs, next stop
start, vorspulen.... lautstärke..."*

The fixtures are WAV files written here with the stdlib ``wave`` module. The
left channel is a slow ramp (sample value = 0.9 * position / length), so the
first sample written after a seek tells where the playback really went. The
equalizer at flat gains is the identity, so the ramp reaches the sink
unchanged. There is no sound card on the test host: the numpy engine plays
into a sink that keeps the bytes, the QMediaPlayer engine runs on its clock.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
import wave
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import (  # noqa: E402
    QEventLoop,
    QMimeData,
    QPoint,
    QPointF,
    Qt,
    QTimer,
    QUrl,
)
from PyQt6.QtGui import QDropEvent, QWheelEvent  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
RATE = 44100
PEAK = 0.9


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_controls_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()


# -- fixtures -------------------------------------------------------------------------


def ramp_wav(path, seconds: float, right: float = 0.0) -> Path:
    """Left: 0.9 * t / length; right: a constant (tells files apart)."""
    frames = int(seconds * RATE)
    left = (np.arange(frames) / frames * PEAK * 32767).astype("<i2")
    other = np.full(frames, int(right * 32767), "<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(np.stack([left, other], axis=1).tobytes())
    return Path(path)


def ramp_seconds(sample: float, seconds: float) -> float:
    """Where in a *seconds* long ramp file *sample* (left channel) sits."""
    return sample / PEAK * seconds


def wait(cond, timeout: float = 15.0) -> bool:
    """Run a real event loop until *cond()* holds. Not processEvents() and
    sleep: while the decoder ran on the GUI thread, it handed out its next
    buffer only once the last one was read, so every sleep stalled decoding
    (a seek measured that way took 25 s instead of a quarter of one); the
    engine's signals still arrive through this loop."""
    if cond():
        return True
    end = time.time() + timeout
    loop = QEventLoop()
    timer = QTimer()
    timer.setInterval(1)
    timer.timeout.connect(lambda: (cond() or time.time() > end) and loop.quit())
    timer.start()
    loop.exec()
    timer.stop()
    return bool(cond())


def pump(seconds: float) -> None:
    end = time.time() + seconds
    wait(lambda: time.time() > end, seconds + 1)


class ThrottledSink(MP.MemorySink):
    """A sound card that takes *frames* per pump tick (10 ms): with 4410 it
    plays ten times faster than real time, so a test has time to act while
    a track plays and the engine keeps decoded audio queued."""

    def __init__(self, frames: int = 4410) -> None:
        super().__init__()
        self.frames = frames
        self.starts = 0

    def start(self) -> None:
        self.starts += 1
        super().start()

    def bytes_free(self) -> int:
        return self.frames * 8 if self.running else 0


def eq_engine(sink=None):
    sink = sink if sink is not None else ThrottledSink()
    return MP.EqEngine(sink_factory=lambda fmt: sink), sink


def written_frames(sink) -> int:
    return len(sink.data) // 8


def hold(engine, sink) -> int:
    """Stop *sink* taking audio and wait out the audio thread's step in
    progress; the frames it took per tick (give them back with
    ``sink.frames = ...``). The engine feeds the sink from a thread of its
    own: a write between reading the sink's length and a seek counted
    pre-seek audio as the seek's (measured: the track's first 441 frames,
    22 of 40 runs)."""
    frames, sink.frames = sink.frames, 0
    engine.set_volume(engine.volume)  # runs in the audio thread after that step
    return frames


# -- 1. seeking: the numpy engine ---------------------------------------------------------


def test_happy_format_time_shows_minutes_and_hours():
    assert MP.format_time(0) == "0:00"
    assert MP.format_time(83_000) == "1:23"
    assert MP.format_time(296_999) == "4:56"
    assert MP.format_time(3_723_000) == "1:02:03"


def test_sad_format_time_of_nonsense_is_zero():
    assert MP.format_time(-5) == "0:00"
    assert MP.format_time(None) == "0:00"


def _seek_and_measure(engine, sink, target_ms, seconds):
    """Seek, play to the end; the first post-seek sample's place (s) and
    the post-seek samples."""
    frames = hold(engine, sink)
    before = written_frames(sink)
    engine.seek(target_ms)
    sink.frames = frames
    assert engine.position_ms() == target_ms
    assert wait(lambda: engine.finished, 30), engine.error
    after = sink.samples()[before:]
    return ramp_seconds(float(after[0, 0]), seconds), after


@pytest.mark.parametrize("target_ms", [6000, 1000])
def test_happy_eq_engine_seeks_forward_and_back(tmp_path, target_ms):
    """6 s lies beyond what is decoded (the decoder runs on, dropping);
    1 s lies behind (the decoder starts again from the top)."""
    seconds = 8.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    engine, sink = eq_engine()
    engine.load(str(path))
    engine.play()
    assert wait(lambda: written_frames(sink) > RATE * 2)  # 2 s in
    where, after = _seek_and_measure(engine, sink, target_ms, seconds)
    assert abs(where - target_ms / 1000) < 0.005, where
    # The rest of the track, whole: no gap, nothing twice.
    expected = int((seconds - target_ms / 1000) * RATE)
    assert abs(len(after) - expected) < 64, (len(after), expected)
    assert np.max(np.abs(np.diff(after[:, 0]))) < 1e-3
    assert engine.error == ""


def test_happy_eq_engine_seeks_inside_what_is_already_decoded(tmp_path):
    """A seek into the audio decoded ahead takes it from the queue: the
    equalizer runs on, the output equals an unbroken run."""
    seconds = 8.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    engine, sink = eq_engine(ThrottledSink(frames=441))  # real time: keeps a queue
    engine.load(str(path))
    engine.play()
    assert wait(lambda: len(engine._pending) > RATE * 8 * 1.5)
    current = engine.position_ms()
    target = current + 1000
    hold(engine, sink)
    before = written_frames(sink)
    starts = engine._decoder_starts
    engine.seek(target)
    sink.frames = 1 << 20
    assert wait(lambda: engine.finished, 30)
    assert engine._decoder_starts == starts  # no second decode
    first = float(sink.samples()[before, 0])
    assert abs(ramp_seconds(first, seconds) - target / 1000) < 0.005


def test_edge_eq_engine_seek_back_while_the_decoder_holds_a_buffer(tmp_path):
    """With the queue full the decoder keeps its next buffer unread; after
    stop() that buffer is still available and was read as the first one
    of the new run: the track went on 4096 frames before the target."""
    seconds = 6.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    engine, sink = eq_engine(ThrottledSink(frames=441))
    engine.load(str(path))
    engine.play()
    assert wait(lambda: not engine._room() and engine._decoder.bufferAvailable()
                and engine.position_ms() > 600)
    hold(engine, sink)
    before = written_frames(sink)
    engine.seek(300)
    engine._pump()  # the timer fires before the decoder's first new buffer
    sink.frames = 1 << 20
    assert wait(lambda: engine.finished, 30)
    first = float(sink.samples()[before, 0])
    assert abs(ramp_seconds(first, seconds) - 0.3) < 0.005, ramp_seconds(first, seconds)


def test_happy_eq_engine_seek_keeps_the_equalizer_consistent(tmp_path):
    """After a restart the output is the equalizer run over the track from
    the target on - what a fresh start there would play."""
    seconds = 6.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    gains = list(MP.PRESETS["Rock"])
    engine, sink = eq_engine()
    engine.set_gains(gains)
    engine.load(str(path))
    engine.play()
    assert wait(lambda: written_frames(sink) > RATE * 3)
    frames = hold(engine, sink)
    before = written_frames(sink)
    engine.seek(1000)
    sink.frames = frames
    assert wait(lambda: engine.finished, 30)
    after = sink.samples()[before:]
    with wave.open(str(path)) as w:
        pcm = np.frombuffer(w.readframes(w.getnframes()), "<i2").reshape(-1, 2)
    source = pcm.astype(np.float32)[RATE:] / 32768.0
    eq = MP.Equalizer(RATE, 2)
    eq.set_gains(gains)
    ref = np.concatenate([eq.process(source), eq.flush()])[eq.latency:eq.latency + len(source)]
    n = min(len(ref), len(after))
    assert abs(len(after) - len(ref)) < 64
    assert np.max(np.abs(after[:n] - ref[:n])) < 1e-3


def test_happy_eq_engine_seek_while_paused_stays_paused(tmp_path):
    seconds = 6.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    engine, sink = eq_engine()
    engine.load(str(path))
    engine.play()
    assert wait(lambda: written_frames(sink) > RATE)
    engine.pause()
    engine.seek(4000)
    assert engine.state == "paused" and engine.position_ms() == 4000
    before = written_frames(sink)
    pump(0.3)
    assert written_frames(sink) == before  # nothing plays while paused
    engine.play()
    assert wait(lambda: engine.finished, 30)
    first = float(sink.samples()[before, 0])
    assert abs(ramp_seconds(first, seconds) - 4.0) < 0.005


def test_edge_eq_engine_seek_before_play_starts_there(tmp_path):
    seconds = 4.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    engine, sink = eq_engine()
    engine.load(str(path))
    engine.seek(2500)
    assert engine.state == "stopped" and engine.position_ms() == 2500
    engine.play()
    assert wait(lambda: engine.finished, 30)
    assert abs(ramp_seconds(float(sink.samples()[0, 0]), seconds) - 2.5) < 0.005


def test_edge_eq_engine_seek_past_the_end_finishes_the_track(tmp_path):
    path = ramp_wav(tmp_path / "ramp.wav", 4.0)
    engine, _sink = eq_engine()
    ended = []
    engine.finished_playing.connect(lambda: ended.append(True))
    engine.load(str(path))
    engine.play()
    assert wait(lambda: engine.duration_ms() > 0)
    engine.seek(10 ** 9)
    assert wait(lambda: ended, 10)
    assert engine.finished and engine.error == ""


def test_edge_eq_engine_seek_past_the_end_before_the_length_is_known(tmp_path):
    """Right after play() the decoder has not told the length yet: the seek
    decodes to the end, finds nothing more and ends the track - no error."""
    path = ramp_wav(tmp_path / "ramp.wav", 2.0)
    engine, _sink = eq_engine()
    ended = []
    engine.finished_playing.connect(lambda: ended.append(True))
    engine.load(str(path))
    engine.play()
    engine._duration = 0  # as before durationChanged arrived
    engine.seek(60_000)
    assert wait(lambda: ended, 10)
    assert engine.error == ""


def test_sad_eq_engine_seek_without_a_track_does_nothing(tmp_path):
    engine, sink = eq_engine()
    engine.seek(5000)
    assert engine.position_ms() == 0 and engine.state == "stopped" and not sink.data
    path = ramp_wav(tmp_path / "ramp.wav", 2.0)
    engine.load(str(path))
    engine.seek(-300)  # clamped to the start
    assert engine.position_ms() == 0


def test_sad_stop_right_after_play_is_no_error(tmp_path):
    """Stopping the decoder makes it emit finished() at once; with nothing
    decoded yet that read as "no audio could be decoded" and showed
    "Cannot play" after a plain ⏹."""
    path = ramp_wav(tmp_path / "ramp.wav", 2.0)
    engine, _sink = eq_engine()
    errors = []
    engine.failed.connect(errors.append)
    engine.load(str(path))
    engine.play()
    engine.stop()
    pump(0.2)
    assert engine.error == "" and errors == []


def test_edge_eq_engine_duration_is_known_while_playing(tmp_path):
    path = ramp_wav(tmp_path / "ramp.wav", 3.0)
    engine, _sink = eq_engine()
    engine.load(str(path))
    assert engine.duration_ms() == 0
    engine.play()
    assert wait(lambda: engine.duration_ms() > 0)
    assert abs(engine.duration_ms() - 3000) < 50


def test_edge_seek_latency_far_into_a_long_track(tmp_path):
    """Seeking back to 50 s of a 60 s WAV decodes 50 s again: well under a
    second (the measured figures for long compressed files are in the
    report of the change)."""
    path = ramp_wav(tmp_path / "long.wav", 60.0)
    engine, sink = eq_engine()
    engine.load(str(path))
    engine.play()
    assert wait(lambda: written_frames(sink) > RATE)
    engine.seek(55_000)  # forward: runs the decoder on
    assert wait(lambda: engine.finished, 30)
    engine.play()
    assert wait(lambda: written_frames(sink) > 0 and engine.position_ms() > 100)
    frames = hold(engine, sink)
    before = written_frames(sink)
    start = time.perf_counter()
    engine.seek(50_000)  # backward: decodes from the top
    sink.frames = frames
    assert wait(lambda: written_frames(sink) > before, 10)
    latency = time.perf_counter() - start
    first = float(sink.samples()[before, 0])
    assert abs(ramp_seconds(first, 60.0) - 50.0) < 0.01
    assert latency < 3.0, latency


# -- 1. seeking: the QMediaPlayer engine ---------------------------------------------------


def _simple():
    return MP.SimpleEngine()


def test_happy_simple_engine_seeks_and_knows_the_length(tmp_path):
    path = ramp_wav(tmp_path / "ramp.wav", 8.0)
    engine = _simple()
    try:
        engine.load(str(path))
        engine.play()
        assert wait(lambda: engine.duration_ms() > 0 and engine.position_ms() > 0)
        assert abs(engine.duration_ms() - 8000) < 50
        engine.seek(5000)
        assert wait(lambda: engine.position_ms() >= 5000, 5)
        assert engine.position_ms() < 7000
        engine.seek(1000)
        assert wait(lambda: engine.position_ms() < 3000, 5)
    finally:
        engine.stop()


def test_edge_simple_engine_seek_before_play_and_past_the_end(tmp_path):
    path = ramp_wav(tmp_path / "ramp.wav", 6.0)
    engine = _simple()
    ended = []
    engine.finished_playing.connect(lambda: ended.append(True))
    try:
        engine.load(str(path))
        engine.seek(4000)
        assert engine.position_ms() == 4000
        engine.play()
        assert wait(lambda: engine.position_ms() >= 4000 and engine.state == "playing", 5)
        engine.seek(10 ** 9)
        assert wait(lambda: ended, 5)
        assert engine.finished and engine.error == ""
    finally:
        engine.stop()


def test_sad_simple_engine_reports_a_broken_file(tmp_path):
    broken = tmp_path / "broken.mp3"
    broken.write_bytes(b"not audio at all" * 100)
    engine = _simple()
    errors = []
    engine.failed.connect(errors.append)
    engine.load(str(broken))
    engine.play()
    assert wait(lambda: errors, 10)
    assert engine.error and engine.state == "stopped"
    engine.seek(1000)  # no crash on a failed track


# -- the panel: a scripted engine ----------------------------------------------------------

from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402


class FakeEngine(QObject):
    """The engine interface without audio: tests drive position and ends."""

    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, duration_ms: int = 200_000) -> None:
        super().__init__()
        self.state, self.error, self.finished, self.loaded, self.path = (
            "stopped", "", False, False, "")
        self.duration = duration_ms
        self.position = 0
        self.volume = 1.0
        self.gains_db = [0.0] * 10
        self.loads: list[str] = []
        self.seeks: list[int] = []
        self.broken: set[str] = set()

    def load(self, path):
        self.path, self.loaded, self.error, self.finished = path, True, "", False
        self.state, self.position = "stopped", 0
        self.loads.append(path)
        self.changed.emit()

    def play(self):
        if self.path in self.broken:
            self.error = "broken"
            self.state = "stopped"
            self.changed.emit()
            self.failed.emit("broken")
            return
        self.state = "playing"
        self.changed.emit()

    def pause(self):
        if self.state == "playing":
            self.state = "paused"
            self.changed.emit()

    def stop(self):
        self.state, self.position = "stopped", 0
        self.changed.emit()

    def seek(self, ms):
        ms = max(0, int(ms))
        self.seeks.append(ms)
        if self.duration and ms >= self.duration and self.state != "stopped":
            self.end()
            return
        self.position = ms
        self.changed.emit()

    def end(self):
        self.state, self.finished, self.position = "stopped", True, 0
        self.changed.emit()
        self.finished_playing.emit()

    def set_volume(self, v):
        self.volume = v

    def set_gains(self, g):
        pass

    def position_ms(self):
        return self.position

    def duration_ms(self):
        return self.duration if self.loaded else 0

    def current_bars(self, n=32):
        return None


def fake_panel(tmp_path, n=4, **kw):
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, **kw)
    paths = []
    for i in range(n):
        p = tmp_path / f"t{i}.wav"
        p.write_bytes(b"RIFF")
        paths.append(str(p))
    panel.add_files(paths)
    return panel, engine, paths


def names(engine):
    return [os.path.basename(p) for p in engine.loads]


# -- 1. seeking: the panel ------------------------------------------------------------------


def test_happy_panel_time_label_and_seek_slider_follow_the_track(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 1)
    try:
        panel.play_selected()
        engine.position = 83_000
        engine.duration = 296_000
        panel._refresh_time()
        assert panel.time_label.text() == "1:23 / 4:56"
        assert panel.seek_slider.maximum() == 296_000
        assert panel.seek_slider.value() == 83_000
    finally:
        panel.close()


def test_happy_panel_click_on_the_seek_slider_jumps_there(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 1)
    try:
        panel.resize(600, 500)
        panel.show()
        panel.play_selected()
        panel._refresh_time()
        slider = panel.seek_slider
        QTest.mouseClick(slider, Qt.MouseButton.LeftButton, pos=QPoint(slider.width() * 3 // 4,
                                                                       slider.height() // 2))
        assert engine.seeks, "a click seeks"
        assert abs(engine.seeks[-1] - 150_000) < 200_000 * 0.05, engine.seeks
    finally:
        panel.close()


def test_edge_panel_dragging_the_slider_seeks_on_release_only(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 1)
    try:
        panel.resize(600, 500)
        panel.show()
        panel.play_selected()
        panel._refresh_time()
        slider = panel.seek_slider
        slider.setSliderDown(True)  # the user holds the handle
        slider.setSliderPosition(100_000)
        engine.position = 5_000
        panel._refresh_time()  # the clock must not pull the handle back
        assert slider.value() == 100_000 and engine.seeks == []
        assert panel.time_label.text().startswith("1:40")  # shows where it would go
        slider.setSliderDown(False)
        assert engine.seeks == [100_000]
    finally:
        panel.close()


def test_sad_panel_seek_slider_without_a_track_is_disabled(tmp_path):
    panel = MP.PlayerPanel(engine=FakeEngine())
    try:
        panel._refresh_time()
        assert not panel.seek_slider.isEnabled()
        assert panel.time_label.text() == "0:00 / 0:00"
    finally:
        panel.close()


def test_e2e_panel_seeks_a_real_track_with_the_slider(tmp_path):
    seconds = 8.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    sink = ThrottledSink()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink))
    try:
        panel.resize(600, 500)
        panel.show()
        panel.add_files([str(path)])
        panel.play_selected()
        assert wait(lambda: panel.engine.duration_ms() > 0 and written_frames(sink) > RATE)
        panel._refresh_time()
        assert panel.time_label.text().endswith("/ 0:08")
        frames = hold(panel.engine, sink)
        before = written_frames(sink)
        slider = panel.seek_slider
        slider.setSliderDown(True)
        slider.setSliderPosition(6000)
        slider.setSliderDown(False)
        sink.frames = frames
        assert wait(lambda: written_frames(sink) > before)
        first = float(sink.samples()[before, 0])
        assert abs(ramp_seconds(first, seconds) - 6.0) < 0.01
    finally:
        panel.close()


# -- 4. shuffle and repeat -----------------------------------------------------------------


def test_happy_repeat_off_stops_at_the_end_and_next_does_not_wrap(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    try:
        assert panel.repeat == "off"
        panel.play_selected()
        engine.end()
        engine.end()
        assert names(engine) == ["t0.wav", "t1.wav", "t2.wav"]
        engine.end()  # the last one ended: nothing more
        assert names(engine) == ["t0.wav", "t1.wav", "t2.wav"]
        panel.next_button.click()
        assert len(engine.loads) == 3
    finally:
        panel.close()


def test_happy_repeat_all_wraps_both_ways(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    try:
        panel.set_repeat("all")
        panel.play_selected()
        for _ in range(3):
            engine.end()
        assert names(engine) == ["t0.wav", "t1.wav", "t2.wav", "t0.wav"]
        panel.prev_button.click()  # at 0:00 of the first: back to the last
        assert names(engine)[-1] == "t2.wav"
    finally:
        panel.close()


def test_happy_repeat_one_replays_on_its_own_but_next_moves_on(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    try:
        panel.set_repeat("one")
        panel.play_selected()
        engine.end()
        engine.end()
        assert names(engine) == ["t0.wav"] * 3
        panel.next_button.click()
        assert names(engine)[-1] == "t1.wav"
    finally:
        panel.close()


def test_edge_previous_restarts_after_three_seconds(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    try:
        panel.playlist.setCurrentRow(1)
        panel.play_selected()
        engine.position = 12_000
        panel.prev_button.click()
        assert names(engine) == ["t1.wav"] and engine.seeks[-1] == 0
        engine.position = 1_000
        panel.prev_button.click()
        assert names(engine)[-1] == "t0.wav"
        engine.position = 0
        panel.prev_button.click()  # first track, repeat off: starts it again
        assert names(engine)[-1] == "t0.wav"
    finally:
        panel.close()


def test_happy_shuffle_plays_every_track_once_per_round(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 6)
    try:
        panel._rng.seed(7)
        panel.set_shuffle(True)
        panel.play_selected()
        for _ in range(5):
            engine.end()
        assert sorted(names(engine)) == sorted(f"t{i}.wav" for i in range(6))
        engine.end()  # repeat off: the round is over
        assert len(engine.loads) == 6
        order = names(engine)
        engine.position = 0
        panel.prev_button.click()  # back through the history
        assert names(engine)[-1] == order[-2]
    finally:
        panel.close()


def test_edge_shuffle_with_repeat_all_starts_a_new_round(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    try:
        panel._rng.seed(1)
        panel.set_shuffle(True)
        panel.set_repeat("all")
        panel.play_selected()
        for _ in range(8):
            engine.end()
        assert len(engine.loads) == 9
        rounds = [sorted(names(engine)[i:i + 3]) for i in (0, 3, 6)]
        assert all(r == ["t0.wav", "t1.wav", "t2.wav"] for r in rounds)
    finally:
        panel.close()


def test_happy_the_buttons_cycle_repeat_and_toggle_shuffle(tmp_path):
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    try:
        seen = []
        for _ in range(4):
            panel.repeat_button.click()
            seen.append(panel.repeat)
        assert seen == ["all", "one", "off", "all"]
        assert panel.repeat_button.toolTip()
        panel.shuffle_button.click()
        assert panel.shuffle and panel.shuffle_button.isChecked()
    finally:
        panel.close()


def test_sad_an_unknown_repeat_mode_is_refused(tmp_path):
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    try:
        with pytest.raises(ValueError):
            panel.set_repeat("forever")
        assert panel.repeat == "off"
    finally:
        panel.close()


def test_edge_next_and_previous_on_an_empty_playlist_do_nothing():
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine)
    try:
        panel.next_button.click()
        panel.prev_button.click()
        engine.end()
        assert engine.loads == []
    finally:
        panel.close()


def test_e2e_repeat_one_replays_a_real_track(tmp_path):
    path = ramp_wav(tmp_path / "short.wav", 0.3)
    sink = MP.MemorySink()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink))
    try:
        panel.add_files([str(path)])
        panel.set_repeat("one")
        panel.play_selected()
        one = int(0.3 * RATE)
        assert wait(lambda: written_frames(sink) >= 3 * one, 20)
        panel.set_repeat("off")
        assert wait(lambda: panel.engine.state == "stopped" and panel.engine.finished, 20)
    finally:
        panel.close()


# -- 5. volume ---------------------------------------------------------------------------


def test_happy_the_volume_curve_is_perceptual():
    f = MP.perceptual_to_linear
    assert f(0.0) == 0.0 and f(1.0) == 1.0
    assert abs(f(0.5) - 0.125) < 1e-9  # cubic: half way is -18 dB
    values = [f(i / 100) for i in range(101)]
    assert values == sorted(values) and len(set(values)) == 101
    # Equal slider steps are about equal steps in loudness (dB) up top.
    db = [20 * np.log10(f(v)) for v in (0.4, 0.6, 0.8, 1.0)]
    steps = np.diff(db)
    assert max(steps) / min(steps) < 2.5
    for v in (0.0, 0.1, 0.33, 0.8, 1.0):
        assert abs(MP.linear_to_perceptual(f(v)) - v) < 1e-9


def test_sad_the_volume_curve_clamps():
    assert MP.perceptual_to_linear(-1) == 0.0 and MP.perceptual_to_linear(7) == 1.0
    assert MP.linear_to_perceptual(-1) == 0.0 and MP.linear_to_perceptual(7) == 1.0


def test_happy_volume_slider_mute_and_keys(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 1)
    try:
        assert panel.volume.value() == 80
        assert abs(engine.volume - 0.8 ** 3) < 1e-6
        panel.mute_button.click()
        assert panel.muted and engine.volume == 0.0 and panel.volume.value() == 80
        panel.mute_button.click()
        assert not panel.muted and abs(engine.volume - 0.512) < 1e-6
        panel.volume.setValue(50)
        assert abs(engine.volume - 0.125) < 1e-6
        panel.volume.setValue(0)
        assert engine.volume == 0.0
    finally:
        panel.close()


def test_edge_the_mouse_wheel_on_the_volume_slider(tmp_path):
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    try:
        panel.resize(600, 500)
        panel.show()
        slider = panel.volume
        slider.setValue(50)
        centre = QPointF(slider.width() / 2, slider.height() / 2)
        event = QWheelEvent(centre, QPointF(slider.mapToGlobal(centre.toPoint())), QPoint(0, 0),
                            QPoint(0, 120), Qt.MouseButton.NoButton,
                            Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)
        QApplication.sendEvent(slider, event)
        assert slider.value() > 50
    finally:
        panel.close()


# -- 6. keyboard (only while the panel has the focus) --------------------------------------


def key(widget, k, mods=Qt.KeyboardModifier.NoModifier):
    QTest.keyClick(widget, k, mods)
    APP.processEvents()


def test_happy_keys_play_pause_seek_and_step(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    try:
        panel.show()
        lst = panel.playlist
        lst.setCurrentRow(1)
        key(lst, Qt.Key.Key_Return)
        assert names(engine) == ["t1.wav"] and engine.state == "playing"
        key(lst, Qt.Key.Key_Space)
        assert engine.state == "paused"
        key(lst, Qt.Key.Key_Space)
        assert engine.state == "playing"
        engine.position = 10_000
        key(lst, Qt.Key.Key_Right)
        assert engine.seeks[-1] == 15_000
        key(lst, Qt.Key.Key_Left, Qt.KeyboardModifier.ShiftModifier)
        assert engine.seeks[-1] == 0  # 15 s - 30 s: the start
        engine.position = 15_000
        key(lst, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
        assert engine.seeks[-1] == 45_000
        key(lst, Qt.Key.Key_Right, Qt.KeyboardModifier.ControlModifier)
        assert names(engine)[-1] == "t2.wav"
        engine.position = 0
        key(lst, Qt.Key.Key_Left, Qt.KeyboardModifier.ControlModifier)
        assert names(engine)[-1] == "t1.wav"
    finally:
        panel.close()


def test_happy_keys_volume_mute_and_delete(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    try:
        panel.show()
        lst = panel.playlist
        key(lst, Qt.Key.Key_Plus)
        assert panel.volume.value() == 85
        key(lst, Qt.Key.Key_Minus)
        key(lst, Qt.Key.Key_Minus)
        assert panel.volume.value() == 75
        key(lst, Qt.Key.Key_M)
        assert panel.muted and engine.volume == 0.0
        key(lst, Qt.Key.Key_M)
        assert not panel.muted
        lst.setCurrentRow(0)
        lst.item(0).setSelected(True)
        lst.item(2).setSelected(True)
        key(lst, Qt.Key.Key_Delete)
        assert [lst.item(i).text() for i in range(lst.count())] == ["t1.wav"]
    finally:
        panel.close()


def test_sad_keys_do_nothing_when_the_focus_is_elsewhere(tmp_path):
    from PyQt6.QtWidgets import QLineEdit

    panel, engine, _paths = fake_panel(tmp_path, 2)
    other = QLineEdit()
    try:
        panel.show()
        other.show()
        for k in (Qt.Key.Key_Space, Qt.Key.Key_Delete, Qt.Key.Key_Return, Qt.Key.Key_M):
            key(other, k)
        assert engine.loads == [] and panel.playlist.count() == 2 and not panel.muted
    finally:
        other.close()
        panel.close()


def test_edge_an_equalizer_slider_keeps_its_own_arrow_keys(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 1)
    try:
        panel.show()
        panel.play_selected()
        engine.position = 10_000
        band = panel.sliders[0]
        key(band, Qt.Key.Key_Up)
        assert band.value() == 1 and engine.seeks == []
        key(panel.volume, Qt.Key.Key_Right)
        assert panel.volume.value() == 81 and engine.seeks == []
    finally:
        panel.close()


def test_edge_shift_right_past_the_end_goes_to_the_next_track(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 2)
    try:
        panel.show()
        panel.play_selected()
        engine.position = engine.duration - 10_000
        key(panel.playlist, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)
        assert names(engine) == ["t0.wav", "t1.wav"]
    finally:
        panel.close()


# -- 7. the current track and errors ---------------------------------------------------------


def test_happy_the_playing_track_is_highlighted_and_named(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 3)
    titles = []
    panel.track_changed.connect(titles.append)
    try:
        panel.playlist.setCurrentRow(1)
        panel.play_selected()
        assert panel.current_row() == 1
        assert panel.playlist.item(1).font().bold()
        assert not panel.playlist.item(0).font().bold()
        assert titles[-1] == "t1.wav"
        assert "t1.wav" in panel.now_playing.toolTip()
        panel.playlist.setCurrentRow(0)  # selecting is not playing
        assert panel.current_row() == 1
        engine.end()
        assert panel.current_row() == 2 and panel.playlist.item(2).font().bold()
        assert not panel.playlist.item(1).font().bold()
    finally:
        panel.close()


def test_sad_an_unplayable_track_is_skipped_with_a_note(tmp_path):
    panel, engine, paths = fake_panel(tmp_path, 3)
    try:
        engine.broken = {paths[1]}
        panel.play_selected()
        engine.end()
        assert wait(lambda: names(engine)[-1] == "t2.wav", 3)
        assert engine.state == "playing"
        assert "t1.wav" in panel.note.text()
        assert "broken" in panel.playlist.item(1).toolTip()
    finally:
        panel.close()


def test_edge_when_nothing_is_playable_it_stops_instead_of_looping(tmp_path):
    panel, engine, paths = fake_panel(tmp_path, 3)
    try:
        engine.broken = set(paths)
        panel.set_repeat("all")
        panel.play_selected()
        pump(0.3)
        assert len(engine.loads) == 3
        assert engine.state == "stopped" and panel.note.text()
    finally:
        panel.close()


def test_edge_removing_the_playing_track_keeps_it_playing_and_next_follows_on(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 4)
    try:
        panel.playlist.setCurrentRow(1)
        panel.play_selected()
        panel.playlist.clearSelection()
        panel.playlist.item(1).setSelected(True)
        panel._remove_selected()
        assert engine.state == "playing" and panel.current_row() == -1
        engine.end()
        assert names(engine)[-1] == "t2.wav"
    finally:
        panel.close()


def test_e2e_a_broken_real_file_is_skipped(tmp_path):
    broken = tmp_path / "broken.mp3"
    broken.write_bytes(b"not audio at all" * 100)
    good = ramp_wav(tmp_path / "good.wav", 0.5)
    sink = MP.MemorySink()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink))
    try:
        panel.add_files([str(broken), str(good)])
        panel.play_selected()
        assert wait(lambda: panel.engine.path == str(good) and panel.engine.finished, 20)
        assert "broken.mp3" in panel.note.text()
    finally:
        panel.close()


# -- 2. drag & drop ----------------------------------------------------------------------------


def drop_on(widget, mime):
    """A drop from outside (no drag source) at the widget's centre."""
    from PyQt6.QtGui import QDragEnterEvent

    pos = QPointF(widget.width() / 2, widget.height() / 2)
    actions = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
    enter = QDragEnterEvent(pos.toPoint(), actions, mime, Qt.MouseButton.LeftButton,
                            Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(widget.viewport(), enter)
    if not enter.isAccepted():
        return False
    drop = QDropEvent(pos, actions, mime, Qt.MouseButton.LeftButton,
                      Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(widget.viewport(), drop)
    return drop.isAccepted()


def url_mime(*paths):
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(p)) for p in paths])
    return mime


def touch(path, data=b"RIFF"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def rows(panel):
    return [panel.playlist.item(i).text() for i in range(panel.playlist.count())]


def test_happy_desktop_files_dropped_on_the_playlist(tmp_path):
    a, b = touch(tmp_path / "a.mp3"), touch(tmp_path / "b.flac")
    notes = touch(tmp_path / "notes.txt", b"text")
    panel = MP.PlayerPanel(engine=FakeEngine())
    try:
        panel.resize(500, 600)
        panel.show()
        assert drop_on(panel.playlist, url_mime(a, notes, b))
        assert wait(lambda: panel.playlist.count() == 2, 5)
        assert rows(panel) == ["a.mp3", "b.flac"]
        assert "1" in panel.note.text() and "not audio" in panel.note.text()
    finally:
        panel.close()


def test_happy_a_dropped_folder_adds_its_audio_sorted_and_bounded(tmp_path, monkeypatch):
    music = tmp_path / "music"
    for name in ("b/02.ogg", "b/01.mp3", "a.wav", "cover.jpg", "c/d/e/f/g/h/deep.mp3"):
        touch(music / name)
    files, skipped, truncated = MP.collect_local([str(music)])
    assert [os.path.relpath(p, music) for p, _t in files] == ["a.wav", "b/01.mp3", "b/02.ogg"]
    # cover.jpg beside tracks is no note; deep.mp3 lies below MAX_DROP_DEPTH: one lost entry
    assert skipped == 1 and not truncated
    monkeypatch.setattr(MP, "MAX_DROP_FILES", 2)
    files, _skipped, truncated = MP.collect_local([str(music)])
    assert len(files) == 2 and truncated


def test_edge_a_folder_that_links_to_itself_ends(tmp_path):
    music = tmp_path / "music"
    touch(music / "x.mp3")
    os.symlink(music, music / "loop")
    files, _skipped, _truncated = MP.collect_local([str(music)])
    assert [Path(p).name for p, _t in files] == ["x.mp3"]


def test_sad_a_text_drag_is_refused_and_only_non_audio_adds_nothing(tmp_path):
    panel = MP.PlayerPanel(engine=FakeEngine())
    try:
        panel.resize(500, 600)
        panel.show()
        text = QMimeData()
        text.setText("/music/a.mp3")
        assert not drop_on(panel.playlist, text)
        assert drop_on(panel.playlist, url_mime(touch(tmp_path / "x.pdf", b"%PDF")))
        assert wait(lambda: panel.note.text() != "", 5)
        assert panel.playlist.count() == 0
    finally:
        panel.close()


def test_edge_special_files_are_not_tracks(tmp_path):
    os.mkfifo(tmp_path / "pipe.mp3")
    os.symlink("/dev/zero", tmp_path / "zero.wav")
    files, skipped, _t = MP.collect_local([str(tmp_path / "pipe.mp3"), str(tmp_path / "zero.wav")])
    assert files == [] and skipped == 2


def test_happy_a_dropped_playlist_file_adds_its_tracks(tmp_path):
    touch(tmp_path / "m" / "one.mp3")
    touch(tmp_path / "m" / "two.ogg")
    (tmp_path / "list.m3u8").write_text("#EXTM3U\n#EXTINF:61,The One\nm/one.mp3\nm/two.ogg\n",
                                        encoding="utf-8")
    files, skipped, _t = MP.collect_local([str(tmp_path / "list.m3u8")])
    assert [(Path(p).name, t) for p, t in files] == [("one.mp3", "The One"), ("two.ogg", "")]
    assert skipped == 0


def _ram_with_music():
    from core.ram_fs import RamFsSession

    ram = RamFsSession("music-ram")
    ram.mkdir("/music")
    ram.mkdir("/music/live")
    for path in ("/music/a.wav", "/music/live/b.wav", "/other/a.wav"):
        if ram.parent(path) and not ram.exists(ram.parent(path)):
            ram.mkdir(ram.parent(path))
        with ram.open_write(path) as fh:
            fh.write(b"RIFF" + bytes(64))
    with ram.open_write("/music/readme.txt") as fh:
        fh.write(b"hi")
    return ram


def test_happy_remote_files_and_folders_are_copied_to_a_bounded_temp(tmp_path):
    ram = _ram_with_music()
    files, skipped, truncated, folder = MP.fetch_remote(
        ram, ["/music", "/other/a.wav", "/music/readme.txt"], str(tmp_path))
    try:
        assert [t for _p, t in files] == ["a.wav", "b.wav", "a.wav"]
        assert len({p for p, _t in files}) == 3  # same names, no clash
        assert all(Path(p).read_bytes().startswith(b"RIFF") for p, _t in files)
        assert skipped == 1 and not truncated  # the dropped readme; the one in /music is no news
        assert all(p.startswith(folder) for p, _t in files)
    finally:
        import shutil

        shutil.rmtree(folder, ignore_errors=True)


def test_sad_remote_copies_beyond_the_bounds_stop_and_clean_up(tmp_path, monkeypatch):
    ram = _ram_with_music()
    monkeypatch.setattr(MP, "MAX_REMOTE_BYTES", 10)
    with pytest.raises(OSError, match="larger than"):
        MP.fetch_remote(ram, ["/music/a.wav"], str(tmp_path))
    assert list(tmp_path.iterdir()) == []
    monkeypatch.setattr(MP, "MAX_REMOTE_BYTES", 1 << 20)
    monkeypatch.setattr(MP, "MAX_DROP_FILES", 1)
    files, _s, truncated, folder = MP.fetch_remote(ram, ["/music"], str(tmp_path))
    assert len(files) == 1 and truncated
    import shutil

    shutil.rmtree(folder, ignore_errors=True)


def test_happy_a_remote_drop_goes_through_the_background_and_temp(tmp_path, monkeypatch):
    import tempfile

    from ui.extension_host import ExtensionContext

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    ram = _ram_with_music()
    panel = MP.PlayerPanel(engine=FakeEngine())
    jobs = []
    panel.run_in_background = lambda work, done, error: jobs.append((work, done, error))
    panel.drop_resolver = lambda mime: ExtensionContext(backend=ram, folder="/music",
                                                        paths=("/music",))
    try:
        panel.resize(500, 600)
        panel.show()
        mime = QMimeData()
        mime.setData(MP.TRANSFER_MIME_TYPE, b"{}")
        assert drop_on(panel.playlist, mime)
        assert panel.playlist.count() == 0 and len(jobs) == 1  # nothing on the GUI thread
        while jobs:  # the listing, then one copy per track
            work, done, _error = jobs.pop(0)
            done(work())
        assert rows(panel) == ["a.wav", "b.wav"]
        assert all(MP._is_temp_copy(panel.playlist.item(i).data(Qt.ItemDataRole.UserRole))
                   for i in range(2))
    finally:
        panel.close()
        MP.deactivate(None)


def test_edge_reordering_keeps_the_playing_track(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 4)
    try:
        panel.playlist.setCurrentRow(1)
        panel.play_selected()
        model = panel.playlist.model()
        from PyQt6.QtCore import QModelIndex

        assert model.moveRow(QModelIndex(), 1, QModelIndex(), 4)  # t1 to the end
        assert rows(panel) == ["t0.wav", "t2.wav", "t3.wav", "t1.wav"]
        assert panel.current_row() == 3 and panel.playlist.item(3).font().bold()
        engine.end()
        assert engine.state == "stopped" and len(engine.loads) == 1  # it is last now
        panel.set_repeat("all")
        panel.next_button.click()
        assert names(engine)[-1] == "t0.wav"
    finally:
        panel.close()


def test_e2e_real_drags_under_xvfb(tmp_path):
    """Real drags do not run on the offscreen platform; under Xvfb they do:
    rows reorder by dragging, files dragged out of a file pane land in the
    playlist."""
    import shutil
    import subprocess

    if shutil.which("Xvfb") is None:
        pytest.skip("Xvfb not installed")
    script = Path(__file__).resolve().parent / "media_player_drag_check.py"
    # Xvfb picks a free display itself and names it on -displayfd: "xvfb-run
    # -a" chose its number before starting, and parallel runs then raced
    # for the same one (6 at once: 3 failed with "could not connect").
    read_end, write_end = os.pipe()
    server = subprocess.Popen(
        ["Xvfb", "-displayfd", str(write_end), "-screen", "0", "1280x1024x24",
         "-nolisten", "tcp", "-noreset"],
        pass_fds=(write_end,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    os.close(write_end)
    try:
        number = os.read(read_end, 32).decode().strip()
        os.close(read_end)
        assert number.isdigit(), "Xvfb did not report its display"
        env = dict(os.environ, QT_QPA_PLATFORM="xcb", DISPLAY=f":{number}")
        proc = subprocess.run([sys.executable, str(script), str(tmp_path)],
                              env=env, capture_output=True, text=True, timeout=120)
    finally:
        server.terminate()
        server.wait(10)
    assert proc.returncode == 0 and "REORDER OK" in proc.stdout and "PANE DROP OK" in proc.stdout, (
        proc.stdout[-2000:], proc.stderr[-2000:])


# -- 3. playlists ---------------------------------------------------------------------------


def test_happy_m3u_with_titles_lengths_and_relative_paths(tmp_path):
    touch(tmp_path / "music" / "Ünïcode 日本.mp3")
    touch(tmp_path / "abs.flac")
    touch(tmp_path / "list" / "here.ogg")
    data = (
        "﻿#EXTM3U\r\n#EXTINF:183,Artist - Song\r\n../music/Ünïcode 日本.mp3\r\n"
        f"#EXTINF:-1,\r\n{tmp_path / 'abs.flac'}\r\n"
        f"{QUrl.fromLocalFile(str(tmp_path / 'list' / 'here.ogg')).toString()}\r\n"
    ).encode("utf-8")
    entries, skipped = MP.parse_m3u(data, str(tmp_path / "list"))
    assert skipped == 0
    assert [(Path(e.path).name, e.title, e.duration) for e in entries] == [
        ("Ünïcode 日本.mp3", "Artist - Song", 183), ("abs.flac", "", 0), ("here.ogg", "", 0)]
    assert entries[0].path == str(tmp_path / "music" / "Ünïcode 日本.mp3")


def test_sad_hostile_playlists_are_refused_or_skipped(tmp_path):
    with pytest.raises(MP.PlaylistError, match="NUL"):
        MP.parse_m3u(b"#EXTM3U\na.mp3\x00\n", str(tmp_path))
    big = tmp_path / "big.m3u"
    big.write_bytes(b"#" * (MP.MAX_PLAYLIST_BYTES + 1))
    with pytest.raises(MP.PlaylistError, match="larger"):
        MP.read_playlist(str(big))
    with pytest.raises(MP.PlaylistError):
        MP.read_playlist(str(tmp_path / "missing.m3u"))
    os.mkfifo(tmp_path / "fifo.m3u")
    with pytest.raises(MP.PlaylistError):
        MP.read_playlist(str(tmp_path / "fifo.m3u"))  # never blocks on a pipe
    os.symlink("/dev/zero", tmp_path / "zero.mp3")
    lines = ["http://example.com/stream.mp3", "missing.mp3", "notes.txt", "zero.mp3",
             "x" * 5000 + ".mp3", "bad\x07bell.mp3", "/etc/passwd"]
    touch(tmp_path / "notes.txt", b"t")
    entries, skipped = MP.parse_m3u("\n".join(lines).encode(), str(tmp_path))
    assert entries == [] and skipped == len(lines)


def test_edge_playlist_bounds_legacy_encoding_and_backslashes(tmp_path, monkeypatch):
    touch(tmp_path / "Mus" / "café.mp3")
    latin = "#EXTM3U\nMus\\café.mp3\n".encode("latin-1")
    entries, skipped = MP.parse_m3u(latin, str(tmp_path))
    assert [Path(e.path).name for e in entries] == ["café.mp3"] and skipped == 0
    for i in range(5):
        touch(tmp_path / f"{i}.mp3")
    monkeypatch.setattr(MP, "MAX_PLAYLIST_ENTRIES", 3)
    entries, skipped = MP.parse_m3u("\n".join(f"{i}.mp3" for i in range(5)).encode(),
                                    str(tmp_path))
    assert len(entries) == 3 and skipped == 2
    assert MP.parse_m3u(b"", str(tmp_path)) == ([], 0)


def test_happy_write_playlist_round_trips(tmp_path):
    inside = touch(tmp_path / "pl" / "sub" / "ä 1.mp3")
    outside = touch(tmp_path / "elsewhere" / "b.ogg")
    entries = [MP.PlaylistEntry(str(inside), "Title, with comma", 61),
               MP.PlaylistEntry(str(outside), "", 0)]
    target = tmp_path / "pl" / "list.m3u8"
    written, skipped = MP.write_playlist(str(target), entries)
    assert (written, skipped) == (2, 0)
    text = target.read_text(encoding="utf-8")
    assert text.startswith("#EXTM3U\n")
    assert "#EXTINF:61,Title, with comma\nsub/ä 1.mp3\n" in text
    assert f"\n{outside}\n" in text
    back, skipped = MP.read_playlist(str(target))
    assert back == entries and skipped == 0


def test_sad_write_playlist_leaves_out_temporary_remote_copies(tmp_path, monkeypatch):
    folder = tmp_path / "axross-media-x"
    copy = touch(folder / "0" / "r.mp3")
    monkeypatch.setattr(MP, "_TEMP_FOLDERS", [str(folder)])
    keep = touch(tmp_path / "k.mp3")
    written, skipped = MP.write_playlist(str(tmp_path / "l.m3u"),
                                         [MP.PlaylistEntry(str(copy)),
                                          MP.PlaylistEntry(str(keep))])
    assert (written, skipped) == (1, 1)
    assert "r.mp3" not in (tmp_path / "l.m3u").read_text(encoding="utf-8")


def test_happy_panel_saves_and_loads_a_playlist(tmp_path):
    panel, _engine, paths = fake_panel(tmp_path, 3)
    try:
        target = tmp_path / "out.m3u8"
        panel.save_playlist(str(target))
        panel.clear_playlist()
        Path(paths[1]).unlink()
        panel.load_playlist(str(target))
        assert rows(panel) == ["t0.wav", "t2.wav"]
        assert "1" in panel.note.text()  # one entry is gone
    finally:
        panel.close()


def test_sad_panel_load_of_a_broken_playlist_keeps_the_list(tmp_path):
    panel, _engine, _paths = fake_panel(tmp_path, 2)
    try:
        bad = tmp_path / "bad.m3u"
        bad.write_bytes(b"\x00\x01")
        panel.load_playlist(str(bad))
        assert panel.playlist.count() == 2 and "NUL" in panel.note.text()
    finally:
        panel.close()


# -- 3. the last playlist comes back -----------------------------------------------------------


def test_happy_the_last_playlist_position_and_settings_come_back(tmp_path):
    state = tmp_path / "cfg" / "media_player.json"
    panel, engine, paths = fake_panel(tmp_path, 3, state_path=str(state))
    panel.playlist.setCurrentRow(1)
    panel.play_selected()
    engine.position = 83_000
    panel.volume.setValue(40)
    panel.set_muted(True)
    panel.set_shuffle(True)
    panel.set_repeat("all")
    panel.shutdown()
    assert state.stat().st_mode & 0o777 == 0o600
    again_engine = FakeEngine()
    again = MP.PlayerPanel(engine=again_engine, state_path=str(state))
    try:
        assert rows(again) == ["t0.wav", "t1.wav", "t2.wav"]
        assert again.current_row() == 1 and again.playlist.item(1).font().bold()
        assert again_engine.path == paths[1] and again_engine.state == "stopped"
        assert again_engine.position_ms() == 83_000
        assert again.volume.value() == 40 and again.muted and again.shuffle
        assert again.repeat == "all" and again_engine.volume == 0.0
        again.toggle_play()  # ▶ goes on where it was
        assert again_engine.state == "playing" and again_engine.loads == [paths[1]]
    finally:
        again.close()


def test_sad_a_broken_state_file_is_ignored_and_kept_aside(tmp_path):
    state = tmp_path / "media_player.json"
    state.write_text("{not json", encoding="utf-8")
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state))
    try:
        assert panel.playlist.count() == 0 and panel.volume.value() == 80
        panel.add_files([str(touch(tmp_path / "a.mp3"))])
        panel.save_state()
        assert len(list(tmp_path.glob("media_player.json.unreadable-*"))) == 1
        assert "a.mp3" in state.read_text(encoding="utf-8")
    finally:
        panel.close()


def test_edge_a_state_with_gone_tracks_and_odd_values(tmp_path):
    import json

    keep = touch(tmp_path / "keep.mp3")
    state = tmp_path / "media_player.json"
    state.write_text(json.dumps({
        "version": 1, "volume": 900, "muted": "yes", "repeat": "forever", "shuffle": 1,
        "tracks": [{"path": str(tmp_path / "gone.mp3")}, {"path": str(keep), "title": 5},
                   "junk", {"path": "/etc/passwd"}],
        "current": 7, "position_ms": -5}), encoding="utf-8")
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state))
    try:
        assert rows(panel) == ["keep.mp3"]
        assert panel.volume.value() == 100 and not panel.muted and panel.repeat == "off"
        assert panel.current_row() == -1
    finally:
        panel.close()
    state.write_bytes(b" " * (MP.MAX_STATE_BYTES + 1))
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state))
    try:
        assert panel.playlist.count() == 0
    finally:
        panel.close()


def test_e2e_a_restored_position_plays_from_there(tmp_path):
    import json

    seconds = 6.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    state = tmp_path / "media_player.json"
    state.write_text(json.dumps({"version": 1, "tracks": [{"path": str(path)}], "current": 0,
                                 "position_ms": 2500}), encoding="utf-8")
    sink = MP.MemorySink()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink),
                           state_path=str(state))
    try:
        panel._refresh_time()
        assert panel.time_label.text().startswith("0:02")
        panel.play_button.click()
        assert wait(lambda: panel.engine.finished, 20)
        assert abs(ramp_seconds(float(sink.samples()[0, 0]), seconds) - 2.5) < 0.01
    finally:
        panel.close()


# -- the extension in the window ------------------------------------------------------------------


def test_e2e_extension_dock_takes_drops_names_the_track_and_saves(tmp_path, monkeypatch):
    from unittest import mock

    from core.ram_fs import RamFsSession
    from ui.file_pane import TRANSFER_MIME_TYPE
    from ui.main_window import MainWindow

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    info = next(e for e in EX.discover() if e.module_name == "media_player")
    EX.set_enabled(info.ext_id, True)
    music = tmp_path / "music"
    music.mkdir()
    ramp_wav(music / "one.wav", 0.4)
    ramp_wav(music / "two.wav", 0.4)
    touch(music / "notes.txt", b"t")
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.resize(1200, 800)
        win.show()
        host = win.extension_host
        assert wait(lambda: host.module(info.ext_id) is not None, 10)
        (dock,) = host.docks(info.ext_id)
        dock.show()
        panel = dock.widget()
        panel.engine.sink_factory = lambda fmt: MP.MemorySink()
        pane = win._active_pane
        pane.navigate(str(music))
        mime = QMimeData()
        mime.setData(TRANSFER_MIME_TYPE, pane._encode_transfer_payload(
            [str(music / "one.wav"), str(music / "notes.txt")]))
        assert drop_on(panel.playlist, mime)
        assert wait(lambda: panel.playlist.count() == 1, 10)
        ram = RamFsSession("drop-ram")
        with ram.open_write("/two.wav") as fh:
            fh.write((music / "two.wav").read_bytes())
        with mock.patch.object(type(pane), "backend", new_callable=mock.PropertyMock,
                               return_value=ram):
            mime = QMimeData()
            mime.setData(TRANSFER_MIME_TYPE, pane._encode_transfer_payload(["/two.wav"]))
            assert drop_on(panel.playlist, mime)
        assert wait(lambda: panel.playlist.count() == 2, 10)
        panel.playlist.setCurrentRow(0)
        panel.play_selected()
        bar = dock.titleBarWidget()
        assert wait(lambda: "one" in bar._title_label.text(), 5)
        # Delete in the focused playlist removes a row - no file pane delete.
        panel.playlist.setFocus()
        panel.playlist.setCurrentRow(1)
        panel.playlist.item(1).setSelected(True)
        QTest.keyClick(panel.playlist, Qt.Key.Key_Delete)
        assert panel.playlist.count() == 1 and (music / "one.wav").exists()
        EX.set_enabled(info.ext_id, False)
        host.set_enabled(info.ext_id, False)
        state = Path(tmp_path / "home" / ".config" / "axross" / "media_player.json")
        assert wait(lambda: state.exists(), 5)
        assert "one.wav" in state.read_text(encoding="utf-8")
    finally:
        win.close()
        win.deleteLater()


# -- review round: no filesystem waits on the GUI thread, nothing lost ------------------------


def test_edge_restoring_checks_the_tracks_off_the_gui_thread_and_saves_nothing_meanwhile(
        tmp_path):
    import json

    track = touch(tmp_path / "a.mp3")
    state = tmp_path / "media_player.json"
    saved = {"version": 1, "tracks": [{"path": str(track)}], "current": 0, "position_ms": 0}
    state.write_text(json.dumps(saved), encoding="utf-8")
    jobs = []
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state),
                           run_in_background=lambda w, d, e: jobs.append((w, d, e)))
    try:
        assert len(jobs) == 1 and panel.playlist.count() == 0  # nothing stat()ed yet
        panel.save_state()  # e.g. the window closes before the check is back
        assert json.loads(state.read_text(encoding="utf-8"))["tracks"] == saved["tracks"]
        work, done, _failed = jobs[0]
        done(work())
        assert rows(panel) == ["a.mp3"] and panel.current_row() == 0
    finally:
        panel.close()


def test_sad_a_state_file_that_is_a_pipe_is_not_opened(tmp_path):
    os.mkfifo(tmp_path / "media_player.json")
    state, usable = MP.read_state(tmp_path / "media_player.json")  # returns, no block
    assert state == {} and not usable


def test_edge_a_remote_drop_without_tracks_makes_no_temp_folder(tmp_path):
    ram = _ram_with_music()
    files, skipped, _t, folder = MP.fetch_remote(ram, ["/music/readme.txt"], str(tmp_path))
    assert files == [] and skipped == 1 and folder == ""
    assert list(tmp_path.iterdir()) == []


# -- the fallback engine (no numpy) in the panel ------------------------------------------------


def test_e2e_panel_with_the_qmediaplayer_engine_seeks_skips_and_moves_on(tmp_path):
    broken = touch(tmp_path / "broken.mp3", b"not audio at all" * 100)
    first = ramp_wav(tmp_path / "first.wav", 3.0)
    second = ramp_wav(tmp_path / "second.wav", 3.0)
    panel = MP.PlayerPanel(engine=MP.SimpleEngine())
    try:
        panel.resize(600, 600)
        panel.show()
        panel.add_files([str(first), str(broken), str(second)])
        panel.play_selected()
        assert wait(lambda: panel.engine.duration_ms() > 0 and panel.engine.position_ms() > 0, 10)
        panel._refresh_time()
        assert panel.time_label.text().endswith("/ 0:03")
        slider = panel.seek_slider
        slider.setSliderDown(True)
        slider.setSliderPosition(2000)
        slider.setSliderDown(False)
        assert wait(lambda: panel.engine.position_ms() >= 2000, 5)
        key(panel.playlist, Qt.Key.Key_Right, Qt.KeyboardModifier.ShiftModifier)  # past the end
        # first ends -> broken fails and is skipped with a note -> second plays
        assert wait(lambda: panel.engine.path == str(second) and panel.engine.state == "playing",
                    15)
        assert "broken.mp3" in panel.note.text()
    finally:
        panel.close()


class VolumeSink(MP.MemorySink):
    def __init__(self):
        super().__init__()
        self.volumes = []

    def set_volume(self, volume):
        self.volumes.append(volume)


def test_e2e_the_volume_reaches_the_sound_card(tmp_path):
    path = ramp_wav(tmp_path / "ramp.wav", 4.0)
    sink = VolumeSink()
    sink.bytes_free = lambda: 0  # holds the track: it keeps playing
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink))
    try:
        panel.add_files([str(path)])
        panel.play_selected()
        panel.volume.setValue(50)
        assert abs(sink.volumes[-1] - 0.125) < 1e-9
        panel.mute_button.click()
        assert sink.volumes[-1] == 0.0
        panel.mute_button.click()
        assert abs(sink.volumes[-1] - 0.125) < 1e-9
    finally:
        panel.close()


# -- the control buttons need no emoji font --------------------------------------------
#
# Reported: shuffle, repeat and mute showed an empty box ("tofu") on a host
# without an emoji font - their labels were 🔀 🔁 🔊, which no font of a
# plain Linux install has (fc-list ':charset=1f500' finds none). The
# buttons now draw their own icons and carry no text.

CONTROLS = ("prev_button", "play_button", "stop_button", "next_button",
            "shuffle_button", "repeat_button", "mute_button")


def test_happy_every_control_button_shows_an_icon_and_no_text(tmp_path):
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    try:
        for name in CONTROLS:
            button = getattr(panel, name)
            assert button.text() == "", (name, button.text())
            assert not button.icon().isNull(), name
            assert button.toolTip(), name
    finally:
        panel.close()


def test_happy_the_icons_follow_play_repeat_and_mute(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path, 1)
    try:
        assert panel.play_button.property("control") == "play"
        panel.play_selected()
        panel._refresh()
        assert engine.state == "playing"
        assert panel.play_button.property("control") == "pause"
        seen = []
        for _ in range(3):
            panel.repeat_button.click()
            seen.append(panel.repeat_button.property("control"))
        assert seen == ["repeat", "repeat-one", "repeat"]
        assert panel.mute_button.property("control") == "volume"
        panel.mute_button.click()
        assert panel.mute_button.property("control") == "volume-x"
    finally:
        panel.close()


def test_sad_every_control_icon_is_valid_svg_and_renders_pixels():
    from PyQt6.QtCore import QByteArray
    from PyQt6.QtSvg import QSvgRenderer

    assert set(MP.CONTROL_ICONS) == {"previous", "play", "pause", "stop", "next", "shuffle",
                                     "repeat", "repeat-one", "volume", "volume-x"}
    for name in MP.CONTROL_ICONS:
        assert QSvgRenderer(QByteArray(MP.control_svg(name, "#123456").encode())).isValid(), name
        image = MP.control_icon(name, "#ff0000").pixmap(32, 32).toImage()
        painted = sum(1 for x in range(32) for y in range(32) if image.pixelColor(x, y).alpha() > 0)
        assert painted > 20, name
    with pytest.raises(KeyError):
        MP.control_svg("no-such-icon", "#000000")


def test_sad_no_button_label_needs_a_glyph_outside_the_basic_planes():
    """Nothing the player puts on a button needs an emoji font: no label
    in the source uses a character beyond U+FFFF."""
    source = (EX.bundled_dir() / "media_player.py").read_text(encoding="utf-8")
    import re

    for match in re.finditer(r"QPushButton\((['\"])(.*?)\1", source):
        assert all(ord(c) <= 0xFFFF for c in match.group(2)), match.group(0)
    for match in re.finditer(r"setText\((.*?)\)\n", source):
        assert all(ord(c) <= 0xFFFF for c in match.group(1)), match.group(0)


def test_edge_a_theme_switch_recolours_the_icons(tmp_path, monkeypatch):
    """The real path: the main window's theme sets the application palette
    (and a style sheet); the icons follow its button text colour."""
    from PyQt6.QtGui import QPalette

    from ui.main_window import MainWindow

    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    win = MainWindow()
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    old_palette = APP.palette()
    try:
        win._reconnect_timer.stop()
        seen = []
        for theme in ("modern-light", "modern-dark"):
            win._apply_theme(theme)
            APP.processEvents()
            want = panel.palette().color(QPalette.ColorRole.ButtonText).name()
            assert panel.stop_button.property("control-colour") == want, theme
            seen.append(want)
        assert seen[0] != seen[1]
    finally:
        panel.close()
        win.close()
        win.deleteLater()
        APP.setPalette(old_palette)
        APP.setStyleSheet("")
