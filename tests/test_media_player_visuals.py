"""The Media Player's visualizations and the collapsible equalizer.

Operator: *„beim media player bitte noch andere sound animationen einbauen
die man dann auch wechseln kann z.b. durch klick auf die animation.
eawualizer im media player einklappen/ausklappen koennen"*.

Decided: besides the spectrum bars, a mirrored spectrum, a radial
spectrum, an oscilloscope and a stereo VU meter - all from the samples the
numpy engine already keeps (the last FRAME frames written to the sound
card). A left click on the visualization goes to the next one; the choice
and whether the equalizer is open are kept in the player's state file.
Without numpy (SimpleEngine) there are no samples: every visualization
shows its empty face and nothing raises.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QEventLoop, QObject, QPoint, Qt, QTimer, pyqtSignal  # noqa: E402
from PyQt6.QtTest import QSignalSpy, QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
AUDIO = Path(__file__).resolve().parent / "fixtures" / "audio"
RATE = 44100


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_visuals_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()
BACKGROUND = "#101418"


def sine(freq=440.0, frames=2048, amp=0.5, right=None):
    t = np.arange(frames) / RATE
    left = (amp * np.sin(2 * np.pi * freq * t)).astype(np.float32)
    other = left if right is None else np.full(frames, right, np.float32)
    return np.stack([left, other], axis=1)


def wait(cond, timeout: float = 15.0) -> bool:
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


class SampleEngine(QObject):
    """The engine interface with fixed samples: what EqEngine hands the
    visualizer, without decoding. ``samples=None`` is SimpleEngine's
    answer (no numpy, nothing to show)."""

    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, samples=None) -> None:
        super().__init__()
        self.state, self.error, self.finished, self.loaded, self.path = (
            "stopped", "", False, False, "")
        self.samples = samples
        self.gains_db = [0.0] * 10
        self.bars_asked = 0
        self.samples_asked = 0

    def load(self, path):
        self.path, self.loaded = path, True

    def play(self):
        self.state = "playing"
        self.changed.emit()

    def pause(self):
        self.state = "paused"
        self.changed.emit()

    def stop(self):
        self.state = "stopped"
        self.changed.emit()

    def seek(self, ms):
        pass

    def set_volume(self, v):
        pass

    def set_gains(self, g):
        self.gains_db = list(g)

    def position_ms(self):
        return 0

    def duration_ms(self):
        return 0

    def current_bars(self, n=32):
        self.bars_asked += 1
        if self.samples is None:
            return None
        return MP.spectrum_bars(self.samples, RATE, n)

    def current_samples(self):
        self.samples_asked += 1
        return self.samples


def painted(widget) -> set[str]:
    """The colours of a grab of *widget*, sampled on a grid."""
    img = widget.grab().toImage()
    return {img.pixelColor(x, y).name()
            for x in range(0, img.width(), 3) for y in range(0, img.height(), 3)}


def visualizer(samples=None, size=(320, 120)):
    vis = MP.Visualizer(SampleEngine(samples))
    vis.resize(*size)
    vis.show()
    return vis


# -- the data behind the new faces -----------------------------------------------------


class TestWaveform:
    def test_happy_a_sine_spans_its_amplitude(self):
        points = MP.waveform(sine(amp=0.5), 256)
        assert len(points) == 256
        assert 0.45 < float(points.max()) <= 0.5 and -0.5 <= float(points.min()) < -0.45

    def test_sad_fewer_than_two_points_is_refused(self):
        with pytest.raises(ValueError):
            MP.waveform(sine(), 1)

    def test_edge_empty_mono_and_loud_input(self):
        assert MP.waveform(np.zeros((0, 2), np.float32), 8).tolist() == [0.0] * 8
        mono = MP.waveform(sine()[:, 0], 64)
        assert len(mono) == 64 and float(np.abs(mono).max()) > 0.4
        loud = MP.waveform(sine(amp=3.0), 64)
        assert float(loud.max()) <= 1.0 and float(loud.min()) >= -1.0
        few = MP.waveform(sine(frames=10), 100)  # more points than samples
        assert len(few) == 100


class TestVuLevels:
    def test_happy_left_loud_right_silent(self):
        rms_l, rms_r, peak_l, peak_r = MP.vu_levels(sine(amp=0.5, right=0.0))
        # 0.5 amplitude: RMS 0.354 = -9 dBFS -> 51/60 on the -60..0 scale
        assert abs(rms_l - 51 / 60) < 0.02
        assert peak_l >= rms_l and abs(peak_l - (60 - 6.02) / 60) < 0.02
        assert rms_r == 0.0 and peak_r == 0.0

    def test_sad_silence_and_empty_are_all_zero(self):
        assert list(MP.vu_levels(np.zeros((2048, 2), np.float32))) == [0.0] * 4
        assert list(MP.vu_levels(np.zeros((0, 2), np.float32))) == [0.0] * 4

    def test_edge_mono_is_both_channels_and_clipping_stops_at_one(self):
        rms_l, rms_r, peak_l, peak_r = MP.vu_levels(sine(amp=0.5)[:, 0])
        assert rms_l == rms_r and peak_l == peak_r
        assert max(MP.vu_levels(sine(amp=4.0))) == 1.0


# -- the visualizer widget --------------------------------------------------------------


def test_happy_the_modes_and_the_default():
    assert MP.Visualizer.MODES[0] == "spectrum"
    assert {"spectrum", "mirror", "radial", "scope", "vu"} <= set(MP.Visualizer.MODES)
    assert set(MP.VISUALIZER_NAMES) == set(MP.Visualizer.MODES)
    vis = visualizer()
    try:
        assert vis.mode == "spectrum"
    finally:
        vis.close()


def test_e2e_happy_a_click_goes_to_the_next_visualization_and_wraps(tmp_path):
    vis = visualizer(sine())
    try:
        spy = QSignalSpy(vis.mode_changed)
        seen = [vis.mode]
        for _ in MP.Visualizer.MODES:
            QTest.mouseClick(vis, Qt.MouseButton.LeftButton, pos=QPoint(20, 20))
            seen.append(vis.mode)
        assert seen[:-1] == list(MP.Visualizer.MODES)
        assert seen[-1] == MP.Visualizer.MODES[0], "after the last comes the first again"
        assert [args[0] for args in spy] == seen[1:]
        assert MP.VISUALIZER_NAMES[vis.mode] in vis.toolTip()
    finally:
        vis.close()


def test_e2e_happy_every_visualization_draws_the_sound_and_differs():
    vis = visualizer(sine(1000.0, amp=0.8))
    # A seeded star field: of 3000 random ones, 13 put no near star on this
    # grid's sampled pixels (measured) and the starfield failed the check.
    vis.reset_stars(seed=1)
    try:
        faces = {}
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode)
            vis._label_until = 0.0  # the name overlay is not the face
            for _ in range(3):
                vis.tick()
            colours = painted(vis)
            assert len(colours - {BACKGROUND}) > 2, mode
            faces[mode] = vis.grab().toImage()
        modes = list(faces)
        for i, a in enumerate(modes):
            for b in modes[i + 1:]:
                assert faces[a] != faces[b], (a, b)
    finally:
        vis.close()


def test_e2e_happy_the_real_engine_feeds_every_visualization():
    engine = MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink())
    engine.load(str(AUDIO / "sine.wav"))
    engine.play()
    assert wait(lambda: engine.finished)
    samples = engine.current_samples()
    assert samples.shape == (MP.FRAME, 2) and float(np.abs(samples).max()) > 0.1
    vis = MP.Visualizer(engine)
    vis.resize(300, 100)
    vis.show()
    vis.reset_stars(seed=1)  # a random star field can miss the sampled grid
    try:
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode)
            vis._label_until = 0.0
            vis.tick()
            assert len(painted(vis) - {BACKGROUND}) > 2, mode
    finally:
        vis.close()


def test_sad_without_numpy_samples_every_visualization_shows_its_empty_face():
    vis = visualizer(None)
    try:
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode)
            vis.tick()  # current_bars / current_samples answer None
            vis.repaint()
            assert vis.grab().width() == 320
    finally:
        vis.close()


def test_sad_an_engine_without_current_samples_is_fine():
    """SimpleEngine and older engines have only current_bars()."""

    class BarsOnly(SampleEngine):
        current_samples = None

    engine = BarsOnly(sine())
    vis = MP.Visualizer(engine)
    vis.resize(200, 80)
    vis.show()
    try:
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode)
            vis.tick()
            vis.repaint()
    finally:
        vis.close()


def test_sad_an_unknown_mode_is_refused_and_the_right_button_does_nothing():
    vis = visualizer(sine())
    try:
        with pytest.raises(ValueError):
            vis.set_mode("lava-lamp")
        QTest.mouseClick(vis, Qt.MouseButton.RightButton, pos=QPoint(10, 10))
        assert vis.mode == "spectrum"
    finally:
        vis.close()


def test_edge_a_tiny_visualizer_paints_every_face():
    vis = visualizer(sine(), size=(3, 2))
    try:
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode)
            vis.tick()
            vis.repaint()
    finally:
        vis.close()


def test_edge_a_face_asks_only_for_the_data_it_shows():
    """Painting runs on a timer on the GUI thread: the oscilloscope and the
    VU meter need no FFT, the spectra no raw samples."""
    engine = SampleEngine(sine())
    vis = MP.Visualizer(engine)
    try:
        vis.set_mode("scope")  # a switch draws the new face at once: one tick
        vis.tick()
        vis.set_mode("vu")
        vis.tick()
        assert engine.bars_asked == 0 and engine.samples_asked == 4
        for mode in ("spectrum", "mirror", "radial"):
            vis.set_mode(mode)
            vis.tick()
        assert engine.bars_asked == 6 and engine.samples_asked == 4
    finally:
        vis.close()


def test_edge_a_switch_while_paused_shows_the_sound_at_once():
    """The timer runs only while playing: the face a click brings draws the
    samples the engine holds right away."""
    vis = visualizer(sine(amp=0.8))
    try:
        assert not vis.timer.isActive()
        vis.set_mode("vu", announce=False)
        assert vis.vu[0] > 0.5
        vis.set_mode("scope", announce=False)
        assert vis.trace is not None and float(np.abs(vis.trace).max()) > 0.5
    finally:
        vis.close()


def test_edge_the_name_shows_briefly_after_a_switch():
    vis = visualizer(sine())
    try:
        vis.next_mode()
        assert vis._label_until > time.monotonic()
        with_name = vis.grab().toImage()
        vis._label_until = 0.0
        assert vis.grab().toImage() != with_name
    finally:
        vis.close()


# -- the panel: the choice is kept, the equalizer folds ---------------------------------


def panel_with_state(tmp_path, engine=None):
    state = tmp_path / "cfg" / "media_player.json"
    panel = MP.PlayerPanel(engine=engine or SampleEngine(sine()), state_path=str(state))
    return panel, state


def test_e2e_happy_the_visualization_choice_comes_back(tmp_path):
    panel, state = panel_with_state(tmp_path)
    try:
        panel.resize(600, 700)
        panel.show()
        QTest.mouseClick(panel.visualizer, Qt.MouseButton.LeftButton, pos=QPoint(15, 15))
        QTest.mouseClick(panel.visualizer, Qt.MouseButton.LeftButton, pos=QPoint(15, 15))
        chosen = panel.visualizer.mode
        assert chosen == MP.Visualizer.MODES[2]
        assert panel._save_timer.isActive(), "a switch schedules a save"
    finally:
        panel.shutdown()
        panel.close()
    assert json.loads(state.read_text(encoding="utf-8"))["visualizer"] == chosen
    again, _state = panel_with_state(tmp_path)
    try:
        assert again.visualizer.mode == chosen
    finally:
        again.close()


def test_e2e_happy_the_equalizer_folds_and_unfolds_and_stays_so(tmp_path):
    panel, state = panel_with_state(tmp_path)
    try:
        panel.resize(600, 700)
        panel.show()
        assert panel.eq_body.isVisible() and panel.eq_toggle.isChecked()
        playlist_height = panel.playlist.height()
        QTest.mouseClick(panel.eq_toggle, Qt.MouseButton.LeftButton)
        assert not panel.eq_body.isVisible() and not panel.eq_toggle.isChecked()
        assert panel.eq_check.isVisible() and panel.preset.isVisible(), "the header row stays"
        APP.processEvents()
        assert panel.playlist.height() > playlist_height, "the playlist gets the room"
        assert panel.eq_toggle.arrowType() == Qt.ArrowType.RightArrow
    finally:
        panel.shutdown()
        panel.close()
    assert json.loads(state.read_text(encoding="utf-8"))["equalizer_open"] is False
    again, _state = panel_with_state(tmp_path)
    try:
        again.resize(600, 700)
        again.show()
        assert not again.eq_body.isVisible()
        QTest.mouseClick(again.eq_toggle, Qt.MouseButton.LeftButton)
        assert again.eq_body.isVisible()
        assert again.eq_toggle.arrowType() == Qt.ArrowType.DownArrow
    finally:
        again.close()


def test_happy_folding_keeps_the_gains_and_the_switch(tmp_path):
    engine = SampleEngine(sine())
    panel = MP.PlayerPanel(engine=engine)
    try:
        panel.preset.setCurrentText("Rock")
        panel.eq_check.setChecked(False)
        panel.set_equalizer_open(False)
        panel.set_equalizer_open(True)
        assert engine.gains_db == MP.PRESETS["Rock"]
        assert not panel.eq_check.isChecked()
        assert [s.value() for s in panel.sliders] == [round(g) for g in MP.PRESETS["Rock"]]
    finally:
        panel.close()


def test_sad_odd_saved_values_give_the_defaults(tmp_path):
    state = tmp_path / "media_player.json"
    for visual, open_ in (("lava-lamp", "yes"), (5, 1), (None, None), (["scope"], {})):
        state.write_text(json.dumps({"version": 1, "visualizer": visual,
                                     "equalizer_open": open_}), encoding="utf-8")
        panel = MP.PlayerPanel(engine=SampleEngine(), state_path=str(state))
        try:
            assert panel.visualizer.mode == "spectrum", visual
            assert panel.eq_toggle.isChecked() and not panel.eq_body.isHidden(), open_
        finally:
            panel.close()


def test_edge_an_old_state_file_without_the_new_keys(tmp_path):
    state = tmp_path / "media_player.json"
    state.write_text(json.dumps({"version": 1, "volume": 30}), encoding="utf-8")
    panel = MP.PlayerPanel(engine=SampleEngine(), state_path=str(state))
    try:
        assert panel.volume.value() == 30
        assert panel.visualizer.mode == "spectrum" and panel.eq_toggle.isChecked()
    finally:
        panel.close()


def test_edge_without_numpy_the_equalizer_is_off_but_still_folds(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "np", None)
    panel = MP.PlayerPanel(engine=SampleEngine(None))
    try:
        panel.resize(600, 700)
        panel.show()
        assert not panel.eq_check.isEnabled() and not panel.eq_body.isEnabled()
        assert panel.eq_toggle.isEnabled()
        QTest.mouseClick(panel.eq_toggle, Qt.MouseButton.LeftButton)
        assert not panel.eq_body.isVisible()
        QTest.mouseClick(panel.visualizer, Qt.MouseButton.LeftButton, pos=QPoint(10, 10))
        assert panel.visualizer.mode == MP.Visualizer.MODES[1]
        panel.visualizer.tick()
        panel.visualizer.repaint()
    finally:
        panel.close()
