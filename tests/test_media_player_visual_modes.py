"""The Media Player's visualizer: more faces, colour schemes, options,
fullscreen / detach, and a playlist that folds away.

Operator (paraphrased): more modes for the spectrum and colour
combinations, both configurable; a fullscreen mode so the spectrum can run
like a screensaver, or the animation detached into its own window of any
size; the track list collapsible.

Decided:

* five new faces on top of the old five - a line spectrum on a log
  frequency axis, a waterfall (spectrogram), a polar spectrum, a stereo
  scope (Lissajous / goniometer) and a starfield driven by the bass;
* named colour schemes (Classic, Fire, Ice, Neon, Mono), one that follows
  the app theme, and a custom one; the peak colour always keeps the WCAG
  non-text contrast (SC 1.4.11, 3:1) on the background;
* bar count, peak fall, smoothing and the fps cap within ranges defined
  once (VISUAL_OPTIONS) and held here;
* fullscreen (menu, double-click, F11; Esc, F11 or a double-click
  leaves) and Detach into a window of its own: the one visualizer widget
  moves, it is never duplicated; closing the window attaches it back;
* the playlist folds away; keys and drops onto the panel keep working.
"""

from __future__ import annotations

import importlib.util
import json
import os
import statistics
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import (  # noqa: E402
    QEventLoop,
    QMimeData,
    QObject,
    QPoint,
    QPointF,
    Qt,
    QTimer,
    QUrl,
    pyqtSignal,
)
from PyQt6.QtGui import (  # noqa: E402
    QColor,
    QContextMenuEvent,
    QDragEnterEvent,
    QDropEvent,
    QImage,
    QPalette,
)
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QSpinBox  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
AUDIO = Path(__file__).resolve().parent / "fixtures" / "audio"
RATE = 44100
NEW_FACES = ("line", "waterfall", "polar", "lissajous", "starfield")
NAMED_SCHEMES = ("classic", "fire", "ice", "neon", "mono")


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_visual_modes_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()


def sine(freq=440.0, frames=2048, amp=0.5, right=None):
    t = np.arange(frames) / RATE
    left = (amp * np.sin(2 * np.pi * freq * t)).astype(np.float32)
    other = left if right is None else np.full(frames, right, np.float32)
    return np.stack([left, other], axis=1)


def noise(frames=2048, amp=0.3, seed=1):
    rng = np.random.default_rng(seed)
    return (rng.standard_normal((frames, 2)) * amp).astype(np.float32)


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
    """The engine interface with fixed samples (None: no numpy)."""

    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, samples=None) -> None:
        super().__init__()
        self.state, self.error, self.finished, self.loaded, self.path = (
            "stopped", "", False, False, "")
        self.samples = samples
        self.gains_db = [0.0] * 10
        self.muted_calls = 0

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
        if self.samples is None:
            return None
        return MP.spectrum_bars(self.samples, RATE, n)

    def current_samples(self):
        return self.samples


def visualizer(samples=None, size=(320, 160)):
    vis = MP.Visualizer(SampleEngine(samples))
    vis.resize(*size)
    vis.show()
    return vis


def colours_of(widget) -> list[QColor]:
    img = widget.grab().toImage()
    return [img.pixelColor(x, y) for x in range(0, img.width(), 2)
            for y in range(0, img.height(), 2)]


def near(a: QColor, b: QColor, tolerance: int = 40) -> bool:
    return (abs(a.red() - b.red()) + abs(a.green() - b.green())
            + abs(a.blue() - b.blue())) <= tolerance


def shows_scheme(widget, scheme) -> tuple[bool, bool]:
    """(the background is there, a bar or peak colour of *scheme* is there)."""
    seen = colours_of(widget)
    background = QColor(scheme.background)
    anchors = [QColor(c) for c in (scheme.low, scheme.mid, scheme.high, scheme.peak)]
    return (any(c == background for c in seen),
            any(near(c, a) for c in seen if c != background for a in anchors))


def settle(vis, ticks=4):
    vis._label_until = 0.0  # the name overlay is not the face
    for _ in range(ticks):
        vis.tick()


# -- the spectrum has no dead bars any more ------------------------------------------------


def _old_loop_bars(samples, rate, n_bars):
    """The loop spectrum_bars was before: the reference for bars with bins."""
    data = np.asarray(samples, np.float32)
    mono = data.mean(axis=1)
    n = len(mono)
    window = 0.5 - 0.5 * np.cos(2 * np.pi * np.arange(n) / n)
    mags = np.abs(np.fft.rfft(mono * window))
    freqs = np.fft.rfftfreq(n, 1.0 / rate)
    edges = np.geomspace(40.0, min(16000.0, rate / 2), n_bars + 1)
    out, has = np.zeros(n_bars, np.float32), np.zeros(n_bars, bool)
    for i in range(n_bars):
        sel = mags[(freqs >= edges[i]) & (freqs < edges[i + 1])]
        if len(sel):
            has[i] = True
            peak = float(sel.max()) / (n / 4.0)
            db = 20 * np.log10(peak) if peak > 0 else -200.0
            out[i] = min(1.0, max(0.0, (db + 70.0) / 70.0))
    return out, has


class TestSpectrumBars:
    @pytest.mark.parametrize("n_bars", [16, 32, 64, 128])
    def test_happy_white_noise_moves_every_bar(self, n_bars):
        """A bar narrower than the FFT's bin spacing (21.5 Hz at 2048
        frames) held no bin and stayed at 0 for ever: bars 1 and 3 of 32,
        32 of 128 under white noise (measured before the fix)."""
        bars = MP.spectrum_bars(noise(), RATE, n_bars)
        assert len(bars) == n_bars
        assert int((bars == 0).sum()) == 0, [i for i in range(n_bars) if bars[i] == 0]

    def test_sad_silence_and_no_samples_stay_zero(self):
        assert MP.spectrum_bars(np.zeros((2048, 2), np.float32), RATE, 64).max() == 0.0
        assert MP.spectrum_bars(np.zeros((0, 2), np.float32), RATE, 64).tolist() == [0.0] * 64

    @pytest.mark.parametrize("n_bars", [MP.VISUAL_OPTIONS["bars"][0], 32,
                                        MP.VISUAL_OPTIONS["bars"][1]])
    def test_edge_bars_with_bins_are_unchanged_and_the_tone_stays_put(self, n_bars):
        for samples in (noise(), sine(1000.0), sine(60.0, amp=0.9)):
            new = MP.spectrum_bars(samples, RATE, n_bars)
            old, has = _old_loop_bars(samples, RATE, n_bars)
            assert np.allclose(new[has], old[has], atol=1e-5)
        centres = MP.bar_centres(RATE, 2048, n_bars)
        peak = int(np.argmax(MP.spectrum_bars(sine(1000.0), RATE, n_bars)))
        assert abs(np.log2(centres[peak] / 1000)) < 0.5


# -- colour schemes ------------------------------------------------------------------------------


class TestSchemes:
    def test_happy_named_schemes_keep_their_peaks_visible(self):
        assert set(NAMED_SCHEMES) <= set(MP.COLOUR_SCHEMES)
        assert set(MP.SCHEME_NAMES) == set(MP.COLOUR_SCHEMES) | {"theme", "custom"}
        assert MP.DEFAULT_SCHEME == "classic"
        assert MP.COLOUR_SCHEMES["classic"].background == "#101418", "the old look stays"
        for name, scheme in MP.COLOUR_SCHEMES.items():
            for colour in scheme:
                assert QColor(colour).isValid() and colour.startswith("#"), (name, colour)
            assert MP.peak_contrast(scheme) >= MP.MIN_PEAK_CONTRAST, name

    def test_happy_the_threshold_is_wcag_non_text_contrast(self):
        """SC 1.4.11: user-interface parts and graphics need 3:1."""
        assert MP.MIN_PEAK_CONTRAST == 3.0

    def test_sad_a_custom_peak_like_the_background_is_made_readable(self):
        scheme = MP.custom_scheme({"background": "#202020", "low": "#00ff00",
                                   "high": "#ff0000", "peak": "#202020"})
        assert scheme.background == "#202020"
        assert MP.peak_contrast(scheme) >= MP.MIN_PEAK_CONTRAST
        assert scheme.peak != "#202020"

    def test_sad_broken_custom_colours_fall_back_per_colour(self):
        default = MP.custom_scheme(None)
        for broken in ("x", 5, [], {"background": "red; drop", "low": 3, "peak": "#12345"}):
            scheme = MP.custom_scheme(broken)
            assert scheme == default, broken
        mixed = MP.custom_scheme({"background": "#000000", "low": "#zzzzzz"})
        assert mixed.background == "#000000" and mixed.low == default.low

    def test_edge_every_background_and_peak_pair_on_a_grid_ends_readable(self):
        steps = ("#000000", "#3f3f3f", "#777777", "#7f7f7f", "#808080", "#bfbfbf", "#ffffff",
                 "#ff0000", "#00ff00", "#0000ff", "#ffff00")
        for background in steps:
            for peak in steps:
                scheme = MP.custom_scheme({"background": background, "peak": peak})
                assert MP.peak_contrast(scheme) >= MP.MIN_PEAK_CONTRAST, (background, peak)
                if MP.contrast_ratio(peak, background) >= MP.MIN_PEAK_CONTRAST:
                    assert scheme.peak == peak, "a readable choice is kept as it is"

    def test_edge_the_theme_scheme_follows_light_dark_and_a_broken_palette(self):
        for base, text, highlight in (("#ffffff", "#000000", "#3daee9"),
                                      ("#1e1e1e", "#eeeeee", "#2a82da"),
                                      ("#777777", "#777777", "#777777")):
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Base, QColor(base))
            palette.setColor(QPalette.ColorRole.Text, QColor(text))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(highlight))
            scheme = MP.theme_scheme(palette)
            assert scheme.background == base
            assert MP.peak_contrast(scheme) >= MP.MIN_PEAK_CONTRAST, (base, text)


# -- options -----------------------------------------------------------------------------------


class TestOptions:
    def test_happy_ranges_hold_their_defaults_and_the_old_behaviour(self):
        assert set(MP.VISUAL_OPTIONS) == {"bars", "peak_fall", "smoothing", "fps"}
        for name, (low, high, default) in MP.VISUAL_OPTIONS.items():
            assert low < default < high, name
        # the visualizer before the options: 32 bars, 0.85 decay, a peak
        # falling 0.015 of the height a frame at 30 frames a second (45 %/s)
        assert MP.VISUAL_OPTIONS["bars"][2] == MP.Visualizer.BARS == 32
        assert MP.VISUAL_OPTIONS["smoothing"][2] == 85
        assert MP.VISUAL_OPTIONS["peak_fall"][2] == 45
        assert MP.VISUAL_OPTIONS["fps"][2] == 30

    def test_sad_nonsense_values_give_the_default(self):
        for name, (_low, _high, default) in MP.VISUAL_OPTIONS.items():
            for value in (None, "12", 3.5, True, [], {}):
                assert MP.clamp_option(name, value) == default, (name, value)
        with pytest.raises(KeyError):
            MP.clamp_option("lava", 3)

    def test_edge_out_of_range_is_clamped(self):
        for name, (low, high, _default) in MP.VISUAL_OPTIONS.items():
            assert MP.clamp_option(name, low - 1000) == low
            assert MP.clamp_option(name, high + 1000) == high
            assert MP.clamp_option(name, low) == low and MP.clamp_option(name, high) == high

    def test_happy_options_drive_the_visualizer(self):
        vis = visualizer(noise())
        try:
            vis.set_option("fps", 60)
            assert vis.timer.interval() == round(1000 / 60)
            vis.set_option("bars", 64)
            settle(vis)
            assert len(vis.levels) == len(vis.peaks) == 64
            vis.set_option("bars", 10_000)
            assert vis.options["bars"] == MP.VISUAL_OPTIONS["bars"][1]
            vis.set_option("smoothing", 0)
            vis.tick()
            assert np.allclose(vis.levels, vis.engine.current_bars(vis.options["bars"]))
        finally:
            vis.close()

    def test_edge_the_bars_settle_at_the_same_speed_whatever_the_fps(self):
        """smoothing is the share kept a frame at the default 30 fps; at 60
        fps two frames keep the same."""
        vis = visualizer(np.zeros((2048, 2), np.float32))
        try:
            kept = {}
            for fps, frames in ((30, 1), (60, 2), (15, 0.5)):
                vis.set_option("fps", fps)
                vis.levels = [1.0] * len(vis.levels)
                for _ in range(max(1, int(frames))):
                    vis.tick()
                kept[fps] = vis.levels[0]
            assert abs(kept[30] - 0.85) < 1e-6 and abs(kept[60] - 0.85) < 1e-6
            assert abs(kept[15] - 0.85 ** 2) < 1e-6
        finally:
            vis.close()

    def test_edge_the_peak_falls_at_the_chosen_speed_whatever_the_fps(self):
        """peak_fall is % of the height a second: a frame takes its share."""
        vis = visualizer(sine(1000.0, amp=0.9))
        try:
            vis.set_option("smoothing", 0)
            vis.engine.samples = np.zeros((2048, 2), np.float32)
            vis.set_option("peak_fall", 150)
            for fps in (30, 60):
                vis.set_option("fps", fps)
                vis.peaks = [0.9] * len(vis.peaks)
                vis.tick()
                assert abs((0.9 - max(vis.peaks)) - 1.5 / fps) < 1e-6, fps
        finally:
            vis.close()


# -- faces ----------------------------------------------------------------------------------------


def test_happy_the_new_faces_follow_the_old_ones():
    assert MP.Visualizer.MODES[:5] == ("spectrum", "mirror", "radial", "scope", "vu")
    assert set(NEW_FACES) <= set(MP.Visualizer.MODES)
    assert set(MP.VISUALIZER_NAMES) == set(MP.Visualizer.MODES)


@pytest.fixture(scope="module")
def played_engine():
    engine = MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink())
    engine.load(str(AUDIO / "sine.wav"))  # 440 Hz on the left, the right silent
    engine.play()
    assert wait(lambda: engine.finished)
    return engine


def test_e2e_happy_every_face_paints_the_real_engine_in_every_scheme(played_engine):
    vis = MP.Visualizer(played_engine)
    vis.resize(360, 180)
    vis.show()
    try:
        for scheme_name in (*NAMED_SCHEMES, "theme", "custom"):
            vis.set_scheme(scheme_name)
            scheme = vis.colours
            for mode in MP.Visualizer.MODES:
                vis.set_mode(mode, announce=False)
                settle(vis, 6)
                background, scheme_colour = shows_scheme(vis, scheme)
                assert background, (scheme_name, mode)
                assert scheme_colour, (scheme_name, mode)
    finally:
        vis.close()


def test_happy_the_waterfall_keeps_a_history_and_scrolls():
    vis = visualizer(sine(1000.0, amp=0.9))
    try:
        vis.set_mode("waterfall", announce=False)  # the switch draws a row at once
        for _ in range(5):
            vis.tick()
        history = vis.waterfall
        assert history.shape[1] == vis.options["bars"]
        assert all(history[-i].any() for i in range(1, 7)) and not history[:-6].any()
        vis.set_option("bars", 16)
        assert vis.waterfall.shape[1] == 16 and not vis.waterfall.any()
    finally:
        vis.close()


def test_happy_the_starfield_speeds_up_with_the_bass():
    def travelled(samples):
        vis = visualizer(samples)
        try:
            vis.set_mode("starfield", announce=False)
            vis.reset_stars(seed=7)
            before = vis.stars[:, 2].copy()
            for _ in range(5):
                vis.tick()
            moved = before - vis.stars[:, 2]
            return float(np.median(moved[moved > 0]))
        finally:
            vis.close()

    quiet = travelled(np.zeros((2048, 2), np.float32))
    bass = travelled(sine(60.0, amp=0.9))
    assert quiet > 0, "the stars drift in silence too"
    assert bass > 2 * quiet


def test_happy_the_stereo_scope_shows_left_against_right():
    vis = visualizer(sine(440.0, amp=0.8, right=0.0))
    try:
        vis.set_mode("lissajous", announce=False)
        x, y = vis.lissajous
        assert float(np.abs(x).max()) > 0.3, "left alone: a diagonal, not a vertical line"
        vis.engine.samples = sine(440.0, amp=0.8)  # the same on both: mono
        vis.tick()
        x, y = vis.lissajous
        assert float(np.abs(x).max()) < 1e-6 and float(np.abs(y).max()) > 0.3
        vis.engine.samples = sine(440.0, amp=0.8)[:, 0]  # one channel only
        vis.tick()
        x, y = vis.lissajous
        assert float(np.abs(x).max()) < 1e-6
    finally:
        vis.close()


def test_sad_the_new_faces_without_samples_and_tiny():
    vis = visualizer(None, size=(3, 2))
    try:
        for mode in NEW_FACES:
            vis.set_mode(mode, announce=False)
            vis.tick()
            vis.repaint()
        vis.resize(200, 100)
        for mode in NEW_FACES:
            vis.set_mode(MP.Visualizer.MODES[0], announce=False)
            vis.set_mode(mode, announce=False)
            vis.repaint()
            assert vis.grab().width() == 200
    finally:
        vis.close()


# -- the right-click menu -------------------------------------------------------------------------


def actions_by_data(menu):
    found = {}
    for action in menu.actions():
        if action.menu() is not None:
            found.update(actions_by_data(action.menu()))
        elif action.data() is not None:
            found[action.data()] = action
    return found


def test_e2e_happy_the_menu_lists_every_face_and_scheme_and_switches():
    vis = visualizer(sine())
    try:
        QTest.mouseClick(vis, Qt.MouseButton.RightButton, pos=QPoint(10, 10))
        assert vis.mode == "spectrum", "the right button does not switch the face"
        APP.sendEvent(vis, QContextMenuEvent(QContextMenuEvent.Reason.Mouse, QPoint(10, 10),
                                             vis.mapToGlobal(QPoint(10, 10))))
        assert vis.menu is not None and vis.menu.isVisible(), "a popup, never a blocking exec"
        found = actions_by_data(vis.menu)
        for mode in MP.Visualizer.MODES:
            assert ("mode", mode) in found, mode
        for scheme in MP.SCHEME_NAMES:
            assert ("scheme", scheme) in found, scheme
        assert found[("mode", "spectrum")].isChecked()
        assert found[("scheme", "classic")].isChecked()
        changes = []
        vis.settings_changed.connect(lambda: changes.append(1))
        found[("mode", "waterfall")].trigger()
        found[("scheme", "fire")].trigger()
        assert vis.mode == "waterfall" and vis.scheme == "fire"
        assert vis.colours == MP.COLOUR_SCHEMES["fire"] and changes
        vis.menu.close()
        again = actions_by_data(vis.build_menu())
        assert again[("mode", "waterfall")].isChecked()
        assert again[("scheme", "fire")].isChecked()
    finally:
        vis.close()


# -- the panel: fullscreen, detach, playlist ------------------------------------------------------


def make_panel(tmp_path, engine=None, tracks=0):
    state = tmp_path / "cfg" / "media_player.json"
    panel = MP.PlayerPanel(engine=engine or SampleEngine(sine()), state_path=str(state))
    paths = []
    for i in range(tracks):
        path = tmp_path / f"t{i}.wav"
        path.write_bytes((AUDIO / "sine.wav").read_bytes())
        paths.append(str(path))
    if paths:
        panel.add_files(paths)
    panel.resize(600, 760)
    panel.show()
    return panel, state


def visualizers():
    return [w for w in QApplication.allWidgets() if isinstance(w, MP.Visualizer)]


def close(panel):
    panel.shutdown()
    panel.close()
    APP.processEvents()


def test_e2e_happy_fullscreen_by_f11_and_out_by_escape_and_f11(tmp_path):
    panel, _state = make_panel(tmp_path)
    vis = panel.visualizer
    try:
        vis.setFocus()
        QTest.keyClick(vis, Qt.Key.Key_F11)
        assert panel.is_fullscreen and panel.visual_window.isFullScreen()
        assert vis.window() is panel.visual_window
        assert not panel.isAncestorOf(vis)
        QTest.keyClick(vis, Qt.Key.Key_Escape)
        assert not panel.is_fullscreen and panel.visual_window is None
        assert panel.isAncestorOf(vis) and vis.isVisible()
        vis.setFocus()
        QTest.keyClick(vis, Qt.Key.Key_F11)
        assert panel.is_fullscreen
        QTest.keyClick(vis, Qt.Key.Key_F11)
        assert not panel.is_fullscreen and panel.isAncestorOf(vis)
    finally:
        close(panel)


def real_double_click(widget, pos):
    """What a window system delivers: press, release, double click, release.
    QTest's mouseDClick sends the double click alone, and after a release
    its clock jumps half a second (no accidental double click) - so the
    press goes first and the release after."""
    QTest.mousePress(widget, Qt.MouseButton.LeftButton, pos=pos)
    QTest.mouseDClick(widget, Qt.MouseButton.LeftButton, pos=pos)
    QTest.mouseRelease(widget, Qt.MouseButton.LeftButton, pos=pos)


def test_e2e_happy_a_double_click_goes_fullscreen_without_switching_the_face(tmp_path):
    panel, _state = make_panel(tmp_path)
    vis = panel.visualizer
    try:
        QTest.mouseClick(vis, Qt.MouseButton.LeftButton, pos=QPoint(20, 20))
        assert vis.mode == MP.Visualizer.MODES[1]
        real_double_click(vis, QPoint(20, 20))
        assert panel.is_fullscreen
        assert vis.mode == MP.Visualizer.MODES[1], "the double click's own press is undone"
        real_double_click(vis, QPoint(20, 20))
        assert not panel.is_fullscreen and vis.mode == MP.Visualizer.MODES[1]
        QTest.mouseDClick(vis, Qt.MouseButton.LeftButton, pos=QPoint(20, 20))
        assert panel.is_fullscreen, "a double click alone (no press before it) works too"
        assert vis.mode == MP.Visualizer.MODES[1]
    finally:
        close(panel)


def test_e2e_happy_fullscreen_from_the_menu_and_back(tmp_path):
    panel, _state = make_panel(tmp_path)
    try:
        found = actions_by_data(panel.visualizer.build_menu())
        assert not found[("window", "fullscreen")].isChecked()
        found[("window", "fullscreen")].trigger()
        assert panel.is_fullscreen and panel.visual_window.isFullScreen()
        found = actions_by_data(panel.visualizer.build_menu())
        assert found[("window", "fullscreen")].isChecked()
        found[("window", "fullscreen")].trigger()
        assert not panel.is_fullscreen and panel.isAncestorOf(panel.visualizer)
    finally:
        close(panel)


def test_sad_no_fullscreen_while_the_panel_is_hidden_or_switched_off(tmp_path):
    panel, _state = make_panel(tmp_path)
    try:
        panel.hide()
        assert panel.set_fullscreen(True) is False and panel.visual_window is None
        panel.show()
        assert panel.set_fullscreen(True) is True
        panel.hide()  # the dock closed while fullscreen: the screen is given back
        assert wait(lambda: not panel.is_fullscreen, 3)
        assert panel.isAncestorOf(panel.visualizer)
        panel.show()
        panel.shutdown()
        assert panel.set_fullscreen(True) is False and panel.visual_window is None
    finally:
        panel.close()


def test_edge_the_cursor_hides_in_fullscreen_and_comes_back_on_a_move(tmp_path):
    panel, _state = make_panel(tmp_path)
    vis = panel.visualizer
    try:
        assert vis.hide_cursor is True
        vis.CURSOR_HIDE_MS = 30
        panel.set_fullscreen(True)
        assert wait(lambda: vis.cursor().shape() == Qt.CursorShape.BlankCursor, 3)
        vis.CURSOR_HIDE_MS = 5000  # the move restarts the wait: not again during the check
        QTest.mouseMove(vis, QPoint(40, 40))
        assert vis.cursor().shape() != Qt.CursorShape.BlankCursor
        panel.set_fullscreen(False)
        assert vis.cursor().shape() != Qt.CursorShape.BlankCursor
        vis.set_hide_cursor(False)
        panel.set_fullscreen(True)
        time.sleep(0.1)
        APP.processEvents()
        assert vis.cursor().shape() != Qt.CursorShape.BlankCursor
    finally:
        close(panel)


def test_e2e_happy_detach_and_attach_through_the_menu_move_the_one_visualizer(tmp_path):
    engine = SampleEngine(sine())
    panel, _state = make_panel(tmp_path, engine, tracks=1)
    vis = panel.visualizer
    try:
        panel.play_selected()
        assert vis.timer.isActive()
        found = actions_by_data(vis.build_menu())
        found[("window", "detach")].trigger()
        window = panel.visual_window
        assert window is not None and window.isVisible() and not window.isFullScreen()
        assert vis.window() is window and not panel.isAncestorOf(vis)
        assert panel.visual_placeholder.isVisible()
        assert [w for w in visualizers() if w.engine is engine] == [vis], "moved, not copied"
        assert vis.timer.isActive(), "it keeps playing"
        window.resize(900, 500)
        APP.processEvents()
        assert vis.width() >= 800
        # keys in the detached window still reach the player
        vis.setFocus()
        QTest.keyClick(vis, Qt.Key.Key_Space)
        assert engine.state == "paused"
        found = actions_by_data(vis.build_menu())
        assert ("window", "detach") not in found
        found[("window", "attach")].trigger()
        assert panel.visual_window is None and panel.isAncestorOf(vis)
        assert not panel.visual_placeholder.isVisible()
        assert [w for w in visualizers() if w.engine is engine] == [vis]
    finally:
        close(panel)


def test_sad_closing_the_detached_window_attaches_it_back(tmp_path):
    panel, _state = make_panel(tmp_path)
    vis = panel.visualizer
    try:
        panel.detach_visualizer()
        panel.visual_window.close()
        APP.processEvents()
        assert panel.visual_window is None and panel.isAncestorOf(vis) and vis.isVisible()
        panel.detach_visualizer()
        panel.set_fullscreen(True)
        assert panel.visual_window.isFullScreen()
        panel.set_fullscreen(False)  # back to the detached window, not into the panel
        assert panel.visual_window is not None and not panel.visual_window.isFullScreen()
        panel.shutdown()  # the extension goes: the window goes with it
        assert panel.visual_window is None and panel.isAncestorOf(vis)
    finally:
        panel.close()


def test_edge_detach_twice_and_attach_without_a_window(tmp_path):
    panel, _state = make_panel(tmp_path)
    try:
        panel.attach_visualizer()  # nothing to attach: nothing happens
        panel.detach_visualizer()
        first = panel.visual_window
        panel.detach_visualizer()
        assert panel.visual_window is first
        assert len([w for w in visualizers() if w.engine is panel.engine]) == 1
    finally:
        close(panel)


def drop_on_panel(panel, mime):
    pos = QPointF(panel.visualizer.x() + 10, panel.visualizer.y() + 10)
    actions = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
    enter = QDragEnterEvent(pos.toPoint(), actions, mime, Qt.MouseButton.LeftButton,
                            Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(panel, enter)
    if not enter.isAccepted():
        return False
    drop = QDropEvent(pos, actions, mime, Qt.MouseButton.LeftButton,
                      Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(panel, drop)
    return drop.isAccepted()


def test_e2e_happy_the_playlist_folds_keys_and_drops_still_work_and_it_stays_folded(tmp_path):
    engine = SampleEngine(sine())
    panel, state = make_panel(tmp_path, engine, tracks=2)
    try:
        assert panel.playlist.isVisible() and panel.playlist_toggle.isChecked()
        height = panel.visualizer.height()
        panel.playlist.setFocus()
        QTest.mouseClick(panel.playlist_toggle, Qt.MouseButton.LeftButton)
        APP.processEvents()
        assert not panel.playlist.isVisible() and not panel.playlist_buttons.isVisible()
        assert panel.playlist_toggle.isVisible(), "the toggle stays to unfold it"
        assert panel.visualizer.height() > height, "the visualizer gets the room"
        assert panel.playlist_toggle.arrowType() == Qt.ArrowType.RightArrow
        # the transport keys
        panel.setFocus()
        QTest.keyClick(panel, Qt.Key.Key_Space)
        assert engine.state == "playing"
        QTest.keyClick(panel.visualizer, Qt.Key.Key_M)
        assert panel.muted
        # a drop onto the panel (the visualizer takes none: it lands on the panel)
        assert not panel.visualizer.acceptDrops() and panel.acceptDrops()
        extra = tmp_path / "extra.wav"
        extra.write_bytes((AUDIO / "sine.wav").read_bytes())
        mime = QMimeData()
        mime.setUrls([QUrl.fromLocalFile(str(extra))])
        assert drop_on_panel(panel, mime)
        assert wait(lambda: panel.playlist.count() == 3, 5)
        found = actions_by_data(panel.visualizer.build_menu())
        assert found[("playlist", "open")].isChecked() is False
    finally:
        close(panel)
    assert json.loads(state.read_text(encoding="utf-8"))["playlist_open"] is False
    again, _state = make_panel(tmp_path)
    try:
        assert not again.playlist.isVisible() and not again.playlist_toggle.isChecked()
        actions_by_data(again.visualizer.build_menu())[("playlist", "open")].trigger()
        assert again.playlist.isVisible() and again.playlist_buttons.isVisible()
    finally:
        close(again)
    assert json.loads(state.read_text(encoding="utf-8"))["playlist_open"] is True


def test_sad_a_drop_of_something_else_onto_the_panel_is_refused(tmp_path):
    panel, _state = make_panel(tmp_path)
    try:
        mime = QMimeData()
        mime.setText("not a file")
        assert not drop_on_panel(panel, mime)
        mime = QMimeData()
        mime.setUrls([QUrl("https://example.org/a.mp3")])
        assert not drop_on_panel(panel, mime)
    finally:
        close(panel)


def test_e2e_happy_scheme_colours_and_options_come_back(tmp_path):
    panel, state = make_panel(tmp_path)
    try:
        vis = panel.visualizer
        vis.set_mode("starfield", announce=False)
        vis.set_custom_colours({"background": "#000010", "low": "#112233", "high": "#ddeeff",
                                "peak": "#ffcc00"})
        vis.set_scheme("custom")
        vis.set_option("bars", 48)
        vis.set_option("fps", 50)
        vis.set_option("smoothing", 40)
        vis.set_option("peak_fall", 7)
        vis.set_hide_cursor(False)
        assert panel._save_timer.isActive(), "a change schedules a save"
    finally:
        close(panel)
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["visual_scheme"] == "custom"
    assert saved["visual_options"] == {"bars": 48, "fps": 50, "smoothing": 40, "peak_fall": 7,
                                       "hide_cursor": False}
    assert saved["visual_custom"]["peak"] == "#ffcc00"
    again, _state = make_panel(tmp_path)
    try:
        vis = again.visualizer
        assert vis.mode == "starfield" and vis.scheme == "custom"
        assert vis.colours.background == "#000010" and vis.colours.peak == "#ffcc00"
        assert vis.options == {"bars": 48, "fps": 50, "smoothing": 40, "peak_fall": 7}
        assert vis.timer.interval() == round(1000 / 50) and vis.hide_cursor is False
    finally:
        close(again)


@pytest.mark.parametrize("broken", [
    {"visual_scheme": "lava", "visual_options": {"bars": "many", "fps": 1000, "smoothing": -5,
                                                "peak_fall": None, "hide_cursor": "no"},
     "visual_custom": "x", "playlist_open": "no"},
    {"visual_scheme": 5, "visual_options": [1, 2], "visual_custom": {"peak": 7},
     "playlist_open": None},
])
def test_sad_a_broken_saved_state_falls_back_to_the_defaults(tmp_path, broken):
    state = tmp_path / "cfg" / "media_player.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"version": 1, **broken}), encoding="utf-8")
    panel = MP.PlayerPanel(engine=SampleEngine(sine()), state_path=str(state))
    try:
        vis = panel.visualizer
        assert vis.scheme == MP.DEFAULT_SCHEME
        assert vis.colours == MP.COLOUR_SCHEMES[MP.DEFAULT_SCHEME]
        options = broken["visual_options"]
        expected = {name: spec[2] for name, spec in MP.VISUAL_OPTIONS.items()}
        if isinstance(options, dict):
            expected["fps"] = MP.VISUAL_OPTIONS["fps"][1]  # a number out of range: clamped
            expected["smoothing"] = MP.VISUAL_OPTIONS["smoothing"][0]
        assert vis.options == expected
        assert vis.hide_cursor is True
        assert panel.playlist_toggle.isChecked() and not panel.playlist.isHidden()
    finally:
        panel.close()


def test_edge_an_unreadable_state_file_gives_the_defaults(tmp_path):
    state = tmp_path / "media_player.json"
    state.write_bytes(b"\xff{not json")
    panel = MP.PlayerPanel(engine=SampleEngine(), state_path=str(state))
    try:
        assert panel.visualizer.scheme == MP.DEFAULT_SCHEME
        assert panel.playlist_toggle.isChecked()
    finally:
        panel.close()


# -- the settings dialog --------------------------------------------------------------------------


def test_e2e_happy_the_settings_dialog_from_the_menu_changes_the_visualizer(tmp_path):
    panel, _state = make_panel(tmp_path)
    vis = panel.visualizer
    try:
        actions_by_data(vis.build_menu())[("settings", "open")].trigger()
        dialog = panel.visual_settings
        assert dialog is not None and dialog.isVisible()
        assert dialog.close_corner is not None, "the [x] in the corner"
        spins = {spin.objectName(): spin for spin in dialog.findChildren(QSpinBox)}
        for name, (low, high, _default) in MP.VISUAL_OPTIONS.items():
            assert (spins[name].minimum(), spins[name].maximum()) == (low, high), name
        spins["bars"].setValue(20)
        assert vis.options["bars"] == 20
        dialog.scheme_box.setCurrentIndex(dialog.scheme_box.findData("ice"))
        assert vis.scheme == "ice"
        dialog.mode_box.setCurrentIndex(dialog.mode_box.findData("polar"))
        assert vis.mode == "polar"
        assert not dialog.colour_buttons["peak"].isEnabled(), "custom colours only for Custom"
        dialog.scheme_box.setCurrentIndex(dialog.scheme_box.findData("custom"))
        assert dialog.colour_buttons["peak"].isEnabled()
        dialog.pick_colour("peak", QColor(vis.colours.background))  # unreadable on purpose
        assert MP.peak_contrast(vis.colours) >= MP.MIN_PEAK_CONTRAST
        assert dialog.contrast_note.isVisible(), "the dialog says the peak was adjusted"
        actions_by_data(vis.build_menu())[("settings", "open")].trigger()
        assert panel.visual_settings is dialog, "one dialog, raised again"
        from PyQt6 import sip

        dialog.close()
        APP.processEvents()
        QApplication.sendPostedEvents(None, 0)  # the deferred delete
        assert panel.visual_settings is None and sip.isdeleted(dialog), "no dialog left behind"
        panel.open_visual_settings()
        assert panel.visual_settings is not None and panel.visual_settings is not dialog
    finally:
        close(panel)


def test_happy_the_extension_menu_opens_the_visualizer_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    class Api:
        def __init__(self):
            self.docks, self.menu = [], {}

        def add_dock(self, title, widget):
            self.docks.append(widget)

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            pass

        def add_menu_action(self, label, cb, shortcut=None):
            self.menu[label] = cb

        def run_in_background(self, work, on_done=None, on_error=None):
            on_done(work())

        def notify(self, text):
            pass

    api = Api()
    MP.activate(api)
    panel = api.docks[0]
    try:
        assert list(api.menu) == ["Media Player Visualizer…"]
        api.menu["Media Player Visualizer…"]()
        assert panel.visual_settings is not None and panel.visual_settings.isVisible()
    finally:
        MP.deactivate(api)
        APP.processEvents()


# -- what a frame costs ------------------------------------------------------------------------


def test_perf_every_face_paints_within_its_budget():
    """Painting runs on the GUI thread: at the highest fps cap a frame lasts
    1000 / 60 ms and a face may take half of it (PAINT_BUDGET_MS) - median of
    15 frames, ticks included, fullscreen at 1920x1080 with the most bars and
    white noise, which crosses the scopes' traces over themselves (an
    antialiased polyline cost 79 ms there before it was drawn as segments).
    A face over budget is measured once more: other test runs share this
    host, and a slow face is slow both times."""
    assert MP.PAINT_BUDGET_MS == pytest.approx(1000 / MP.VISUAL_OPTIONS["fps"][1] / 2)
    vis = MP.Visualizer(SampleEngine(noise()))
    vis.resize(1920, 1080)
    image = QImage(1920, 1080, QImage.Format.Format_ARGB32_Premultiplied)
    costs = {}
    try:
        vis.set_option("bars", MP.VISUAL_OPTIONS["bars"][1])
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode, announce=False)
            settle(vis, 3)
            for _attempt in range(2):  # a second look before a load spike counts as slow
                times = []
                for _ in range(15):
                    start = time.perf_counter()
                    vis.tick()
                    vis.render(image)
                    times.append((time.perf_counter() - start) * 1000)
                costs[mode] = round(statistics.median(times), 2)
                if costs[mode] <= MP.PAINT_BUDGET_MS:
                    break
    finally:
        vis.close()
    slow = {mode: cost for mode, cost in costs.items() if cost > MP.PAINT_BUDGET_MS}
    assert slow == {}, costs
