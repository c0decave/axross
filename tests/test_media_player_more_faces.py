"""The Media Player's visualizer: eight more faces after the first ten.

Asked for (paraphrased): more visualizations in the looks of a set of
reference pictures - a sheet of neon audio-wave styles
(segmented LED equalizer blocks, dotted particle columns, stacked
multi-line wave ribbons, gaussian bumps per band), a Kaleidosync
kaleidoscope, a 3D wave landscape with dots rising above it, "Unknown
Pleasures" ridgelines under a striped sun, and a circular spectrum seen in
3D perspective.

Decided (one face for each look the first ten do not have):

* led - a segmented LED equalizer: blocks with gaps, a colour per block
  from quiet to loud, the unlit blocks dimly visible, a falling peak block;
* particles - the bars as columns of round dots, sparks rising from a band
  that jumps (an onset) and dying out;
* ribbon - a ribbon of thin lines twisting across the window, its height
  following the bands, its twist moving on with the onsets;
* ridges - the spectrum's history as ridgelines in depth, each one hiding
  what lies behind it, under a striped sun with rays that grows with the
  bass;
* terrain - the spectrum's history as a wireframe landscape receding to a
  horizon, coloured dots on its front rows and above its peaks;
* ring - the bars on a ring seen at a tilt, the colour going round with
  the scheme's colours, the front bars nearer (bigger) than the back ones;
* kaleidoscope - petals, orbs and spikes from bass, middle and treble,
  mirrored into an N-fold symmetric picture that turns with the onsets;
* bell curves - a smooth gaussian bump for each group of bands.

Not taken: the slider-style EQ (a picture of a control, not of the sound),
the step (square) waveform and the plain rainbow line (the oscilloscope and
the line spectrum show the same). Every new face draws in the colour
scheme's colours, keeps a readable (3:1) element on its background, paints
within PAINT_BUDGET_MS (test_media_player_visual_modes.py measures every
face), and a still sound gives a still picture
(test_media_player_visualizer_idle.py).
"""

from __future__ import annotations

import importlib.util
import json
import math
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
from PyQt6.QtGui import QColor, QContextMenuEvent, QImage  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
RATE = 44100
OLD_FACES = ("spectrum", "mirror", "radial", "scope", "vu", "line", "waterfall", "polar",
             "lissajous", "starfield")
NEW_FACES = ("led", "particles", "ribbon", "ridges", "terrain", "ring", "kaleidoscope",
             "bells")
NAMED_SCHEMES = ("classic", "fire", "ice", "neon", "mono")
LOW_CONTRAST = {"background": "#202020", "low": "#232323", "high": "#262626",
                "peak": "#202020"}


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_more_faces_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()


# -- signals ---------------------------------------------------------------------------------


def music(seconds: float = 6.0, seed: int = 3):
    """A music-like stereo signal at 120 bpm: a kick on every beat, a bass
    line, a chord swelling and fading on the left, a hi-hat on the
    off-beats on the right."""
    rng = np.random.default_rng(seed)
    t = np.arange(int(seconds * RATE)) / RATE
    beat = 0.5
    tb = t % beat
    kick = np.exp(-tb * 18) * np.sin(2 * np.pi * (50 + 70 * np.exp(-tb * 30)) * tb)
    bar = (t // (2 * beat)).astype(int) % 4
    bass_freq = np.choose(bar, [55.0, 55.0, 73.4, 82.4])
    bass = 0.35 * np.sin(2 * np.pi * bass_freq * t) * (0.6 + 0.4 * np.exp(-tb * 4))
    swell = 0.5 + 0.5 * np.sin(2 * np.pi * t / 4.0)
    chord = sum(np.sin(2 * np.pi * f * t) for f in (220.0, 277.2, 329.6, 1318.5)) * 0.08 * swell
    off = (t + beat / 2) % beat
    hat = np.diff(rng.standard_normal(len(t) + 1)) * 0.12 * np.exp(-off * 60)
    left = 0.7 * kick + bass + chord + 0.4 * hat
    right = 0.7 * kick + bass + 0.4 * chord + hat
    return np.clip(np.stack([left, right], axis=1), -1, 1).astype(np.float32)


MUSIC = music()


def sine(freq=1000.0, frames=2048, amp=0.9):
    t = np.arange(frames) / RATE
    mono = (amp * np.sin(2 * np.pi * freq * t)).astype(np.float32)
    return np.stack([mono, mono], axis=1)


def silence(frames=2048):
    return np.zeros((frames, 2), np.float32)


class Engine(QObject):
    """The engine interface. *samples* fixed, or MUSIC played on: every
    tick takes the next 30th of a second."""

    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, samples=None, *, playing=False) -> None:
        super().__init__()
        self.state, self.error, self.finished, self.loaded, self.path = (
            "stopped", "", False, False, "")
        self.samples = samples
        self.playing = playing
        self.cursor = 0
        self.gains_db = [0.0] * 10
        self.bars_override = None

    def _window(self):
        if not self.playing:
            return self.samples
        start = self.cursor % (len(MUSIC) - MP.FRAME)
        self.cursor += RATE // 30
        return MUSIC[start:start + MP.FRAME]

    def current_bars(self, n=32):
        if self.bars_override is not None:
            return self.bars_override
        window = self._window()
        return None if window is None else MP.spectrum_bars(window, RATE, n)

    def current_samples(self):
        return self._window()

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


def visualizer(samples=None, size=(400, 225), *, playing=False, mode=None):
    vis = MP.Visualizer(Engine(samples, playing=playing))
    vis.resize(*size)
    vis.show()
    if mode is not None:
        vis.set_mode(mode, announce=False)
    vis._label_until = 0.0  # the name overlay is not the face
    return vis


def settle(vis, ticks=12):
    vis._label_until = 0.0
    for _ in range(ticks):
        vis.tick()


def pixels(widget_or_image) -> np.ndarray:
    """The picture as (height, width) 0xRRGGBB."""
    img = widget_or_image if isinstance(widget_or_image, QImage) else \
        widget_or_image.grab().toImage()
    img = img.convertToFormat(QImage.Format.Format_RGB32)
    ptr = img.constBits()
    ptr.setsize(img.sizeInBytes())
    rows = np.frombuffer(ptr, np.uint32).reshape(img.height(), img.bytesPerLine() // 4)
    return rows[:, :img.width()].copy() & 0xFFFFFF


def rgb(value: str | int) -> int:
    return QColor(value).rgb() & 0xFFFFFF if isinstance(value, str) else value


def channels(arr):
    return ((arr >> 16) & 0xFF).astype(int), ((arr >> 8) & 0xFF).astype(int), \
        (arr & 0xFF).astype(int)


def distance(arr, colour) -> np.ndarray:
    r, g, b = channels(arr)
    cr, cg, cb = channels(np.uint32(rgb(colour)))
    return np.abs(r - cr) + np.abs(g - cg) + np.abs(b - cb)


def painted_share(vis) -> float:
    """The share of pixels that are not the background."""
    arr = pixels(vis)
    return float(np.mean(arr != rgb(vis.colours.background)))


def differing_share(a: np.ndarray, b: np.ndarray, tolerance: int = 30) -> float:
    ar, ag, ab = channels(a)
    br, bg, bb = channels(b)
    return float(np.mean((np.abs(ar - br) + np.abs(ag - bg) + np.abs(ab - bb)) > tolerance))


def readable_share(vis) -> float:
    """The share of pixels with WCAG non-text contrast (3:1) on the background."""
    arr = pixels(vis)
    seen = np.unique(arr)
    background = vis.colours.background
    good = [c for c in seen.tolist()
            if MP.contrast_ratio(f"#{c:06x}", background) >= MP.MIN_PEAK_CONTRAST]
    return float(np.isin(arr, good).mean()) if good else 0.0


def wait(cond, timeout: float = 10.0) -> bool:
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


# -- the list of faces ---------------------------------------------------------------------------


def test_happy_the_new_faces_come_after_the_old_ten():
    assert MP.Visualizer.MODES == OLD_FACES + NEW_FACES
    assert set(MP.VISUALIZER_NAMES) == set(MP.Visualizer.MODES)
    names = [MP.VISUALIZER_NAMES[m] for m in MP.Visualizer.MODES]
    assert all(isinstance(n, str) and n.strip() for n in names)
    assert len(set(names)) == len(names), "every face has a name of its own"
    assert not set(NEW_FACES) & set(MP._SAMPLE_MODES), "the new faces draw the spectrum"


# -- happy: each face paints the sound, and looks like nothing else -----------------------------


@pytest.fixture(scope="module")
def music_faces():
    """Every face after 20 ticks of MUSIC, at 400x225."""
    vis = visualizer(playing=True)
    vis.reset_stars(seed=5)
    faces = {}
    try:
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode, announce=False)
            settle(vis, 20)
            faces[mode] = pixels(vis)
    finally:
        vis.close()
    return faces


@pytest.mark.parametrize("mode", NEW_FACES)
def test_happy_each_new_face_paints_music_unlike_every_other_face(music_faces, mode):
    background = rgb(MP.COLOUR_SCHEMES["classic"].background)
    picture = music_faces[mode]
    assert float(np.mean(picture != background)) > 0.03, mode
    assert len(np.unique(picture)) > 8, "more than a couple of colours"
    for other, image in music_faces.items():
        if other != mode:
            assert differing_share(picture, image) > 0.03, (mode, other)


@pytest.mark.parametrize("mode", NEW_FACES)
def test_happy_each_new_face_reacts_to_the_sound(mode):
    quiet = visualizer(silence(), mode=mode)
    loud = visualizer(playing=True, mode=mode)
    try:
        for vis in (quiet, loud):
            vis.reset_stars(seed=2)
            settle(vis, 20)
        assert differing_share(pixels(quiet), pixels(loud)) > 0.02, mode
    finally:
        quiet.close()
        loud.close()


# -- happy: what each face shows ---------------------------------------------------------------


def test_happy_led_lit_blocks_have_gaps_unlit_blocks_glow_dimly_and_the_peak_block_falls():
    vis = visualizer(sine(1000.0), size=(400, 240), mode="led")
    try:
        vis.set_option("smoothing", 0)
        vis.set_option("bars", 16)
        settle(vis, 3)
        segments, pitch, gap = vis.led_layout(vis.height())
        assert 3 <= segments <= vis.LED_SEGMENTS and gap >= 1
        loud = int(np.argmax(vis.levels))
        column = int((loud + 0.5) * vis.width() / len(vis.levels))
        arr = pixels(vis)
        background = rgb(vis.colours.background)
        lit = arr[:, column] != background
        runs = int(np.count_nonzero(np.diff(lit.astype(int)) == 1))
        assert runs >= segments - 1, "blocks separated by gaps, not one bar"
        quiet = int(np.argmin(vis.levels))
        quiet_x = int((quiet + 0.5) * vis.width() / len(vis.levels))
        unlit = arr[:, quiet_x][arr[:, quiet_x] != background]
        assert len(unlit), "unlit LEDs stay dimly visible"
        for colour in (vis.colours.low, vis.colours.mid, vis.colours.high):
            assert np.all(distance(unlit, vis.colours.background) < distance(unlit, colour)), \
                "unlit is dim: nearer the background than any lit colour"
        # the peak block stays up when the sound goes, then falls
        vis.engine.samples = silence()
        vis.set_option("peak_fall", 5)
        settle(vis, 2)
        arr = pixels(vis)
        assert np.any(distance(arr[:, column], vis.colours.peak) < 40), "the peak block"
        top = segments - 1
        assert round(vis.peaks[loud] * segments) >= top - 1
    finally:
        vis.close()


def test_happy_particles_spark_on_an_onset_and_die_out():
    vis = visualizer(silence(), mode="particles")
    try:
        vis.reset_stars(seed=11)
        settle(vis, 5)
        assert vis.sparks is None or len(vis.sparks) == 0, "silence: no sparks"
        vis.engine.samples, vis.engine.playing = None, True
        settle(vis, 8)
        assert vis.sparks is not None and len(vis.sparks) > 0, "the beat throws sparks"
        assert len(vis.sparks) <= vis.SPARK_MAX
        heights = vis.sparks[:, 1].copy()
        vis.engine.playing, vis.engine.samples = False, silence()
        vis.tick()
        assert len(vis.sparks) and np.all(vis.sparks[:, 1] > heights.min()), "they rise"
        settle(vis, int(vis.SPARK_LIFE * vis.options["fps"]) + 3)
        assert len(vis.sparks) == 0, "and die out"
    finally:
        vis.close()


def test_happy_the_ribbon_twists_its_lines_and_turns_only_with_onsets():
    vis = visualizer(playing=True, mode="ribbon")
    try:
        settle(vis, 15)
        xs, ys = vis.ribbon_curves(vis.width(), vis.height())
        assert ys.shape == (vis.RIBBON_LINES, len(xs)) and len(xs) >= 32
        assert np.all((ys >= 0) & (ys <= vis.height()))
        spread = ys.max(axis=0) - ys.min(axis=0)
        inner = spread[len(spread) // 8: -len(spread) // 8]
        assert inner.min() < 0.35 * inner.max(), "the ribbon twists: its lines meet and part"
        turning = vis.phase
        settle(vis, 5)
        assert vis.phase != turning, "onsets turn it on"
        vis.engine.playing, vis.engine.samples = False, MUSIC[:MP.FRAME].copy()
        settle(vis, 2)
        held = vis.phase
        settle(vis, 10)
        assert vis.phase == held, "a still sound: a still ribbon"
    finally:
        vis.close()


def test_happy_ridges_keep_a_history_and_the_front_ridges_hide_the_ones_behind():
    vis = visualizer(playing=True, size=(400, 300), mode="ridges")
    try:
        vis.set_option("bars", 32)
        settle(vis, 5)
        assert vis.history.shape == (vis.HISTORY_ROWS, 32)
        assert vis.history[-1].any() and not vis.history[0].any(), "it fills from the front"
        rows = vis.HISTORY_ROWS
        layout = vis.ridge_layout(vis.width(), vis.height())
        assert len(layout) == rows
        assert all(a[0] < b[0] for a, b in zip(layout, layout[1:])), "back rows higher up"
        assert layout[0][3] - layout[0][2] < layout[-1][3] - layout[-1][2], "and narrower"
        x = int((layout[-1][2] + layout[-1][3]) / 2)  # the middle of the front ridge
        background = rgb(vis.colours.background)

        def column(front_loud: bool) -> np.ndarray:
            history = np.zeros_like(vis.history)
            history[0] = 1.0  # the back ridge as loud as can be
            if front_loud:
                history[-1] = 1.0
            vis.history = history
            vis.repaint()
            return pixels(vis)[:, x]

        base, reach = layout[-1][0], layout[-1][1]
        inside = slice(int(base - reach * 0.6) + 3, int(base) - 3)
        behind = column(False)[inside]
        assert np.any(behind != background), "the rows behind show there"
        hidden = column(True)[inside]
        assert np.all(hidden == background), "the front ridge hides them"
    finally:
        vis.close()


def test_happy_the_ridges_sun_grows_with_the_bass():
    vis = visualizer(silence(), size=(400, 300), mode="ridges")
    try:
        settle(vis, 3)
        quiet = vis.sun_layout(vis.width(), vis.height())
        assert quiet is not None
        vis.engine.samples = sine(60.0)
        vis.set_option("smoothing", 0)
        settle(vis, 3)
        loud = vis.sun_layout(vis.width(), vis.height())
        assert loud[2] > quiet[2] * 1.1
        cx, cy, radius = loud
        arr = pixels(vis)
        top = arr[int(cy - radius * 0.9):int(cy - radius * 0.1), int(cx)]
        assert np.any(distance(top, vis.colours.high) < 60) or \
            np.any(distance(top, vis.colours.mid) < 60), "the sun in the scheme's colours"
        tiny = visualizer(silence(), size=(300, 60), mode="ridges")
        try:
            assert tiny.sun_layout(tiny.width(), tiny.height()) is None, "no room: no sun"
        finally:
            tiny.close()
    finally:
        vis.close()


def test_happy_the_terrain_recedes_to_a_horizon():
    vis = visualizer(playing=True, size=(480, 270), mode="terrain")
    try:
        settle(vis, 30)
        xs, ys, base = vis.terrain_points(vis.width(), vis.height())
        rows = xs.shape[0]
        assert rows == vis.TERRAIN_ROWS and xs.shape == ys.shape == base.shape
        horizon = vis.terrain_horizon(vis.height())
        widths = xs[:, -1] - xs[:, 0]
        assert np.all(np.diff(widths) > 0), "the front rows are wider"
        assert np.all(np.diff(base[:, 0]) > 0), "and lower: further away is nearer the horizon"
        assert base[0, 0] > horizon and base[-1, 0] <= vis.height()
        assert np.all(ys <= base + 1e-6), "the sound rises above the ground"
        arr = pixels(vis)
        background = rgb(vis.colours.background)
        assert np.any(distance(arr, vis.colours.peak) < 40), "dots in the peak colour"
        vis.engine.playing, vis.engine.samples = False, silence()
        vis.set_option("smoothing", 0)
        vis.set_option("peak_fall", 300)
        settle(vis, vis.HISTORY_ROWS + 30)
        arr = pixels(vis)
        assert np.all(arr[:int(horizon) - 1] == background), "silence: the sky stays empty"
        assert np.any(arr[int(horizon) + 1:] != background), "the ground is there"
    finally:
        vis.close()


def test_happy_the_ring_is_seen_in_perspective_and_coloured_around_with_the_scheme():
    vis = visualizer(silence(), size=(480, 270), mode="ring")
    try:
        xs, ys, scales = vis.ring_layout(vis.width(), vis.height())
        n = len(vis.levels)
        assert len(xs) == len(ys) == len(scales) == n
        width, height = xs.max() - xs.min(), ys.max() - ys.min()
        assert height < 0.6 * width, "a tilted ring is an ellipse"
        front, back = int(np.argmax(ys)), int(np.argmin(ys))
        assert scales[front] > scales[back], "nearer bars are bigger"
        colours = vis.ring_colours()
        assert len(colours) == n and len(set(colours)) >= 3, "the colour goes round"
        assert all(colours[i] == colours[(n - i) % n] for i in range(n)), \
            "the colours go round and back: no seam where the circle closes"
        # the same level: the front bar is taller in pixels than the back one
        # (one bar at a time - the front and the back bar share a column)
        background = rgb(vis.colours.background)

        def bar_height(i):
            vis.levels = [0.0] * n
            vis.peaks = [0.0] * n
            vis.levels[i] = vis.peaks[i] = 0.8
            column = pixels(vis)[:int(ys[i]), int(round(xs[i]))]
            lit = np.nonzero(column != background)[0]
            return int(ys[i]) - int(lit.min()) if len(lit) else 0

        near, far = bar_height(front), bar_height(back)
        assert near > far * 1.5 > 0, (near, far)
        # the floor's ellipse lies under the bars whatever the bar count
        for bars in (8, 10, 13, 32):
            vis.set_option("bars", bars)
            xs_n, ys_n, _scales = vis.ring_layout(vis.width(), vis.height())
            cx, cy, rx, ry = vis._ring_frame(vis.width(), vis.height())
            assert np.allclose(((xs_n - cx) / rx) ** 2 + ((ys_n - cy) / ry) ** 2, 1.0), bars
    finally:
        vis.close()


@pytest.mark.parametrize("scheme", [*NAMED_SCHEMES, "theme", "custom"])
def test_edge_the_ring_colours_stay_readable_in_every_scheme(scheme):
    vis = visualizer(silence(), mode="ring")
    try:
        vis.set_custom_colours(LOW_CONTRAST)
        vis.set_scheme(scheme)
        background = vis.colours.background
        for colour in vis.ring_colours():
            assert MP.contrast_ratio(colour, background) >= MP.MIN_PEAK_CONTRAST, (scheme,
                                                                                   colour)
    finally:
        vis.close()


def _polar_matches(arr, cx, cy, radius, angle_map, background, tolerance=60):
    """The share of sampled points (r, a) whose colour matches the one at
    (r, angle_map(a)), among points where either is painted."""
    hits = total = 0
    h, w = arr.shape
    for r in np.linspace(radius * 0.1, radius * 0.95, 40):
        for a in np.linspace(0, 2 * math.pi, 180, endpoint=False):
            b = angle_map(a)
            x1, y1 = int(round(cx + r * math.cos(a))), int(round(cy + r * math.sin(a)))
            x2, y2 = int(round(cx + r * math.cos(b))), int(round(cy + r * math.sin(b)))
            if not (0 <= x1 < w and 0 <= y1 < h and 0 <= x2 < w and 0 <= y2 < h):
                continue
            p, q = arr[y1, x1], arr[y2, x2]
            if p == background and q == background:
                continue
            total += 1
            hits += int(distance(np.uint32(p), int(q)) <= tolerance)
    return hits / max(1, total), total


def test_happy_the_kaleidoscope_is_n_fold_and_mirror_symmetric_and_turns_with_onsets():
    vis = visualizer(playing=True, size=(400, 400), mode="kaleidoscope")
    try:
        settle(vis, 25)
        arr = pixels(vis)
        background = rgb(vis.colours.background)
        cx, cy = vis.width() / 2, vis.height() / 2
        radius = min(cx, cy)
        fold = vis.KALEIDO_FOLD
        assert fold >= 4
        turn, total = _polar_matches(arr, cx, cy, radius, lambda a: a + 2 * math.pi / fold,
                                     background)
        assert total > 300 and turn > 0.85, (turn, total)
        axis = vis.kaleido_rotation()
        mirror, total = _polar_matches(arr, cx, cy, radius, lambda a: 2 * axis - a, background)
        assert total > 300 and mirror > 0.85, (mirror, total)
        # not trivially symmetric: a turn by half the fold angle does not match
        half, _total = _polar_matches(arr, cx, cy, radius,
                                      lambda a: a + math.pi / fold / 2, background)
        assert half < turn - 0.1
        before = vis.kaleido_rotation()
        settle(vis, 5)
        assert vis.kaleido_rotation() != before, "onsets turn it"
    finally:
        vis.close()


def test_happy_bell_curves_rise_where_the_bands_sound():
    vis = visualizer(sine(1000.0), size=(480, 200), mode="bells")
    try:
        vis.set_option("smoothing", 0)
        settle(vis, 3)
        xs, ys, levels = vis.bell_shapes(vis.width(), vis.height())
        loud = int(np.argmax(levels))
        assert levels[loud] > 0.8 and ys.shape == xs.shape and ys.shape[0] == len(levels)
        assert len(levels) <= vis.BELLS_MAX
        top = ys[loud]
        assert top.argmin() == len(top) // 2, "a bump: highest in its middle"
        assert np.all(np.diff(top[: len(top) // 2 + 1]) <= 1e-9), "rising smoothly"
        arr = pixels(vis)
        background = rgb(vis.colours.background)
        far = [g for g in range(len(levels)) if abs(g - loud) > 3]
        band_x = int(xs[loud][len(top) // 2])
        row = int(vis.height() * 0.4)
        assert arr[row, band_x] != background, "the loud bump is drawn"
        far_x = [int(xs[g][len(top) // 2]) for g in far]
        assert all(arr[row, x] == background for x in far_x), "the quiet bands stay low"
    finally:
        vis.close()


# -- sad ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", NEW_FACES)
def test_sad_no_samples_silence_nan_and_inf_bars(mode):
    vis = visualizer(None, mode=mode)
    try:
        settle(vis, 3)
        vis.repaint()  # no numpy samples: an empty face, no error
        vis.engine.samples = silence()
        settle(vis, 3)
        vis.repaint()
        n = vis.options["bars"]
        broken = np.full(n, np.nan, np.float32)
        broken[::3] = np.inf
        broken[1::3] = -np.inf
        vis.engine.bars_override = broken
        settle(vis, 3)
        assert all(math.isfinite(v) and 0.0 <= v <= 1.0 for v in vis.levels), vis.levels
        assert all(math.isfinite(v) and 0.0 <= v <= 1.0 for v in vis.peaks)
        assert math.isfinite(vis.phase)
        if mode in ("ridges", "terrain"):
            assert np.isfinite(vis.history).all()
        vis.repaint()
        vis.engine.bars_override = [0.5]  # fewer bars than asked for
        settle(vis, 2)
        vis.repaint()
    finally:
        vis.close()


@pytest.mark.parametrize("mode", NEW_FACES)
def test_sad_a_zero_and_a_tiny_size_paint_without_error(mode):
    vis = visualizer(sine(200.0), size=(1, 1), mode=mode)
    try:
        vis.setMinimumHeight(0)
        for size in ((0, 0), (1, 1), (7, 7), (8, 8), (9, 300), (300, 9)):
            vis.resize(*size)
            settle(vis, 2)
            image = QImage(max(1, size[0]), max(1, size[1]),
                           QImage.Format.Format_ARGB32_Premultiplied)
            vis.render(image)
    finally:
        vis.close()


@pytest.mark.parametrize("mode", NEW_FACES)
def test_sad_without_numpy_a_new_face_stays_empty(monkeypatch, mode):
    """Playback works without numpy (the visualizations need it): a new
    face then shows its background, as the old ones do - no error."""
    monkeypatch.setattr(MP, "np", None)
    vis = MP.Visualizer(Engine(None))
    vis.resize(320, 180)
    vis.show()
    try:
        vis.set_mode(mode, announce=False)
        vis._label_until = 0.0
        vis.tick()
        arr = pixels(vis)  # paints
        assert np.all(arr == rgb(vis.colours.background)), mode
    finally:
        vis.close()


def test_sad_without_numpy_every_face_paints_without_error(monkeypatch):
    """A face added later is held too: an exception in paintEvent would
    abort the process."""
    monkeypatch.setattr(MP, "np", None)
    vis = MP.Visualizer(Engine(None))
    vis.resize(320, 180)
    vis.show()
    try:
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode, announce=False)
            vis.tick()
            assert vis.grab().width() == 320, mode
    finally:
        vis.close()


def test_edge_the_cached_pictures_go_with_their_face():
    """The LED and particle faces draw from pictures of the whole window
    (three of them for the particles: 100 MB at 4K): another face lets
    them go."""
    vis = visualizer(playing=True, mode="particles")
    try:
        settle(vis, 2)
        vis.grab()
        assert vis._sprites is not None
        vis.set_mode("ribbon", announce=False)
        assert vis._sprites is None
        vis.set_mode("led", announce=False)
        vis.grab()
        assert vis._sprites is not None and vis._sprites[0][0] == "led"
    finally:
        vis.close()


def test_sad_an_unknown_face_name_is_refused():
    vis = visualizer(sine())
    try:
        for name in ("plasma", "", "LED", None):
            with pytest.raises(ValueError):
                vis.set_mode(name)
        assert vis.mode == "spectrum"
    finally:
        vis.close()


# -- edge ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode", NEW_FACES)
def test_edge_a_huge_window_and_the_option_limits(mode):
    vis = visualizer(playing=True, size=(640, 360), mode=mode)
    try:
        for name, (low, high, _default) in MP.VISUAL_OPTIONS.items():
            for value in (low, high):
                vis.set_option(name, value)
                settle(vis, 3)
                assert painted_share(vis) > 0.005, (mode, name, value)
        vis.resize(3840, 2160)
        image = QImage(3840, 2160, QImage.Format.Format_ARGB32_Premultiplied)
        image.fill(0)
        settle(vis, 2)
        vis.render(image)
        assert len(np.unique(pixels(image))) > 3, "a 4K frame shows the face"
    finally:
        vis.close()


@pytest.mark.parametrize("mode", NEW_FACES)
def test_edge_every_scheme_shows_its_colours_and_a_readable_part(mode):
    vis = visualizer(playing=True, mode=mode)
    try:
        vis.set_custom_colours(LOW_CONTRAST)
        for scheme in (*NAMED_SCHEMES, "theme", "custom"):
            vis.set_scheme(scheme)
            settle(vis, 15)
            arr = pixels(vis)
            colours = vis.colours
            assert np.any(arr == rgb(colours.background)), (mode, scheme)
            anchors = (colours.low, colours.mid, colours.high, colours.peak)
            assert any(np.any(distance(arr, a) < 40) for a in anchors), (mode, scheme)
            assert readable_share(vis) > 0.0005, (mode, scheme, "nothing readable")
    finally:
        vis.close()


def test_edge_a_new_bar_count_resets_the_history_sparks_and_cached_pictures():
    vis = visualizer(playing=True, mode="ridges")
    try:
        settle(vis, 5)
        vis.set_option("bars", 16)
        assert vis.history.shape == (vis.HISTORY_ROWS, 16) and not vis.history.any()
        vis.set_mode("particles", announce=False)
        settle(vis, 10)
        vis.set_option("bars", 64)
        assert vis.sparks is None or len(vis.sparks) == 0
        for mode, size in (("led", (500, 260)), ("particles", (520, 240))):
            vis.set_mode(mode, announce=False)
            settle(vis, 2)
            vis.grab()  # paints (an offscreen repaint() need not)
            first = vis._sprites
            assert first is not None and first[0][0] == mode
            vis.resize(*size)
            vis.grab()
            assert vis._sprites is not first and vis._sprites[0][1:3] == size
            vis.set_scheme("fire" if vis.scheme != "fire" else "ice")
            assert vis._sprites is None, "a new scheme draws them anew"
    finally:
        vis.close()


# -- the panel: menu, fullscreen, detach, saved state -------------------------------------------


def make_panel(tmp_path, engine=None):
    state = tmp_path / "cfg" / "media_player.json"
    panel = MP.PlayerPanel(engine=engine or Engine(playing=True), state_path=str(state))
    panel.resize(700, 760)
    panel.show()
    return panel, state


def close(panel):
    panel.shutdown()
    panel.close()
    APP.processEvents()


def actions_by_data(menu):
    found = {}
    for action in menu.actions():
        if action.menu() is not None:
            found.update(actions_by_data(action.menu()))
        elif action.data() is not None:
            found[action.data()] = action
    return found


def choose_in_menu(menu: QMenu, title: str, data) -> None:
    """Go through the real popup with the keys a user presses: Down onto
    the submenu entry *title*, Right opens it, Down onto the entry carrying
    *data*, Return chooses it."""
    entry = next(a for a in menu.actions() if a.text() == title)
    while menu.activeAction() is not entry:
        QTest.keyClick(menu, Qt.Key.Key_Down)
    QTest.keyClick(menu, Qt.Key.Key_Right)
    sub = entry.menu()
    assert wait(sub.isVisible, 3), "the submenu opens"
    target = next(a for a in sub.actions() if a.data() == data)
    for _ in range(len(sub.actions())):
        if sub.activeAction() is target:
            break
        QTest.keyClick(sub, Qt.Key.Key_Down)
    assert sub.activeAction() is target
    QTest.keyClick(sub, Qt.Key.Key_Return)


def test_e2e_happy_a_new_face_through_the_real_context_menu_fullscreen_and_detached(tmp_path):
    panel, state = make_panel(tmp_path)
    vis = panel.visualizer
    try:
        for mode in NEW_FACES:
            APP.sendEvent(vis, QContextMenuEvent(QContextMenuEvent.Reason.Mouse, QPoint(10, 10),
                                                 vis.mapToGlobal(QPoint(10, 10))))
            assert vis.menu is not None and vis.menu.isVisible()
            choose_in_menu(vis.menu, MP.tr("Visualization"), ("mode", mode))
            assert vis.mode == mode, mode
            assert wait(lambda: not vis.menu.isVisible(), 3)
            assert actions_by_data(vis.build_menu())[("mode", mode)].isChecked()
        vis.set_mode("kaleidoscope", announce=False)
        settle(vis, 10)
        vis.setFocus()
        QTest.keyClick(vis, Qt.Key.Key_F11)
        assert panel.is_fullscreen and vis.window() is panel.visual_window
        assert vis.mode == "kaleidoscope"
        APP.processEvents()
        settle(vis, 5)
        assert painted_share(vis) > 0.01, "the fullscreen frame shows the face"
        QTest.keyClick(vis, Qt.Key.Key_Escape)
        assert not panel.is_fullscreen and panel.isAncestorOf(vis)
        actions_by_data(vis.build_menu())[("mode", "terrain")].trigger()
        actions_by_data(vis.build_menu())[("window", "detach")].trigger()
        window = panel.visual_window
        assert window is not None and vis.window() is window
        window.resize(800, 450)
        APP.processEvents()
        settle(vis, 30)
        frame = vis.grab()
        assert frame.width() >= 780 and vis.mode == "terrain"
        assert painted_share(vis) > 0.01
        actions_by_data(vis.build_menu())[("window", "attach")].trigger()
        assert panel.visual_window is None and panel.isAncestorOf(vis)
        # the settings dialog offers them too
        panel.open_visual_settings()
        box = panel.visual_settings.mode_box
        assert [box.itemData(i) for i in range(box.count())] == list(MP.Visualizer.MODES)
        box.setCurrentIndex(box.findData("bells"))
        assert vis.mode == "bells"
    finally:
        close(panel)
    assert json.loads(state.read_text(encoding="utf-8"))["visualizer"] == "bells"
    again, _state = make_panel(tmp_path)
    try:
        assert again.visualizer.mode == "bells", "the new face comes back"
    finally:
        close(again)


@pytest.mark.parametrize("saved", ["plasma", "", 5, None, ["led"], "LED"])
def test_sad_an_unknown_or_removed_saved_face_falls_back_to_the_default(tmp_path, saved):
    state = tmp_path / "cfg" / "media_player.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"version": 1, "visualizer": saved}), encoding="utf-8")
    panel = MP.PlayerPanel(engine=Engine(sine()), state_path=str(state))
    try:
        assert panel.visualizer.mode == MP.Visualizer.MODES[0]
    finally:
        panel.close()
