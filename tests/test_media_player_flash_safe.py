"""The Media Player's visualizations are photosensitivity-safe: at most three
flashes (six transitions) in any second, and no flashing in saturated red
(WCAG 2.3.1 / 2.3.2), whatever the sound does.

Review (round 1 of the release reviews): nothing measured it. Under a flash
meter (tests/flash_meter.py, the reading of axross-amp's) a sound gated at
6 Hz - a trance gate, a strobing synth, 16th notes - flashed the spectrum,
the radial and line spectrum, the VU meter, the LED equalizer, the ring and
the bells 12 times a second, at 10 Hz 20 times, in the Classic scheme's
saturated red too; the stereo scope flashed 18-21 times a second in steady
white noise (radio static), and the kaleidoscope turned its petals by up to
86 degrees in one frame at every beat.

Now each value a face draws from may turn at most FlashLimiter.BUDGET times
a second (held, it stays where it turned), the waterfall's rows and the
traces' size likewise, the onset phase turns at most MAX_TURN a second, the
stereo scope draws dots, and no dense trace nor level colour is a saturated
red. A single beat after silence still shows at once.

Round 2 measured music too (MusicEngine: a gated synth, noise that differs
left and right, antiphase, 30 ms bursts) in every scheme, at 60 frames a
second and in small faces: see the tests from WORST_MUSIC on.
"""

from __future__ import annotations

import importlib.util
import math
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)  # or no libpulse.so.0

from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402
from flash_meter import ALLOWED, FlashMeter  # noqa: E402

APP = QApplication.instance() or QApplication([])
WIDTH, HEIGHT = 480, 270


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_flash_safe_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()
FACES = tuple(MP.Visualizer.MODES)


class GatedEngine:
    """Every bar (and the samples: white noise) on and off *hz* times a
    second - the hardest sound for a flash rule. *pattern*: "all" together,
    "oddeven" (every other bar the other way), "halves" (the low half
    against the high half). *hz* 0: always on."""

    def __init__(self, fps: int, hz: float, pattern: str = "all") -> None:
        self.frame, self.fps, self.hz, self.pattern = 0, fps, hz, pattern
        self.rng = np.random.default_rng(7)

    def _on(self) -> bool:
        return math.floor(self.frame / self.fps * self.hz * 2) % 2 == 0

    def current_bars(self, n=32):
        on = self._on()
        bars = np.full(n, 1.0 if on else 0.0, np.float32)
        if self.pattern == "oddeven":
            bars[1::2] = 0.0 if on else 1.0
        elif self.pattern == "halves":
            bars[n // 2:] = 0.0 if on else 1.0
        return bars

    def current_samples(self):
        if not self._on():
            return np.zeros((MP.FRAME, 2), np.float32)
        return self.rng.uniform(-0.9, 0.9, (MP.FRAME, 2)).astype(np.float32)


def _pixels(image: QImage) -> np.ndarray:
    image = image.convertToFormat(QImage.Format.Format_RGB888)
    data = np.frombuffer(image.constBits().asstring(image.sizeInBytes()), np.uint8)
    rows = data.reshape(image.height(), image.bytesPerLine())
    return rows[:, : image.width() * 3].reshape(image.height(), image.width(), 3)


class MusicEngine:
    """The worst music for a flash rule, as samples and the bars the player
    works out of them (spectrum_bars), FRAME samples ending at the frame's
    time. *signal*:

    - ``gate<hz>``: a synth chord (square waves, a little noise) gated on
      and off *hz* times a second - a trance gate;
    - ``noise``: steady white noise that differs between left and right;
    - ``antiphase``: white noise, the right channel the left one inverted;
    - ``lrgate<hz>`` / ``antigate<hz>``: those noises gated *hz* times a second;
    - ``swap<hz>``: noise in the left channel, then in the right, *hz* times
      a second;
    - ``burst<n>``: bursts of noise 30 ms long, *n* a second;
    - ``trem<hz>``: the synth chord with a tremolo of 4 dB *hz* times a
      second - moves of the bars just under the flash guard's step."""

    def __init__(self, fps: int, signal: str, seed: int = 11) -> None:
        self.frame, self.fps, self.signal = 0, fps, signal
        self.rng = np.random.default_rng(seed)

    def current_samples(self):
        n = MP.FRAME
        t = self.frame / self.fps - n / MP.RATE + np.arange(n) / MP.RATE
        signal = self.signal
        number = float("".join(c for c in signal if c.isdigit() or c == ".") or 0)
        gate = (np.floor(t * number * 2) % 2 == 0) if number else np.ones(n, bool)
        noise = self.rng.uniform(-0.95, 0.95, (n, 2))
        if signal.startswith(("gate", "trem")):
            tone = sum(np.sign(np.sin(2 * np.pi * f * t)) for f in (110, 220, 330, 440)) / 4
            if signal.startswith("trem"):
                gate = np.where(gate, 1.0, 10 ** (-4 / 20))
            mono = (0.7 * tone + 0.3 * noise[:, 0]) * gate * 0.9
            out = np.column_stack([mono, mono])
        elif signal.startswith(("noise", "lrgate")):
            out = noise * gate[:, None]
        elif signal.startswith(("antiphase", "antigate")):
            out = np.column_stack([noise[:, 0], -noise[:, 0]]) * gate[:, None]
        elif signal.startswith("swap"):
            out = np.column_stack([noise[:, 0] * gate, noise[:, 0] * ~gate])
        elif signal.startswith("burst"):
            out = noise * (((t * number) % 1.0) < 0.030 * number)[:, None]
        else:
            raise ValueError(signal)
        return out.astype(np.float32)

    def current_bars(self, n=32):
        return MP.spectrum_bars(self.current_samples(), MP.RATE, n)


def measure(face: str, hz: float, *, scheme: str = "classic", fps: int = 30,
            smoothing: int | None = None, pattern: str = "all", seconds: float = 2.0,
            custom=None, music: str | None = None, seed: int = 11,
            size: tuple[int, int] = (WIDTH, HEIGHT)) -> tuple[int, int]:
    """(luminance, red): the most transitions in any second of *face*, at
    *size*, fed by GatedEngine (*hz*, *pattern*) or, given *music*, by
    MusicEngine."""
    engine = MusicEngine(fps, music, seed) if music else GatedEngine(fps, hz, pattern)
    width, height = size
    vis = MP.Visualizer(engine)
    try:
        vis.resize(width, height)
        vis.set_option("fps", fps)
        if smoothing is not None:
            vis.set_option("smoothing", smoothing)
        if custom:
            vis.set_custom_colours(custom)
        vis.set_scheme(scheme)
        vis.set_mode(face, announce=False)
        meter = FlashMeter(width, height, fps)
        image = QImage(width, height, QImage.Format.Format_RGB32)
        for frame in range(round(seconds * fps)):
            engine.frame = frame
            vis.tick()
            vis.render(image)
            meter.push(_pixels(image))
        return meter.worst("luminance"), meter.worst("red")
    finally:
        vis.deleteLater()


def _assert_safe(face, result, **how):
    luminance, red = result
    assert luminance <= ALLOWED and red <= ALLOWED, (
        f"{face} {how}: {luminance} transitions of luminance, {red} of red in a second "
        f"(WCAG allows {ALLOWED})")


# -- the meter itself ---------------------------------------------------------------------


def _toggle(colour, hz: float, fps: int = 30, seconds: float = 2.0) -> tuple[int, int]:
    meter = FlashMeter(96, 54, fps)
    for frame in range(round(seconds * fps)):
        on = math.floor(frame / fps * hz * 2) % 2 == 0
        meter.push(np.full((54, 96, 3), colour if on else (0, 0, 0), np.uint8))
    return meter.worst("luminance"), meter.worst("red")


def test_meter_counts_a_full_screen_flash_and_a_red_one():
    assert _toggle((255, 255, 255), 5.0)[0] >= 9  # 10 transitions a second
    assert _toggle((255, 255, 255), 1.0)[0] <= 2
    luminance, red = _toggle((255, 0, 0), 5.0)
    assert red >= 9
    assert _toggle((0, 255, 0), 5.0)[1] == 0  # no red in green


def test_meter_lets_a_thin_moving_line_through():
    meter = FlashMeter(96, 54, 30)
    for frame in range(60):
        picture = np.zeros((54, 96, 3), np.uint8)
        picture[:, (frame * 7) % 96] = 255
        meter.push(picture)
    assert meter.worst() == 0


# -- the guard ----------------------------------------------------------------------------


def test_limiter_turns_at_most_its_budget_a_second():
    guard = MP.FlashLimiter()
    turns, last, direction = 0, None, 0
    for frame in range(300):  # 10 s at 30 fps, a 10 Hz square wave
        target = 1.0 if (frame // 1.5) % 2 == 0 else 0.0
        shown = float(guard.step([target], frame / 30)[0])
        if last is not None and abs(shown - last) >= MP.FlashLimiter.STEP:
            way = 1 if shown > last else -1
            if way != direction:
                turns += 1
                direction = way
        last = shown
    assert turns <= MP.FlashLimiter.BUDGET * 10 + 1


def test_limiter_leaves_small_moves_and_a_single_beat_alone():
    guard = MP.FlashLimiter()
    assert guard.step([0.0, 0.5], 0.0).tolist() == [0.0, 0.5]
    assert guard.step([1.0, 0.52], 1 / 30).tolist() == [1.0, 0.52]  # a beat: at once
    assert guard.step([0.2, 0.49], 2 / 30).tolist() == [0.2, 0.49]
    shown = guard.step([np.nan, 5.0], 3 / 30)
    assert np.isfinite(shown).all() and (0 <= shown).all() and (shown <= 1).all()


def test_no_level_colour_and_no_dense_trace_is_a_saturated_red():
    def saturated(colour: str) -> bool:
        from PyQt6.QtGui import QColor

        c = QColor(colour)
        light = [(v / 12.92) if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
                 for v in (c.redF(), c.greenF(), c.blueF())]
        return sum(light) > 0 and light[0] / sum(light) >= 0.8

    assert saturated("#e74c3c")  # Classic's loud colour is one
    for scheme in MP.SCHEME_NAMES:
        vis = MP.Visualizer(GatedEngine(30, 0))
        try:
            vis.set_custom_colours({"background": "#000000", "low": "#ff0000",
                                    "high": "#ff0000", "peak": "#ffffff"})
            vis.set_scheme(scheme)
            colours = [c.name() for c in vis._level_colours()]
            assert not any(saturated(c) for c in colours), scheme
            assert not saturated(vis._dense_colour), scheme
            assert not saturated(vis._colour("trace").name()), scheme
        finally:
            vis.deleteLater()


def test_happy_a_beat_after_silence_still_shows_at_once():
    class Beat:
        bars = np.zeros(32, np.float32)

        def current_bars(self, n=32):
            return self.bars[:n]

    engine = Beat()
    vis = MP.Visualizer(engine)
    try:
        for _ in range(30):
            vis.tick()
        engine.bars = np.ones(32, np.float32)
        vis.tick()
        assert min(vis.levels) == 1.0
    finally:
        vis.deleteLater()


# -- every face ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES)
@pytest.mark.parametrize("hz", [6.0, 10.0])
def test_safety_no_face_flashes_with_a_gated_sound(face, hz):
    _assert_safe(face, measure(face, hz), hz=hz)


@pytest.mark.parametrize("face", FACES)
def test_safety_no_face_flashes_in_the_fire_scheme(face):
    _assert_safe(face, measure(face, 6.0, scheme="fire"), scheme="fire")


@pytest.mark.parametrize("face", ("scope", "lissajous", "vu", "spectrum", "waterfall", "led",
                                  "particles", "kaleidoscope"))
def test_safety_no_face_flashes_in_steady_white_noise(face):
    _assert_safe(face, measure(face, 0.0, scheme="fire"), noise="steady")


@pytest.mark.parametrize("face", ("spectrum", "radial", "vu", "line", "led", "ring", "bells",
                                  "kaleidoscope", "lissajous", "scope", "waterfall"))
def test_safety_the_fastest_settings_do_not_flash_either(face):
    _assert_safe(face, measure(face, 8.0, fps=60, smoothing=0), fps=60, smoothing=0)


@pytest.mark.parametrize("face", ("spectrum", "mirror", "radial", "polar", "ring", "bells", "led"))
@pytest.mark.parametrize("pattern", ["oddeven", "halves"])
def test_safety_bars_in_antiphase_do_not_flash(face, pattern):
    _assert_safe(face, measure(face, 6.0, pattern=pattern), pattern=pattern)


@pytest.mark.parametrize("face", ("spectrum", "radial", "line", "bells", "lissajous", "vu"))
def test_safety_a_custom_red_and_white_scheme_does_not_flash(face):
    custom = {"background": "#000000", "low": "#ff0000", "high": "#ffffff", "peak": "#ffffff"}
    _assert_safe(face, measure(face, 6.0, scheme="custom", custom=custom), scheme="red/white")


def _red_share(colour) -> float:
    c = QColor(colour)
    light = [(v / 12.92) if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
             for v in (c.redF(), c.greenF(), c.blueF())]
    return light[0] / sum(light) if sum(light) > 0 else 0.0


def test_edge_level_colours_change_smoothly_where_a_gradient_nears_red():
    """Review (round 2): a level colour just under the saturated-red
    threshold (0.8) was kept, the next one, just over it, was mixed with
    white to 0.79 - so a level moving by one step about there, or a
    gradient crossing the threshold again and again as its channels round,
    changed the bar's colour back and forth. Now every colour's red share
    is its own, capped where the mixed ones land: either side of the cap
    are neighbours."""
    customs = [None, {"background": "#000000", "low": "#ff0000", "high": "#ffffff",
                      "peak": "#ffffff"},
               {"background": "#000000", "low": "#202020", "high": "#ff2000",
                "peak": "#ffffff"}]
    for scheme in MP.SCHEME_NAMES:
        for custom in (customs if scheme == "custom" else [None]):
            vis = MP.Visualizer(GatedEngine(30, 0))
            try:
                if custom:
                    vis.set_custom_colours(custom)
                vis.set_scheme(scheme)
                last = MP.Visualizer.LEVEL_STEPS - 1
                for i, shown in enumerate(vis._level_colours()):
                    own = _red_share(vis._level_hex(i / last))
                    capped = min(own, MP.FLASH_SAFE_RED)
                    assert abs(_red_share(shown) - capped) <= 0.005, (
                        scheme, custom, i, vis._level_hex(i / last), shown.name())
            finally:
                vis.deleteLater()


# -- the worst music, in every scheme (review round 2) ------------------------------------

#: The signals of MusicEngine a face is measured with.
WORST_MUSIC = ("gate6", "gate8", "gate10", "noise", "antiphase", "burst3", "burst8",
               "lrgate8", "antigate8", "swap4", "trem8")
RED_AND_WHITE = {"background": "#000000", "low": "#ff0000", "high": "#ffffff", "peak": "#ffffff"}
SCHEME_NAMES_ORDER = tuple(MP.SCHEME_NAMES)
#: A media player in a narrow dock, a short strip, the default size, a big window.
DOCK_SIZES = ((120, 90), (200, 150), (320, 180), (640, 120), (WIDTH, HEIGHT))


@pytest.mark.parametrize("face", FACES)
def test_safety_no_face_flashes_with_the_worst_music_in_any_scheme(face):
    """Each face with half the signals of WORST_MUSIC, each in another
    colour scheme (or a red and white custom one): the faces take them in
    turn, so every signal and every scheme is seen with many faces without
    running every triple (the CPU of a test run is shared)."""
    schemes = [*SCHEME_NAMES_ORDER, "redwhite"]
    index = FACES.index(face)
    failures = []
    for k, music in enumerate(WORST_MUSIC):
        if (k + index) % 2:
            continue
        scheme = schemes[(k + index) // 2 % len(schemes)]
        custom = RED_AND_WHITE if scheme == "redwhite" else None
        result = measure(face, 0.0, music=music, custom=custom,
                         scheme="custom" if custom else scheme)
        if max(result) > ALLOWED:
            failures.append((music, scheme, result))
    assert not failures, f"{face}: {failures}"


@pytest.mark.parametrize("face", ("scope", "lissajous", "vu"))
@pytest.mark.parametrize("music", ("noise", "lrgate8", "antiphase", "swap4"))
def test_safety_the_scopes_do_not_flash_with_stereo_noise_at_any_size(face, music):
    """Review (round 2): stereo white noise that differs left and right
    broke a scope in another player. Here the stereo scope stood still,
    but the oscilloscope in a dock-sized face (320 x 180 or less) flashed
    14-24 times a second: a trace of a point every pixel or so, a new
    zigzag of noise every frame, filled most of the face and emptied it."""
    failures = [(size, result) for size in DOCK_SIZES
                for result in [measure(face, 0.0, music=music, scheme="fire", size=size)]
                if max(result) > ALLOWED]
    assert not failures, failures


@pytest.mark.parametrize("music", ("gate6", "gate8", "gate10", "burst8"))
def test_safety_the_bells_of_a_small_face_do_not_flash(music):
    """Review (round 2): in a face of 120 x 90 the 32 bells were under 4 px
    wide, their flanks so steep and close that a level's move under the
    flash guard's step shifted every outline: 18 flashes a second with a
    synth gated at 10 Hz (200 x 150: 9). A bell is now BELL_WIDTH px at
    least."""
    failures = [(size, result) for size in ((120, 90), (200, 150), (320, 180))
                for result in [measure("bells", 0.0, music=music, size=size)]
                if max(result) > ALLOWED]
    assert not failures, failures


@pytest.mark.parametrize("face", ("kaleidoscope", "line", "spectrum", "bells"))
@pytest.mark.parametrize("music", ("gate6", "gate8"))
def test_safety_a_gated_synth_at_the_fastest_settings_does_not_flash(face, music):
    """Review (round 2): at 60 frames a second without smoothing a synth
    gated at 6 or 8 Hz flashed the kaleidoscope 7-8 times a second and the
    line spectrum 7: each bar kept to its own five turns a second, but the
    bars took them in different frames, and together they turned the
    picture more often. The bars now turn in the same frames
    (FlashLimiter(together=True))."""
    _assert_safe(face, measure(face, 0.0, music=music, fps=60, smoothing=0),
                 music=music, fps=60)


def test_limiter_together_turns_every_value_in_the_same_frames():
    guard = MP.FlashLimiter(together=True)
    frames_with_turns = set()
    last = None
    for frame in range(60):  # 2 s at 30 fps; each value flips at its own time
        values = [1.0 if ((frame + k) // 2) % 2 else 0.0 for k in range(4)]
        shown = guard.step(values, frame / 30)
        if last is not None and np.any(np.abs(shown - last) >= MP.FlashLimiter.STEP):
            frames_with_turns.add(frame)
        last = shown.copy()
    turns = sorted(frames_with_turns)
    assert len(turns) >= 2 * MP.FlashLimiter.BUDGET - 1  # it does turn
    # evenly: a frame of turns every 1 / BUDGET s at most (not five at once,
    # then none for the rest of the second)
    assert min(b - a for a, b in zip(turns, turns[1:])) >= 30 / MP.FlashLimiter.BUDGET - 1e-9


@pytest.mark.parametrize("music", ("gate7", "gate8"))
def test_safety_the_waterfall_in_a_red_scheme_does_not_flash_red(music):
    """Review (round 2): the waterfall's colours ran from the background
    over the bar colours as they are - a custom scheme's red quiet bars
    made most of the face a saturated red, which (WCAG 2.3.2) flashes at
    the least change: 10 red transitions a second at 60 frames a second
    with a synth gated at 8 Hz (the noise in it decides: several seeds).
    Its colours are now flash_safe_colour's, like the level colours."""
    for seed in (1, 3, 5, 6, 8):
        _assert_safe("waterfall", measure("waterfall", 0.0, music=music, fps=60, smoothing=0,
                                          scheme="custom", custom=RED_AND_WHITE, seed=seed),
                     music=music, seed=seed)


@pytest.mark.parametrize("music", ("swap2", "swap4", "swap6"))
def test_safety_the_vu_meter_does_not_flash_with_noise_going_left_right(music):
    """Review (round 2): noise in the left channel, then in the right, a
    few times a second, at 60 frames a second: each bar of the VU meter
    rose as the other fell, each on its own budget of turns, and a third
    of the face over both saw both - 10 transitions a second. The two bars
    (and their peaks) now turn in the same frames, three a second."""
    for seed in (11, 2):
        _assert_safe("vu", measure("vu", 0.0, music=music, fps=60, seed=seed), music=music,
                     seed=seed)


@pytest.mark.parametrize("music", ("gate10", "burst8"))
def test_safety_the_terrain_of_a_small_face_does_not_flash(music):
    """Review (round 2): a 120 x 90 face drew the terrain's 22 rows a few
    pixels apart; a level's least move (under the flash guard's step)
    shifted every line - 8 to 10 flashes a second with a synth gated at
    10 Hz. A row now takes TERRAIN_ROW_PX px at least."""
    for seed in (1, 3, 11):
        _assert_safe("terrain", measure("terrain", 0.0, music=music, size=(120, 90), seed=seed),
                     music=music, seed=seed)
