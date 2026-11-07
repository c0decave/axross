"""The visualizer's faces cost less per frame.

Feedback: every visualization has to be measured and optimized. Measured
(scripts/bench_visualizer.py, old and new loaded side by side, CPU time of
the GUI thread, the smallest median of 12 interleaved rounds, 1920x1080,
128 bars, white noise): all faces together 94 -> 60 ms a frame (-36 %), at
the panel's size (480x200, 32 bars) 17.4 -> 13.3 ms (-24 %); with two
Python threads busy (transfers) 306 -> 199 ms (-35 %). The line spectrum
11.4 -> 2.9 ms, the polar spectrum 12.6 -> 3.6, the stereo scope 11.4 ->
5.6, the oscilloscope 3.8 -> 1.8.

Where it went, and what these tests pin:

* a colour per bar was mixed each frame (two QColor and a name() a bar):
  now a table of 256 per scheme (``Visualizer._level_colours``);
* a fillRect per bar and per peak (256-512 calls): now one drawRects per
  brush;
* traces drawn as separate segments with a 1.2-1.5 px pen (a QLineF per
  segment, the path stroker per segment): now one polyline TRACE_WIDTH wide;
* a large antialiased gradient fill (7.5 of 10.6 ms of the line spectrum):
  now filled without antialiasing and its edge drawn as a one pixel
  antialiased line in the same gradient (``_fill_with_smooth_edge``);
* Qt painted the parent's background under the face each frame, which
  paints every pixel itself: now WA_OpaquePaintEvent.

Not changed, measured without a gain: the particle columns and the LED
equalizer as pixmap fragments (one call) instead of a blit per bar, the
kaleidoscope's twelve copies merged into one path per layer (slower), the
terrain's columns as one path (within the noise).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)  # or no libpulse.so.0

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QColor, QImage, QLinearGradient, QPainter  # noqa: E402

from tests.test_media_player_visual_modes import MP, SampleEngine, noise, settle  # noqa: E402


class Recorder:
    """A painter that records the calls a face makes (and draws nothing)."""

    def __init__(self, real: QPainter) -> None:
        self.calls: list[str] = []
        self._real = real

    def __getattr__(self, name):
        attr = getattr(self._real, name)
        if not callable(attr):
            return attr

        def call(*args, **kwargs):
            self.calls.append(name)
            if name in ("fontMetrics", "font", "device", "transform", "pen", "brush"):
                return attr(*args, **kwargs)
            return None

        return call

    def count(self, *names: str) -> int:
        return sum(1 for c in self.calls if c in names)


def _face(mode: str, bars: int = 128, size=(1920, 1080)):
    vis = MP.Visualizer(SampleEngine(noise()))
    vis.resize(*size)
    vis.set_option("bars", bars)
    vis.set_mode(mode, announce=False)
    settle(vis, 6)
    return vis


def _record(vis) -> Recorder:
    image = QImage(vis.width(), vis.height(), QImage.Format.Format_ARGB32_Premultiplied)
    painter = QPainter(image)
    try:
        recorder = Recorder(painter)
        getattr(vis, f"_paint_{vis.mode}")(recorder)
    finally:
        painter.end()
    return recorder


DRAWS = ("fillRect", "drawRects", "drawLine", "drawLines", "drawPolyline", "drawPolygon",
         "drawPath", "drawImage", "drawPoints", "drawEllipse", "drawText")


# -- happy ------------------------------------------------------------------------------------


@pytest.mark.parametrize("mode, most", [("spectrum", 2), ("mirror", 3)])
def test_happy_the_bar_faces_draw_in_a_few_calls_whatever_the_bar_count(mode, most):
    for bars in (16, 128):
        vis = _face(mode, bars)
        try:
            assert _record(vis).count(*DRAWS) <= most, bars
        finally:
            vis.close()


def test_happy_the_radial_peaks_are_one_call_and_the_rays_take_their_colour_from_a_table():
    vis = _face("radial")
    try:
        recorder = _record(vis)
        assert recorder.count("drawRects") == 1
        assert recorder.count("fillRect") == 0
        assert recorder.count("drawLine") == len(vis.levels)
    finally:
        vis.close()


@pytest.mark.parametrize("mode, polylines", [("scope", 1),
                                             ("lissajous", MP.Visualizer.LISSAJOUS_FADE),
                                             ("line", 2), ("polar", 2)])
def test_happy_traces_are_polylines_not_a_line_a_segment(mode, polylines):
    vis = _face(mode)
    try:
        recorder = _record(vis)
        assert recorder.count("drawLines") == 0
        assert recorder.count("drawPolyline") == polylines
    finally:
        vis.close()


def test_happy_the_table_colour_is_the_mixed_one_within_a_channel_step():
    vis = _face("radial", size=(320, 160))
    try:
        for i in range(0, 1001):
            level = i / 1000
            exact = QColor(vis._level_hex(level))
            table = vis._level_colour(level)
            assert max(abs(exact.red() - table.red()), abs(exact.green() - table.green()),
                       abs(exact.blue() - table.blue())) <= 1, level
    finally:
        vis.close()


def test_happy_every_face_paints_every_pixel_so_the_widget_may_be_opaque():
    """WA_OpaquePaintEvent: Qt no longer paints anything under the face, so
    a pixel the face leaves out would show what was there before."""
    vis = _face("spectrum", 32, (360, 200))
    sentinel = QColor(255, 0, 255)
    try:
        assert vis.testAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        for mode in MP.Visualizer.MODES:
            vis.set_mode(mode, announce=False)
            settle(vis, 4)
            image = QImage(vis.size(), QImage.Format.Format_ARGB32_Premultiplied)
            image.fill(sentinel)
            vis.render(image)
            pixels = np.frombuffer(image.constBits().asstring(image.sizeInBytes()), np.uint32)
            assert not np.any(pixels == sentinel.rgba()), mode
    finally:
        vis.close()


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_broken_level_gets_a_colour_not_an_error():
    vis = _face("radial", size=(320, 160))
    try:
        assert vis._level_colour(float("nan")) == vis._level_colour(0.0)
        assert vis._level_colour(-3.0) == vis._level_colour(0.0)
        assert vis._level_colour(7.0) == vis._level_colour(1.0)
    finally:
        vis.close()


def test_sad_a_new_scheme_builds_a_new_table():
    vis = _face("radial", size=(320, 160))
    try:
        before = vis._level_colour(1.0)
        vis.set_scheme("ice" if vis.scheme != "ice" else "fire")
        after = vis._level_colour(1.0)
        assert after == QColor(vis._level_hex(1.0)) and after != before
    finally:
        vis.close()


# -- edge -------------------------------------------------------------------------------------


def _curve_and_fill(width=1920, height=1080, n=128, seed=4):
    rng = np.random.default_rng(seed)
    xs = (np.arange(n) + 0.5) / n * width
    ys = height - rng.uniform(0.1, 0.9, n) * (height - 4)
    edge_x = np.concatenate(([0.0], xs, [width]))
    edge_y = np.concatenate(([ys[0]], ys, [ys[-1]]))
    shape = MP.qpolygon(np.concatenate(([0.0], edge_x, [width])),
                        np.concatenate(([height], edge_y, [height])))
    gradient = QLinearGradient(0, height, 0, 0)
    gradient.setColorAt(0.0, QColor("#2ecc71"))
    gradient.setColorAt(1.0, QColor("#e74c3c"))
    return shape, MP.qpolygon(edge_x, edge_y), gradient


def _paint(width, height, draw) -> QImage:
    image = QImage(width, height, QImage.Format.Format_ARGB32_Premultiplied)
    image.fill(QColor("#11141a"))
    painter = QPainter(image)
    draw(painter)
    painter.end()
    return image


def _antialiased_fill(shape, gradient):
    def draw(painter):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawPolygon(shape)
    return draw


def _rgb(image: QImage):
    raw = np.frombuffer(image.constBits().asstring(image.sizeInBytes()), np.uint8)
    return raw.reshape(image.height(), -1, 4)[:, :image.width(), :3].astype(np.int16)


def _plain_fill(shape, gradient):
    def draw(painter):
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(gradient)
        painter.drawPolygon(shape)
    return draw


def _blended(image: QImage, plain: QImage) -> int:
    """Pixels of *image* that are neither the background nor the fill's
    colour of their row (a vertical gradient: one colour a row): the
    partly covered ones an antialiased edge is made of."""
    pixels, inside = _rgb(image), _rgb(plain)
    background = pixels[0, 0]
    first_filled = np.argmax(np.any(inside != background, axis=2), axis=1)
    filled = inside[np.arange(inside.shape[0]), first_filled]
    is_background = np.all(pixels == background, axis=2)
    is_fill = np.all(np.abs(pixels - filled[:, None, :]) <= 2, axis=2)
    return int(np.count_nonzero(~is_background & ~is_fill))


def test_edge_the_smooth_edge_fill_has_a_blended_edge_like_an_antialiased_fill():
    shape, edge, gradient = _curve_and_fill(960, 540)
    plain = _paint(960, 540, _plain_fill(shape, gradient))
    smooth = _paint(960, 540, lambda p: MP._fill_with_smooth_edge(p, shape, edge, gradient))
    antialiased = _paint(960, 540, _antialiased_fill(shape, gradient))
    # every column the curve crosses has blended pixels, as the antialiased fill has
    assert _blended(smooth, plain) > 0.5 * _blended(antialiased, plain) > 1000
    # and it is the same picture otherwise (the line lies half a pixel over the edge)
    diff = np.abs(_rgb(smooth) - _rgb(antialiased)).max(axis=2)
    assert diff.mean() < 4.0 and (diff > 64).mean() < 0.03


def test_edge_without_its_edge_line_the_fill_shows_steps():
    """Negative control for the test above: the plain fill alone has no
    blended pixel - its edge is a staircase."""
    shape, _edge, gradient = _curve_and_fill(960, 540)
    plain = _paint(960, 540, _plain_fill(shape, gradient))
    assert _blended(plain, plain) == 0


# -- perf -------------------------------------------------------------------------------------


def _cheapest(fn, rounds=9, frames=5) -> float:
    best = 1e9
    for _ in range(rounds):
        start = time.thread_time()
        for _ in range(frames):
            fn()
        best = min(best, (time.thread_time() - start) / frames)
    return best * 1000


def test_perf_the_smooth_edge_fill_costs_well_under_an_antialiased_fill():
    """Both measured here, interleaved, as this thread's CPU time (the
    cheapest of nine rounds): 0.3 of the antialiased fill was measured,
    under 0.6 is required - another host's load makes both dearer."""
    shape, edge, gradient = _curve_and_fill()
    image = QImage(1920, 1080, QImage.Format.Format_ARGB32_Premultiplied)

    def run(draw):
        def frame():
            painter = QPainter(image)
            draw(painter)
            painter.end()
        return frame

    smooth = run(lambda p: MP._fill_with_smooth_edge(p, shape, edge, gradient))
    full = run(_antialiased_fill(shape, gradient))
    costs = {"smooth": 1e9, "full": 1e9}
    for _ in range(3):
        costs["smooth"] = min(costs["smooth"], _cheapest(smooth, rounds=3))
        costs["full"] = min(costs["full"], _cheapest(full, rounds=3))
    assert costs["smooth"] < costs["full"] * 0.6, costs


def test_perf_sad_the_comparison_catches_a_fill_as_dear_as_before():
    """Negative control: the antialiased fill against itself is not cheaper."""
    shape, _edge, gradient = _curve_and_fill()
    image = QImage(1920, 1080, QImage.Format.Format_ARGB32_Premultiplied)

    def frame():
        painter = QPainter(image)
        _antialiased_fill(shape, gradient)(painter)
        painter.end()

    a, b = _cheapest(frame), _cheapest(frame)
    assert not a < b * 0.6, (a, b)


def test_perf_e2e_the_bench_script_compares_two_versions(tmp_path):
    """scripts/bench_visualizer.py: the measurement behind these numbers,
    run small (two faces, two rounds) against this very file."""
    import subprocess

    from core.subprocess_env import worker_env

    root = Path(__file__).resolve().parent.parent
    face_file = root / "resources" / "extensions" / "media_player.py"
    out = subprocess.run(
        [sys.executable, str(root / "scripts" / "bench_visualizer.py"), "--old", str(face_file),
         "--size", "320x160", "--bars", "16", "--rounds", "2", "--frames", "2",
         "spectrum", "line"],
        capture_output=True, text=True, timeout=120, cwd=root,
        env=worker_env(dict(os.environ, QT_QPA_PLATFORM="offscreen")))
    assert out.returncode == 0, out.stderr
    lines = [line for line in out.stdout.splitlines() if line.strip()]
    assert [line.split()[0] for line in lines] == ["spectrum", "line", "all"], out.stdout
