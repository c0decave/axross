"""The media viewer creates its QMediaPlayer only after Qt Multimedia answered.

QMediaPlayer, QAudioOutput and QVideoWidget start Qt's multimedia backend in
the GUI thread - measured with the hanging GPU driver stand-in
(tests/hanging_gpu_driver.py): each of the three hangs there without
core.multimedia_env's defaults, and a deaf audio server hangs QAudioOutput.
The viewer asks core.multimedia_probe first (off the GUI thread) and shows a
message instead of a player when the child hung or failed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import multimedia_probe as MPROBE  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, VIDEO, MediaItem  # noqa: E402
from tests import hanging_gpu_driver as HGD  # noqa: E402
from tests.media_testkit import video_bytes, write_image  # noqa: E402
from ui import media_viewer as MV  # noqa: E402

APP = QApplication.instance() or QApplication([])
HUNG = MPROBE.ProbeResult(ok=False, reason="Qt Multimedia did not answer within 15 s "
                                              "(it hung while starting its media backend)")
FFMPEG_VARS = ("QT_FFMPEG_DECODING_HW_DEVICE_TYPES", "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES")

pytestmark = pytest.mark.skipif(not MV.video_supported(), reason="QtMultimedia not available")


def wait_until(cond, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


@pytest.fixture(autouse=True)
def _fresh_probe():
    MPROBE.reset()
    yield
    MPROBE.reset()


def _item(path: Path, kind: str) -> MediaItem:
    return MediaItem(str(path), path.name, "", kind, path.stat().st_size, path.stat().st_mtime)


def _clip(tmp_path) -> Path:
    clip = tmp_path / "clip.mp4"
    clip.write_bytes(video_bytes(frames=3))
    return clip


def _viewer(items) -> MV.MediaViewer:
    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(320, 240)
    viewer.show()
    viewer.set_items(items, 0)
    return viewer


class GatedProbe:
    """run_probe that answers *result* once the test opens the gate."""

    def __init__(self, result) -> None:
        self.result = result
        self.gate = threading.Event()
        self.calls = 0

    def __call__(self, timeout=None, **_kw):
        self.calls += 1
        self.gate.wait(10)
        return self.result


# --- happy -------------------------------------------------------------------------------


def test_happy_the_player_waits_for_the_probe_then_plays(tmp_path, monkeypatch):
    probe = GatedProbe(MPROBE.ProbeResult(ok=True))
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    viewer = _viewer([_item(_clip(tmp_path), VIDEO)])
    try:
        assert wait_until(lambda: viewer.mode == "starting")
        assert "Starting video playback" in viewer.placeholder_text()
        assert viewer._player is None  # no multimedia object on the GUI thread yet
        probe.gate.set()
        assert wait_until(lambda: viewer.mode == "video", 15)
        assert viewer._player is not None and probe.calls == 1
    finally:
        viewer.shutdown()


def test_happy_a_known_good_probe_plays_at_once(tmp_path, monkeypatch):
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: MPROBE.ProbeResult(ok=True))
    MPROBE.probe()
    viewer = _viewer([_item(_clip(tmp_path), VIDEO)])
    try:
        assert wait_until(lambda: viewer.mode == "video")
    finally:
        viewer.shutdown()


# --- sad ---------------------------------------------------------------------------------


def test_sad_a_hung_probe_shows_why_and_creates_no_player(tmp_path, monkeypatch):
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: HUNG)
    viewer = _viewer([_item(_clip(tmp_path), VIDEO)])
    try:
        assert wait_until(lambda: viewer.mode == "placeholder")
        text = viewer.placeholder_text()
        assert "clip.mp4" in text and HUNG.reason in text
        assert viewer._player is None and viewer._video_widget is None
    finally:
        viewer.shutdown()


def test_sad_the_next_video_after_a_failure_does_not_probe_again(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(MPROBE, "run_probe",
                        lambda timeout=None, **_kw: calls.append(1) or HUNG)
    second = tmp_path / "second.mp4"
    second.write_bytes(video_bytes(frames=3))
    viewer = _viewer([_item(_clip(tmp_path), VIDEO), _item(second, VIDEO)])
    try:
        assert wait_until(lambda: viewer.mode == "placeholder")
        viewer.next_item()
        assert wait_until(lambda: viewer.mode == "placeholder" and "second.mp4"
                          in viewer.placeholder_text())
        assert calls == [1] and viewer._player is None
    finally:
        viewer.shutdown()


# --- edge --------------------------------------------------------------------------------


def test_edge_moving_on_while_the_probe_runs_keeps_the_new_item(tmp_path, monkeypatch):
    probe = GatedProbe(MPROBE.ProbeResult(ok=True))
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    image = _item(write_image(tmp_path / "z.png"), IMAGE)
    viewer = _viewer([_item(_clip(tmp_path), VIDEO), image])
    try:
        assert wait_until(lambda: viewer.mode == "starting")
        viewer.next_item()
        assert wait_until(lambda: viewer.mode == "image")
        probe.gate.set()
        assert wait_until(lambda: MPROBE.cached() is not None)
        wait_until(lambda: False, 0.3)
        assert viewer.mode == "image" and viewer._player is None
    finally:
        viewer.shutdown()


def test_edge_the_slideshow_waits_while_the_player_starts(tmp_path, monkeypatch):
    probe = GatedProbe(MPROBE.ProbeResult(ok=True))
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    image = _item(write_image(tmp_path / "z.png"), IMAGE)
    viewer = _viewer([_item(_clip(tmp_path), VIDEO), image])
    try:
        assert wait_until(lambda: viewer.mode == "starting")
        viewer.start_slideshow()
        assert not viewer.slideshow_timer.isActive()
    finally:
        probe.gate.set()
        viewer.shutdown()
        assert wait_until(lambda: MPROBE.cached() is not None)


def test_edge_a_viewer_closed_before_the_answer_is_left_alone(tmp_path, monkeypatch):
    from PyQt6 import sip

    probe = GatedProbe(MPROBE.ProbeResult(ok=True))
    monkeypatch.setattr(MPROBE, "run_probe", probe)
    viewer = _viewer([_item(_clip(tmp_path), VIDEO)])
    assert wait_until(lambda: viewer.mode == "starting")
    viewer.shutdown()
    sip.delete(viewer)
    probe.gate.set()
    assert wait_until(lambda: MPROBE.cached() is not None)
    wait_until(lambda: False, 0.3)  # the late answer reaches no deleted widget


# --- e2e: the real hanging driver, the real viewer, the real probe child -------------------

_VIEWER_UNDER_DRIVER = textwrap.dedent("""
    import json, sys, time
    sys.path.insert(0, {root!r})
    from PyQt6.QtWidgets import QApplication
    app = QApplication([])
    from core.local_fs import LocalFS
    from core.media_collect import VIDEO, MediaItem
    from ui import media_viewer as MV
    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(320, 240)
    viewer.show()
    clip = {clip!r}
    if {direct!r}:
        viewer._ensure_player()  # the old way: straight into Qt Multimedia
        print(json.dumps({{"mode": "direct"}}), flush=True)
        raise SystemExit(0)
    viewer.set_items([MediaItem(clip, "clip.mp4", "", VIDEO, 1, 0.0)], 0)
    start = time.monotonic()
    seen = set()
    while time.monotonic() - start < 20:
        app.processEvents()
        seen.add(viewer.mode)
        if viewer.mode in ("placeholder", "video"):
            break
        time.sleep(0.01)
    print(json.dumps({{"mode": viewer.mode, "seen": sorted(seen),
                      "text": viewer.placeholder_text(),
                      "player": viewer._player is not None,
                      "seconds": round(time.monotonic() - start, 2)}}), flush=True)
    viewer.shutdown()
""")


def _run_under_driver(tmp_path, *, layer1: bool, direct: bool = False, timeout: float = 45):
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    lib = HGD.build(tmp_path / "gpu")
    env = {k: v for k, v in os.environ.items() if k not in FFMPEG_VARS}
    env.update(QT_QPA_PLATFORM="offscreen", **{MPROBE.SECONDS_ENV: "3"})
    if layer1:
        env.update({name: "" for name in FFMPEG_VARS})
    code = _VIEWER_UNDER_DRIVER.format(root=str(ROOT), clip=str(_clip(tmp_path)), direct=direct)
    try:
        return subprocess.run(HGD.command(lib, [sys.executable, "-c", code]), env=env,
                              capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired:
        return None


def test_e2e_negative_control_the_old_path_hangs_under_the_driver(tmp_path):
    assert _run_under_driver(tmp_path, layer1=False, direct=True, timeout=10) is None


def test_e2e_under_the_hanging_driver_the_viewer_shows_why(tmp_path):
    result = _run_under_driver(tmp_path, layer1=False)
    assert result is not None, "the viewer froze under the hanging driver"
    assert result.returncode == 0, result.stderr[-1500:]
    state = json.loads(result.stdout.strip().splitlines()[-1])
    assert state["mode"] == "placeholder" and not state["player"]
    assert "starting" in state["seen"]
    assert "did not answer within 3 s" in state["text"]
    assert MPROBE.STEP_LABELS["decoder"] in state["text"]


def test_e2e_with_layer1_the_viewer_plays_under_the_driver(tmp_path):
    result = _run_under_driver(tmp_path, layer1=True)
    assert result is not None and result.returncode == 0, result and result.stderr[-1500:]
    state = json.loads(result.stdout.strip().splitlines()[-1])
    assert state["mode"] == "video" and state["player"], state
