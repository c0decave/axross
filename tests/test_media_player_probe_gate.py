"""The Media Player has a track probed in a child before Qt Multimedia opens it.

Qt Multimedia's FFmpeg demuxes and decodes inside axross: a file that
crashed it ended the program - and a crashing track in the restored
playlist did it again at every start. Before a local track is loaded (also
the one a restore loads), ffprobe - when installed - opens it in a child
(core.media_gate), off the GUI thread; a track whose probe crashes or hangs
is marked, said and skipped like any track that cannot be played.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import media_gate as MG  # noqa: E402
from core import metadata_formats as MF  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_probe_gate_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_probe_gate_ext"] = MP
_spec.loader.exec_module(MP)

from tests.test_media_player_review_fixes import FakeEngine  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the fake ffprobe is a sh script")


@pytest.fixture(autouse=True)
def _fresh_cache():
    MG.forget()
    yield
    MG.forget()


@pytest.fixture
def ffprobe(monkeypatch, tmp_path):
    """A fake ffprobe: a track whose name has 'bad' crashes it."""
    script = tmp_path / "ffprobe"
    script.write_text('#!/bin/sh\ncase "$*" in *bad*) kill -SEGV $$ ;; esac\nexit 0\n')
    script.chmod(0o755)
    monkeypatch.setattr(MF, "ffprobe_path", lambda: str(script))


class _Relay(QObject):
    go = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self.go.connect(lambda fn: fn())  # queued: emitted from a worker


_RELAY = _Relay()


def _background(work, done, failed):
    """The extension API's runner: the work on a thread, the answer on the GUI thread."""
    import threading

    def run():
        try:
            value = work()
        except Exception as exc:  # noqa: BLE001
            _RELAY.go.emit(lambda: failed(exc))
            return
        _RELAY.go.emit(lambda: done(value))

    threading.Thread(target=run, daemon=True).start()


def _wait(cond, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _tracks(folder: Path, *names: str) -> list[str]:
    out = []
    for name in names:
        (folder / name).write_bytes(b"ID3" + b"\x00" * 64)
        out.append(str(folder / name))
    return out


def test_sad_a_track_whose_probe_crashes_is_skipped_not_loaded(ffprobe, tmp_path):
    engine = FakeEngine()
    loaded = []
    real_load = engine.load
    engine.load = lambda path: (loaded.append(path), real_load(path))
    panel = MP.PlayerPanel(engine=engine, run_in_background=_background)
    try:
        bad, good = _tracks(tmp_path, "bad.mp3", "good.mp3")
        panel.add_files([bad, good])
        panel.playlist.setCurrentRow(0)
        panel.play_selected()
        assert _wait(lambda: loaded == [good]), loaded
        assert "crash" in panel.playlist.item(0).toolTip()
        assert "skipped" in panel.note.text() or engine.path == good
    finally:
        panel.deleteLater()


def test_happy_a_track_whose_probe_passes_plays(ffprobe, tmp_path):
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, run_in_background=_background)
    try:
        (good,) = _tracks(tmp_path, "good.mp3")
        panel.add_files([good])
        panel.playlist.setCurrentRow(0)
        panel.play_selected()
        assert _wait(lambda: engine.state == "playing" and engine.path == good)
    finally:
        panel.deleteLater()


def test_sad_stop_while_the_probe_runs_plays_nothing(monkeypatch, tmp_path):
    script = tmp_path / "ffprobe"
    script.write_text("#!/bin/sh\nsleep 1\nexit 0\n")
    script.chmod(0o755)
    monkeypatch.setattr(MF, "ffprobe_path", lambda: str(script))
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, run_in_background=_background)
    try:
        (good,) = _tracks(tmp_path, "good.mp3")
        panel.add_files([good])
        panel.playlist.setCurrentRow(0)
        panel.play_selected()
        panel.stop_button.click()
        time.sleep(1.5)
        _wait(lambda: False, 0.5)
        assert engine.state == "stopped" and not engine.loaded
    finally:
        panel.deleteLater()


def test_sad_a_restored_track_whose_probe_crashes_is_not_loaded(ffprobe, tmp_path):
    bad, good = _tracks(tmp_path, "bad.mp3", "good.mp3")
    state = tmp_path / "state.json"
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, state_path=str(state), run_in_background=_background)
    try:
        panel.add_files([bad, good])
        panel.playlist.setCurrentRow(0)
        panel._set_current(panel.playlist.item(0))
        panel.save_state()
    finally:
        panel.deleteLater()
    assert json.loads(state.read_text())
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, state_path=str(state), run_in_background=_background)
    try:
        assert _wait(lambda: panel.playlist.count() == 2)
        _wait(lambda: False, 0.5)
        assert not engine.loaded
    finally:
        panel.deleteLater()
