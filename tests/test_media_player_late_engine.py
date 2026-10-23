"""The Media Player builds its engine only after Qt Multimedia answered.

Reported: axross-full showed no window on a laptop with the NVIDIA driver.
The stuck main thread: PlayerPanel.__init__ -> EqEngine() -> QAudioDecoder()
-> Qt's FFmpeg backend -> cuInit, for ever - the panel is built while the
main window starts. Now the panel comes up at once with its controls off,
core.multimedia_probe tries Qt Multimedia in a child off the GUI thread,
and only then the engine is built (on the GUI thread) and attached. When
the child hangs or fails, the panel says why and stays off; everything
else works. A panel given an engine (the tests) attaches it at once.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from core import extensions as EX  # noqa: E402
from core import multimedia_probe as MPROBE  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_late_engine_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()

OK = MPROBE.ProbeResult(ok=True)
HUNG = MPROBE.ProbeResult(ok=False, reason="Qt Multimedia did not answer within 15 s "
                                              "(it hung while starting its media backend)")


class FakeEngine(QObject):
    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.state, self.error, self.loaded, self.path = "stopped", "", False, ""
        self.position = 0
        self.volume = None
        self.gains = None
        self.calls: list[tuple] = []

    def load(self, path):
        self.path, self.loaded, self.state, self.position = path, True, "stopped", 0
        self.calls.append(("load", path))
        self.changed.emit()

    def play(self):
        self.state = "playing"
        self.calls.append(("play",))
        self.changed.emit()

    def pause(self):
        self.state = "paused"
        self.changed.emit()

    def stop(self):
        self.state, self.position = "stopped", 0
        self.calls.append(("stop",))
        self.changed.emit()

    def seek(self, ms):
        self.position = int(ms)
        self.calls.append(("seek", int(ms)))
        self.changed.emit()

    def set_volume(self, v):
        self.volume = v

    def set_gains(self, g):
        self.gains = list(g)

    def position_ms(self):
        return self.position

    def duration_ms(self):
        return 200_000 if self.loaded else 0

    def current_bars(self, n=32):
        return None


class Background:
    """run_in_background whose work runs only when the test says so."""

    def __init__(self) -> None:
        self.queue: list[tuple] = []

    def __call__(self, work, done, failed) -> None:
        self.queue.append((work, done, failed))

    def run_all(self) -> None:
        while self.queue:
            work, done, failed = self.queue.pop(0)
            try:
                value = work()
            except Exception as exc:  # noqa: BLE001
                failed(exc)
            else:
                done(value)


def touch(path: Path) -> Path:
    path.write_bytes(b"ID3")
    return path


def late_panel(probe_result=OK, *, factory=None, **kw):
    """A panel without an engine: (panel, background, made engines, probe calls)."""
    background = Background()
    made: list[FakeEngine] = []
    probes: list[int] = []

    def make():
        engine = FakeEngine()
        made.append(engine)
        return engine

    def probe():
        probes.append(1)
        return probe_result

    panel = MP.PlayerPanel(run_in_background=background, engine_factory=factory or make,
                           audio_probe=probe, **kw)
    return panel, background, made, probes


TRANSPORT = ("prev_button", "play_button", "stop_button", "next_button")


def transport_enabled(panel) -> list[bool]:
    return [getattr(panel, name).isEnabled() for name in TRANSPORT]


# --- happy -------------------------------------------------------------------------------


def test_happy_the_panel_comes_up_before_the_engine():
    panel, background, made, probes = late_panel()
    try:
        assert made == [] and probes == []  # nothing ran on the GUI thread
        assert not panel.engine_ready
        assert transport_enabled(panel) == [False] * 4
        assert "Starting audio" in panel.audio_status.text()
        assert panel.audio_status.isVisibleTo(panel)
        background.run_all()
        assert probes == [1] and len(made) == 1
        assert panel.engine is made[0] and panel.engine_ready
        assert transport_enabled(panel) == [True] * 4
        assert not panel.audio_status.isVisibleTo(panel)
        assert panel.visualizer.engine is made[0]
    finally:
        panel.close()


def test_happy_the_late_engine_is_wired_like_an_injected_one(tmp_path):
    panel, background, made, _ = late_panel()
    try:
        background.run_all()
        engine = made[0]
        panel.add_files([str(touch(tmp_path / "a.mp3")), str(touch(tmp_path / "b.mp3"))])
        panel.playlist.setCurrentRow(0)
        panel.play_selected()
        assert engine.path.endswith("a.mp3") and engine.state == "playing"
        engine.finished_playing.emit()  # the track ended: the next one plays
        assert engine.path.endswith("b.mp3")
        panel.stop_button.click()
        assert engine.state == "stopped"
        engine.error = "broken"
        engine.changed.emit()
        assert "broken" in panel.now_playing.text()
        assert engine.volume is not None  # the slider's volume reached it
    finally:
        panel.close()


def test_happy_the_restored_track_waits_for_the_engine(tmp_path, monkeypatch):
    track = touch(tmp_path / "song.mp3")
    state = tmp_path / "media_player.json"
    state.write_text(json.dumps({"version": 1, "tracks": [{"path": str(track)}], "current": 0,
                                 "position_ms": 83_000}), encoding="utf-8")
    tags = []

    class TagReader(QObject):
        """Qt's QMediaPlayer as the tag reader uses it: counts the readers."""

        mediaStatusChanged = pyqtSignal(object)  # noqa: N815 - Qt's name

        def __init__(self, parent=None):
            super().__init__(parent)

        def setSource(self, url):  # noqa: N802 - Qt API
            tags.append(url.toLocalFile())

    import PyQt6.QtMultimedia as QtMultimedia

    monkeypatch.setattr(QtMultimedia, "QMediaPlayer", TagReader)
    panel, background, made, _ = late_panel(state_path=str(state))
    try:
        # the restore's check of the files is first in the queue, the probe second
        work, done, failed = background.queue.pop(0)
        done(work())
        assert panel.current_row() == 0
        assert tags == []  # Qt's tag reader is a multimedia object too: not yet
        panel.save_state()  # a save meanwhile keeps the position
        assert json.loads(state.read_text())["position_ms"] == 83_000
        background.run_all()
        engine = made[0]
        assert ("load", str(track)) in engine.calls and ("seek", 83_000) in engine.calls
        assert engine.state == "stopped"  # restored, not playing
        assert tags == [str(track)]
        panel.save_state()
        assert json.loads(state.read_text())["position_ms"] == 83_000
    finally:
        panel.close()


def test_happy_the_engine_first_then_the_restored_track(tmp_path, monkeypatch):
    track = touch(tmp_path / "song.mp3")
    state = tmp_path / "media_player.json"
    state.write_text(json.dumps({"version": 1, "tracks": [{"path": str(track)}], "current": 0,
                                 "position_ms": 5_000}), encoding="utf-8")
    monkeypatch.setattr(MP.PlayerPanel, "_read_tags", lambda self, path: None)
    panel, background, made, _ = late_panel(state_path=str(state))
    try:
        restore = background.queue.pop(0)
        background.run_all()  # the probe and the engine
        work, done, _failed = restore
        done(work())
        assert made[0].calls[-2:] == [("load", str(track)), ("seek", 5_000)]
    finally:
        panel.close()


def test_happy_play_asked_for_while_starting_plays_once_ready(tmp_path, monkeypatch):
    monkeypatch.setattr(MP.PlayerPanel, "_read_tags", lambda self, path: None)
    panel, background, made, _ = late_panel()
    try:
        first = panel.add_collected(*MP.collect_local([str(touch(tmp_path / "x.mp3"))]))
        panel.play_item(first)  # "Play in Media Player" right after the start
        background.run_all()
        assert made[0].path.endswith("x.mp3") and made[0].state == "playing"
    finally:
        panel.close()


def test_happy_an_injected_engine_needs_no_probe():
    engine = FakeEngine()
    probes = []
    panel = MP.PlayerPanel(engine=engine, audio_probe=lambda: probes.append(1) or OK)
    try:
        assert panel.engine is engine and panel.engine_ready and probes == []
        assert transport_enabled(panel) == [True] * 4
        assert not panel.audio_status.isVisibleTo(panel)
    finally:
        panel.close()


# --- sad ---------------------------------------------------------------------------------


def test_sad_a_hung_probe_leaves_the_player_off_and_says_why():
    panel, background, made, _ = late_panel(HUNG)
    failures = []
    panel.engine_failed.connect(failures.append)
    try:
        background.run_all()
        assert made == []  # no engine: no multimedia object in this process
        assert not panel.engine_ready
        assert transport_enabled(panel) == [False] * 4
        text = panel.audio_status.text()
        assert text.startswith("Audio does not start on this system: ")
        assert HUNG.reason in text
        assert "The Media Player is off; everything else works." in text
        assert failures == [text]
        panel.toggle_play()  # nothing to call into, nothing breaks
        panel.next_track()
    finally:
        panel.close()


def test_sad_an_engine_that_fails_to_build_is_reported():
    def broken():
        raise RuntimeError("no audio backend")

    panel, background, _made, _ = late_panel(factory=broken)
    failures = []
    panel.engine_failed.connect(failures.append)
    try:
        background.run_all()
        assert not panel.engine_ready
        assert "no audio backend" in panel.audio_status.text()
        assert len(failures) == 1
    finally:
        panel.close()


def test_sad_a_probe_that_raises_is_reported():
    def probe():
        raise OSError("fork failed")

    background = Background()
    panel = MP.PlayerPanel(run_in_background=background, engine_factory=FakeEngine,
                           audio_probe=probe)
    try:
        background.run_all()
        assert not panel.engine_ready and "fork failed" in panel.audio_status.text()
    finally:
        panel.close()


def test_sad_the_extension_notifies_once(monkeypatch, tmp_path):
    monkeypatch.setattr(MP, "state_file", lambda: tmp_path / "media_player.json")
    monkeypatch.setattr(MPROBE, "run_probe", lambda timeout=None, **_kw: HUNG)
    MPROBE.reset()

    class Api:
        def __init__(self):
            self.notes, self.docks = [], []

        def add_dock(self, title, widget):
            self.docks.append(widget)
            return None

        def add_context_action(self, *a, **kw):
            pass

        def run_in_background(self, work, on_done=None, on_error=None):
            try:
                value = work()
            except Exception as exc:  # noqa: BLE001
                on_error(exc)
            else:
                on_done(value)

        def notify(self, text, timeout_ms=5000):
            self.notes.append(text)

    api = Api()
    try:
        MP.activate(api)
        panel = api.docks[0]
        assert not panel.engine_ready
        assert len(api.notes) == 1 and HUNG.reason in api.notes[0]
    finally:
        MP.deactivate(api)
        MPROBE.reset()


# --- edge --------------------------------------------------------------------------------


def test_edge_a_result_after_shutdown_builds_nothing():
    panel, background, made, _ = late_panel()
    panel.shutdown()
    background.run_all()
    assert made == [] and not panel.engine_ready
    panel.close()


def test_edge_a_result_after_the_widget_is_gone_builds_nothing():
    from PyQt6 import sip

    panel, background, made, _ = late_panel()
    sip.delete(panel)
    background.run_all()
    assert made == []


def test_edge_the_playlist_works_while_audio_is_off(tmp_path):
    panel, background, _made, _ = late_panel(HUNG)
    try:
        background.run_all()
        assert panel.add_files([str(touch(tmp_path / "a.mp3"))]) == 1
        assert panel.playlist.count() == 1
        panel.clear_playlist()
        assert panel.playlist.count() == 0
    finally:
        panel.close()


def test_edge_the_volume_and_equalizer_set_meanwhile_reach_the_engine():
    panel, background, made, _ = late_panel()
    try:
        panel.volume.setValue(30)
        panel.apply_preset("Rock")
        background.run_all()
        assert made[0].gains == MP.PRESETS["Rock"]
        assert made[0].volume == pytest.approx(MP.perceptual_to_linear(0.3))
    finally:
        panel.close()


def test_edge_every_control_child_is_a_widget():
    """The status line is part of the panel (not a stray window)."""
    panel, _bg, _made, _ = late_panel()
    try:
        assert isinstance(panel.audio_status.parent(), QWidget)
        assert panel.audio_status.window() is panel.window()
    finally:
        panel.close()
