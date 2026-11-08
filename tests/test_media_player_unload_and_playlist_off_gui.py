"""The Media Player ends its threads when it is switched off, and Load
Playlist checks the entries off the GUI thread.

The review found:

* The audio, decoder and equalizer QThreads live in the module-level
  ``_THREADS`` and were ended only by an ``atexit`` / ``aboutToQuit`` hook.
  Every switch-on or Reload runs the module afresh (a new ``_THREADS``, a
  new hook) and ``deactivate`` never ended them: 3, 6, 9 threads running
  after three on/off cycles, each copy kept alive by its exit hook.
* Load Playlist… called ``read_playlist`` on the GUI thread, and
  ``parse_m3u`` asks ``os.path.isfile`` for each of up to 10,000 entries: a
  playlist on a dead mount froze the window. ``restore_state`` had moved
  the same check off the GUI thread already; Load Playlist now does too.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])
SOURCE = ROOT / "resources" / "extensions" / "media_player.py"


def _fresh(name: str):
    """A copy of the module as the host makes one on every switch-on."""
    spec = importlib.util.spec_from_file_location(name, SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MP = _fresh("media_player_unload_off_gui_ext")


def _start_threads(module) -> list:
    return [module.media_thread(n) for n in (module.AUDIO_THREAD, module.DECODER_THREAD,
                                             module.EQUALIZER_THREAD)]


def test_happy_deactivate_ends_the_media_threads():
    threads = _start_threads(MP)
    assert all(t.isRunning() for t in threads)
    MP.deactivate(None)
    assert all(t.isFinished() for t in threads)
    assert MP._THREADS == {}


class _ExitHooks:
    """Stands in for the module's ``atexit``: which hooks are registered."""

    def __init__(self) -> None:
        self.hooks: list = []

    def register(self, fn, *args, **kwargs):
        self.hooks.append(fn)
        return fn

    def unregister(self, fn) -> None:
        self.hooks = [h for h in self.hooks if h is not fn]


def test_edge_on_off_cycles_leave_no_thread_running_and_no_exit_hook():
    quit_hooks = APP.receivers(APP.aboutToQuit)
    exit_hooks = _ExitHooks()
    copies = []
    for cycle in range(3):
        module = _fresh(f"media_player_unload_cycle_{cycle}")
        module.atexit = exit_hooks
        copies.append((module, _start_threads(module)))
        assert exit_hooks.hooks == [module.end_media_threads]
        module.deactivate(None)
        sys.modules.pop(module.__name__, None)
    assert [t for _m, ts in copies for t in ts if t.isRunning()] == []
    assert exit_hooks.hooks == []
    assert APP.receivers(APP.aboutToQuit) == quit_hooks


def test_sad_a_thread_that_does_not_end_keeps_its_exit_hook(monkeypatch):
    module = _fresh("media_player_unload_stuck")
    _start_threads(module)
    monkeypatch.setattr(module, "end_media_threads", lambda timeout_ms=5000: False)
    module.deactivate(None)
    assert module._exit_handler_registered  # the hook still ends it at the exit
    monkeypatch.undo()
    assert module.end_media_threads() is True
    module._unregister_exit_handlers()


# -- Load Playlist ------------------------------------------------------------------


class FakeEngine(QObject):
    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.state, self.error, self.finished, self.loaded, self.path = (
            "stopped", "", False, False, "")

    def load(self, path):
        self.path, self.loaded = path, True

    def play(self):
        self.state = "playing"

    def pause(self):
        self.state = "paused"

    def stop(self):
        self.state = "stopped"

    def seek(self, ms):
        pass

    def set_volume(self, v):
        pass

    def set_gains(self, gains):
        pass

    def set_eq_enabled(self, on):
        pass

    def position_ms(self):
        return 0

    def duration_ms(self):
        return 0

    def current_bars(self, n=32):
        return None

    def current_samples(self):
        return None


def _rows(panel) -> list[str]:
    return [panel.playlist.item(r).text() for r in range(panel.playlist.count())]


def _playlist(tmp_path, names) -> Path:
    for name in names:
        (tmp_path / name).write_bytes(b"ID3")
    target = tmp_path / "list.m3u"
    target.write_text("".join(f"{n}\n" for n in names), encoding="utf-8")
    return target


def test_happy_load_playlist_checks_the_entries_off_the_gui_thread(tmp_path, monkeypatch):
    target = _playlist(tmp_path, ["a.mp3", "b.mp3"])
    gui = threading.current_thread()
    checked_on = []
    real_isfile = os.path.isfile

    def isfile(path):
        checked_on.append(threading.current_thread())
        return real_isfile(path)

    monkeypatch.setattr(MP.os.path, "isfile", isfile)
    jobs = []
    panel = MP.PlayerPanel(engine=FakeEngine(),
                           run_in_background=lambda w, d, e: jobs.append((w, d, e)))
    try:
        panel.load_playlist(str(target))
        assert checked_on == [] and panel.playlist.count() == 0  # nothing on the GUI thread
        (work, done, _error), = jobs
        result = []
        worker = threading.Thread(target=lambda: result.append(work()))
        worker.start()
        worker.join(10)
        assert checked_on and gui not in checked_on
        done(result[0])
        assert _rows(panel) == ["a.mp3", "b.mp3"]
        assert "2" in panel.note.text()
    finally:
        panel.close()


def test_sad_a_refused_playlist_keeps_the_list_and_says_why(tmp_path):
    jobs = []
    panel = MP.PlayerPanel(engine=FakeEngine(),
                           run_in_background=lambda w, d, e: jobs.append((w, d, e)))
    try:
        panel.add_files([str(_playlist(tmp_path, ["keep.mp3"]).parent / "keep.mp3")])
        bad = tmp_path / "bad.m3u"
        bad.write_bytes(b"\x00\x01")
        panel.load_playlist(str(bad))
        (work, _done, error), = jobs
        with pytest.raises(MP.PlaylistError) as caught:
            work()
        error(caught.value)
        assert _rows(panel) == ["keep.mp3"] and "NUL" in panel.note.text()
    finally:
        panel.close()


def test_edge_only_the_last_load_asked_for_fills_the_list(tmp_path):
    (tmp_path / "1").mkdir()
    (tmp_path / "2").mkdir()
    first = _playlist(tmp_path / "1", ["one.mp3"])
    second = _playlist(tmp_path / "2", ["two.mp3"])
    jobs = []
    panel = MP.PlayerPanel(engine=FakeEngine(),
                           run_in_background=lambda w, d, e: jobs.append((w, d, e)))
    try:
        panel.load_playlist(str(first))
        panel.load_playlist(str(second))
        (w1, d1, _e1), (w2, d2, _e2) = jobs
        d2(w2())
        d1(w1())  # the slower, older one arrives last
        assert _rows(panel) == ["two.mp3"]
    finally:
        panel.close()
