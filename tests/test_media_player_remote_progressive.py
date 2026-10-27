"""Remote tracks play as soon as the first one is copied.

A remote track is copied to a bounded temporary folder to play
(fetch_remote). "Play in Media Player" on a remote selection, and a drop
from a remote pane, copied every file of the selection before the first
track was added: measured with eight 4 MB tracks read at 40 MB/s, the
first one started after 958 ms, with four after 499 ms - the whole copy,
growing with the selection (scratch remote probe of the change). Now the
files are listed first, then copied one by one off the GUI thread; each
lands in the playlist as it arrives and the first one plays at once.
"""

from __future__ import annotations

import importlib.util
import os
import queue
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtCore import QMimeData, QObject, QPointF, Qt, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("media_player_remote_progressive_ut", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = _load()


class FakeEngine(QObject):
    finished_playing = pyqtSignal()
    changed = pyqtSignal()
    failed = pyqtSignal(str)

    def __init__(self, log=None) -> None:
        super().__init__()
        self.state, self.error, self.finished, self.loaded, self.path = (
            "stopped", "", False, False, "")
        self.volume = 1.0
        self.loads: list[str] = []
        self.log = log if log is not None else []

    def load(self, path):
        self.path, self.loaded = path, True
        self.loads.append(path)
        self.log.append(("load", os.path.basename(path)))

    def play(self):
        self.state = "playing"
        self.changed.emit()

    def pause(self):
        self.state = "paused"

    def stop(self):
        self.state = "stopped"

    def seek(self, ms):
        pass

    def set_volume(self, volume):
        self.volume = volume

    def position_ms(self):
        return 0

    def duration_ms(self):
        return 0

    def current_bars(self, n_bars=32):
        return [0.0] * n_bars

    def current_samples(self):
        return None


class LoggedRam(RamFsSession):
    """A remote backend that logs each file it opens for reading; a file
    named in *gates* is read only once its event is set."""

    def __init__(self, log, gates=None) -> None:
        super().__init__("music-ram")
        self.log = log
        self.gates = gates or {}

    def open_read(self, path, *args, **kwargs):
        name = os.path.basename(path)
        self.log.append(("open", name))
        gate = self.gates.get(name)
        if gate is not None:
            assert gate.wait(10), f"{name}: the gate never opened"
        return super().open_read(path, *args, **kwargs)


def music(log, names=("a.wav", "b.wav", "c.wav"), size=64, gates=None):
    ram = LoggedRam(log, gates)
    ram.mkdir("/music")
    for name in names:
        with ram.open_write(f"/music/{name}") as fh:
            fh.write(b"RIFF" + bytes(size))
    return ram


class Jobs:
    """run_in_background whose jobs the test runs one at a time."""

    def __init__(self) -> None:
        self.pending = []

    def __call__(self, work, done, error) -> None:
        self.pending.append((work, done, error))

    def run_next(self) -> None:
        work, done, error = self.pending.pop(0)
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 - like the host
            error(exc)
            return
        done(result)

    def run_all(self) -> None:
        while self.pending:
            self.run_next()


class Threads:
    """run_in_background like the host: a worker thread, callbacks on the GUI thread."""

    def __init__(self) -> None:
        self.results = queue.Queue()

    def __call__(self, work, done, error) -> None:
        def run():
            try:
                self.results.put((done, work()))
            except Exception as exc:  # noqa: BLE001
                self.results.put((error, exc))
        threading.Thread(target=run, daemon=True).start()

    def pump_until(self, cond, timeout=10.0) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if cond():
                return True
            try:
                callback, value = self.results.get(timeout=0.01)
            except queue.Empty:
                APP.processEvents()
                continue
            callback(value)
        return cond()


def rows(panel):
    return [panel.playlist.item(i).text() for i in range(panel.playlist.count())]


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    yield tmp_path
    MP.deactivate(None)


def media_folders(root):
    return sorted(p for p in Path(root).glob("axross-media-*"))


# -- happy ------------------------------------------------------------------------------


def test_happy_the_first_remote_track_plays_before_the_next_is_copied(temp_root):
    log = []
    jobs = Jobs()
    engine = FakeEngine(log)
    panel = MP.PlayerPanel(engine=engine, run_in_background=jobs)
    try:
        panel.add_remote(music(log), ["/music"], play_first=True)
        assert panel.playlist.count() == 0 and len(jobs.pending) == 1  # the listing
        jobs.run_next()  # list
        jobs.run_next()  # copy a.wav
        assert rows(panel) == ["a.wav"]
        assert engine.loads and os.path.basename(engine.loads[0]) == "a.wav"
        assert engine.state == "playing"
        assert ("open", "b.wav") not in log  # not copied yet
        assert len(jobs.pending) == 1  # the next copy waits its turn
        jobs.run_all()
        assert rows(panel) == ["a.wav", "b.wav", "c.wav"]
        assert all(MP._is_temp_copy(panel.playlist.item(i).data(Qt.ItemDataRole.UserRole))
                   for i in range(3))
        assert "3" in panel.note.text()
        assert len(engine.loads) == 1  # the others wait in the playlist
    finally:
        panel.close()


def test_happy_e2e_play_in_media_player_starts_with_the_first_copy(temp_root, monkeypatch):
    """Through the extension's own entry point and a host that runs the
    background work at once."""
    monkeypatch.setenv("HOME", str(temp_root / "home"))
    log = []

    class Api:
        def __init__(self):
            self.actions, self.notes, self.docks = {}, [], []

        def add_dock(self, title, widget):
            self.docks.append(widget)

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            self.actions[label] = cb

        def run_in_background(self, work, on_done=None, on_error=None):
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                on_error(exc)
                return
            on_done(result)

        def notify(self, text):
            self.notes.append(text)

    api = Api()
    MP.activate(api)
    panel = api.docks[0]
    loads = []
    real_play_item = panel.play_item
    panel.play_item = lambda item, **kw: (log.append(("play", item.text())),
                                          loads.append(item), real_play_item(item, **kw))
    try:
        ram = music(log)
        api.actions["Play in Media Player"](SimpleNamespace(
            backend=ram, folder="/music", paths=["/music/a.wav", "/music/b.wav",
                                                 "/music/c.wav"],
            items=[], pane=None, is_local=False))
        assert rows(panel) == ["a.wav", "b.wav", "c.wav"]
        assert log.index(("play", "a.wav")) < log.index(("open", "b.wav")), log
        assert len(loads) == 1
    finally:
        panel.engine.stop()
        MP.deactivate(api)
    assert media_folders(temp_root) == []


def test_happy_e2e_a_remote_drop_fills_the_playlist_while_it_copies(temp_root):
    from PyQt6.QtGui import QDragEnterEvent, QDropEvent

    from ui.extension_host import ExtensionContext

    log = []
    gate = threading.Event()
    ram = music(log, gates={"c.wav": gate})
    threads = Threads()
    panel = MP.PlayerPanel(engine=FakeEngine(), run_in_background=threads)
    panel.drop_resolver = lambda mime: ExtensionContext(backend=ram, folder="/music",
                                                        paths=("/music",))
    try:
        panel.resize(500, 600)
        panel.show()
        mime = QMimeData()
        mime.setData(MP.TRANSFER_MIME_TYPE, b"{}")
        view = panel.playlist.viewport()
        pos = QPointF(view.width() / 2, view.height() / 2)
        actions = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
        QApplication.sendEvent(view, QDragEnterEvent(pos.toPoint(), actions, mime,
                                                     Qt.MouseButton.LeftButton,
                                                     Qt.KeyboardModifier.NoModifier))
        drop = QDropEvent(pos, actions, mime, Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.NoModifier)
        QApplication.sendEvent(view, drop)
        assert drop.isAccepted()
        # c.wav's copy is held: a and b are in the list already.
        assert threads.pump_until(lambda: rows(panel) == ["a.wav", "b.wav"]), rows(panel)
        assert "2" in panel.note.text() and "3" in panel.note.text()  # 2 of 3
        gate.set()
        assert threads.pump_until(lambda: rows(panel) == ["a.wav", "b.wav", "c.wav"])
        assert threads.pump_until(lambda: "Added 3" in panel.note.text()), panel.note.text()
    finally:
        gate.set()
        panel.close()


# -- sad --------------------------------------------------------------------------------


def test_sad_a_file_over_its_bound_stops_the_copies_and_keeps_what_plays(temp_root,
                                                                       monkeypatch):
    log = []
    ram = music(log, names=("a.wav", "b.wav", "c.wav"), size=64)
    with ram.open_write("/music/b.wav") as fh:
        fh.write(b"RIFF" + bytes(4096))
    monkeypatch.setattr(MP, "MAX_REMOTE_BYTES", 1024)
    jobs = Jobs()
    failures = []
    panel = MP.PlayerPanel(engine=FakeEngine(), run_in_background=jobs)
    try:
        panel.add_remote(ram, ["/music"], play_first=True, failed=failures.append)
        jobs.run_all()
        assert rows(panel) == ["a.wav"]  # b failed, c never copied
        assert ("open", "c.wav") not in log
        assert failures and "larger than" in str(failures[0])
        assert "larger than" in panel.note.text()
        path = panel.playlist.item(0).data(Qt.ItemDataRole.UserRole)
        assert os.path.isfile(path)  # the playing copy stays
        folder = media_folders(temp_root)
        assert len(folder) == 1 and not list(folder[0].glob("1/*"))  # b's part is gone
    finally:
        panel.close()
    MP.deactivate(None)
    assert media_folders(temp_root) == []


def test_sad_the_first_file_failing_leaves_no_folder(temp_root, monkeypatch):
    log = []
    monkeypatch.setattr(MP, "MAX_REMOTE_BYTES", 10)
    jobs = Jobs()
    panel = MP.PlayerPanel(engine=FakeEngine(), run_in_background=jobs)
    try:
        panel.add_remote(music(log), ["/music"])
        jobs.run_all()
        assert rows(panel) == []
        assert "larger than" in panel.note.text()
        assert media_folders(temp_root) == []
    finally:
        panel.close()


def test_sad_nothing_to_copy_makes_no_folder_and_says_so(temp_root):
    log = []
    ram = music(log, names=())
    with ram.open_write("/music/readme.txt") as fh:
        fh.write(b"hi")
    jobs = Jobs()
    panel = MP.PlayerPanel(engine=FakeEngine(), run_in_background=jobs)
    try:
        panel.add_remote(ram, ["/music", "/gone.wav"])
        jobs.run_all()
        assert rows(panel) == []
        assert media_folders(temp_root) == []
        assert "Skipped" in panel.note.text()
    finally:
        panel.close()


# -- edge -------------------------------------------------------------------------------


def test_edge_the_total_bound_counts_over_all_copies(temp_root, monkeypatch):
    log = []
    ram = music(log, size=600)
    monkeypatch.setattr(MP, "MAX_REMOTE_TOTAL_BYTES", 1500)  # two files fit, not three
    jobs = Jobs()
    panel = MP.PlayerPanel(engine=FakeEngine(), run_in_background=jobs)
    try:
        panel.add_remote(ram, ["/music"])
        jobs.run_all()
        assert rows(panel) == ["a.wav", "b.wav"]
        assert "together" in panel.note.text()
    finally:
        panel.close()


def test_edge_a_panel_that_closed_copies_no_further(temp_root):
    log = []
    jobs = Jobs()
    panel = MP.PlayerPanel(engine=FakeEngine(), run_in_background=jobs)
    panel.add_remote(music(log), ["/music"])
    jobs.run_next()  # list
    jobs.run_next()  # copy a
    panel.shutdown()
    jobs.run_all()  # what was already handed on finishes quietly
    assert ("open", "c.wav") not in log
    assert not jobs.pending
    MP.deactivate(None)
    assert media_folders(temp_root) == []
