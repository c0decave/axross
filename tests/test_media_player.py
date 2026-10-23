"""The Media Player extension (punch-list item 21).

Operator: *„extension -> media player mit lame, wav, ogg, vorbis support mit
equalizer, fenster mit fancy animation zum sound..."*. Decided: an extension;
with numpy a 10-band equalizer, a spectrum visualizer, playlist, tags and
cover; without numpy plain playback.

The DSP is plain numpy and tested on numbers; the playback chain (Qt's
FFmpeg decoder -> equalizer -> audio sink) runs against a sink that keeps
the bytes, because the test host has no sound card. The fixtures are one
second of a 440 Hz sine (tests/fixtures/audio/generate.sh).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
AUDIO = Path(__file__).resolve().parent / "fixtures" / "audio"
RATE = 44100


def load():
    path = EX.bundled_dir() / "media_player.py"
    spec = importlib.util.spec_from_file_location("example_media_player", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = load()


def sine(freq, seconds=0.5, rate=RATE, amp=0.5):
    t = np.arange(int(seconds * rate)) / rate
    mono = (amp * np.sin(2 * np.pi * freq * t)).astype(np.float32)
    return np.stack([mono, mono], axis=1)


def run_eq(eq, signal, block=1000):
    out = [eq.process(signal[i:i + block]) for i in range(0, len(signal), block)]
    out.append(eq.flush())
    joined = np.concatenate([o for o in out if len(o)])
    return joined[eq.latency:eq.latency + len(signal)]


def rms(x):
    return float(np.sqrt(np.mean(np.square(x))))


# -- DSP ----------------------------------------------------------------------------


class TestEqualizer:
    def test_happy_flat_is_identity_across_any_block_size(self):
        signal = sine(440) + sine(5000, amp=0.2)
        for block in (64, 1000, 4096):
            out = run_eq(MP.Equalizer(RATE, channels=2), signal, block)
            assert out.shape == signal.shape
            assert np.max(np.abs(out - signal)) < 1e-4, block

    def test_happy_a_boost_raises_its_band_and_leaves_the_others(self):
        eq = MP.Equalizer(RATE, channels=2)
        gains = [0.0] * 10
        gains[MP.BANDS.index(1000)] = 12.0
        eq.set_gains(gains)
        boosted = run_eq(eq, sine(1000))
        eq2 = MP.Equalizer(RATE, channels=2)
        eq2.set_gains(gains)
        low = run_eq(eq2, sine(62))
        ratio = rms(boosted[RATE // 10:]) / rms(sine(1000)[RATE // 10:])
        assert 3.0 < ratio < 4.5  # +12 dB is x3.98
        assert abs(rms(low[RATE // 10:]) / rms(sine(62)[RATE // 10:]) - 1) < 0.1

    def test_sad_gains_are_clamped_and_must_be_ten(self):
        eq = MP.Equalizer(RATE, channels=2)
        eq.set_gains([99] * 10)
        assert eq.gains_db == [MP.MAX_GAIN_DB] * 10
        with pytest.raises(ValueError):
            eq.set_gains([0] * 9)

    def test_edge_empty_blocks_and_mono(self):
        eq = MP.Equalizer(RATE, channels=1)
        assert len(eq.process(np.zeros((0, 1), np.float32))) == 0
        mono = sine(440)[:, :1]
        assert np.max(np.abs(run_eq(eq, mono) - mono)) < 1e-4

    def test_edge_presets_are_ten_bands_in_range(self):
        assert "Flat" in MP.PRESETS
        for name, gains in MP.PRESETS.items():
            assert len(gains) == 10 and all(abs(g) <= MP.MAX_GAIN_DB for g in gains), name


class TestSpectrum:
    def test_happy_the_peak_bar_holds_the_tone(self):
        bars = MP.spectrum_bars(sine(1000)[:2048], RATE, n_bars=32)
        centres = MP.bar_centres(RATE, 2048, 32)
        assert len(bars) == 32 and bars.max() <= 1.0 and bars.min() >= 0.0
        peak = int(np.argmax(bars))
        assert abs(np.log2(centres[peak] / 1000)) < 0.5

    def test_edge_silence_is_all_zero(self):
        assert MP.spectrum_bars(np.zeros((2048, 2), np.float32), RATE, n_bars=16).max() == 0.0


def test_happy_audio_files_by_suffix():
    assert MP.is_audio("song.MP3") and MP.is_audio("a.ogg") and MP.is_audio("x.flac")
    assert not MP.is_audio("notes.txt") and not MP.is_audio("mp3")


# -- the playback chain ----------------------------------------------------------------


def _wait(cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    return False


@pytest.mark.parametrize("name", ["sine.wav", "sine.mp3", "sine.ogg", "sine.flac"])
def test_e2e_every_format_decodes_through_the_equalizer(name):
    sink = MP.MemorySink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(AUDIO / name))
    engine.play()
    assert _wait(lambda: engine.finished), engine.error
    pcm = sink.samples(channels=2)
    assert engine.error == ""
    assert abs(len(pcm) - RATE) < RATE * 0.06  # one second, give or take codec padding
    left, right = pcm[:, 0], pcm[:, 1]
    assert rms(left[2000:-2000]) > 0.1 and rms(right[2000:-2000]) < 0.02


def test_happy_the_equalizer_changes_what_is_played():
    flat_sink, cut_sink = MP.MemorySink(), MP.MemorySink()
    flat = MP.EqEngine(sink_factory=lambda fmt: flat_sink)
    cut = MP.EqEngine(sink_factory=lambda fmt: cut_sink)
    gains = [0.0] * 10
    gains[MP.BANDS.index(500)] = -12.0
    cut.set_gains(gains)
    for engine in (flat, cut):
        engine.load(str(AUDIO / "sine.wav"))
        engine.play()
        assert _wait(lambda e=engine: e.finished)
    ratio = rms(cut_sink.samples(2)[5000:-5000, 0]) / rms(flat_sink.samples(2)[5000:-5000, 0])
    assert ratio < 0.6  # 440 Hz sits between the 250 and 500 Hz bands


def test_happy_spectrum_follows_playback():
    engine = MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink())
    engine.load(str(AUDIO / "sine.wav"))
    engine.play()
    assert _wait(lambda: engine.finished)
    bars = engine.current_bars(16)
    assert bars.max() > 0.3


def test_sad_a_missing_or_broken_file_reports_an_error(tmp_path):
    broken = tmp_path / "broken.mp3"
    broken.write_bytes(b"not audio at all" * 100)
    for path in (tmp_path / "missing.ogg", broken):
        engine = MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink())
        engine.load(str(path))
        engine.play()
        assert _wait(lambda: engine.error != "" or engine.finished)
        assert engine.error


def test_edge_stop_and_pause():
    sink = MP.MemorySink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(AUDIO / "sine.wav"))
    engine.play()
    engine.pause()
    assert engine.state == "paused"
    engine.stop()
    assert engine.state == "stopped" and engine.position_ms() == 0


# -- the panel ---------------------------------------------------------------------


def test_happy_panel_playlist_eq_and_visualizer(tmp_path):
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink()))
    try:
        panel.add_files([str(AUDIO / "sine.wav"), str(AUDIO / "sine.ogg"), str(tmp_path / "x.txt")])
        assert panel.playlist.count() == 2  # the text file is no audio
        panel.preset.setCurrentText("Bass boost")
        assert panel.engine.gains_db == MP.PRESETS["Bass boost"]
        assert [s.value() for s in panel.sliders] == [round(g) for g in MP.PRESETS["Bass boost"]]
        panel.playlist.setCurrentRow(0)
        panel.play_selected()
        assert _wait(lambda: panel.engine.finished)
        panel.resize(700, 400)
        panel.show()
        panel.visualizer.tick()
        img = panel.visualizer.grab().toImage()
        assert len({img.pixelColor(x, img.height() - 3).name() for x in range(0, img.width(), 3)}) > 1
        assert "sine" in panel.now_playing.text()
    finally:
        panel.close()


def test_edge_next_track_starts_when_one_ends(tmp_path):
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink()))
    try:
        panel.add_files([str(AUDIO / "sine.wav"), str(AUDIO / "sine.flac")])
        panel.playlist.setCurrentRow(0)
        panel.play_selected()
        assert _wait(lambda: panel.playlist.currentRow() == 1, timeout=20)
    finally:
        panel.close()


def test_e2e_extension_loads_and_plays_from_the_pane(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    info = next(e for e in EX.discover() if e.module_name == "media_player")
    EX.set_enabled(info.ext_id, True)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        host = win.extension_host
        assert _wait(lambda: host.module(info.ext_id) is not None, 10)
        assert host.error(info.ext_id) == ""
        (dock,) = host.docks(info.ext_id)
        assert dock.windowTitle() == "Media Player"
        import shutil

        music = tmp_path / "music"
        music.mkdir()
        for name in ("sine.wav", "sine.mp3", "sine.ogg", "sine.flac"):
            shutil.copy(AUDIO / name, music / name)
        pane = win._active_pane
        pane.navigate(str(music))
        pane._table.selectAll()
        labels = [a.text() for a in pane._build_context_menu().actions()]
        assert "Play in Media Player" in labels
        panel = dock.widget()
        panel.engine.sink_factory = lambda fmt: MP.MemorySink()
        next(a for a in pane._build_context_menu().actions() if a.text() == "Play in Media Player").trigger()
        assert panel.playlist.count() == 4
        assert _wait(lambda: panel.engine.state in ("playing", "stopped") and panel.engine.loaded)
    finally:
        win.close()
        win.deleteLater()


def test_edge_switching_the_equalizer_off_and_on_keeps_the_gains():
    engine = MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink())
    engine.set_gains(MP.PRESETS["Rock"])
    engine.set_eq_enabled(False)
    assert engine.equalizer.flat and engine.gains_db == MP.PRESETS["Rock"]
    engine.set_eq_enabled(True)
    assert engine.equalizer.gains_db == MP.PRESETS["Rock"]
    panel = MP.PlayerPanel(engine=engine)
    try:
        panel.preset.setCurrentText("Vocal")
        panel.eq_check.setChecked(False)
        assert engine.equalizer.flat
        panel.eq_check.setChecked(True)
        assert engine.equalizer.gains_db == MP.PRESETS["Vocal"]
    finally:
        panel.close()


# -- round-2 verification: decoding stays just ahead of playback ----------------------


class _StalledSink(MP.MemorySink):
    """A sound card that takes nothing until *open* is set."""

    open = False

    def bytes_free(self) -> int:
        return (1 << 30) if self.open else 0


def _long_wav(path, seconds):
    import wave

    frames = int(seconds * RATE)
    t = np.arange(frames) / RATE
    mono = (0.3 * np.sin(2 * np.pi * 440 * t) * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(np.stack([mono, mono], axis=1).tobytes())
    return frames


def test_edge_a_long_track_is_decoded_only_a_little_ahead_and_plays_whole(tmp_path):
    """The whole track was decoded as fast as the decoder went and kept as
    float samples until played: memory grew with the track's length
    (30 s of play had 90 s decoded; a one-hour track ~1 GB)."""
    frames = _long_wav(tmp_path / "long.wav", 40)
    sink = _StalledSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(tmp_path / "long.wav"))
    engine.play()
    end = time.time() + 4
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)
    ahead = engine._decoded_frames / RATE
    assert ahead <= MP.MAX_AHEAD_SECONDS + 1.0, ahead
    assert len(engine._pending) <= (MP.MAX_AHEAD_SECONDS + 1.0) * RATE * 8
    sink.open = True
    end = time.time() + 60
    while not engine.finished and time.time() < end:
        APP.processEvents()
        time.sleep(0.002)
    assert engine.finished and not engine.error
    assert len(sink.samples()) == frames


class _RemoteApi:
    """The extension API for a remote pane: background work runs at once."""

    def __init__(self):
        self.actions, self.notes, self.docks = {}, [], []

    def add_dock(self, title, widget):
        self.docks.append(widget)

    def add_context_action(self, label, cb, applies_to="any", extensions=()):
        self.actions[label] = cb

    def run_in_background(self, work, on_done=None, on_error=None):
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 - handed on like the host does
            on_error(exc)
            return
        on_done(result)

    def notify(self, text):
        self.notes.append(text)


def _remote_ctx(paths):
    from types import SimpleNamespace

    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    for path in paths:
        with ram.open_write(path) as fh:
            fh.write((AUDIO / "sine.wav").read_bytes())
    return SimpleNamespace(backend=ram, folder="/", paths=list(paths), items=[], pane=None,
                           is_local=False)


def _media_temp_folders(tmp_root):
    return sorted(p for p in Path(tmp_root).glob("axross-media-*"))


def test_sad_remote_copies_are_removed_on_error_and_when_the_extension_unloads(tmp_path,
                                                                              monkeypatch):
    """A remote track is copied to a temporary folder to play; those folders
    (up to 512 MB each) stayed until reboot, a failed copy's too."""
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))  # the player saves its state there
    api = _RemoteApi()
    MP.activate(api)
    panel = api.docks[0]
    panel.engine.sink_factory = lambda fmt: MP.MemorySink()
    try:
        monkeypatch.setattr(MP, "MAX_REMOTE_BYTES", 100)
        api.actions["Play in Media Player"](_remote_ctx(["/big.wav"]))
        assert any("larger than" in n for n in api.notes)
        assert _media_temp_folders(tmp_path) == []
        monkeypatch.setattr(MP, "MAX_REMOTE_BYTES", 512 * 1024 * 1024)
        api.actions["Play in Media Player"](_remote_ctx(["/a.wav"]))
        assert panel.playlist.count() == 1
        assert len(_media_temp_folders(tmp_path)) == 1
    finally:
        panel.engine.stop()
    MP.deactivate(api)
    assert _media_temp_folders(tmp_path) == []
