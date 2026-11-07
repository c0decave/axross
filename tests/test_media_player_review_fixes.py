"""Media Player defects found by the review of 2026-11-06.

Playlist and state files: an ``#EXTINF:inf`` length raised OverflowError out
of a button slot; a track named ``#1 Crush.mp3`` was saved as a line that
reads back as a comment; Windows (cp1252) playlists lost ’ – … € names;
saving over a shared playlist made it owner-only; the player wrote files
larger than its own readers accept; a file name that is no UTF-8 failed
every save of the state (and the unload with it, the music kept playing).
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_review_fixes_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_review_fixes_ext"] = MP
_spec.loader.exec_module(MP)


class FakeEngine(QObject):
    """An engine without Qt Multimedia (as in the playlist tests)."""

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
        self.changed.emit()

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


def _track(folder: Path, name: str) -> Path:
    path = folder / name
    path.write_bytes(b"ID3")
    return path


# --- playlists ---------------------------------------------------------------


@pytest.mark.parametrize("length", ["inf", "-inf", "1e999", "nan"])
def test_sad_an_infinite_extinf_length_is_no_length_not_a_crash(tmp_path, length):
    _track(tmp_path, "a.mp3")
    entries, skipped = MP.parse_m3u(f"#EXTM3U\n#EXTINF:{length},Song\na.mp3\n".encode(),
                                    str(tmp_path))
    assert skipped == 0 and entries[0].duration == 0 and entries[0].title == "Song"


def test_happy_a_track_named_with_a_hash_survives_save_and_load(tmp_path):
    hashed = _track(tmp_path, "#1 Crush.mp3")
    spaced = _track(tmp_path, " intro.mp3")
    plain = _track(tmp_path, "b.mp3")
    target = tmp_path / "list.m3u"
    written, skipped = MP.write_playlist(str(target), [MP.PlaylistEntry(str(p))
                                                       for p in (hashed, spaced, plain)])
    assert (written, skipped) == (3, 0)
    assert "./#1 Crush.mp3" in target.read_text(encoding="utf-8")
    entries, skipped = MP.read_playlist(str(target))
    assert [os.path.basename(e.path) for e in entries] == ["#1 Crush.mp3", " intro.mp3", "b.mp3"]
    assert skipped == 0


def test_happy_a_windows_playlist_keeps_its_cp1252_names(tmp_path):
    _track(tmp_path, "Don’t Stop – Live….mp3")
    data = "#EXTM3U\r\nDon’t Stop – Live….mp3\r\n".encode("cp1252")
    entries, skipped = MP.parse_m3u(data, str(tmp_path))
    assert skipped == 0
    assert os.path.basename(entries[0].path) == "Don’t Stop – Live….mp3"


def test_edge_a_latin1_byte_x85_does_not_cut_the_line(tmp_path):
    """str.splitlines cut at \\x85 (NEL): one entry became two broken ones."""
    _track(tmp_path, "a…b.mp3")
    entries, skipped = MP.parse_m3u(b"a\x85b.mp3\n", str(tmp_path))
    assert skipped == 0 and os.path.basename(entries[0].path) == "a…b.mp3"


def test_happy_saving_over_a_shared_playlist_keeps_its_mode(tmp_path):
    _track(tmp_path, "a.mp3")
    target = tmp_path / "shared.m3u"
    target.write_text("#EXTM3U\n", encoding="utf-8")
    target.chmod(0o644)
    MP.write_playlist(str(target), [MP.PlaylistEntry(str(tmp_path / "a.mp3"))])
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_sad_a_playlist_is_never_written_larger_than_it_can_be_read(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "MAX_PLAYLIST_BYTES", 400)
    tracks = [_track(tmp_path, f"track-{n:03d}-with-a-long-name.mp3") for n in range(40)]
    target = tmp_path / "big.m3u"
    written, skipped = MP.write_playlist(str(target), [MP.PlaylistEntry(str(t)) for t in tracks])
    assert written + skipped == 40 and skipped > 0
    assert target.stat().st_size <= 400
    entries, _skipped = MP.read_playlist(str(target))   # no "larger than" refusal
    assert len(entries) == written


# --- the state file ------------------------------------------------------------


def test_sad_a_file_name_that_is_no_utf8_does_not_break_saving(tmp_path):
    name = os.fsdecode(b"caf\xe9.mp3")          # a lone surrogate in the str
    state = {"version": MP.STATE_VERSION, "tracks": [{"path": f"/music/{name}", "title": "",
                                                      "duration": 0}], "current": 0}
    target = tmp_path / "state.json"
    MP.write_state(target, state)
    back, usable = MP.read_state(target)
    assert usable and back["tracks"][0]["path"] == f"/music/{name}"


def test_sad_a_state_too_large_keeps_its_first_tracks(tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "MAX_STATE_BYTES", 2000)
    tracks = [{"path": f"/music/{'x' * 40}-{n}.mp3", "title": "", "duration": 0}
              for n in range(200)]
    text = MP.encode_state({"version": 1, "tracks": tracks, "current": 150,
                            "position_ms": 1234})
    assert len(text) <= 2000
    data = json.loads(text)
    assert 0 < len(data["tracks"]) < 200 and data["tracks"][0] == tracks[0]
    assert data["current"] == -1 and data["position_ms"] == 0   # it was cut off
    target = tmp_path / "state.json"
    target.write_text(text, encoding="ascii")
    assert MP.read_state(target)[1]


def test_sad_a_failing_save_is_reported_not_raised_and_the_unload_still_stops(tmp_path,
                                                                             monkeypatch):
    def broken(*_a, **_k):
        raise ValueError("the player state is too large to save")

    monkeypatch.setattr(MP, "write_state", broken)
    engine = FakeEngine()
    panel = MP.PlayerPanel(engine=engine, state_path=str(tmp_path / "s.json"))
    try:
        panel.save_state()
        assert "Cannot save the player state" in panel.note.text()
        engine.state = "playing"
        panel.shutdown()
        assert engine.state == "stopped"
    finally:
        panel.deleteLater()
