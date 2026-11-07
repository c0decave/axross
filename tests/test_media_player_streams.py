"""Streams in the Media Player: internet radio and files on a web server by
their http / https URL - added by "URL…", named in a playlist (.m3u of a
radio station), kept in the saved state, played by the engine (no seeking:
a stream has no position to go to). Asked for with the standalone player
("local files and stream URLs"); axross's panel has it too.
"""

from __future__ import annotations

import functools
import http.server
import importlib.util
import math
import os
import sys
import threading
import time
import wave
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_streams_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_streams_ext"] = MP
_spec.loader.exec_module(MP)

from tests.test_media_player_review_fixes import FakeEngine  # noqa: E402


@pytest.mark.parametrize("url,ok", [
    ("http://radio.example.org/live.mp3", True),
    ("https://example.org/a.ogg", True),
    ("HTTPS://example.org/stream", True),
    ("ftp://example.org/a.mp3", False),
    ("file://~", False),
    ("http://", False),
    ("~/a.mp3", False),
    ("http://example.org/a b.mp3", False),
    ("http://example.org/\x07.mp3", False),
    ("http://example.org/" + "x" * 3000, False),
])
def test_edge_what_counts_as_a_stream(url, ok):
    assert MP.is_stream(url) is ok


def test_happy_a_radio_playlist_names_streams_and_they_round_trip(tmp_path):
    (tmp_path / "a.mp3").write_bytes(b"ID3")
    data = (b"#EXTM3U\n#EXTINF:-1,Station One\nhttp://radio.example.org/one\n"
            b"ftp://example.org/x.mp3\na.mp3\n")
    entries, skipped = MP.parse_m3u(data, str(tmp_path))
    assert [e.path for e in entries][0] == "http://radio.example.org/one"
    assert entries[0].title == "Station One" and skipped == 1
    target = tmp_path / "radio.m3u8"
    MP.write_playlist(str(target), entries)
    assert "http://radio.example.org/one" in target.read_text(encoding="utf-8")
    back, _skipped = MP.read_playlist(str(target))
    assert [e.path for e in back] == [e.path for e in entries]


def test_happy_url_adds_a_stream_and_the_state_keeps_it(tmp_path):
    state = tmp_path / "s.json"
    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state))
    try:
        assert panel.add_stream("https://radio.example.org/live")
        assert not panel.add_stream("ftp://example.org/x.mp3")
        assert "only http" in panel.note.text()
        item = panel.playlist.item(0)
        assert item.text() == "radio.example.org - live"
        panel.save_state()
    finally:
        panel.shutdown()
        panel.deleteLater()
    again = MP.PlayerPanel(engine=FakeEngine(), state_path=str(state))
    try:
        again.restore_state()
        end = time.monotonic() + 5
        while again.playlist.count() == 0 and time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.01)
        assert again.playlist.item(0).data(MP._PATH_ROLE) == "https://radio.example.org/live"
    finally:
        again.shutdown()
        again.deleteLater()


# --- the engine plays a stream (needs Qt Multimedia) -------------------------------


def _tone(path: Path, seconds: float = 2.0, rate: int = 44100) -> Path:
    n = int(seconds * rate)
    frames = bytearray()
    for i in range(n):
        v = int(math.sin(2 * math.pi * 440 * i / rate) * 0.3 * 32767)
        frames += v.to_bytes(2, "little", signed=True) * 2
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))
    return path


@pytest.fixture
def web(tmp_path):
    _tone(tmp_path / "tone.wav")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path))

    class Quiet(handler.func):
        def log_message(self, *_a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0),
                                             functools.partial(Quiet, directory=str(tmp_path)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_happy_the_engine_plays_a_stream_and_does_not_seek_it(web):
    pytest.importorskip("numpy")
    pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)
    sink = MP.MemorySink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(f"{web}/tone.wav")
        engine.play()
        end = time.monotonic() + 10
        while len(sink.data) < 44100 * 4 // 2 and not engine.error and time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.01)
        assert engine.error == ""
        assert len(sink.data) >= 44100 * 4 // 2     # half a second of audio arrived
        before = engine.position_ms()
        engine.seek(before + 60_000)
        assert engine.state == "playing" and not engine.finished
    finally:
        engine.close()


def test_happy_the_url_button_is_in_the_playlist_row(tmp_path):
    from PyQt6.QtWidgets import QPushButton

    panel = MP.PlayerPanel(engine=FakeEngine(), state_path=str(tmp_path / "s.json"))
    try:
        texts = [b.text() for b in panel.playlist_buttons.findChildren(QPushButton)
                 if panel.playlist_buttons.layout().indexOf(b) >= 0]
        assert texts[:4] == ["Add…", "URL…", "Remove", "Clear"]
    finally:
        panel.shutdown()
        panel.deleteLater()
