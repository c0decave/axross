"""The Media Player's -15 s / +15 s buttons (the user: "15s rewind and forward
wind support with button"): from where the track is, never before its
start; past its end the track ends as usual - the next one plays, repeat
one replays it, the last one stops; paused stays paused; nothing loaded,
nothing happens."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)

from tests.test_media_player_controls import MP, APP, fake_panel, names  # noqa: E402


def _playing(panel, engine, at_ms: int, row: int = 0):
    panel.play_item(panel.playlist.item(row))
    engine.play()
    engine.seek(at_ms)
    APP.processEvents()


def test_happy_the_buttons_skip_15_seconds_back_and_forth(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path)
    try:
        _playing(panel, engine, 60_000)
        panel.forward15_button.click()
        assert engine.position == 75_000
        panel.back15_button.click()
        panel.back15_button.click()
        assert engine.position == 45_000
        assert engine.state == "playing"
        assert panel.time_label.text().startswith("0:45")
    finally:
        panel.close()


def test_edge_back_stops_at_the_start(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path)
    try:
        _playing(panel, engine, 7_000)
        panel.back15_button.click()
        assert engine.position == 0
        assert engine.state == "playing"
    finally:
        panel.close()


def test_edge_forward_past_the_end_ends_the_track_as_usual(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path)
    try:
        _playing(panel, engine, engine.duration - 5_000)
        panel.forward15_button.click()
        # a moment before the end: the track ends there by itself
        assert engine.position == engine.duration - MP.SKIP_END_MARGIN_MS
        engine.end()
        APP.processEvents()
        assert names(engine) == ["t0.wav", "t1.wav"]
    finally:
        panel.close()


def test_edge_paused_stays_paused(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path)
    try:
        _playing(panel, engine, 30_000)
        engine.pause()
        panel.forward15_button.click()
        assert engine.state == "paused"
        assert engine.position == 45_000
    finally:
        panel.close()


def test_sad_nothing_loaded_nothing_happens(tmp_path):
    panel, engine, _paths = fake_panel(tmp_path)
    try:
        panel.forward15_button.click()
        panel.back15_button.click()
        assert engine.seeks == []
    finally:
        panel.close()


def test_happy_the_buttons_sit_beside_play_with_icons_and_names(tmp_path):
    panel, _engine, _paths = fake_panel(tmp_path)
    try:
        assert panel.back15_button.property("control") == "back15"
        assert panel.forward15_button.property("control") == "forward15"
        assert panel.back15_button.accessibleName() == "Back 15 seconds"
        assert "15" in panel.forward15_button.toolTip()
        panel.resize(520, 400)
        panel.show()
        APP.processEvents()
        x = {b: b.mapTo(panel, b.rect().topLeft()).x()
             for b in (panel.prev_button, panel.back15_button, panel.play_button,
                       panel.forward15_button, panel.next_button)}
        assert x[panel.prev_button] < x[panel.back15_button] < x[panel.play_button]
        assert x[panel.play_button] < x[panel.forward15_button] < x[panel.next_button]
        assert panel.back15_button.isVisible() and panel.forward15_button.isVisible()
    finally:
        panel.close()
