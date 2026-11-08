"""The Media Player's equalizer row is axross's one (core.audio_route): a
band moved is saved there 250 ms later (one save for a whole drag), and
every panel and the Audio Mixer take it.

What was wrong: the save was left to that timer when the panel closed or
the extension unloaded. After shutdown() it saved nothing (the panel was
gone) - a band moved just before the unload was lost. A closed panel's
timer saved its bands whenever the event loop next ran - over what the
Audio Mixer had saved since - and every player playing then was re-tuned.
That made tests/test_media_player_controls.py's restored-position test
fail in 5 of 8 runs after the equalizer-slider test: the ramp's first
sample came out 6% high (+1 dB at the bottom band), read as "2.655 s
instead of 2.5 s". It looked like a seek that started at the wrong place.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", exc_type=ImportError)  # or no libpulse.so.0

from PyQt6.QtCore import Qt  # noqa: E402

from core import audio_route  # noqa: E402
from core.audio_settings import AudioSettings  # noqa: E402
from tests.media_testkit import need_multimedia_backend  # noqa: E402
from tests.test_media_player_controls import (  # noqa: E402
    MP,
    fake_panel,
    key,
    pump,
    ramp_seconds,
    ramp_wav,
    wait,
)

FLAT = [0.0] * 10


def saved_gains() -> list[float]:
    """The bands in audio.json (not core.audio_route's copy)."""
    return [float(g) for g in AudioSettings.load().eq_gains]


def move_the_bottom_band(panel) -> None:
    panel.show()
    band = panel.sliders[0]
    key(band, Qt.Key.Key_Up)
    assert band.value() == 1


@pytest.fixture(autouse=True)
def _flat_to_begin():
    audio_route.update(eq_gains=FLAT, eq_preset="Flat", eq_enabled=True)
    yield


def test_happy_shutdown_saves_a_band_moved_just_before(tmp_path):
    """The unload right after a band moved: the move is saved (it was lost -
    the timer found the panel gone)."""
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    try:
        move_the_bottom_band(panel)
        panel.shutdown()
        assert saved_gains()[0] == 1.0
        pump(0.4)  # the timer has nothing left to save
        assert saved_gains()[0] == 1.0
    finally:
        panel.close()


def test_happy_closing_saves_a_pending_band_at_once(tmp_path):
    """Closed, the panel saves its pending change then - not whenever the
    event loop next runs."""
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    try:
        move_the_bottom_band(panel)
        panel.close()
        assert saved_gains()[0] == 1.0
    finally:
        panel.close()


def test_sad_a_closed_panel_announces_nothing_later(tmp_path):
    """Nothing is published once the panel closed: the closed panel's timer
    published its bands up to 250 ms later, and every player playing then
    was re-tuned mid-track."""
    panel, _engine, _paths = fake_panel(tmp_path, 1)
    heard = []
    audio_route.notifier().changed.connect(heard.append)
    try:
        move_the_bottom_band(panel)
        panel.close()
        heard.clear()
        pump(0.4)
        assert heard == []
    finally:
        audio_route.notifier().changed.disconnect(heard.append)
        panel.close()


def test_e2e_the_next_panel_plays_with_the_moved_band_from_the_first_sample(tmp_path):
    """The case the controls tests hit: one panel moves a band and closes,
    the next panel at once plays a restored position. It starts with that
    band (it started flat and was re-tuned when the closed panel's timer
    fired, mid-track) and keeps it to the end."""
    need_multimedia_backend()
    first, _engine, _paths = fake_panel(tmp_path, 1)
    try:
        move_the_bottom_band(first)
    finally:
        first.close()
    moved = [1.0] + FLAT[1:]
    seconds = 6.0
    path = ramp_wav(tmp_path / "ramp.wav", seconds)
    state = tmp_path / "media_player.json"
    state.write_text(json.dumps({"version": 1, "tracks": [{"path": str(path)}], "current": 0,
                                 "position_ms": 2500}), encoding="utf-8")
    sink = MP.MemorySink()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink),
                           state_path=str(state))
    try:
        assert [float(s.value()) for s in panel.sliders] == moved
        panel.play_button.click()
        assert panel.engine.gains_db == moved
        assert wait(lambda: panel.engine.finished, 20)
        pump(0.4)  # past the 250 ms the closed panel's timer took
        assert panel.engine.gains_db == moved
        assert len(sink.samples()) > 0
    finally:
        panel.shutdown()
        panel.close()
