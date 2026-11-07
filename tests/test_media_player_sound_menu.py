"""The Media Player's sound menu: output device, sleep timer, Audio Mixer.

The request: perfect the sound/audio options and the Media Player. The
player's "…" button next to the volume opens a menu with *Output* (the
Media Player's own channel of the Audio Mixer: *Same as the output* or a
device - saved as ``media_output`` and followed at once), *Sleep Timer*
(pause after 15-90 minutes, fading out over the last seconds, or at the end
of the track) and *Audio Mixer…*. Driven offscreen with the in-memory
sink; the device list is the ``output_lister`` seam.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import struct
import sys
import time
import wave
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import audio_route as AR  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_media_player_sound", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["bundled_media_player_sound"] = MP
_spec.loader.exec_module(MP)

# Playing needs the numpy engine on Qt Multimedia (which needs libpulse &
# co.); the menus need neither, so without them only playback is skipped.
try:
    import numpy  # noqa: F401
    import PyQt6.QtMultimedia  # noqa: F401

    CAN_PLAY = True
except ImportError:
    CAN_PLAY = False

needs_playback = pytest.mark.skipif(
    not CAN_PLAY, reason="no numpy or Qt Multimedia cannot be loaded: nothing plays")


class MenuEngine(MP.PendingEngine):
    """An engine that plays nothing but keeps its volume, for the menus."""

    def __init__(self) -> None:
        super().__init__()
        self.volume = 1.0

    def set_volume(self, volume: float) -> None:
        self.volume = float(volume)


def engine():
    if CAN_PLAY:
        return MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink())
    return MenuEngine()

HEADSET = ("bluez_output.AA_BB_CC_DD_EE_07.1", "Studio Headset")
SPEAKERS = ("alsa_output.pci", "Built-in Speakers")


@pytest.fixture
def audio_json(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    AR.forget()
    yield tmp_path / ".config" / "axross" / "audio.json"
    AR.forget()


def tone_wav(path: Path, seconds: float) -> Path:
    rate = 44100
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", int(8000 * math.sin(i / 20)))
                               for i in range(int(rate * seconds))))
    return path


@pytest.fixture
def panel(audio_json):
    made = []

    def build(**kw):
        opened = []
        p = MP.PlayerPanel(engine=engine(),
                           output_lister=lambda: [SPEAKERS, HEADSET],
                           open_mixer=lambda: opened.append(1), **kw)
        p.opened = opened
        p.show()
        made.append(p)
        return p

    yield build
    for p in made:
        p.close()
        p.deleteLater()


def wait(cond, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return bool(cond())


def entries(menu) -> dict:
    menu.aboutToShow.emit()
    return {a.text(): a for a in menu.actions() if not a.isSeparator()}


def sub(panel, title):
    return entries(panel.sound_menu)[title].menu()


def test_happy_the_sound_menu(panel):
    p = panel()
    assert list(entries(p.sound_menu)) == ["Output", "Sleep Timer", "Audio Mixer…"]


def test_happy_choosing_an_output_saves_the_media_channel(panel, audio_json):
    p = panel()
    out = entries(sub(p, "Output"))
    assert list(out) == ["Same as the output", "Built-in Speakers", "Studio Headset"]
    assert out["Same as the output"].isChecked()
    out["Studio Headset"].trigger()
    assert json.loads(audio_json.read_text())["media_output"] == HEADSET[0]
    assert AR.source_output_id("media") == HEADSET[0]
    assert entries(sub(p, "Output"))["Studio Headset"].isChecked()


def test_sad_a_chosen_device_that_is_gone_stays_listed(panel, audio_json):
    AR.update(media_output="bluez_output.GONE")
    p = panel()
    out = entries(sub(p, "Output"))
    gone = next(a for t, a in out.items() if "not connected" in t)
    assert gone.isChecked()


def test_sad_before_the_audio_check_no_devices_are_listed(audio_json, monkeypatch):
    from core import multimedia_probe as MPROBE

    monkeypatch.setattr(MPROBE, "cached", lambda: None)
    p = MP.PlayerPanel(engine=engine())
    try:
        out = entries(sub(p, "Output"))
        texts = list(out)
        assert texts[0] == "Same as the output"
        assert not out[texts[1]].isEnabled()  # the note, not a device
        assert "Audio Mixer…" not in entries(p.sound_menu)  # no mixer to open
    finally:
        p.close()


def test_happy_audio_mixer_entry(panel):
    p = panel()
    entries(p.sound_menu)["Audio Mixer…"].trigger()
    assert p.opened == [1]


@needs_playback
def test_happy_sleep_timer_fades_out_and_pauses(panel, tmp_path):
    p = panel()
    p.add_files([str(tone_wav(tmp_path / "a.wav", 30))])
    p.play_selected()
    assert wait(lambda: p.engine.state == "playing", 5)
    entries(sub(p, "Sleep Timer"))["15 minutes"].trigger()
    assert p.sleep_minutes == 15 and p.sleep_label.text() == "Sleep: 15 min"
    full = p.engine.volume
    # nearly up: the fade has begun
    p._sleep_deadline = time.monotonic() + p.SLEEP_FADE_SECONDS / 2
    p._sleep_tick()
    assert 0 < p.engine.volume < full
    # up: paused, the volume back, the timer off
    p._sleep_deadline = time.monotonic() - 1
    p._sleep_tick()
    assert p.engine.state != "playing"
    assert p.engine.volume == pytest.approx(full)
    assert p.sleep_minutes == 0 and not p.sleep_label.isVisible()
    assert "sleep timer" in p.note.text()


@needs_playback
def test_happy_sleep_at_the_end_of_the_track(panel, tmp_path):
    p = panel()
    p.add_files([str(tone_wav(tmp_path / "a.wav", 0.3)), str(tone_wav(tmp_path / "b.wav", 5))])
    entries(sub(p, "Sleep Timer"))["At the End of the Track"].trigger()
    assert p.sleep_label.text() == "Sleep: end of track"
    p.play_selected()
    assert wait(lambda: "end of the track" in p.note.text(), 10)
    assert p.engine.path.endswith("a.wav")  # b.wav was not started
    assert p.sleep_minutes == 0


def test_edge_turning_the_timer_off_mid_fade_restores_the_volume(panel, tmp_path):
    p = panel()
    full = p.engine.volume
    p.set_sleep_timer(30)
    p._sleep_deadline = time.monotonic() + 1
    p._sleep_tick()
    assert p.engine.volume < full
    entries(sub(p, "Sleep Timer"))["Off"].trigger()
    assert p.engine.volume == pytest.approx(full)
    assert not p._sleep_timer.isActive()


# --- the audio check failed (product review) ---------------------------------
# Output still said "(the devices are listed once the audio check answered)"
# after the check had answered that there is no sound, and the Sleep Timer
# was offered for a player that cannot play.

REASON = "Qt Multimedia failed: libpulse.so.0: cannot open shared object file"


def _failed_panel(**kw):
    from core.multimedia_probe import ProbeResult

    return MP.PlayerPanel(audio_probe=lambda: ProbeResult(False, REASON),
                          open_mixer=lambda: None, **kw)


def test_sad_a_failed_audio_check_says_there_is_no_sound_and_why(audio_json):
    p = _failed_panel()
    try:
        assert p.audio_error  # the panel's own message is there too
        out = sub(p, "Output")
        texts = [a.text() for a in out.actions()]
        assert texts == [f"No sound: {REASON}"]
        assert not out.actions()[0].isEnabled()
        assert not any("once the audio check answered" in t for t in texts)
    finally:
        p.close()


def test_sad_no_sleep_timer_while_the_player_cannot_play(audio_json):
    p = _failed_panel()
    try:
        assert list(entries(p.sound_menu)) == ["Output", "Audio Mixer…"]
    finally:
        p.close()


def test_sad_a_failed_check_of_another_panel_counts_too(audio_json, monkeypatch):
    """A panel still waiting (no engine yet) after this run's check failed."""
    from core import multimedia_probe as MPROBE

    monkeypatch.setattr(MPROBE, "cached", lambda: MPROBE.ProbeResult(False, REASON))
    p = MP.PlayerPanel(audio_probe=lambda: MPROBE.ProbeResult(True),
                       run_in_background=lambda work, done, failed: None)
    try:
        assert p.no_sound_reason() == REASON
        assert "Sleep Timer" not in entries(p.sound_menu)
    finally:
        p.close()


def test_edge_try_again_that_works_offers_the_sleep_timer_again(audio_json):
    p = _failed_panel(output_lister=lambda: [SPEAKERS])
    try:
        assert "Sleep Timer" not in entries(p.sound_menu)
        p.audio_error = p.audio_reason = ""  # what Try Again clears
        assert list(entries(p.sound_menu)) == ["Output", "Sleep Timer", "Audio Mixer…"]
        assert list(entries(sub(p, "Output"))) == ["Same as the output", "Built-in Speakers"]
    finally:
        p.close()
