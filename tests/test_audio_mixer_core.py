"""The Audio Mixer's settings: one equalizer and a channel per source.

The request: a general audio mixer for all needed sound settings - outputs,
what plays where, volumes, equalizer. This file is its core:

* core/audio_eq.py - the equalizer moved out of the Media Player: one for
  everything axross plays, with its setting in the audio settings
  (``eq_enabled``, ``eq_preset``, ``eq_gains``); :func:`equalize_int16`
  runs it over a piece of PCM (the Agent's voice).
* core/audio_settings.py / core/audio_route.py - a master mute and, per
  source (Media Player, Agent voice, media preview), a volume, a mute and an
  output of its own; ``source_gain``, ``source_output_id``, ``eq_gains`` and
  ``update`` (save and publish).
* The Media Player's equalizer row is a view of that setting: a change
  there is saved for all, a change elsewhere shows there.
"""

from __future__ import annotations

import array
import json
import math
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import audio_eq as AEQ  # noqa: E402
from core import audio_route as AR  # noqa: E402
from core.audio_settings import FIELDS, AudioSettings  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def own_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    AR.forget()
    yield tmp_path / ".config" / "axross" / "audio.json"
    AR.forget()


def tone(rate: int, hz: float, seconds: float, amp: float = 0.3) -> bytes:
    n = int(rate * seconds)
    return array.array("h", (int(amp * 32767 * math.sin(2 * math.pi * hz * i / rate))
                             for i in range(n))).tobytes()


def rms(pcm: bytes) -> float:
    samples = array.array("h", pcm)
    return math.sqrt(sum(s * s for s in samples) / max(1, len(samples)))


# =====================================================================================
# the equalizer
# =====================================================================================

class TestEq:
    def test_happy_presets_and_names(self):
        assert AEQ.preset_of(AEQ.PRESETS["Rock"]) == "Rock"
        assert AEQ.preset_of([1.0] * 10) == AEQ.CUSTOM
        assert AEQ.gains_ok(AEQ.PRESETS["Vocal"])

    def test_sad_gains_that_are_not_ten_numbers(self):
        for bad in ([0.0] * 9, "flat", [0.0] * 9 + [True], [0.0] * 9 + [13.0]):
            assert not AEQ.gains_ok(bad)
        with pytest.raises(ValueError):
            AEQ.clean_gains([0.0] * 9 + [float("nan")])
        assert AEQ.clean_gains([20] + [0] * 9)[0] == AEQ.MAX_GAIN_DB

    @pytest.mark.skipif(not AEQ.available(), reason="numpy is missing")
    def test_happy_a_band_boost_is_heard_and_the_length_kept(self):
        rate = 16000
        pcm = tone(rate, 1000, 0.5)
        gains = [0.0] * 10
        gains[AEQ.BANDS.index(1000)] = 12.0
        out = AEQ.equalize_int16(pcm, rate, gains)
        assert len(out) == len(pcm)
        assert rms(out[4000:-4000]) > 2.5 * rms(pcm[4000:-4000])  # ~+12 dB in the middle
        cut = [0.0] * 10
        cut[AEQ.BANDS.index(1000)] = -12.0
        assert rms(AEQ.equalize_int16(pcm, rate, cut)[4000:-4000]) < 0.5 * rms(pcm[4000:-4000])

    def test_edge_flat_or_nothing_is_left_alone(self):
        pcm = tone(16000, 440, 0.1)
        assert AEQ.equalize_int16(pcm, 16000, [0.0] * 10) is pcm
        assert AEQ.equalize_int16(b"", 16000, AEQ.PRESETS["Rock"]) == b""
        assert AEQ.equalize_int16(b"\x01", 16000, AEQ.PRESETS["Rock"]) == b"\x01"

    @pytest.mark.skipif(not AEQ.available(), reason="numpy is missing")
    def test_edge_loud_boosts_clip_instead_of_wrapping(self):
        pcm = tone(16000, 62, 0.4, amp=0.95)
        out = array.array("h", AEQ.equalize_int16(pcm, 16000, [12.0] * 10))
        assert max(out) == 32767 and min(out) == -32768


# =====================================================================================
# the settings and the route
# =====================================================================================

class TestSettings:
    def test_happy_the_new_fields_round_trip(self, own_settings):
        saved = AudioSettings()
        saved.set("voice_volume", 40)
        saved.set("media_output", "bluez_output.AA")
        saved.set("eq_gains", AEQ.PRESETS["Rock"])
        saved.set("eq_preset", "Rock")
        saved.set("output_muted", True)
        saved.save(own_settings)
        again = AudioSettings.load(own_settings)
        assert again.voice_volume == 40 and again.media_output == "bluez_output.AA"
        assert again.eq_gains == AEQ.PRESETS["Rock"] and again.output_muted is True

    def test_sad_bad_values_keep_their_defaults(self, own_settings):
        own_settings.parent.mkdir(parents=True)
        own_settings.write_text(json.dumps({"voice_volume": 400, "eq_gains": [1, 2],
                                            "media_muted": "yes", "eq_preset": 5,
                                            "preview_output": "x" * 600}))
        saved = AudioSettings.load(own_settings)
        assert saved.voice_volume == 100 and saved.eq_gains == [0.0] * 10
        assert saved.media_muted is False and saved.eq_preset == "Flat"
        assert saved.preview_output == ""

    def test_edge_the_gains_are_a_copy(self):
        gains = list(AEQ.PRESETS["Rock"])
        saved = AudioSettings()
        saved.set("eq_gains", gains)
        gains[0] = 0.0
        assert saved.eq_gains[0] == AEQ.PRESETS["Rock"][0]

    def test_edge_every_source_has_its_three_fields(self):
        for source in AR.SOURCES:
            assert {f"{source}_volume", f"{source}_muted", f"{source}_output"} <= set(FIELDS)


class TestRoute:
    def test_happy_a_source_plays_at_master_times_its_own(self, own_settings):
        AR.update(own_settings, output_volume=50, voice_volume=40)
        assert AR.source_gain("voice") == pytest.approx(0.2)
        assert AR.source_gain("media") == pytest.approx(0.5)

    def test_happy_mute_wins(self, own_settings):
        AR.update(own_settings, media_muted=True)
        assert AR.source_gain("media") == 0.0 and AR.source_gain("voice") == 1.0
        AR.update(own_settings, output_muted=True)
        assert AR.output_gain() == 0.0 and AR.source_gain("voice") == 0.0

    def test_happy_a_source_s_own_output_or_the_output_s(self, own_settings):
        AR.update(own_settings, output_device="alsa_output.pci", voice_output="bluez_output.AA")
        assert AR.source_output_id("voice") == "bluez_output.AA"
        assert AR.source_output_id("media") == "alsa_output.pci"

    def test_happy_update_saves_and_tells_the_players(self, own_settings):
        heard = []
        AR.notifier().changed.connect(heard.append)
        try:
            AR.update(own_settings, eq_gains=AEQ.PRESETS["Vocal"], eq_preset="Vocal")
        finally:
            AR.notifier().changed.disconnect(heard.append)
        assert heard and heard[-1].eq_preset == "Vocal"
        assert json.loads(own_settings.read_text())["eq_preset"] == "Vocal"
        assert AR.eq_gains() == AEQ.PRESETS["Vocal"]

    def test_sad_a_bad_change_saves_nothing(self, own_settings):
        AR.update(own_settings, voice_volume=30)
        with pytest.raises(ValueError):
            AR.update(own_settings, voice_volume=30, media_volume=300)
        assert json.loads(own_settings.read_text())["media_volume"] == 100
        with pytest.raises(KeyError):
            AR.update(own_settings, nonsense=1)

    def test_sad_an_unknown_source(self):
        with pytest.raises(ValueError):
            AR.source_gain("radio")
        with pytest.raises(ValueError):
            AR.source_output_id("radio")

    def test_edge_eq_off_or_flat_is_no_eq(self, own_settings):
        assert AR.eq_gains() is None  # flat by default
        AR.update(own_settings, eq_gains=AEQ.PRESETS["Rock"], eq_enabled=False)
        assert AR.eq_gains() is None
        AR.update(own_settings, eq_enabled=True)
        assert AR.eq_gains() == AEQ.PRESETS["Rock"]


# =====================================================================================
# the players
# =====================================================================================

class _Sink:
    def __init__(self):
        self.volumes = []

    def setVolume(self, v):  # noqa: N802 - Qt's name
        self.volumes.append(v)


def test_happy_a_playing_voice_follows_the_mixer_volume(own_settings):
    from ui import voice as V

    player = V.QtPlayer()  # the voice: no sink factory of its own
    sink = _Sink()
    player._sink = sink
    from PyQt6 import sip

    orig = sip.isdeleted
    sip_isdeleted = sip.isdeleted
    try:
        V.sip.isdeleted = lambda obj: False if obj is sink else sip_isdeleted(obj)
        AR.update(own_settings, voice_volume=25)
    finally:
        V.sip.isdeleted = orig
        player._sink = None
    assert sink.volumes and sink.volumes[-1] == pytest.approx(0.25)


@pytest.mark.skipif(not AEQ.available(), reason="numpy is missing")
def test_happy_the_voice_is_equalized_a_test_tone_is_not(own_settings):
    from ui import voice as V

    AR.update(own_settings, eq_gains=[12.0] * 10, eq_preset="Custom")
    written = {}

    class IO:
        def __init__(self, key):
            self.key = key

        def write(self, data):
            written.setdefault(self.key, bytearray()).extend(data)

    class Sink:
        def bufferSize(self):  # noqa: N802
            return 1 << 20

        def bytesFree(self):  # noqa: N802
            return 1 << 20

        def state(self):
            from PyQt6.QtMultimedia import QAudio

            return QAudio.State.IdleState

        def stop(self):
            pass

        def deleteLater(self):  # noqa: N802
            pass

    pcm = tone(16000, 1000, 0.3, amp=0.05)
    voice = V.QtPlayer(sink_factory=lambda rate: (Sink(), IO("voice"), 16000), equalize=True)
    plain = V.QtPlayer(sink_factory=lambda rate: (Sink(), IO("tone"), 16000))
    voice.enqueue(pcm, 16000)
    plain.enqueue(pcm, 16000)
    voice.stop()
    plain.stop()
    assert bytes(written["tone"]) == pcm  # a test tone goes out as it is
    assert rms(bytes(written["voice"])[3000:-3000]) > 2.5 * rms(pcm[3000:-3000])


def _player_panel():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "bundled_media_player_mixer", ROOT / "resources" / "extensions" / "media_player.py")
    mp = importlib.util.module_from_spec(spec)
    sys.modules["bundled_media_player_mixer"] = mp
    spec.loader.exec_module(mp)
    sink = mp.MemorySink()
    return mp, mp.PlayerPanel(engine=mp.EqEngine(sink_factory=lambda fmt: sink))


@pytest.mark.skipif(not AEQ.available(), reason="numpy is missing")
def test_happy_the_media_player_shows_and_changes_the_shared_equalizer(own_settings):
    from PyQt6.QtTest import QTest

    AR.update(own_settings, eq_gains=AEQ.PRESETS["Rock"], eq_preset="Rock")
    mp, panel = _player_panel()
    try:
        assert panel.preset.currentText() == "Rock"
        assert [s.value() for s in panel.sliders] == [round(g) for g in AEQ.PRESETS["Rock"]]
        assert panel.engine.gains_db == AEQ.PRESETS["Rock"]
        # the panel's change is saved for all of axross
        panel.preset.setCurrentText("Vocal")
        QTest.qWait(400)
        assert json.loads(own_settings.read_text())["eq_preset"] == "Vocal"
        assert AR.eq_gains() == AEQ.PRESETS["Vocal"]
        # a slider makes it Custom
        panel.sliders[0].setValue(11)
        QTest.qWait(400)
        assert panel.preset.currentText() == "Custom"
        assert json.loads(own_settings.read_text())["eq_gains"][0] == 11.0
        # and the mixer's change shows in the panel
        AR.update(own_settings, eq_enabled=False, eq_gains=AEQ.PRESETS["Loudness"],
                  eq_preset="Loudness")
        assert not panel.eq_check.isChecked() and panel.preset.currentText() == "Loudness"
        assert [s.value() for s in panel.sliders] == [round(g) for g in AEQ.PRESETS["Loudness"]]
    finally:
        panel.close()


def test_happy_the_media_player_plays_at_its_mixer_channel(own_settings):
    mp, panel = _player_panel()
    try:
        panel.volume.setValue(100)
        AR.update(own_settings, output_volume=50, media_volume=50)
        assert panel.engine.volume == pytest.approx(0.25, abs=0.01)
        AR.update(own_settings, media_muted=True)
        assert panel.engine.volume == 0.0
    finally:
        panel.close()


def test_edge_the_media_player_s_names_still_work():
    """Tests and code reach the equalizer through the Media Player module."""
    mp, panel = _player_panel()
    panel.close()
    assert mp.BANDS is AEQ.BANDS and mp.Equalizer is AEQ.Equalizer
    assert mp.PRESETS is AEQ.PRESETS and mp.HOP == AEQ.HOP


def test_edge_the_notifier_survives_the_exit_clean_up():
    """main.py deletes every parentless Python-owned QObject after
    app.exec(); the notifier is not one of them, and one deleted anyway is
    made anew - players connected to a deleted one and failed."""
    from PyQt6 import sip

    from core.qt_exit import _python_owned, _qt

    first = AR.notifier()
    assert not sip.ispyowned(first)
    assert all(obj is not first for obj in _python_owned(_qt()))
    sip.delete(first)
    again = AR.notifier()
    assert again is not first and not sip.isdeleted(again)
    heard = []
    again.changed.connect(heard.append)
    AR.publish(AR.settings())
    assert heard
