"""The Audio Mixer panel (resources/extensions/audio_mixer.py).

The request: a general audio mixer where all the needed sound settings
are made - outputs, what plays where, volumes, equalizer. These tests click
the panel's axross and Equalizer tabs offscreen; the device list is a seam
(``device_lister``), the settings go to a file of the test's own and the
players' side is core.audio_route (tests/test_audio_mixer_core.py).
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import audio_eq as AEQ  # noqa: E402
from core import audio_route as AR  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_audio_mixer", ROOT / "resources" / "extensions" / "audio_mixer.py")
MIX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_audio_mixer"] = MIX
_spec.loader.exec_module(MIX)

SPEAKERS = ("alsa_output.pci-0000_00_1f.3.analog-stereo", "Built-in Speakers")
HEADSET = ("bluez_output.AA_BB_CC_DD_EE_07.1", "Studio Headset")


@pytest.fixture
def path(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    AR.forget()
    yield tmp_path / ".config" / "axross" / "audio.json"
    AR.forget()


@pytest.fixture
def panel(path):
    made = []

    def build(**kw):
        opened = []
        p = MIX.MixerPanel(settings_path=path, device_lister=lambda: [SPEAKERS, HEADSET],
                           open_audio_settings=lambda: opened.append(1), **kw)
        p.opened = opened
        p.resize(700, 420)
        p.show()
        QTest.qWait(50)
        made.append(p)
        return p

    yield build
    for p in made:
        p.shutdown()
        p.close()
        p.deleteLater()


def saved(path) -> dict:
    return json.loads(path.read_text())


def choose(combo, data) -> None:
    index = combo.findData(data)
    assert index >= 0, data
    combo.setCurrentIndex(index)
    combo.activated.emit(index)


def test_happy_channels_volumes_mutes_and_outputs_e2e(panel, path):
    p = panel()
    assert [p.channels[s].label.text() for s in MIX.SOURCES] == [
        "Media Player", "Agent voice", "Media preview", "Arcade"]
    # the device list came at show time
    assert p.master.output.itemText(0) == "System default"
    assert p.master.output.findData(HEADSET[0]) >= 0
    voice = p.channels["voice"]
    assert voice.output.itemText(0) == "Same as the output"
    # the voice goes to the headset at 40 %, the music stays
    voice.slider.setValue(40)
    choose(voice.output, HEADSET[0])
    p.master.slider.setValue(80)
    p.save_now()
    data = saved(path)
    assert data["voice_volume"] == 40 and data["voice_output"] == HEADSET[0]
    assert data["output_volume"] == 80 and data["media_output"] == ""
    assert AR.source_gain("voice") == pytest.approx(0.32)
    assert AR.source_output_id("voice") == HEADSET[0]
    assert AR.source_output_id("media") == ""
    # mute the preview, then the master
    QTest.mouseClick(p.channels["preview"].mute, Qt.MouseButton.LeftButton)
    assert not p.channels["preview"].slider.isEnabled()
    QTest.mouseClick(p.master.mute, Qt.MouseButton.LeftButton)
    p.save_now()
    assert AR.source_gain("media") == 0.0
    assert all(not c.slider.isEnabled() for c in p.channels.values())
    assert saved(path)["preview_muted"] is True and saved(path)["output_muted"] is True


def test_happy_the_equalizer_tab_e2e(panel, path):
    p = panel()
    p.tabs.setCurrentIndex(1)
    assert p.eq_check.isChecked() and p.preset_combo.currentText() == "Flat"
    p.preset_combo.setCurrentText("Rock")
    p.preset_combo.activated.emit(p.preset_combo.currentIndex())
    assert [s.value() for s in p.bands] == [round(g) for g in AEQ.PRESETS["Rock"]]
    p.save_now()
    assert saved(path)["eq_preset"] == "Rock" and AR.eq_gains() == AEQ.PRESETS["Rock"]
    # one band moved: Custom
    p.bands[3].setValue(9)
    assert p.preset_combo.currentText() == "Custom"
    assert p.band_values[3].text() == "+9"
    p.save_now()
    assert saved(path)["eq_gains"][3] == 9.0 and saved(path)["eq_preset"] == "Custom"
    # Flat and off
    QTest.mouseClick(p.flat_button, Qt.MouseButton.LeftButton)
    p.eq_check.setChecked(False)
    p.save_now()
    assert AR.eq_gains() is None and saved(path)["eq_enabled"] is False
    assert not p.bands[0].isEnabled()


def test_happy_changes_made_elsewhere_show_here(panel, path):
    p = panel()
    AR.update(path, media_volume=30, eq_preset="Vocal", eq_gains=AEQ.PRESETS["Vocal"])
    assert p.channels["media"].slider.value() == 30
    assert p.channels["media"].value.text() == "30 %"
    assert p.preset_combo.currentText() == "Vocal"


def test_happy_a_slider_drag_is_saved_once(panel, path, monkeypatch):
    p = panel()
    calls = []
    real = AR.update
    monkeypatch.setattr(MIX.AR, "update", lambda *a, **k: (calls.append(k), real(*a, **k))[1])
    for v in range(50, 70):
        p.channels["media"].slider.setValue(v)
    QTest.qWait(MIX.SAVE_DELAY_MS + 200)
    assert len(calls) == 1 and calls[0] == {"media_volume": 69}


def test_happy_audio_settings_button(panel):
    p = panel()
    QTest.mouseClick(p.settings_button, Qt.MouseButton.LeftButton)
    assert p.opened == [1]


def test_sad_a_saved_device_that_is_not_connected_stays_listed(panel, path):
    AR.update(path, media_output="bluez_output.GONE")
    p = panel()
    combo = p.channels["media"].output
    assert combo.currentData() == "bluez_output.GONE"
    assert "not connected" in combo.currentText()


def test_sad_an_unwritable_settings_file_is_said(panel, path, monkeypatch):
    p = panel()

    def refuse(*a, **k):
        raise OSError("read-only file system")

    monkeypatch.setattr(MIX.AR, "update", refuse)
    p.channels["voice"].slider.setValue(10)
    p.save_now()
    assert "read-only" in p.message.text()
    assert p.channels["voice"].slider.value() == 100  # shows what is saved


def test_edge_the_settings_page_s_saves_reach_the_panel(panel, path):
    from core.audio_settings import AudioSettings

    p = panel()
    page_saved = AudioSettings.load(path)
    page_saved.set("output_volume", 55)
    page_saved.save(path)
    AR.publish(page_saved)
    assert p.master.slider.value() == 55


def test_edge_shutdown_saves_what_is_pending(panel, path):
    p = panel()
    p.channels["voice"].slider.setValue(12)
    p.shutdown()
    assert saved(path)["voice_volume"] == 12


def test_edge_without_numpy_the_equalizer_says_so(panel, monkeypatch):
    monkeypatch.setattr(MIX.AEQ, "available", lambda: False)
    p = panel()
    p.tabs.setCurrentIndex(1)
    assert p.eq_note.isVisible() and "numpy" in p.eq_note.text()


def test_happy_activate_adds_the_panel(path, monkeypatch):
    monkeypatch.setattr(MIX, "make_system_mixer", lambda: None)

    class Api:
        window = None
        docks: list = []

        def add_dock(self, title, widget, **_kw):
            self.docks.append((title, widget))

    api = Api()
    MIX.activate(api)
    [(title, widget)] = api.docks
    assert title == "Audio Mixer" and isinstance(widget, MIX.MixerPanel)
    assert not widget.settings_button.isVisible()
    MIX.deactivate(api)
    widget.deleteLater()
