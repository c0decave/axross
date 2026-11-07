"""The Audio Mixer's System page (ui/system_mixer_page.py) against a fake pactl.

The request: a general audio mixer for all sound settings - outputs, what
plays where, volumes. The System page shows the sound server's devices,
programs and cards and changes them through core.system_mixer; here it is
clicked offscreen while tests/fake_pactl.py (first on PATH) plays the
server: a laptop with built-in audio, a Bluetooth headset, Firefox
playing, a recorder on the microphone.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import fake_pactl as FP  # noqa: E402
from PyQt6.QtCore import QCoreApplication  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import system_mixer as SM  # noqa: E402
from ui import system_mixer_page as SMP  # noqa: E402

APP = QApplication.instance() or QApplication([])

BUILTIN = "alsa_output.pci-0000_00_1f.3.analog-stereo"
HEADSET = "bluez_output.AA_BB_CC_DD_EE_01.1"


def wait_until(predicate, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QCoreApplication.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


@pytest.fixture
def fake(tmp_path, monkeypatch):
    paths = FP.install(tmp_path)
    monkeypatch.setenv("PATH", f"{paths['bin']}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_PACTL_STATE", str(paths["state"]))
    monkeypatch.setenv("FAKE_PACTL_LOG", str(paths["log"]))
    return paths


@pytest.fixture
def page(fake):
    made = []

    def build():
        mixer = SM.SystemMixer(timeout_ms=15000)
        p = SMP.SystemMixerPage(mixer)
        p.resize(800, 700)
        p.show()
        made.append(p)
        assert wait_until(lambda: mixer.state() == SM.STATE_READY), mixer.reason()
        assert wait_until(lambda: len(p.rows["outputs"]) == 2)
        # pactl subscribe reads from now on: its call is logged once it runs
        assert wait_until(lambda: ["subscribe"] in FP.calls(fake["log"]))
        end = time.monotonic() + 1.0
        while time.monotonic() < end:
            QCoreApplication.processEvents()
            time.sleep(0.01)
        return p

    yield build
    for p in made:
        p.shutdown()
        p.close()
        p.deleteLater()
    QCoreApplication.processEvents()


def entry(fake, kind: str, name_or_index):
    for item in FP.read_state(fake["state"])[kind]:
        if name_or_index in (item.get("name"), item.get("index")):
            return item
    raise AssertionError(name_or_index)


def test_happy_the_page_lists_the_server_e2e(page):
    p = page()
    outputs = p.rows["outputs"]
    assert list(outputs) == [BUILTIN, HEADSET]
    assert outputs[BUILTIN].label.text() == "Built-in Audio Analog Stereo"
    assert outputs[BUILTIN].slider.value() == 60  # the louder channel
    assert outputs[BUILTIN].extra.isChecked() and not outputs[HEADSET].extra.isChecked()
    assert len(p.rows["inputs"]) == 1  # monitors left out
    playback = p.rows["playback"]
    assert [r.label.text() for r in playback.values()][0].startswith("Firefox")
    assert len(p.rows["recording"]) == 1 and len(p.rows["cards"]) == 2
    assert not p.status.isVisible()


def test_happy_volume_mute_default_move_and_profile_reach_the_server(page, fake):
    p = page()
    outputs = p.rows["outputs"]
    outputs[HEADSET].slider.setValue(75)
    assert wait_until(lambda: round(max(
        v["value"] for v in entry(fake, "sinks", HEADSET)["volume"].values()) / 655.36) == 75)
    outputs[BUILTIN].mute.click()
    assert wait_until(lambda: entry(fake, "sinks", BUILTIN)["mute"] is True)
    outputs[HEADSET].extra.click()  # Default
    assert wait_until(lambda: FP.read_state(fake["state"])["default_sink"] == HEADSET)
    assert wait_until(lambda: p.rows["outputs"][HEADSET].extra.isChecked())
    # Firefox to the headset
    firefox = p.rows["playback"][90]
    combo = firefox.extra
    combo.setCurrentIndex(combo.findData(entry(fake, "sinks", HEADSET)["index"]))
    combo.activated.emit(combo.currentIndex())
    assert wait_until(lambda: entry(fake, "sink-inputs", 90)["sink"] ==
                      entry(fake, "sinks", HEADSET)["index"])
    # the headset's card to its headset profile
    card_row = next(r for name, r in p.rows["cards"].items() if "bluez" in name)
    cards = card_row.combo
    cards.setCurrentIndex(cards.findData("headset-head-unit"))
    cards.activated.emit(cards.currentIndex())
    assert wait_until(lambda: next(c for c in FP.read_state(fake["state"])["cards"]
                                   if "bluez" in c["name"])["active_profile"] ==
                      "headset-head-unit")


def test_happy_a_change_made_elsewhere_shows(page, fake):
    p = page()
    FP.update_state(fake["state"], lambda st: (
        next(s for s in st["sinks"] if s["name"] == BUILTIN).update(mute=True),
        st["events"].append("Event 'change' on sink #56")))
    assert wait_until(lambda: p.rows["outputs"][BUILTIN].mute.isChecked())
    assert not p.rows["outputs"][BUILTIN].slider.isEnabled()


def test_sad_no_sound_server_says_why_and_offers_retry(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # no pactl at all
    mixer = SM.SystemMixer(timeout_ms=5000)
    p = SMP.SystemMixerPage(mixer)
    p.show()
    try:
        assert wait_until(lambda: mixer.state() == SM.STATE_UNAVAILABLE)
        assert p.status.isVisible() and p.status.text()
        assert p.retry_button.isVisible()
        assert not p.sections["outputs"][0].isVisible()
    finally:
        p.shutdown()
        p.close()
        p.deleteLater()


def test_edge_a_slider_held_is_not_replaced_under_the_mouse(page, fake):
    p = page()
    row = p.rows["outputs"][BUILTIN]
    row.slider.setSliderDown(True)
    FP.update_state(fake["state"], lambda st: (
        next(s for s in st["sinks"] if s["name"] == BUILTIN).update(mute=True),
        st["events"].append("Event 'change' on sink #56")))
    assert wait_until(lambda: p._dirty)
    assert not row.mute.isChecked()
    row.slider.setSliderDown(False)
    row.slider.sliderReleased.emit()
    assert row.mute.isChecked()


def test_edge_rows_are_kept_while_their_set_stays(page, fake):
    p = page()
    before = p.rows["outputs"][BUILTIN]
    p.mixer.refresh()
    QCoreApplication.processEvents()
    time.sleep(0.3)
    QCoreApplication.processEvents()
    assert p.rows["outputs"][BUILTIN] is before


def test_happy_the_mixer_panel_has_the_system_tab(page, fake, tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "bundled_audio_mixer_sys", ROOT / "resources" / "extensions" / "audio_mixer.py")
    mix = importlib.util.module_from_spec(spec)
    sys.modules["bundled_audio_mixer_sys"] = mix
    spec.loader.exec_module(mix)
    monkeypatch.setenv("HOME", str(tmp_path))
    panel = mix.MixerPanel(device_lister=list, system_mixer=SM.SystemMixer(timeout_ms=15000))
    try:
        assert [panel.tabs.tabText(i) for i in range(panel.tabs.count())] == [
            "axross", "Equalizer", "System"]
        panel.show()
        panel.tabs.setCurrentIndex(2)
        assert wait_until(lambda: len(panel.system_page.rows["outputs"]) == 2)
    finally:
        panel.shutdown()
        panel.close()
        panel.deleteLater()


def test_happy_the_whole_mixer_fits_a_340_px_dock(page, fake, tmp_path, monkeypatch):
    """Product review: the Audio Mixer needed 496 px and scrolled sideways in
    a 366 px dock (each channel and device was one line of five widgets)."""
    spec = importlib.util.spec_from_file_location(
        "bundled_audio_mixer_narrow", ROOT / "resources" / "extensions" / "audio_mixer.py")
    mix = importlib.util.module_from_spec(spec)
    sys.modules["bundled_audio_mixer_narrow"] = mix
    spec.loader.exec_module(mix)
    monkeypatch.setenv("HOME", str(tmp_path))
    panel = mix.MixerPanel(
        device_lister=lambda: [(BUILTIN, "Built-in Audio Analog Stereo"),
                               (HEADSET, "WH-1000XM4 Wireless Noise Cancelling Headset")],
        system_mixer=SM.SystemMixer(timeout_ms=15000))
    try:
        panel.resize(340, 700)
        panel.show()
        assert panel.minimumSizeHint().width() <= 340
        panel.tabs.setCurrentIndex(2)
        page_ = panel.system_page
        assert wait_until(
            lambda: len(page_.rows["playback"]) >= 1 and len(page_.rows["cards"]) >= 1)
        QCoreApplication.processEvents()
        scroll = panel.tabs.currentWidget()
        assert scroll.horizontalScrollBar().maximum() == 0
        # every row still has its slider, value, mute and its extra
        for section in ("outputs", "inputs", "playback", "recording"):
            for row in page_.rows[section].values():
                assert row.extra is not None and row.extra.isVisibleTo(page_)
                assert row.slider.width() >= 100
    finally:
        panel.shutdown()
        panel.close()
        panel.deleteLater()


def test_happy_every_volume_slider_marks_100_percent(page):
    """Product review: the sliders go to 150 % with no mark where the
    device's normal level is."""
    from PyQt6.QtWidgets import QSlider

    p = page()
    sliders = [row.slider for section in ("outputs", "inputs", "playback", "recording")
               for row in p.rows[section].values()]
    assert sliders
    for slider in sliders:
        assert slider.maximum() == SMP.MAX_PERCENT == 150
        assert slider.tickPosition() == QSlider.TickPosition.TicksBelow
        assert slider.tickInterval() == SMP.NORMAL_PERCENT == 100
        assert "100 %" in slider.toolTip()
