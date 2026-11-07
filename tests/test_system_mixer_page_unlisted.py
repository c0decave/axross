"""The System page shows what the sound server says, also for what it
does not list.

* A program that records a monitor (OBS, a screen recorder recording
  what the speakers play) uses a source the Inputs list leaves out. Its
  row's device list fell back to its first entry - the page claimed it
  recorded the microphone - and choosing that shown entry moved it there.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import system_mixer as SM  # noqa: E402
from ui.system_mixer_page import SystemMixerPage  # noqa: E402

APP = QApplication.instance() or QApplication([])


class FakeMixer(QObject):
    """The part of core.system_mixer.SystemMixer the page uses."""

    changed = pyqtSignal()
    state_changed = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.snap = SM.MixerSnapshot()
        self.calls: list = []

    def state(self):
        return SM.STATE_READY

    def reason(self):
        return ""

    def start(self):
        pass

    def shutdown(self):
        pass

    def refresh(self):
        pass

    def sinks(self):
        return self.snap.sinks

    def sources(self, include_monitors: bool = False):
        if include_monitors:
            return self.snap.sources
        return tuple(d for d in self.snap.sources if not d.is_monitor)

    def sink_inputs(self):
        return self.snap.sink_inputs

    def source_outputs(self):
        return self.snap.source_outputs

    def cards(self):
        return ()

    def device(self, kind, index):
        pool = self.snap.sinks if kind == SM.SINK else self.snap.sources
        return next((d for d in pool if d.index == index), None)

    def move_stream(self, stream, device):
        self.calls.append(("move", stream.index, device.name))

    def set_default(self, device):
        self.calls.append(("default", device.name))


def dev(kind, index, name, desc, *, default=False, monitor=False):
    return SM.Device(kind=kind, index=index, name=name, description=desc,
                     is_default=default, is_monitor=monitor)


MIC = dev(SM.SOURCE, 1, "alsa_input.mic", "Microphone")
USB = dev(SM.SOURCE, 2, "alsa_input.usb", "USB Mic")
MONITOR = dev(SM.SOURCE, 3, "alsa_output.spk.monitor", "Monitor of Speakers", monitor=True)
SPEAKERS = dev(SM.SINK, 4, "alsa_output.spk", "Speakers", default=True)


@pytest.fixture
def page():
    mixer = FakeMixer()
    p = SystemMixerPage(mixer)
    p.show()
    yield p, mixer
    p.close()
    p.deleteLater()
    APP.processEvents()


def show(mixer, **parts):
    mixer.snap = SM.MixerSnapshot(**parts)
    mixer.changed.emit()


def test_sad_a_recorder_of_a_monitor_shows_the_monitor_and_is_not_moved(page):
    p, mixer = page
    recorder = SM.Stream(kind=SM.SOURCE_OUTPUT, index=77, application="OBS", device_index=3)
    show(mixer, sinks=(SPEAKERS,), sources=(MIC, USB, MONITOR), source_outputs=(recorder,))
    combo = p.rows["recording"][77].extra
    assert combo.currentText() == "Monitor of Speakers"
    assert combo.currentData() == 3
    combo.activated.emit(combo.currentIndex())  # the shown entry chosen again
    assert mixer.calls == []
    combo.setCurrentIndex(combo.findData(USB.index))
    combo.activated.emit(combo.currentIndex())
    assert mixer.calls == [("move", 77, "alsa_input.usb")]


def test_edge_a_stream_on_an_unknown_device_claims_none(page):
    p, mixer = page
    stream = SM.Stream(kind=SM.SINK_INPUT, index=5, application="mpv", device_index=-1)
    show(mixer, sinks=(SPEAKERS,), sources=(MIC,), sink_inputs=(stream,))
    combo = p.rows["playback"][5].extra
    assert combo.currentText() != "Speakers"
    combo.activated.emit(combo.currentIndex())
    assert mixer.calls == []


def test_happy_a_listed_device_is_shown_as_before(page):
    p, mixer = page
    recorder = SM.Stream(kind=SM.SOURCE_OUTPUT, index=78, application="arecord", device_index=2)
    show(mixer, sinks=(SPEAKERS,), sources=(MIC, USB, MONITOR), source_outputs=(recorder,))
    combo = p.rows["recording"][78].extra
    assert [combo.itemText(i) for i in range(combo.count())] == ["Microphone", "USB Mic"]
    assert combo.currentText() == "USB Mic"


def test_sad_the_default_radio_follows_a_default_the_list_leaves_out(page):
    """The Default radios are exclusive, and an exclusive group ignores
    unchecking its checked button: a default that moved to a monitor (not
    listed) or no default at all left the old radio checked - the page
    showed a default the server no longer had."""
    p, mixer = page
    mic_default = dev(SM.SOURCE, 1, MIC.name, MIC.description, default=True)
    show(mixer, sinks=(SPEAKERS,), sources=(mic_default, USB, MONITOR))
    radios = {name: row.extra for name, row in p.rows["inputs"].items()}
    assert radios[MIC.name].isChecked()
    monitor_default = dev(SM.SOURCE, 3, MONITOR.name, MONITOR.description, default=True,
                          monitor=True)
    show(mixer, sinks=(SPEAKERS,), sources=(MIC, USB, monitor_default))
    assert not any(r.isChecked() for r in radios.values())
    assert mixer.calls == []  # unchecking set no default
    usb_default = dev(SM.SOURCE, 2, USB.name, USB.description, default=True)
    show(mixer, sinks=(SPEAKERS,), sources=(MIC, usb_default, MONITOR))
    assert radios[USB.name].isChecked() and not radios[MIC.name].isChecked()
