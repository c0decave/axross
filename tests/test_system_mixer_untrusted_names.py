"""The Audio Mixer's System page shows device and program names as text.

The sound server names a Bluetooth headset's output and card after the
name the headset tells (anyone in radio range picks it), and a program
names its own stream. The page showed those names in labels and tooltips
with Qt's rich-text guess: a headset called
``<img width=4000 height=4000 src=x>`` laid the page out 4000 pixels
wide, and markup could restyle or hide the rows around it.
"""

from __future__ import annotations

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
from PyQt6.QtCore import QCoreApplication, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import system_mixer as SM  # noqa: E402
from ui import system_mixer_page as SMP  # noqa: E402

APP = QApplication.instance() or QApplication([])

HEADSET = "bluez_output.AA_BB_CC_DD_EE_01.1"
#: The name a headset told: as rich text it lays the page out huge.
WIDE = "<img width=4000 height=4000 src=x>"


def wait_until(predicate, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        QCoreApplication.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


@pytest.fixture
def page(tmp_path, monkeypatch):
    state = FP.default_state()
    for sink in state["sinks"]:
        if sink["name"] == HEADSET:
            sink["description"] = WIDE
    for card in state["cards"]:
        if card["name"].startswith("bluez_card."):
            card["properties"]["device.description"] = WIDE
    paths = FP.install(tmp_path, state)
    monkeypatch.setenv("PATH", f"{paths['bin']}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_PACTL_STATE", str(paths["state"]))
    monkeypatch.setenv("FAKE_PACTL_LOG", str(paths["log"]))
    mixer = SM.SystemMixer(timeout_ms=15000)
    p = SMP.SystemMixerPage(mixer)
    p.resize(800, 700)
    p.show()
    assert wait_until(lambda: mixer.state() == SM.STATE_READY), mixer.reason()
    assert wait_until(lambda: len(p.rows["outputs"]) == 2 and len(p.rows["cards"]) == 2)
    yield p
    p.shutdown()
    p.close()
    p.deleteLater()
    QCoreApplication.processEvents()


def test_sad_a_device_s_markup_name_is_shown_as_text(page):
    row = page.rows["outputs"][HEADSET]
    assert row.label.text() == WIDE
    assert row.label.textFormat() == Qt.TextFormat.PlainText
    assert row.label.sizeHint().width() < 2000
    assert "<img" not in row.label.toolTip() and "&lt;img" in row.label.toolTip()
    card = next(r for name, r in page.rows["cards"].items() if name.startswith("bluez_card."))
    assert card.label.textFormat() == Qt.TextFormat.PlainText
    assert card.label.sizeHint().width() < 2000


def test_sad_messages_are_plain(page):
    assert page.message.textFormat() == Qt.TextFormat.PlainText
    assert page.status.textFormat() == Qt.TextFormat.PlainText
