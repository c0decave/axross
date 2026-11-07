"""A Bluetooth device's name is chosen by whoever owns the device.

Any device in radio range can call itself anything: BLE advertisements
and the remote name request carry up to 248 bytes the device picks.
axross shows that name in the pairing question ("Does <name> show the
passkey 123456?"), the device list, the details, the map and messages.

Two ways such a name forged what the user read:

* Qt guesses rich text from a label's text: a name like
  ``<p style="font-size:1px">`` restyled - or hid - the passkey and the
  question the user was asked to confirm.
* control and format characters: a newline, a NUL or a right-to-left
  override (U+202E) reordered the text around the name.

The name is cleaned where it enters (core.bluetooth.device_text), and the
labels, message boxes and the map's tooltip that show it take it as plain
text.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import bluetooth as BT  # noqa: E402
from ui import bluetooth_map as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext_untrusted", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext_untrusted"] = BTX
_spec.loader.exec_module(BTX)

HCI = "/org/bluez/hci0"
EVIL = "C0:FF:EE:00:00:01"
#: A name that restyles the rest of the pairing question.
MARKUP = '<p style="font-size:1px">Keyboard'
#: A name with a right-to-left override, a newline and a NUL in it.
FORGED = "Head\u202ephones\nPasskey OK\x00"


def dev_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


def evil(name: str):
    return {"address": EVIL, "props": {"Name": name, "Alias": name, "RSSI": -50,
                                       "AddressType": "random", "Paired": True}}


@pytest.fixture
def fake():
    bus = FakeBluezBus()
    yield bus
    bus.close()


@pytest.fixture
def panel(fake, tmp_path):
    made = []

    def build(name: str):
        fake.command("add_adapter", name="hci0", props={"Powered": True})
        fake.command("add_device", **evil(name))
        client = BT.BluezClient(bus=fake.qt_connection())
        p = BTX.BluetoothPanel(client, sink_lister=list,
                               audio_settings_path=tmp_path / "audio.json",
                               link_settings_path=tmp_path / "bt.json")
        p.resize(900, 420)
        p.show()
        p.start()
        assert wait_until(lambda: client.state == "ready")
        assert wait_until(lambda: client.device(dev_path(EVIL)) is not None)
        made.append(p)
        return p

    yield build
    for p in made:
        p.shutdown()
        p.close()
        p.deleteLater()


# =====================================================================================
# the name where it enters
# =====================================================================================

def test_sad_control_and_format_characters_leave_the_name():
    """A newline, a NUL and a right-to-left override do not reach the
    texts that show the name."""
    device = BT.Device.from_props(dev_path(EVIL), {"Address": EVIL, "Name": FORGED,
                                                   "Alias": FORGED}, None)
    for text in (device.name, device.alias, device.display_name):
        assert text.isprintable(), repr(text)
    assert device.display_name == "Head phones Passkey OK"


def test_sad_an_overlong_name_is_cut():
    """BlueZ takes at most 248 bytes; anything a D-Bus peer hands over
    longer is cut, not laid out in every label."""
    device = BT.Device.from_props(dev_path(EVIL), {"Address": EVIL, "Name": "A" * 100_000},
                                  None)
    assert len(device.name) == BT.MAX_NAME


def test_happy_ordinary_names_stay_as_they_are():
    for name in ("Band 7", "Jabra Elite 85t", "Kopfhörer", "耳机", "Bob's 🎧", ""):
        assert BT.device_text(name) == name


# =====================================================================================
# where the name is shown
# =====================================================================================

def test_sad_a_markup_name_cannot_restyle_the_pairing_question():
    """The pairing question shows the name as it is - the passkey and the
    question stay what BlueZ asked."""
    request = BT.AgentRequest(token=1, kind="confirm", device_path=dev_path(EVIL),
                              device_name=MARKUP, passkey=123456)
    dialog = BTX.AgentDialog(request, None)
    try:
        assert dialog.text_label.textFormat() == Qt.TextFormat.PlainText
        assert MARKUP in dialog.text_label.text()
        assert "123456" in dialog.text_label.text()
    finally:
        dialog.deleteLater()


def test_sad_a_markup_name_is_plain_in_the_details(panel):
    p = panel(MARKUP)
    dialog = p.open_details(dev_path(EVIL))
    assert dialog is not None
    name = dialog.fields["name"]
    assert name.text() == MARKUP
    assert name.textFormat() == Qt.TextFormat.PlainText
    assert dialog.message.textFormat() == Qt.TextFormat.PlainText
    assert dialog.test_label.textFormat() == Qt.TextFormat.PlainText
    dialog.close()


def test_sad_a_markup_name_is_plain_in_the_panel_s_messages_and_boxes(panel):
    p = panel(MARKUP)
    assert p.message.textFormat() == Qt.TextFormat.PlainText
    p._reconnecting(dev_path(EVIL), 1)
    p._error(f"{MARKUP} could not connect")
    boxes = [b for b in p.findChildren(QMessageBox) if b.isVisible()]
    assert boxes and all(b.textFormat() == Qt.TextFormat.PlainText for b in boxes)
    for box in boxes:
        box.close()


def test_sad_a_markup_name_is_escaped_in_the_map_s_tooltip():
    nearby = BM.NearbyMap()
    try:
        device = BT.Device.from_props(dev_path(EVIL), {"Address": EVIL, "Name": MARKUP,
                                                       "RSSI": -50}, None)
        nearby.set_devices([device])
        assert nearby.tooltip(dev_path(EVIL)).startswith(MARKUP)
        markup = nearby.tooltip_markup(dev_path(EVIL))
        assert "<p " not in markup and "&lt;p style=" in markup
        assert nearby.tooltip_markup("/nothing") == ""
    finally:
        nearby.deleteLater()
