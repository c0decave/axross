"""The Bluetooth extension's panel, driven offscreen against a fake BlueZ.

The request: a Bluetooth view to connect speakers and headphones. The
panel (resources/extensions/bluetooth.py) shows the adapter with its
power switch, scans, lists the devices with kind, signal, battery and
state, and pairs, trusts, connects, disconnects and removes them. For a
speaker or headset *Use as Audio Output* waits for its output in Qt's
device list and makes it axross's output (core.audio_route).

These tests click the real widgets (QTest) while core.bluetooth talks to
tests/fake_bluez.py on a private D-Bus; only Qt's audio device list is a
seam (``sink_lister``), because a real headset's sink cannot be made here.
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

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QLineEdit, QMessageBox  # noqa: E402

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from core import bluetooth as BT  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext"] = BTX
_spec.loader.exec_module(BTX)

SPEAKER = "AA:BB:CC:DD:EE:01"
PHONE = "AA:BB:CC:DD:EE:02"
A2DP_SINK = "0000110b-0000-1000-8000-00805f9b34fb"
HCI = "/org/bluez/hci0"


def dev_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


@pytest.fixture
def fake():
    bus = FakeBluezBus()
    yield bus
    bus.close()


class Env:
    def __init__(self, fake, tmp_path, *, powered=True, devices=(), adapter=True,
                 sink_timeout=2.0):
        if adapter:
            fake.command("add_adapter", name="hci0",
                         props={"Powered": powered, "Alias": "workstation"})
        for spec in devices:
            fake.command("add_device", **spec)
        self.fake = fake
        self.outputs: list[tuple[str, str]] = [("alsa_output.pci", "Built-in Audio")]
        self.audio_settings_opened = []
        self.audio_path = tmp_path / "audio.json"
        self.client = BT.BluezClient(bus=fake.qt_connection())
        self.panel = BTX.BluetoothPanel(
            self.client, sink_lister=lambda: list(self.outputs), sink_timeout=sink_timeout,
            open_audio_settings=lambda: self.audio_settings_opened.append(1),
            audio_settings_path=self.audio_path)
        self.panel.resize(760, 420)
        self.panel.show()
        self.panel.start()
        assert wait_until(lambda: self.client.state != "loading")

    # -- helpers that click like a user --------------------------------------------------

    def row_of(self, path: str) -> int:
        table = self.panel.table
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item is not None and item.data(Qt.ItemDataRole.UserRole) == path:
                return row
        return -1

    def select(self, path: str) -> None:
        assert wait_until(lambda: self.row_of(path) >= 0), f"{path} not listed"
        table = self.panel.table
        rect = table.visualItemRect(table.item(self.row_of(path), 0))
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
        assert self.panel.selected_path() == path

    def click(self, button) -> None:
        assert button.isEnabled(), f"{button.text()} is disabled"
        QTest.mouseClick(button, Qt.MouseButton.LeftButton)

    def cell(self, path: str, column: int) -> str:
        row = self.row_of(path)
        return self.panel.table.item(row, column).text() if row >= 0 else ""

    def dialog(self, cls=QDialog):
        assert wait_until(lambda: self.panel.open_dialog() is not None), "no dialog opened"
        dialog = self.panel.open_dialog()
        assert isinstance(dialog, cls), dialog
        return dialog

    def close(self) -> None:
        self.panel.shutdown()
        self.panel.close()
        self.panel.deleteLater()


@pytest.fixture
def env(fake, tmp_path):
    made = []

    def build(**kw):
        e = Env(fake, tmp_path, **kw)
        made.append(e)
        return e

    yield build
    for e in made:
        e.close()
    from core import audio_route

    audio_route.forget()


def speaker(**over):
    spec = {"address": SPEAKER, "props": {"Name": "Desk Speaker", "Alias": "Desk Speaker",
                                          "Icon": "audio-card", "UUIDs": [A2DP_SINK]}}
    spec.update(over)
    return spec


def phone(**over):
    spec = {"address": PHONE, "props": {"Name": "Pixel", "Alias": "Pixel", "Icon": "phone",
                                        "RSSI": -52}}
    spec.update(over)
    return spec


# -- happy: the full way -----------------------------------------------------------------------

def test_happy_scan_pair_connect_and_use_as_output_e2e(env, fake):
    e = env(devices=[speaker(on_scan=True, props={"Name": "Desk Speaker", "Alias": "Desk Speaker",
                                                  "Icon": "audio-card", "UUIDs": [A2DP_SINK],
                                                  "RSSI": -41}, battery=73)])
    panel = e.panel
    assert panel.controls.isVisible() and panel.table.rowCount() == 0
    assert panel.power_check.isChecked()
    # scan
    e.click(panel.scan_button)
    assert wait_until(lambda: e.row_of(dev_path(SPEAKER)) >= 0)
    assert wait_until(lambda: panel.scan_button.text() == "Stop Scan")
    assert e.cell(dev_path(SPEAKER), BTX.COL_NAME) == "Desk Speaker"
    assert e.cell(dev_path(SPEAKER), BTX.COL_ADDRESS) == SPEAKER
    assert e.cell(dev_path(SPEAKER), BTX.COL_TYPE) == "Speaker"
    assert e.cell(dev_path(SPEAKER), BTX.COL_SIGNAL) == "-41 dBm"
    assert e.cell(dev_path(SPEAKER), BTX.COL_BATTERY) == "73 %"
    # pair (Just Works: no dialog)
    e.select(dev_path(SPEAKER))
    e.click(panel.pair_button)
    assert wait_until(lambda: "Paired" in e.cell(dev_path(SPEAKER), BTX.COL_STATE))
    assert panel.open_dialog() is None
    # trust
    e.click(panel.trust_button)
    assert wait_until(lambda: "Trusted" in e.cell(dev_path(SPEAKER), BTX.COL_STATE))
    assert panel.trust_button.text() == "Untrust"
    # connect
    e.click(panel.connect_button)
    assert wait_until(lambda: "Connected" in e.cell(dev_path(SPEAKER), BTX.COL_STATE))
    assert wait_until(lambda: panel.disconnect_button.isEnabled())
    # use as audio output: the sink shows up a moment later
    e.click(panel.output_button)
    assert "Waiting" in panel.message.text()
    e.outputs.append(("bluez_output.AA_BB_CC_DD_EE_01.1", "Desk Speaker"))
    assert wait_until(lambda: "audio output" in panel.message.text()
                      and "Waiting" not in panel.message.text(), 5)
    from core.audio_settings import AudioSettings

    assert AudioSettings.load(e.audio_path).output_device == "bluez_output.AA_BB_CC_DD_EE_01.1"
    # stop the scan
    e.click(panel.scan_button)
    assert wait_until(lambda: panel.scan_button.text() == "Scan")
    assert wait_until(lambda: e.cell(dev_path(SPEAKER), BTX.COL_SIGNAL) == "")


def test_happy_use_as_output_connects_first(env, fake):
    e = env(devices=[speaker(props={"Name": "Desk Speaker", "Alias": "Desk Speaker",
                                    "Icon": "audio-card", "UUIDs": [A2DP_SINK],
                                    "Paired": True})])
    e.select(dev_path(SPEAKER))
    e.outputs.append(("bluez_output.AA_BB_CC_DD_EE_01.1", "Desk Speaker"))
    e.click(e.panel.output_button)
    assert wait_until(lambda: "Connected" in e.cell(dev_path(SPEAKER), BTX.COL_STATE))
    from core.audio_settings import AudioSettings

    assert wait_until(lambda: AudioSettings.load(e.audio_path).output_device
                      == "bluez_output.AA_BB_CC_DD_EE_01.1")


def test_happy_confirm_passkey_dialog_e2e(env, fake):
    e = env(devices=[phone(behaviour={"pair": "confirm", "passkey": 4711})])
    e.select(dev_path(PHONE))
    e.click(e.panel.pair_button)
    dialog = e.dialog()
    assert "004711" in dialog.text_label.text() and "Pixel" in dialog.text_label.text()
    QTest.mouseClick(dialog.accept_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: "Paired" in e.cell(dev_path(PHONE), BTX.COL_STATE))


def test_happy_pin_dialog_e2e(env, fake):
    e = env(devices=[phone(behaviour={"pair": "pin", "pin": "2468"})])
    e.select(dev_path(PHONE))
    e.click(e.panel.pair_button)
    dialog = e.dialog()
    edit = dialog.findChild(QLineEdit)
    assert not dialog.accept_button.isEnabled()  # nothing typed yet
    QTest.keyClicks(edit, "2468")
    QTest.keyClick(edit, Qt.Key.Key_Return)
    assert wait_until(lambda: "Paired" in e.cell(dev_path(PHONE), BTX.COL_STATE))


def test_happy_remove_after_confirmation_e2e(env, fake):
    e = env(devices=[phone(props={"Name": "Pixel", "Alias": "Pixel", "Icon": "phone",
                                  "Paired": True})])
    e.select(dev_path(PHONE))
    e.click(e.panel.remove_button)
    box = e.dialog(QMessageBox)
    QTest.mouseClick(box.button_for_remove, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: e.row_of(dev_path(PHONE)) < 0)
    # BlueZ forgot the device already; the message still names it
    assert wait_until(lambda: e.panel.message.text() == "Removed Pixel.")


def test_happy_power_switch(env, fake):
    e = env(powered=False)
    assert not e.panel.scan_button.isEnabled()
    QTest.mouseClick(e.panel.power_check, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: e.client.adapters()[0].powered)
    assert wait_until(lambda: e.panel.scan_button.isEnabled())


# -- sad ------------------------------------------------------------------------------------

def test_sad_rejecting_the_passkey_does_not_pair_e2e(env, fake):
    e = env(devices=[phone(behaviour={"pair": "confirm", "passkey": 1})])
    e.select(dev_path(PHONE))
    e.click(e.panel.pair_button)
    dialog = e.dialog()
    QTest.mouseClick(dialog.reject_button, Qt.MouseButton.LeftButton)
    # the user said no: the panel says it happened, no second dialog to click away
    assert wait_until(lambda: "rejected" in e.panel.message.text().lower())
    assert e.panel.open_dialog() is None
    assert "Paired" not in e.cell(dev_path(PHONE), BTX.COL_STATE)


def test_sad_connect_error_dialog_e2e(env, fake):
    e = env(devices=[speaker(behaviour={
        "connect": "error:org.bluez.Error.Failed:br-connection-profile-unavailable"})])
    e.select(dev_path(SPEAKER))
    e.click(e.panel.connect_button)
    box = e.dialog(QMessageBox)
    assert "profile" in box.text().lower()
    assert "Desk Speaker" in box.text()


def test_sad_no_sink_appears_says_why_and_offers_audio_settings(env, fake):
    e = env(devices=[speaker(props={"Name": "Desk Speaker", "Alias": "Desk Speaker",
                                    "Icon": "audio-card", "UUIDs": [A2DP_SINK],
                                    "Paired": True, "Connected": True})], sink_timeout=0.3)
    e.select(dev_path(SPEAKER))
    e.click(e.panel.output_button)
    box = e.dialog(QMessageBox)
    assert "A2DP" in box.text()
    QTest.mouseClick(box.audio_settings_button, Qt.MouseButton.LeftButton)
    assert e.audio_settings_opened == [1]
    from core.audio_settings import AudioSettings

    assert AudioSettings.load(e.audio_path).output_device == ""


def test_sad_rfkill_error_resets_the_switch(env, fake):
    e = env(powered=False)
    fake.command("adapter_behave", path=HCI, behaviour={"power": "rfkill"})
    QTest.mouseClick(e.panel.power_check, Qt.MouseButton.LeftButton)
    box = e.dialog(QMessageBox)
    assert "rfkill" in box.text()
    assert wait_until(lambda: not e.panel.power_check.isChecked())


def test_sad_service_not_running_offers_nothing(fake, tmp_path, env):
    fake.kill_fake()
    e = env(adapter=False)
    assert wait_until(lambda: e.client.state == "not-running")
    assert "bluetoothd" in e.panel.status.text()
    assert not e.panel.controls.isVisible()


def test_sad_no_adapter_offers_nothing_then_comes_alive(env, fake):
    e = env(adapter=False)
    assert "No Bluetooth adapter" in e.panel.status.text()
    assert not e.panel.controls.isVisible()
    fake.command("add_adapter", name="hci0", props={"Powered": True})
    assert wait_until(lambda: e.panel.controls.isVisible())


def test_sad_the_service_dies_while_a_dialog_is_open(env, fake):
    e = env(devices=[phone(behaviour={"pair": "confirm", "passkey": 2})])
    e.select(dev_path(PHONE))
    e.click(e.panel.pair_button)
    e.dialog()
    fake.kill_fake()
    assert wait_until(lambda: not e.panel.controls.isVisible())
    assert wait_until(lambda: not any(isinstance(d, BTX.AgentDialog) and d.isVisible()
                                      for d in e.panel.findChildren(QDialog)))


# -- edge -----------------------------------------------------------------------------------

def test_edge_bluez_cancels_and_the_dialog_closes(env, fake):
    e = env(devices=[phone(behaviour={"pair": "confirm", "passkey": 2, "agent_timeout": 0.4})])
    e.select(dev_path(PHONE))
    e.click(e.panel.pair_button)
    dialog = e.dialog()
    assert wait_until(lambda: sip.isdeleted(dialog) or not dialog.isVisible())
    box = e.dialog(QMessageBox)
    assert "timed out" in box.text()


def test_edge_buttons_follow_the_state(env, fake):
    e = env(devices=[phone(props={"Name": "Pixel", "Alias": "Pixel", "Icon": "phone",
                                  "Paired": True, "Connected": True})])
    panel = e.panel
    assert not panel.connect_button.isEnabled()  # nothing selected
    e.select(dev_path(PHONE))
    assert not panel.pair_button.isEnabled()        # paired already
    assert not panel.connect_button.isEnabled()     # connected already
    assert panel.disconnect_button.isEnabled()
    assert not panel.output_button.isEnabled()      # a phone takes no sound
    fake.command("set", path=dev_path(PHONE), iface="org.bluez.Device1",
                 props={"Connected": False})
    assert wait_until(lambda: panel.connect_button.isEnabled())
    assert not panel.disconnect_button.isEnabled()


def test_edge_buttons_are_off_while_an_operation_runs(env, fake):
    e = env(devices=[speaker(behaviour={"pair": "hang"})])
    e.select(dev_path(SPEAKER))
    e.click(e.panel.pair_button)
    assert wait_until(lambda: "Pairing" in e.cell(dev_path(SPEAKER), BTX.COL_STATE))
    assert not e.panel.connect_button.isEnabled()
    assert e.panel.pair_button.text() == "Cancel Pairing"


def test_edge_a_device_disappearing_keeps_the_rest(env, fake):
    e = env(devices=[speaker(), phone()])
    e.select(dev_path(PHONE))
    fake.command("remove", path=dev_path(SPEAKER))
    assert wait_until(lambda: e.row_of(dev_path(SPEAKER)) < 0)
    assert e.panel.selected_path() == dev_path(PHONE)


def test_edge_battery_and_rssi_update_in_place(env, fake):
    e = env(devices=[speaker(battery=90)])
    fake.command("battery", path=dev_path(SPEAKER), percentage=12)
    assert wait_until(lambda: e.cell(dev_path(SPEAKER), BTX.COL_BATTERY) == "12 %")


def test_edge_the_scan_stops_by_itself(env, fake, monkeypatch):
    monkeypatch.setattr(BTX, "SCAN_LIMIT_MS", 300)
    e = env()
    e.click(e.panel.scan_button)
    assert wait_until(lambda: e.client.adapters()[0].discovering)
    assert wait_until(lambda: not e.client.adapters()[0].discovering, 5)


def test_happy_activate_adds_the_panel_and_deactivate_cleans_up(fake, monkeypatch):
    fake.command("add_adapter", name="hci0", props={"Powered": True})
    conn = fake.qt_connection()
    monkeypatch.setattr(BTX, "make_client", lambda: BT.BluezClient(bus=conn))

    class Api:
        window = None
        docks: list = []

        def add_dock(self, title, widget):
            self.docks.append((title, widget))
            return None

        def notify(self, text):
            pass

    api = Api()
    BTX.activate(api)
    [(title, panel)] = api.docks
    assert title == "Bluetooth"
    assert wait_until(lambda: panel.client.state == "ready")
    panel.client.start_discovery(HCI)
    assert wait_until(lambda: panel.client.adapters()[0].discovering)
    BTX.deactivate(api)
    assert wait_until(lambda: fake.calls("StopDiscovery"), 3)
    panel.deleteLater()
