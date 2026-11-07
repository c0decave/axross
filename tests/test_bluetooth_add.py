"""Add Device: a new Bluetooth device in one go (ui/bluetooth_add.py).

The request: perfect adding Bluetooth devices. Adding one took five
buttons in the right order (Scan, Pair, Trust, Connect, Use as Audio
Output); *Add Device…* does them in a row - it switches the adapter on when
asked, scans while open, lists the new devices nearby, and pairs, trusts,
connects and (for a speaker or headset) makes the device axross's output,
showing each step. Driven offscreen against tests/fake_bluez.py on a
private D-Bus; Qt's audio outputs are the panel's ``sink_lister`` seam.
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
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402
from ui import bluetooth_add as BA  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext_add", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext_add"] = BTX
_spec.loader.exec_module(BTX)

HCI = "/org/bluez/hci0"
SPEAKER = "AA:BB:CC:DD:EE:01"
KEYBOARD = "AA:BB:CC:DD:EE:03"
TAG = "D4:11:22:33:44:55"
A2DP = "0000110b-0000-1000-8000-00805f9b34fb"
SINK = ("bluez_output.AA_BB_CC_DD_EE_01.1", "Desk Speaker")


def dev_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


def speaker(**over):
    spec = {"address": SPEAKER, "on_scan": True,
            "props": {"Name": "Desk Speaker", "Alias": "Desk Speaker", "Icon": "audio-card",
                      "Class": 0x240414, "UUIDs": [A2DP], "RSSI": -48}}
    spec.update(over)
    return spec


def keyboard(**over):
    spec = {"address": KEYBOARD, "on_scan": True,
            "props": {"Name": "Keys", "Alias": "Keys", "Icon": "input-keyboard",
                      "Class": 0x002540, "RSSI": -60}}
    spec.update(over)
    return spec


def tag():
    return {"address": TAG, "on_scan": True,
            "props": {"AddressType": "random", "ManufacturerData": {"76": [1]}, "RSSI": -40}}


@pytest.fixture
def fake():
    bus = FakeBluezBus()
    yield bus
    bus.close()


class Env:
    def __init__(self, fake, tmp_path, *devices, powered=True):
        fake.command("add_adapter", name="hci0", props={"Powered": powered})
        for spec in devices:
            fake.command("add_device", **spec)
        self.outputs = [("alsa_output.pci", "Built-in Audio")]
        self.audio_path = tmp_path / "audio.json"
        self.client = BT.BluezClient(bus=fake.qt_connection())
        self.panel = BTX.BluetoothPanel(self.client, sink_lister=lambda: list(self.outputs),
                                        sink_timeout=2.0, audio_settings_path=self.audio_path,
                                        link_settings_path=tmp_path / "bt.json")
        self.panel.resize(900, 420)
        self.panel.show()
        self.panel.start()
        assert wait_until(lambda: self.client.state == "ready")

    def dialog(self) -> BA.AddDeviceDialog:
        QTest.mouseClick(self.panel.add_button, Qt.MouseButton.LeftButton)
        dialog = self.panel._add_dialog
        assert dialog is not None and dialog.isVisible()
        return dialog

    def close(self):
        self.panel.shutdown()
        self.panel.close()
        self.panel.deleteLater()


@pytest.fixture
def env(fake, tmp_path):
    made = []

    def build(*devices, **kw):
        e = Env(fake, tmp_path, *devices, **kw)
        made.append(e)
        return e

    yield build
    for e in made:
        e.close()
    from core import audio_route

    audio_route.forget()


def rows(dialog) -> list[str]:
    return [dialog.list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(dialog.list.count())]


def choose(dialog, path) -> None:
    for i in range(dialog.list.count()):
        if dialog.list.item(i).data(Qt.ItemDataRole.UserRole) == path:
            dialog.list.item(i).setSelected(True)
            return
    raise AssertionError(path)


def test_happy_a_speaker_is_added_and_becomes_the_output_e2e(env, fake):
    e = env(speaker(), keyboard(), tag())
    dialog = e.dialog()
    # it scans by itself and lists the named new devices, strongest first
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER), dev_path(KEYBOARD)])
    assert "▂▄▆█" in dialog.list.item(0).text()
    choose(dialog, dev_path(SPEAKER))
    e.outputs.append(SINK)
    QTest.mouseClick(dialog.add_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: dialog.finished_ok is True, 10), dialog.message.text()
    device = e.client.device(dev_path(SPEAKER))
    assert device.paired and device.trusted and device.connected
    assert dialog.progress.text().count("✓") == 4
    assert "added and connected" in dialog.message.text()
    from core.audio_settings import AudioSettings

    assert AudioSettings.load(e.audio_path).output_device == SINK[0]
    # the scan it started is stopped
    assert wait_until(lambda: not e.client.adapters()[0].discovering)
    assert dialog.close_button.text() == "Close"


def test_happy_a_keyboard_skips_the_audio_step(env):
    e = env(keyboard())
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(KEYBOARD)])
    choose(dialog, dev_path(KEYBOARD))
    dialog.add_selected()
    assert wait_until(lambda: dialog.finished_ok is True, 10)
    assert "Use as audio output" not in dialog.progress.text()
    assert dialog.progress.text().count("✓") == 3


def test_happy_unnamed_devices_on_request(env):
    e = env(speaker(), tag())
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    dialog.unnamed_check.setChecked(True)
    assert wait_until(lambda: dev_path(TAG) in rows(dialog))
    assert rows(dialog)[0] == dev_path(SPEAKER)  # named first, even if weaker


def test_happy_a_switched_off_adapter_is_switched_on_when_asked(env):
    e = env(speaker(), powered=False)
    dialog = e.dialog()
    assert dialog.power_button.isVisible() and not dialog.add_button.isEnabled()
    QTest.mouseClick(dialog.power_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: e.client.adapters()[0].powered)
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    assert not dialog.power_button.isVisible()


def test_sad_an_adapter_that_cannot_be_switched_on_says_why_and_can_be_tried_again(env, fake):
    """Switch On disabled its button until the adapter's Powered changed;
    a refusal (rfkill) changes nothing, and the error went unread: the
    dialog stayed on "The Bluetooth adapter is off." with a dead button."""
    e = env(speaker(), powered=False)
    fake.command("adapter_behave", path=HCI, behaviour={"power": "rfkill"})
    dialog = e.dialog()
    QTest.mouseClick(dialog.power_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: "rfkill" in dialog.power_label.text(), 10)
    assert wait_until(lambda: dialog.power_button.isEnabled())
    assert not e.client.adapters()[0].powered
    fake.command("adapter_behave", path=HCI, behaviour={"power": "ok"})
    QTest.mouseClick(dialog.power_button, Qt.MouseButton.LeftButton)
    assert wait_until(lambda: e.client.adapters()[0].powered)


def test_sad_a_failed_pairing_stops_and_says_why(env):
    e = env(speaker(behaviour={"pair": "error:org.bluez.Error.AuthenticationFailed:"}))
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.finished_ok is False, 10)
    assert "✗ Pair" in dialog.progress.text()
    assert "could not be added" in dialog.message.text()
    assert not e.client.device(dev_path(SPEAKER)).connected
    # another try is possible
    assert dialog.add_button.isEnabled()


def test_sad_no_audio_output_appears(env):
    e = env(speaker())
    e.panel._sink_timeout = 0.3
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.finished_ok is False, 10)
    assert "✗ Use as audio output" in dialog.progress.text()
    assert e.client.device(dev_path(SPEAKER)).connected  # what worked stays


def test_sad_cancel_stops_a_pairing(env):
    e = env(speaker(behaviour={"pair": "hang"}))
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.steps.get("pair") == "run")
    assert dialog.close_button.text() == "Cancel"
    QTest.mouseClick(dialog.close_button, Qt.MouseButton.LeftButton)
    assert dialog.finished_ok is False and dialog.message.text() == "Canceled."
    assert wait_until(lambda: e.client.busy(dev_path(SPEAKER)) is None, 10)


def test_edge_closing_the_dialog_stops_its_scan(env):
    e = env(speaker())
    dialog = e.dialog()
    assert wait_until(lambda: e.client.adapters()[0].discovering)
    dialog.close()
    assert wait_until(lambda: not e.client.adapters()[0].discovering)
    assert wait_until(lambda: e.panel._add_dialog is None)


def test_edge_one_dialog_at_a_time(env):
    e = env()
    first = e.panel.open_add_device()
    assert e.panel.open_add_device() is first


def test_edge_signal_bars():
    assert BA.signal_bars(None) == ""
    assert BA.signal_bars(-40) == "▂▄▆█"
    assert BA.signal_bars(-60) == "▂▄▆·"
    assert BA.signal_bars(-75) == "▂▄··"
    assert BA.signal_bars(-95) == "▂···"


def test_edge_after_a_canceled_add_the_list_follows_the_signal_again(env, fake):
    """After Cancel the dialog lists new signals again (it stopped updating
    the rows while it remembered the canceled device)."""
    e = env(speaker(behaviour={"pair": "hang"}), keyboard())
    dialog = e.dialog()
    assert wait_until(lambda: dev_path(KEYBOARD) in rows(dialog))
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.steps.get("pair") == "run")
    QTest.mouseClick(dialog.close_button, Qt.MouseButton.LeftButton)
    assert dialog.finished_ok is False
    fake.command("set", path=dev_path(KEYBOARD), iface="org.bluez.Device1", props={"RSSI": -45})

    def keyboard_row():
        return next(dialog.list.item(i).text() for i in range(dialog.list.count())
                    if dialog.list.item(i).data(Qt.ItemDataRole.UserRole) == dev_path(KEYBOARD))

    assert wait_until(lambda: "▂▄▆█" in keyboard_row())


def test_edge_the_outcome_stays_when_the_list_changes_after_the_add(env, fake):
    """The added device leaves the list (it is paired now); a device seen
    nearby afterwards refills the list - the outcome stays, it is not
    replaced by "No new device found yet." (0.15.61 regression)."""
    e = env(keyboard())
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(KEYBOARD)])
    choose(dialog, dev_path(KEYBOARD))
    dialog.add_selected()
    assert wait_until(lambda: dialog.finished_ok is True, 10)
    assert "added and connected" in dialog.message.text()
    fake.command("add_device", address="11:22:33:44:55:66", on_scan=False,
                 props={"RSSI": -90})
    assert wait_until(lambda: len(e.client.devices(HCI)) == 2)
    dialog._fill()
    assert "added and connected" in dialog.message.text(), dialog.message.text()


def test_sad_cancel_while_waiting_for_the_output_keeps_axross_output(env):
    """Cancel during "Use as audio output": the wait ends, and the device's
    output appearing afterwards does not become axross's output."""
    from core.audio_settings import AudioSettings

    e = env(speaker())
    e.panel._sink_timeout = 3.0
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.steps.get("output") == "run", 10)
    QTest.mouseClick(dialog.close_button, Qt.MouseButton.LeftButton)
    assert dialog.finished_ok is False and dialog.message.text() == "Canceled."
    assert e.panel._waiter is None
    e.outputs.append(SINK)  # the speaker's output shows up after Cancel
    wait_until(lambda: False, 1.2)
    assert AudioSettings.load(e.audio_path).output_device != SINK[0]


def test_sad_cancel_while_connecting_drops_the_connection(env):
    """Cancel during "Connect": the connection that comes after Cancel is
    not kept, and nothing goes on to the output step."""
    e = env(speaker(behaviour={"delay": 2.0}))  # Cancel lands inside it on a busy host
    log = _ops(e)
    dialog = _connecting(e)
    QTest.mouseClick(dialog.close_button, Qt.MouseButton.LeftButton)
    assert dialog.finished_ok is False
    # the connection is dropped as it comes - too briefly for polling
    # Connected to see it, so the client's operations tell
    _connection_comes_and_goes(e, log)
    assert dialog.steps.get("output") == "wait"
    assert e.panel._waiter is None


def test_sad_another_output_chosen_while_add_waits_ends_the_add(env):
    """Use as Audio Output for another device while Add waits for its
    device's output: Add hears that its wait ended instead of hanging."""
    e = env(speaker(), keyboard())
    e.panel._sink_timeout = 5.0
    dialog = e.dialog()
    assert wait_until(lambda: dev_path(SPEAKER) in rows(dialog))
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.steps.get("output") == "run", 10)
    e.panel._wait_for_sink(e.client.device(dev_path(KEYBOARD)))
    assert wait_until(lambda: dialog.finished_ok is False, 3)
    assert dialog.steps["output"] == "fail"
    assert "Another device" in dialog.message.text()


def test_edge_the_corner_x_cancels_a_running_pairing(env):
    """The [x] of the dialog's corner (every dialog has one) closes it as
    closing the window does: a pairing under way is canceled."""
    from PyQt6.QtWidgets import QToolButton

    e = env(speaker(behaviour={"pair": "hang"}))
    dialog = e.dialog()
    corner = dialog.findChild(QToolButton, "axCloseCorner")
    assert corner is not None
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.steps.get("pair") == "run")
    from PyQt6 import sip

    corner.click()
    assert wait_until(lambda: sip.isdeleted(dialog) or not dialog.isVisible())
    assert wait_until(lambda: e.client.busy(dev_path(SPEAKER)) is None, 10)


def _ops(e) -> list[tuple[str, str]]:
    """The client's finished operations on the speaker, as (op, error)."""
    log: list[tuple[str, str]] = []
    e.client.operation_finished.connect(
        lambda path, op, error: log.append((op, error)) if path == dev_path(SPEAKER) else None)
    return log


def _connecting(e):
    """Add Device with the speaker's Connect under way (it takes 2 s)."""
    dialog = e.dialog()
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    choose(dialog, dev_path(SPEAKER))
    dialog.add_selected()
    assert wait_until(lambda: dialog.steps.get("connect") == "run", 10)
    return dialog


def _connection_comes_and_goes(e, log) -> None:
    """The Connect that was under way ends, and its connection is dropped
    by the client although the dialog that canceled it is gone."""
    assert wait_until(lambda: ("connect", "") in log, 8)
    assert wait_until(lambda: ("disconnect", "") in log, 5)
    wait_until(lambda: False, 0.3)
    assert not e.client.device(dev_path(SPEAKER)).connected


def test_sad_cancel_then_close_during_connect_drops_the_connection(env):
    """Cancel during "Connect", then Close before the connection comes:
    the connection is still not kept."""
    e = env(speaker(behaviour={"delay": 2.0}))
    log = _ops(e)
    dialog = _connecting(e)
    QTest.mouseClick(dialog.close_button, Qt.MouseButton.LeftButton)  # Cancel
    assert dialog.finished_ok is False
    QTest.mouseClick(dialog.close_button, Qt.MouseButton.LeftButton)  # Close
    _connection_comes_and_goes(e, log)


def test_sad_escape_during_connect_drops_the_connection(env):
    """Escape during "Connect" leaves the dialog at once; the connection
    that comes after is not kept."""
    e = env(speaker(behaviour={"delay": 2.0}))
    log = _ops(e)
    dialog = _connecting(e)
    QTest.keyClick(dialog, Qt.Key.Key_Escape)
    _connection_comes_and_goes(e, log)


def test_sad_the_corner_x_during_connect_drops_the_connection(env):
    """The corner's [x] during "Connect" closes the dialog as Cancel would;
    the connection that comes after is not kept."""
    from PyQt6.QtWidgets import QToolButton

    e = env(speaker(behaviour={"delay": 2.0}))
    log = _ops(e)
    dialog = _connecting(e)
    corner = dialog.findChild(QToolButton, "axCloseCorner")
    assert corner is not None
    corner.click()
    _connection_comes_and_goes(e, log)


def test_edge_drop_when_connected_is_one_shot(env):
    """The client's drop_when_connected drops the Connect under way only:
    asking while none runs drops nothing, and the next Connect is kept."""
    e = env(speaker(on_scan=False, behaviour={"delay": 0.3}))
    log = _ops(e)
    path = dev_path(SPEAKER)
    assert e.client.drop_when_connected(path) is False
    e.client.connect_device(path)
    assert e.client.drop_when_connected(path) is True
    assert wait_until(lambda: ("disconnect", "") in log, 5)
    assert log == [("connect", ""), ("disconnect", "")]
    assert wait_until(lambda: not e.client.device(path).connected, 5)
    e.client.connect_device(path)
    assert wait_until(lambda: len(log) == 3, 5)
    wait_until(lambda: False, 0.5)
    assert log == [("connect", ""), ("disconnect", ""), ("connect", "")]
    assert e.client.device(path).connected


def test_edge_add_scans_itself_while_another_program_scans(env, fake):
    """BlueZ keeps one scan per program: Add Device starts its own even when
    another program's scan has the adapter discovering, and stops only its
    own when closed."""
    e = env(speaker())
    fake.command("other_scan", path=HCI)
    assert wait_until(lambda: e.client.adapters()[0].discovering)
    dialog = e.dialog()
    assert wait_until(lambda: e.client.scanning(HCI))
    assert wait_until(lambda: rows(dialog) == [dev_path(SPEAKER)])
    dialog.close()
    assert wait_until(lambda: not e.client.scanning(HCI))
    APP.processEvents()
    assert e.client.adapters()[0].discovering
    assert fake.command("other_scan", path=HCI, on=False) == []
