"""Connection options and tests for Bluetooth devices.

The request: connection and test options, for audio among others.
core.bluetooth_link connects single profiles (A2DP, the headset profile
with its microphone ...), reconnects chosen devices when their
connection drops, and runs a timed connection test; the details dialog's
*Connection* tab offers all of it, with a test sound on the device's own
output and a level meter on a headset's microphone.

Against tests/fake_bluez.py on a private D-Bus. Qt's audio devices and
players are seams (a headset's sink cannot be made here): the listers
return (id, description) pairs, the player and recorder are small fakes
with the signals of ui.voice's.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from PyQt6.QtCore import QObject, Qt, pyqtSignal  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import bluetooth as BT  # noqa: E402
from core import bluetooth_link as BTL  # noqa: E402
from ui import bluetooth_details as BD  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "bundled_bluetooth_ext_link", ROOT / "resources" / "extensions" / "bluetooth.py")
BTX = importlib.util.module_from_spec(_spec)
sys.modules["bundled_bluetooth_ext_link"] = BTX
_spec.loader.exec_module(BTX)

HCI = "/org/bluez/hci0"
HEADSET = "AA:BB:CC:DD:EE:07"
BAND = "E0:11:22:33:44:88"
PHONE = "AA:BB:CC:DD:EE:02"


def u16(n: int) -> str:
    return f"0000{n:04x}-0000-1000-8000-00805f9b34fb"


A2DP, HFP, AVRCP = u16(0x110B), u16(0x111E), u16(0x110E)
SINK = ("bluez_output.AA_BB_CC_DD_EE_07.1", "Studio Headset")
SOURCE = ("bluez_input.AA_BB_CC_DD_EE_07.0", "Studio Headset Microphone")


def dev_path(address: str) -> str:
    return f"{HCI}/dev_{address.replace(':', '_')}"


def headset(**over):
    spec = {"address": HEADSET, "props": {"Name": "Studio Headset", "Alias": "Studio Headset",
                                          "Icon": "audio-headset", "Class": 0x240404,
                                          "Paired": True, "Trusted": True,
                                          "UUIDs": [A2DP, HFP, AVRCP]}}
    spec.update(over)
    return spec


def band(**over):
    spec = {"address": BAND, "gatt": [
        {"uuid": u16(0x1800), "chars": [{"uuid": u16(0x2A00), "flags": ["read"],
                                         "value": list(b"Band")}]},
        {"uuid": u16(0x180F), "chars": [{"uuid": u16(0x2A19), "flags": ["read"],
                                         "value": [70]}]}],
        "props": {"Name": "Band", "AddressType": "random", "Appearance": 0x00C1,
                  "Paired": True}}
    spec.update(over)
    return spec


class FakePlayer(QObject):
    failed = pyqtSignal(str)
    drained = pyqtSignal()
    level = pyqtSignal(float)

    def __init__(self, device_id: str, fail: str = "") -> None:
        super().__init__()
        self.device_id = device_id
        self.played: list[tuple[bytes, int]] = []
        self.stopped = False
        self._fail = fail

    def enqueue(self, pcm: bytes, rate: int) -> None:
        self.played.append((pcm, rate))
        if self._fail:
            self.failed.emit(self._fail)
        self.drained.emit()

    def stop(self) -> None:
        self.stopped = True


class FakeRecorder(QObject):
    data = pyqtSignal(bytes)

    def __init__(self, device_id: str) -> None:
        super().__init__()
        self.device_id = device_id
        self.running = False

    def start(self) -> None:
        self.running = True

    def stop(self) -> None:
        self.running = False


@pytest.fixture
def fake():
    bus = FakeBluezBus()
    yield bus
    bus.close()


@pytest.fixture
def client(fake):
    made = []

    def build(*devices):
        fake.command("add_adapter", name="hci0", props={"Powered": True})
        for spec in devices:
            fake.command("add_device", **spec)
        c = BT.BluezClient(bus=fake.qt_connection())
        c.finished = []
        c.operation_finished.connect(lambda p, op, err: c.finished.append((p, op, err)))
        c.start()
        assert wait_until(lambda: c.state == "ready")
        made.append(c)
        return c

    yield build
    for c in made:
        c.shutdown()


def result(c, path, op, timeout=8.0):
    def found():
        return next((e for p, o, e in c.finished if p == path and o == op), None)

    assert wait_until(lambda: found() is not None, timeout), c.finished
    return found()


# =====================================================================================
# pure parts
# =====================================================================================

def test_happy_profiles_of_a_headset():
    device = BT.Device.from_props(dev_path(HEADSET), {"UUIDs": [HFP, A2DP, u16(0x1800)]}, None)
    assert [label for _u, label in BTL.profiles_of(device)] == [
        "Audio playback (A2DP)", "Headset with microphone (HFP)"]
    assert BTL.profiles_of(BT.Device.from_props("/x", {}, None)) == []


def test_happy_find_source():
    device = BT.Device.from_props(dev_path(HEADSET), {"Address": HEADSET,
                                                      "Name": "Studio Headset"}, None)
    assert BTL.find_source([("alsa_input.pci", "Built-in"), SOURCE], device) == SOURCE
    assert BTL.find_source([("alsa_input.pci", "Built-in")], device) is None


def test_happy_reconnect_choices_round_trip_privately(tmp_path):
    path = tmp_path / "sub" / "bluetooth.json"
    BTL.save_reconnect({"aa:bb:cc:dd:ee:07", "11:22:33:44:55:66"}, path)
    assert BTL.load_reconnect(path) == {"AA:BB:CC:DD:EE:07", "11:22:33:44:55:66"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["version"] == 1


def test_sad_a_broken_reconnect_file_is_no_choice(tmp_path):
    path = tmp_path / "bluetooth.json"
    assert BTL.load_reconnect(path) == set()
    for text in ("{", "[]", '{"reconnect": "AA"}', '{"reconnect": [1, "nope", "AA:BB"]}'):
        path.write_text(text)
        assert BTL.load_reconnect(path) == set()
    path.write_text('{"reconnect": ["aa:bb:cc:dd:ee:07", "zz:bb:cc:dd:ee:07"]}')
    assert BTL.load_reconnect(path) == {"AA:BB:CC:DD:EE:07"}


def test_edge_report_text_marks():
    text = BTL.report_text([BTL.Step("Connection", "connected in 120 ms", True),
                            BTL.Step("GATT round trip", "nothing readable", None),
                            BTL.Step("Audio output", "none appeared", False)])
    assert text.splitlines() == ["✓ Connection: connected in 120 ms",
                                 "– GATT round trip: nothing readable",
                                 "✗ Audio output: none appeared"]


def test_happy_the_test_sound_is_two_tones():
    pcm = BD.test_sound()
    seconds = sum(s for _hz, s in BD.TEST_SOUND)
    assert len(pcm) == 2 * int(BD.TEST_RATE * BD.TEST_SOUND[0][1]) + \
        2 * int(BD.TEST_RATE * BD.TEST_SOUND[1][1])
    assert abs(len(pcm) / 2 / BD.TEST_RATE - seconds) < 0.01


# =====================================================================================
# profiles
# =====================================================================================

class TestProfiles:
    def test_happy_connect_and_disconnect_one_profile(self, client, fake):
        c = client(headset())
        path = dev_path(HEADSET)
        c.connect_profile(path, HFP)
        assert result(c, path, "connect-profile") == ""
        assert wait_until(lambda: c.device(path).connected)
        call = fake.calls("ConnectProfile")[0]
        assert call["signature"] == "s" and call["body"] == [HFP]
        c.disconnect_profile(path, HFP)
        assert result(c, path, "disconnect-profile") == ""
        assert wait_until(lambda: not c.device(path).connected)

    def test_sad_a_profile_the_device_does_not_offer(self, client):
        c = client(headset())
        c.connect_profile(dev_path(HEADSET), u16(0x1124))
        assert "profile" in result(c, dev_path(HEADSET), "connect-profile").lower()

    def test_sad_disconnecting_a_profile_that_is_not_connected(self, client):
        c = client(headset())
        c.disconnect_profile(dev_path(HEADSET), A2DP)
        assert "not connected" in result(c, dev_path(HEADSET), "disconnect-profile")


# =====================================================================================
# reconnecting
# =====================================================================================

DELAYS = (0.05, 0.1)


class Events:
    def __init__(self, rec: BTL.Reconnector) -> None:
        self.attempts, self.back, self.gave_up = [], [], []
        rec.attempting.connect(lambda p, n: self.attempts.append(n))
        rec.reconnected.connect(self.back.append)
        rec.gave_up.connect(self.gave_up.append)


class TestReconnect:
    def test_happy_a_drop_is_repaired(self, client, fake, tmp_path):
        c = client(headset(props={**headset()["props"], "Connected": True}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=DELAYS)
        ev = Events(rec)
        rec.set_enabled(c.device(dev_path(HEADSET)), True)
        assert BTL.load_reconnect(tmp_path / "bt.json") == {HEADSET}
        fake.command("set", path=dev_path(HEADSET), iface="org.bluez.Device1",
                     props={"Connected": False})  # out of range
        assert wait_until(lambda: ev.back == [dev_path(HEADSET)], 5)
        assert ev.attempts == [1] and c.device(dev_path(HEADSET)).connected
        assert rec.pending(dev_path(HEADSET)) == 0
        rec.stop()

    def test_happy_the_user_s_own_disconnect_is_not_a_drop(self, client, fake, tmp_path):
        c = client(headset(props={**headset()["props"], "Connected": True}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=DELAYS)
        ev = Events(rec)
        rec.set_enabled(c.device(dev_path(HEADSET)), True)
        rec.expect_disconnect(dev_path(HEADSET))
        c.disconnect_device(dev_path(HEADSET))
        assert wait_until(lambda: not c.device(dev_path(HEADSET)).connected)
        QTest.qWait(300)
        assert ev.attempts == [] and not c.device(dev_path(HEADSET)).connected
        rec.stop()

    def test_sad_every_attempt_fails_then_it_gives_up(self, client, fake, tmp_path):
        c = client(headset(props={**headset()["props"], "Connected": True},
                           behaviour={"connect": "error:org.bluez.Error.Failed:page-timeout"}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=DELAYS)
        ev = Events(rec)
        rec.set_enabled(c.device(dev_path(HEADSET)), True)
        fake.command("set", path=dev_path(HEADSET), iface="org.bluez.Device1",
                     props={"Connected": False})
        assert wait_until(lambda: ev.gave_up == [dev_path(HEADSET)], 5)
        assert ev.attempts == [1, 2] and ev.back == []
        rec.stop()

    def test_edge_not_chosen_no_attempt(self, client, fake, tmp_path):
        c = client(headset(props={**headset()["props"], "Connected": True}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=DELAYS)
        ev = Events(rec)
        fake.command("set", path=dev_path(HEADSET), iface="org.bluez.Device1",
                     props={"Connected": False})
        assert wait_until(lambda: not c.device(dev_path(HEADSET)).connected)
        QTest.qWait(250)
        assert ev.attempts == []
        rec.stop()

    def test_edge_switching_it_off_cancels_a_waiting_attempt(self, client, fake, tmp_path):
        c = client(headset(props={**headset()["props"], "Connected": True}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=(0.5,))
        ev = Events(rec)
        device = c.device(dev_path(HEADSET))
        rec.set_enabled(device, True)
        fake.command("set", path=dev_path(HEADSET), iface="org.bluez.Device1",
                     props={"Connected": False})
        assert wait_until(lambda: rec.pending(dev_path(HEADSET)) == 1)
        rec.set_enabled(device, False)
        assert rec.pending(dev_path(HEADSET)) == 0
        QTest.qWait(700)
        assert ev.attempts == []
        assert BTL.load_reconnect(tmp_path / "bt.json") == set()
        rec.stop()

    def test_edge_a_device_that_goes_takes_its_attempt(self, client, fake, tmp_path):
        c = client(headset(props={**headset()["props"], "Connected": True}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=(0.4,))
        rec.set_enabled(c.device(dev_path(HEADSET)), True)
        fake.command("set", path=dev_path(HEADSET), iface="org.bluez.Device1",
                     props={"Connected": False})
        assert wait_until(lambda: rec.pending(dev_path(HEADSET)) == 1)
        fake.command("remove", path=dev_path(HEADSET))
        assert wait_until(lambda: rec.pending(dev_path(HEADSET)) == 0)
        rec.stop()

    def test_edge_switching_the_adapter_off_holds_the_attempts_until_it_is_on(
            self, client, fake, tmp_path):
        """BlueZ drops every connection when the adapter goes off (switched
        off, the computer asleep). The attempts used to run into "not ready"
        until the reconnector gave up, and switched on again the device
        stayed disconnected; now they wait, uncounted, for the adapter."""
        c = client(headset(props={**headset()["props"], "Connected": True}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=DELAYS)
        ev = Events(rec)
        rec.set_enabled(c.device(dev_path(HEADSET)), True)
        c.set_powered(HCI, False)
        assert result(c, HCI, "power") == ""
        assert wait_until(lambda: not c.device(dev_path(HEADSET)).connected)
        QTest.qWait(400)  # longer than every delay together
        assert ev.attempts == [] and ev.gave_up == []
        assert rec.pending(dev_path(HEADSET)) == 1
        c.set_powered(HCI, True)
        assert wait_until(lambda: ev.back == [dev_path(HEADSET)], 5)
        assert ev.attempts == [1] and c.device(dev_path(HEADSET)).connected
        rec.stop()

    def test_edge_switching_reconnect_off_drops_a_held_attempt(self, client, fake, tmp_path):
        c = client(headset(props={**headset()["props"], "Connected": True}))
        rec = BTL.Reconnector(c, path=tmp_path / "bt.json", delays=DELAYS)
        ev = Events(rec)
        rec.set_enabled(c.device(dev_path(HEADSET)), True)
        c.set_powered(HCI, False)
        assert wait_until(lambda: rec.pending(dev_path(HEADSET)) == 1)
        QTest.qWait(200)
        rec.set_enabled(c.device(dev_path(HEADSET)), False)
        assert rec.pending(dev_path(HEADSET)) == 0
        c.set_powered(HCI, True)
        assert result(c, HCI, "power") == ""
        QTest.qWait(300)
        assert ev.attempts == [] and not c.device(dev_path(HEADSET)).connected
        rec.stop()

    def test_sad_an_unwritable_choice_raises_and_changes_nothing(self, client, tmp_path):
        c = client(headset())
        blocked = tmp_path / "file"
        blocked.write_text("")
        rec = BTL.Reconnector(c, path=blocked / "bt.json", delays=DELAYS)
        with pytest.raises(OSError):
            rec.set_enabled(c.device(dev_path(HEADSET)), True)
        assert not rec.enabled(c.device(dev_path(HEADSET)))
        rec.stop()


# =====================================================================================
# the connection test
# =====================================================================================

def run_test(c, path, **kw) -> list[BTL.Step]:
    test = BTL.ConnectionTest(c, path, **kw)
    done = []
    test.finished.connect(done.append)
    test.start()
    assert wait_until(lambda: done, 10), test.steps
    return done[0]


class TestConnectionTest:
    def test_happy_a_ble_device_connects_resolves_and_answers(self, client):
        c = client(band())
        steps = run_test(c, dev_path(BAND), reads=3)
        assert [(s.name, s.ok) for s in steps] == [
            ("Connection", True), ("Services", True), ("GATT round trip", True)]
        assert steps[0].text.startswith("connected in ")
        assert "3 reads" in steps[2].text

    def test_happy_a_headset_s_audio_output_is_found(self, client):
        c = client(headset())
        outputs = [("alsa_output.pci", "Built-in")]
        c.device_updated.connect(lambda p: outputs.append(SINK) if SINK not in outputs
                                 and c.device(p) and c.device(p).connected else None)
        steps = run_test(c, dev_path(HEADSET), sink_lister=lambda: list(outputs))
        assert [(s.name, s.ok) for s in steps] == [
            ("Connection", True), ("Services", True), ("GATT round trip", None),
            ("Audio output", True)]
        assert "Studio Headset" in steps[3].text

    def test_sad_no_audio_output_appears(self, client):
        c = client(headset(props={**headset()["props"], "Connected": True,
                                  "ServicesResolved": True}))
        steps = run_test(c, dev_path(HEADSET), sink_lister=list, sink_timeout=0.3)
        assert steps[0] == BTL.Step("Connection", "already connected", None)
        assert steps[-1].name == "Audio output" and steps[-1].ok is False
        assert "A2DP" in steps[-1].text

    def test_sad_the_connection_fails(self, client):
        c = client(headset(behaviour={"connect": "error:org.bluez.Error.Failed:page-timeout"}))
        steps = run_test(c, dev_path(HEADSET), sink_lister=list)
        assert steps == [BTL.Step("Connection", BT.error_text("", "page-timeout"), False)]

    def test_sad_a_read_fails(self, client):
        spec = band()
        spec["gatt"][1]["chars"][0]["read"] = "error:org.bluez.Error.NotAuthorized:no"
        c = client(spec)
        steps = run_test(c, dev_path(BAND))
        assert steps[2].name == "GATT round trip" and steps[2].ok is False

    def test_sad_a_device_bluez_forgot(self, client):
        c = client()
        steps = run_test(c, dev_path(BAND))
        assert steps[0].ok is False

    def test_edge_services_that_never_resolve(self, client, fake):
        c = client(band(props={"Name": "Band", "AddressType": "random", "Connected": True,
                               "ServicesResolved": False}))
        fake.command("set", path=dev_path(BAND), iface="org.bluez.Device1",
                     props={"ServicesResolved": False})
        steps = run_test(c, dev_path(BAND), resolve_timeout=0.3)
        assert steps[1].name == "Services" and steps[1].ok is False

    def test_edge_cancel_reports_nothing(self, client):
        c = client(headset(behaviour={"connect": "hang"}))
        test = BTL.ConnectionTest(c, dev_path(HEADSET), sink_lister=list)
        done = []
        test.finished.connect(done.append)
        test.start()
        assert test.running
        test.cancel()
        assert not test.running
        QTest.qWait(100)
        assert done == []


# =====================================================================================
# the Connection tab
# =====================================================================================

class Panel:
    def __init__(self, fake, tmp_path, *devices, outputs=(), inputs=(), player_fail=""):
        fake.command("add_adapter", name="hci0", props={"Powered": True})
        for spec in devices:
            fake.command("add_device", **spec)
        self.fake = fake
        self.outputs = list(outputs)
        self.inputs = list(inputs)
        self.players: list[FakePlayer] = []
        self.recorders: list[FakeRecorder] = []
        self.client = BT.BluezClient(bus=fake.qt_connection())

        def player(device_id):
            self.players.append(FakePlayer(device_id, player_fail))
            return self.players[-1]

        def recorder(device_id):
            self.recorders.append(FakeRecorder(device_id))
            return self.recorders[-1]

        self.panel = BTX.BluetoothPanel(
            self.client, sink_lister=lambda: list(self.outputs),
            source_lister=lambda: list(self.inputs), make_player=player,
            make_recorder=recorder, link_settings_path=tmp_path / "bt.json",
            reconnect_delays=DELAYS, test_options={"sink_timeout": 0.5, "reads": 2,
                                                    "resolve_timeout": 1.0})
        self.panel.resize(900, 420)
        self.panel.show()
        self.panel.start()
        assert wait_until(lambda: self.client.state == "ready")

    def dialog(self, address: str):
        path = dev_path(address)
        assert wait_until(lambda: self.panel._row_of(path) >= 0)
        self.panel.select_path(path)
        QTest.mouseClick(self.panel.test_button, Qt.MouseButton.LeftButton)
        dialog = self.panel._details[path]
        assert dialog.tabs.currentIndex() == 2
        return dialog

    def close(self):
        self.panel.shutdown()
        self.panel.close()
        self.panel.deleteLater()


@pytest.fixture
def panel(fake, tmp_path):
    made = []

    def build(*devices, **kw):
        p = Panel(fake, tmp_path, *devices, **kw)
        made.append(p)
        return p

    yield build
    for p in made:
        p.close()


def click(button) -> None:
    assert button.isEnabled() and button.isVisible(), button.text()
    QTest.mouseClick(button, Qt.MouseButton.LeftButton)


def test_happy_headset_connection_tab_e2e(panel, tmp_path):
    p = panel(headset(), outputs=[SINK], inputs=[SOURCE])
    dialog = p.dialog(HEADSET)
    labels = [dialog.profile_combo.itemText(i) for i in range(dialog.profile_combo.count())]
    assert labels == ["Audio playback (A2DP)", "Headset with microphone (HFP)",
                      "Media controls (AVRCP)"]
    # not connected: no sound test yet
    assert not dialog.sound_button.isEnabled()
    dialog.profile_combo.setCurrentIndex(1)
    click(dialog.profile_connect_button)
    assert wait_until(lambda: "Headset with microphone (HFP) connected." in
                      dialog.message.text())
    assert wait_until(lambda: dialog.sound_button.isEnabled())
    # the test sound goes to the headset's own output
    click(dialog.sound_button)
    assert wait_until(lambda: dialog.test_label.text() == "Test sound played.")
    assert [pl.device_id for pl in p.players] == [SINK[0]]
    assert p.players[0].played[0][1] == BD.TEST_RATE and p.players[0].stopped
    # the microphone: a level meter
    click(dialog.mic_button)
    assert p.recorders[0].device_id == SOURCE[0] and p.recorders[0].running
    assert dialog.mic_button.text() == "Stop"
    loud = (b"\x00\x40" * 800)
    p.recorders[0].data.emit(loud)
    assert dialog.level_bar.value() > 0
    click(dialog.mic_button)
    assert not p.recorders[0].running and dialog.level_bar.value() == 0
    # reconnect automatically is saved
    dialog.reconnect_check.setChecked(True)
    assert BTL.load_reconnect(tmp_path / "bt.json") == {HEADSET}
    # the connection test reports
    click(dialog.test_button)
    assert wait_until(lambda: dialog.test_label.text().startswith("Test finished"), 8)
    report = dialog.report.toPlainText()
    assert "✓ Connection: already connected" not in report  # it was connected: "–"
    assert "– Connection: already connected" in report
    assert "✓ Audio output: Studio Headset" in report


def test_sad_no_sink_and_no_microphone_say_which_profile(panel):
    p = panel(headset(props={**headset()["props"], "Connected": True}))
    dialog = p.dialog(HEADSET)
    click(dialog.sound_button)
    assert "A2DP" in dialog.test_label.text()
    click(dialog.mic_button)
    assert "HFP" in dialog.test_label.text()
    assert p.players == [] and p.recorders == []


def test_sad_a_player_that_fails_says_so(panel):
    p = panel(headset(props={**headset()["props"], "Connected": True}), outputs=[SINK],
              player_fail="the sink went away")
    dialog = p.dialog(HEADSET)
    click(dialog.sound_button)
    assert wait_until(lambda: "the sink went away" in dialog.test_label.text())
    assert dialog.sound_button.isEnabled()  # it can be tried again


def test_edge_a_phone_has_no_audio_tests(panel):
    p = panel({"address": PHONE, "props": {"Name": "Pixel", "Icon": "phone", "Class": 0x5A020C,
                                           "UUIDs": [u16(0x1116)]}})
    dialog = p.dialog(PHONE)
    assert not dialog.sound_button.isVisible() and not dialog.mic_button.isVisible()
    assert [dialog.profile_combo.itemText(i)
            for i in range(dialog.profile_combo.count())] == ["Network (PAN)"]


def test_edge_a_device_without_profiles(panel):
    p = panel(band())
    dialog = p.dialog(BAND)
    assert dialog.profile_combo.currentData() is None
    assert not dialog.profile_connect_button.isEnabled()


def test_happy_the_panel_reconnects_and_says_so(panel, fake):
    p = panel(headset(props={**headset()["props"], "Connected": True}))
    p.panel.reconnector.set_enabled(p.client.device(dev_path(HEADSET)), True)
    fake.command("set", path=dev_path(HEADSET), iface="org.bluez.Device1",
                 props={"Connected": False})
    assert wait_until(lambda: p.panel.message.text() == "Reconnected to Studio Headset.", 5)


def test_edge_the_panel_s_disconnect_is_not_repaired(panel, fake):
    p = panel(headset(props={**headset()["props"], "Connected": True}))
    p.panel.reconnector.set_enabled(p.client.device(dev_path(HEADSET)), True)
    assert wait_until(lambda: p.panel._row_of(dev_path(HEADSET)) >= 0)
    p.panel.select_path(dev_path(HEADSET))
    click(p.panel.disconnect_button)
    assert wait_until(lambda: not p.client.device(dev_path(HEADSET)).connected)
    QTest.qWait(300)
    assert not p.client.device(dev_path(HEADSET)).connected
    assert "reconnect" not in p.panel.message.text().lower()


def test_edge_closing_the_dialog_stops_its_tests(panel):
    p = panel(headset(props={**headset()["props"], "Connected": True}), inputs=[SOURCE])
    dialog = p.dialog(HEADSET)
    click(dialog.mic_button)
    assert p.recorders[0].running
    dialog.close()
    assert not p.recorders[0].running
