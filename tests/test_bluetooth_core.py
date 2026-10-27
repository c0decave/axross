"""core.bluetooth: BlueZ over D-Bus, tested against a fake org.bluez.

The request was a Bluetooth view to connect speakers and headphones.
core.bluetooth is its Qt-widget-free half: BluezClient talks to BlueZ
(``org.bluez`` on the system D-Bus) through QtDBus, every call
asynchronous; the pure helpers turn BlueZ's errors, icons, classes and
QMediaDevices' outputs into what the panel shows.

The client is driven against tests/fake_bluez.py on a private dbus-daemon
(tests/bluez_testkit.py) - never the host's system bus - so the D-Bus
round trips (signatures, signals, the pairing agent BlueZ calls back) are
real.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from bluez_testkit import FakeBluezBus, wait_until  # noqa: E402
from core import bluetooth as BT  # noqa: E402

APP = QApplication.instance() or QApplication([])

SPEAKER = "AA:BB:CC:DD:EE:01"
PHONE = "AA:BB:CC:DD:EE:02"
A2DP_SINK = "0000110b-0000-1000-8000-00805f9b34fb"


def dev_path(address: str, adapter: str = "hci0") -> str:
    return f"/org/bluez/{adapter}/dev_{address.replace(':', '_')}"


class Recorder:
    """Collects a client's signals."""

    def __init__(self, client: BT.BluezClient) -> None:
        self.finished: list[tuple[str, str, str]] = []
        self.requests: list[BT.AgentRequest] = []
        self.cancelled: list[int] = []
        self.states: list[str] = []
        client.operation_finished.connect(lambda p, op, err: self.finished.append((p, op, err)))
        client.agent_request.connect(self.requests.append)
        client.agent_cancelled.connect(self.cancelled.append)
        client.state_changed.connect(self.states.append)

    def result(self, path: str, op: str):
        for p, o, err in self.finished:
            if p == path and o == op:
                return err
        return None

    def wait(self, path: str, op: str, timeout: float = 8.0) -> str:
        assert wait_until(lambda: self.result(path, op) is not None, timeout), \
            f"{op} on {path} never finished; got {self.finished}"
        return self.result(path, op)


@pytest.fixture
def fake():
    bus = FakeBluezBus()
    yield bus
    bus.close()


def make_client(fake, *, adapter=True, powered=True, devices=(), start=True):
    if adapter:
        fake.command("add_adapter", name="hci0", props={"Powered": powered,
                                                         "PowerState": "on" if powered else "off",
                                                         "Alias": "workstation"})
    for spec in devices:
        fake.command("add_device", **spec)
    client = BT.BluezClient(bus=fake.qt_connection())
    rec = Recorder(client)
    if start:
        client.start()
        assert wait_until(lambda: client.state in ("ready", "no-adapter")), client.state
    return client, rec


@pytest.fixture
def made(fake):
    clients = []

    def build(**kw):
        client, rec = make_client(fake, **kw)
        clients.append(client)
        return client, rec

    yield build
    for client in clients:
        client.shutdown()


def speaker(**over):
    spec = {"address": SPEAKER, "props": {"Name": "Desk Speaker", "Alias": "Desk Speaker",
                                          "Icon": "audio-card", "Class": 0x240414,
                                          "UUIDs": [A2DP_SINK]}}
    spec.update(over)
    return spec


# =====================================================================================
# pure helpers
# =====================================================================================

class TestErrorText:
    def test_happy_not_ready_says_switch_the_adapter_on(self):
        text = BT.error_text("org.bluez.Error.NotReady", "Resource Not Ready")
        assert "switch" in text.lower() and "adapter" in text.lower()

    @pytest.mark.parametrize("name, word", [
        ("org.bluez.Error.AuthenticationFailed", "PIN"),
        ("org.bluez.Error.AuthenticationRejected", "rejected"),
        ("org.bluez.Error.AuthenticationCanceled", "canceled"),
        ("org.bluez.Error.AuthenticationTimeout", "timed out"),
        ("org.bluez.Error.InProgress", "still running"),
        ("org.bluez.Error.AlreadyExists", "already paired"),
        ("org.bluez.Error.AlreadyConnected", "already connected"),
        ("org.bluez.Error.NotConnected", "not connected"),
        ("org.bluez.Error.DoesNotExist", "no longer known"),
        ("org.bluez.Error.ConnectionAttemptFailed", "in range"),
        ("org.freedesktop.DBus.Error.NoReply", "did not answer"),
        ("org.freedesktop.DBus.Error.ServiceUnknown", "not running"),
        ("org.freedesktop.DBus.Error.AccessDenied", "denied"),
    ])
    def test_happy_every_known_error_has_its_own_sentence(self, name, word):
        assert word.lower() in BT.error_text(name, "x").lower()

    def test_happy_rfkill_is_named_with_the_way_out(self):
        text = BT.error_text("org.bluez.Error.Failed", "Blocked through rfkill")
        assert "rfkill" in text and "unblock" in text

    def test_happy_a_missing_audio_profile_points_at_the_sound_server(self):
        text = BT.error_text("org.bluez.Error.Failed", "br-connection-profile-unavailable")
        assert "profile" in text.lower() and ("PipeWire" in text or "PulseAudio" in text)

    def test_sad_an_unknown_error_keeps_name_and_message(self):
        text = BT.error_text("org.example.Error.Weird", "something odd")
        assert "org.example.Error.Weird" in text and "something odd" in text

    def test_edge_failed_without_a_message_still_says_something(self):
        assert BT.error_text("org.bluez.Error.Failed", "").strip()
        assert BT.error_text("", "").strip()


class TestDeviceKind:
    @pytest.mark.parametrize("icon, kind", [
        ("audio-card", "Speaker"), ("audio-headset", "Headset"),
        ("audio-headphones", "Headphones"), ("phone", "Phone"), ("computer", "Computer"),
        ("input-keyboard", "Keyboard"), ("input-mouse", "Mouse"),
        ("input-gaming", "Game Controller"),
    ])
    def test_happy_the_icon_decides(self, icon, kind):
        assert BT.device_kind(icon, 0) == kind

    def test_happy_the_class_decides_without_an_icon(self):
        assert BT.device_kind("", 0x5a020c) == "Phone"        # major 2
        assert BT.device_kind("", 0x240404) == "Headset"      # major 4, minor 1
        assert BT.device_kind("", 0x240418) == "Headphones"   # major 4, minor 6
        assert BT.device_kind("", 0x240414) == "Speaker"      # major 4, minor 5
        assert BT.device_kind("", 0x002540) == "Keyboard"     # major 5, keyboard bit

    def test_sad_nothing_known_is_a_device(self):
        assert BT.device_kind("", 0) == "Device"
        assert BT.device_kind("unknown-icon", 0) == "Device"

    def test_edge_a_strange_class_type_does_not_raise(self):
        assert BT.device_kind(None, None) == "Device"


class TestNormalise:
    def test_happy_a_byte_from_dbus_is_a_number(self):
        """QtDBus hands 'y' (Battery1.Percentage) to Python as bytes."""
        assert BT.normalise(b"P") == 80

    def test_happy_nested_values(self):
        from PyQt6.QtDBus import QDBusObjectPath, QDBusVariant

        value = {"a": [QDBusObjectPath("/x"), QDBusVariant(3)], "b": b"\x05"}
        assert BT.normalise(value) == {"a": ["/x", 3], "b": 5}

    def test_edge_longer_bytes_stay_bytes(self):
        assert BT.normalise(b"ab") == b"ab"


class TestAudioOutput:
    def _device(self, **kw) -> BT.Device:
        base = dict(path=dev_path(SPEAKER), adapter="/org/bluez/hci0", address=SPEAKER,
                    name="Desk Speaker", alias="Desk Speaker", icon="audio-card",
                    device_class=0, rssi=None, paired=True, trusted=False, connected=True,
                    blocked=False, uuids=(), battery=None)
        base.update(kw)
        return BT.Device(**base)

    def test_happy_an_a2dp_sink_is_an_audio_output(self):
        assert BT.is_audio_output(self._device(icon="", uuids=(A2DP_SINK,)))

    def test_happy_a_headset_icon_is_an_audio_output(self):
        assert BT.is_audio_output(self._device(icon="audio-headset"))

    def test_sad_a_phone_is_not(self):
        assert not BT.is_audio_output(self._device(icon="phone", uuids=()))

    def test_happy_pipewire_sink_id_matches_by_address(self):
        outputs = [("alsa_output.pci", "Built-in Audio"),
                   ("bluez_output.AA_BB_CC_DD_EE_01.1", "Desk Speaker")]
        assert BT.find_sink(outputs, self._device()) == outputs[1]

    def test_happy_pulseaudio_sink_id_matches_too(self):
        outputs = [("bluez_sink.aa_bb_cc_dd_ee_01.a2dp_sink", "Something")]
        assert BT.find_sink(outputs, self._device()) == outputs[0]

    def test_happy_the_description_matches_when_the_id_has_no_address(self):
        outputs = [("{0.0.0.00000000}.{guid}", "Desk Speaker")]
        assert BT.find_sink(outputs, self._device()) == outputs[0]

    def test_sad_another_devices_sink_is_not_taken(self):
        outputs = [("bluez_output.AA_BB_CC_DD_EE_02.1", "Other Speaker")]
        assert BT.find_sink(outputs, self._device()) is None

    def test_edge_no_outputs(self):
        assert BT.find_sink([], self._device()) is None

    def test_happy_set_audio_output_saves_and_publishes(self, tmp_path, monkeypatch):
        from core import audio_route
        from core.audio_settings import AudioSettings

        path = tmp_path / "audio.json"
        AudioSettings(output_volume=40).save(path)
        got = []
        audio_route.notifier().changed.connect(got.append)
        try:
            BT.set_audio_output("bluez_output.AA_BB_CC_DD_EE_01.1", path=path)
        finally:
            audio_route.notifier().changed.disconnect(got.append)
            audio_route.forget()
        saved = AudioSettings.load(path)
        assert saved.output_device == "bluez_output.AA_BB_CC_DD_EE_01.1"
        assert saved.output_volume == 40  # the rest of the settings stays
        assert got and got[-1].output_device == "bluez_output.AA_BB_CC_DD_EE_01.1"


class TestSinkWaiter:
    def _device(self):
        return TestAudioOutput()._device()

    def test_happy_the_sink_is_found_once_it_appears(self):
        polls = []

        def lister():
            polls.append(1)
            return [("bluez_output.AA_BB_CC_DD_EE_01.1", "Desk Speaker")] if len(polls) >= 3 else []

        waiter = BT.SinkWaiter(self._device(), lister=lister, timeout=5.0, interval_ms=20)
        found, timed_out = [], []
        waiter.found.connect(lambda i, d: found.append(i))
        waiter.timed_out.connect(lambda: timed_out.append(1))
        waiter.start()
        assert wait_until(lambda: found, 3)
        assert found == ["bluez_output.AA_BB_CC_DD_EE_01.1"] and not timed_out
        assert len(polls) == 3

    def test_sad_no_sink_times_out(self):
        waiter = BT.SinkWaiter(self._device(), lister=lambda: [("x", "y")], timeout=0.2,
                               interval_ms=20)
        timed_out = []
        waiter.timed_out.connect(lambda: timed_out.append(1))
        waiter.start()
        assert wait_until(lambda: timed_out, 3)

    def test_sad_a_lister_that_raises_does_not_escape(self):
        def lister():
            raise RuntimeError("audio server gone")

        waiter = BT.SinkWaiter(self._device(), lister=lister, timeout=0.2, interval_ms=20)
        timed_out = []
        waiter.timed_out.connect(lambda: timed_out.append(1))
        waiter.start()
        assert wait_until(lambda: timed_out, 3)

    def test_edge_stop_cancels_without_a_signal(self):
        waiter = BT.SinkWaiter(self._device(), lister=lambda: [], timeout=0.1, interval_ms=20)
        timed_out = []
        waiter.timed_out.connect(lambda: timed_out.append(1))
        waiter.start()
        waiter.stop()
        wait_until(lambda: False, 0.3)
        assert not timed_out and not waiter.running


def test_happy_the_bundle_spec_names_qtdbus():
    """resources/extensions are data to PyInstaller; core.bluetooth's import
    is traced, but the hidden import says it where a reader looks."""
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    assert re.search(r'"PyQt6\.QtDBus"', spec)


# =====================================================================================
# BluezClient against the fake BlueZ
# =====================================================================================

class TestStart:
    def test_happy_adapters_and_devices_are_listed(self, made):
        client, _rec = made(devices=[speaker(battery=80)])
        assert client.state == "ready"
        [adapter] = client.adapters()
        assert adapter.path == "/org/bluez/hci0" and adapter.alias == "workstation"
        assert adapter.powered is True
        [device] = client.devices()
        assert device.address == SPEAKER and device.display_name == "Desk Speaker"
        assert device.kind == "Speaker" and device.battery == 80
        assert BT.is_audio_output(device)

    def test_sad_no_adapter_says_so(self, made):
        client, _rec = made(adapter=False)
        assert client.state == "no-adapter"
        assert client.adapters() == [] and client.devices() == []

    def test_happy_an_adapter_plugged_in_later_makes_it_ready(self, made, fake):
        client, _rec = made(adapter=False)
        fake.command("add_adapter", name="hci0")
        assert wait_until(lambda: client.state == "ready")

    def test_sad_service_not_running(self, fake):
        fake.kill_fake()
        client = BT.BluezClient(bus=fake.qt_connection())
        try:
            client.start()
            assert wait_until(lambda: client.state == "not-running")
            assert "bluetoothd" in client.state_text()
        finally:
            client.shutdown()

    def test_happy_the_service_starting_later_is_picked_up(self, fake):
        fake.kill_fake()
        client = BT.BluezClient(bus=fake.qt_connection())
        try:
            client.start()
            assert wait_until(lambda: client.state == "not-running")
            fake.start_fake()
            fake.command("add_adapter", name="hci0")
            assert wait_until(lambda: client.state == "ready", 8)
            # signals of the new owner arrive too
            fake.command("add_device", **speaker())
            assert wait_until(lambda: len(client.devices()) == 1)
        finally:
            client.shutdown()

    def test_sad_no_dbus_at_all(self):
        from PyQt6.QtDBus import QDBusConnection

        conn = QDBusConnection.connectToBus("unix:path=/nonexistent/axross-no-bus", "ax-no-bus")
        client = BT.BluezClient(bus=conn)
        try:
            client.start()
            assert client.state == "unavailable"
            assert "D-Bus" in client.state_text()
        finally:
            client.shutdown()
            QDBusConnection.disconnectFromBus("ax-no-bus")

    def test_edge_two_adapters(self, made, fake):
        fake.command("add_adapter", name="hci1", props={"Alias": "dongle"})
        client, _rec = made()
        assert [a.alias for a in client.adapters()] == ["workstation", "dongle"]


class TestAdapter:
    def test_happy_power_off_and_on(self, made):
        client, rec = made()
        client.set_powered("/org/bluez/hci0", False)
        assert rec.wait("/org/bluez/hci0", "power") == ""
        assert wait_until(lambda: client.adapters()[0].powered is False)
        rec.finished.clear()
        client.set_powered("/org/bluez/hci0", True)
        assert rec.wait("/org/bluez/hci0", "power") == ""
        assert wait_until(lambda: client.adapters()[0].powered is True)

    def test_sad_rfkill_blocked(self, made, fake):
        client, rec = made(powered=False)
        fake.command("adapter_behave", path="/org/bluez/hci0", behaviour={"power": "rfkill"})
        client.set_powered("/org/bluez/hci0", True)
        assert "rfkill" in rec.wait("/org/bluez/hci0", "power")
        assert client.adapters()[0].powered is False

    def test_happy_scan_finds_a_device_with_rssi_and_stop_clears_it(self, made, fake):
        client, rec = made()
        fake.command("add_device", on_scan=True, address=PHONE,
                     props={"Name": "Pixel", "Icon": "phone", "RSSI": -48})
        assert client.devices() == []
        client.start_discovery("/org/bluez/hci0")
        assert rec.wait("/org/bluez/hci0", "scan") == ""
        assert wait_until(lambda: client.adapters()[0].discovering)
        assert wait_until(lambda: len(client.devices()) == 1)
        device = client.devices()[0]
        assert device.rssi == -48 and device.kind == "Phone"
        fake.command("set", path=dev_path(PHONE), iface="org.bluez.Device1", props={"RSSI": -70})
        assert wait_until(lambda: client.device(dev_path(PHONE)).rssi == -70)
        client.stop_discovery("/org/bluez/hci0")
        assert rec.wait("/org/bluez/hci0", "stop-scan") == ""
        assert wait_until(lambda: not client.adapters()[0].discovering)
        assert wait_until(lambda: client.device(dev_path(PHONE)).rssi is None)

    def test_sad_scan_while_powered_off(self, made):
        client, rec = made(powered=False)
        client.start_discovery("/org/bluez/hci0")
        text = rec.wait("/org/bluez/hci0", "scan")
        assert "switch" in text.lower()

    def test_edge_a_device_out_of_range_disappears(self, made, fake):
        client, _rec = made(devices=[speaker()])
        fake.command("remove", path=dev_path(SPEAKER))
        assert wait_until(lambda: client.devices() == [])
        assert client.device(dev_path(SPEAKER)) is None


class TestPairing:
    def test_happy_just_works_registers_an_agent_only_for_the_pairing(self, made, fake):
        client, rec = made(devices=[speaker()])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert client.busy(path) == "pair"
        assert rec.wait(path, "pair") == ""
        assert wait_until(lambda: client.device(path).paired)
        assert client.busy(path) is None
        register = fake.calls("RegisterAgent")
        assert len(register) == 1 and register[0]["body"][1] == "KeyboardDisplay"
        assert wait_until(lambda: fake.calls("UnregisterAgent"))
        assert fake.command("agents") == {}
        assert rec.requests == []

    def test_happy_confirm_the_passkey(self, made, fake):
        client, rec = made(devices=[speaker(behaviour={"pair": "confirm", "passkey": 123456})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        [req] = rec.requests
        assert req.kind == "confirm" and req.passkey == 123456 and req.device_path == path
        assert req.device_name == "Desk Speaker" and req.needs_answer
        client.answer(req.token, True)
        assert rec.wait(path, "pair") == ""
        assert wait_until(lambda: client.device(path).paired)

    def test_happy_pin_code(self, made):
        client, rec = made(devices=[speaker(behaviour={"pair": "pin", "pin": "1234"})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        assert rec.requests[0].kind == "pin"
        client.answer(rec.requests[0].token, True, "1234")
        assert rec.wait(path, "pair") == ""

    def test_happy_passkey_goes_out_as_uint32(self, made):
        client, rec = made(devices=[speaker(behaviour={"pair": "passkey", "passkey": 4242})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        assert rec.requests[0].kind == "passkey"
        client.answer(rec.requests[0].token, True, 4242)
        assert rec.wait(path, "pair") == ""  # the fake checks the reply is 'u'

    def test_happy_display_passkey_needs_no_answer(self, made):
        client, rec = made(devices=[speaker(behaviour={"pair": "display-passkey",
                                                       "passkey": 777})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        assert rec.requests[0].kind == "display-passkey" and not rec.requests[0].needs_answer
        assert rec.requests[0].passkey == 777
        assert rec.wait(path, "pair") == ""
        assert client._requests == {}  # the shown code is not kept after the pairing

    def test_sad_the_user_rejects(self, made):
        client, rec = made(devices=[speaker(behaviour={"pair": "confirm", "passkey": 1})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        client.answer(rec.requests[0].token, False)
        assert "rejected" in rec.wait(path, "pair").lower()
        assert not client.device(path).paired

    def test_sad_a_wrong_pin(self, made):
        client, rec = made(devices=[speaker(behaviour={"pair": "pin", "pin": "1234"})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        client.answer(rec.requests[0].token, True, "9999")
        assert "PIN" in rec.wait(path, "pair")

    def test_sad_nobody_listening_is_a_rejection_never_an_accept(self, fake):
        """Security: without a UI to ask, a confirmation is refused."""
        fake.command("add_adapter", name="hci0", props={"Powered": True})
        fake.command("add_device", **speaker(behaviour={"pair": "confirm", "passkey": 5}))
        client = BT.BluezClient(bus=fake.qt_connection())
        finished = []
        client.operation_finished.connect(lambda p, op, err: finished.append(err))
        try:
            client.start()
            assert wait_until(lambda: client.state == "ready")
            client.pair(dev_path(SPEAKER))
            assert wait_until(lambda: finished)
            assert "rejected" in finished[0].lower()
            assert not client.device(dev_path(SPEAKER)).paired
        finally:
            client.shutdown()

    def test_sad_pair_error_from_bluez(self, made):
        client, rec = made(devices=[speaker(
            behaviour={"pair": "error:org.bluez.Error.ConnectionAttemptFailed:Page Timeout"})])
        client.pair(dev_path(SPEAKER))
        assert "in range" in rec.wait(dev_path(SPEAKER), "pair")

    def test_edge_bluez_cancels_the_request(self, made):
        """BlueZ gives up (agent timeout): the dialog's request is cancelled
        and a late answer is harmless."""
        client, rec = made(devices=[speaker(behaviour={"pair": "confirm", "passkey": 9,
                                                       "agent_timeout": 0.3})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        assert wait_until(lambda: rec.cancelled)
        assert rec.cancelled == [rec.requests[0].token]
        assert "timed out" in rec.wait(path, "pair")
        client.answer(rec.requests[0].token, True)  # too late: no crash, nothing sent

    def test_edge_a_second_operation_while_busy_is_refused_at_once(self, made):
        client, rec = made(devices=[speaker(behaviour={"pair": "hang"})])
        path = dev_path(SPEAKER)
        client.pair(path)
        client.connect_device(path)
        assert "still running" in rec.wait(path, "connect", 2)
        assert client.busy(path) == "pair"

    def test_sad_the_service_dies_mid_pairing(self, made, fake):
        client, rec = made(devices=[speaker(behaviour={"pair": "confirm", "passkey": 3})])
        path = dev_path(SPEAKER)
        client.pair(path)
        assert wait_until(lambda: rec.requests)
        fake.kill_fake()
        assert rec.wait(path, "pair")  # an error text, not a hang
        assert wait_until(lambda: client.state == "not-running")
        assert rec.cancelled == [rec.requests[0].token]
        assert client.busy(path) is None
        assert client.devices() == [] and client.adapters() == []


class TestDeviceOperations:
    def test_happy_trust_connect_disconnect_remove(self, made, fake):
        client, rec = made(devices=[speaker(props={"Name": "Desk Speaker", "Paired": True,
                                                   "Icon": "audio-card"})])
        path = dev_path(SPEAKER)
        client.set_trusted(path, True)
        assert rec.wait(path, "trust") == ""
        assert wait_until(lambda: client.device(path).trusted)
        client.connect_device(path)
        assert rec.wait(path, "connect") == ""
        assert wait_until(lambda: client.device(path).connected)
        client.disconnect_device(path)
        assert rec.wait(path, "disconnect") == ""
        assert wait_until(lambda: not client.device(path).connected)
        client.remove_device(path)
        assert rec.wait(path, "remove") == ""
        assert wait_until(lambda: client.device(path) is None)
        assert fake.calls("RemoveDevice")[0]["signature"] == "o"

    def test_sad_connect_without_an_audio_profile(self, made):
        client, rec = made(devices=[speaker(behaviour={
            "connect": "error:org.bluez.Error.Failed:br-connection-profile-unavailable"})])
        client.connect_device(dev_path(SPEAKER))
        assert "profile" in rec.wait(dev_path(SPEAKER), "connect").lower()

    def test_sad_disconnect_when_not_connected(self, made):
        client, rec = made(devices=[speaker()])
        client.disconnect_device(dev_path(SPEAKER))
        assert "not connected" in rec.wait(dev_path(SPEAKER), "disconnect").lower()

    def test_sad_an_unknown_device(self, made):
        client, rec = made()
        client.connect_device("/org/bluez/hci0/dev_00_00_00_00_00_00")
        assert rec.wait("/org/bluez/hci0/dev_00_00_00_00_00_00", "connect")

    def test_happy_battery_appears_changes_and_goes(self, made, fake):
        client, _rec = made(devices=[speaker()])
        path = dev_path(SPEAKER)
        assert client.device(path).battery is None
        fake.command("battery", path=path, percentage=55)
        assert wait_until(lambda: client.device(path).battery == 55)
        fake.command("battery", path=path, percentage=54)
        assert wait_until(lambda: client.device(path).battery == 54)
        fake.command("battery", path=path, percentage=None)
        assert wait_until(lambda: client.device(path).battery is None)
        assert client.device(path) is not None  # only Battery1 went

    def test_edge_a_device_without_a_name_shows_its_address(self, made):
        client, _rec = made(devices=[{"address": PHONE, "props": {"Alias": ""}}])
        assert client.devices()[0].display_name == PHONE

    def test_edge_a_malformed_signal_does_not_escape_the_slot(self, made):
        from PyQt6.QtDBus import QDBusMessage

        client, _rec = made(devices=[speaker()])
        broken = QDBusMessage.createSignal(dev_path(SPEAKER), "org.freedesktop.DBus.Properties",
                                           "PropertiesChanged")
        broken.setArguments([42])
        client._on_properties_changed(broken)  # logged, not raised
        client._on_interfaces_added(broken)
        client._on_interfaces_removed(broken)
        assert client.device(dev_path(SPEAKER)) is not None

    def test_happy_shutdown_stops_our_scan_and_leaves_no_agent(self, made, fake):
        client, rec = made()
        client.start_discovery("/org/bluez/hci0")
        assert rec.wait("/org/bluez/hci0", "scan") == ""
        client.shutdown()
        assert wait_until(lambda: fake.calls("StopDiscovery"), 3)
        assert fake.command("agents") == {}
