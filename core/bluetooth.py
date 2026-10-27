"""Bluetooth through BlueZ on the system D-Bus - the Bluetooth panel's engine.

BlueZ (``bluetoothd``) is the Linux Bluetooth stack; it is driven over the
system D-Bus as the ``org.bluez`` service. This module talks to it with
PyQt6.QtDBus - no host program, no extra Python package - and holds
everything of the Bluetooth panel (resources/extensions/bluetooth.py)
that needs no widget, so it is tested against a fake ``org.bluez`` on a
private bus (tests/fake_bluez.py):

* :class:`BluezClient` - the adapters and devices BlueZ knows, kept up to
  date from ``InterfacesAdded`` / ``InterfacesRemoved`` /
  ``PropertiesChanged``, and the operations on them (power, scan, pair,
  trust, connect, disconnect, remove). Every D-Bus call is asynchronous
  (QDBusPendingCallWatcher): pairing can wait 30 s and more for the
  device or the user, and the GUI thread never waits. A result arrives as
  ``operation_finished(path, op, error_text)``; ``error_text`` is "" for
  success and else a sentence for the user (:func:`error_text`), never an
  exception out of a slot.
* The pairing agent: an ``org.bluez.Agent1`` object is registered with
  BlueZ only while one of our pairings runs (a speaker or headphones pair
  "Just Works" and never call it). Every question BlueZ asks it - confirm
  a passkey, enter a PIN or passkey, authorize - becomes an
  ``agent_request`` for the panel to ask the user; nothing is accepted
  without an answer, and a request with nobody listening is rejected.
* :class:`SinkWaiter`, :func:`find_sink`, :func:`set_audio_output` - after
  a headset connects, its output shows up in Qt's device list
  (QMediaDevices) once the sound server made one; the waiter polls for it
  with a timeout and the panel makes it axross's output in
  core.audio_route (Edit > Settings > Audio), which running players
  follow (``audio_route.notifier().changed``).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from itertools import count
from typing import Callable, Iterable

from PyQt6.QtCore import QMetaType, QObject, QTimer, pyqtClassInfo, pyqtSignal, pyqtSlot
from PyQt6.QtDBus import (
    QDBusAbstractAdaptor,
    QDBusArgument,
    QDBusConnection,
    QDBusMessage,
    QDBusObjectPath,
    QDBusPendingCallWatcher,
    QDBusPendingReply,
    QDBusServiceWatcher,
    QDBusVariant,
)

from core.i18n import tr

log = logging.getLogger(__name__)

SERVICE = "org.bluez"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPERTIES = "org.freedesktop.DBus.Properties"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
BATTERY = "org.bluez.Battery1"
AGENT_MANAGER = "org.bluez.AgentManager1"
AGENT = "org.bluez.Agent1"
#: Our agent answers every kind of question, so BlueZ picks the strongest
#: pairing method the device offers; each question goes to the user.
AGENT_CAPABILITY = "KeyboardDisplay"

#: Milliseconds a D-Bus call may take. Pairing waits for the device and the
#: user (BlueZ's own agent timeout is about 30 s, a PIN typed on a keyboard
#: takes longer); connecting a headset waits for its profiles.
CALL_TIMEOUT_MS = 25_000
PAIR_TIMEOUT_MS = 120_000
CONNECT_TIMEOUT_MS = 60_000

#: Service UUIDs of a device that takes sound: A2DP sink, headset (HSP),
#: hands-free (HFP).
AUDIO_SINK_UUIDS = frozenset({
    "0000110b-0000-1000-8000-00805f9b34fb",
    "00001108-0000-1000-8000-00805f9b34fb",
    "0000111e-0000-1000-8000-00805f9b34fb",
})
AUDIO_ICONS = frozenset({"audio-card", "audio-headset", "audio-headphones"})

#: BlueZ's Icon property (derived from the class or appearance) -> kind.
_ICON_KINDS = {
    "audio-card": "Speaker",
    "audio-headset": "Headset",
    "audio-headphones": "Headphones",
    "phone": "Phone",
    "computer": "Computer",
    "input-keyboard": "Keyboard",
    "input-mouse": "Mouse",
    "input-gaming": "Game Controller",
    "input-tablet": "Tablet",
    "camera-video": "Camera",
    "camera-photo": "Camera",
    "printer": "Printer",
    "scanner": "Scanner",
    "modem": "Modem",
    "network-wireless": "Network",
    "video-display": "Display",
    "multimedia-player": "Media Player",
}
#: Major device class (bits 8-12 of the Class of Device) -> kind.
_MAJOR_KINDS = {1: "Computer", 2: "Phone", 3: "Network", 4: "Audio Device",
                5: "Input Device", 6: "Imaging", 7: "Wearable", 8: "Toy", 9: "Health"}
#: Minor classes of the audio/video major class.
_AUDIO_MINOR = {1: "Headset", 2: "Headset", 5: "Speaker", 6: "Headphones",
                7: "Speaker", 8: "Speaker", 10: "Speaker"}

#: Kinds of device the panel can name, for tr() and for the type column.
KINDS = tuple(dict.fromkeys([*_ICON_KINDS.values(), *_MAJOR_KINDS.values(),
                             *_AUDIO_MINOR.values(), "Device"]))


# -- pure helpers ----------------------------------------------------------------------------

def error_text(name: str, message: str) -> str:
    """A D-Bus error from BlueZ as a sentence for the user."""
    name = name or ""
    message = (message or "").strip()
    low = message.lower()
    if "rfkill" in low:
        return tr("Bluetooth is blocked (rfkill). Unblock it with the wireless switch or "
                  "`rfkill unblock bluetooth`.")
    if "profile-unavailable" in low:
        return tr("The device offers no profile this computer can use. For speakers and "
                  "headphones the sound server needs its Bluetooth support (PipeWire's or "
                  "PulseAudio's Bluetooth module).")
    if "page-timeout" in low or "page timeout" in low:
        return tr("The device did not answer - is it switched on and in range?")
    texts = {
        "org.bluez.Error.NotReady": tr("The Bluetooth adapter is not ready - switch the adapter "
                                       "on first."),
        "org.bluez.Error.AuthenticationFailed": tr("Pairing failed: the PIN or passkey did not "
                                                   "match, or the device refused."),
        "org.bluez.Error.AuthenticationRejected": tr("Pairing was rejected."),
        "org.bluez.Error.AuthenticationCanceled": tr("Pairing was canceled."),
        "org.bluez.Error.AuthenticationTimeout": tr("Pairing timed out - the device or the "
                                                    "answer did not come in time."),
        "org.bluez.Error.ConnectionAttemptFailed": tr("The connection attempt failed - is the "
                                                      "device switched on and in range?"),
        "org.bluez.Error.InProgress": tr("Another operation on this device is still running - "
                                         "wait for it to finish."),
        "org.bluez.Error.AlreadyExists": tr("The device is already paired."),
        "org.bluez.Error.AlreadyConnected": tr("The device is already connected."),
        "org.bluez.Error.NotConnected": tr("The device is not connected."),
        "org.bluez.Error.DoesNotExist": tr("The device is no longer known to BlueZ."),
        "org.bluez.Error.NotAvailable": tr("This is not available on the device or adapter."),
        "org.bluez.Error.NotSupported": tr("The device or adapter does not support this."),
        "org.bluez.Error.NotAuthorized": tr("BlueZ refused: not authorized."),
        "org.bluez.Error.Blocked": tr("Bluetooth is blocked (rfkill). Unblock it with the "
                                      "wireless switch or `rfkill unblock bluetooth`."),
        "org.freedesktop.DBus.Error.NoReply": tr("BlueZ did not answer in time."),
        "org.freedesktop.DBus.Error.Timeout": tr("BlueZ did not answer in time."),
        "org.freedesktop.DBus.Error.ServiceUnknown": tr("The Bluetooth service (bluetoothd) is "
                                                        "not running."),
        "org.freedesktop.DBus.Error.NameHasNoOwner": tr("The Bluetooth service (bluetoothd) is "
                                                        "not running."),
        "org.freedesktop.DBus.Error.Disconnected": tr("The connection to the system D-Bus was "
                                                      "lost."),
        "org.freedesktop.DBus.Error.UnknownObject": tr("The device or adapter is gone."),
        "org.freedesktop.DBus.Error.AccessDenied": tr("D-Bus denied the request - is your user "
                                                      "allowed to use Bluetooth?"),
    }
    text = texts.get(name)
    if text is not None:
        if name.endswith(("NotSupported", "NotAvailable", "AccessDenied")) and message:
            return f"{text} ({message})"
        return text
    if name == "org.bluez.Error.Failed":
        return (tr("BlueZ reported a failure: {message}").format(message=message) if message
                else tr("BlueZ reported a failure."))
    if name == "org.bluez.Error.InvalidArguments":
        return tr("BlueZ rejected the request as invalid: {message}").format(message=message)
    if not name and not message:
        return tr("The operation failed.")
    return f"{name}: {message}" if name and message else (name or message)


def device_kind(icon, device_class) -> str:
    """"Speaker", "Headset", "Phone", ... from BlueZ's Icon, else from the
    Class of Device; "Device" when neither says anything."""
    kind = _ICON_KINDS.get(icon if isinstance(icon, str) else "")
    if kind:
        return kind
    if not isinstance(device_class, int) or isinstance(device_class, bool) or device_class <= 0:
        return "Device"
    major = (device_class >> 8) & 0x1F
    minor = (device_class >> 2) & 0x3F
    if major == 4:
        return _AUDIO_MINOR.get(minor, "Audio Device")
    if major == 5:
        if minor & 0x10:
            return "Keyboard"
        if minor & 0x20:
            return "Mouse"
    return _MAJOR_KINDS.get(major, "Device")


def normalise(value):
    """A value as QtDBus hands it to Python, as plain Python: a byte ('y',
    which arrives as one-byte ``bytes``) is a number, object paths and
    variants are unwrapped."""
    if isinstance(value, (bytes, bytearray)) and len(value) == 1:
        return value[0]
    if isinstance(value, QDBusObjectPath):
        return value.path()
    if isinstance(value, QDBusVariant):
        return normalise(value.variant())
    if isinstance(value, dict):
        return {normalise(k): normalise(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalise(v) for v in value]
    return value


def _int_or_none(value) -> int | None:
    value = normalise(value)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


@dataclass(frozen=True)
class Adapter:
    path: str
    address: str
    name: str
    alias: str
    powered: bool
    discovering: bool
    discoverable: bool
    power_state: str

    @property
    def display_name(self) -> str:
        return self.alias or self.name or self.address or self.path.rsplit("/", 1)[-1]

    @classmethod
    def from_props(cls, path: str, props: dict) -> Adapter:
        return cls(path=path, address=str(props.get("Address", "")),
                   name=str(props.get("Name", "")), alias=str(props.get("Alias", "")),
                   powered=bool(props.get("Powered", False)),
                   discovering=bool(props.get("Discovering", False)),
                   discoverable=bool(props.get("Discoverable", False)),
                   power_state=str(props.get("PowerState", "")))


@dataclass(frozen=True)
class Device:
    path: str
    adapter: str
    address: str
    name: str
    alias: str
    icon: str
    device_class: int
    rssi: int | None
    paired: bool
    trusted: bool
    connected: bool
    blocked: bool
    uuids: tuple
    battery: int | None

    @property
    def display_name(self) -> str:
        return self.alias or self.name or self.address

    @property
    def kind(self) -> str:
        return device_kind(self.icon, self.device_class)

    @classmethod
    def from_props(cls, path: str, props: dict, battery: dict | None) -> Device:
        uuids = props.get("UUIDs") or ()
        return cls(path=path, adapter=str(props.get("Adapter", path.rsplit("/", 1)[0])),
                   address=str(props.get("Address", "")), name=str(props.get("Name", "")),
                   alias=str(props.get("Alias", "")), icon=str(props.get("Icon", "")),
                   device_class=_int_or_none(props.get("Class")) or 0,
                   rssi=_int_or_none(props.get("RSSI")),
                   paired=bool(props.get("Paired", False)),
                   trusted=bool(props.get("Trusted", False)),
                   connected=bool(props.get("Connected", False)),
                   blocked=bool(props.get("Blocked", False)),
                   uuids=tuple(str(u).lower() for u in uuids if isinstance(u, str)),
                   battery=_int_or_none((battery or {}).get("Percentage")))


def is_audio_output(device: Device) -> bool:
    """True for a device that takes sound (speaker, headset, headphones)."""
    return bool(AUDIO_SINK_UUIDS & set(device.uuids)) or device.icon in AUDIO_ICONS or \
        device.kind in ("Speaker", "Headset", "Headphones")


def find_sink(outputs: Iterable[tuple[str, str]], device: Device) -> tuple[str, str] | None:
    """The ``(id, description)`` of *outputs* that is *device*'s sound
    output: an id that carries its address (PipeWire
    ``bluez_output.AA_BB_..``, PulseAudio ``bluez_sink.aa_bb_..``), else a
    description equal to its name."""
    outputs = list(outputs)
    address = device.address.lower()
    if address:
        keys = (address.replace(":", "_"), address)
        for output in outputs:
            ident = str(output[0]).lower()
            if any(key in ident for key in keys):
                return output
    names = {n.strip().lower() for n in (device.alias, device.name) if n and n.strip()}
    for output in outputs:
        if str(output[1]).strip().lower() in names:
            return output
    return None


def set_audio_output(device_id: str, path=None):
    """Make *device_id* axross's audio output: saved like Edit > Settings >
    Audio saves it, and published to running players."""
    from core import audio_route
    from core.audio_settings import AudioSettings

    settings = AudioSettings.load(path)
    settings.set("output_device", device_id)
    settings.save(path)
    audio_route.publish(settings)
    return settings


def qt_audio_outputs() -> list[tuple[str, str]]:
    """Qt's audio outputs as ``(id, description)`` - only after
    core.multimedia_probe answered ok (its rule for every device list)."""
    from PyQt6.QtMultimedia import QMediaDevices

    from core import audio_route

    return [(audio_route.device_id(d), d.description()) for d in QMediaDevices.audioOutputs()]


# -- the agent BlueZ calls back --------------------------------------------------------------

@dataclass(frozen=True)
class AgentRequest:
    """A question BlueZ asks during a pairing.

    ``kind``: ``confirm`` (does the device show ``passkey``?), ``pin`` and
    ``passkey`` (type what the device shows or wants), ``display-passkey``
    / ``display-pin`` (show it; no answer), ``authorize`` (allow the
    pairing) and ``authorize-service`` (allow ``uuid``).
    """

    token: int
    kind: str
    device_path: str
    device_name: str
    passkey: int | None = None
    pin: str = ""
    uuid: str = ""

    @property
    def needs_answer(self) -> bool:
        return not self.kind.startswith("display-")


@pyqtClassInfo("D-Bus Interface", AGENT)
class _Agent(QDBusAbstractAdaptor):
    """org.bluez.Agent1 - every method hands its question to the client."""

    def __init__(self, parent: QObject, client: "BluezClient") -> None:
        super().__init__(parent)
        self._client = client

    @pyqtSlot()
    def Release(self) -> None:  # noqa: N802 - D-Bus method name
        self._client._agent_released()

    @pyqtSlot(QDBusObjectPath, QDBusMessage)
    def RequestPinCode(self, device, message) -> None:  # noqa: N802
        self._client._agent_ask(message, "pin", device)

    @pyqtSlot(QDBusObjectPath, str)
    def DisplayPinCode(self, device, pincode) -> None:  # noqa: N802
        self._client._agent_show("display-pin", device, pin=pincode)

    @pyqtSlot(QDBusObjectPath, QDBusMessage)
    def RequestPasskey(self, device, message) -> None:  # noqa: N802
        self._client._agent_ask(message, "passkey", device)

    @pyqtSlot(QDBusObjectPath, "uint", "ushort")
    def DisplayPasskey(self, device, passkey, entered) -> None:  # noqa: N802
        self._client._agent_show("display-passkey", device, passkey=int(passkey))

    @pyqtSlot(QDBusObjectPath, "uint", QDBusMessage)
    def RequestConfirmation(self, device, passkey, message) -> None:  # noqa: N802
        self._client._agent_ask(message, "confirm", device, passkey=int(passkey))

    @pyqtSlot(QDBusObjectPath, QDBusMessage)
    def RequestAuthorization(self, device, message) -> None:  # noqa: N802
        self._client._agent_ask(message, "authorize", device)

    @pyqtSlot(QDBusObjectPath, str, QDBusMessage)
    def AuthorizeService(self, device, uuid, message) -> None:  # noqa: N802
        self._client._agent_ask(message, "authorize-service", device, uuid=uuid)

    @pyqtSlot()
    def Cancel(self) -> None:  # noqa: N802
        self._client._agent_cancel_all()


# -- the client ------------------------------------------------------------------------------

_agent_numbers = count(1)


class BluezClient(QObject):
    """BlueZ's adapters and devices, and the operations on them.

    ``state``: ``unavailable`` (no system D-Bus), ``not-running`` (no
    bluetoothd), ``loading``, ``no-adapter``, ``ready``, ``error``
    (BlueZ answered the first question with an error).
    """

    state_changed = pyqtSignal(str)
    #: The set of adapters or devices changed, or an adapter's properties.
    adapters_changed = pyqtSignal()
    devices_changed = pyqtSignal()
    #: One device's properties changed (path).
    device_updated = pyqtSignal(str)
    #: (path, op) - op: power, scan, stop-scan, pair, cancel-pairing,
    #: trust, connect, disconnect, remove.
    operation_started = pyqtSignal(str, str)
    #: (path, op, error text - "" when it worked).
    operation_finished = pyqtSignal(str, str, str)
    agent_request = pyqtSignal(object)
    #: The token of a request BlueZ took back (timeout, canceled pairing).
    agent_cancelled = pyqtSignal(int)

    def __init__(self, bus: QDBusConnection | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._bus = bus
        self._state = "loading"
        self._state_detail = ""
        #: path -> {interface: {property: value}} of adapters and devices.
        self._objects: dict[str, dict[str, dict]] = {}
        self._busy: dict[str, str] = {}
        self._watchers: set[QDBusPendingCallWatcher] = set()
        self._scans: set[str] = set()
        self._agent_path = f"/org/axross/bluetooth/agent{next(_agent_numbers)}"
        self._agent_host: QObject | None = None
        self._agent_registered = False
        self._agent_registering = False
        #: callbacks waiting for the agent registration to answer
        self._agent_waiters: list[Callable[[], None]] = []
        self._requests: dict[int, tuple[AgentRequest, QDBusMessage | None]] = {}
        self._tokens = count(1)
        self._service_watcher: QDBusServiceWatcher | None = None
        self._subscribed = False
        self._started = False
        self._shut = False
        self._load_serial = 0

    # -- reading -------------------------------------------------------------------------

    @property
    def state(self) -> str:
        return self._state

    def state_text(self) -> str:
        """What the panel says about the state ("" when ready)."""
        if self._state == "unavailable":
            return tr("The system D-Bus cannot be reached ({detail}). The Bluetooth panel talks "
                      "to BlueZ over the system D-Bus.").format(detail=self._state_detail or "?")
        if self._state == "not-running":
            return tr("The Bluetooth service (bluetoothd) is not running. Start it (for "
                      "example: systemctl start bluetooth); this panel notices when it runs.")
        if self._state == "no-adapter":
            return tr("No Bluetooth adapter found. Plug one in or unblock it (rfkill); this "
                      "panel notices when it appears.")
        if self._state == "error":
            return tr("BlueZ could not be read: {text}").format(text=self._state_detail)
        if self._state == "loading":
            return tr("Asking BlueZ…")
        return ""

    def adapters(self) -> list[Adapter]:
        return [Adapter.from_props(path, ifaces[ADAPTER])
                for path, ifaces in sorted(self._objects.items()) if ADAPTER in ifaces]

    def adapter(self, path: str) -> Adapter | None:
        props = self._objects.get(path, {}).get(ADAPTER)
        return Adapter.from_props(path, props) if props is not None else None

    def devices(self, adapter: str | None = None) -> list[Device]:
        out = []
        for path, ifaces in sorted(self._objects.items()):
            if DEVICE not in ifaces:
                continue
            device = Device.from_props(path, ifaces[DEVICE], ifaces.get(BATTERY))
            if adapter is None or device.adapter == adapter:
                out.append(device)
        return out

    def device(self, path: str) -> Device | None:
        ifaces = self._objects.get(path, {})
        if DEVICE not in ifaces:
            return None
        return Device.from_props(path, ifaces[DEVICE], ifaces.get(BATTERY))

    def busy(self, path: str) -> str | None:
        """The operation running on *path*, or None."""
        return self._busy.get(path)

    # -- start and stop ------------------------------------------------------------------

    def start(self) -> None:
        """Connect to BlueZ: watch the service, load what it knows."""
        if self._started or self._shut:
            return
        self._started = True
        try:
            if self._bus is None:
                self._bus = QDBusConnection.systemBus()
            if not self._bus.isConnected():
                self._state_detail = self._bus.lastError().message() or tr("not connected")
                self._set_state("unavailable")
                return
            self._agent_host = QObject(self)
            _Agent(self._agent_host, self)
            if not self._bus.registerObject(self._agent_path, self._agent_host):
                log.warning("the Bluetooth agent object %s could not be registered",
                            self._agent_path)
            self._service_watcher = QDBusServiceWatcher(
                SERVICE, self._bus, QDBusServiceWatcher.WatchModeFlag.WatchForOwnerChange, self)
            self._service_watcher.serviceOwnerChanged.connect(self._owner_changed)
            self._subscribe(True)
            msg = QDBusMessage.createMethodCall("org.freedesktop.DBus", "/org/freedesktop/DBus",
                                                "org.freedesktop.DBus", "NameHasOwner")
            msg.setArguments([SERVICE])
            self._async(msg, CALL_TIMEOUT_MS, self._has_owner_answered)
        except Exception as exc:  # noqa: BLE001 - the panel says it, axross keeps running
            log.exception("starting the Bluetooth client failed")
            self._state_detail = str(exc)
            self._set_state("unavailable")

    def shutdown(self) -> None:
        """Stop our scans, take our agent back, cancel open questions."""
        if self._shut:
            return
        self._shut = True
        bus = self._bus
        if bus is None or not self._started or not bus.isConnected():
            return
        try:
            for adapter in sorted(self._scans):
                bus.send(QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER,
                                                       "StopDiscovery"))
            self._scans.clear()
            for token in list(self._requests):
                self._reply_request(token, accept=False, error="org.bluez.Error.Canceled")
            if self._agent_registered:
                msg = QDBusMessage.createMethodCall(SERVICE, "/org/bluez", AGENT_MANAGER,
                                                    "UnregisterAgent")
                msg.setArguments([QDBusObjectPath(self._agent_path)])
                bus.send(msg)
                self._agent_registered = False
            bus.unregisterObject(self._agent_path)
            self._subscribe(False)
            if self._service_watcher is not None:
                self._service_watcher.serviceOwnerChanged.disconnect(self._owner_changed)
        except Exception:  # noqa: BLE001 - closing must not fail
            log.exception("stopping the Bluetooth client failed")

    def _subscribe(self, on: bool) -> None:
        if on == self._subscribed or self._bus is None:
            return
        method = self._bus.connect if on else self._bus.disconnect
        ok = all([
            method(SERVICE, "/", OBJECT_MANAGER, "InterfacesAdded", self._on_interfaces_added),
            method(SERVICE, "/", OBJECT_MANAGER, "InterfacesRemoved",
                   self._on_interfaces_removed),
            method(SERVICE, "", PROPERTIES, "PropertiesChanged", self._on_properties_changed),
        ])
        if not ok:
            log.warning("the BlueZ signals could not be %s",
                        "subscribed" if on else "unsubscribed")
        self._subscribed = on

    def _set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self.state_changed.emit(state)

    def _update_state(self) -> None:
        self._set_state("ready" if any(ADAPTER in i for i in self._objects.values())
                        else "no-adapter")

    # -- the service coming and going ----------------------------------------------------

    def _has_owner_answered(self, error: tuple[str, str] | None, args: list) -> None:
        if error is not None:
            self._state_detail = error_text(*error)
            self._set_state("unavailable")
            return
        if args and args[0]:
            self._load()
        else:
            self._set_state("not-running")

    def _owner_changed(self, _name: str, _old: str, new: str) -> None:
        try:
            if self._shut:
                return
            if new:
                self._agent_registered = False
                self._load()
            else:
                self._service_gone()
        except Exception:  # noqa: BLE001 - a slot never raises
            log.exception("handling the BlueZ owner change failed")

    def _service_gone(self) -> None:
        self._load_serial += 1  # a GetManagedObjects still under way is stale
        self._agent_registered = False
        self._agent_registering = False
        self._agent_waiters.clear()
        self._scans.clear()
        self._agent_cancel_all()
        had = bool(self._objects)
        self._objects.clear()
        self._set_state("not-running")
        if had:
            self.adapters_changed.emit()
            self.devices_changed.emit()

    def _load(self) -> None:
        self._load_serial += 1
        serial = self._load_serial
        if self._state != "ready":
            self._set_state("loading")
        msg = QDBusMessage.createMethodCall(SERVICE, "/", OBJECT_MANAGER, "GetManagedObjects")
        self._async(msg, CALL_TIMEOUT_MS, lambda err, args: self._loaded(serial, err, args))

    def _loaded(self, serial: int, error, args: list) -> None:
        if serial != self._load_serial or self._shut:
            return
        if error is not None:
            if error[0] in ("org.freedesktop.DBus.Error.ServiceUnknown",
                            "org.freedesktop.DBus.Error.NameHasNoOwner"):
                self._set_state("not-running")
            else:
                self._state_detail = error_text(*error)
                self._set_state("error")
            return
        objects = normalise(args[0]) if args else {}
        self._objects = {}
        if isinstance(objects, dict):
            for path, ifaces in objects.items():
                self._store(str(path), ifaces)
        self._update_state()
        self.adapters_changed.emit()
        self.devices_changed.emit()

    def _store(self, path: str, ifaces) -> bool:
        """Keep the BlueZ interfaces of *path*; True when it is an adapter or
        a device (or the battery of one)."""
        if not isinstance(ifaces, dict):
            return False
        wanted = {k: dict(v) for k, v in ifaces.items()
                  if k in (ADAPTER, DEVICE, BATTERY) and isinstance(v, dict)}
        if not wanted:
            return False
        self._objects.setdefault(path, {}).update(wanted)
        return True

    # -- signals from BlueZ --------------------------------------------------------------

    @pyqtSlot(QDBusMessage)
    def _on_interfaces_added(self, message: QDBusMessage) -> None:
        try:
            if self._shut:
                return
            args = message.arguments()
            if len(args) < 2:
                return
            path, ifaces = normalise(args[0]), normalise(args[1])
            if not isinstance(path, str) or not self._store(path, ifaces):
                return
            if ADAPTER in ifaces:
                self._update_state()
                self.adapters_changed.emit()
            if DEVICE in ifaces:
                self.devices_changed.emit()
            elif BATTERY in ifaces:
                self.device_updated.emit(path)
        except Exception:  # noqa: BLE001 - a slot never raises
            log.exception("handling InterfacesAdded failed")

    @pyqtSlot(QDBusMessage)
    def _on_interfaces_removed(self, message: QDBusMessage) -> None:
        try:
            if self._shut:
                return
            args = message.arguments()
            if len(args) < 2:
                return
            path, gone = normalise(args[0]), normalise(args[1])
            if not isinstance(path, str) or not isinstance(gone, list) or path not in self._objects:
                return
            ifaces = self._objects[path]
            for name in gone:
                ifaces.pop(name, None)
            if DEVICE not in ifaces and ADAPTER not in ifaces:
                del self._objects[path]
            if ADAPTER in gone:
                self._scans.discard(path)
                self._update_state()
                self.adapters_changed.emit()
            if DEVICE in gone:
                self.devices_changed.emit()
            elif BATTERY in gone:
                self.device_updated.emit(path)
        except Exception:  # noqa: BLE001
            log.exception("handling InterfacesRemoved failed")

    @pyqtSlot(QDBusMessage)
    def _on_properties_changed(self, message: QDBusMessage) -> None:
        try:
            if self._shut:
                return
            args = message.arguments()
            if len(args) < 2:
                return
            path = message.path()
            iface, changed = normalise(args[0]), normalise(args[1])
            invalidated = normalise(args[2]) if len(args) > 2 else []
            props = self._objects.get(path, {}).get(iface)
            if props is None or not isinstance(changed, dict):
                return
            props.update(changed)
            for name in invalidated if isinstance(invalidated, list) else ():
                props.pop(name, None)
            if iface == ADAPTER:
                if "Discovering" in changed and not changed["Discovering"]:
                    self._scans.discard(path)
                self.adapters_changed.emit()
            else:
                self.device_updated.emit(path)
        except Exception:  # noqa: BLE001
            log.exception("handling PropertiesChanged failed")

    # -- calls ---------------------------------------------------------------------------

    def _async(self, msg: QDBusMessage, timeout_ms: int, done) -> None:
        """Send *msg*; ``done(error, args)`` on the GUI thread with error
        ``(name, message)`` or None."""
        watcher = QDBusPendingCallWatcher(self._bus.asyncCall(msg, timeout_ms), self)
        self._watchers.add(watcher)

        def finished(w) -> None:
            self._watchers.discard(w)
            w.deleteLater()
            try:
                reply = QDBusPendingReply(w)
                if reply.isError():
                    err = reply.error()
                    done((err.name(), err.message()), [])
                else:
                    done(None, list(reply.reply().arguments()))
            except Exception:  # noqa: BLE001 - a slot never raises
                log.exception("handling the reply to %s.%s failed", msg.interface(),
                              msg.member())

        watcher.finished.connect(finished)

    def _finish_later(self, path: str, op: str, text: str) -> None:
        QTimer.singleShot(0, lambda: self.operation_finished.emit(path, op, text))

    def _begin(self, path: str, op: str, needs: str,
               on_success: Callable[[], None] | None = None):
        """Claim *path* for *op*: one operation per object at a time. Returns
        ``done(error, args)`` that ends it with operation_finished, or None
        when it is refused (said through operation_finished)."""
        if self._shut or self._bus is None or self._state not in ("ready", "no-adapter"):
            self._finish_later(path, op, self.state_text() or tr("Bluetooth is not available."))
            return None
        if needs not in self._objects.get(path, {}):
            self._finish_later(path, op, error_text(
                "org.bluez.Error.DoesNotExist" if needs == DEVICE
                else "org.freedesktop.DBus.Error.UnknownObject", ""))
            return None
        if self._busy.get(path) is not None:
            self._finish_later(path, op, error_text("org.bluez.Error.InProgress", ""))
            return None
        self._busy[path] = op
        self.operation_started.emit(path, op)

        def done(error, _args) -> None:
            if self._busy.get(path) == op:
                del self._busy[path]
            if error is None and on_success is not None:
                on_success()
            self.operation_finished.emit(path, op, "" if error is None else error_text(*error))

        return done

    def _operation(self, path: str, op: str, msg: QDBusMessage,
                   timeout_ms: int = CALL_TIMEOUT_MS, *, needs: str = DEVICE,
                   on_success: Callable[[], None] | None = None) -> None:
        done = self._begin(path, op, needs, on_success)
        if done is not None:
            self._async(msg, timeout_ms, done)

    def _set_property(self, path: str, iface: str, name: str, value: bool, op: str,
                      needs: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, path, PROPERTIES, "Set")
        msg.setArguments([iface, name, QDBusVariant(bool(value))])
        self._operation(path, op, msg, needs=needs)

    def set_powered(self, adapter: str, on: bool) -> None:
        self._set_property(adapter, ADAPTER, "Powered", on, "power", ADAPTER)

    def start_discovery(self, adapter: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER, "StartDiscovery")
        self._operation(adapter, "scan", msg, needs=ADAPTER,
                        on_success=lambda: self._scans.add(adapter))

    def stop_discovery(self, adapter: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER, "StopDiscovery")
        self._operation(adapter, "stop-scan", msg, needs=ADAPTER,
                        on_success=lambda: self._scans.discard(adapter))

    def set_trusted(self, device: str, on: bool) -> None:
        self._set_property(device, DEVICE, "Trusted", on, "trust", DEVICE)

    def connect_device(self, device: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "Connect")
        self._operation(device, "connect", msg, CONNECT_TIMEOUT_MS)

    def disconnect_device(self, device: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "Disconnect")
        self._operation(device, "disconnect", msg)

    def remove_device(self, device: str) -> None:
        props = self._objects.get(device, {}).get(DEVICE, {})
        adapter = str(props.get("Adapter") or device.rsplit("/", 1)[0])
        msg = QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER, "RemoveDevice")
        msg.setArguments([QDBusObjectPath(device)])
        self._operation(device, "remove", msg)

    def cancel_pairing(self, device: str) -> None:
        """Ask BlueZ to stop a pairing of ours; the pairing itself then
        finishes with "canceled"."""
        if self._bus is None or self._shut:
            return
        msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "CancelPairing")
        self._async(msg, CALL_TIMEOUT_MS, lambda err, _a: self.operation_finished.emit(
            device, "cancel-pairing", "" if err is None else error_text(*err)))

    def pair(self, device: str) -> None:
        """Pair with *device*: our agent is registered first (BlueZ asks the
        agent of the connection that called Pair), and taken back after."""
        done = self._begin(device, "pair", DEVICE)
        if done is None:  # refused (busy, unknown, not ready)
            return

        def finished(error, args) -> None:
            # a code shown for this pairing has served its purpose
            for token, (request, _msg) in list(self._requests.items()):
                if request.device_path == device and not request.needs_answer:
                    del self._requests[token]
            done(error, args)
            if "pair" not in self._busy.values():
                self._unregister_agent()

        def send_pair() -> None:
            if self._shut:
                finished(("org.bluez.Error.AuthenticationCanceled", ""), [])
                return
            msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "Pair")
            self._async(msg, PAIR_TIMEOUT_MS, finished)

        self._with_agent(send_pair)

    # -- the agent -----------------------------------------------------------------------

    def _with_agent(self, then: Callable[[], None]) -> None:
        if self._agent_registered:
            then()
            return
        self._agent_waiters.append(then)
        if self._agent_registering:
            return
        self._agent_registering = True
        msg = QDBusMessage.createMethodCall(SERVICE, "/org/bluez", AGENT_MANAGER, "RegisterAgent")
        msg.setArguments([QDBusObjectPath(self._agent_path), AGENT_CAPABILITY])

        def registered(error, _args) -> None:
            self._agent_registering = False
            if error is None or error[0] == "org.bluez.Error.AlreadyExists":
                self._agent_registered = True
            else:  # pairing still works for devices that need no question
                log.warning("the Bluetooth agent could not be registered: %s %s", *error)
            waiters, self._agent_waiters = self._agent_waiters, []
            for waiter in waiters:
                waiter()

        self._async(msg, CALL_TIMEOUT_MS, registered)

    def _unregister_agent(self) -> None:
        if not self._agent_registered or self._shut:
            return
        self._agent_registered = False
        msg = QDBusMessage.createMethodCall(SERVICE, "/org/bluez", AGENT_MANAGER,
                                            "UnregisterAgent")
        msg.setArguments([QDBusObjectPath(self._agent_path)])
        self._async(msg, CALL_TIMEOUT_MS, lambda err, _a: err and log.info(
            "unregistering the Bluetooth agent: %s %s", *err))

    def _device_name(self, path: str) -> str:
        device = self.device(path)
        return device.display_name if device is not None else path.rsplit("/", 1)[-1]

    def _agent_ask(self, message: QDBusMessage, kind: str, device, **extra) -> None:
        """A question that needs the user's answer: held (delayed reply)
        until :meth:`answer`; rejected at once when nobody listens."""
        try:
            message.setDelayedReply(True)
            # PyQt hands the slot a message that is gone after it returns: keep a copy.
            message = QDBusMessage(message)
            path = normalise(device)
            token = next(self._tokens)
            request = AgentRequest(token=token, kind=kind, device_path=path,
                                   device_name=self._device_name(path), **extra)
            self._requests[token] = (request, message)
            if self._shut or self.receivers(self.agent_request) == 0:
                log.warning("Bluetooth agent: %s for %s rejected - nobody to ask", kind, path)
                self._reply_request(token, accept=False)
                return
            self.agent_request.emit(request)
        except Exception:  # noqa: BLE001 - never accept by accident
            log.exception("the Bluetooth agent request %s failed", kind)
            try:
                self._bus.send(message.createErrorReply("org.bluez.Error.Rejected", "error"))
            except Exception:  # noqa: BLE001
                pass

    def _agent_show(self, kind: str, device, **extra) -> None:
        try:
            path = normalise(device)
            token = next(self._tokens)
            request = AgentRequest(token=token, kind=kind, device_path=path,
                                   device_name=self._device_name(path), **extra)
            self._requests[token] = (request, None)
            self.agent_request.emit(request)
        except Exception:  # noqa: BLE001
            log.exception("the Bluetooth agent display %s failed", kind)

    def answer(self, token: int, accept: bool, value=None) -> None:
        """The user's answer to request *token*: accept with *value* (the
        PIN as text, the passkey as a number) or reject. A request BlueZ
        took back already is ignored."""
        try:
            self._reply_request(token, accept=accept, value=value)
        except Exception:  # noqa: BLE001
            log.exception("answering the Bluetooth agent failed")

    def _reply_request(self, token: int, *, accept: bool, value=None,
                       error: str = "org.bluez.Error.Rejected") -> None:
        entry = self._requests.pop(token, None)
        if entry is None:
            return
        request, message = entry
        if message is None or self._bus is None:
            return
        if not accept:
            self._bus.send(message.createErrorReply(error, "Rejected by the user"
                                                    if error.endswith("Rejected") else "Canceled"))
            return
        if request.kind == "pin":
            pin = str(value or "")
            if not (1 <= len(pin) <= 16):
                self._bus.send(message.createErrorReply("org.bluez.Error.Rejected", "no PIN"))
                return
            self._bus.send(message.createReply([pin]))
        elif request.kind == "passkey":
            try:
                passkey = int(value)
            except (TypeError, ValueError):
                passkey = -1
            if not 0 <= passkey <= 999_999:
                self._bus.send(message.createErrorReply("org.bluez.Error.Rejected",
                                                        "no passkey"))
                return
            arg = QDBusArgument()
            arg.add(passkey, QMetaType.Type.UInt.value)
            self._bus.send(message.createReply([arg]))
        else:
            self._bus.send(message.createReply([]))

    def _agent_cancel_all(self) -> None:
        """BlueZ took its question back (Cancel), or went away."""
        for token in list(self._requests):
            entry = self._requests.pop(token)
            if entry[1] is not None or entry[0].kind.startswith("display-"):
                self.agent_cancelled.emit(token)

    def _agent_released(self) -> None:
        self._agent_registered = False
        self._agent_cancel_all()


# -- waiting for a headset's audio output ----------------------------------------------------

class SinkWaiter(QObject):
    """Poll Qt's audio outputs until *device*'s shows up, or *timeout*.

    The sound server makes the output a moment after the device connected
    (PipeWire: ``bluez_output.<address>.<n>``) - or never, when the A2DP
    profile is not available. ``lister`` returns ``(id, description)``
    pairs; without one, core.multimedia_probe is asked first (no Qt
    device list before it answered ok) and then QMediaDevices.
    """

    found = pyqtSignal(str, str)
    timed_out = pyqtSignal()
    #: The audio system itself is not usable (the probe's text).
    failed = pyqtSignal(str)

    def __init__(self, device: Device, *, lister: Callable[[], list] | None = None,
                 timeout: float = 20.0, interval_ms: int = 500,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.device = device
        self._lister = lister
        self._timeout = timeout
        self._deadline = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._poll)
        self.running = False

    def start(self) -> None:
        self.running = True
        self._deadline = time.monotonic() + self._timeout
        if self._lister is not None:
            self._begin()
            return
        from core import multimedia_probe as MPROBE

        def probed(result) -> None:
            if not self.running:
                return
            if result.ok:
                self._lister = qt_audio_outputs
                self._begin()
            else:
                self.running = False
                self.failed.emit(MPROBE.unavailable_text(result))

        MPROBE.probe_async(probed, context=self)

    def stop(self) -> None:
        self.running = False
        self._timer.stop()

    def _begin(self) -> None:
        self._timer.start()
        self._poll()

    def _poll(self) -> None:
        if not self.running:
            return
        try:
            match = find_sink(self._lister(), self.device)
        except Exception:  # noqa: BLE001 - the next poll may work; the timeout bounds it
            log.debug("listing the audio outputs failed", exc_info=True)
            match = None
        if match is not None:
            self.stop()
            self.found.emit(str(match[0]), str(match[1]))
        elif time.monotonic() >= self._deadline:
            self.stop()
            self.timed_out.emit()


__all__ = ["AGENT_CAPABILITY", "AUDIO_SINK_UUIDS", "Adapter", "AgentRequest", "BluezClient",
           "Device", "KINDS", "SinkWaiter", "device_kind", "error_text", "find_sink",
           "is_audio_output", "normalise", "qt_audio_outputs", "set_audio_output"]
