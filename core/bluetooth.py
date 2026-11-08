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
import math
import time
import unicodedata
from collections import deque
from dataclasses import dataclass
from itertools import count
from typing import Callable, Iterable

from PyQt6.QtCore import (
    QByteArray,
    QMetaType,
    QObject,
    QTimer,
    QVariant,
    pyqtClassInfo,
    pyqtSignal,
    pyqtSlot,
)
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
GATT_SERVICE = "org.bluez.GattService1"
GATT_CHARACTERISTIC = "org.bluez.GattCharacteristic1"
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
#: Exact GAP Appearance values (Bluetooth Assigned Numbers 2.6) -> kind.
_APPEARANCE_KINDS = {0x03C1: "Keyboard", 0x03C2: "Mouse", 0x03C3: "Game Controller",
                     0x03C4: "Game Controller", 0x03C5: "Tablet", 0x0941: "Earbuds",
                     0x0942: "Headset", 0x0943: "Headphones", 0x0944: "Headphones"}
#: GAP Appearance category (the upper 10 bits) -> kind.
_APPEARANCE_CATEGORIES = {
    0x01: "Phone", 0x02: "Computer", 0x03: "Watch", 0x04: "Clock", 0x05: "Display",
    0x06: "Remote Control", 0x07: "Eyeglasses", 0x08: "Tag", 0x09: "Tag",
    0x0A: "Media Player", 0x0B: "Scanner", 0x0C: "Health Device", 0x0D: "Health Device",
    0x0E: "Health Device", 0x0F: "Input Device", 0x10: "Health Device",
    0x11: "Fitness Sensor", 0x12: "Fitness Sensor", 0x13: "Remote Control", 0x14: "Network",
    0x15: "Sensor", 0x16: "Light", 0x17: "Climate Device", 0x18: "Climate Device",
    0x19: "Climate Device", 0x1A: "Climate Device", 0x1B: "Climate Device",
    0x1C: "Access Control", 0x1F: "Light", 0x21: "Speaker", 0x22: "Audio Source",
    0x23: "Vehicle", 0x24: "Appliance", 0x25: "Headphones", 0x27: "Media Player",
    0x28: "Display", 0x29: "Hearing Aid", 0x2A: "Game Controller", 0x31: "Health Device",
    0x32: "Health Device", 0x34: "Health Device", 0x35: "Health Device",
    0x36: "Health Device", 0x37: "Health Device", 0x51: "Fitness Sensor",
}
#: Major device class (bits 8-12 of the Class of Device) -> kind.
_MAJOR_KINDS = {1: "Computer", 2: "Phone", 3: "Network", 4: "Audio Device",
                5: "Input Device", 6: "Imaging", 7: "Wearable", 8: "Toy", 9: "Health"}
#: Minor classes of the audio/video major class.
_AUDIO_MINOR = {1: "Headset", 2: "Headset", 5: "Speaker", 6: "Headphones",
                7: "Speaker", 8: "Speaker", 10: "Speaker"}

#: Kinds of device the panel can name, for tr() and for the type column.
KINDS = tuple(dict.fromkeys([*_ICON_KINDS.values(), *_APPEARANCE_KINDS.values(),
                             *_APPEARANCE_CATEGORIES.values(), *_MAJOR_KINDS.values(),
                             *_AUDIO_MINOR.values(), "Earbuds", "Beacon", "Game Console",
                             "Device"]))
#: Kinds that take sound.
AUDIO_KINDS = frozenset({"Speaker", "Headset", "Headphones", "Earbuds", "Hearing Aid"})

#: What a scan looks for (Adapter1.SetDiscoveryFilter "Transport"): both
#: radios, Classic (BR/EDR) only, Low Energy only.
TRANSPORTS = ("auto", "bredr", "le")
#: Bearers a device is seen on.
BEARERS = ("Classic", "LE", "Dual")

#: The Bluetooth base UUID: a 16-bit UUID ``xxxx`` is
#: ``0000xxxx-0000-1000-8000-00805f9b34fb``.
_BASE_SUFFIX = "-0000-1000-8000-00805f9b34fb"

#: 16-bit service, profile and characteristic UUIDs (Bluetooth Assigned
#: Numbers) -> their names. Proper names, not translated.
UUID_NAMES = {
    0x1101: "Serial Port", 0x1103: "Dial-up Networking", 0x1105: "OBEX Object Push",
    0x1106: "OBEX File Transfer", 0x1108: "Headset", 0x110A: "Audio Source",
    0x110B: "Audio Sink", 0x110C: "A/V Remote Control Target",
    0x110D: "Advanced Audio Distribution", 0x110E: "A/V Remote Control",
    0x110F: "A/V Remote Control Controller", 0x1112: "Headset Audio Gateway",
    0x1115: "PAN User", 0x1116: "Network Access Point", 0x1117: "Group Network",
    0x111E: "Handsfree", 0x111F: "Handsfree Audio Gateway", 0x1124: "Human Interface Device",
    0x112D: "SIM Access", 0x112F: "Phonebook Access", 0x1132: "Message Access",
    0x1134: "Message Notification", 0x1200: "PnP Information", 0x1203: "Generic Audio",
    0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x1802: "Immediate Alert",
    0x1803: "Link Loss", 0x1804: "Tx Power", 0x1805: "Current Time",
    0x180A: "Device Information", 0x180D: "Heart Rate", 0x180F: "Battery",
    0x1810: "Blood Pressure", 0x1812: "HID over GATT", 0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power", 0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing", 0x181C: "User Data", 0x181D: "Weight Scale",
    0x1826: "Fitness Machine", 0x1844: "Volume Control",
    0x1846: "Coordinated Set Identification", 0x184D: "Microphone Control",
    0x184E: "Audio Stream Control", 0x184F: "Broadcast Audio Scan",
    0x1850: "Published Audio Capabilities", 0xFD6F: "Exposure Notification",
    0xFE2C: "Google Fast Pair", 0xFE95: "Xiaomi", 0xFEAA: "Eddystone", 0xFEED: "Tile",
    0x2A00: "Device Name", 0x2A01: "Appearance",
    0x2A04: "Peripheral Preferred Connection Parameters", 0x2A05: "Service Changed",
    0x2A06: "Alert Level", 0x2A07: "Tx Power Level", 0x2A19: "Battery Level",
    0x2A23: "System ID", 0x2A24: "Model Number", 0x2A25: "Serial Number",
    0x2A26: "Firmware Revision", 0x2A27: "Hardware Revision", 0x2A28: "Software Revision",
    0x2A29: "Manufacturer Name", 0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location", 0x2A4A: "HID Information", 0x2A4B: "Report Map",
    0x2A4D: "Report", 0x2A50: "PnP ID", 0x2A6D: "Pressure", 0x2A6E: "Temperature",
    0x2A6F: "Humidity", 0x2B29: "Client Supported Features", 0x2B2A: "Database Hash",
}
#: Company identifiers (the key of BLE manufacturer data) -> company.
COMPANY_NAMES = {
    0x0000: "Ericsson", 0x0002: "Intel", 0x0006: "Microsoft", 0x000A: "Qualcomm",
    0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x001D: "Qualcomm",
    0x0030: "STMicroelectronics",
    0x0046: "MediaTek", 0x004C: "Apple", 0x0059: "Nordic Semiconductor", 0x0075: "Samsung",
    0x0087: "Garmin", 0x009E: "Bose", 0x00E0: "Google", 0x012D: "Sony", 0x0131: "Cypress",
    0x0157: "Huami", 0x0171: "Amazon", 0x01DA: "Logitech", 0x02E5: "Espressif",
    0x038F: "Xiaomi", 0x0499: "Ruuvi",
}
#: AdvertisingFlags bit: the device does not do BR/EDR (Classic).
_FLAG_BREDR_NOT_SUPPORTED = 0x04


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
        "org.bluez.Error.NotPermitted": tr("The device does not allow this (its "
                                           "characteristic is not readable or writable)."),
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


def device_kind(icon, device_class, appearance=None) -> str:
    """"Speaker", "Headset", "Phone", ... from an exact GAP Appearance (a
    BLE device's own word), BlueZ's Icon, the Appearance's category, else
    the Class of Device; "Device" when none says anything."""
    appearance = appearance if isinstance(appearance, int) and \
        not isinstance(appearance, bool) and appearance > 0 else None
    if appearance is not None and appearance in _APPEARANCE_KINDS:
        return _APPEARANCE_KINDS[appearance]
    kind = _ICON_KINDS.get(icon if isinstance(icon, str) else "")
    if kind:
        return kind
    if appearance is not None and (appearance >> 6) in _APPEARANCE_CATEGORIES:
        return _APPEARANCE_CATEGORIES[appearance >> 6]
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


def short_uuid(uuid) -> int | None:
    """The 16-bit number of a UUID on the Bluetooth base, else None."""
    text = str(uuid or "").strip().lower()
    if len(text) == 36 and text.startswith("0000") and text.endswith(_BASE_SUFFIX):
        try:
            return int(text[4:8], 16)
        except ValueError:
            return None
    return None


def uuid_name(uuid) -> str:
    """A service, profile or characteristic UUID by its name ("Audio Sink"),
    else as short as it gets ("0xFE9F", or the full UUID)."""
    number = short_uuid(uuid)
    if number is None:
        return str(uuid or "")
    return UUID_NAMES.get(number, f"0x{number:04X}")


def company_name(company: int) -> str:
    """The company of a manufacturer-data key: a short name for the common
    ones, else the Bluetooth SIG's list (core.bluetooth_vendor)."""
    from core.bluetooth_vendor import company_name as full_name

    return full_name(company) or tr("Company 0x{id:04X}").format(id=company)


def _bytes(value) -> bytes:
    value = normalise(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, int) and 0 <= value <= 255:
        return bytes([value])  # one 'y' byte
    if isinstance(value, list) and all(isinstance(v, int) and 0 <= v <= 255 for v in value):
        return bytes(value)
    return b""


def bearer(*, device_class: int = 0, address_type: str = "", uuids=(), appearance=None,
           tx_power=None, manufacturer_data=(), service_data=(), adv_flags=None) -> str:
    """"Classic", "LE" or "Dual" - what BlueZ's properties say about the
    radio a device was seen on; "" when they say nothing.

    Classic: a Class of Device, a BR/EDR profile (0x11xx-0x13xx). LE: a
    random address, advertising data (flags, appearance, TX power,
    manufacturer or service data), a GATT service. Generic Access and
    Generic Attribute are left out - BR/EDR devices list them too."""
    numbers = {n for n in (short_uuid(u) for u in uuids) if n is not None}
    if adv_flags is not None and adv_flags & _FLAG_BREDR_NOT_SUPPORTED:
        return "LE"
    classic = device_class > 0 or any(0x1100 <= n <= 0x13FF for n in numbers)
    le = (address_type == "random" or appearance is not None or tx_power is not None
          or bool(manufacturer_data) or bool(service_data) or adv_flags is not None
          or any((0x1802 <= n <= 0x18FF) or n >= 0xFD00 for n in numbers))
    if classic and le:
        return "Dual"
    return "Classic" if classic else "LE" if le else ""


#: Signal at 1 m when the device does not advertise its transmit power
#: (the usual calibration of a phone-sized BLE device).
DEFAULT_RSSI_AT_1M = -59
#: Free-space loss at 1 m on 2.4 GHz, plus a little for antennas and bodies:
#: the signal at 1 m of a device that advertises its TX power.
LOSS_AT_1M_DB = 41
#: Path-loss exponent: 2 is free space; rooms with walls and people are 2-4.
PATH_LOSS_EXPONENT = 2.2
#: Distances the estimate is held to (metres).
MIN_DISTANCE, MAX_DISTANCE = 0.1, 100.0
#: Weight of a new signal reading in the smoothed signal (the rest is the old one).
RSSI_SMOOTHING = 0.3
#: Signal readings kept per device (for its graph).
RSSI_HISTORY = 120


def estimate_distance(rssi, tx_power=None, exponent: float = PATH_LOSS_EXPONENT) -> float | None:
    """A rough distance in metres from a signal strength (log-distance
    path loss): the signal at 1 m is the advertised TX power minus
    LOSS_AT_1M_DB, or DEFAULT_RSSI_AT_1M without one. Walls, bodies and
    antennas make it a guess within a factor of two or three - good for
    "near" and "far", not for a tape measure. None without a signal."""
    if rssi is None or isinstance(rssi, bool) or not isinstance(rssi, (int, float)):
        return None
    if not -127 <= rssi <= 20:
        return None
    if isinstance(tx_power, (int, float)) and not isinstance(tx_power, bool) \
            and -127 <= tx_power <= 20:
        at_1m = tx_power - LOSS_AT_1M_DB
    else:
        at_1m = DEFAULT_RSSI_AT_1M
    distance = 10 ** ((at_1m - rssi) / (10 * max(1.0, exponent)))
    return min(MAX_DISTANCE, max(MIN_DISTANCE, distance))


def distance_text(metres: float | None) -> str:
    """"~0.5 m", "~3 m", "~25 m", "" - rounded as coarsely as the estimate is."""
    if metres is None or not math.isfinite(metres):
        return ""
    if metres < 1:
        return f"~{metres:.1f} m"
    if metres < 10:
        return f"~{metres:.0f} m"
    return f"~{round(metres / 5) * 5:.0f} m"


def discovery_filter(transport: str = "auto", rssi: int | None = None,
                     duplicate_data: bool = True) -> dict:
    """The argument of Adapter1.SetDiscoveryFilter. BlueZ checks the types:
    RSSI must be an int16 ('n') - a Python int would go out as 'i' - so
    it is a QVariant of a short."""
    if transport not in TRANSPORTS:
        raise ValueError(f"unknown transport {transport!r}")
    flt: dict = {"Transport": transport, "DuplicateData": bool(duplicate_data)}
    if rssi is not None:
        if isinstance(rssi, bool) or not isinstance(rssi, int) or not -127 <= rssi <= 20:
            raise ValueError(f"RSSI {rssi!r} is not between -127 and 20 dBm")
        value = QVariant(int(rssi))
        value.convert(QMetaType(QMetaType.Type.Short.value))
        flt["RSSI"] = value
    return flt


def normalise(value):
    """A value as QtDBus hands it to Python, as plain Python: a byte ('y',
    which arrives as one-byte ``bytes``) is a number, a byte array ('ay',
    a QByteArray) is ``bytes``, object paths and variants are unwrapped."""
    if isinstance(value, QByteArray):
        return bytes(value)
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


#: The longest name a device can tell (Bluetooth Core: 248 bytes).
MAX_NAME = 248


def device_text(value) -> str:
    """A name a device chose (Name, Alias) as it may be shown: without
    control and format characters - a newline, a NUL or a right-to-left
    override would forge or reorder the text around it in a dialog - and
    at most :data:`MAX_NAME` characters."""
    text = str(value or "")
    if not text.isprintable():
        text = " ".join("".join(ch if unicodedata.category(ch)[0] not in "CZ" else " "
                                for ch in text).split())
    return text[:MAX_NAME]


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
    address_type: str = ""
    appearance: int | None = None
    tx_power: int | None = None
    #: ((company id, data), ...) of the BLE advertisement
    manufacturer_data: tuple = ()
    #: ((service uuid, data), ...) of the BLE advertisement
    service_data: tuple = ()
    adv_flags: int | None = None
    bonded: bool = False
    legacy_pairing: bool = False
    services_resolved: bool = False
    #: time.time() the device was last heard (advertisement, signal), or None
    last_seen: float | None = None
    #: the signal smoothed over the last readings (steadier than rssi)
    rssi_smoothed: float | None = None

    @property
    def distance(self) -> float | None:
        """A rough distance in metres (estimate_distance), None without a
        signal - BlueZ reports one only while scanning."""
        if self.rssi is None:
            return None
        return estimate_distance(self.rssi_smoothed if self.rssi_smoothed is not None
                                 else self.rssi, self.tx_power)

    @property
    def display_name(self) -> str:
        return self.alias or self.name or self.address

    @property
    def named(self) -> bool:
        """True when the device told its name (BlueZ makes the alias of a
        nameless one from its address)."""
        return bool(self.name) or bool(self.alias and self.alias.replace("-", ":").upper()
                                       != self.address.upper())

    @property
    def kind(self) -> str:
        """From the appearance, icon or class; when they say nothing, what
        the advertisement implies (a beacon, a tracker, earbuds...)."""
        kind = device_kind(self.icon, self.device_class, self.appearance)
        if kind == "Device" and (self.manufacturer_data or self.service_data):
            from core.bluetooth_adv import kind_hint

            kind = kind_hint(self.idents) or kind
        return kind

    @property
    def idents(self) -> list:
        """What the advertisement says (core.bluetooth_adv.Ident list)."""
        from core.bluetooth_adv import device_identify

        return device_identify(self)

    @property
    def bearer(self) -> str:
        return bearer(device_class=self.device_class, address_type=self.address_type,
                      uuids=self.uuids, appearance=self.appearance, tx_power=self.tx_power,
                      manufacturer_data=self.manufacturer_data, service_data=self.service_data,
                      adv_flags=self.adv_flags)

    @property
    def vendor(self) -> str:
        """The company of the BLE manufacturer data, else the maker of a
        public address (its IEEE OUI, core.bluetooth_vendor); "" for a
        random address without manufacturer data."""
        if self.manufacturer_data:
            return ", ".join(dict.fromkeys(company_name(c) for c, _d in self.manufacturer_data))
        from core.bluetooth_vendor import address_vendor

        return address_vendor(self.address, self.address_type or "public")

    @property
    def services(self) -> list[str]:
        """The names of the services and profiles the device offers."""
        return [uuid_name(u) for u in self.uuids]

    @classmethod
    def from_props(cls, path: str, props: dict, battery: dict | None,
                   last_seen: float | None = None,
                   rssi_smoothed: float | None = None) -> Device:
        uuids = props.get("UUIDs") or ()
        mdata = normalise(props.get("ManufacturerData"))
        sdata = normalise(props.get("ServiceData"))
        flags = _bytes(props.get("AdvertisingFlags")) if "AdvertisingFlags" in props else None
        return cls(path=path, adapter=str(props.get("Adapter", path.rsplit("/", 1)[0])),
                   address=str(props.get("Address", "")),
                   name=device_text(props.get("Name", "")),
                   alias=device_text(props.get("Alias", "")), icon=str(props.get("Icon", "")),
                   device_class=_int_or_none(props.get("Class")) or 0,
                   rssi=_int_or_none(props.get("RSSI")),
                   paired=bool(props.get("Paired", False)),
                   trusted=bool(props.get("Trusted", False)),
                   connected=bool(props.get("Connected", False)),
                   blocked=bool(props.get("Blocked", False)),
                   uuids=tuple(str(u).lower() for u in uuids if isinstance(u, str)),
                   battery=_int_or_none((battery or {}).get("Percentage")),
                   address_type=str(props.get("AddressType", "")),
                   appearance=_int_or_none(props.get("Appearance")),
                   tx_power=_int_or_none(props.get("TxPower")),
                   manufacturer_data=tuple(sorted(
                       (int(k), _bytes(v)) for k, v in mdata.items()
                       if isinstance(k, int) and not isinstance(k, bool)))
                   if isinstance(mdata, dict) else (),
                   service_data=tuple(sorted((str(k).lower(), _bytes(v))
                                             for k, v in sdata.items()))
                   if isinstance(sdata, dict) else (),
                   adv_flags=flags[0] if flags else None,
                   bonded=bool(props.get("Bonded", False)),
                   legacy_pairing=bool(props.get("LegacyPairing", False)),
                   services_resolved=bool(props.get("ServicesResolved", False)),
                   last_seen=last_seen, rssi_smoothed=rssi_smoothed)


@dataclass(frozen=True)
class GattCharacteristic:
    path: str
    uuid: str
    flags: tuple
    #: the last value read or notified, None before
    value: bytes | None
    notifying: bool

    @property
    def name(self) -> str:
        return uuid_name(self.uuid)

    @property
    def readable(self) -> bool:
        return "read" in self.flags

    @property
    def notifiable(self) -> bool:
        return "notify" in self.flags or "indicate" in self.flags

    @property
    def value_text(self) -> str:
        return decode_value(self.uuid, self.value) if self.value is not None else ""


@dataclass(frozen=True)
class GattService:
    path: str
    uuid: str
    primary: bool
    characteristics: tuple

    @property
    def name(self) -> str:
        return uuid_name(self.uuid)


def _hex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def _sint(data: bytes, start: int, size: int) -> int:
    return int.from_bytes(data[start:start + size], "little", signed=True)


def decode_value(uuid, data: bytes) -> str:
    """A characteristic's value for people: the known GATT formats (names
    and revisions as text, battery level, appearance, heart rate,
    temperature, humidity, pressure), else text when it is printable, else
    hex."""
    data = bytes(data or b"")
    if not data:
        return tr("(empty)")
    number = short_uuid(uuid)
    try:
        if number in (0x2A00, 0x2A24, 0x2A25, 0x2A26, 0x2A27, 0x2A28, 0x2A29):
            return data.decode("utf-8", errors="replace").rstrip("\x00")
        if number == 0x2A19:
            return f"{data[0]} %"
        if number == 0x2A01 and len(data) >= 2:
            value = int.from_bytes(data[:2], "little")
            return f"{tr(device_kind('', 0, value))} (0x{value:04X})"
        if number == 0x2A07:
            return f"{_sint(data, 0, 1)} dBm"
        if number == 0x2A37 and len(data) >= 2:
            wide = data[0] & 0x01
            if wide and len(data) < 3:
                return _hex(data)
            bpm = int.from_bytes(data[1:3], "little") if wide else data[1]
            return tr("{bpm} bpm").format(bpm=bpm)
        if number == 0x2A6E and len(data) >= 2:
            return f"{_sint(data, 0, 2) / 100:.2f} °C"
        if number == 0x2A6F and len(data) >= 2:
            return f"{int.from_bytes(data[:2], 'little') / 100:.2f} %"
        if number == 0x2A6D and len(data) >= 4:
            return f"{int.from_bytes(data[:4], 'little') / 10 / 100:.1f} hPa"
    except (IndexError, ValueError):
        pass
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text and text.isprintable():
        return f"\"{text}\""
    return _hex(data)


def is_audio_output(device: Device) -> bool:
    """True for a device that takes sound (speaker, headset, headphones)."""
    return bool(AUDIO_SINK_UUIDS & set(device.uuids)) or device.icon in AUDIO_ICONS or \
        device.kind in AUDIO_KINDS


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
    """Qt's audio outputs (core.audio_route.qt_audio_outputs; here as well,
    where the Bluetooth window and the tests look it up)."""
    from core import audio_route

    return audio_route.qt_audio_outputs()


#: The BlueZ interfaces the client keeps.
_KEPT = (ADAPTER, DEVICE, BATTERY, GATT_SERVICE, GATT_CHARACTERISTIC)
_GATT = (GATT_SERVICE, GATT_CHARACTERISTIC)

#: Device properties that change only while the device is in range.
_HEARD_PROPS = frozenset({"RSSI", "TxPower", "ManufacturerData", "ServiceData",
                          "AdvertisingFlags", "AdvertisingData"})
#: Of those, the ones BlueZ holds only while the device is seen in a running
#: scan: it invalidates RSSI and TxPower when discovery stops, but keeps the
#: advertising data of a device it heard hours ago.
_LIVE_PROPS = frozenset({"RSSI", "TxPower"})


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
    #: display-passkey: how many digits were typed on the device so far
    entered: int | None = None

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
        self._client._agent_show("display-passkey", device, passkey=int(passkey),
                                 entered=int(entered))

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
    #: A device was heard now: a signal reading or advertising data came in
    #: (path). The presence log (core.bluetooth_presence) counts on it.
    device_heard = pyqtSignal(str)
    #: A device's GATT services or a characteristic's value changed
    #: (the device's path).
    gatt_changed = pyqtSignal(str)
    #: (path, op) - op: power, scan, stop-scan, pair, cancel-pairing,
    #: trust, connect, connect-profile, disconnect, disconnect-profile,
    #: remove; on a characteristic: read, notify, stop-notify.
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
        #: device path -> time.time() it was last heard (advertising, signal)
        self._seen: dict[str, float] = {}
        #: device path -> smoothed signal, and the recent readings (time, dBm)
        self._rssi_avg: dict[str, float] = {}
        self._rssi_log: dict[str, deque] = {}
        self._agent_path = f"/org/axross/bluetooth/agent{next(_agent_numbers)}"
        self._agent_host: QObject | None = None
        self._agent_registered = False
        self._agent_registering = False
        #: callbacks waiting for the agent registration to answer
        self._agent_waiters: list[Callable[[], None]] = []
        self._requests: dict[int, tuple[AgentRequest, QDBusMessage | None]] = {}
        #: devices whose Pair went out to BlueZ, and those canceled before it did
        self._pair_sent: set[str] = set()
        self._pair_canceled: set[str] = set()
        #: devices whose running Connect is dropped when it comes (drop_when_connected)
        self._drop_after_connect: set[str] = set()
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
            device = Device.from_props(path, ifaces[DEVICE], ifaces.get(BATTERY),
                                       self._seen.get(path), self._rssi_avg.get(path))
            if adapter is None or device.adapter == adapter:
                out.append(device)
        return out

    def device(self, path: str) -> Device | None:
        ifaces = self._objects.get(path, {})
        if DEVICE not in ifaces:
            return None
        return Device.from_props(path, ifaces[DEVICE], ifaces.get(BATTERY), self._seen.get(path),
                                 self._rssi_avg.get(path))

    def rssi_history(self, path: str) -> list[tuple[float, int]]:
        """The device's recent signal readings, oldest first: (time.time(), dBm)."""
        return list(self._rssi_log.get(path, ()))

    def busy(self, path: str) -> str | None:
        """The operation running on *path*, or None."""
        return self._busy.get(path)

    def scanning(self, adapter: str) -> bool:
        """True while *our* scan runs on *adapter*. BlueZ keeps one discovery
        per D-Bus client: ``Adapter.discovering`` is also true while another
        program scans, and StopDiscovery from us then fails with "No
        discovery started" - only a scan of ours can be stopped."""
        return adapter in self._scans

    def device_of(self, path: str) -> str | None:
        """The device a GATT service or characteristic belongs to."""
        while path and path != "/":
            if DEVICE in self._objects.get(path, {}):
                return path
            path = path.rsplit("/", 1)[0]
        return None

    def gatt_services(self, device: str) -> list[GattService]:
        """The GATT services BlueZ resolved for *device* (a connected BLE
        device), each with its characteristics, in handle order."""
        prefix = device.rstrip("/") + "/"
        chars: dict[str, list[GattCharacteristic]] = {}
        services = []
        for path, ifaces in sorted(self._objects.items()):
            if not path.startswith(prefix):
                continue
            if GATT_CHARACTERISTIC in ifaces:
                props = ifaces[GATT_CHARACTERISTIC]
                flags = normalise(props.get("Flags")) or []
                value = props.get("Value")
                chars.setdefault(str(normalise(props.get("Service", path.rsplit("/", 1)[0]))),
                                 []).append(GattCharacteristic(
                    path=path, uuid=str(props.get("UUID", "")).lower(),
                    flags=tuple(str(f) for f in flags if isinstance(f, str)),
                    value=_bytes(value) if value is not None else None,
                    notifying=bool(props.get("Notifying", False))))
            elif GATT_SERVICE in ifaces:
                services.append((path, ifaces[GATT_SERVICE]))
        return [GattService(path=path, uuid=str(props.get("UUID", "")).lower(),
                            primary=bool(props.get("Primary", True)),
                            characteristics=tuple(chars.get(path, ())))
                for path, props in services]

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
        self._seen = {}
        self._rssi_avg = {}
        self._rssi_log = {}
        if isinstance(objects, dict):
            for path, ifaces in objects.items():
                self._store(str(path), ifaces)
                self._heard(str(path), self._objects.get(str(path), {}).get(DEVICE), live=True)
        self._update_state()
        self.adapters_changed.emit()
        self.devices_changed.emit()

    def _gatt_changed(self, path: str) -> None:
        device = self.device_of(path)
        if device is not None:
            self.gatt_changed.emit(device)

    def _heard(self, path: str, props, *, live: bool = False) -> None:
        """Note *path* as heard now when *props* carry what only a device in
        range sends: a signal strength or advertising data. With *live* (a
        snapshot of everything BlueZ holds, not a change) only what BlueZ
        drops after a scan counts - kept advertising data may be old."""
        if not isinstance(props, dict):
            return
        now = time.time()
        heard = bool((_LIVE_PROPS if live else _HEARD_PROPS) & props.keys())
        if heard:
            self._seen[path] = now
        rssi = _int_or_none(props.get("RSSI"))
        if rssi is not None and -127 <= rssi <= 20:
            old = self._rssi_avg.get(path)
            self._rssi_avg[path] = float(rssi) if old is None else \
                old + RSSI_SMOOTHING * (rssi - old)
            self._rssi_log.setdefault(path, deque(maxlen=RSSI_HISTORY)).append((now, rssi))
        if heard:
            self.device_heard.emit(path)

    def _store(self, path: str, ifaces) -> bool:
        """Keep the BlueZ interfaces of *path*; True when it is an adapter or
        a device (or the battery of one)."""
        if not isinstance(ifaces, dict):
            return False
        wanted = {k: dict(v) for k, v in ifaces.items()
                  if k in _KEPT and isinstance(v, dict)}
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
            self._added(normalise(args[0]), normalise(args[1]))
        except Exception:  # noqa: BLE001 - a slot never raises
            log.exception("handling InterfacesAdded failed")

    def _added(self, path, ifaces) -> None:
        """Objects BlueZ (or another transport: core.bluetooth_direct) added."""
        if not isinstance(path, str) or not self._store(path, ifaces):
            return
        if ADAPTER in ifaces:
            self._update_state()
            self.adapters_changed.emit()
        if DEVICE in ifaces:
            self._heard(path, ifaces[DEVICE])
            self.devices_changed.emit()
        elif BATTERY in ifaces:
            self.device_updated.emit(path)
        elif any(i in ifaces for i in _GATT):
            self._gatt_changed(path)

    @pyqtSlot(QDBusMessage)
    def _on_interfaces_removed(self, message: QDBusMessage) -> None:
        try:
            if self._shut:
                return
            args = message.arguments()
            if len(args) < 2:
                return
            self._removed(normalise(args[0]), normalise(args[1]))
        except Exception:  # noqa: BLE001
            log.exception("handling InterfacesRemoved failed")

    def _removed(self, path, gone) -> None:
        """Interfaces *gone* of *path* went away."""
        if not isinstance(path, str) or not isinstance(gone, list) or path not in self._objects:
            return
        ifaces = self._objects[path]
        device = self.device_of(path) if any(i in gone for i in _GATT) else None
        for name in gone:
            ifaces.pop(name, None)
        if not any(i in ifaces for i in (DEVICE, ADAPTER, *_GATT)):
            del self._objects[path]
            self._seen.pop(path, None)
            self._rssi_avg.pop(path, None)
            self._rssi_log.pop(path, None)
        if device is not None:
            self.gatt_changed.emit(device)
        if ADAPTER in gone:
            self._scans.discard(path)
            self._update_state()
            self.adapters_changed.emit()
        if DEVICE in gone:
            # its GATT objects go with it (BlueZ removes them first; be sure)
            for child in [p for p in self._objects if p.startswith(path + "/")]:
                del self._objects[child]
            self.devices_changed.emit()
        elif BATTERY in gone:
            self.device_updated.emit(path)

    @pyqtSlot(QDBusMessage)
    def _on_properties_changed(self, message: QDBusMessage) -> None:
        try:
            if self._shut:
                return
            args = message.arguments()
            if len(args) < 2:
                return
            self._changed(message.path(), normalise(args[0]), normalise(args[1]),
                          normalise(args[2]) if len(args) > 2 else [])
        except Exception:  # noqa: BLE001
            log.exception("handling PropertiesChanged failed")

    def _changed(self, path: str, iface, changed, invalidated=()) -> None:
        """Properties of *path*'s interface *iface* changed or went."""
        props = self._objects.get(path, {}).get(iface)
        if props is None or not isinstance(changed, dict):
            return
        props.update(changed)
        for name in invalidated if isinstance(invalidated, (list, tuple)) else ():
            props.pop(name, None)
            if name == "RSSI" and iface == DEVICE:
                self._rssi_avg.pop(path, None)  # the next scan starts afresh
        if iface == ADAPTER:
            if "Discovering" in changed and not changed["Discovering"]:
                self._scans.discard(path)
            self.adapters_changed.emit()
        elif iface in _GATT:
            self._gatt_changed(path)
        else:
            if iface == DEVICE:
                self._heard(path, changed)
            self.device_updated.emit(path)

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

    def _transport_ok(self) -> bool:
        """Whether calls can go out (the D-Bus here; a stick in a subclass)."""
        return self._bus is not None

    def _finish_later(self, path: str, op: str, text: str) -> None:
        QTimer.singleShot(0, lambda: self.operation_finished.emit(path, op, text))

    def _begin(self, path: str, op: str, needs: str,
               on_success: Callable[[], None] | None = None):
        """Claim *path* for *op*: one operation per object at a time. Returns
        ``done(error, args)`` that ends it with operation_finished, or None
        when it is refused (said through operation_finished)."""
        if self._shut or not self._transport_ok() or self._state not in ("ready", "no-adapter"):
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

    def start_discovery(self, adapter: str, *, transport: str = "auto",
                        rssi: int | None = None, duplicate_data: bool = True) -> None:
        """Scan with a filter: *transport* (TRANSPORTS) picks Classic, LE or
        both; *rssi* hides devices weaker than that many dBm; with
        *duplicate_data* every advertisement updates the signal (a live
        map) instead of the first only. A filter the user did not ask for
        (both radios, any signal) that BlueZ refuses does not stop the scan."""
        flt = discovery_filter(transport, rssi, duplicate_data)  # ValueError before anything runs
        done = self._begin(adapter, "scan", ADAPTER, lambda: self._scans.add(adapter))
        if done is None:
            return
        set_filter = QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER,
                                                   "SetDiscoveryFilter")
        set_filter.setArguments([flt])
        start = QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER, "StartDiscovery")
        asked = transport != "auto" or rssi is not None

        def filtered(error, _args) -> None:
            if error is not None:
                if asked:
                    done(error, [])
                    return
                log.info("BlueZ refused the discovery filter, scanning without: %s %s", *error)
            self._async(start, CALL_TIMEOUT_MS, done)

        self._async(set_filter, CALL_TIMEOUT_MS, filtered)

    def stop_discovery(self, adapter: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER, "StopDiscovery")
        self._operation(adapter, "stop-scan", msg, needs=ADAPTER,
                        on_success=lambda: self._scans.discard(adapter))

    def set_trusted(self, device: str, on: bool) -> None:
        self._set_property(device, DEVICE, "Trusted", on, "trust", DEVICE)

    def connect_device(self, device: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "Connect")
        done = self._begin(device, "connect", DEVICE)
        if done is None:
            return

        def connected(error, args) -> None:
            drop = device in self._drop_after_connect
            self._drop_after_connect.discard(device)
            done(error, args)
            if drop and error is None:
                self.disconnect_device(device)

        self._async(msg, CONNECT_TIMEOUT_MS, connected)

    def drop_when_connected(self, device: str) -> bool:
        """The Connect of *device* under way is not kept: once it ends, a
        connection it made is disconnected - one shot, held by the client,
        so it holds after whoever asked (Add Device's dialog) is gone.
        False when no Connect of *device* is running."""
        if self._busy.get(device) != "connect":
            return False
        self._drop_after_connect.add(device)
        return True

    def connect_profile(self, device: str, uuid: str) -> None:
        """Connect one profile of *device* (Device1.ConnectProfile) - the
        headset profile with its microphone, say, next to A2DP."""
        msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "ConnectProfile")
        msg.setArguments([str(uuid)])
        self._operation(device, "connect-profile", msg, CONNECT_TIMEOUT_MS)

    def disconnect_profile(self, device: str, uuid: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "DisconnectProfile")
        msg.setArguments([str(uuid)])
        self._operation(device, "disconnect-profile", msg)

    def disconnect_device(self, device: str) -> None:
        msg = QDBusMessage.createMethodCall(SERVICE, device, DEVICE, "Disconnect")
        self._operation(device, "disconnect", msg)

    def remove_device(self, device: str) -> None:
        props = self._objects.get(device, {}).get(DEVICE, {})
        adapter = str(props.get("Adapter") or device.rsplit("/", 1)[0])
        msg = QDBusMessage.createMethodCall(SERVICE, adapter, ADAPTER, "RemoveDevice")
        msg.setArguments([QDBusObjectPath(device)])
        self._operation(device, "remove", msg)

    def read_characteristic(self, path: str) -> None:
        """Read a GATT characteristic; the value lands in gatt_services()
        and gatt_changed says so (BlueZ sends no PropertiesChanged for a
        read value it already had)."""
        done = self._begin(path, "read", GATT_CHARACTERISTIC)
        if done is None:
            return
        msg = QDBusMessage.createMethodCall(SERVICE, path, GATT_CHARACTERISTIC, "ReadValue")
        msg.setArguments([{}])  # options a{sv}: none

        def read(error, args) -> None:
            if error is None:
                props = self._objects.get(path, {}).get(GATT_CHARACTERISTIC)
                if props is not None:
                    props["Value"] = _bytes(args[0]) if args else b""
            done(error, args)
            if error is None:
                self._gatt_changed(path)

        self._async(msg, CALL_TIMEOUT_MS, read)

    def set_notify(self, path: str, on: bool) -> None:
        """Start or stop notifications of a characteristic: each new value
        then arrives as gatt_changed (a heart rate, a sensor reading)."""
        msg = QDBusMessage.createMethodCall(SERVICE, path, GATT_CHARACTERISTIC,
                                            "StartNotify" if on else "StopNotify")
        self._operation(path, "notify" if on else "stop-notify", msg,
                        needs=GATT_CHARACTERISTIC)

    def cancel_pairing(self, device: str) -> None:
        """Ask BlueZ to stop a pairing of ours; the pairing itself then
        finishes with "canceled"."""
        if self._bus is None or self._shut:
            return
        if self._busy.get(device) == "pair" and device not in self._pair_sent:
            # still registering our agent: the Pair is not sent at all
            self._pair_canceled.add(device)
            self._finish_later(device, "cancel-pairing", "")
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
            self._pair_sent.discard(device)
            self._pair_canceled.discard(device)
            # a code shown for this pairing has served its purpose
            for token, (request, _msg) in list(self._requests.items()):
                if request.device_path == device and not request.needs_answer:
                    del self._requests[token]
            done(error, args)
            if "pair" not in self._busy.values():
                self._unregister_agent()

        def send_pair() -> None:
            if self._shut or device in self._pair_canceled:
                finished(("org.bluez.Error.AuthenticationCanceled", ""), [])
                return
            self._pair_sent.add(device)
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
        """A code to show (display-*; no answer). BlueZ calls DisplayPasskey
        again for every digit typed on the device: a code already shown for
        the same device keeps its token, so the panel updates that dialog
        instead of opening one more per call."""
        try:
            path = normalise(device)
            token = next((t for t, (shown, _m) in self._requests.items()
                          if shown.kind == kind and shown.device_path == path), None)
            if token is None:
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


__all__ = ["AGENT_CAPABILITY", "AUDIO_KINDS", "AUDIO_SINK_UUIDS", "Adapter", "AgentRequest",
           "BEARERS", "BluezClient", "COMPANY_NAMES", "Device", "GattCharacteristic",
           "GattService", "KINDS", "SinkWaiter", "TRANSPORTS", "UUID_NAMES", "bearer",
           "company_name", "decode_value", "device_kind", "discovery_filter", "distance_text",
           "error_text", "estimate_distance", "find_sink", "is_audio_output", "normalise",
           "qt_audio_outputs", "set_audio_output", "short_uuid", "uuid_name"]
