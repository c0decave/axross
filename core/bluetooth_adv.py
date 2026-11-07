"""What a BLE advertisement says a device is.

BlueZ hands over the advertisement's manufacturer data (company id ->
bytes) and service data (UUID -> bytes) undecoded. Many devices say more
there than in their name: a beacon its ids, a tracker that it is one, a
phone which Apple or Microsoft feature it offers, a sensor its readings.
:func:`identify` reads the published formats:

* Apple (company 0x004C): iBeacon, and the Continuity messages - AirDrop,
  AirPods & Beats pairing (with the model), AirPlay, Handoff, Instant
  Hotspot, Nearby, *Find My* (an accessory away from its owner says so).
* Microsoft (0x0006): Swift Pair (a device in pairing mode, with its name)
  and the Connected Devices Platform beacon (Windows, Xbox, ...).
* Google Fast Pair (service 0xFE2C, with the model id), Eddystone
  (0xFEAA: UID, URL, TLM telemetry, EID), AltBeacon (0xBEAC in any
  company's data), Exposure Notification (0xFD6F).
* Trackers (kind "Tag"): Tile (0xFEED, 0xFEEC), Samsung SmartTag (0xFD5A), Chipolo
  (0xFE33), Find My.
* Sensors: Ruuvi (0x0499, format 5), BTHome v2 (0xFCD2, unencrypted),
  Xiaomi MiBeacon (0xFE95, the product id).

Pure functions (no Qt, no D-Bus): the bytes in, :class:`Ident` out. A
field that does not fit its format is skipped, not guessed at - the data
comes from whoever is in radio range.
"""

from __future__ import annotations

import struct
import uuid as _uuid
from dataclasses import dataclass

from core.i18n import tr

APPLE = 0x004C
MICROSOFT = 0x0006
RUUVI = 0x0499


@dataclass(frozen=True)
class Ident:
    """One thing an advertisement says."""

    #: what it is: "iBeacon", "AirPods Pro", "Find My", "Eddystone TLM" ...
    name: str
    #: its fields as text ("major 1, minor 2, -59 dBm at 1 m"), "" without
    detail: str = ""
    #: a device kind it implies (core.bluetooth.KINDS words), "" for none
    kind: str = ""

    def text(self) -> str:
        return f"{self.name}: {self.detail}" if self.detail else self.name


def _short(uuid) -> int | None:
    from core.bluetooth import short_uuid

    return short_uuid(uuid)


def _s8(value: int) -> int:
    return value - 256 if value > 127 else value


# -- Apple ------------------------------------------------------------------------------------

#: Continuity message types (the first byte of each TLV in Apple's data).
APPLE_TYPES = {0x01: "Apple (hidden)", 0x03: "AirPrint", 0x05: "AirDrop", 0x06: "HomeKit",
               0x07: "AirPods / Beats", 0x08: "Hey Siri", 0x09: "AirPlay target",
               0x0A: "AirPlay source", 0x0B: "Magic Switch", 0x0C: "Handoff",
               0x0D: "Wi-Fi settings", 0x0E: "Instant Hotspot", 0x0F: "Nearby Action",
               0x10: "Apple Nearby", 0x12: "Find My"}
#: Proximity pairing (type 0x07): the model, bytes 1-2 of the message.
APPLE_AUDIO_MODELS = {0x0220: "AirPods", 0x0F20: "AirPods (2nd generation)",
                      0x1320: "AirPods (3rd generation)", 0x1920: "AirPods (4th generation)",
                      0x0E20: "AirPods Pro", 0x1420: "AirPods Pro (2nd generation)",
                      0x2420: "AirPods Pro (2nd generation, USB-C)", 0x0A20: "AirPods Max",
                      0x0320: "Powerbeats3", 0x0B20: "Powerbeats Pro", 0x0C20: "Beats Solo Pro",
                      0x0520: "BeatsX", 0x0620: "Beats Solo3", 0x0920: "Beats Studio3",
                      0x1020: "Beats Flex", 0x1120: "Beats Studio Buds", 0x1220: "Beats Fit Pro",
                      0x1620: "Beats Studio Buds+", 0x1720: "Beats Studio Pro",
                      0x1D20: "Beats Pill"}


def _audio_kind(model: str) -> str:
    if model == "Beats Pill":
        return "Speaker"
    if "Max" in model or "Solo" in model or "Studio3" in model or "Studio Pro" in model:
        return "Headphones"
    return "Earbuds"


def _apple(data: bytes) -> list[Ident]:
    out: list[Ident] = []
    i = 0
    while i + 2 <= len(data):
        kind, length = data[i], data[i + 1]
        body = data[i + 2:i + 2 + length]
        if len(body) < length:
            break
        i += 2 + length
        if kind == 0x02 and length == 0x15:  # iBeacon
            beacon = _uuid.UUID(bytes=bytes(body[:16]))
            major, minor = struct.unpack(">HH", body[16:20])
            out.append(Ident("iBeacon", tr("{uuid}, major {major}, minor {minor}, "
                                           "{tx} dBm at 1 m").format(
                uuid=beacon, major=major, minor=minor, tx=_s8(body[20])), "Beacon"))
        elif kind == 0x07 and length >= 3:
            model = struct.unpack(">H", body[1:3])[0]
            name = APPLE_AUDIO_MODELS.get(model)
            out.append(Ident(name or tr("AirPods / Beats"),
                             "" if name else tr("model 0x{m:04X}").format(m=model),
                             _audio_kind(name or "")))
        elif kind == 0x12:  # Find My: offline finding
            if length >= 0x19:
                out.append(Ident(tr("Find My"), tr("separated from its owner"), "Tag"))
            else:
                out.append(Ident(tr("Find My"), tr("near its owner")))
        elif kind in APPLE_TYPES:
            out.append(Ident(tr(APPLE_TYPES[kind])))
    return out


# -- Microsoft ----------------------------------------------------------------------------------

#: Connected Devices Platform beacon: the device type (low 6 bits of byte 1).
CDP_DEVICES = {1: ("Xbox One", "Game Console"), 6: ("Apple iPhone", "Phone"),
               7: ("Apple iPad", "Tablet"), 8: ("Android device", "Phone"),
               9: ("Windows desktop", "Computer"), 11: ("Windows phone", "Phone"),
               12: ("Linux device", "Computer"), 13: ("Windows IoT", ""),
               14: ("Surface Hub", "Computer"), 15: ("Windows laptop", "Computer"),
               16: ("Windows tablet", "Tablet")}


def _microsoft(data: bytes) -> list[Ident]:
    if len(data) >= 3 and data[0] == 0x03 and data[1] in (0x00, 0x01, 0x02):
        name = ""
        if data[1] == 0x00:  # LE only: a reserved RSSI byte, then the name
            name = data[3:].decode("utf-8", "replace").strip("\x00")
        elif data[1] in (0x01, 0x02) and len(data) > 9:  # + BR/EDR address, class
            name = data[9:].decode("utf-8", "replace").strip("\x00")
        from core.bluetooth import device_text

        return [Ident(tr("Swift Pair"), tr("ready to pair") + (f", {device_text(name)}"
                                                                if name.strip() else ""))]
    if len(data) >= 2 and data[0] == 0x01:
        name, kind = CDP_DEVICES.get(data[1] & 0x3F, ("", ""))
        return [Ident(tr("Microsoft CDP"), tr(name) if name else "", kind)]
    return []


# -- Eddystone, AltBeacon, Fast Pair, sensors -------------------------------------------------

_URL_SCHEMES = ("http://www.", "https://www.", "http://", "https://")
_URL_CODES = (".com/", ".org/", ".edu/", ".net/", ".info/", ".biz/", ".gov/",
              ".com", ".org", ".edu", ".net", ".info", ".biz", ".gov")


def eddystone_url(body: bytes) -> str:
    """The URL of an Eddystone-URL frame's scheme + encoded bytes."""
    if not body or body[0] >= len(_URL_SCHEMES):
        return ""
    out = [_URL_SCHEMES[body[0]]]
    for b in body[1:]:
        if b < len(_URL_CODES):
            out.append(_URL_CODES[b])
        elif 0x21 <= b <= 0x7E:
            out.append(chr(b))
        else:
            return ""
    return "".join(out)


def _eddystone(data: bytes) -> list[Ident]:
    if not data:
        return []
    frame = data[0]
    if frame == 0x00 and len(data) >= 18:
        return [Ident("Eddystone UID", tr("namespace {ns}, instance {inst}, {tx} dBm at "
                                          "0 m").format(ns=data[2:12].hex(),
                                                        inst=data[12:18].hex(),
                                                        tx=_s8(data[1])), "Beacon")]
    if frame == 0x10 and len(data) >= 3:
        url = eddystone_url(data[2:])
        return [Ident("Eddystone URL", url, "Beacon")] if url else []
    if frame == 0x20 and len(data) >= 14 and data[1] == 0x00:
        volts, temp, count, secs = struct.unpack(">HhII", data[2:14])
        parts = []
        if volts:
            parts.append(tr("battery {v:.2f} V").format(v=volts / 1000))
        if temp != -0x8000:
            parts.append(f"{temp / 256:.1f} °C")
        parts.append(tr("up {d}").format(d=_uptime(secs / 10)))
        return [Ident("Eddystone TLM", ", ".join(parts), "Beacon")]
    if frame in (0x30, 0x40):
        return [Ident("Eddystone EID", tr("ephemeral id"), "Beacon")]
    return []


def _uptime(seconds: float) -> str:
    from core.bluetooth_presence import duration_text

    return duration_text(seconds)


def _altbeacon(data: bytes) -> list[Ident]:
    if len(data) >= 24 and data[0] == 0xBE and data[1] == 0xAC:
        return [Ident("AltBeacon", tr("id {id}, {tx} dBm at 1 m").format(
            id=data[2:22].hex(), tx=_s8(data[22])), "Beacon")]
    return []


def _fast_pair(data: bytes) -> list[Ident]:
    if len(data) == 3:
        return [Ident(tr("Google Fast Pair"), tr("ready to pair, model {m}").format(
            m=data.hex().upper()))]
    return [Ident(tr("Google Fast Pair"), tr("paired before"))]


def _ruuvi(data: bytes) -> list[Ident]:
    if len(data) >= 18 and data[0] == 5:
        temp, hum, press = struct.unpack(">hHH", data[1:7])
        power = struct.unpack(">H", data[13:15])[0]
        parts = []
        if temp != -0x8000:
            parts.append(f"{temp * 0.005:.2f} °C")
        if hum != 0xFFFF:
            parts.append(f"{hum * 0.0025:.1f} %")
        if press != 0xFFFF:
            parts.append(f"{(press + 50000) / 100:.1f} hPa")
        if power >> 5 != 0x7FF:
            parts.append(tr("battery {v:.2f} V").format(v=((power >> 5) + 1600) / 1000))
        return [Ident("RuuviTag", ", ".join(parts), "Sensor")]
    return []


#: BTHome v2 objects: id -> (name, bytes, signed, factor, unit).
_BTHOME = {0x00: ("packet", 1, False, 1, ""), 0x01: ("battery", 1, False, 1, " %"),
           0x02: ("temperature", 2, True, 0.01, " °C"), 0x03: ("humidity", 2, False, 0.01, " %"),
           0x04: ("pressure", 3, False, 0.01, " hPa"), 0x05: ("illuminance", 3, False, 0.01,
                                                               " lx"),
           0x0C: ("voltage", 2, False, 0.001, " V"), 0x12: ("CO2", 2, False, 1, " ppm"),
           0x2E: ("humidity", 1, False, 1, " %"), 0x45: ("temperature", 2, True, 0.1, " °C")}


def _bthome(data: bytes) -> list[Ident]:
    if not data:
        return []
    info = data[0]
    if info >> 5 != 2:
        return []
    if info & 0x01:
        return [Ident("BTHome", tr("encrypted"), "Sensor")]
    parts, i = [], 1
    while i < len(data):
        spec = _BTHOME.get(data[i])
        if spec is None:
            break  # an unknown object's size is unknown: stop there
        name, size, signed, factor, unit = spec
        raw = data[i + 1:i + 1 + size]
        if len(raw) < size:
            break
        i += 1 + size
        if name == "packet":
            continue
        value = int.from_bytes(raw, "little", signed=signed) * factor
        text = f"{value:.2f}".rstrip("0").rstrip(".") if factor < 1 else str(int(value))
        parts.append(f"{tr(name)} {text}{unit}")
    return [Ident("BTHome", ", ".join(parts), "Sensor")]


def _mibeacon(data: bytes) -> list[Ident]:
    if len(data) >= 4:
        product = struct.unpack("<H", data[2:4])[0]
        return [Ident("Xiaomi MiBeacon", tr("product 0x{p:04X}").format(p=product))]
    return []


#: Service UUID (16-bit) -> what its service data or presence says.
SERVICE_DECODERS = {0xFEAA: _eddystone, 0xFE2C: _fast_pair, 0xFCD2: _bthome,
                    0xFE95: _mibeacon}
#: 16-bit service UUIDs whose presence alone says what a device is.
SERVICE_IDENTS = {0xFEED: Ident("Tile", "", "Tag"), 0xFEEC: Ident("Tile", "", "Tag"),
                  0xFD5A: Ident("Samsung SmartTag", "", "Tag"),
                  0xFE33: Ident("Chipolo", "", "Tag"),
                  0xFD6F: Ident("Exposure Notification", "", "Phone"),
                  0xFE9F: Ident("Google", "", ""),
                  0x1812: Ident("HID over GATT", "", "")}


def identify(manufacturer_data=(), service_data=(), uuids=()) -> list[Ident]:
    """What the advertisement says, in order, without repeats.
    *manufacturer_data*: ((company id, bytes), ...); *service_data*:
    ((uuid, bytes), ...); *uuids*: the advertised service UUIDs."""
    out: list[Ident] = []
    for company, data in manufacturer_data:
        data = bytes(data)
        if company == APPLE:
            out += _apple(data)
        elif company == MICROSOFT:
            out += _microsoft(data)
        elif company == RUUVI:
            out += _ruuvi(data)
        out += _altbeacon(data)
    for uuid, data in service_data:
        decoder = SERVICE_DECODERS.get(_short(uuid))
        if decoder is not None:
            out += decoder(bytes(data))
    for uuid in (*uuids, *(u for u, _d in service_data)):
        ident = SERVICE_IDENTS.get(_short(uuid))
        if ident is not None:
            out.append(ident)
    return list(dict.fromkeys(out))


def device_identify(device) -> list[Ident]:
    """:func:`identify` of a core.bluetooth.Device."""
    return identify(device.manufacturer_data, device.service_data, device.uuids)


def kind_hint(idents) -> str:
    """The first device kind the advertisement implies, "" for none."""
    return next((i.kind for i in idents if i.kind), "")


# -- Class of Device ----------------------------------------------------------------------------

#: Major service classes (bits 13-23 of the Class of Device).
SERVICE_CLASSES = ((13, "Limited discoverable"), (14, "LE Audio"), (16, "Positioning"),
                   (17, "Networking"), (18, "Rendering"), (19, "Capturing"),
                   (20, "Object transfer"), (21, "Audio"), (22, "Telephony"),
                   (23, "Information"))
MAJOR_CLASSES = ("Miscellaneous", "Computer", "Phone", "Network access point",
                 "Audio / video", "Peripheral", "Imaging", "Wearable", "Toy", "Health")


def class_text(device_class: int) -> str:
    """"Audio / video; services: Rendering, Audio" for a Class of Device."""
    if not device_class:
        return ""
    major = (device_class >> 8) & 0x1F
    words = [tr(MAJOR_CLASSES[major]) if major < len(MAJOR_CLASSES)
             else tr("Uncategorized") if major == 0x1F else f"0x{major:02X}"]
    services = [tr(name) for bit, name in SERVICE_CLASSES if device_class >> bit & 1]
    if services:
        words.append(tr("services: {names}").format(names=", ".join(services)))
    return "; ".join(words)


__all__ = ["APPLE_AUDIO_MODELS", "APPLE_TYPES", "CDP_DEVICES", "Ident", "class_text",
           "device_identify", "eddystone_url", "identify", "kind_hint"]
