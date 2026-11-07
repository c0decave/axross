"""What a BLE advertisement says a device is (core.bluetooth_adv).

The request: scanning, identification and connection to all sorts of
Bluetooth / BLE hardware and software. Many devices say what they are
only in their advertisement's manufacturer or service data: beacons
(iBeacon, Eddystone, AltBeacon), trackers (Find My, Tile, SmartTag),
Apple's Continuity messages (AirPods with the model, AirDrop, Handoff),
Microsoft Swift Pair and the CDP beacon, Google Fast Pair, sensors
(Ruuvi, BTHome). The payloads below are laid out per the published
formats; a payload that does not fit is skipped, not guessed at.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import bluetooth as BT  # noqa: E402
from core import bluetooth_adv as BA  # noqa: E402

SVC = "0000{:04x}-0000-1000-8000-00805f9b34fb"


def names(idents):
    return [i.name for i in idents]


def test_happy_ibeacon():
    body = bytes.fromhex("e2c56db5dffb48d2b060d0f5a71096e0") + struct.pack(">HHb", 1, 2, -59)
    [ident] = BA.identify([(BA.APPLE, bytes([0x02, 0x15]) + body)])
    assert ident.name == "iBeacon" and ident.kind == "Beacon"
    assert ident.detail == ("e2c56db5-dffb-48d2-b060-d0f5a71096e0, major 1, minor 2, "
                            "-59 dBm at 1 m")


def test_happy_apple_continuity_messages():
    airpods = bytes([0x07, 0x05, 0x01, 0x0E, 0x20, 0x55, 0xAA])
    find_my = bytes([0x12, 0x19]) + bytes(0x19)
    handoff = bytes([0x0C, 0x02, 0x00, 0x00])
    out = BA.identify([(BA.APPLE, airpods + find_my + handoff)])
    assert names(out) == ["AirPods Pro", "Find My", "Handoff"]
    assert out[0].kind == "Earbuds" and out[1].kind == "Tag"
    assert out[1].detail == "separated from its owner"


def test_edge_apple_unknown_model_and_owner_nearby():
    out = BA.identify([(BA.APPLE, bytes([0x07, 0x03, 0x01, 0x77, 0x77, 0x12, 0x02, 0, 0]))])
    assert out[0].name == "AirPods / Beats" and out[0].detail == "model 0x7777"
    assert out[1].name == "Find My" and out[1].kind == ""


def test_sad_a_truncated_apple_message_is_skipped():
    # the length says 0x19 but only one byte follows (and an iBeacon too short)
    assert BA.identify([(BA.APPLE, bytes([0x12, 0x19, 0x10]))]) == []
    assert BA.identify([(BA.APPLE, bytes([0x02, 0x15, 1, 2, 3]))]) == []


def test_happy_microsoft_swift_pair_and_cdp():
    [swift] = BA.identify([(BA.MICROSOFT, bytes([0x03, 0x00, 0x80]) + b"Surface Pen")])
    assert swift.name == "Swift Pair" and swift.detail == "ready to pair, Surface Pen"
    [cdp] = BA.identify([(BA.MICROSOFT, bytes([0x01, 0x09, 0x20, 0x00]))])
    assert (cdp.name, cdp.detail, cdp.kind) == ("Microsoft CDP", "Windows desktop", "Computer")


def test_sad_a_swift_pair_name_is_plain_text():
    [swift] = BA.identify([(BA.MICROSOFT, bytes([0x03, 0x00, 0x80]) + b"Pen\nfake\x1b[31m")])
    assert "\n" not in swift.detail and "\x1b" not in swift.detail


def test_happy_eddystone_frames():
    uid = bytes([0x00, 0xEE]) + bytes(range(10)) + bytes(range(6))
    url = bytes([0x10, 0xEE, 0x03]) + b"example" + bytes([0x07])
    tlm = bytes([0x20, 0x00]) + struct.pack(">HhII", 3000, 22 * 256 + 128, 10, 36000)
    out = BA.identify(service_data=[(SVC.format(0xFEAA), uid), (SVC.format(0xFEAA), url),
                                    (SVC.format(0xFEAA), tlm)])
    assert names(out) == ["Eddystone UID", "Eddystone URL", "Eddystone TLM"]
    assert "namespace 00010203040506070809, instance 000102030405, -18 dBm" in out[0].detail
    assert out[1].detail == "https://example.com"
    assert out[2].detail == "battery 3.00 V, 22.5 °C, up 1 h 00 min"


def test_sad_an_eddystone_url_with_a_control_byte_is_dropped():
    assert BA.eddystone_url(bytes([0x03]) + b"ex\x0aample") == "https://ex.netample"
    assert BA.eddystone_url(bytes([0x09]) + b"x") == ""
    assert BA.eddystone_url(bytes([0x02]) + b"a\x01b\x80") == ""


def test_happy_altbeacon_in_any_companys_data():
    data = bytes([0xBE, 0xAC]) + bytes(20) + bytes([0xC5, 0x00])
    [ident] = BA.identify([(0x0118, data)])
    assert ident.name == "AltBeacon" and ident.detail.endswith("-59 dBm at 1 m")


def test_happy_fast_pair_and_trackers():
    out = BA.identify(service_data=[(SVC.format(0xFE2C), bytes([0x2C, 0x40, 0x1A]))],
                      uuids=[SVC.format(0xFEED)])
    assert [i.text() for i in out] == ["Google Fast Pair: ready to pair, model 2C401A", "Tile"]
    assert BA.kind_hint(out) == "Tag"
    [tag] = BA.identify(service_data=[(SVC.format(0xFD5A), b"\x10\x00")])
    assert tag.name == "Samsung SmartTag"


def test_happy_ruuvi_format_5():
    data = bytes([5]) + struct.pack(">hHH", 4800, 20000, 51325) + bytes(6) + \
        struct.pack(">H", (1400 << 5) | 0x10) + bytes(9)
    [ident] = BA.identify([(BA.RUUVI, data)])
    assert ident.detail == "24.00 °C, 50.0 %, 1013.2 hPa, battery 3.00 V"
    assert ident.kind == "Sensor"


def test_happy_bthome_v2():
    data = bytes([0x40, 0x00, 0x07, 0x01, 0x61, 0x02]) + struct.pack("<h", 2312) + \
        bytes([0x03]) + struct.pack("<H", 4550)
    [ident] = BA.identify(service_data=[(SVC.format(0xFCD2), data)])
    assert ident.detail == "battery 97 %, temperature 23.12 °C, humidity 45.5 %"


def test_edge_bthome_stops_at_an_unknown_object_and_says_encrypted():
    [ident] = BA.identify(service_data=[(SVC.format(0xFCD2), bytes([0x40, 0x01, 0x50, 0xEE,
                                                                     0x02, 0, 0]))])
    assert ident.detail == "battery 80 %"
    [enc] = BA.identify(service_data=[(SVC.format(0xFCD2), bytes([0x41, 1, 2, 3]))])
    assert enc.detail == "encrypted"
    assert BA.identify(service_data=[(SVC.format(0xFCD2), bytes([0x20, 0x01, 0x50]))]) == []


def test_edge_nothing_known_says_nothing():
    assert BA.identify([(0x1234, b"\x00\x01")], [(SVC.format(0x1234), b"")], []) == []
    assert BA.identify([(BA.APPLE, b"")]) == []


def test_happy_the_device_kind_comes_from_the_advertisement_when_nothing_else_says():
    props = {"Address": "D4:11:22:33:44:55", "AddressType": "random",
             "ManufacturerData": {0x004C: [0x12, 0x19, *bytes(0x19)]}, "Adapter": "/org/bluez/hci0"}
    device = BT.Device.from_props("/org/bluez/hci0/dev_D4_11_22_33_44_55", props, None)
    assert device.kind == "Tag"
    assert names(device.idents) == ["Find My"]
    # an appearance wins over the advertisement
    props["Appearance"] = 0x00C1
    assert BT.Device.from_props("/p", props, None).kind == "Watch"


def test_happy_class_of_device_text():
    assert BA.class_text(0x240414) == "Audio / video; services: Rendering, Audio"
    assert BA.class_text(0x001F00) == "Uncategorized"
    assert BA.class_text(0) == ""
