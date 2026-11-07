"""Bluetooth without BlueZ: a USB stick driven directly through Bumble.

core.bluetooth.BluezClient talks to BlueZ over the system D-Bus - Linux
with bluetoothd only. :class:`DirectClient` is the same client (same
signals, same reading methods, same devices and GATT tree, so the whole
panel works on it) with Bumble (``pip install bumble``; the
``bluetooth-raw`` extra) and libusb in place of the D-Bus: it runs on
Linux without bluetoothd, on Windows and on macOS, with a USB Bluetooth
stick of its own.

* The stick is opened through a Bumble transport name (``usb:0``,
  ``usb:0A12:0001``; :func:`list_sticks` lists them). While axross holds
  it, the operating system's Bluetooth stack does not have it: libusb
  detaches its driver and gives the stick back when axross lets go.
  Windows needs the WinUSB driver on the stick (Zadig); macOS hands out
  external sticks only.
* What BlueZ does is done here, with BlueZ's semantics where the panel
  depends on them: scanning as a discovery filter says (LE scan and/or
  Classic inquiry, a minimum signal), devices from advertisements and
  inquiry results, RSSI and TX power dropped when the scan ends,
  connections (LE with GATT discovery, Classic), GATT reads and
  notifications, pairing with the panel's questions (confirm a number,
  type a passkey or PIN - never answered without the user), bonds kept
  in a 0600 key file and known again at the next start.
* Not here: audio (no sound server behind it - "Use as Audio Output" is
  BlueZ's), single profiles (ConnectProfile).

Bumble runs on a thread of its own with its asyncio loop; everything it
reports is handed to the GUI thread and applied through BluezClient's own
_added / _changed / _removed, as BlueZ's signals are.
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import threading
from pathlib import Path
from typing import Callable

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal

from core import bluetooth as BT
from core.i18n import tr

log = logging.getLogger(__name__)

ADAPTER_PATH = "/org/bluez/hci0"
BASE_UUID = "-0000-1000-8000-00805f9b34fb"
CONNECT_TIMEOUT_S = 20.0
KEYS_FILE = "bluetooth-direct-keys.json"
KEYS_VARIABLE = "AXROSS_BT_DIRECT_KEYS"
#: The Class of Device the stick says it is: a computer (laptop).
OWN_CLASS = 0x6C010C
#: Seconds an LE pairing may take (the Security Manager's own limit: 30 s
#: per step; Bumble has none).
PAIR_TIMEOUT_S = 60.0
#: A device that is neither paired nor connected is forgotten this long
#: after it was last heard, as BlueZ's TemporaryTimeout (30 s) does.
TEMPORARY_TIMEOUT_S = 30.0
FORGET_SWEEP_MS = 10_000


def available() -> bool:
    """Whether Bumble is installed (the bluetooth-raw extra)."""
    import importlib.util

    return importlib.util.find_spec("bumble") is not None


# -- what Bumble says, as BlueZ properties ----------------------------------------------------

def uuid16(value: int) -> str:
    return f"{value:08x}{BASE_UUID}"


def uuid_text(raw: bytes) -> str:
    """A UUID as BlueZ writes it, from its little-endian bytes (2, 4 or 16)."""
    raw = bytes(raw)
    if len(raw) == 2:
        return uuid16(struct.unpack("<H", raw)[0])
    if len(raw) == 4:
        return f"{struct.unpack('<I', raw)[0]:08x}{BASE_UUID}"
    h = raw[::-1].hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def adv_props(structures) -> dict:
    """Device1 properties from advertising (or EIR) structures [(type, bytes)]."""
    props: dict = {}
    uuids: list[str] = []
    for kind, data in structures:
        kind, data = int(kind), bytes(data)
        if kind == 0x01 and data:
            props["AdvertisingFlags"] = bytes(data[:1])
        elif kind in (0x08, 0x09):
            name = BT.device_text(data.decode("utf-8", "replace").rstrip("\x00"))
            if kind == 0x09 or "Name" not in props:
                props["Name"] = props["Alias"] = name
        elif kind == 0x0A and data:
            props["TxPower"] = struct.unpack("<b", data[:1])[0]
        elif kind == 0x19 and len(data) >= 2:
            props["Appearance"] = struct.unpack("<H", data[:2])[0]
        elif kind == 0x0D and len(data) >= 3:
            props["Class"] = int.from_bytes(data[:3], "little")
        elif kind == 0xFF and len(data) >= 2:
            company = struct.unpack("<H", data[:2])[0]
            props.setdefault("ManufacturerData", {})[company] = bytes(data[2:])
        elif kind in (0x16, 0x20, 0x21):
            size = {0x16: 2, 0x20: 4, 0x21: 16}[kind]
            if len(data) >= size:
                props.setdefault("ServiceData", {})[uuid_text(data[:size])] = bytes(data[size:])
        elif kind in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
            size = {0x02: 2, 0x03: 2, 0x04: 4, 0x05: 4, 0x06: 16, 0x07: 16}[kind]
            uuids += [uuid_text(data[i:i + size]) for i in range(0, len(data) - size + 1, size)]
    if uuids:
        props["UUIDs"] = list(dict.fromkeys(uuids))
    return props


def gatt_flags(properties: int) -> list[str]:
    names = ((0x01, "broadcast"), (0x02, "read"), (0x04, "write-without-response"),
             (0x08, "write"), (0x10, "notify"), (0x20, "indicate"),
             (0x40, "authenticated-signed-writes"))
    return [name for bit, name in names if properties & bit]


def device_path(address: str) -> str:
    return f"{ADAPTER_PATH}/dev_{address.upper().replace(':', '_')}"


def keys_path() -> Path:
    from core.secure_storage import data_file_path

    return data_file_path(KEYS_FILE, KEYS_VARIABLE)


def _is_hci(dev) -> bool:
    """Bumble's own test (bumble/transport/usb.py): class E0/01/01 on the
    device, or on an interface of a "per interface" / composite device."""
    hci = (0xE0, 0x01, 0x01)
    if (dev.getDeviceClass(), dev.getDeviceSubClass(), dev.getDeviceProtocol()) == hci:
        return True
    if dev.getDeviceClass() not in (0x00, 0xEF):
        return False
    for config in dev:
        for interface in config:
            for setting in interface:
                if (setting.getClass(), setting.getSubClass(), setting.getProtocol()) == hci:
                    return True
    return False


def list_sticks() -> list[dict]:
    """The USB Bluetooth controllers libusb sees: {"transport", "name",
    "vid", "pid", "bus", "address", "serial"}; [] without Bumble or libusb.
    The transport names the stick itself, not its place in the list
    ("usb:0A12:0001/SERIAL", else "usb:0A12:0001#n" among sticks of that
    kind): after a replug the saved choice still means the same stick, or
    none - never another adapter."""
    try:
        import usb1
    except ImportError:
        return []
    out = []
    seen: dict[tuple, int] = {}
    try:
        with usb1.USBContext() as context:
            for dev in context.getDeviceIterator(skip_on_error=True):
                try:
                    if not _is_hci(dev):
                        continue
                except usb1.USBError:
                    continue
                vid, pid = dev.getVendorID(), dev.getProductID()
                n = seen.get((vid, pid), 0)
                seen[(vid, pid)] = n + 1
                serial = ""
                try:
                    serial = dev.getSerialNumber() or ""
                except usb1.USBError:  # the descriptor needs the device opened
                    pass
                ident = f"{vid:04X}:{pid:04X}"
                safe_serial = serial if serial.isascii() and serial.isalnum() else ""
                transport = f"usb:{ident}/{safe_serial}" if safe_serial else f"usb:{ident}#{n}"
                maker = _usb_maker(vid)
                out.append({"transport": transport, "vid": vid, "pid": pid, "serial": serial,
                            "bus": dev.getBusNumber(), "address": dev.getDeviceAddress(),
                            "name": f"{maker} {ident}" if maker else ident})
    except Exception:  # noqa: BLE001 - no libusb backend, no permission: no sticks
        log.info("listing USB Bluetooth sticks failed", exc_info=True)
    return out


_USB_MAKERS = {0x0A12: "CSR / Qualcomm", 0x8087: "Intel", 0x0BDA: "Realtek",
               0x0A5C: "Broadcom", 0x0E8D: "MediaTek", 0x0CF3: "Qualcomm Atheros",
               0x13D3: "IMC Networks", 0x2357: "TP-Link", 0x0B05: "ASUS", 0x1915: "Nordic"}


def _usb_maker(vid: int) -> str:
    return _USB_MAKERS.get(vid, "")


# -- the client --------------------------------------------------------------------------------

class _ToGui(QObject):
    """Hands callables from the radio thread to the GUI thread."""

    call = pyqtSignal(object)


class DirectClient(BT.BluezClient):
    """BluezClient with a USB stick through Bumble instead of BlueZ.

    *transport*: a Bumble transport name (``usb:0``). *opener*: a seam for
    the tests - ``async opener() -> (hci_source, hci_sink, close)``, a
    virtual controller instead of a stick. *keys*: the bond file (None:
    :func:`keys_path`)."""

    def __init__(self, transport: str = "usb:0", *, opener=None, keys: Path | None = None,
                 address: str | None = None, parent: QObject | None = None) -> None:
        super().__init__(bus=None, parent=parent)
        self.transport = transport
        self._opener = opener
        self._keys_file = Path(keys) if keys is not None else None
        self._own_address = address
        self._to_gui = _ToGui()
        self._to_gui.call.connect(lambda fn: fn(), Qt.ConnectionType.QueuedConnection)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._device = None  # bumble.device.Device
        self._close: Callable | None = None
        self._radio_ready = False
        #: device path -> bumble Address, Connection, characteristic proxy
        self._addresses: dict = {}
        self._links: dict = {}
        self._proxies: dict = {}
        #: the merged discovery filter while we scan: transport, rssi
        self._filter: dict = {}
        self._scanning = {"le": False, "bredr": False}
        #: token -> (AgentRequest, concurrent future the radio thread waits on)
        self._direct_requests: dict = {}
        #: addresses we asked to pair with: only those pairings are accepted
        self._pair_wanted: set[str] = set()
        #: device path -> the concurrent future of its running pairing
        self._pairings: dict = {}
        self._forget = QTimer(self)
        self._forget.setInterval(FORGET_SWEEP_MS)
        self._forget.timeout.connect(self.forget_stale)

    # -- start and stop --------------------------------------------------------------------

    def _transport_ok(self) -> bool:
        return self._radio_ready

    def state_text(self) -> str:
        if self._state == "unavailable":
            return tr("The Bluetooth stick {stick} cannot be used: {detail}").format(
                stick=self.transport, detail=self._state_detail or "?")
        if self._state == "loading":
            return tr("Opening the Bluetooth stick {stick}…").format(stick=self.transport)
        return super().state_text()

    def start(self) -> None:
        if self._started or self._shut:
            return
        self._started = True
        self._set_state("loading")
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name="bt-direct", daemon=True)
        self._thread.start()
        self._radio(self._open(), self._opened)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _gui(self, fn: Callable, *args) -> None:
        """Run fn(*args) on the GUI thread (from the radio thread)."""
        self._to_gui.call.emit(lambda: None if self._shut else fn(*args))

    def _radio(self, coro, done: Callable | None = None) -> None:
        """Run *coro* on the radio thread; done(result, error) on the GUI one."""
        if self._loop is None or self._loop.is_closed():
            coro.close()
            if done is not None:
                QTimer.singleShot(0, lambda: done(None, RuntimeError("closed")))
            return
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        if done is None:
            return future

        def finished(f) -> None:
            if f.cancelled():
                error, result = RuntimeError("canceled"), None
            else:
                error = f.exception()
                result = None if error is not None else f.result()
            self._to_gui.call.emit(lambda: done(result, error))

        future.add_done_callback(finished)
        return future

    async def _open(self):
        from bumble.device import Device, DeviceConfiguration

        if self._opener is not None:
            source, sink, close = await self._opener()
        else:
            from bumble.transport import open_transport

            transport = await open_transport(self.transport)
            source, sink, close = transport.source, transport.sink, transport.close
        self._close = close
        if self._shut:  # shut down while the stick was being opened: give it back
            await _maybe_await(close())
            raise RuntimeError("closed")
        config = DeviceConfiguration(name="axross", classic_enabled=True, le_enabled=True)
        config.class_of_device = OWN_CLASS
        # not visible, not connectable, no Classic connection accepted unasked:
        # axross starts every connection itself (Bumble's defaults are open)
        config.discoverable = False
        config.connectable = False
        config.classic_accept_any = False
        if self._own_address:
            from bumble.hci import Address

            config.address = Address(self._own_address)
        device = Device.from_config_with_hci(config, source, sink)
        device.pairing_config_factory = self._pairing_config
        device.on("advertisement", lambda adv: self._gui(self._advertised, adv))
        device.on("inquiry_result", lambda address, cod, data, rssi: self._gui(
            self._inquired, address, cod, data, rssi))
        await device.power_on()
        self._device = device
        address = str(device.public_address).split("/")[0]
        if address in ("00:00:00:00:00:00", ""):
            address = str(device.random_address).split("/")[0]
        # the bonds of each stick apart (its address), in one 0600 file; the
        # address resolver is built again from it (power_on built it empty)
        device.keystore = _PrivateKeyStore(address, str(self._keys_file or keys_path()))
        bonds = []
        try:
            bonds = [name for name, _keys in await device.keystore.get_all()]
            await device.refresh_resolving_list()
        except Exception:  # noqa: BLE001 - an unreadable key file is no bonds
            log.warning("the Bluetooth key file cannot be read", exc_info=True)
        return address, bonds

    def _opened(self, result, error) -> None:
        if error is not None:
            log.warning("opening the Bluetooth stick %s failed: %r", self.transport, error)
            self._state_detail = str(error) or type(error).__name__
            self._set_state("unavailable")
            return
        address, bonds = result
        self._radio_ready = True
        self._added(ADAPTER_PATH, {BT.ADAPTER: {
            "Address": address, "AddressType": "public", "Name": "axross", "Alias": "axross",
            "Class": OWN_CLASS, "Powered": True, "PowerState": "on", "Discoverable": False,
            "DiscoverableTimeout": 0, "Pairable": True, "Discovering": False, "UUIDs": []}})
        for name in bonds:  # the bonded devices, known again
            # Bumble names a bond "ADDRESS/P" (public) or "ADDRESS" (random)
            text, _sep, kind = name.partition("/")
            text = text.upper()
            if BT.device_text(text) == text and len(text) == 17:
                self._added(device_path(text), {BT.DEVICE: self._new_device(text, {
                    "Paired": True, "Bonded": True, "Trusted": True,
                    "AddressType": "public" if kind.upper().startswith("P") else "random"})})
        self._update_state()
        self._forget.start()

    def shutdown(self) -> None:
        if self._shut:
            return
        self._shut = True
        self._forget.stop()
        for token in list(self._direct_requests):
            self._answer_future(token, None)
        loop = self._loop
        if loop is None or loop.is_closed():
            return

        async def close():
            device = self._device
            try:
                if device is not None:
                    for conn in list(device.connections.values()):
                        try:
                            await asyncio.wait_for(conn.disconnect(), 3)
                        except Exception:  # noqa: BLE001 - going anyway
                            pass
                    await asyncio.wait_for(device.power_off(), 3)
            except Exception:  # noqa: BLE001
                pass
            if self._close is not None:
                try:
                    result = self._close()
                    if asyncio.iscoroutine(result):
                        await asyncio.wait_for(result, 3)
                except Exception:  # noqa: BLE001
                    pass

        try:
            asyncio.run_coroutine_threadsafe(close(), loop).result(8)
        except Exception:  # noqa: BLE001 - the stick goes back when the process ends anyway
            log.info("closing the Bluetooth stick took too long", exc_info=True)
        loop.call_soon_threadsafe(loop.stop)
        if self._thread is not None:
            self._thread.join(5)
        self._radio_ready = False

    # -- devices ---------------------------------------------------------------------------

    def _new_device(self, address: str, props: dict) -> dict:
        base = {"Address": address, "AddressType": "public",
                "Alias": address.replace(":", "-"), "Paired": False, "Bonded": False,
                "Trusted": False, "Blocked": False, "Connected": False,
                "ServicesResolved": False, "LegacyPairing": False, "UUIDs": [],
                "Adapter": ADAPTER_PATH}
        base.update(props)
        return base

    def forget_stale(self, now: float | None = None) -> None:
        """As BlueZ: a device neither paired, trusted nor connected goes
        TEMPORARY_TIMEOUT_S after it was last heard (phones change their
        random address every few minutes; they would pile up)."""
        import time

        now = time.time() if now is None else now
        for path, ifaces in list(self._objects.items()):
            props = ifaces.get(BT.DEVICE)
            if props is None or self._busy.get(path) is not None or path in self._links:
                continue
            if props.get("Paired") or props.get("Trusted") or props.get("Connected"):
                continue
            seen = self._seen.get(path)
            if seen is not None and now - seen < TEMPORARY_TIMEOUT_S:
                continue
            if seen is None and "RSSI" in props:
                continue  # heard, the time of it not noted yet
            self._removed(path, list(ifaces))
            self._addresses.pop(path, None)

    def _passes(self, radio: str, props: dict) -> bool:
        transport = self._filter.get("transport", "auto")
        if transport not in ("auto", radio):
            return False
        rssi = props.get("RSSI")
        return self._filter.get("rssi") is None or rssi is None or rssi >= self._filter["rssi"]

    def _note_device(self, address, props: dict, radio: str) -> None:
        text = str(address).split("/")[0].upper()
        path = device_path(text)
        if path in self._objects:
            self._addresses[path] = address
            self._changed(path, BT.DEVICE, props)
        elif self._passes(radio, props):
            self._addresses[path] = address
            self._added(path, {BT.DEVICE: self._new_device(text, props)})

    def _advertised(self, adv) -> None:
        if not self._scanning["le"]:
            return
        props = adv_props(adv.data.ad_structures)
        props["AddressType"] = "random" if int(adv.address.address_type) in (1, 3) else "public"
        if adv.rssi != adv.RSSI_NOT_AVAILABLE:
            props["RSSI"] = int(adv.rssi)
        self._note_device(adv.address, props, "le")

    def _inquired(self, address, class_of_device, data, rssi) -> None:
        if not self._scanning["bredr"]:
            return
        props = adv_props(data.ad_structures if data is not None else ())
        props["Class"] = int(class_of_device)
        if rssi is not None:
            props["RSSI"] = int(rssi)
        self._note_device(address, props, "bredr")

    # -- operations ------------------------------------------------------------------------

    @staticmethod
    def _error(error, name: str = "org.bluez.Error.Failed"):
        """BluezClient's done() error tuple from an exception."""
        if error is None:
            return None
        text = str(error) or type(error).__name__
        if "TIMEOUT" in text.upper() or isinstance(error, asyncio.TimeoutError):
            return ("org.bluez.Error.Failed", tr("No answer from the device (out of range?)"))
        return (name, text[:300])

    def set_powered(self, adapter: str, on: bool) -> None:
        done = self._begin(adapter, "power", BT.ADAPTER)
        if done is None:
            return

        async def power():
            if on:
                await self._device.power_on()
            else:
                await self._stop_radio_scans()
                for conn in list(self._device.connections.values()):
                    await conn.disconnect()
                await self._device.power_off()

        def finished(_result, error) -> None:
            if error is None:
                if not on:
                    self._scans.discard(adapter)
                    self._discovery_ended()
                self._changed(adapter, BT.ADAPTER, {"Powered": on,
                                                    "PowerState": "on" if on else "off"})
            done(self._error(error), [])

        self._radio(power(), finished)

    def start_discovery(self, adapter: str, *, transport: str = "auto",
                        rssi: int | None = None, duplicate_data: bool = True) -> None:
        BT.discovery_filter(transport, rssi, duplicate_data)  # ValueError as BlueZ's client
        done = self._begin(adapter, "scan", BT.ADAPTER)
        if done is None:
            return
        if not self.adapter(adapter).powered:
            done(("org.bluez.Error.NotReady", ""), [])
            return
        self._filter = {"transport": transport, "rssi": rssi}
        wanted = {"le", "bredr"} if transport == "auto" else {transport}

        async def scan():
            if "le" in wanted:
                await self._device.start_scanning(legacy=True, active=True,
                                                  filter_duplicates=not duplicate_data)
            if "bredr" in wanted:
                try:
                    await self._device.start_discovery(auto_restart=True)
                except Exception:  # noqa: BLE001 - an LE-only controller: LE goes on
                    if "le" not in wanted:
                        raise
                    wanted.discard("bredr")

        def finished(_result, error) -> None:
            if error is None:
                self._scanning = {"le": "le" in wanted, "bredr": "bredr" in wanted}
                self._scans.add(adapter)
                self._changed(adapter, BT.ADAPTER, {"Discovering": True})
            done(self._error(error), [])

        self._radio(scan(), finished)

    async def _stop_radio_scans(self) -> None:
        if self._scanning["le"]:
            await self._device.stop_scanning()
        if self._scanning["bredr"]:
            await self._device.stop_discovery()

    def stop_discovery(self, adapter: str) -> None:
        done = self._begin(adapter, "stop-scan", BT.ADAPTER)
        if done is None:
            return

        def finished(_result, error) -> None:
            self._scans.discard(adapter)
            self._discovery_ended()
            done(self._error(error), [])

        self._radio(self._stop_radio_scans(), finished)

    def _discovery_ended(self) -> None:
        """As BlueZ: Discovering false, every device's RSSI and TxPower gone."""
        self._scanning = {"le": False, "bredr": False}
        self._changed(ADAPTER_PATH, BT.ADAPTER, {"Discovering": False})
        for path, ifaces in list(self._objects.items()):
            props = ifaces.get(BT.DEVICE)
            if props is None:
                continue
            gone = [k for k in ("RSSI", "TxPower") if k in props]
            if gone:
                self._changed(path, BT.DEVICE, {}, gone)

    def set_trusted(self, device: str, on: bool) -> None:
        done = self._begin(device, "trust", BT.DEVICE)
        if done is not None:
            self._changed(device, BT.DEVICE, {"Trusted": bool(on)})
            QTimer.singleShot(0, lambda: done(None, []))

    def _is_le(self, path: str) -> bool:
        props = self._objects[path][BT.DEVICE]
        return props.get("AddressType") == "random" or "Class" not in props

    def _address_of(self, path: str):
        address = self._addresses.get(path)
        if address is None:
            from bumble.hci import Address

            props = self._objects[path][BT.DEVICE]
            kind = Address.RANDOM_DEVICE_ADDRESS if props.get("AddressType") == "random" \
                else Address.PUBLIC_DEVICE_ADDRESS
            address = Address(props["Address"], kind)
        return address

    def connect_device(self, device: str) -> None:
        done = self._begin(device, "connect", BT.DEVICE)
        if done is None:
            return
        if self._objects[device][BT.DEVICE].get("Connected"):
            done(("org.bluez.Error.AlreadyConnected", ""), [])
            return
        from bumble.core import BT_BR_EDR_TRANSPORT, BT_LE_TRANSPORT

        le = self._is_le(device)
        address = self._address_of(device)

        async def connect():
            paused = le and self._scanning["le"]
            if paused:  # many controllers cannot scan and connect at once
                await self._device.stop_scanning()
            try:
                conn = await self._device.connect(
                    address, transport=BT_LE_TRANSPORT if le else BT_BR_EDR_TRANSPORT,
                    timeout=CONNECT_TIMEOUT_S)
            finally:
                if paused and self._scanning["le"]:  # the scan goes on, as BlueZ's does
                    await self._device.start_scanning(legacy=True, active=True,
                                                      filter_duplicates=False)
            conn.on("disconnection", lambda _reason: self._gui(self._dropped, device))
            services = []
            if le:
                from bumble.device import Peer

                try:
                    peer = Peer(conn)
                    await peer.discover_services()
                    for svc in peer.services:
                        await svc.discover_characteristics()
                except BaseException:
                    await _quietly(conn.disconnect())  # no link left up, unseen
                    raise
                services = list(peer.services)
            return conn, services

        def finished(result, error) -> None:
            drop = device in self._drop_after_connect
            self._drop_after_connect.discard(device)
            if error is None and device not in self._objects:  # removed meanwhile
                self._radio(_quietly(result[0].disconnect()))
            if error is not None or device not in self._objects:
                done(self._error(error) or ("org.bluez.Error.Failed", "device went away"), [])
                return
            conn, services = result
            self._links[device] = conn
            self._changed(device, BT.DEVICE, {"Connected": True})
            self._add_gatt(device, services)
            self._changed(device, BT.DEVICE, {"ServicesResolved": True})
            done(None, [])
            if drop:
                self.disconnect_device(device)

        self._radio(connect(), finished)

    def _add_gatt(self, device: str, services) -> None:
        for svc in services:
            spath = f"{device}/service{svc.handle:04x}"
            self._added(spath, {BT.GATT_SERVICE: {"UUID": uuid_text(svc.uuid.uuid_bytes),
                                                  "Primary": True, "Device": device}})
            for char in svc.characteristics:
                cpath = f"{spath}/char{char.handle:04x}"
                self._proxies[cpath] = char
                self._added(cpath, {BT.GATT_CHARACTERISTIC: {
                    "UUID": uuid_text(char.uuid.uuid_bytes), "Service": spath,
                    "Flags": gatt_flags(int(char.properties)), "Notifying": False}})

    def _dropped(self, device: str) -> None:
        self._links.pop(device, None)
        for cpath in [p for p in self._proxies if p.startswith(device + "/")]:
            del self._proxies[cpath]
        if device not in self._objects:
            return
        self._changed(device, BT.DEVICE, {"ServicesResolved": False})
        for child in sorted((p for p in self._objects if p.startswith(device + "/")),
                            reverse=True):
            self._removed(child, list(self._objects[child]))
        self._changed(device, BT.DEVICE, {"Connected": False})

    def disconnect_device(self, device: str) -> None:
        done = self._begin(device, "disconnect", BT.DEVICE)
        if done is None:
            return
        conn = self._links.get(device)
        if conn is None:
            done(("org.bluez.Error.NotConnected", ""), [])
            return

        def finished(_result, error) -> None:
            self._dropped(device)
            done(self._error(error), [])

        self._radio(conn.disconnect(), finished)

    def connect_profile(self, device: str, uuid: str) -> None:
        self._unsupported(device, "connect-profile")

    def disconnect_profile(self, device: str, uuid: str) -> None:
        self._unsupported(device, "disconnect-profile")

    def _unsupported(self, path: str, op: str) -> None:
        done = self._begin(path, op, BT.DEVICE)
        if done is not None:
            QTimer.singleShot(0, lambda: done(("org.bluez.Error.NotSupported", tr(
                "Single profiles need BlueZ; a stick used directly has no audio profiles.")),
                []))

    def remove_device(self, device: str) -> None:
        done = self._begin(device, "remove", BT.DEVICE)
        if done is None:
            return
        address = self._objects[device][BT.DEVICE].get("Address", "")
        conn = self._links.get(device)

        async def remove():
            if conn is not None:
                await conn.disconnect()
            store = self._device.keystore
            # Bumble names a bond "ADDRESS/P" (public) or "ADDRESS" (random)
            for name, _keys in await store.get_all():
                if name.split("/")[0].upper() == address.upper():
                    await store.delete(name)

        def finished(_result, error) -> None:
            done(None, [])  # the busy mark goes before the object does
            if device in self._objects:
                for child in sorted((p for p in self._objects if p.startswith(device + "/")),
                                    reverse=True):
                    self._removed(child, list(self._objects[child]))
                self._removed(device, list(self._objects[device]))
            self._addresses.pop(device, None)
            self._links.pop(device, None)

        self._radio(remove(), finished)

    def read_characteristic(self, path: str) -> None:
        done = self._begin(path, "read", BT.GATT_CHARACTERISTIC)
        if done is None:
            return
        proxy = self._proxies.get(path)
        if proxy is None or "read" not in self._objects[path][BT.GATT_CHARACTERISTIC]["Flags"]:
            done(("org.bluez.Error.NotPermitted", ""), [])
            return

        def finished(value, error) -> None:
            if error is None:
                props = self._objects.get(path, {}).get(BT.GATT_CHARACTERISTIC)
                if props is not None:
                    props["Value"] = bytes(value)
            done(self._error(error), [])
            if error is None:
                self._gatt_changed(path)

        self._radio(proxy.read_value(), finished)

    def set_notify(self, path: str, on: bool) -> None:
        op = "notify" if on else "stop-notify"
        done = self._begin(path, op, BT.GATT_CHARACTERISTIC)
        if done is None:
            return
        proxy = self._proxies.get(path)
        flags = self._objects[path][BT.GATT_CHARACTERISTIC]["Flags"]
        if proxy is None or (on and not {"notify", "indicate"} & set(flags)):
            done(("org.bluez.Error.NotSupported", ""), [])
            return

        def value(data) -> None:
            self._gui(lambda: path in self._objects and self._changed(
                path, BT.GATT_CHARACTERISTIC, {"Value": bytes(data)}))

        def finished(_result, error) -> None:
            if error is None:
                self._changed(path, BT.GATT_CHARACTERISTIC, {"Notifying": on})
            done(self._error(error), [])

        self._radio(proxy.subscribe(value) if on else proxy.unsubscribe(), finished)

    # -- pairing ---------------------------------------------------------------------------

    def _pairing_config(self, connection):
        from bumble.pairing import PairingConfig

        return PairingConfig(sc=True, mitm=True, bonding=True,
                             delegate=_Delegate(self, connection))

    def pair(self, device: str) -> None:
        done = self._begin(device, "pair", BT.DEVICE)
        if done is None:
            return
        if self._objects[device][BT.DEVICE].get("Paired"):
            done(("org.bluez.Error.AlreadyExists", ""), [])
            return
        from bumble.core import BT_BR_EDR_TRANSPORT, BT_LE_TRANSPORT

        le = self._is_le(device)
        address = self._address_of(device)
        conn = self._links.get(device)
        wanted = self._objects[device][BT.DEVICE]["Address"].upper()
        self._pair_wanted.add(wanted)

        async def pair():
            link = conn
            if link is None:  # BlueZ connects for a pairing too
                link = await self._device.connect(
                    address, transport=BT_LE_TRANSPORT if le else BT_BR_EDR_TRANSPORT,
                    timeout=CONNECT_TIMEOUT_S)
                link.on("disconnection", lambda _reason: self._gui(self._dropped, device))
                self._gui(self._linked, device, link)
            if le:
                await asyncio.wait_for(link.pair(), PAIR_TIMEOUT_S)
            else:
                await asyncio.wait_for(link.authenticate(), PAIR_TIMEOUT_S)
                await asyncio.wait_for(link.encrypt(), PAIR_TIMEOUT_S)
            return link

        def finished(_result, error) -> None:
            self._pair_wanted.discard(wanted)
            self._pairings.pop(device, None)
            for token, (request, _future) in list(self._direct_requests.items()):
                if request.device_path == device:
                    self._answer_future(token, None)  # the radio side stops waiting too
                    self.agent_cancelled.emit(token)
            if error is None and device in self._objects:
                self._changed(device, BT.DEVICE, {"Paired": True, "Bonded": True})
            done(None if error is None else self._error(
                error, "org.bluez.Error.AuthenticationFailed"), [])

        self._pairings[device] = self._radio(pair(), finished)

    def _linked(self, device: str, conn) -> None:
        if device in self._objects:
            self._links[device] = conn
            self._changed(device, BT.DEVICE, {"Connected": True})

    def cancel_pairing(self, device: str) -> None:
        """Stop a pairing of ours: its questions are rejected and the
        pairing itself is canceled (also one waiting for the device)."""
        for token, (request, future) in list(self._direct_requests.items()):
            if request.device_path == device:
                self._answer_future(token, None)
        running = self._pairings.get(device)
        if running is not None:
            running.cancel()
        self._finish_later(device, "cancel-pairing", "")

    def _ask(self, connection, kind: str, **extra):
        """From the radio thread: put a question to the user; a concurrent
        future with the answer (None: rejected or canceled)."""
        import concurrent.futures

        future: concurrent.futures.Future = concurrent.futures.Future()
        address = str(connection.peer_address).split("/")[0].upper()

        def ask() -> None:
            path = device_path(address)
            request = BT.AgentRequest(token=next(self._tokens), kind=kind, device_path=path,
                                      device_name=self._device_name(path), **extra)
            if request.needs_answer:
                self._direct_requests[request.token] = (request, future)
            else:
                future.set_result(True)
            self.agent_request.emit(request)

        self._gui(ask)
        return future

    def answer(self, token: int, accept: bool, value=None) -> None:
        entry = self._direct_requests.get(token)
        if entry is None:
            return
        request = entry[0]
        if not accept:
            self._answer_future(token, None)
        elif request.kind == "pin":
            pin = str(value or "")
            self._answer_future(token, pin if 1 <= len(pin) <= 16 else None)
        elif request.kind == "passkey":
            try:
                passkey = int(value)
            except (TypeError, ValueError):
                passkey = -1
            self._answer_future(token, passkey if 0 <= passkey <= 999_999 else None)
        else:
            self._answer_future(token, True)

    def _answer_future(self, token: int, value) -> None:
        entry = self._direct_requests.pop(token, None)
        if entry is not None and not entry[1].done():
            entry[1].set_result(value)


async def _maybe_await(result) -> None:
    if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
        await result


async def _quietly(coro) -> None:
    try:
        await asyncio.wait_for(coro, 5)
    except Exception:  # noqa: BLE001 - a link going down anyway
        pass


class _Delegate:
    """Bumble's pairing questions, put to the user through agent_request."""

    def __new__(cls, client: DirectClient, connection):
        from bumble.pairing import PairingDelegate

        class Delegate(PairingDelegate):
            def __init__(self) -> None:
                super().__init__(
                    io_capability=PairingDelegate.DISPLAY_OUTPUT_AND_KEYBOARD_INPUT)

            async def _wait(self, future):
                return await asyncio.wrap_future(future)

            def _ours(self) -> bool:
                """Only a pairing the user started (Pair) goes on; one a device
                nearby starts is refused without a question."""
                address = str(connection.peer_address).split("/")[0].upper()
                return address in client._pair_wanted

            async def accept(self) -> bool:
                return self._ours()

            async def confirm(self, auto: bool = False) -> bool:
                if not self._ours():
                    return False
                if auto:
                    return True  # "just works" of a pairing the user asked for
                return bool(await self._wait(client._ask(connection, "authorize")))

            async def compare_numbers(self, number: int, digits: int) -> bool:
                if not self._ours():
                    return False
                return bool(await self._wait(client._ask(connection, "confirm",
                                                          passkey=int(number))))

            async def get_number(self) -> int | None:
                if not self._ours():
                    return None
                return await self._wait(client._ask(connection, "passkey"))

            async def get_string(self, max_length: int) -> str | None:
                if not self._ours():
                    return None
                return await self._wait(client._ask(connection, "pin"))

            async def display_number(self, number: int, digits: int) -> None:
                client._ask(connection, "display-passkey", passkey=int(number))

        return Delegate()


def _private_key_store():
    from bumble.keys import JsonKeyStore

    class PrivateKeyStore(JsonKeyStore):
        """Bumble's JSON key file, written 0600 (it holds link keys)."""

        async def save(self, db) -> None:
            import json

            self.directory_name.mkdir(parents=True, exist_ok=True, mode=0o700)
            temp = self.filename.with_name(self.filename.name + ".tmp")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(db, output, sort_keys=True, indent=4)
            os.replace(temp, self.filename)

    return PrivateKeyStore


class _PrivateKeyStore:
    def __new__(cls, namespace, filename):
        return _private_key_store()(namespace, filename)


__all__ = ["ADAPTER_PATH", "DirectClient", "adv_props", "available", "device_path",
           "gatt_flags", "keys_path", "list_sticks", "uuid16", "uuid_text"]
