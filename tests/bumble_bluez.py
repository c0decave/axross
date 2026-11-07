"""``org.bluez`` on a private D-Bus, backed by a real Bluetooth stick.

The Bluetooth tests talk to tests/fake_bluez.py, which answers from a
script. This is the same D-Bus face (it is a FakeBluez: the same object
tree, signatures, errors and per-client discovery) with a radio behind
it: Bumble drives a USB stick through libusb, without the host's BlueZ.
It lets core.bluetooth.BluezClient - and the panel - scan, connect and
read GATT over the air, against a second stick playing the peer
(tests/bumble_peer.py).

    python tests/bumble_bluez.py usb:0      # DBUS_SESSION_BUS_ADDRESS set

What it does over the air (BlueZ 5 semantics where axross depends on them):

* ``StartDiscovery`` - an active LE scan and a Classic inquiry (as the
  filter's Transport says). Each advertisement adds or updates a Device1
  (Address, AddressType, Name/Alias, RSSI, TxPower, ManufacturerData,
  ServiceData, UUIDs, Appearance, AdvertisingFlags); an inquiry result
  adds Class, RSSI and the EIR name. When the last discovery ends, RSSI
  and TxPower are invalidated, as BlueZ does.
* ``Connect`` / ``Disconnect`` - an LE or BR/EDR link; on LE the GATT
  services and characteristics appear as GattService1 /
  GattCharacteristic1 objects, then ServicesResolved. A link the peer
  drops sets Connected false.
* ``ReadValue``, ``StartNotify`` / ``StopNotify`` on those characteristics.
* ``Pair`` - Bumble's pairing with "just works" (no agent questions yet).

``AXROSS_BT_SNOOP=<file>`` writes every HCI packet to a btsnoop file.

The test-control commands of FakeBluez (``add_device`` ...) still work, so
a test can mix scripted and real devices.
"""

from __future__ import annotations

import asyncio
import os
import queue
import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fake_bluez import ADAPTER, DEVICE, GATT_CHAR, GATT_SERVICE, FakeBluez  # noqa: E402

#: How often the D-Bus loop takes what the radio thread handed over (s).
DRAIN_S = 0.02
CONNECT_TIMEOUT_S = 20.0

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# the advertisement -> Device1 properties of axross's own direct mode
from core.bluetooth_direct import adv_props, gatt_flags, uuid16, uuid_text  # noqa: E402,F401


class BumbleBluez(FakeBluez):
    def __init__(self, transport: str, adapter: str = "hci0") -> None:
        super().__init__()
        self.transport_name = transport
        self.adapter_path = f"/org/bluez/{adapter}"
        self.inbox: queue.SimpleQueue = queue.SimpleQueue()
        self.loop = asyncio.new_event_loop()
        self.device = None  # bumble.device.Device
        #: device path -> bumble Connection
        self.links: dict = {}
        #: device path -> bumble Peer
        self.gatt_peers: dict = {}
        #: characteristic path -> bumble CharacteristicProxy
        self.proxies: dict = {}
        #: device path -> bumble Address (with its type)
        self.addresses: dict = {}
        self.scanning = {"le": False, "bredr": False}
        self.ready = threading.Event()
        self.start_error = ""
        threading.Thread(target=self._radio_thread, name="bumble", daemon=True).start()

    # -- the radio thread ---------------------------------------------------------------

    def _radio_thread(self) -> None:
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._open())
        except Exception as exc:  # noqa: BLE001 - said on stderr, the service quits
            self.start_error = repr(exc)
            self.ready.set()
            return
        self.ready.set()
        self.loop.run_forever()

    async def _open(self) -> None:
        from bumble.device import Device, DeviceConfiguration
        from bumble.transport import open_transport

        self.hci = await open_transport(self.transport_name)
        config = DeviceConfiguration(name="axross-bridge", classic_enabled=True,
                                     le_enabled=True)
        self.device = Device.from_config_with_hci(config, self.hci.source, self.hci.sink)
        snoop = os.environ.get("AXROSS_BT_SNOOP", "")
        if snoop:  # every HCI packet to a btsnoop file (core.bluetooth_stream reads it)
            from bumble.snoop import BtSnooper

            self.snoop_file = open(snoop, "wb", buffering=0)  # noqa: SIM115 - open while it runs
            self.device.host.snooper = BtSnooper(self.snoop_file)
        self.device.on("advertisement", lambda adv: self.hand(self._advertised, adv))
        self.device.on("inquiry_result", lambda address, cod, data, rssi: self.hand(
            self._inquired, address, cod, data, rssi))
        self.device.on("inquiry_complete", lambda: self.hand(self._inquiry_done))
        await self.device.power_on()
        self.address = str(self.device.public_address).split("/")[0]

    def hand(self, fn, *args) -> None:
        """Run *fn(*args)* on the D-Bus thread (all object state lives there)."""
        self.inbox.put((fn, args))

    def radio(self, coro, done=None) -> None:
        """Run *coro* on the radio thread; *done(result, error)* on the D-Bus one."""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)

        def finished(f) -> None:
            error = f.exception()
            self.hand(done or (lambda _r, _e: None), None if error else f.result(), error)
        future.add_done_callback(finished)

    def _drain(self) -> None:
        while True:
            try:
                fn, args = self.inbox.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception as exc:  # noqa: BLE001 - one bad event is not the bridge
                print(f"bumble-bluez: {fn.__name__}: {exc!r}", file=sys.stderr, flush=True)
        self.later(DRAIN_S, self._drain)

    def run(self) -> None:
        self.ready.wait(30)
        if self.start_error or self.device is None:
            print(f"error {self.start_error or 'the stick did not answer'}", flush=True)
            return
        self.add_object(self.adapter_path, {ADAPTER: {
            "Address": self.address, "AddressType": "public", "Name": "axross-bridge",
            "Alias": "axross-bridge", "Class": 0x6C010C, "Powered": True, "PowerState": "on",
            "Discoverable": False, "DiscoverableTimeout": 180, "Pairable": True,
            "Discovering": False, "UUIDs": []}})
        self.adapter_behaviour[self.adapter_path] = {}
        self.later(DRAIN_S, self._drain)
        super().run()

    # -- discovery ----------------------------------------------------------------------

    def _wanted(self) -> set[str]:
        """The radios the discoveries running now want (BlueZ merges filters)."""
        out: set[str] = set()
        for sender in self.discovery.get(self.adapter_path, ()):
            transport = self.filters.get(sender, {}).get("Transport", "auto")
            out |= {"le", "bredr"} if transport == "auto" else {transport}
        return out

    def _scan_as_wanted(self) -> None:
        wanted = self._wanted()
        if "le" in wanted and not self.scanning["le"]:
            self.scanning["le"] = True
            self.radio(self.device.start_scanning(legacy=True, active=True,
                                                  filter_duplicates=False))
        elif "le" not in wanted and self.scanning["le"]:
            self.scanning["le"] = False
            self.radio(self.device.stop_scanning())
        if "bredr" in wanted and not self.scanning["bredr"]:
            self.scanning["bredr"] = True
            self.radio(self.device.start_discovery(auto_restart=True))
        elif "bredr" not in wanted and self.scanning["bredr"]:
            self.scanning["bredr"] = False
            self.radio(self.device.stop_discovery())

    def start_scan(self, msg, path: str, sender: str) -> None:
        super().start_scan(msg, path, sender)
        if path == self.adapter_path:
            self._scan_as_wanted()

    def discovery_ended(self, path: str) -> None:
        super().discovery_ended(path)
        if path == self.adapter_path:
            self._scan_as_wanted()

    def _inquiry_done(self) -> None:
        pass  # auto_restart inquires again while a discovery wants it

    def dev_path(self, address) -> str:
        text = str(address).split("/")[0].upper()
        return f"{self.adapter_path}/dev_{text.replace(':', '_')}"

    def _seen(self, address, props: dict, radio: str) -> None:
        path = self.dev_path(address)
        self.addresses[path] = address
        if path in self.objects:
            self.set_props(path, DEVICE, props)
            return
        if not any(self.passes(s, {DEVICE: props}) for s in
                   self.discovery.get(self.adapter_path, ())):
            return
        base = {"Address": str(address).split("/")[0].upper(), "Alias":
                str(address).split("/")[0].upper().replace(":", "-"), "Paired": False,
                "Bonded": False, "Trusted": False, "Blocked": False, "Connected": False,
                "ServicesResolved": False, "LegacyPairing": False, "UUIDs": [],
                "Adapter": self.adapter_path}
        base.update(props)
        self.add_object(path, {DEVICE: base})

    def _advertised(self, adv) -> None:
        if "le" not in self._wanted():
            return
        props = adv_props(adv.data.ad_structures)
        props["AddressType"] = "random" if adv.address.address_type in (1, 3) else "public"
        if adv.rssi != adv.RSSI_NOT_AVAILABLE:
            props["RSSI"] = int(adv.rssi)
        self._seen(adv.address, props, "le")

    def _inquired(self, address, class_of_device, data, rssi) -> None:
        if "bredr" not in self._wanted():
            return
        props = adv_props(data.ad_structures if data is not None else ())
        props.update({"AddressType": "public", "Class": int(class_of_device)})
        if rssi is not None:
            props["RSSI"] = int(rssi)
        self._seen(address, props, "bredr")

    # -- links --------------------------------------------------------------------------

    def _is_le(self, path: str) -> bool:
        props = self.objects[path][DEVICE]
        return props.get("AddressType") == "random" or "Class" not in props

    def on_org_bluez_Device1_Connect(self, msg, path, sender):
        if path not in self.addresses:  # a scripted device of the test
            return super().on_org_bluez_Device1_Connect(msg, path, sender)
        if self.objects[path][DEVICE].get("Connected"):
            self.error(msg, "org.bluez.Error.AlreadyConnected", "Already Connected")
            return
        from bumble.core import BT_BR_EDR_TRANSPORT, BT_LE_TRANSPORT

        le = self._is_le(path)
        address = self.addresses[path]

        async def connect():
            conn = await self.device.connect(
                address, transport=BT_LE_TRANSPORT if le else BT_BR_EDR_TRANSPORT,
                timeout=CONNECT_TIMEOUT_S)
            conn.on("disconnection", lambda _reason: self.hand(self._dropped, path))
            services = []
            if le:
                from bumble.device import Peer

                peer = Peer(conn)
                await peer.discover_services()
                for svc in peer.services:
                    await svc.discover_characteristics()
                services = list(peer.services)
                return conn, peer, services
            return conn, None, services

        def done(result, error) -> None:
            if error is not None:
                self.error(msg, "org.bluez.Error.Failed",
                           ("le-connection-abort-by-local" if le else
                            "br-connection-page-timeout") + f" ({error!r})"[:200])
                return
            conn, peer, services = result
            self.links[path] = conn
            self.reply(msg)
            self.set_props(path, DEVICE, {"Connected": True})
            if peer is not None:
                self.gatt_peers[path] = peer
                self._add_real_gatt(path, services)
            self.set_props(path, DEVICE, {"ServicesResolved": True})

        self.radio(connect(), done)
    on_org_bluez_Device1_Connect.signature = ""

    def _add_real_gatt(self, path: str, services) -> None:
        for svc in services:
            spath = f"{path}/service{svc.handle:04x}"
            self.add_object(spath, {GATT_SERVICE: {"UUID": uuid_text(svc.uuid.uuid_bytes),
                                                   "Primary": True, "Device": path}})
            for char in svc.characteristics:
                cpath = f"{spath}/char{char.handle:04x}"
                uuid = uuid_text(char.uuid.uuid_bytes)
                self.proxies[cpath] = char
                self.add_object(cpath, {GATT_CHAR: {
                    "UUID": uuid, "Service": spath, "Flags": gatt_flags(int(char.properties)),
                    "Notifying": False}})

    def _dropped(self, path: str) -> None:
        self.links.pop(path, None)
        self.gatt_peers.pop(path, None)
        for cpath in [p for p in self.proxies if p.startswith(path + "/")]:
            del self.proxies[cpath]
        if path in self.objects:
            self.set_props(path, DEVICE, {"ServicesResolved": False})
            self.remove_gatt(path)
            self.set_props(path, DEVICE, {"Connected": False})

    def on_org_bluez_Device1_Disconnect(self, msg, path, sender):
        conn = self.links.get(path)
        if conn is None:
            return super().on_org_bluez_Device1_Disconnect(msg, path, sender)

        def done(_result, _error) -> None:
            self.reply(msg)
            self._dropped(path)

        self.radio(conn.disconnect(), done)
    on_org_bluez_Device1_Disconnect.signature = ""

    def on_org_bluez_Device1_Pair(self, msg, path, sender):
        conn = self.links.get(path)
        if path not in self.addresses:
            return super().on_org_bluez_Device1_Pair(msg, path, sender)
        if self.objects[path][DEVICE].get("Paired"):
            self.error(msg, "org.bluez.Error.AlreadyExists", "Already Exists")
            return
        if conn is None:
            self.error(msg, "org.bluez.Error.Failed", "connect first (bridge)")
            return

        def done(_result, error) -> None:
            if error is not None:
                self.error(msg, "org.bluez.Error.AuthenticationFailed",
                           f"Authentication Failed ({error!r})"[:200])
                return
            self.reply(msg)
            self.set_props(path, DEVICE, {"Paired": True, "Bonded": True})

        self.radio(self.device.pair(conn), done)
    on_org_bluez_Device1_Pair.signature = ""

    # -- GATT ---------------------------------------------------------------------------

    def on_org_bluez_GattCharacteristic1_ReadValue(self, msg, path, sender, options):
        proxy = self.proxies.get(path)
        if proxy is None:
            return super().on_org_bluez_GattCharacteristic1_ReadValue(msg, path, sender,
                                                                       options)
        if "read" not in self.objects[path][GATT_CHAR]["Flags"]:
            self.error(msg, "org.bluez.Error.NotPermitted", "Read not permitted")
            return

        def done(value, error) -> None:
            if error is not None:
                self.error(msg, "org.bluez.Error.Failed", repr(error)[:200])
                return
            self.reply(msg, "ay", (bytes(value),))
            self.objects[path][GATT_CHAR]["Value"] = list(bytes(value))

        self.radio(proxy.read_value(), done)
    on_org_bluez_GattCharacteristic1_ReadValue.signature = "a{sv}"

    def on_org_bluez_GattCharacteristic1_StartNotify(self, msg, path, sender):
        proxy = self.proxies.get(path)
        if proxy is None:
            return super().on_org_bluez_GattCharacteristic1_StartNotify(msg, path, sender)
        if not {"notify", "indicate"} & set(self.objects[path][GATT_CHAR]["Flags"]):
            self.error(msg, "org.bluez.Error.NotSupported", "Operation is not supported")
            return

        def value(data) -> None:
            self.hand(lambda: path in self.objects and self.set_props(
                path, GATT_CHAR, {"Value": list(bytes(data))}))

        def done(_result, error) -> None:
            if error is not None:
                self.error(msg, "org.bluez.Error.Failed", repr(error)[:200])
                return
            self.reply(msg)
            self.set_props(path, GATT_CHAR, {"Notifying": True})

        self.radio(proxy.subscribe(value), done)
    on_org_bluez_GattCharacteristic1_StartNotify.signature = ""

    def on_org_bluez_GattCharacteristic1_StopNotify(self, msg, path, sender):
        proxy = self.proxies.get(path)
        if proxy is None:
            return super().on_org_bluez_GattCharacteristic1_StopNotify(msg, path, sender)

        def done(_result, _error) -> None:
            self.reply(msg)
            self.set_props(path, GATT_CHAR, {"Notifying": False})

        self.radio(proxy.unsubscribe(), done)
    on_org_bluez_GattCharacteristic1_StopNotify.signature = ""

    def close(self) -> None:
        async def shut():
            for conn in list(self.links.values()):
                try:
                    await conn.disconnect()
                except Exception:  # noqa: BLE001
                    pass
            try:
                await self.device.power_off()
            except Exception:  # noqa: BLE001
                pass
            await self.hci.close()
            if getattr(self, "snoop_file", None) is not None:
                self.snoop_file.close()
        if self.device is not None:
            try:
                asyncio.run_coroutine_threadsafe(shut(), self.loop).result(10)
            except Exception:  # noqa: BLE001
                pass


def main() -> int:
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        print("DBUS_SESSION_BUS_ADDRESS is not set", file=sys.stderr)
        return 2
    service = BumbleBluez(sys.argv[1] if len(sys.argv) > 1 else "usb:0")
    try:
        service.run()
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
