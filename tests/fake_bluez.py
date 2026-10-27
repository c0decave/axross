"""A fake BlueZ (``org.bluez``) for the Bluetooth tests, on a private D-Bus.

Run as ``python tests/fake_bluez.py`` with ``DBUS_SESSION_BUS_ADDRESS``
pointing at a private bus (tests/bluez_testkit.py starts one). It speaks
D-Bus through jeepney - a pure-Python D-Bus library that keyring needs on
Linux, so it is there wherever axross runs on Linux - and not through
QtDBus: PyQt6 cannot marshal ``a{oa{sa{sv}}}`` (the GetManagedObjects
reply; libdbus aborts on the nested map), and a fake that does not share
the client's D-Bus library catches the client's marshalling mistakes.

What it serves, modelled on BlueZ 5:

* ``/`` - org.freedesktop.DBus.ObjectManager (GetManagedObjects,
  InterfacesAdded, InterfacesRemoved);
* ``/org/bluez`` - org.bluez.AgentManager1;
* ``/org/bluez/hciN`` - org.bluez.Adapter1 (StartDiscovery,
  StopDiscovery, RemoveDevice, Powered through Properties.Set);
* ``/org/bluez/hciN/dev_XX_..`` - org.bluez.Device1 (Pair, Connect,
  Disconnect, CancelPairing, Trusted through Properties.Set) and
  org.bluez.Battery1;
* org.freedesktop.DBus.Properties (Get, GetAll, Set, PropertiesChanged)
  on all of them.

Signatures of incoming calls are checked the way BlueZ checks them; a
wrong one is answered with org.freedesktop.DBus.Error.InvalidArgs, so a
client that sends ``i`` where BlueZ wants ``u`` fails here as it would
against the real daemon.

The tests steer it through ``org.axross.test.FakeBluez.Command(s) -> s``
on ``/org/axross/test``: a JSON command in, a JSON answer out (see
:meth:`FakeBluez.command`).
"""

from __future__ import annotations

import json
import os
import sys
import time
from itertools import count

from jeepney import DBusAddress, HeaderFields, MessageType, new_error, new_method_call
from jeepney import new_method_return, new_signal
from jeepney.bus_messages import message_bus
from jeepney.io.blocking import open_dbus_connection

SERVICE = "org.bluez"
OM = "org.freedesktop.DBus.ObjectManager"
PROPS = "org.freedesktop.DBus.Properties"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
BATTERY = "org.bluez.Battery1"
AGENT_MANAGER = "org.bluez.AgentManager1"
AGENT = "org.bluez.Agent1"
CONTROL = "org.axross.test.FakeBluez"
CONTROL_PATH = "/org/axross/test"

#: D-Bus type of every property the fake knows.
TYPES = {
    ADAPTER: {"Address": "s", "AddressType": "s", "Name": "s", "Alias": "s", "Class": "u",
              "Powered": "b", "PowerState": "s", "Discoverable": "b",
              "DiscoverableTimeout": "u", "Pairable": "b", "Discovering": "b", "UUIDs": "as"},
    DEVICE: {"Address": "s", "AddressType": "s", "Name": "s", "Alias": "s", "Icon": "s",
             "Class": "u", "Appearance": "q", "Paired": "b", "Bonded": "b", "Trusted": "b",
             "Blocked": "b", "Connected": "b", "ServicesResolved": "b", "LegacyPairing": "b",
             "RSSI": "n", "TxPower": "n", "UUIDs": "as", "Adapter": "o"},
    BATTERY: {"Percentage": "y", "Source": "s"},
}
#: Properties a client may set, per interface.
WRITABLE = {ADAPTER: {"Powered", "Discoverable", "Alias", "Pairable"},
            DEVICE: {"Trusted", "Blocked", "Alias"}}


def _error_parts(spec: str) -> tuple[str, str]:
    """``"error:org.bluez.Error.Failed:text"`` -> (name, text)."""
    _, name, text = (spec.split(":", 2) + ["", ""])[:3]
    return name or "org.bluez.Error.Failed", text


class FakeBluez:
    def __init__(self) -> None:
        self.conn = open_dbus_connection(bus="SESSION")
        #: path -> {interface: {property: value}}
        self.objects: dict[str, dict[str, dict]] = {}
        #: device path -> behaviour dict (pair, connect, pin, passkey, delays)
        self.behaviour: dict[str, dict] = {}
        #: adapter path -> behaviour dict (power, discovery)
        self.adapter_behaviour: dict[str, dict] = {}
        #: device paths that appear only while discovering
        self.hidden: dict[str, dict] = {}
        #: agent path by sender
        self.agents: dict[str, tuple[str, str]] = {}
        self.calls: list[dict] = []
        #: outgoing call serial -> callback(message)
        self.waiting: dict[int, object] = {}
        #: (due, callback) - run by the loop
        self.timers: list[tuple[float, object]] = []
        self.serials = count(10_000)
        self.running = True

    # -- plumbing -----------------------------------------------------------------------

    def emit(self, path: str, interface: str, member: str, signature: str, body: tuple) -> None:
        self.conn.send(new_signal(DBusAddress(path, interface=interface), member, signature, body))

    def reply(self, msg, signature=None, body=()) -> None:
        self.conn.send(new_method_return(msg, signature, body))

    def error(self, msg, name: str, text: str = "") -> None:
        self.conn.send(new_error(msg, name, "s", (text or name.rsplit(".", 1)[-1],)))

    def call_out(self, destination: str, path: str, interface: str, member: str,
                 signature: str | None, body: tuple, on_reply) -> None:
        serial = next(self.serials)
        self.waiting[serial] = on_reply
        self.conn.send(new_method_call(DBusAddress(path, destination, interface), member,
                                       signature, body), serial=serial)

    def later(self, seconds: float, callback) -> None:
        self.timers.append((time.monotonic() + seconds, callback))

    @staticmethod
    def variant(interface: str, name: str, value):
        sig = TYPES.get(interface, {}).get(name, "s")
        return (sig, value)

    def wire(self, interface: str, props: dict) -> dict:
        return {k: self.variant(interface, k, v) for k, v in props.items()}

    def wire_object(self, path: str) -> dict:
        return {iface: self.wire(iface, props) for iface, props in self.objects[path].items()}

    def changed(self, path: str, interface: str, props: dict, invalidated=()) -> None:
        self.emit(path, PROPS, "PropertiesChanged", "sa{sv}as",
                  (interface, self.wire(interface, props), list(invalidated)))

    def set_props(self, path: str, interface: str, props: dict) -> None:
        current = self.objects[path][interface]
        diff = {k: v for k, v in props.items() if current.get(k) != v}
        current.update(props)
        if diff:
            self.changed(path, interface, diff)

    def add_object(self, path: str, interfaces: dict) -> None:
        self.objects[path] = {i: dict(p) for i, p in interfaces.items()}
        self.emit("/", OM, "InterfacesAdded", "oa{sa{sv}}", (path, self.wire_object(path)))

    def remove_object(self, path: str) -> None:
        interfaces = list(self.objects.pop(path, {}))
        if interfaces:
            self.emit("/", OM, "InterfacesRemoved", "oas", (path, interfaces))

    def adapter_of(self, path: str) -> str:
        return path.rsplit("/", 1)[0]

    # -- the loop -----------------------------------------------------------------------

    def run(self) -> None:
        self.conn.send_and_get_reply(message_bus.RequestName(SERVICE))
        print("ready", flush=True)
        while self.running:
            now = time.monotonic()
            due = [t for t in self.timers if t[0] <= now]
            self.timers = [t for t in self.timers if t[0] > now]
            for _when, callback in due:
                callback()
            wait = min((t[0] for t in self.timers), default=now + 0.2) - time.monotonic()
            try:
                msg = self.conn.receive(timeout=max(0.0, min(wait, 0.2)))
            except TimeoutError:
                continue
            kind = msg.header.message_type
            if kind in (MessageType.method_return, MessageType.error):
                callback = self.waiting.pop(msg.header.fields.get(HeaderFields.reply_serial), None)
                if callback is not None:
                    callback(msg)
                continue
            if kind != MessageType.method_call:
                continue
            try:
                self.dispatch(msg)
            except Exception as exc:  # noqa: BLE001 - a broken test command, said back
                self.error(msg, "org.freedesktop.DBus.Error.Failed", f"fake: {exc!r}")

    def dispatch(self, msg) -> None:
        fields = msg.header.fields
        path = fields.get(HeaderFields.path)
        interface = fields.get(HeaderFields.interface)
        member = fields.get(HeaderFields.member)
        signature = fields.get(HeaderFields.signature, "")
        sender = fields.get(HeaderFields.sender, "")
        if interface != CONTROL:
            self.calls.append({"path": path, "interface": interface, "member": member,
                               "signature": signature, "body": _jsonable(msg.body),
                               "sender": sender})
        handler = getattr(self, f"on_{(interface or '').replace('.', '_')}_{member}", None)
        expected = getattr(handler, "signature", None)
        if handler is None:
            self.error(msg, "org.freedesktop.DBus.Error.UnknownMethod",
                       f"no method {interface}.{member} at {path}")
            return
        if expected is not None and signature != expected:
            self.error(msg, "org.freedesktop.DBus.Error.InvalidArgs",
                       f"{member} wants ({expected}), got ({signature})")
            return
        if interface not in (CONTROL, OM, AGENT_MANAGER) and path not in self.objects:
            self.error(msg, "org.freedesktop.DBus.Error.UnknownObject", f"no object {path}")
            return
        handler(msg, path, sender, *msg.body)

    # -- ObjectManager / Properties -------------------------------------------------------

    def on_org_freedesktop_DBus_ObjectManager_GetManagedObjects(self, msg, path, sender):
        if path != "/":
            self.error(msg, "org.freedesktop.DBus.Error.UnknownObject", path)
            return
        self.reply(msg, "a{oa{sa{sv}}}", ({p: self.wire_object(p) for p in self.objects},))
    on_org_freedesktop_DBus_ObjectManager_GetManagedObjects.signature = ""

    def on_org_freedesktop_DBus_Properties_Get(self, msg, path, sender, interface, name):
        props = self.objects[path].get(interface)
        if props is None or name not in props:
            self.error(msg, "org.freedesktop.DBus.Error.InvalidArgs", f"no property {name}")
            return
        self.reply(msg, "v", (self.variant(interface, name, props[name]),))
    on_org_freedesktop_DBus_Properties_Get.signature = "ss"

    def on_org_freedesktop_DBus_Properties_GetAll(self, msg, path, sender, interface):
        self.reply(msg, "a{sv}", (self.wire(interface, self.objects[path].get(interface, {})),))
    on_org_freedesktop_DBus_Properties_GetAll.signature = "s"

    def on_org_freedesktop_DBus_Properties_Set(self, msg, path, sender, interface, name, value):
        sig, raw = value
        want = TYPES.get(interface, {}).get(name)
        if name not in WRITABLE.get(interface, ()) or interface not in self.objects[path]:
            self.error(msg, "org.freedesktop.DBus.Error.PropertyReadOnly", name)
            return
        if sig != want:
            self.error(msg, "org.freedesktop.DBus.Error.InvalidArgs",
                       f"{name} wants {want}, got {sig}")
            return
        if interface == ADAPTER and name == "Powered":
            mode = self.adapter_behaviour.get(path, {}).get("power", "ok")
            if raw and mode == "rfkill":
                self.error(msg, "org.bluez.Error.Failed", "Blocked through rfkill")
                return
            if mode.startswith("error:"):
                self.error(msg, *_error_parts(mode))
                return
            if mode == "hang":
                return
            self.reply(msg)
            self.set_props(path, ADAPTER, {"Powered": raw, "PowerState": "on" if raw else "off"})
            if not raw and self.objects[path][ADAPTER].get("Discovering"):
                self.set_props(path, ADAPTER, {"Discovering": False})
            return
        self.reply(msg)
        self.set_props(path, interface, {name: raw})
    on_org_freedesktop_DBus_Properties_Set.signature = "ssv"

    # -- AgentManager1 ----------------------------------------------------------------------

    def on_org_bluez_AgentManager1_RegisterAgent(self, msg, path, sender, agent, capability):
        if capability not in ("DisplayOnly", "DisplayYesNo", "KeyboardOnly", "NoInputNoOutput",
                              "KeyboardDisplay", ""):
            self.error(msg, "org.bluez.Error.InvalidArguments", "Invalid capability")
            return
        if sender in self.agents:
            self.error(msg, "org.bluez.Error.AlreadyExists", "Already Exists")
            return
        self.agents[sender] = (agent, capability)
        self.reply(msg)
    on_org_bluez_AgentManager1_RegisterAgent.signature = "os"

    def on_org_bluez_AgentManager1_UnregisterAgent(self, msg, path, sender, agent):
        if self.agents.get(sender, ("",))[0] != agent:
            self.error(msg, "org.bluez.Error.DoesNotExist", "Does Not Exist")
            return
        del self.agents[sender]
        self.reply(msg)
    on_org_bluez_AgentManager1_UnregisterAgent.signature = "o"

    def on_org_bluez_AgentManager1_RequestDefaultAgent(self, msg, path, sender, agent):
        self.reply(msg)
    on_org_bluez_AgentManager1_RequestDefaultAgent.signature = "o"

    # -- Adapter1 -------------------------------------------------------------------------

    def on_org_bluez_Adapter1_StartDiscovery(self, msg, path, sender):
        adapter = self.objects[path][ADAPTER]
        mode = self.adapter_behaviour.get(path, {}).get("discovery", "ok")
        if not adapter.get("Powered"):
            self.error(msg, "org.bluez.Error.NotReady", "Resource Not Ready")
            return
        if mode.startswith("error:"):
            self.error(msg, *_error_parts(mode))
            return
        if adapter.get("Discovering"):
            self.error(msg, "org.bluez.Error.InProgress", "Operation already in progress")
            return
        self.reply(msg)
        self.set_props(path, ADAPTER, {"Discovering": True})
        for dev_path, interfaces in list(self.hidden.items()):
            if dev_path.startswith(path + "/"):
                del self.hidden[dev_path]
                self.later(0.05, lambda p=dev_path, i=interfaces: self.add_object(p, i))
    on_org_bluez_Adapter1_StartDiscovery.signature = ""

    def on_org_bluez_Adapter1_StopDiscovery(self, msg, path, sender):
        if not self.objects[path][ADAPTER].get("Discovering"):
            self.error(msg, "org.bluez.Error.Failed", "No discovery started")
            return
        self.reply(msg)
        self.set_props(path, ADAPTER, {"Discovering": False})
        for dev_path, interfaces in self.objects.items():
            device = interfaces.get(DEVICE)
            if device is not None and dev_path.startswith(path + "/") and "RSSI" in device:
                del device["RSSI"]
                self.changed(dev_path, DEVICE, {}, ["RSSI"])
    on_org_bluez_Adapter1_StopDiscovery.signature = ""

    def on_org_bluez_Adapter1_RemoveDevice(self, msg, path, sender, device):
        if device not in self.objects or not device.startswith(path + "/"):
            self.error(msg, "org.bluez.Error.DoesNotExist", "Does Not Exist")
            return
        self.remove_object(device)  # BlueZ unregisters the object before it replies
        self.reply(msg)
    on_org_bluez_Adapter1_RemoveDevice.signature = "o"

    def on_org_bluez_Adapter1_SetDiscoveryFilter(self, msg, path, sender, flt):
        self.reply(msg)
    on_org_bluez_Adapter1_SetDiscoveryFilter.signature = "a{sv}"

    # -- Device1 --------------------------------------------------------------------------

    def _powered(self, path: str) -> bool:
        return bool(self.objects.get(self.adapter_of(path), {}).get(ADAPTER, {}).get("Powered"))

    def on_org_bluez_Device1_Pair(self, msg, path, sender):
        device = self.objects[path][DEVICE]
        how = self.behaviour.get(path, {})
        mode = how.get("pair", "just-works")
        if not self._powered(path):
            self.error(msg, "org.bluez.Error.NotReady", "Resource Not Ready")
            return
        if device.get("Paired"):
            self.error(msg, "org.bluez.Error.AlreadyExists", "Already Exists")
            return
        if how.get("pairing"):
            self.error(msg, "org.bluez.Error.InProgress", "In Progress")
            return
        if mode == "hang":
            how["pairing"] = True
            return
        if mode.startswith("error:"):
            self.error(msg, *_error_parts(mode))
            return

        def paired() -> None:
            how.pop("pairing", None)
            if path not in self.objects:
                self.error(msg, "org.bluez.Error.Failed", "device went away")
                return
            self.reply(msg)
            self.set_props(path, DEVICE, {"Paired": True, "Bonded": True})

        if mode == "just-works":
            how["pairing"] = True
            self.later(float(how.get("delay", 0.05)), paired)
            return
        agent = self.agents.get(sender)
        if agent is None:
            self.error(msg, "org.bluez.Error.AuthenticationFailed", "Authentication Failed")
            return
        how["pairing"] = True
        destination, agent_path = sender, agent[0]
        state = {"done": False}

        def answered(reply) -> None:
            if state["done"]:
                return
            state["done"] = True
            if reply.header.message_type == MessageType.error:
                how.pop("pairing", None)
                name = reply.header.fields.get(HeaderFields.error_name, "")
                self.error(msg, {"org.bluez.Error.Rejected": "org.bluez.Error.AuthenticationRejected",
                                 "org.bluez.Error.Canceled": "org.bluez.Error.AuthenticationCanceled"}
                           .get(name, "org.bluez.Error.AuthenticationFailed"),
                           "Authentication " + ("Rejected" if "Rejected" in name else
                                                "Canceled" if "Canceled" in name else "Failed"))
                return
            body = reply.body
            reply_sig = reply.header.fields.get(HeaderFields.signature, "")
            ok = True
            if mode == "pin":
                ok = reply_sig == "s" and body[0] == str(how.get("pin", "0000"))
            elif mode == "passkey":
                ok = reply_sig == "u" and body[0] == int(how.get("passkey", 0))
            elif mode == "confirm":
                ok = reply_sig == ""
            if not ok:
                how.pop("pairing", None)
                self.error(msg, "org.bluez.Error.AuthenticationFailed", "Authentication Failed")
                return
            paired()

        def timed_out() -> None:
            if state["done"]:
                return
            state["done"] = True
            how.pop("pairing", None)
            self.call_out(destination, agent_path, AGENT, "Cancel", None, (), lambda _r: None)
            self.error(msg, "org.bluez.Error.AuthenticationTimeout", "Authentication Timeout")

        self.later(float(how.get("agent_timeout", 25.0)), timed_out)
        if mode == "confirm":
            self.call_out(destination, agent_path, AGENT, "RequestConfirmation", "ou",
                          (path, int(how.get("passkey", 0))), answered)
        elif mode == "pin":
            self.call_out(destination, agent_path, AGENT, "RequestPinCode", "o", (path,), answered)
        elif mode == "passkey":
            self.call_out(destination, agent_path, AGENT, "RequestPasskey", "o", (path,), answered)
        elif mode == "display-passkey":
            self.call_out(destination, agent_path, AGENT, "DisplayPasskey", "ouq",
                          (path, int(how.get("passkey", 0)), 0), lambda _r: None)
            self.later(float(how.get("delay", 0.3)), lambda: (state.update(done=True), paired()))
        elif mode == "authorize":
            self.call_out(destination, agent_path, AGENT, "RequestAuthorization", "o", (path,),
                          answered)
    on_org_bluez_Device1_Pair.signature = ""

    def on_org_bluez_Device1_CancelPairing(self, msg, path, sender):
        how = self.behaviour.get(path, {})
        if not how.pop("pairing", None):
            self.error(msg, "org.bluez.Error.DoesNotExist", "Does Not Exist")
            return
        self.reply(msg)
    on_org_bluez_Device1_CancelPairing.signature = ""

    def on_org_bluez_Device1_Connect(self, msg, path, sender):
        how = self.behaviour.get(path, {})
        mode = how.get("connect", "ok")
        if not self._powered(path):
            self.error(msg, "org.bluez.Error.NotReady", "Resource Not Ready")
            return
        if self.objects[path][DEVICE].get("Connected"):
            self.error(msg, "org.bluez.Error.AlreadyConnected", "Already Connected")
            return
        if mode == "hang":
            return
        if mode.startswith("error:"):
            self.error(msg, *_error_parts(mode))
            return

        def connected() -> None:
            if path not in self.objects:
                self.error(msg, "org.bluez.Error.Failed", "device went away")
                return
            self.reply(msg)
            self.set_props(path, DEVICE, {"Connected": True, "ServicesResolved": True})

        self.later(float(how.get("delay", 0.05)), connected)
    on_org_bluez_Device1_Connect.signature = ""

    def on_org_bluez_Device1_Disconnect(self, msg, path, sender):
        if not self.objects[path][DEVICE].get("Connected"):
            self.error(msg, "org.bluez.Error.NotConnected", "Not Connected")
            return
        self.reply(msg)
        self.set_props(path, DEVICE, {"Connected": False, "ServicesResolved": False})
    on_org_bluez_Device1_Disconnect.signature = ""

    # -- the test's control -------------------------------------------------------------

    def on_org_axross_test_FakeBluez_Command(self, msg, path, sender, text):
        self.reply(msg, "s", (json.dumps(self.command(json.loads(text))),))
    on_org_axross_test_FakeBluez_Command.signature = "s"

    def command(self, cmd: dict):
        """One test command:

        * ``add_adapter`` name, props
        * ``add_device`` adapter, address, props, behaviour, battery, on_scan
        * ``remove`` path; ``set`` path, iface, props
        * ``battery`` path, percentage (None removes Battery1)
        * ``behave`` path, behaviour; ``adapter_behave`` path, behaviour
        * ``calls`` (and ``clear_calls``), ``agents``, ``objects``, ``quit``
        """
        op = cmd["op"]
        if op == "add_adapter":
            path = f"/org/bluez/{cmd.get('name', 'hci0')}"
            props = {"Address": "00:1A:7D:DA:71:13", "AddressType": "public", "Name": "host",
                     "Alias": "host", "Class": 0x6c010c, "Powered": False, "PowerState": "off",
                     "Discoverable": False, "DiscoverableTimeout": 180, "Pairable": True,
                     "Discovering": False, "UUIDs": []}
            props.update(cmd.get("props", {}))
            if "PowerState" not in cmd.get("props", {}):
                props["PowerState"] = "on" if props["Powered"] else "off"
            self.add_object(path, {ADAPTER: props})
            self.adapter_behaviour[path] = dict(cmd.get("behaviour", {}))
            return path
        if op == "add_device":
            adapter = f"/org/bluez/{cmd.get('adapter', 'hci0')}"
            address = cmd["address"].upper()
            path = f"{adapter}/dev_{address.replace(':', '_')}"
            props = {"Address": address, "AddressType": "public", "Alias": address.replace(":", "-"),
                     "Paired": False, "Bonded": False, "Trusted": False, "Blocked": False,
                     "Connected": False, "ServicesResolved": False, "LegacyPairing": False,
                     "UUIDs": [], "Adapter": adapter}
            props.update(cmd.get("props", {}))
            interfaces = {DEVICE: props}
            if cmd.get("battery") is not None:
                interfaces[BATTERY] = {"Percentage": int(cmd["battery"])}
            self.behaviour[path] = dict(cmd.get("behaviour", {}))
            if cmd.get("on_scan"):
                self.hidden[path] = interfaces
            else:
                self.add_object(path, interfaces)
            return path
        if op == "remove":
            self.remove_object(cmd["path"])
            return True
        if op == "set":
            self.set_props(cmd["path"], cmd["iface"], cmd["props"])
            return True
        if op == "battery":
            path = cmd["path"]
            if cmd.get("percentage") is None:
                if self.objects[path].pop(BATTERY, None) is not None:
                    self.emit("/", OM, "InterfacesRemoved", "oas", (path, [BATTERY]))
            elif BATTERY in self.objects[path]:
                self.set_props(path, BATTERY, {"Percentage": int(cmd["percentage"])})
            else:
                self.objects[path][BATTERY] = {"Percentage": int(cmd["percentage"])}
                self.emit("/", OM, "InterfacesAdded", "oa{sa{sv}}",
                          (path, {BATTERY: self.wire(BATTERY, self.objects[path][BATTERY])}))
            return True
        if op == "behave":
            self.behaviour.setdefault(cmd["path"], {}).update(cmd["behaviour"])
            return True
        if op == "adapter_behave":
            self.adapter_behaviour.setdefault(cmd["path"], {}).update(cmd["behaviour"])
            return True
        if op == "calls":
            return self.calls
        if op == "clear_calls":
            self.calls = []
            return True
        if op == "agents":
            return {k: list(v) for k, v in self.agents.items()}
        if op == "objects":
            return self.objects
        if op == "quit":
            self.running = False
            return True
        raise ValueError(f"unknown op {op!r}")


def _jsonable(value):
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (bytes, bytearray)):
        return list(value)
    return value


def main() -> int:
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        print("DBUS_SESSION_BUS_ADDRESS is not set", file=sys.stderr)
        return 2
    FakeBluez().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
