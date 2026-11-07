"""Connection options and tests for Bluetooth devices - the widget-free half.

The Bluetooth panel's details dialog (ui/bluetooth_details.py, tab
*Connection*) uses it:

* :data:`PROFILES` / :func:`profiles_of` - the profiles of a device one
  can connect on their own (BlueZ Device1.ConnectProfile): A2DP for
  music, the headset profile (HFP) for the microphone, HID, PAN ...
* :class:`Reconnector` - *Reconnect automatically*: when a chosen
  device's connection drops (out of range, switched off and on) axross
  connects it again, after 2, 5, 15, 30 and 60 s, then gives up until
  the next drop. A connection that drops again within
  :data:`RECONNECT_STABLE` seconds continues the count instead of
  starting over. A disconnect the user asked for is not a drop. While the
  adapter is off (switched off, the computer asleep - BlueZ drops every
  connection then) an attempt waits without counting and goes on when the
  adapter is back, instead of spending all of them on "not ready". The
  choice is kept per address in ``~/.config/axross/bluetooth.json``.
* :class:`ConnectionTest` - *Test Connection*: connects (if needed) and
  times it, waits for BlueZ to resolve the services, times a few GATT
  reads (the round trip of a BLE link), and for a speaker or headset
  waits for its audio output to appear. Each step is a line of the
  report, with what went wrong where it did.
* :func:`find_source` / :func:`qt_audio_inputs` - a headset's microphone
  among the sound server's inputs (PipeWire ``bluez_input.<address>``,
  PulseAudio ``bluez_source.<address>``).

Everything is asynchronous on the GUI thread: Qt timers and the
client's signals, never a wait.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from core import bluetooth as BT
from core.i18n import tr

log = logging.getLogger(__name__)


def _u(n: int) -> str:
    return f"0000{n:04x}-0000-1000-8000-00805f9b34fb"


#: Profiles that connect on their own: (uuid, label), in the order offered.
PROFILES = (
    (_u(0x110B), "Audio playback (A2DP)"),
    (_u(0x111E), "Headset with microphone (HFP)"),
    (_u(0x1108), "Headset (HSP)"),
    (_u(0x110E), "Media controls (AVRCP)"),
    (_u(0x1124), "Input device (HID)"),
    (_u(0x1116), "Network (PAN)"),
    (_u(0x1101), "Serial port"),
)
HFP_UUID = _u(0x111E)

#: Seconds before each reconnect attempt; after the last one it gives up.
RECONNECT_DELAYS = (2.0, 5.0, 15.0, 30.0, 60.0)
#: Seconds a connection made by an attempt must stay up to count as
#: repaired: a device that connects and drops at once (BlueZ connects,
#: then a profile fails) would otherwise start the count over on every
#: brief connection and be retried for ever.
RECONNECT_STABLE = 10.0
SETTINGS_VERSION = 1


def profiles_of(device: BT.Device) -> list[tuple[str, str]]:
    """The connectable profiles *device* offers, as (uuid, label)."""
    offered = set(device.uuids)
    return [(uuid, label) for uuid, label in PROFILES if uuid in offered]


def find_source(inputs: Iterable[tuple[str, str]], device: BT.Device) -> tuple[str, str] | None:
    """The ``(id, description)`` of *inputs* that is *device*'s microphone:
    an id carrying its address, else a description equal to its name (the
    same rules as core.bluetooth.find_sink)."""
    return BT.find_sink(inputs, device)


def qt_audio_inputs() -> list[tuple[str, str]]:
    """Qt's audio inputs as ``(id, description)`` - only after
    core.multimedia_probe answered ok."""
    from PyQt6.QtMultimedia import QMediaDevices

    from core import audio_route

    return [(audio_route.device_id(d), d.description()) for d in QMediaDevices.audioInputs()]


# -- what is kept --------------------------------------------------------------------------

def settings_file() -> Path:
    return Path.home() / ".config" / "axross" / "bluetooth.json"


def load_reconnect(path: Path | None = None) -> set[str]:
    """The addresses to reconnect automatically (upper case); empty when
    the file is missing or broken."""
    try:
        raw = json.loads(Path(path or settings_file()).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return set()
    items = raw.get("reconnect") if isinstance(raw, dict) else None
    if not isinstance(items, list):
        return set()
    return {a.upper() for a in items if isinstance(a, str) and _is_address(a)}


def save_reconnect(addresses: Iterable[str], path: Path | None = None) -> None:
    path = Path(path or settings_file())
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"version": SETTINGS_VERSION,
                   "reconnect": sorted({a.upper() for a in addresses})}, handle, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _is_address(text: str) -> bool:
    parts = text.split(":")
    return len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789abcdefABCDEF"
                                                       for c in p) for p in parts)


# -- reconnecting --------------------------------------------------------------------------

class Reconnector(QObject):
    """Connect the chosen devices again when their connection drops."""

    #: (device path, attempt number) - an attempt starts
    attempting = pyqtSignal(str, int)
    #: device path - connected again after a drop
    reconnected = pyqtSignal(str)
    #: device path - every attempt failed
    gave_up = pyqtSignal(str)

    def __init__(self, client: BT.BluezClient, *, path: Path | None = None,
                 delays: tuple[float, ...] = RECONNECT_DELAYS,
                 stable: float = RECONNECT_STABLE,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.client = client
        self._path = path
        self._delays = tuple(delays)
        self._stable = stable
        self.addresses = load_reconnect(path)
        #: device path -> connected when last seen
        self._connected: dict[str, bool] = {}
        #: device path -> the attempt under way or waiting (1-based)
        self._attempts: dict[str, int] = {}
        self._timers: dict[str, QTimer] = {}
        #: device path -> (attempts it took, monotonic time) of a connection
        #: an attempt made, until it has stayed up :data:`RECONNECT_STABLE`
        self._recent: dict[str, tuple[int, float]] = {}
        #: device paths whose next disconnect the user asked for
        self._expected: set[str] = set()
        #: device paths whose attempt waits for their adapter to be switched on
        self._held: set[str] = set()
        self._stopped = False
        client.device_updated.connect(self._device_updated)
        client.devices_changed.connect(self._devices_changed)
        client.operation_finished.connect(self._finished)
        client.adapters_changed.connect(self._adapters_changed)
        self._devices_changed()

    def enabled(self, device: BT.Device) -> bool:
        return device.address.upper() in self.addresses

    def set_enabled(self, device: BT.Device, on: bool) -> None:
        """Choose *device*; saved at once (OSError when it cannot be)."""
        address = device.address.upper()
        if on == (address in self.addresses):
            return
        changed = (self.addresses | {address}) if on else (self.addresses - {address})
        save_reconnect(changed, self._path)
        self.addresses = changed
        if not on:
            self._cancel(device.path)

    def expect_disconnect(self, path: str) -> None:
        """The user is disconnecting *path*: not a drop to repair."""
        self._expected.add(path)
        self._cancel(path)

    @property
    def max_attempts(self) -> int:
        return len(self._delays)

    def pending(self, path: str) -> int:
        """The attempt under way or waiting for *path*, 0 for none."""
        return self._attempts.get(path, 0)

    def stop(self) -> None:
        self._stopped = True
        for path in list(self._timers) + list(self._held):
            self._cancel(path)
        for signal, slot in ((self.client.device_updated, self._device_updated),
                             (self.client.devices_changed, self._devices_changed),
                             (self.client.operation_finished, self._finished),
                             (self.client.adapters_changed, self._adapters_changed)):
            try:
                signal.disconnect(slot)
            except (TypeError, RuntimeError):
                pass

    # -- the client's signals ----------------------------------------------------------------

    def _devices_changed(self) -> None:
        known = {d.path: d for d in self.client.devices()}
        for path in list(self._connected):
            if path not in known:
                self._connected.pop(path, None)
                self._cancel(path)
                self._expected.discard(path)
        for path, device in known.items():
            self._connected.setdefault(path, device.connected)

    def _device_updated(self, path: str) -> None:
        if self._stopped:
            return
        device = self.client.device(path)
        if device is None:
            return
        was = self._connected.get(path, device.connected)
        self._connected[path] = device.connected
        if device.connected:
            attempts = self._attempts.get(path, 0)
            if attempts:
                self._cancel(path)
                self._recent[path] = (attempts, time.monotonic())
                self.reconnected.emit(path)
            self._expected.discard(path)
            return
        if not was:
            return
        if path in self._expected:  # the user's own disconnect
            self._expected.discard(path)
            return
        if self.enabled(device):
            attempts, since = self._recent.pop(path, (0, 0.0))
            if attempts and time.monotonic() - since < self._stable:
                log.info("Bluetooth: the connection to %s dropped again at once - "
                         "reconnecting (attempt %d)", device.address, attempts + 1)
                self._schedule(path, attempts + 1)
                return
            log.info("Bluetooth: the connection to %s dropped - reconnecting", device.address)
            self._schedule(path, 1)

    def _finished(self, path: str, op: str, error: str) -> None:
        if op != "connect" or path not in self._attempts or path in self._timers \
                or path in self._held:
            return
        if not error:
            return  # Connected arrives as a property change
        attempt = self._attempts[path]
        if not self._adapter_on(path):  # switched off meanwhile: not the device's fault
            self._hold(path)
            return
        log.info("Bluetooth: reconnect attempt %d to %s failed: %s", attempt, path, error)
        self._schedule(path, attempt + 1)

    def _adapters_changed(self) -> None:
        if self._stopped:
            return
        for path in list(self._held):
            if self._adapter_on(path):
                self._held.discard(path)
                log.info("Bluetooth: the adapter is on again - reconnecting %s", path)
                self._schedule(path, self._attempts.get(path, 1))

    def _adapter_on(self, path: str) -> bool:
        device = self.client.device(path)
        adapter = self.client.adapter(device.adapter) if device is not None else None
        return adapter is not None and adapter.powered

    def _hold(self, path: str) -> None:
        """Wait for the adapter, keeping the attempt's number."""
        timer = self._timers.pop(path, None)
        if timer is not None:
            timer.stop()
            timer.deleteLater()
        self._held.add(path)

    # -- attempts ---------------------------------------------------------------------------

    def _schedule(self, path: str, attempt: int) -> None:
        self._cancel(path)
        if attempt > len(self._delays):
            self.gave_up.emit(path)
            return
        self._attempts[path] = attempt
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: self._attempt(path))
        self._timers[path] = timer
        timer.start(int(self._delays[attempt - 1] * 1000))

    def _attempt(self, path: str) -> None:
        timer = self._timers.pop(path, None)
        if timer is not None:
            timer.deleteLater()
        device = self.client.device(path)
        if self._stopped or device is None or not self.enabled(device):
            self._attempts.pop(path, None)
            return
        if device.connected:
            self._recent[path] = (self._attempts.pop(path, 0), time.monotonic())
            self.reconnected.emit(path)
            return
        if not self._adapter_on(path):
            self._hold(path)
            return
        self.attempting.emit(path, self._attempts[path])
        self.client.connect_device(path)

    def _cancel(self, path: str) -> None:
        self._held.discard(path)
        timer = self._timers.pop(path, None)
        if timer is not None:
            timer.stop()
            timer.deleteLater()
        self._attempts.pop(path, None)
        self._recent.pop(path, None)


# -- the connection test -------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """One line of a connection test's report: ``ok`` True (worked),
    False (failed) or None (did not apply)."""

    name: str
    text: str
    ok: bool | None


def report_text(steps: Iterable[Step]) -> str:
    marks = {True: "✓", False: "✗", None: "–"}
    return "\n".join(f"{marks[s.ok]} {tr(s.name)}: {s.text}" for s in steps)


def _ms(seconds: float) -> str:
    return tr("{ms} ms").format(ms=int(round(seconds * 1000)))


#: Characteristics read for the round trip, best first.
_ROUND_TRIP_UUIDS = (_u(0x2A19), _u(0x2A00), _u(0x2A29), _u(0x2A24))


class ConnectionTest(QObject):
    """Connect, resolve, read, find the sound output - timing each step."""

    #: what it is doing now
    progress = pyqtSignal(str)
    #: the report: list[Step]
    finished = pyqtSignal(object)

    def __init__(self, client: BT.BluezClient, path: str, *,
                 sink_lister: Callable[[], list] | None = None, reads: int = 5,
                 resolve_timeout: float = 10.0, sink_timeout: float = 10.0,
                 parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.client = client
        self.path = path
        self.steps: list[Step] = []
        self.running = False
        self._sink_lister = sink_lister
        self._reads = max(1, reads)
        self._resolve_timeout = resolve_timeout
        self._sink_timeout = sink_timeout
        self._phase = ""
        self._t0 = 0.0
        self._times: list[float] = []
        self._char: str | None = None
        self._waiter: BT.SinkWaiter | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._timed_out)

    def start(self) -> None:
        device = self.client.device(self.path)
        if self.running:
            return
        self.running = True
        self.steps = []
        self.client.operation_finished.connect(self._op_finished)
        self.client.device_updated.connect(self._device_updated)
        if device is None:
            self._fail(Step("Connection", tr("The device is no longer known to BlueZ."), False))
            return
        if device.connected:
            self.steps.append(Step("Connection", tr("already connected"), None))
            self._resolve()
            return
        self._phase = "connect"
        self.progress.emit(tr("Connecting…"))
        self._t0 = time.monotonic()
        self.client.connect_device(self.path)

    def cancel(self) -> None:
        if self.running:
            self._end(emit=False)

    # -- steps -------------------------------------------------------------------------------

    def _resolve(self) -> None:
        device = self.client.device(self.path)
        if device is not None and device.services_resolved:
            self.steps.append(Step("Services", tr("resolved"), True))
            self._gatt()
            return
        self._phase = "resolve"
        self.progress.emit(tr("Waiting for the services…"))
        self._t0 = time.monotonic()
        self._timer.start(int(self._resolve_timeout * 1000))

    def _gatt(self) -> None:
        chars = [c for s in self.client.gatt_services(self.path) for c in s.characteristics
                 if c.readable]
        if not chars:
            text = tr("no GATT services (a Classic device)") if not \
                self.client.gatt_services(self.path) else tr("nothing readable")
            self.steps.append(Step("GATT round trip", text, None))
            self._audio()
            return
        chars.sort(key=lambda c: _ROUND_TRIP_UUIDS.index(c.uuid)
                   if c.uuid in _ROUND_TRIP_UUIDS else len(_ROUND_TRIP_UUIDS))
        self._char = chars[0].path
        self._times = []
        self._phase = "read"
        self.progress.emit(tr("Reading {name}…").format(name=chars[0].name))
        self._read()

    def _read(self) -> None:
        self._t0 = time.monotonic()
        self.client.read_characteristic(self._char)

    def _audio(self) -> None:
        device = self.client.device(self.path)
        if device is None or not BT.is_audio_output(device):
            self._done()
            return
        self._phase = "sink"
        self.progress.emit(tr("Waiting for the audio output…"))
        self._t0 = time.monotonic()
        waiter = BT.SinkWaiter(device, lister=self._sink_lister, timeout=self._sink_timeout,
                               interval_ms=200, parent=self)
        waiter.found.connect(self._sink_found)
        waiter.timed_out.connect(self._sink_missing)
        waiter.failed.connect(self._sink_failed)
        self._waiter = waiter
        waiter.start()

    # -- results -----------------------------------------------------------------------------

    def _op_finished(self, path: str, op: str, error: str) -> None:
        if not self.running:
            return
        if self._phase == "connect" and path == self.path and op == "connect":
            if error:
                self._fail(Step("Connection", error, False))
                return
            self.steps.append(Step("Connection", tr("connected in {time}").format(
                time=_ms(time.monotonic() - self._t0)), True))
            self._resolve()
        elif self._phase == "read" and path == self._char and op == "read":
            if error:
                self.steps.append(Step("GATT round trip", error, False))
                self._audio()
                return
            self._times.append(time.monotonic() - self._t0)
            if len(self._times) < self._reads:
                self._read()
                return
            times = self._times
            self.steps.append(Step("GATT round trip", tr(
                "{n} reads: {low} / {mean} / {high} (fastest / average / slowest)").format(
                n=len(times), low=_ms(min(times)), mean=_ms(sum(times) / len(times)),
                high=_ms(max(times))), True))
            self._audio()

    def _device_updated(self, path: str) -> None:
        if not self.running or path != self.path:
            return
        device = self.client.device(path)
        if self._phase == "resolve" and device is not None and device.services_resolved:
            self._timer.stop()
            self.steps.append(Step("Services", tr("resolved after {time}").format(
                time=_ms(time.monotonic() - self._t0)), True))
            self._gatt()
        elif device is not None and not device.connected and self._phase in ("resolve", "read"):
            self._fail(Step("Connection", tr("the connection dropped during the test"), False))

    def _timed_out(self) -> None:
        if self._phase == "resolve":
            self.steps.append(Step("Services", tr("not resolved within {seconds:g} s").format(
                seconds=self._resolve_timeout), False))
            self._audio()

    def _sink_found(self, _ident: str, description: str) -> None:
        self.steps.append(Step("Audio output", tr("{output} after {time}").format(
            output=description, time=_ms(time.monotonic() - self._t0)), True))
        self._done()

    def _sink_missing(self) -> None:
        self.steps.append(Step("Audio output", tr(
            "none appeared within {seconds:g} s - is the A2DP profile available?").format(
            seconds=self._sink_timeout), False))
        self._done()

    def _sink_failed(self, text: str) -> None:
        self.steps.append(Step("Audio output", text, False))
        self._done()

    def _fail(self, step: Step) -> None:
        self.steps.append(step)
        self._done()

    def _done(self) -> None:
        self._end(emit=True)

    def _end(self, *, emit: bool) -> None:
        self.running = False
        self._phase = ""
        self._timer.stop()
        if self._waiter is not None:
            self._waiter.stop()
            self._waiter.deleteLater()
            self._waiter = None
        for signal, slot in ((self.client.operation_finished, self._op_finished),
                             (self.client.device_updated, self._device_updated)):
            try:
                signal.disconnect(slot)
            except (TypeError, RuntimeError):
                pass
        if emit:
            self.finished.emit(list(self.steps))


__all__ = ["ConnectionTest", "HFP_UUID", "PROFILES", "RECONNECT_DELAYS", "Reconnector", "Step",
           "find_source", "load_reconnect", "profiles_of", "qt_audio_inputs", "report_text",
           "save_reconnect", "settings_file"]
