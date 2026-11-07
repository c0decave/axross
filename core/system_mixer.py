"""The system's sound mixer through ``pactl`` - the Audio Mixer panel's engine.

``pactl`` is the command-line client of PulseAudio; PipeWire speaks the same
protocol through ``pipewire-pulse``, so one client covers both sound servers.
This module holds everything of the mixer panel that needs no widget:

* The model: frozen dataclasses for the sound server's objects -
  :class:`Device` (an output, "sink", or an input, "source"),
  :class:`Stream` (an application playing, "sink-input", or recording,
  "source-output") and :class:`Card` (a sound card or a Bluetooth headset
  with its profiles, e.g. ``a2dp-sink`` vs ``headset-head-unit``), together
  in one :class:`MixerSnapshot`.
* Pure functions that turn pactl's JSON (``pactl -f json list ...``, pactl
  16 or newer) into that model and build the argument lists of the
  commands. They are tested without a process.
* :class:`SystemMixer`, a QObject that runs pactl through QProcess - never
  blocking the GUI thread, no worker thread, every command with a timeout so
  a hanging pactl wedges nothing. ``pactl subscribe`` runs alongside and
  every burst of events becomes one refresh. Results arrive as ``changed()``
  (the lists are new), ``error(str)`` (a sentence for the user) and
  ``state_changed(str)``.

Commands never pass through a shell. Names (of devices, cards, profiles)
that start with ``-`` or hold control characters are refused, and every
command puts ``--`` before the subcommand so nothing after it can be read
as an option. Volumes are clamped to 0-150 %.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from PyQt6.QtCore import QObject, QProcess, QProcessEnvironment, QTimer, pyqtSignal

from core.subprocess_env import clean_child_env

log = logging.getLogger(__name__)

#: pactl prints JSON (``-f json``) since version 16.
PACTL_MIN_MAJOR = 16
#: PA_VOLUME_NORM: the raw volume value of 100 %.
VOLUME_NORM = 65536
MAX_PERCENT = 150.0
DEFAULT_TIMEOUT_MS = 5000
#: Events of ``pactl subscribe`` within this window make one refresh.
COALESCE_MS = 150
#: A dead ``pactl subscribe`` is started again this many times; a run that
#: lasted RESTART_RESET_S or longer starts the count anew.
SUBSCRIBE_RESTARTS = 5
SUBSCRIBE_RESTART_DELAY_MS = 1000
RESTART_RESET_S = 30.0

SINK, SOURCE = "sink", "source"
SINK_INPUT, SOURCE_OUTPUT = "sink-input", "source-output"
DEVICE_KINDS = (SINK, SOURCE)
STREAM_KINDS = (SINK_INPUT, SOURCE_OUTPUT)

STATE_IDLE = "idle"  # start() not called yet
STATE_PROBING = "probing"  # pactl --version and the first listing are running
STATE_READY = "ready"
STATE_UNAVAILABLE = "unavailable"  # no pactl, or no sound server answers
STATE_TOO_OLD = "too_old"  # pactl older than 16: no JSON output
STATE_STOPPED = "stopped"  # after shutdown()

#: The facilities of ``pactl subscribe`` whose events change the lists.
_REFRESH_FACILITIES = frozenset({SINK, SOURCE, SINK_INPUT, SOURCE_OUTPUT, "card", "server"})
_EVENT_RE = re.compile(r"^Event '([\w-]+)' on ([\w-]+)(?: #(\d+))?\s*$")
_VERSION_RE = re.compile(r"pactl\s+(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_CONNECTION_RE = re.compile(
    r"connection (failure|refused|terminated)|pa_context_connect|no pulseaudio daemon",
    re.IGNORECASE,
)
_MAX_NAME = 1024
_INVALID_INDEX = 0xFFFFFFFF


class MixerParseError(ValueError):
    """pactl's output is not what the parser expects."""


# ------------------------------------------------------------------- model
@dataclass(frozen=True)
class Channel:
    name: str  # "front-left", "mono", ...
    percent: float  # 100.0 is the device's nominal volume (PA_VOLUME_NORM)


@dataclass(frozen=True)
class Port:
    name: str
    description: str
    #: True / False when the server knows (a jack plugged in or not), else None.
    available: bool | None = None


@dataclass(frozen=True)
class Device:
    """A sink (output) or a source (input)."""

    kind: str  # SINK or SOURCE
    index: int
    name: str
    description: str
    channels: tuple[Channel, ...] = ()
    muted: bool = False
    state: str = ""  # "running", "idle", "suspended" (lower case), "" unknown
    ports: tuple[Port, ...] = ()
    active_port: str = ""
    is_default: bool = False
    #: A source that records what a sink plays; a mixer usually hides these.
    is_monitor: bool = False
    monitor_of: str = ""  # the sink's name for a monitor source
    card_index: int = -1  # the Card this device belongs to, -1 for none
    card_name: str = ""
    icon_name: str = ""  # properties "device.icon_name"
    bus: str = ""  # "pci", "usb", "bluetooth", ...
    form_factor: str = ""  # "headset", "speaker", "internal", ...

    @property
    def volume_percent(self) -> float:
        """The overall volume: the loudest channel, as pavucontrol shows it."""
        return max((c.percent for c in self.channels), default=0.0)

    @property
    def label(self) -> str:
        return self.description or self.name


@dataclass(frozen=True)
class Stream:
    """An application's playback (sink-input) or recording (source-output)."""

    kind: str  # SINK_INPUT or SOURCE_OUTPUT
    index: int
    application: str  # "application.name", else the binary, else ""
    media: str = ""  # "media.name": the title, "Playback", ...
    #: The index of the sink it plays on (SINK_INPUT) or the source it
    #: records from (SOURCE_OUTPUT); -1 when unknown.
    device_index: int = -1
    channels: tuple[Channel, ...] = ()
    muted: bool = False
    corked: bool = False  # paused
    pid: int | None = None
    binary: str = ""
    icon_name: str = ""

    @property
    def has_volume(self) -> bool:
        return bool(self.channels)

    @property
    def volume_percent(self) -> float:
        return max((c.percent for c in self.channels), default=0.0)

    @property
    def is_own_process(self) -> bool:
        """True for a stream of this axross process."""
        return self.pid == os.getpid()

    @property
    def label(self) -> str:
        return self.application or self.binary or self.media or f"Stream #{self.index}"


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    available: bool = True
    priority: int = 0
    sinks: int = 0
    sources: int = 0


@dataclass(frozen=True)
class Card:
    index: int
    name: str
    description: str
    profiles: tuple[Profile, ...] = ()  # by priority, highest first
    active_profile: str = ""
    icon_name: str = ""
    bus: str = ""

    @property
    def label(self) -> str:
        return self.description or self.name

    def profile(self, name: str) -> Profile | None:
        return next((p for p in self.profiles if p.name == name), None)


@dataclass(frozen=True)
class MixerSnapshot:
    sinks: tuple[Device, ...] = ()
    sources: tuple[Device, ...] = ()  # monitors included (Device.is_monitor)
    sink_inputs: tuple[Stream, ...] = ()
    source_outputs: tuple[Stream, ...] = ()
    cards: tuple[Card, ...] = ()
    default_sink: str = ""  # a sink's name
    default_source: str = ""


# ------------------------------------------------------------ pure parsing
def parse_version(text: str) -> tuple[int, int, int] | None:
    """``pactl --version`` -> (major, minor, micro), None when it names none."""
    m = _VERSION_RE.search(text or "")
    if not m:
        return None
    return tuple(int(g or 0) for g in m.groups())  # type: ignore[return-value]


def parse_event(line: str) -> tuple[str, str, int | None] | None:
    """One line of ``pactl subscribe`` -> (event, facility, index)."""
    m = _EVENT_RE.match((line or "").strip())
    if not m:
        return None
    return m.group(1), m.group(2), int(m.group(3)) if m.group(3) else None


def event_wants_refresh(line: str) -> bool:
    ev = parse_event(line)
    return ev is not None and ev[1] in _REFRESH_FACILITIES


def is_connection_failure(stderr: str) -> bool:
    """pactl could not reach a sound server (none running, or refused)."""
    return bool(_CONNECTION_RE.search(stderr or ""))


def _load_list(text: str, what: str) -> list[dict]:
    try:
        data = json.loads(text, strict=False)
    except (ValueError, RecursionError) as exc:
        raise MixerParseError(f"the list of {what} is not valid JSON ({exc})") from None
    if not isinstance(data, list):
        raise MixerParseError(f"the list of {what} is not a JSON list")
    return [e for e in data if isinstance(e, dict) and _int(e.get("index")) is not None]


def _int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _str(value) -> str:
    if value is None or value == "n/a":
        return ""
    return value if isinstance(value, str) else str(value)


def _bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("yes", "true", "1")
    return bool(value)


def _props(entry: dict) -> dict:
    props = entry.get("properties")
    return props if isinstance(props, dict) else {}


def parse_channels(volume) -> tuple[Channel, ...]:
    """pactl's ``"volume"`` object -> the channels with their percent."""
    if not isinstance(volume, dict):
        return ()
    out = []
    for name, vol in volume.items():
        if not isinstance(vol, dict):
            continue
        raw = _int(vol.get("value"))
        if raw is not None:
            percent = raw * 100.0 / VOLUME_NORM
        else:
            text = _str(vol.get("value_percent")).strip().rstrip("%").strip()
            try:
                percent = float(text)
            except ValueError:
                continue
        out.append(Channel(str(name), round(percent, 2)))
    return tuple(out)


def _ports(entry: dict) -> tuple[Port, ...]:
    ports = entry.get("ports")
    if isinstance(ports, dict):  # cards list their ports as an object
        ports = [dict(v, name=k) for k, v in ports.items() if isinstance(v, dict)]
    if not isinstance(ports, list):
        return ()
    out = []
    for p in ports:
        if not isinstance(p, dict) or not _str(p.get("name")):
            continue
        avail = _str(p.get("availability")).lower()
        available = (True if avail == "available"
                     else False if avail == "not available" else None)
        out.append(Port(_str(p.get("name")), _str(p.get("description")), available))
    return tuple(out)


def parse_devices(text: str, kind: str, default_name: str = "") -> tuple[Device, ...]:
    """``pactl -f json list sinks|sources`` -> devices, by index."""
    if kind not in DEVICE_KINDS:
        raise ValueError(f"not a device kind: {kind!r}")
    out = []
    for e in _load_list(text, kind + "s"):
        props = _props(e)
        name = _str(e.get("name"))
        monitor_of = _str(e.get("monitor_of_sink")) if kind == SOURCE else ""
        out.append(Device(
            kind=kind,
            index=_int(e.get("index")),
            name=name,
            description=_str(e.get("description")) or _str(props.get("device.description")),
            channels=parse_channels(e.get("volume")),
            muted=_bool(e.get("mute")),
            state=_str(e.get("state")).lower(),
            ports=_ports(e),
            active_port=_str(e.get("active_port")),
            is_default=bool(name) and name == default_name,
            is_monitor=bool(monitor_of) or _str(props.get("device.class")) == "monitor",
            monitor_of=monitor_of,
            icon_name=_str(props.get("device.icon_name")),
            bus=_str(props.get("device.bus")),
            form_factor=_str(props.get("device.form_factor")),
        ))
    return tuple(sorted(out, key=lambda d: d.index))


def parse_streams(text: str, kind: str) -> tuple[Stream, ...]:
    """``pactl -f json list sink-inputs|source-outputs`` -> streams, by index."""
    if kind not in STREAM_KINDS:
        raise ValueError(f"not a stream kind: {kind!r}")
    device_key = SINK if kind == SINK_INPUT else SOURCE
    out = []
    for e in _load_list(text, kind + "s"):
        props = _props(e)
        binary = _str(props.get("application.process.binary"))
        device = _int(e.get(device_key))
        out.append(Stream(
            kind=kind,
            index=_int(e.get("index")),
            application=_str(props.get("application.name")) or binary,
            media=_str(props.get("media.name")),
            device_index=-1 if device is None or device == _INVALID_INDEX else device,
            channels=parse_channels(e.get("volume")),
            muted=_bool(e.get("mute")),
            corked=_bool(e.get("corked")),
            pid=_int(props.get("application.process.id")),
            binary=binary,
            icon_name=_str(props.get("application.icon_name")),
        ))
    return tuple(sorted(out, key=lambda s: s.index))


def parse_cards(text: str) -> tuple[Card, ...]:
    """``pactl -f json list cards`` -> cards, by index."""
    out = []
    for e in _load_list(text, "cards"):
        props = _props(e)
        profiles = []
        raw = e.get("profiles")
        if isinstance(raw, dict):
            for pname, p in raw.items():
                if not isinstance(p, dict):
                    continue
                profiles.append(Profile(
                    name=str(pname),
                    description=_str(p.get("description")) or str(pname),
                    available=_bool(p.get("available", True)),
                    priority=_int(p.get("priority")) or 0,
                    sinks=_int(p.get("sinks")) or 0,
                    sources=_int(p.get("sources")) or 0,
                ))
        profiles.sort(key=lambda p: (-p.priority, p.name))
        out.append(Card(
            index=_int(e.get("index")),
            name=_str(e.get("name")),
            description=_str(props.get("device.description")) or _str(e.get("name")),
            profiles=tuple(profiles),
            active_profile=_str(e.get("active_profile")),
            icon_name=_str(props.get("device.icon_name")),
            bus=_str(props.get("device.bus")),
        ))
    return tuple(sorted(out, key=lambda c: c.index))


def _card_key(card_name: str) -> str:
    """``alsa_card.pci-0000_00_1f.3`` -> ``pci-0000_00_1f.3``,
    ``bluez_card.AA_BB_CC_DD_EE_FF`` -> ``AA_BB_CC_DD_EE_FF``."""
    head, sep, tail = card_name.partition("_card.")
    return tail if sep and head and tail else ""


def _card_for(device_name: str, device_props: dict, cards: Sequence[Card],
              card_props: dict[int, dict]) -> Card | None:
    """The card a device belongs to: the same PipeWire device id, the same
    ALSA card number, or the card's name inside the device's name."""
    dev_id = _str(device_props.get("device.id"))
    alsa = _str(device_props.get("alsa.card"))
    for card in cards:
        props = card_props.get(card.index, {})
        if dev_id and _str(props.get("object.id")) == dev_id:
            return card
    for card in cards:
        props = card_props.get(card.index, {})
        if alsa and _str(props.get("alsa.card")) == alsa:
            return card
    _prefix, _sep, rest = device_name.partition(".")
    for card in cards:
        key = _card_key(card.name)
        if key and (rest == key or rest.startswith(key + ".")):
            return card
    return None


def build_snapshot(outputs: dict[str, str]) -> MixerSnapshot:
    """The texts of one refresh -> a snapshot. Keys: ``sinks``, ``sources``,
    ``sink-inputs``, ``source-outputs``, ``cards`` (JSON lists),
    ``default-sink``, ``default-source`` (a name). Raises MixerParseError."""
    default_sink = outputs.get("default-sink", "").strip()
    default_source = outputs.get("default-source", "").strip()
    cards = parse_cards(outputs.get("cards", "[]"))
    card_props = {_int(e.get("index")): _props(e)
                  for e in _load_list(outputs.get("cards", "[]"), "cards")}

    def link(text: str, kind: str, default: str) -> tuple[Device, ...]:
        devices = parse_devices(text, kind, default)
        props_by_index = {_int(e.get("index")): _props(e) for e in _load_list(text, kind + "s")}
        out = []
        for d in devices:
            card = _card_for(d.name, props_by_index.get(d.index, {}), cards, card_props)
            out.append(replace(d, card_index=card.index, card_name=card.name) if card else d)
        return tuple(out)

    return MixerSnapshot(
        sinks=link(outputs.get("sinks", "[]"), SINK, default_sink),
        sources=link(outputs.get("sources", "[]"), SOURCE, default_source),
        sink_inputs=parse_streams(outputs.get("sink-inputs", "[]"), SINK_INPUT),
        source_outputs=parse_streams(outputs.get("source-outputs", "[]"), SOURCE_OUTPUT),
        cards=cards,
        default_sink=default_sink,
        default_source=default_source,
    )


# ------------------------------------------------------- command building
def validate_name(name: object, what: str = "name") -> str:
    """A device, card or profile name that is safe as one pactl argument."""
    if not isinstance(name, str) or not name:
        raise ValueError(f"the {what} is empty")
    if name.startswith("-"):
        raise ValueError(f"the {what} {name!r} starts with '-' and would be read as an option")
    if len(name) > _MAX_NAME or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ValueError(f"the {what} {name[:60]!r} is not a valid name")
    return name


def validate_index(index: object, what: str = "index") -> int:
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError(f"the {what} {index!r} is not a number")
    if not 0 <= index < _INVALID_INDEX:
        raise ValueError(f"the {what} {index} is out of range")
    return index


def clamp_percent(percent: object) -> float:
    """A volume in percent, clamped to 0-150. Raises ValueError for NaN and
    anything not a number."""
    if isinstance(percent, bool):
        raise ValueError(f"{percent!r} is not a volume")
    try:
        value = float(percent)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValueError(f"{percent!r} is not a volume") from None
    if math.isnan(value):
        raise ValueError("NaN is not a volume")
    return min(MAX_PERCENT, max(0.0, value))


def percent_to_raw(percent: float) -> int:
    return int(round(clamp_percent(percent) * VOLUME_NORM / 100.0))


def volume_values(channels: Sequence[Channel], percent) -> list[str]:
    """The VOLUME arguments of a set-*-volume command, as raw integers (no
    locale, no rounding to whole percent).

    A single *percent* sets the loudest channel to it and keeps the balance
    between channels; a sequence sets each channel and must have one value
    per channel."""
    if isinstance(percent, (list, tuple)):
        if channels and len(percent) != len(channels):
            raise ValueError(f"{len(percent)} volumes for {len(channels)} channels")
        if not percent:
            raise ValueError("no volume given")
        return [str(percent_to_raw(p)) for p in percent]
    target = clamp_percent(percent)
    peak = max((c.percent for c in channels), default=0.0)
    if len(channels) < 2 or peak <= 0:
        return [str(percent_to_raw(target))]
    return [str(percent_to_raw(c.percent * target / peak)) for c in channels]


def _kind_of(target) -> str:
    kind = getattr(target, "kind", None)
    if kind not in DEVICE_KINDS + STREAM_KINDS:
        raise ValueError(f"not a device or stream: {target!r}")
    return kind


def _target_arg(target) -> str:
    """Devices by name, streams by index."""
    if _kind_of(target) in DEVICE_KINDS:
        return validate_name(target.name, "device name")
    return str(validate_index(target.index, "stream index"))


def volume_command(target, percent) -> list[str]:
    kind = _kind_of(target)
    return ["--", f"set-{kind}-volume", _target_arg(target),
            *volume_values(target.channels, percent)]


def mute_command(target, muted: bool) -> list[str]:
    kind = _kind_of(target)
    return ["--", f"set-{kind}-mute", _target_arg(target), "1" if muted else "0"]


def default_command(device: Device) -> list[str]:
    if _kind_of(device) not in DEVICE_KINDS:
        raise ValueError("only a sink or a source can be the default")
    return ["--", f"set-default-{device.kind}", validate_name(device.name, "device name")]


def move_command(stream: Stream, device: Device) -> list[str]:
    kind = _kind_of(stream)
    if kind not in STREAM_KINDS:
        raise ValueError("only a stream can be moved")
    wanted = SINK if kind == SINK_INPUT else SOURCE
    if _kind_of(device) != wanted:
        raise ValueError(f"a {kind} moves to a {wanted}, not to a {device.kind}")
    return ["--", f"move-{kind}", str(validate_index(stream.index, "stream index")),
            validate_name(device.name, "device name")]


def card_profile_command(card: Card, profile: str) -> list[str]:
    return ["--", "set-card-profile", validate_name(card.name, "card name"),
            validate_name(profile, "profile name")]


#: The commands of one refresh: key -> pactl arguments.
REFRESH_COMMANDS: dict[str, list[str]] = {
    "sinks": ["-f", "json", "list", "sinks"],
    "sources": ["-f", "json", "list", "sources"],
    "sink-inputs": ["-f", "json", "list", "sink-inputs"],
    "source-outputs": ["-f", "json", "list", "source-outputs"],
    "cards": ["-f", "json", "list", "cards"],
    "default-sink": ["get-default-sink"],
    "default-source": ["get-default-source"],
}

_PACTL_ERRORS = {
    "no such entity": "it does not exist (any more)",
    "access denied": "the sound server refused it",
    "invalid argument": "the sound server did not accept the value",
    "not supported": "the sound server does not support it",
}


def error_sentence(what: str, stderr: str) -> str:
    """``Could not <what>: <reason>.`` from pactl's stderr."""
    line = next((ln.strip() for ln in (stderr or "").splitlines() if ln.strip()), "")
    reason = line
    low = line.lower()
    for key, text in _PACTL_ERRORS.items():
        if key in low:
            reason = text
            break
    if not reason:
        reason = "pactl failed without saying why"
    return f"Could not {what}: {reason.rstrip('.')}."


# ------------------------------------------------------------ the engine
@dataclass(frozen=True)
class _Result:
    ok: bool
    out: str = ""
    err: str = ""
    timed_out: bool = False
    failed_to_start: bool = False


class SystemMixer(QObject):
    """The system's sinks, sources, streams and cards, through pactl.

    Call :meth:`start` once; it checks pactl, lists everything and keeps the
    lists current from ``pactl subscribe``. Every operation returns at once
    (False when refused, with ``error`` emitted); its outcome shows as the
    next ``changed()`` or as ``error(sentence)``. :meth:`shutdown` stops
    every process; the mixer is done after it.
    """

    changed = pyqtSignal()  # the lists (snapshot()) are new
    error = pyqtSignal(str)  # a sentence for the user
    state_changed = pyqtSignal(str)  # one of the STATE_* values

    def __init__(self, parent: QObject | None = None, *, program: str = "pactl",
                 timeout_ms: int = DEFAULT_TIMEOUT_MS, coalesce_ms: int = COALESCE_MS,
                 restart_delay_ms: int = SUBSCRIBE_RESTART_DELAY_MS) -> None:
        super().__init__(parent)
        self._program_name = program
        self._pactl = ""
        self._timeout_ms = int(timeout_ms)
        self._state = STATE_IDLE
        self._reason = ""
        self._version: tuple[int, int, int] | None = None
        self._snap = MixerSnapshot()
        self._procs: set[QProcess] = set()
        self._refreshing = False
        self._refresh_again = False
        self._op_running: set[tuple] = set()
        self._op_queued: dict[tuple, tuple[list[str], str]] = {}
        self._subscribe: QProcess | None = None
        self._subscribe_buf = b""
        self._subscribe_started = 0.0
        self._restarts = 0
        self._coalesce = QTimer(self)
        self._coalesce.setSingleShot(True)
        self._coalesce.setInterval(int(coalesce_ms))
        self._coalesce.timeout.connect(self.refresh)
        self._restart_timer = QTimer(self)
        self._restart_timer.setSingleShot(True)
        self._restart_timer.setInterval(int(restart_delay_ms))
        self._restart_timer.timeout.connect(self._start_subscribe)

    # ------------------------------------------------------------ queries
    def state(self) -> str:
        return self._state

    def reason(self) -> str:
        """Why the mixer is not ready, as a sentence; "" when it is."""
        return self._reason

    def available(self) -> bool:
        return self._state == STATE_READY

    def pactl_version(self) -> tuple[int, int, int] | None:
        return self._version

    def snapshot(self) -> MixerSnapshot:
        return self._snap

    def sinks(self) -> tuple[Device, ...]:
        return self._snap.sinks

    def sources(self, include_monitors: bool = False) -> tuple[Device, ...]:
        if include_monitors:
            return self._snap.sources
        return tuple(d for d in self._snap.sources if not d.is_monitor)

    def sink_inputs(self) -> tuple[Stream, ...]:
        return self._snap.sink_inputs

    def source_outputs(self) -> tuple[Stream, ...]:
        return self._snap.source_outputs

    def cards(self) -> tuple[Card, ...]:
        return self._snap.cards

    def default_sink(self) -> str:
        return self._snap.default_sink

    def default_source(self) -> str:
        return self._snap.default_source

    def device(self, kind: str, index: int) -> Device | None:
        pool = self._snap.sinks if kind == SINK else self._snap.sources
        return next((d for d in pool if d.index == index), None)

    def stream(self, kind: str, index: int) -> Stream | None:
        pool = self._snap.sink_inputs if kind == SINK_INPUT else self._snap.source_outputs
        return next((s for s in pool if s.index == index), None)

    def card(self, key: int | str) -> Card | None:
        return next((c for c in self._snap.cards if key in (c.index, c.name)), None)

    def set_timeout_ms(self, timeout_ms: int) -> None:
        """How long a command may take before it is killed (from the next one on)."""
        self._timeout_ms = max(1, int(timeout_ms))

    def running_processes(self) -> int:
        """pactl processes running now (``pactl subscribe`` included)."""
        return sum(1 for p in self._procs if p.state() != QProcess.ProcessState.NotRunning)

    # ---------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Check pactl and the sound server, list everything, then follow
        ``pactl subscribe``. Again after "unavailable" it is a retry."""
        if self._state in (STATE_STOPPED, STATE_PROBING, STATE_READY):
            return
        found = shutil.which(self._program_name, path=os.environ.get("PATH"))
        if not found:
            self._set_state(
                STATE_UNAVAILABLE,
                "pactl was not found, so axross cannot control the system's sound. "
                "Install pulseaudio-utils (it works with PipeWire as well).")
            return
        self._pactl = found
        self._set_state(STATE_PROBING, "")
        self._run(["--version"], self._on_version, label="pactl --version")

    def shutdown(self) -> None:
        """Stop every pactl process and every timer; the mixer is done."""
        if self._state == STATE_STOPPED:
            return
        self._coalesce.stop()
        self._restart_timer.stop()
        self._set_state(STATE_STOPPED, "The mixer was shut down.")
        procs = list(self._procs)
        self._procs.clear()
        self._subscribe = None
        for proc in procs:
            if proc.state() != QProcess.ProcessState.NotRunning:
                proc.kill()
                proc.waitForFinished(1000)
            proc.deleteLater()

    def refresh(self) -> None:
        """List everything again (or retry start() when not ready)."""
        if self._state != STATE_READY:
            if self._state in (STATE_IDLE, STATE_UNAVAILABLE):
                self.start()
            return
        self._refresh_now()

    # --------------------------------------------------------- operations
    def set_volume(self, target: Device | Stream, percent: float | Sequence[float]) -> bool:
        """Set a device's or stream's volume in percent (clamped to 0-150).
        One value keeps the balance between the channels; a sequence sets
        each channel."""
        return self._operate(
            lambda: volume_command(target, percent),
            f"set the volume of {_label(target)}", ("volume", _key(target)))

    def set_mute(self, target: Device | Stream, muted: bool) -> bool:
        return self._operate(
            lambda: mute_command(target, bool(muted)),
            f"{'mute' if muted else 'unmute'} {_label(target)}", ("mute", _key(target)))

    def set_default(self, device: Device) -> bool:
        """Make a sink the default output or a source the default input."""
        return self._operate(
            lambda: default_command(device),
            f"make {_label(device)} the default", ("default", getattr(device, "kind", "")))

    def move_stream(self, stream: Stream, device: Device) -> bool:
        """Move a playback stream to another sink, a recording to another source."""
        return self._operate(
            lambda: move_command(stream, device),
            f"move {_label(stream)} to {_label(device)}", ("move", _key(stream)))

    def set_card_profile(self, card: Card, profile: str) -> bool:
        """Switch a card's profile, e.g. a headset's ``a2dp-sink``."""
        def build() -> list[str]:
            args = card_profile_command(card, profile)
            known = self.card(card.name)
            if known is not None and known.profiles and known.profile(profile) is None:
                raise ValueError(f"{known.label} has no profile {profile!r}")
            return args
        return self._operate(
            build, f"switch {_label(card)} to the profile {profile}",
            ("profile", getattr(card, "name", "")))

    # ----------------------------------------------------------- internals
    def _set_state(self, state: str, reason: str) -> None:
        self._reason = reason
        if state == self._state:
            return
        self._state = state
        if reason:
            log.info("system mixer: %s (%s)", state, reason)
        self.state_changed.emit(state)

    def _unavailable(self, reason: str) -> None:
        self._stop_subscribe()
        self._refresh_again = False
        self._set_state(STATE_UNAVAILABLE, reason)

    def _env(self) -> QProcessEnvironment:
        env = QProcessEnvironment()
        # The user's environment without a frozen build's loader path;
        # English errors (is_connection_failure) and "." in numbers.
        for name, value in clean_child_env(LC_ALL="C").items():
            env.insert(name, value)
        return env

    def _run(self, args: list[str], on_done: Callable[[_Result], None], *, label: str,
             timeout: bool = True) -> QProcess:
        proc = QProcess(self)
        proc.setProgram(self._pactl)
        proc.setArguments(args)
        proc.setProcessEnvironment(self._env())
        proc.setStandardInputFile(QProcess.nullDevice())
        timer = QTimer(proc)
        timer.setSingleShot(True)
        done = [False]

        def finish(result: _Result) -> None:
            if done[0]:
                return
            done[0] = True
            timer.stop()
            self._procs.discard(proc)
            if proc.state() == QProcess.ProcessState.NotRunning:
                proc.deleteLater()
            else:
                proc.finished.connect(proc.deleteLater)
            if self._state != STATE_STOPPED:
                on_done(result)

        def on_finished(code: int, status: QProcess.ExitStatus) -> None:
            out = bytes(proc.readAllStandardOutput()).decode("utf-8", "replace")
            err = bytes(proc.readAllStandardError()).decode("utf-8", "replace")
            if status != QProcess.ExitStatus.NormalExit:
                finish(_Result(False, out, err or f"{label} crashed"))
            else:
                finish(_Result(code == 0, out, err))

        def on_error(err: QProcess.ProcessError) -> None:
            if err == QProcess.ProcessError.FailedToStart:
                finish(_Result(False, "", proc.errorString(), failed_to_start=True))

        def on_timeout() -> None:
            log.warning("system mixer: %s did not answer within %d ms", label, self._timeout_ms)
            proc.kill()
            finish(_Result(False, "", "", timed_out=True))

        proc.finished.connect(on_finished)
        proc.errorOccurred.connect(on_error)
        timer.timeout.connect(on_timeout)
        self._procs.add(proc)
        proc.start()
        if timeout:
            timer.start(self._timeout_ms)
        return proc

    def _seconds(self) -> str:
        s = self._timeout_ms / 1000.0
        return f"{s:g} s"

    def _on_version(self, result: _Result) -> None:
        if result.failed_to_start:
            self._unavailable(f"pactl could not be started: {result.err}")
            return
        if result.timed_out:
            self._unavailable(f"pactl --version did not answer within {self._seconds()}.")
            return
        version = parse_version(result.out)
        if not result.ok or version is None:
            self._unavailable("pactl --version did not name a version: "
                              + (result.err or result.out).strip()[:200])
            return
        self._version = version
        if version[0] < PACTL_MIN_MAJOR:
            self._stop_subscribe()
            self._set_state(
                STATE_TOO_OLD,
                f"pactl {'.'.join(map(str, version))} is too old: the mixer needs pactl "
                f"{PACTL_MIN_MAJOR} or newer, which lists in JSON.")
            return
        self._refresh_now()

    def _refresh_now(self) -> None:
        if self._refreshing:
            self._refresh_again = True
            return
        self._refreshing = True
        self._refresh_again = False
        results: dict[str, _Result] = {}

        def collect(key: str) -> Callable[[_Result], None]:
            def done(result: _Result) -> None:
                results[key] = result
                if len(results) == len(REFRESH_COMMANDS):
                    self._on_refreshed(results)
            return done

        for key, args in REFRESH_COMMANDS.items():
            self._run(list(args), collect(key), label=f"pactl {' '.join(args)}")

    def _on_refreshed(self, results: dict[str, _Result]) -> None:
        self._refreshing = False
        if self._state not in (STATE_PROBING, STATE_READY):
            return
        probing = self._state == STATE_PROBING
        problem = ""
        for key, res in results.items():
            if res.ok:
                continue
            if res.failed_to_start:
                self._unavailable(f"pactl could not be started: {res.err}")
                return
            if is_connection_failure(res.err):
                line = res.err.strip().splitlines()[0] if res.err.strip() else ""
                self._unavailable(
                    "No sound server answers (PipeWire or PulseAudio is not running"
                    + (f": {line}" if line else "") + ").")
                return
            if res.timed_out:
                problem = problem or (f"The sound server did not answer within "
                                      f"{self._seconds()} (pactl {key}).")
            else:
                problem = problem or error_sentence(f"list the {key.replace('-', ' ')}",
                                                    res.err)
        if not problem:
            try:
                snap = build_snapshot({k: r.out for k, r in results.items()})
            except MixerParseError as exc:
                problem = f"pactl gave output axross cannot read: {exc}."
        if problem:
            if probing:
                self._unavailable(problem)
            else:
                self.error.emit(problem)
                self._again()
            return
        self._snap = snap
        if probing:
            self._set_state(STATE_READY, "")
            self._restarts = 0
            self._start_subscribe()
        self.changed.emit()
        self._again()

    def _again(self) -> None:
        if self._refresh_again and self._state == STATE_READY:
            self._refresh_again = False
            self._refresh_now()

    def _schedule_refresh(self) -> None:
        if self._state == STATE_READY and not self._coalesce.isActive():
            self._coalesce.start()

    def _operate(self, build: Callable[[], list[str]], what: str, key: tuple) -> bool:
        if self._state != STATE_READY:
            self.error.emit(f"Could not {what}: the system mixer is not available. "
                            + (self._reason or ""))
            return False
        try:
            args = build()
        except ValueError as exc:
            self.error.emit(f"Could not {what}: {exc}.")
            return False
        if key in self._op_running:
            # A slider sends many values; only the latest one still matters.
            self._op_queued[key] = (args, what)
            return True
        self._start_op(args, what, key)
        return True

    def _start_op(self, args: list[str], what: str, key: tuple) -> None:
        self._op_running.add(key)

        def done(result: _Result) -> None:
            self._op_running.discard(key)
            if not result.ok:
                if result.timed_out:
                    self.error.emit(f"Could not {what}: the sound server did not answer "
                                    f"within {self._seconds()}.")
                elif is_connection_failure(result.err):
                    self.error.emit(f"Could not {what}: no sound server answers.")
                else:
                    self.error.emit(error_sentence(what, result.err))
            queued = self._op_queued.pop(key, None)
            if queued is not None and self._state == STATE_READY:
                self._start_op(queued[0], queued[1], key)
            self._schedule_refresh()

        self._run(args, done, label=f"pactl {' '.join(args[1:2])}")

    # ---------------------------------------------------- pactl subscribe
    def _start_subscribe(self) -> None:
        if self._state != STATE_READY or self._subscribe is not None:
            return
        self._subscribe_buf = b""
        self._subscribe_started = time.monotonic()
        holder: list[QProcess] = []
        proc = self._run(["subscribe"], lambda result: self._on_subscribe_ended(holder, result),
                         label="pactl subscribe", timeout=False)
        holder.append(proc)
        proc.readyReadStandardOutput.connect(lambda: self._on_subscribe_output(proc))
        self._subscribe = proc

    def _stop_subscribe(self) -> None:
        self._restart_timer.stop()
        proc, self._subscribe = self._subscribe, None
        if proc is not None and proc.state() != QProcess.ProcessState.NotRunning:
            proc.kill()

    def _on_subscribe_output(self, proc: QProcess) -> None:
        if proc is not self._subscribe:
            return
        self._subscribe_buf += bytes(proc.readAllStandardOutput())
        *lines, self._subscribe_buf = self._subscribe_buf.split(b"\n")
        if len(self._subscribe_buf) > 65536:  # no newline in sight: not pactl
            self._subscribe_buf = b""
        if any(event_wants_refresh(ln.decode("utf-8", "replace")) for ln in lines):
            self._schedule_refresh()

    def _on_subscribe_ended(self, holder: list[QProcess], result: _Result) -> None:
        if not holder or holder[0] is not self._subscribe:  # stopped on purpose
            return
        self._subscribe = None
        if self._state != STATE_READY:
            return
        if time.monotonic() - self._subscribe_started >= RESTART_RESET_S:
            self._restarts = 0
        log.info("system mixer: pactl subscribe ended (%s)", result.err.strip()[:200])
        if self._restarts >= SUBSCRIBE_RESTARTS:
            self.error.emit("Live updates from the sound server stopped (pactl subscribe "
                            "ended again and again); the lists change only on Refresh now.")
            self._refresh_now()
            return
        self._restarts += 1
        self._restart_timer.start()
        # The server may be gone: a refresh tells (it turns the state unavailable).
        self._refresh_now()


def _label(target) -> str:
    label = getattr(target, "label", None)
    return label if isinstance(label, str) and label else repr(target)


def _key(target) -> tuple:
    return (getattr(target, "kind", ""), getattr(target, "index", None),
            getattr(target, "name", None))


__all__ = [
    "Card", "Channel", "Device", "MixerParseError", "MixerSnapshot", "Port", "Profile",
    "Stream", "SystemMixer", "build_snapshot", "clamp_percent", "event_wants_refresh",
    "is_connection_failure", "parse_cards", "parse_devices", "parse_event", "parse_streams",
    "parse_version", "volume_values",
]
