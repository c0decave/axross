#!/usr/bin/env python3
"""A fake ``pactl`` for tests/test_system_mixer.py.

Run as a program it behaves like pactl 16 for the subcommands
core/system_mixer.py uses (``--version``, ``-f json list ...``,
``get-default-sink|source``, ``set-*-volume``, ``set-*-mute``,
``set-default-*``, ``move-*``, ``set-card-profile``, ``subscribe``). Its
state is a JSON file named by ``FAKE_PACTL_STATE``; the lists it prints have
the shapes of real ``pactl -f json`` output (PipeWire's pipewire-pulse), and
every change appends the line ``pactl subscribe`` would print. Each call is
logged as a JSON line to ``FAKE_PACTL_LOG``.

Knobs in the state file: ``version``; ``server_down`` (every command but
``--version`` fails with "Connection failure: Connection refused");
``fail`` ({subcommand: stderr}); ``hang`` (["list sinks", "set-sink-mute",
...] sleep instead of answering); ``malformed`` (list types printed as
broken JSON); ``subscribe_exit`` (a running ``subscribe`` exits).

Imported, it gives the tests :func:`install` and :func:`default_state`.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import math
import os
import sys
import time
from pathlib import Path

NORM = 65536
STEREO = ("front-left", "front-right")


# ------------------------------------------------------------ JSON shapes
def volume(channels, percents) -> dict:
    if not isinstance(percents, (list, tuple)):
        percents = [percents] * len(channels)
    return {ch: _vol_entry(round(p * NORM / 100)) for ch, p in zip(channels, percents)}


def _vol_entry(raw: int) -> dict:
    db = "-inf dB" if raw <= 0 else f"{60 * math.log10(raw / NORM):.2f} dB"
    return {"value": raw, "value_percent": f"{round(raw * 100 / NORM)}%", "db": db}


def _sink(index, name, description, *, percent=50, mute=False, state="SUSPENDED",
          props=None, ports=None, active_port=None, channels=STEREO) -> dict:
    return {
        "index": index,
        "state": state,
        "name": name,
        "description": description,
        "driver": "PipeWire",
        "sample_specification": f"s32le {len(channels)}ch 48000Hz",
        "channel_map": ",".join(channels),
        "owner_module": 4294967295,
        "mute": mute,
        "volume": volume(channels, percent),
        "balance": 0,
        "base_volume": _vol_entry(NORM),
        "monitor_source": name + ".monitor",
        "latency": {"actual": 0, "configured": 0},
        "flags": ["HARDWARE", "HW_MUTE_CTRL", "HW_VOLUME_CTRL", "DECIBEL_VOLUME", "LATENCY"],
        "properties": props or {},
        "ports": ports or [],
        "active_port": active_port,
        "formats": ["pcm"],
    }


def _source(index, name, description, *, monitor_of="n/a", **kw) -> dict:
    entry = _sink(index, name, description, **kw)
    entry.pop("monitor_source")
    entry["monitor_of_sink"] = monitor_of
    return entry


def _stream(index, device_key, device, app, media, *, pid, binary, percent=100,
            mute=False, corked=False, channels=STEREO) -> dict:
    return {
        "index": index,
        "driver": "PipeWire",
        "owner_module": "n/a",
        "client": str(index - 1),
        device_key: device,
        "sample_specification": "float32le 2ch 48000Hz",
        "channel_map": ",".join(channels),
        "format": "pcm, format.sample_format = \"\\\"float32le\\\"\"",
        "corked": corked,
        "mute": mute,
        "volume": volume(channels, percent),
        "balance": 0,
        "buffer_latency": 0,
        "sink_latency": 0,
        "resample_method": "PipeWire",
        "properties": {
            "application.name": app,
            "application.process.id": str(pid),
            "application.process.binary": binary,
            "application.icon_name": binary,
            "media.name": media,
            "node.name": binary,
        },
    }


def _port(name, description, availability="availability unknown", priority=100) -> dict:
    return {"name": name, "description": description, "type": "Speaker", "priority": priority,
            "availability_group": "", "availability": availability}


def default_state() -> dict:
    """A laptop with built-in audio and a Bluetooth headset, Firefox playing,
    one recorder on the microphone."""
    builtin_props = {"alsa.card": "0", "device.id": "41", "device.bus": "pci",
                     "device.icon_name": "audio-card-analog-pci",
                     "device.description": "Built-in Audio Analog Stereo",
                     "device.form_factor": "internal"}
    bt_props = {"device.id": "77", "device.bus": "bluetooth", "device.form_factor": "headset",
                "device.icon_name": "audio-headset-bluetooth", "api.bluez5.address":
                "AA:BB:CC:DD:EE:01", "device.description": "WH-1000XM4"}
    return {
        "version": "16.1",
        "server_down": False,
        "fail": {},
        "hang": [],
        "malformed": [],
        "subscribe_exit": False,
        "events": [],
        "default_sink": "alsa_output.pci-0000_00_1f.3.analog-stereo",
        "default_source": "alsa_input.pci-0000_00_1f.3.analog-stereo",
        "sinks": [
            _sink(56, "alsa_output.pci-0000_00_1f.3.analog-stereo",
                  "Built-in Audio Analog Stereo", percent=[60, 30], state="RUNNING",
                  props=builtin_props,
                  ports=[_port("analog-output-speaker", "Speakers", priority=10000),
                         _port("analog-output-headphones", "Headphones", "not available",
                               9900)],
                  active_port="analog-output-speaker"),
            _sink(80, "bluez_output.AA_BB_CC_DD_EE_01.1", "WH-1000XM4", percent=40,
                  props=bt_props, ports=[_port("headset-output", "Headset", "available")],
                  active_port="headset-output"),
        ],
        "sources": [
            _source(57, "alsa_output.pci-0000_00_1f.3.analog-stereo.monitor",
                    "Monitor of Built-in Audio Analog Stereo",
                    monitor_of="alsa_output.pci-0000_00_1f.3.analog-stereo",
                    props={"device.class": "monitor", **builtin_props}),
            _source(58, "alsa_input.pci-0000_00_1f.3.analog-stereo",
                    "Built-in Audio Analog Stereo", percent=80, props=builtin_props,
                    ports=[_port("analog-input-mic", "Microphone", "available")],
                    active_port="analog-input-mic"),
            _source(81, "bluez_output.AA_BB_CC_DD_EE_01.1.monitor", "Monitor of WH-1000XM4",
                    monitor_of="bluez_output.AA_BB_CC_DD_EE_01.1",
                    props={"device.class": "monitor", **bt_props}),
        ],
        "sink-inputs": [
            _stream(90, "sink", 56, "Firefox", "YouTube - Audio", pid=4242, binary="firefox",
                    percent=100),
            _stream(92, "sink", 56, "axross", "Media Player", pid=4343, binary="python3",
                    percent=70, corked=True),
        ],
        "source-outputs": [
            _stream(95, "source", 58, "Audacity", "Recording", pid=4444, binary="audacity",
                    percent=100, channels=("mono",)),
        ],
        "cards": [
            {"index": 41, "name": "alsa_card.pci-0000_00_1f.3", "driver": "alsa",
             "owner_module": "n/a",
             "properties": {"object.id": "41", "alsa.card": "0", "device.bus": "pci",
                            "device.description": "Built-in Audio",
                            "device.icon_name": "audio-card-analog-pci"},
             "profiles": {
                 "off": {"description": "Off", "sinks": 0, "sources": 0, "priority": 0,
                         "available": True},
                 "output:analog-stereo+input:analog-stereo": {
                     "description": "Analog Stereo Duplex", "sinks": 1, "sources": 1,
                     "priority": 6565, "available": True},
                 "output:hdmi-stereo": {"description": "Digital Stereo (HDMI) Output",
                                        "sinks": 1, "sources": 0, "priority": 5900,
                                        "available": False},
             },
             "active_profile": "output:analog-stereo+input:analog-stereo",
             "ports": {}},
            {"index": 77, "name": "bluez_card.AA_BB_CC_DD_EE_01", "driver": "module-bluez5",
             "owner_module": "n/a",
             "properties": {"object.id": "77", "device.bus": "bluetooth",
                            "device.description": "WH-1000XM4",
                            "device.icon_name": "audio-headset-bluetooth"},
             "profiles": {
                 "off": {"description": "Off", "sinks": 0, "sources": 0, "priority": 0,
                         "available": True},
                 "a2dp-sink": {"description": "High Fidelity Playback (A2DP Sink, codec LDAC)",
                               "sinks": 1, "sources": 0, "priority": 18, "available": True},
                 "headset-head-unit": {"description": "Headset Head Unit (HSP/HFP, codec mSBC)",
                                       "sinks": 1, "sources": 1, "priority": 2,
                                       "available": True},
             },
             "active_profile": "a2dp-sink",
             "ports": {}},
        ],
    }


# ------------------------------------------------------------ for the tests
def install(directory: Path, state: dict | None = None) -> dict[str, Path]:
    """A ``pactl`` wrapper in *directory*/bin running this script, and the
    state and log files. Returns {"bin", "state", "log"}; put "bin" first on
    PATH and FAKE_PACTL_STATE / FAKE_PACTL_LOG into the environment."""
    bindir = directory / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    wrapper = bindir / "pactl"
    wrapper.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "{Path(__file__).resolve()}" "$@"\n')
    wrapper.chmod(0o755)
    paths = {"bin": bindir, "state": directory / "pactl-state.json",
             "log": directory / "pactl-calls.jsonl"}
    write_state(paths["state"], state if state is not None else default_state())
    paths["log"].write_text("")
    return paths


@contextlib.contextmanager
def _locked(path: Path):
    with open(str(path) + ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def read_state(path: Path) -> dict:
    with _locked(path):
        return json.loads(Path(path).read_text())


def write_state(path: Path, state: dict) -> None:
    with _locked(path):
        tmp = Path(str(path) + ".tmp")
        tmp.write_text(json.dumps(state))
        os.replace(tmp, path)


def update_state(path: Path, change) -> dict:
    """Run ``change(state)`` on the state under the lock and save it."""
    with _locked(path):
        state = json.loads(Path(path).read_text())
        change(state)
        tmp = Path(str(path) + ".tmp")
        tmp.write_text(json.dumps(state))
        os.replace(tmp, path)
        return state


def calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in Path(log).read_text().splitlines() if line.strip()]


# ------------------------------------------------------------ the program
class _Exit(Exception):
    def __init__(self, code: int, err: str = "") -> None:
        self.code, self.err = code, err


def _parse_argv(argv: list[str]) -> tuple[dict, list[str]]:
    """getopt_long with permutation, as pactl does: options anywhere until
    ``--``."""
    opts: dict = {}
    pos: list[str] = []
    i = 0
    rest = False
    while i < len(argv):
        a = argv[i]
        if rest:
            pos.append(a)
        elif a == "--":
            rest = True
        elif a in ("-f", "--format", "-s", "--server", "-n", "--client-name"):
            if i + 1 >= len(argv):
                raise _Exit(1, f"pactl: option '{a}' requires an argument\n")
            opts[a.lstrip("-")[0]] = argv[i + 1]
            i += 1
        elif a.startswith("--format="):
            opts["f"] = a.split("=", 1)[1]
        elif a == "--version":
            opts["version"] = True
        elif a in ("-h", "--help"):
            opts["help"] = True
        elif a.startswith("-") and len(a) > 1:
            raise _Exit(1, f"pactl: invalid option -- '{a[1:]}'\n")
        else:
            pos.append(a)
        i += 1
    return opts, pos


def _find(entries: list[dict], key: str) -> dict:
    for e in entries:
        if str(e["index"]) == key or e.get("name") == key:
            return e
    raise _Exit(1, "Failure: No such entity\n")


def _parse_volume(text: str) -> int:
    try:
        if text.endswith("%"):
            return round(float(text[:-1]) * NORM / 100)
        if "." in text:
            return round(float(text) * NORM)
        return int(text)
    except ValueError:
        raise _Exit(1, f"Failed to parse volume '{text}'\n") from None


def _event(state: dict, kind: str, facility: str, index=None) -> None:
    suffix = f" #{index}" if index is not None else ""
    state["events"].append(f"Event '{kind}' on {facility}{suffix}")


def _set_volume(state: dict, facility: str, target: str, values: list[str]) -> None:
    if not values:
        raise _Exit(1, "You have to specify a volume\n")
    entry = _find(state[_LISTS[facility]], target)
    channels = list(entry["volume"])
    raws = [_parse_volume(v) for v in values]
    if len(raws) == 1:
        raws = raws * len(channels)
    if len(raws) != len(channels):
        raise _Exit(1, "Invalid number of volume specifications.\n")
    entry["volume"] = {ch: _vol_entry(r) for ch, r in zip(channels, raws)}
    _event(state, "change", facility, entry["index"])


def _set_mute(state: dict, facility: str, target: str, value: str) -> None:
    entry = _find(state[_LISTS[facility]], target)
    if value == "toggle":
        entry["mute"] = not entry["mute"]
    elif value in ("1", "yes", "true", "on"):
        entry["mute"] = True
    elif value in ("0", "no", "false", "off"):
        entry["mute"] = False
    else:
        raise _Exit(1, "Invalid mute specification\n")
    _event(state, "change", facility, entry["index"])


_LISTS = {"sink": "sinks", "source": "sources", "sink-input": "sink-inputs",
          "source-output": "source-outputs", "card": "cards"}


def _apply(state: dict, cmd: str, args: list[str]) -> None:
    need = {"set-default-sink": 1, "set-default-source": 1, "move-sink-input": 2,
            "move-source-output": 2, "set-card-profile": 2}
    if cmd in need and len(args) < need[cmd]:
        raise _Exit(1, "You have to specify more arguments\n")
    for facility in ("sink-input", "source-output", "sink", "source"):
        if cmd == f"set-{facility}-volume":
            if not args:
                raise _Exit(1, "You have to specify a target and a volume\n")
            return _set_volume(state, facility, args[0], args[1:])
        if cmd == f"set-{facility}-mute":
            if len(args) < 2:
                raise _Exit(1, "You have to specify a target and a mute value\n")
            return _set_mute(state, facility, args[0], args[1])
    if cmd in ("set-default-sink", "set-default-source"):
        facility = cmd.rsplit("-", 1)[1]
        entry = _find(state[_LISTS[facility]], args[0])
        state["default_" + facility] = entry["name"]
        _event(state, "change", "server")
        return None
    if cmd in ("move-sink-input", "move-source-output"):
        facility = cmd[len("move-"):]
        device_kind = "sink" if facility == "sink-input" else "source"
        stream = _find(state[_LISTS[facility]], args[0])
        device = _find(state[_LISTS[device_kind]], args[1])
        stream[device_kind] = device["index"]
        _event(state, "change", facility, stream["index"])
        return None
    if cmd == "set-card-profile":
        card = _find(state["cards"], args[0])
        if args[1] not in card["profiles"]:
            raise _Exit(1, "Failure: No such entity\n")
        card["active_profile"] = args[1]
        _event(state, "change", "card", card["index"])
        return None
    raise _Exit(1, f"Specify a valid command. ('{cmd}' is not)\n")


def _subscribe(state_path: Path) -> None:
    seen = len(read_state(state_path)["events"])
    while True:
        state = read_state(state_path)
        if state.get("subscribe_exit"):
            raise _Exit(1, "Connection failure: Connection terminated\n")
        events = state["events"]
        for line in events[seen:]:
            sys.stdout.write(line + "\n")
        sys.stdout.flush()
        seen = len(events)
        time.sleep(0.02)


def main(argv: list[str]) -> int:
    state_path = Path(os.environ["FAKE_PACTL_STATE"])
    log_path = os.environ.get("FAKE_PACTL_LOG")
    if log_path:
        with open(log_path, "a") as fh:
            fh.write(json.dumps(argv) + "\n")
    try:
        opts, pos = _parse_argv(argv)
        state = read_state(state_path)
        if opts.get("version"):
            v = state["version"]
            sys.stdout.write(f"pactl {v}\nCompiled with libpulse {v}.0\n"
                             f"Linked with libpulse {v}.0\n")
            return 0
        if not pos:
            raise _Exit(1, "No command given\n")
        cmd, args = pos[0], pos[1:]
        hang = state.get("hang", [])
        if cmd in hang or " ".join(pos[:2]) in hang:
            time.sleep(600)
        if state.get("server_down"):
            raise _Exit(1, "Connection failure: Connection refused\n")
        if cmd in state.get("fail", {}):
            raise _Exit(1, state["fail"][cmd])
        if cmd == "list":
            what = args[0] if args else ""
            if what not in ("sinks", "sources", "sink-inputs", "source-outputs", "cards"):
                raise _Exit(1, f"Specify a valid list type. ('{what}' is not)\n")
            if opts.get("f") != "json":
                raise _Exit(1, "the fake prints JSON only\n")
            if what in state.get("malformed", []):
                sys.stdout.write('[{"index":1,"name":"broken",\n')
                return 0
            sys.stdout.write(json.dumps(state[what]) + "\n")
            return 0
        if cmd in ("get-default-sink", "get-default-source"):
            sys.stdout.write(state["default_" + cmd.rsplit("-", 1)[1]] + "\n")
            return 0
        if cmd == "subscribe":
            _subscribe(state_path)
            return 0
        update_state(state_path, lambda st: _apply(st, cmd, args))
        return 0
    except _Exit as exc:
        sys.stderr.write(exc.err)
        return exc.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
