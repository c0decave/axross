"""The multimedia probe against the real audio servers of this machine.

The release binary's probe (Qt 6.10, PipeWire backend) deadlocked on every
start and turned the Media Player off although audio worked in the GUI
process (see tests/test_audio_backends.py). These start the real child:
from this tree, and - with AXROSS_FROZEN_BINARY - the built binary, against
PipeWire and PulseAudio where they run. A hung child's native stack lands
in the log (eu-stack or gdb).
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import multimedia_probe as MP  # noqa: E402
from tests import hanging_gpu_driver as HGD  # noqa: E402

def _runtime() -> str:
    """The runtime folder holding the audio sockets: the environment's, else
    the user's own (a test run isolates XDG_RUNTIME_DIR)."""
    for folder in (os.environ.get("XDG_RUNTIME_DIR"), f"/run/user/{os.getuid()}"):
        if folder and (os.path.exists(os.path.join(folder, "pipewire-0"))
                       or os.path.exists(os.path.join(folder, "pulse", "native"))):
            return folder
    return os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"


RUNTIME = _runtime()
SERVERS = {
    "pipewire": os.path.exists(os.path.join(RUNTIME, "pipewire-0")),
    "pulseaudio": os.path.exists(os.path.join(RUNTIME, "pulse", "native")),
}
FROZEN = os.environ.get("AXROSS_FROZEN_BINARY", "")


def _env() -> dict:
    env = {k: v for k, v in os.environ.items() if k != "QT_AUDIO_BACKEND"}
    env["XDG_RUNTIME_DIR"] = RUNTIME
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    return env


def _need(backend: str) -> None:
    if not SERVERS[backend]:
        pytest.skip(f"no {backend} server in {RUNTIME}")


def _check(result: MP.ProbeResult, backend: str) -> None:
    assert result.ok, result.reason
    assert result.backend == backend
    assert result.outputs == len(result.output_devices) >= 1
    assert all(d.device_id and d.description for d in result.output_devices)


@pytest.mark.parametrize("backend", ["pipewire", "pulseaudio"])
def test_happy_e2e_the_child_lists_the_devices_of_each_server(backend):
    _need(backend)
    _check(MP.run_probe(30, env=_env(), backend=backend), backend)


@pytest.mark.skipif(not FROZEN, reason="AXROSS_FROZEN_BINARY names no built binary")
@pytest.mark.parametrize("backend", ["pipewire", "pulseaudio"])
def test_happy_e2e_the_built_binary_lists_the_devices_of_each_server(backend):
    """The release binary's own Qt (6.10): its PipeWire backend deadlocked."""
    _need(backend)
    _check(MP.run_probe(30, command=[FROZEN, "--multimedia-probe"], env=_env(),
                        backend=backend), backend)


def test_sad_e2e_a_server_that_is_not_there_is_named(tmp_path):
    env = {**_env(), "XDG_RUNTIME_DIR": str(tmp_path), "PULSE_SERVER": f"unix:{tmp_path}/none"}
    env["PIPEWIRE_REMOTE"] = str(tmp_path / "none")
    result = MP.run_probe(30, env=env, backend="pulseaudio")
    # Qt falls back to an empty device list rather than failing: no output.
    assert result.ok is False or result.outputs == 0


@pytest.mark.skipif(not (shutil.which("eu-stack") or shutil.which("gdb")),
                    reason="neither eu-stack nor gdb")
def test_edge_e2e_a_hung_child_leaves_its_native_stack_in_the_log(tmp_path, caplog):
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    lib = HGD.build(tmp_path / "gpu")
    env = {k: v for k, v in _env().items() if not k.startswith("QT_FFMPEG_")}
    env["AXROSS_MULTIMEDIA_GPU_PROBE"] = "1"
    with caplog.at_level(logging.WARNING, logger="core.multimedia_probe"):
        result = MP.run_probe(6, command=HGD.command(lib, MP.probe_command()), env=env)
    assert not result.ok and "did not answer" in result.reason
    stacks = "\n".join(r.getMessage() for r in caplog.records)
    assert "native stacks" in stacks and "cuInit" in stacks, stacks[-2000:]


def _fake_tool(tmp_path, body: str) -> str:
    tool = tmp_path / "eu-stack"
    tool.write_text("#!/bin/sh\n" + body + "\n")
    tool.chmod(0o755)
    return str(tool)


def test_sad_a_slow_debugger_cannot_hold_the_message_past_the_budget(tmp_path, monkeypatch):
    """Measured: eu-stack fetched symbols from debuginfod for 5.4 s and the
    probe's failure came after the app had closed."""
    slow = _fake_tool(tmp_path, "sleep 30")
    monkeypatch.setattr(shutil, "which", lambda name: slow if name == "eu-stack" else None)
    monkeypatch.setattr(MP, "_STACK_SECONDS", 1.0)
    start = __import__("time").monotonic()
    assert MP._native_stack(os.getpid()) == ""
    assert __import__("time").monotonic() - start < 3


def test_edge_no_symbol_server_is_asked(tmp_path, monkeypatch):
    seen = tmp_path / "env.txt"
    tool = _fake_tool(tmp_path, f'echo "TID 1: $DEBUGINFOD_URLS" > {seen}; echo "TID 1:"; echo "#0 frame"')
    monkeypatch.setattr(shutil, "which", lambda name: tool if name == "eu-stack" else None)
    monkeypatch.setenv("DEBUGINFOD_URLS", "https://debuginfod.example")
    assert "#0 frame" in MP._native_stack(os.getpid())
    assert seen.read_text().strip() == "TID 1:"
