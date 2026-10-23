"""The real app under a hanging GPU driver or a deaf audio server: the window
comes up, and the Media Player says why it is off.

Reported: axross-full showed no window on a laptop with the NVIDIA driver -
the Media Player extension built its engine (QAudioDecoder) while the main
window started, and Qt's FFmpeg backend hung in cuInit. Layer 1
(core.multimedia_env) stops that GPU probe; here it is switched off
(AXROSS_MULTIMEDIA_GPU_PROBE=1) to show that layer 2 holds alone:
core.multimedia_probe tries Qt Multimedia in a child, the child hangs and
is killed, and the panel shows the reason. main.py from this tree runs
offscreen with an isolated HOME and the Media Player switched on; the
probe's bound is shortened to 3 s (AXROSS_MULTIMEDIA_PROBE_SECONDS).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests import hanging_gpu_driver as HGD  # noqa: E402
from tests.test_multimedia_probe import DeafAudioServer  # noqa: E402

pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

FFMPEG_VARS = ("QT_FFMPEG_DECODING_HW_DEVICE_TYPES", "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES")
SHOWN = "gui smoke: window shown"
#: The window must be up this soon after the start (it took 2-4 s here).
WINDOW_SECONDS = 30.0
PANEL_ERROR = "Media Player: Audio does not start on this system: "


def _home(tmp_path) -> Path:
    home = tmp_path / "home"
    config = home / ".config" / "axross"
    config.mkdir(parents=True)
    (config / "extensions.json").write_text(json.dumps({"enabled": ["bundled:media_player"]}),
                                            encoding="utf-8")
    return home


def _env(home: Path, **extra) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("AXROSS_") and k not in FFMPEG_VARS
           and k not in ("DISPLAY", "WAYLAND_DISPLAY")}
    env.update(
        HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
        XDG_DATA_HOME=str(home / ".local" / "share"), XDG_STATE_HOME=str(home / ".local" / "state"),
        XDG_CACHE_HOME=str(home / ".cache"), QT_QPA_PLATFORM="offscreen",
        PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
        AXROSS_SMOKE_GUI_MS="6000", AXROSS_MULTIMEDIA_PROBE_SECONDS="3",
    )
    env.update(extra)
    return env


def _start_app(argv_prefix: list[str], env: dict, timeout: float = 90.0):
    """Run main.py; (seconds until the window was shown or None, rc, stdout, stderr)."""
    start = time.monotonic()
    proc = subprocess.Popen([*argv_prefix, sys.executable, str(ROOT / "main.py")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=env, cwd=ROOT)
    shown_at: list[float] = []
    out_lines: list[str] = []
    err_lines: list[str] = []

    def read_out() -> None:
        for line in proc.stdout:
            out_lines.append(line)
            if SHOWN in line and not shown_at:
                shown_at.append(time.monotonic() - start)

    def read_err() -> None:
        err_lines.extend(proc.stderr)

    # One reader per pipe and nothing else reading them: the time the
    # window line arrived is measured where it arrives.
    readers = [threading.Thread(target=f, daemon=True) for f in (read_out, read_err)]
    for reader in readers:
        reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    for reader in readers:
        reader.join(5)
    return (shown_at[0] if shown_at else None), proc.returncode, "".join(out_lines), \
        "".join(err_lines)


def _log(home: Path) -> str:
    path = home / ".local" / "state" / "axross" / "logs" / "axross.log"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _driver(tmp_path):
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    return HGD.build(tmp_path / "gpu")


def test_e2e_the_window_comes_up_under_the_hanging_driver_without_layer1(tmp_path):
    lib = _driver(tmp_path)
    home = _home(tmp_path)
    shown, rc, out, err = _start_app(HGD.command(lib, []),
                                     _env(home, AXROSS_MULTIMEDIA_GPU_PROBE="1"))
    log = _log(home)
    assert shown is not None, f"no window: {out[-800:]} {err[-1500:]}"
    assert shown < WINDOW_SECONDS
    assert rc == 0, err[-1500:]
    assert PANEL_ERROR in log, log[-3000:]
    assert "did not answer within 3 s (it hung while starting its media backend" in log
    assert "The Media Player is off; everything else works." in log


def test_e2e_with_layer1_the_player_starts_under_the_hanging_driver(tmp_path):
    lib = _driver(tmp_path)
    home = _home(tmp_path)
    shown, rc, out, err = _start_app(HGD.command(lib, []), _env(home))
    log = _log(home)
    assert shown is not None and shown < WINDOW_SECONDS, err[-1500:]
    assert rc == 0, err[-1500:]
    assert "Qt Multimedia answered in" in log, log[-3000:]
    assert PANEL_ERROR not in log


def test_e2e_a_deaf_audio_server_turns_into_a_message(tmp_path):
    server = DeafAudioServer()
    try:
        home = _home(tmp_path)
        shown, rc, out, err = _start_app([], _env(home, **server.env()))
    finally:
        server.close()
    log = _log(home)
    assert shown is not None and shown < WINDOW_SECONDS, err[-1500:]
    assert rc == 0, err[-1500:]
    assert PANEL_ERROR in log, log[-3000:]
    assert "listing the audio devices" in log
