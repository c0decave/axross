"""Qt Multimedia never probes the GPU drivers on its own.

Reported: axross-full opened no window on a laptop with the NVIDIA driver.
The stuck main thread, natively: QAudioDecoder() (the Media Player engine,
built while the main window starts) -> QPlatformMediaIntegration::instance()
-> av_hwdevice_ctx_create -> cuInit -> wait4, forever. Qt's FFmpeg backend
tries every hardware decoder when it starts - host GPU driver code run in
the GUI thread, for audio that needs none.

core.multimedia_env sets QT_FFMPEG_DECODING_HW_DEVICE_TYPES and
QT_FFMPEG_ENCODING_HW_DEVICE_TYPES to "" (no hardware devices) unless the
user set them: measured, both are needed - either alone still ran cuInit.
Host programs started by axross do not inherit what axross set.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import multimedia_env as ME  # noqa: E402
from core import subprocess_env as SE  # noqa: E402
from tests import hanging_gpu_driver as HGD  # noqa: E402

VARS = ("QT_FFMPEG_DECODING_HW_DEVICE_TYPES", "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES")


@pytest.fixture(autouse=True)
def _fresh():
    ME._SET_BY_AXROSS.clear()
    yield
    ME._SET_BY_AXROSS.clear()


# --- happy ----------------------------------------------------------------


def test_happy_both_variables_are_set_to_no_devices():
    env = {"HOME": "/x"}
    assert sorted(ME.apply_no_gpu_probe(env)) == sorted(VARS)
    assert all(env[name] == "" for name in VARS)


def test_happy_host_programs_do_not_inherit_what_axross_set():
    env = {"PATH": "/usr/bin"}
    ME.apply_no_gpu_probe(env)
    child = SE.clean_child_env(env)
    assert not any(name in child for name in VARS)
    assert child["PATH"] == "/usr/bin"


def test_happy_workers_keep_them():
    env = {"PATH": "/usr/bin"}
    ME.apply_no_gpu_probe(env)
    worker = SE.worker_env(env)
    assert all(worker[name] == "" for name in VARS)


def test_happy_main_applies_it_before_anything_starts():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    main_body = source[source.index("def main() -> int:"):]
    assert "apply_no_gpu_probe(" in main_body
    assert main_body.index("apply_no_gpu_probe(") < main_body.index('"--agent-worker"')


# --- sad ------------------------------------------------------------------


def test_sad_a_users_own_choice_is_kept_and_passed_on():
    env = {"QT_FFMPEG_DECODING_HW_DEVICE_TYPES": "cuda,vaapi"}
    assert ME.apply_no_gpu_probe(env) == ["QT_FFMPEG_ENCODING_HW_DEVICE_TYPES"]
    assert env["QT_FFMPEG_DECODING_HW_DEVICE_TYPES"] == "cuda,vaapi"
    child = SE.clean_child_env(env)
    assert child["QT_FFMPEG_DECODING_HW_DEVICE_TYPES"] == "cuda,vaapi"
    assert "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES" not in child


def test_sad_an_empty_value_the_user_set_counts_as_theirs():
    env = {name: "" for name in VARS}
    assert ME.apply_no_gpu_probe(env) == []
    assert all(name in SE.clean_child_env(env) for name in VARS)


def test_sad_qts_own_probing_can_be_asked_for():
    """AXROSS_MULTIMEDIA_GPU_PROBE=1: Qt's default (try every hardware
    device) - for a user who wants hardware decoding, and for the test that
    shows the second layer (core.multimedia_probe) holds without this one."""
    env = {ME.GPU_PROBE_ENV: "1"}
    assert ME.apply_no_gpu_probe(env) == []
    assert not any(name in env for name in VARS)
    assert ME.set_by_axross() == frozenset()


@pytest.mark.parametrize("value", ["", "0", "no", "off", "false"])
def test_edge_a_switch_that_is_not_on_keeps_the_defaults(value):
    env = {ME.GPU_PROBE_ENV: value}
    assert sorted(ME.apply_no_gpu_probe(env)) == sorted(VARS)


# --- edge -----------------------------------------------------------------


def test_edge_applying_twice_changes_nothing_more():
    env = {}
    first = ME.apply_no_gpu_probe(env)
    assert ME.apply_no_gpu_probe(env) == []
    assert sorted(first) == sorted(VARS)
    assert not any(name in SE.clean_child_env(env) for name in VARS)


# --- e2e: the hang itself -------------------------------------------------

_DECODER = textwrap.dedent("""
    import sys, time
    sys.path.insert(0, {root!r})
    if {apply!r}:
        from core.multimedia_env import apply_no_gpu_probe
        apply_no_gpu_probe()
    from PyQt6.QtWidgets import QApplication
    app = QApplication([])
    from PyQt6.QtMultimedia import QAudioDecoder
    start = time.monotonic()
    QAudioDecoder()
    print("created", round(time.monotonic() - start, 2), flush=True)
""")


def _decoder_under_hanging_driver(tmp_path, apply: bool) -> subprocess.CompletedProcess | None:
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    lib = HGD.build(tmp_path / "gpu")
    env = {k: v for k, v in os.environ.items() if not k.startswith("QT_FFMPEG_")}
    env.update(QT_QPA_PLATFORM="offscreen")
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    code = _DECODER.format(root=str(ROOT), apply=apply)
    try:
        return subprocess.run(HGD.command(lib, [sys.executable, "-c", code]), env=env,
                              capture_output=True, text=True, timeout=12)
    except subprocess.TimeoutExpired:
        return None


def test_e2e_the_hanging_driver_reproduces_the_report(tmp_path):
    """Negative control: without the defaults the decoder never returns."""
    assert _decoder_under_hanging_driver(tmp_path, apply=False) is None


def test_e2e_with_the_defaults_the_decoder_returns_at_once(tmp_path):
    start = time.monotonic()
    result = _decoder_under_hanging_driver(tmp_path, apply=True)
    assert result is not None, "QAudioDecoder hung under the hanging driver"
    assert result.returncode == 0, result.stderr[-600:]
    assert "created" in result.stdout
    assert time.monotonic() - start < 12
