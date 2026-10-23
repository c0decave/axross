"""core.multimedia_probe: Qt Multimedia is tried in a child process first.

Reported: axross-full showed no window on a laptop with the NVIDIA driver -
the Media Player's QAudioDecoder() ran Qt's FFmpeg backend init in the GUI
thread, and that hung in cuInit for ever. core.multimedia_env stops that
one probe; this module is the defence against the next hang of the same
kind (another driver, an audio server that never answers): before the first
in-process Qt Multimedia object, a child creates the same objects under a
bounded time. A child that hangs is killed, and the caller shows why
instead of freezing.

Measured here: a deaf audio server (a socket that accepts and never
answers, PULSE_SERVER / PIPEWIRE_REMOTE) makes QMediaDevices.audioOutputs()
and QAudioOutput() hang just like the GPU driver hangs QAudioDecoder().
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QObject  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import multimedia_probe as MP  # noqa: E402
from tests import hanging_gpu_driver as HGD  # noqa: E402

APP = QApplication.instance() or QApplication([])
FFMPEG_VARS = ("QT_FFMPEG_DECODING_HW_DEVICE_TYPES", "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES")


@pytest.fixture(autouse=True)
def _fresh_cache():
    MP.reset()
    yield
    MP.reset()


def _child(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def _pump(cond, seconds=10.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); it is dead for our purpose.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


# --- happy -----------------------------------------------------------------


def test_happy_the_real_probe_passes_here():
    """offscreen, no audio server: Qt Multimedia answers at once."""
    result = MP.run_probe(timeout=60)
    assert result.ok, result.reason
    assert result.reason == ""
    assert 0 < result.seconds < 60


def test_happy_a_reply_is_parsed():
    reply = json.dumps({"ok": True, "outputs": 2, "inputs": 1})
    result = MP.run_probe(timeout=30, command=_child(f"print({reply!r})"))
    assert result.ok and (result.outputs, result.inputs) == (2, 1)


def test_happy_the_result_is_cached_for_the_process(monkeypatch):
    calls = []

    def fake(timeout=None, **_kw):
        calls.append(timeout)
        return MP.ProbeResult(ok=True)

    monkeypatch.setattr(MP, "run_probe", fake)
    assert MP.cached() is None
    first = MP.probe()
    assert MP.probe() is first and MP.cached() is first
    assert len(calls) == 1


def test_happy_concurrent_callers_share_one_probe(monkeypatch):
    calls = []
    gate = threading.Event()

    def fake(timeout=None, **_kw):
        calls.append(1)
        gate.wait(5)
        return MP.ProbeResult(ok=True)

    monkeypatch.setattr(MP, "run_probe", fake)
    results = []
    threads = [threading.Thread(target=lambda: results.append(MP.probe())) for _ in range(6)]
    for t in threads:
        t.start()
    time.sleep(0.2)
    gate.set()
    for t in threads:
        t.join(10)
    assert len(calls) == 1
    assert len(results) == 6 and all(r is results[0] for r in results)


def test_happy_probe_async_delivers_on_the_gui_thread(monkeypatch):
    monkeypatch.setattr(MP, "run_probe", lambda timeout=None, **_kw: MP.ProbeResult(ok=True))
    got = []
    MP.probe_async(lambda result: got.append((result, threading.current_thread())))
    assert got == []  # not yet probed: it is not answered synchronously
    assert _pump(lambda: got)
    result, thread = got[0]
    assert result.ok and thread is threading.main_thread()


def test_happy_probe_async_answers_at_once_when_cached(monkeypatch):
    monkeypatch.setattr(MP, "run_probe", lambda timeout=None, **_kw: MP.ProbeResult(ok=True))
    MP.probe()
    got = []
    MP.probe_async(got.append)
    assert len(got) == 1 and got[0].ok


def test_happy_the_frozen_build_answers_the_probe_itself(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert MP.probe_command() == [sys.executable, "--multimedia-probe"]
    monkeypatch.setattr(sys, "frozen", False)
    assert MP.probe_command() == [sys.executable, "-m", "core.multimedia_probe"]


def test_happy_main_dispatches_the_probe_mode():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def main() -> int:"):]
    assert '"--multimedia-probe"' in body
    # after layer 1: the child must see what the GUI process would see
    assert body.index("apply_no_gpu_probe(") < body.index('"--multimedia-probe"')


def test_happy_the_unavailable_text_names_the_reason():
    result = MP.ProbeResult(ok=False, reason="it hung")
    assert "it hung" in MP.unavailable_text(result)
    assert MP.unavailable_text(MP.ProbeResult(ok=True)) == ""


# --- sad -------------------------------------------------------------------


def test_sad_a_child_that_hangs_is_killed_and_named(tmp_path):
    pid_file = tmp_path / "pid"
    code = (
        "import json, os, time\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "print(json.dumps({'step': 'audio devices'}), flush=True)\n"
        "time.sleep(120)\n"
    )
    start = time.monotonic()
    result = MP.run_probe(timeout=1.5, command=_child(code))
    elapsed = time.monotonic() - start
    assert not result.ok
    assert "1.5 s" in result.reason
    assert MP.STEP_LABELS["audio devices"] in result.reason
    assert elapsed < 10
    assert not _alive(int(pid_file.read_text()))


def test_sad_a_crashed_child_names_the_signal():
    code = "import os, signal; os.kill(os.getpid(), signal.SIGSEGV)"
    result = MP.run_probe(timeout=30, command=_child(code))
    assert not result.ok
    assert "SIGSEGV" in result.reason


def test_sad_an_error_the_child_reports_is_passed_on():
    reply = json.dumps({"ok": False, "error": "No module named 'PyQt6.QtMultimedia'"})
    result = MP.run_probe(timeout=30, command=_child(f"print({reply!r})"))
    assert not result.ok
    assert "No module named 'PyQt6.QtMultimedia'" in result.reason


def test_sad_a_child_without_a_reply_names_its_status_and_stderr():
    code = "import sys; print('not json'); sys.stderr.write('boom happened\\n'); sys.exit(3)"
    result = MP.run_probe(timeout=30, command=_child(code))
    assert not result.ok
    assert "3" in result.reason and "boom happened" in result.reason


def test_sad_a_command_that_cannot_start(tmp_path):
    result = MP.run_probe(timeout=5, command=[str(tmp_path / "missing-binary")])
    assert not result.ok
    assert result.reason


def test_sad_a_failed_probe_is_cached_too(monkeypatch):
    calls = []

    def fake(timeout=None, **_kw):
        calls.append(1)
        return MP.ProbeResult(ok=False, reason="hung")

    monkeypatch.setattr(MP, "run_probe", fake)
    assert not MP.probe().ok
    assert not MP.probe().ok
    assert len(calls) == 1


@pytest.mark.parametrize("raw", ["soon", "", "0", "-3", "nan", "inf"])
def test_sad_a_bad_timeout_setting_falls_back_to_the_default(monkeypatch, raw):
    monkeypatch.setenv(MP.SECONDS_ENV, raw)
    assert MP.probe_seconds() == MP.PROBE_SECONDS


# --- edge ------------------------------------------------------------------


def test_edge_the_timeout_setting_is_bounded(monkeypatch):
    monkeypatch.setenv(MP.SECONDS_ENV, "4")
    assert MP.probe_seconds() == 4.0
    monkeypatch.setenv(MP.SECONDS_ENV, "100000")
    assert MP.probe_seconds() == MP.MAX_PROBE_SECONDS
    monkeypatch.setenv(MP.SECONDS_ENV, "0.2")
    assert MP.probe_seconds() == MP.MIN_PROBE_SECONDS
    monkeypatch.delenv(MP.SECONDS_ENV)
    assert MP.probe_seconds() == MP.PROBE_SECONDS


def test_edge_a_hang_before_the_first_step_is_still_named():
    result = MP.run_probe(timeout=1.0, command=_child("import time; time.sleep(60)"))
    assert not result.ok
    assert MP.STEP_LABELS["start"] in result.reason


def test_edge_a_reply_after_noise_lines_counts():
    code = ("import json; print('qt.multimedia: some warning'); "
            "print(json.dumps({'step': 'decoder'})); print(json.dumps({'ok': True}))")
    assert MP.run_probe(timeout=30, command=_child(code)).ok


def test_edge_the_callback_of_a_deleted_receiver_is_dropped(monkeypatch):
    gate = threading.Event()

    def fake(timeout=None, **_kw):
        gate.wait(5)
        return MP.ProbeResult(ok=True)

    monkeypatch.setattr(MP, "run_probe", fake)
    receiver = QObject()
    got = []
    MP.probe_async(got.append, context=receiver)
    from PyQt6 import sip

    sip.delete(receiver)  # the dialog closed while the child still runs
    gate.set()
    assert _pump(lambda: MP.cached() is not None, 5)
    _pump(lambda: False, 0.3)
    assert got == []


def test_edge_a_probe_running_across_a_reset_is_not_kept(monkeypatch):
    gate = threading.Event()

    def fake(timeout=None, **_kw):
        gate.wait(5)
        return MP.ProbeResult(ok=False, reason="old")

    monkeypatch.setattr(MP, "run_probe", fake)
    got = []
    worker = threading.Thread(target=lambda: got.append(MP.probe()))
    worker.start()
    time.sleep(0.1)
    MP.reset()
    gate.set()
    worker.join(5)
    assert got and got[0].reason == "old"  # its caller hears it
    assert MP.cached() is None  # but the next run probes anew


def test_edge_reset_forgets_the_result(monkeypatch):
    results = iter([MP.ProbeResult(ok=False, reason="x"), MP.ProbeResult(ok=True)])
    monkeypatch.setattr(MP, "run_probe", lambda timeout=None, **_kw: next(results))
    assert not MP.probe().ok
    MP.reset()
    assert MP.probe().ok


# --- e2e: the real hangs, the real probe child --------------------------------


def _env_without_layer1() -> dict:
    env = {k: v for k, v in os.environ.items() if k not in FFMPEG_VARS}
    env["QT_QPA_PLATFORM"] = "offscreen"
    return env


def test_e2e_the_hanging_gpu_driver_is_caught_and_named(tmp_path):
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    lib = HGD.build(tmp_path / "gpu")
    start = time.monotonic()
    result = MP.run_probe(timeout=4, command=HGD.command(lib, MP.probe_command()),
                          env=_env_without_layer1())
    assert not result.ok
    assert "4 s" in result.reason
    assert MP.STEP_LABELS["decoder"] in result.reason
    assert time.monotonic() - start < 15


def test_e2e_with_layer1_the_hanging_driver_passes(tmp_path):
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    lib = HGD.build(tmp_path / "gpu")
    env = _env_without_layer1()
    env.update({name: "" for name in FFMPEG_VARS})
    result = MP.run_probe(timeout=30, command=HGD.command(lib, MP.probe_command()), env=env)
    assert result.ok, result.reason


class DeafAudioServer:
    """A unix socket that accepts and never answers: PulseAudio and
    PipeWire clients wait for its handshake for ever."""

    def __init__(self) -> None:
        # A unix socket path is limited to ~107 bytes: a short folder.
        self.folder = tempfile.mkdtemp(prefix="deaf")
        self.path = os.path.join(self.folder, "s")
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(self.path)
        self.sock.listen(16)
        self.kept = []
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.kept.append(conn)

    def env(self) -> dict:
        return {"PULSE_SERVER": f"unix:{self.path}", "PIPEWIRE_REMOTE": self.path}

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
        for conn in self.kept:
            conn.close()
        shutil.rmtree(self.folder, ignore_errors=True)


@pytest.fixture
def deaf_server():
    server = DeafAudioServer()
    yield server
    server.close()


def test_e2e_a_deaf_audio_server_is_caught_and_named(deaf_server):
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", **deaf_server.env()}
    start = time.monotonic()
    result = MP.run_probe(timeout=3, env=env)
    assert not result.ok
    assert MP.STEP_LABELS["audio devices"] in result.reason
    assert time.monotonic() - start < 12


def test_e2e_kill_takes_the_whole_process_group(tmp_path):
    """A child that started a helper of its own: both go."""
    pid_file = tmp_path / "pids"
    code = (
        "import os, subprocess, sys, time\n"
        "helper = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"open({str(pid_file)!r}, 'w').write(f'{{os.getpid()}} {{helper.pid}}')\n"
        "time.sleep(120)\n"
    )
    MP.run_probe(timeout=1.5, command=_child(code))
    pids = [int(p) for p in pid_file.read_text().split()]
    assert _pump(lambda: not any(_alive(p) for p in pids), 5), pids


def test_sad_a_killed_child_names_sigkill():
    code = "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"
    result = MP.run_probe(timeout=30, command=_child(code))
    assert not result.ok and signal.SIGKILL.name in result.reason
