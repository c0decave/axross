"""The paths of core.multimedia_probe and core.tls_env no test reached.

Found by branch coverage over every test that imports them (85 % each):
broken child output, a kill that is refused, a grandchild that keeps the
pipe open, a debugger that finds no frame, a broken audio.json, a probe
that raises in its thread (the caller must still hear an answer), and the
real certifi fallback. Each is a way the probe or a TLS connection could
hang or fail silently.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import multimedia_probe as MP  # noqa: E402
from core import tls_env as TE  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    MP.reset()
    monkeypatch.setattr(MP, "_active_backend", None)
    yield
    MP.reset()


# -- the child's output ----------------------------------------------------------------

def test_sad_lines_that_are_no_json_object_are_skipped():
    out = "\n".join(['{"step": "decoder"}', "{not json", "[1, 2]", '"text"', "{",
                     'library noise', '{"ok": true, "outputs": 2}'])
    step, reply = MP._parse(out)
    assert step == "decoder" and reply == {"ok": True, "outputs": 2}


def test_edge_an_unknown_signal_number_is_still_named():
    assert MP._signal_name(signal.SIGKILL) == "SIGKILL"
    assert MP._signal_name(250) == "signal 250"


def test_edge_counts_that_are_no_count_are_zero():
    assert MP._count({"outputs": True}, "outputs") == 0
    assert MP._count({"outputs": -1}, "outputs") == 0
    assert MP._count({"outputs": "3"}, "outputs") == 0
    assert MP._count({"outputs": 3}, "outputs") == 3


# -- killing and reaping --------------------------------------------------------------------

def test_sad_a_refused_group_kill_still_kills_the_child(monkeypatch):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                            start_new_session=True)

    def refuse(*_a):
        raise PermissionError("not allowed")

    monkeypatch.setattr(os, "killpg", refuse)
    try:
        MP._kill(proc)
        assert proc.wait(timeout=10) == -signal.SIGKILL
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.mark.skipif(not shutil.which("setsid"), reason="no setsid")
def test_edge_a_grandchild_that_keeps_the_pipe_open_cannot_hold_the_answer(monkeypatch):
    """The child is killed after the bound; a grandchild in a session of its
    own still holds stdout. The answer comes after the reap bound anyway."""
    monkeypatch.setattr(MP, "_REAP_SECONDS", 1.0)
    monkeypatch.setattr(MP, "_native_stack", lambda pid: "")
    command = ["sh", "-c", "setsid sleep 37.4242 & sleep 37.4242"]
    start = time.monotonic()
    result = MP.run_probe(1.0, command=command, env=dict(os.environ))
    took = time.monotonic() - start
    subprocess.run(["pkill", "-f", "^sleep 37.4242$"], capture_output=True)
    assert not result.ok and "did not answer within 1 s" in result.reason
    assert took < 6, took


# -- the native stack ---------------------------------------------------------------------

def test_edge_no_native_stack_outside_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert MP._native_stack(os.getpid()) == ""


def test_edge_a_debugger_that_prints_no_frame_gives_nothing(tmp_path, monkeypatch):
    tool = tmp_path / "eu-stack"
    tool.write_text("#!/bin/sh\necho 'eu-stack: cannot attach'\nexit 1\n")
    tool.chmod(0o755)
    monkeypatch.setattr(shutil, "which", lambda name: str(tool) if name == "eu-stack" else None)
    assert MP._native_stack(os.getpid()) == ""


def test_sad_a_debugger_that_cannot_start_is_skipped(tmp_path, monkeypatch):
    missing = tmp_path / "gone" / "eu-stack"
    monkeypatch.setattr(shutil, "which", lambda name: str(missing) if name == "eu-stack" else None)
    assert MP._native_stack(os.getpid()) == ""


def test_sad_a_failing_diagnosis_never_breaks_the_probe(monkeypatch, caplog):
    def boom(_pid):
        raise RuntimeError("debugger exploded")

    monkeypatch.setattr(MP, "_native_stack", boom)
    MP._log_native_stack(os.getpid())  # no exception


# -- settings and threads -------------------------------------------------------------------

def test_sad_a_broken_audio_json_counts_as_automatic(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".config" / "axross").mkdir(parents=True)
    (tmp_path / ".config" / "axross" / "audio.json").write_text("{broken")
    assert MP._saved_backend() == "auto"

    from core import audio_settings

    def explode(*_a, **_k):
        raise RuntimeError("unreadable")

    monkeypatch.setattr(audio_settings.AudioSettings, "load", classmethod(explode))
    assert MP._saved_backend() == "auto"


def test_sad_a_probe_that_raises_in_its_thread_is_logged_not_lost(monkeypatch, caplog):
    def explode(timeout=None):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(MP, "probe", explode)
    MP._probe_quietly()  # the starter thread's body
    assert any("Qt Multimedia probe failed" in r.getMessage() for r in caplog.records)


def test_sad_probe_async_still_answers_the_caller_when_the_probe_raises(monkeypatch):
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])

    def explode(timeout=None):
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(MP, "probe", explode)
    answers = []
    MP.probe_async(answers.append)
    end = time.monotonic() + 5
    while not answers and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)
    assert answers and not answers[0].ok
    assert "probe exploded" in answers[0].reason


def test_edge_start_twice_runs_one_probe(monkeypatch):
    calls = []
    gate = threading.Event()

    def slow(timeout=None):
        calls.append(1)
        gate.wait(5)
        return MP.ProbeResult(True)

    monkeypatch.setattr(MP, "probe", slow)
    MP.start()
    MP.start()
    gate.set()
    MP._starter.join(5)
    assert calls == [1]


# -- the child's own guards -------------------------------------------------------------------

@pytest.mark.parametrize("value", ["", "not-a-pid"])
def test_edge_an_invalid_parent_is_no_debugger_permission(monkeypatch, value):
    monkeypatch.setenv(MP.PARENT_ENV, value)
    MP._allow_parent_debugger()  # no exception, no prctl with garbage


def test_edge_the_child_guards_do_nothing_outside_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    MP._allow_parent_debugger()
    MP._die_with_parent()


# -- tls_env ---------------------------------------------------------------------------------

def test_happy_the_real_certifi_bundle_is_the_fallback():
    certifi = pytest.importorskip("certifi")
    env = {}
    chosen = TE.apply_ca_bundle(env, candidates=[], count=lambda: 0)
    assert chosen == certifi.where() and env["SSL_CERT_FILE"] == chosen


def test_sad_without_certifi_and_without_a_host_bundle_nothing_is_set(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_certifi(name, *a, **k):
        if name == "certifi":
            raise ImportError("no certifi")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_certifi)
    env = {}
    assert TE.apply_ca_bundle(env, candidates=[], count=lambda: 0) is None
    assert env == {}


def test_edge_a_candidate_whose_stat_fails_is_skipped(tmp_path, monkeypatch):
    good = tmp_path / "good.crt"
    good.write_text("-----BEGIN CERTIFICATE-----\nx\n")
    real_getsize = os.path.getsize

    def broken(path):
        if str(path).endswith("bad.crt"):
            raise OSError("I/O error")
        return real_getsize(path)

    (tmp_path / "bad.crt").write_text("x")
    monkeypatch.setattr(os.path, "getsize", broken)
    env = {}
    assert TE.apply_ca_bundle(env, candidates=[str(tmp_path / "bad.crt"), str(good)],
                              count=lambda: 0) == str(good)
