"""The Scripts dock's Stop ends what the script started (review round 3).

Before: Stop and closing the window terminated only the direct child, so
a script's ``subprocess.run(["sleep", "987"])`` - or any helper it
started - went on running after "stopped". Now the child leads a session
(and process group) of its own, and Stop and the window close signal the
whole group, as ``core.script_runner.run_bounded`` does for scheduled runs.
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
if os.name != "posix":  # pragma: no cover
    pytest.skip("process groups are POSIX", allow_module_level=True)

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import script_runner as SR  # noqa: E402
from core import scripting  # noqa: E402
from ui import scripts_dock as SD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(predicate, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.02)
    APP.processEvents()
    return predicate()


def _alive(pid: int) -> bool:
    """Running - a zombie waiting for its reaper counts as gone."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False
    except OSError:  # no /proc: ask the kernel
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True


#: Starts one helper process, prints its pid and waits for it.
_SCRIPT = (
    "import subprocess, sys\n"
    "helper = subprocess.Popen([sys.executable, '-c', {code!r}])\n"
    "print('helper', helper.pid, flush=True)\n"
    "helper.wait()\n"
)
_SLEEPER = "import time; time.sleep(120)"
_STUBBORN = ("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
             "print('ready', flush=True); time.sleep(120)")


@pytest.fixture()
def script():
    made: list[str] = []

    def _save(code: str) -> str:
        name = f"t_group_{uuid.uuid4().hex[:8]}"
        made.append(name)
        scripting.save_script(name, _SCRIPT.format(code=code))
        return name

    yield _save
    for name in made:
        scripting.delete_script(name)


@pytest.fixture()
def run_of():
    runs: list[SD.ScriptRun] = []
    helpers: list[int] = []

    def _start(name: str, *, ready: str = ""):
        run = SD.ScriptRun(SR.build_command(name), SR.child_env("normal", watched=True))
        out: list[str] = []
        run.output.connect(lambda text, _err: out.append(text))
        run.ended_text = []
        run.ended.connect(run.ended_text.append)
        runs.append(run)
        run.start()
        assert _wait(lambda: "helper " in "".join(out)), "the script did not start its helper"
        if ready:
            assert _wait(lambda: ready in "".join(out)), "the helper did not get ready"
        pid = int("".join(out).split("helper ", 1)[1].split()[0])
        helpers.append(pid)
        return run, pid

    yield _start
    for run in runs:
        run.shutdown()
    for pid in helpers:  # never leave one behind, whatever the test found
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass


def test_sad_stop_ends_the_process_the_script_started(script, run_of):
    run, helper = run_of(script(_SLEEPER))
    assert _alive(helper)
    run.stop()
    assert _wait(lambda: bool(run.ended_text)), "the run did not end"
    assert "stopped" in run.ended_text[0]
    assert _wait(lambda: not _alive(helper), 10), "the script's helper is still running"


def test_sad_closing_the_window_ends_the_process_the_script_started(script, run_of):
    run, helper = run_of(script(_SLEEPER))
    run.shutdown()  # what the dock does when the window closes
    assert _wait(lambda: not _alive(helper), 10), "the script's helper is still running"


def test_edge_a_helper_that_ignores_terminate_is_killed_after_the_grace(script, run_of):
    """The script itself ends on SIGTERM; its helper ignores it and is
    killed once the grace period is over - after the run has ended."""
    with mock.patch.object(SR, "STOP_GRACE_SECONDS", 0.5):
        run, helper = run_of(script(_STUBBORN), ready="ready")
        group = run.pid()
        run.stop()
        assert _wait(lambda: bool(run.ended_text))
        assert _wait(lambda: not _alive(helper), 10), "the stubborn helper is still running"
    assert group not in SR._LIVE_GROUPS  # no longer killed when axross exits
