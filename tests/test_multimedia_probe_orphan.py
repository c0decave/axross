"""A hung Qt Multimedia probe child never outlives axross.

Measured: the app started under a hanging NVIDIA driver with the GPU-probe
switch on (Qt really calls cuInit) and quit after the window came; the
probe child (``python -m core.multimedia_probe``) was still there 25 s
later with parent pid 1. Only a daemon thread of the GUI process enforced
the bound, and it died with the process - every start that ends within
the bound left a hung process behind.

Three layers: the child ends itself after the bound (a faulthandler timer,
a C thread that needs no GIL); on Linux it dies with its parent
(PR_SET_PDEATHSIG); a normal exit of the parent kills it (atexit).
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

from core import multimedia_probe as MP  # noqa: E402
from tests import hanging_gpu_driver as HGD  # noqa: E402

_PARENT = textwrap.dedent("""\
    import os, sys, threading, time
    sys.path.insert(0, {root!r})
    from core import multimedia_probe as MP
    command = {command!r}
    threading.Thread(target=MP.run_probe, kwargs=dict(timeout=60, command=command),
                     daemon=True).start()
    deadline = time.monotonic() + 30
    while not MP._LIVE and time.monotonic() < deadline:
        time.sleep(0.05)
    print(next(iter(MP._LIVE)).pid, flush=True)
    time.sleep(1.5)  # the child is inside the hanging call by now
    {leave}
""")


def _gone(pid: int, within: float) -> bool:
    deadline = time.monotonic() + within
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    return False


def _hanging_command(tmp_path) -> list[str]:
    reason = HGD.available()
    if reason:
        pytest.skip(reason)
    lib = HGD.build(tmp_path / "gpu")
    return HGD.command(lib, MP.probe_command())


def _env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("QT_FFMPEG_", "AXROSS_"))}
    env.update(QT_QPA_PLATFORM="offscreen")
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    return env


def _parent(tmp_path, leave: str) -> int:
    """Run a parent that starts the probe under the hanging driver and then
    leaves as *leave* says; the child's pid."""
    code = _PARENT.format(root=str(ROOT), command=_hanging_command(tmp_path), leave=leave)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       timeout=60, env=_env(), cwd=str(ROOT))
    lines = r.stdout.split()
    assert lines, r.stderr[-1500:]
    return int(lines[0])


def _kill_if_alive(pid: int) -> None:
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass


# -- happy -------------------------------------------------------------------

def test_happy_a_normal_exit_of_axross_takes_the_hung_child(tmp_path):
    pid = _parent(tmp_path, "sys.exit(0)")
    try:
        assert _gone(pid, 5), "the probe child outlived a normal exit"
    finally:
        _kill_if_alive(pid)


def test_happy_a_finished_probe_is_no_longer_tracked():
    result = MP.run_probe(timeout=30, command=[sys.executable, "-c", "print('{\"ok\": true}')"])
    assert result.ok
    assert not MP._LIVE


# -- sad ---------------------------------------------------------------------

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux")
def test_sad_axross_killed_hard_takes_the_hung_child(tmp_path):
    """os._exit skips atexit, like a crash or SIGKILL."""
    pid = _parent(tmp_path, "os._exit(0)")
    try:
        assert _gone(pid, 5), "the probe child outlived its killed parent"
    finally:
        _kill_if_alive(pid)


def test_sad_the_atexit_hook_survives_a_child_that_is_already_gone():
    proc = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    proc.wait()
    MP._LIVE.add(proc)
    try:
        MP._kill_live()  # no exception for a reaped child
    finally:
        MP._LIVE.discard(proc)


# -- edge --------------------------------------------------------------------

def test_edge_the_child_ends_itself_after_its_deadline(tmp_path):
    """No parent kills it (the parent's watcher thread is gone, or another
    platform without PR_SET_PDEATHSIG): the child's own timer does."""
    command = _hanging_command(tmp_path)
    env = {**_env(), MP.DEADLINE_ENV: "2"}
    start = time.monotonic()
    try:
        r = subprocess.run(command, capture_output=True, text=True, timeout=30, env=env,
                           cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        pytest.fail("the hung probe child did not end itself within 30 s")
    took = time.monotonic() - start
    assert r.returncode != 0
    assert took < 15, took


def test_edge_the_deadline_the_child_gets_is_past_the_parents_bound():
    assert MP.child_deadline(15.0) > 15.0
    assert MP.child_deadline(1.0) > 1.0


def test_edge_a_deadline_that_is_no_number_leaves_the_child_unbounded_by_it(monkeypatch):
    monkeypatch.setenv(MP.DEADLINE_ENV, "soon")
    assert MP._own_deadline() is None
    monkeypatch.setenv(MP.DEADLINE_ENV, "-3")
    assert MP._own_deadline() is None
    monkeypatch.setenv(MP.DEADLINE_ENV, "4.5")
    assert MP._own_deadline() == 4.5


def test_happy_the_exit_hook_kills_a_tracked_child_that_still_runs():
    """The layer for every platform: Linux's PR_SET_PDEATHSIG covers the
    e2e above as well, so the hook itself is checked here."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"],
                            start_new_session=True)
    MP._LIVE.add(proc)
    try:
        MP._kill_live()
        assert proc.wait(timeout=10) < 0
    finally:
        MP._LIVE.discard(proc)
        if proc.poll() is None:
            proc.kill()


def test_edge_a_normal_exit_kills_a_tracked_child_without_the_kernel_layer():
    """A plain sleeping child has no PR_SET_PDEATHSIG: only the exit hook
    of the parent can end it."""
    code = textwrap.dedent("""\
        import subprocess, sys
        sys.path.insert(0, {root!r})
        from core import multimedia_probe as MP
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"],
                                start_new_session=True, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        MP._LIVE.add(proc)
        print(proc.pid, flush=True)
    """).format(root=str(ROOT))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    pid = int(r.stdout.split()[0])
    try:
        assert _gone(pid, 5), "the exit hook did not kill the tracked child"
    finally:
        _kill_if_alive(pid)
