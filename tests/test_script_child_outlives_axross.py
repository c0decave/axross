"""A bounded script child never outlives axross past its time limit.

``core.script_runner.run_bounded`` (scheduled script jobs, the MCP
``script_run`` tool) enforced the time limit only from a thread of the
axross process. When axross ended while a run was in flight - the user
quits during a scheduled job, a crash, a SIGKILL - nothing enforced it any
more: the child, in a session of its own, ran on for good (measured: a
script sleeping 600 s with a 3 s limit was still running 4 s after its
limit, after a normal exit and after a SIGKILL of the parent). The same
class as the multimedia probe child (core.multimedia_probe, 0.13.119).

Two layers now: a normal exit kills the process group of every run still
in flight (atexit), and the child ends itself past its limit plus the stop
grace (a faulthandler timer: a C thread, it needs no GIL), which also holds
when axross was killed or crashed.
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

from core import script_runner as SR  # noqa: E402
from core import scripting  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a zombie counts as gone
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return True


def _parent(tmp_path: Path, ending: str, timeout_s: float = 3.0) -> int:
    """Run a parent process that starts a bounded run of a script sleeping
    600 s, waits until the child is up, then ends with *ending*; returns the
    pid of the script child (written by the script itself)."""
    pidfile = tmp_path / "child.pid"
    name = f"sleeper_{os.getpid()}"
    scripting.save_script(name, textwrap.dedent(f"""
        import os, time
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        time.sleep(600)
    """))
    code = textwrap.dedent(f"""
        import os, sys, threading, time
        sys.path.insert(0, {str(ROOT)!r})
        from core import script_runner
        threading.Thread(target=lambda: script_runner.run_bounded(
            {name!r}, timeout_s={timeout_s}, max_output_chars=1000), daemon=True).start()
        for _ in range(400):
            if os.path.exists({str(pidfile)!r}) and os.path.getsize({str(pidfile)!r}):
                break
            time.sleep(0.025)
        {ending}
    """)
    try:
        subprocess.run([sys.executable, "-c", code], timeout=60, capture_output=True)
        return int(pidfile.read_text())
    finally:
        scripting.delete_script(name)


def _wait_gone(pid: int, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return not _alive(pid)


def _reap(pid: int) -> None:
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass


# -- happy ----------------------------------------------------------------------------------

def test_happy_a_normal_exit_ends_the_run_in_flight_at_once(tmp_path):
    pid = _parent(tmp_path, "sys.exit(0)")
    try:
        assert _wait_gone(pid, 2.0), "the script child outlived the normal exit"
    finally:
        _reap(pid)


def test_happy_a_run_that_ends_by_itself_leaves_nothing_tracked(tmp_path):
    name = f"quick_{os.getpid()}"
    scripting.save_script(name, "print('hi')\n")
    try:
        run = SR.run_bounded(name, timeout_s=30, max_output_chars=1000)
    finally:
        scripting.delete_script(name)
    assert run.exit == 0 and "hi" in run.stdout
    assert SR._LIVE_GROUPS == set()


# -- sad ------------------------------------------------------------------------------------

def test_sad_a_killed_parent_leaves_a_child_that_ends_itself_after_its_limit(tmp_path):
    """SIGKILL skips atexit: the child's own timer ends it, at its limit
    plus the stop grace, not 600 s later."""
    pid = _parent(tmp_path, "os.kill(os.getpid(), 9)", timeout_s=1.0)
    try:
        bound = 1.0 + SR.STOP_GRACE_SECONDS + SR.CHILD_DEADLINE_MARGIN + 3.0
        assert _wait_gone(pid, bound), "the script child outlived its limit"
    finally:
        _reap(pid)


def test_sad_a_deadline_env_that_is_no_number_arms_nothing(monkeypatch):
    for value in ("", "x", "nan", "inf", "-1", "0"):
        monkeypatch.setenv(SR.DEADLINE_ENV, value)
        assert SR._arm_own_deadline() is None
        assert SR.DEADLINE_ENV not in os.environ


# -- edge -----------------------------------------------------------------------------------

def test_edge_the_child_deadline_comes_after_the_parents_soft_stop():
    """The parent's SIGTERM at the limit (with its grace) normally wins;
    the child's own exit is the backstop."""
    assert SR.child_deadline(5.0) == 5.0 + SR.STOP_GRACE_SECONDS + SR.CHILD_DEADLINE_MARGIN
    assert SR.CHILD_DEADLINE_MARGIN > 0


def test_edge_the_deadline_is_not_passed_on_to_what_the_script_starts(monkeypatch):
    import faulthandler

    monkeypatch.setenv(SR.DEADLINE_ENV, "123.5")
    try:
        assert SR._arm_own_deadline() == 123.5
        assert SR.DEADLINE_ENV not in os.environ
    finally:
        faulthandler.cancel_dump_traceback_later()


def test_edge_a_timed_out_run_still_reports_a_timeout_not_the_childs_own_exit(tmp_path):
    name = f"slow_{os.getpid()}"
    scripting.save_script(name, "import time\ntime.sleep(60)\n")
    try:
        run = SR.run_bounded(name, timeout_s=0.5, max_output_chars=1000)
    finally:
        scripting.delete_script(name)
    assert run.timed_out is True
    assert SR._LIVE_GROUPS == set()


def test_edge_an_exit_with_no_run_in_flight_kills_nothing(monkeypatch):
    killed = []
    monkeypatch.setattr(os, "killpg", lambda pid, sig: killed.append(pid))
    SR._kill_live_groups()
    assert killed == []
