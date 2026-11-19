"""A Scripts dock run ends when axross is killed, with what it started.

Measured before: a dock run is a child in a session of its own; axross
kills its process group at a normal exit (atexit), but when axross itself
was killed (SIGKILL, the OOM killer, a crash) the script and every process
it had started ran on for ever - there is no deadline for an interactive
run. The worker children end with axross (PR_SET_PDEATHSIG); the dock's
child now watches the axross that started it and kills its own process
group once it is gone.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX")

_SCRIPT = """\
import os, subprocess, sys, time
grand = subprocess.Popen(["sleep", "120"])
print(os.getpid(), grand.pid, flush=True)
time.sleep(120)
"""

# The stand-in for axross: starts the run as the dock does (its own session,
# the dock's environment) and then waits to be killed.
_AXROSS = textwrap.dedent("""\
    import os, subprocess, sys, time
    sys.path.insert(0, {root!r})
    from core import script_runner as SR
    from core.security_mode import current_policy
    cmd = SR.build_command("spawner")
    env = SR.child_env(current_policy().name, watched={watched})
    subprocess.Popen(cmd.argv, cwd=cmd.cwd, env=env, start_new_session=True,
                     stdin=subprocess.DEVNULL)
    time.sleep(300)
""")


def _gone(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rsplit(b")", 1)[1].split()[0] == b"Z"
    except FileNotFoundError:
        return True
    except OSError:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        return False


def _start(tmp_path: Path, watched: bool):
    home = tmp_path / "home"
    scripts = home / ".config" / "axross" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "spawner.py").write_text(_SCRIPT, encoding="utf-8")
    env = dict(os.environ, HOME=str(home))
    env.pop("AXROSS_SCRIPT_PARENT", None)
    axross = subprocess.Popen(
        [sys.executable, "-c", _AXROSS.format(root=str(ROOT), watched=watched)],
        env=env, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=True,
    )
    line = axross.stdout.readline().decode().split()
    assert len(line) == 2, line
    return axross, int(line[0]), int(line[1])


def _cleanup(*pids: int) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def test_sad_the_run_and_its_children_end_when_axross_is_killed(tmp_path):
    axross, child, grand = _start(tmp_path, watched=True)
    try:
        assert not _gone(child) and not _gone(grand)
        axross.kill()
        axross.wait(10)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (_gone(child) and _gone(grand)):
            time.sleep(0.05)
        assert _gone(child), "the script ran on after axross was killed"
        assert _gone(grand), "what the script started ran on after axross was killed"
    finally:
        _cleanup(child, grand, axross.pid)


def test_happy_the_run_keeps_running_while_axross_lives(tmp_path):
    axross, child, grand = _start(tmp_path, watched=True)
    try:
        time.sleep(1.5)
        assert not _gone(child) and not _gone(grand)
    finally:
        _cleanup(child, grand, axross.pid)
        axross.wait(10)


def test_happy_the_parent_variable_is_not_inherited_by_the_script(tmp_path):
    from core import script_runner as SR

    env = SR.child_env("normal", watched=True)
    assert env[SR.PARENT_ENV] == str(os.getpid())
    os.environ[SR.PARENT_ENV] = "1"
    try:
        assert SR.PARENT_ENV not in SR.child_env("normal")
    finally:
        del os.environ[SR.PARENT_ENV]
