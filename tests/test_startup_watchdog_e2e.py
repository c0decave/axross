"""The real application, started as a subprocess, against a start that hangs.

Incident: axross-full showed no window and no message on a laptop where an
extension's activate() hung natively before the window was shown. These
tests start ``main.py`` from this tree (offscreen, isolated HOME) with an
extension whose activate() never returns and check the three layers:

* the startup watchdog writes every thread's stack to crash.log and says on
  stderr what happened and what to do, within its bound;
* a detached start (from a terminal) prints that message on the terminal;
* the next start skips the extension (it stays switched on) and the window
  comes; ``--safe-mode`` starts past it right away.

And the startup audit's dead mount: a restored pane and terminal whose
folder never answers no longer keep the window from appearing.
"""

from __future__ import annotations

import json
import os
import re
import select
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import startup_guard as SG  # noqa: E402

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and opens a pty"
)

#: The watchdog bound of a start that hangs in an extension. Its report
#: names the extension only when the start got that far within the bound;
#: on a busy host (a full parallel run) it had not after 4 s, so such a
#: start is made again with the next, longer bound (_hung_start).
HUNG_BOUNDS = (4.0, 15.0, 45.0)
BOUND = HUNG_BOUNDS[0]
#: How long the watchdog's message may take after the bound on a busy host
#: (the interpreter and Qt start first).
MESSAGE_GRACE = 60.0
#: How long a start may take to show its window on a busy host.
READY_SECONDS = 120.0

SLEEPER = """
EXTENSION = {"name": "Sleeper", "version": "1.0", "description": "never returns"}

import time


def activate(api):
    while True:
        time.sleep(3600)
"""


def _env(home: Path, marker: str, bound: float | None = BOUND, **extra) -> dict:
    """The start's environment; *bound* None leaves the watchdog at its
    default (SG.WATCHDOG_SECONDS), as users get it. A start that must say
    nothing gets that: on a busy host a start that does not hang took
    longer than 4 s to show its window, and was reported - rightly."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("AXROSS_")}
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_STATE_HOME=str(home / ".local" / "state"),
        XDG_CACHE_HOME=str(home / ".cache"),
        QT_QPA_PLATFORM="offscreen",
        PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
        AXROSS_TEST_MARKER=marker,
    )
    if bound is not None:
        env[SG.WATCHDOG_ENV] = str(bound)
    env.update(extra)
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    return env


def _logs(home: Path) -> Path:
    return home / ".local" / "state" / "axross" / "logs"


def _is_probe_child(pid: int) -> bool:
    try:
        args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    return b"--multimedia-probe" in args or b"core.multimedia_probe" in args


def _marked(marker: str) -> list[int]:
    found = []
    needle = f"AXROSS_TEST_MARKER={marker}".encode()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            environ = Path(f"/proc/{entry}/environ").read_bytes()
            state = Path(f"/proc/{entry}/stat").read_text().rsplit(")", 1)[-1].split()[0]
        except OSError:
            continue
        if needle in environ.split(b"\0") and state != "Z":
            found.append(int(entry))
    return found


def _kill_all(marker: str) -> None:
    for pid in _marked(marker):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    end = time.time() + 10
    while time.time() < end and _marked(marker):
        time.sleep(0.1)


#: Markers of the processes the running test started (killed afterwards).
_MARKERS: list[str] = []


def _new_marker() -> str:
    marker = uuid.uuid4().hex
    _MARKERS.append(marker)
    return marker


@pytest.fixture
def home(tmp_path):
    path = tmp_path / "home"
    (path / ".config" / "axross" / "extensions").mkdir(parents=True)
    yield path
    while _MARKERS:
        _kill_all(_MARKERS.pop())


def _with_sleeper(home: Path) -> None:
    (home / ".config" / "axross" / "extensions" / "sleeper.py").write_text(
        textwrap.dedent(SLEEPER))
    (home / ".config" / "axross" / "extensions.json").write_text(
        json.dumps({"enabled": ["user:sleeper"]}))


def _start(home: Path, *args: str, bound: float | None = BOUND,
           **extra) -> tuple[subprocess.Popen, str]:
    marker = _new_marker()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "main.py"), *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=ROOT, env=_env(home, marker, bound, **extra),
    )
    return proc, marker


def _says_nothing(home: Path, err: bytes) -> None:
    """A start that does not hang says nothing - unless this host was too
    busy to show its window within the watchdog's bound at all: then the
    report was right, the log says when the window came after all (later
    than the bound), and this check cannot be made here."""
    if b"has not appeared" not in err:
        return
    SG.wait_for(lambda: "appeared after all" in _read_log(home), 30.0)
    late = re.search(r"The main window appeared after all, after ([0-9.]+) s", _read_log(home))
    if late and float(late.group(1)) >= SG.WATCHDOG_SECONDS:
        pytest.skip(f"this host took {late.group(1)} s to show the window, longer than "
                    f"the watchdog's {SG.WATCHDOG_SECONDS:g} s")
    raise AssertionError(err[-3000:])


def _read_log(home: Path) -> str:
    try:
        return (_logs(home) / "axross.log").read_text()
    except OSError:
        return ""


def _attempt_home(home: Path, attempt: int) -> Path:
    """A home of its own for each try of a hung start: a try ended after
    it began activating the sleeper leaves a marker that would suspend the
    sleeper on the next try (the startup guard)."""
    if attempt == 0:
        return home
    path = home / f"try{attempt}"
    (path / ".config" / "axross" / "extensions").mkdir(parents=True)
    return path


def _reached_too_late(message: bytes, home: Path) -> bool:
    """The watchdog fired before the start reached the hung extension: the
    message does not name it and no thread is in sleeper.py yet."""
    try:
        crash = (_logs(home) / "crash.log").read_text()
    except OSError:
        crash = ""
    return b'"Sleeper"' not in message and "sleeper.py" not in crash


def _read_until(proc: subprocess.Popen, needle: bytes, seconds: float) -> tuple[bytes, bytes]:
    """stdout and stderr of *proc* until *needle* shows in either or it ends."""
    out = err = b""
    streams = {proc.stdout.fileno(): "out", proc.stderr.fileno(): "err"}
    end = time.time() + seconds
    while time.time() < end and streams:
        ready, _, _ = select.select(list(streams), [], [], 0.1)
        for fd in ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                streams.pop(fd)
                continue
            if streams[fd] == "out":
                out += chunk
            else:
                err += chunk
        if needle in out or needle in err:
            break
    return out, err


# --- happy -----------------------------------------------------------------


def test_happy_e2e_a_normal_start_says_nothing_and_writes_no_stacks(home):
    proc, _ = _start(home, bound=None, AXROSS_SMOKE_GUI_MS="0")
    out, err = proc.communicate(timeout=READY_SECONDS)
    assert proc.returncode == 0, err[-2000:]
    assert b"gui smoke: window shown" in out
    _says_nothing(home, err)
    crash = _logs(home) / "crash.log"
    assert SG.CRASH_HEADER not in crash.read_text()


def test_happy_e2e_safe_mode_starts_past_a_hung_extension(home):
    _with_sleeper(home)
    proc, _ = _start(home, "--safe-mode", bound=None, AXROSS_SMOKE_GUI_MS="0")
    out, err = proc.communicate(timeout=READY_SECONDS)
    assert proc.returncode == 0, err[-2000:]
    assert b"gui smoke: window shown" in out
    _says_nothing(home, err)
    log = (_logs(home) / "axross.log").read_text()
    assert "Safe mode: no extension loaded" in log


# --- sad -------------------------------------------------------------------


def test_sad_e2e_a_hung_extension_is_reported_then_skipped_on_the_next_start(home):
    for attempt, bound in enumerate(HUNG_BOUNDS):
        home_now = _attempt_home(home, attempt)
        _with_sleeper(home_now)
        proc, marker = _start(home_now, bound=bound, AXROSS_SMOKE_GUI_MS="0")
        started = time.time()
        out, err = _read_until(proc, b"What you can do", bound + MESSAGE_GRACE)
        took = time.time() - started
        if bound == HUNG_BOUNDS[-1] or not _reached_too_late(err, home_now):
            break
        _kill_all(marker)
        proc.wait(timeout=10)
    home = home_now
    assert f"has not appeared after {bound:g} s".encode() in err, (out[-1000:], err[-3000:])
    assert b'"Sleeper" (user:sleeper)' in err
    assert b"--safe-mode" in err
    assert b"gui smoke: window shown" not in out
    assert took < bound + MESSAGE_GRACE
    crash = (_logs(home) / "crash.log").read_text()
    assert SG.CRASH_HEADER in crash
    assert "sleeper.py" in crash  # the hung frame is in the stacks
    # The log comes last (after stderr) - wait for it, do not race it.
    assert SG.wait_for(
        lambda: "has not appeared" in (_logs(home) / "axross.log").read_text(), 30.0)
    hung_pid = proc.pid
    _kill_all(marker)  # the user ends the hung start
    proc.wait(timeout=10)

    again, _ = _start(home, bound=None, AXROSS_SMOKE_GUI_MS="0")
    out, err = again.communicate(timeout=READY_SECONDS)
    assert again.returncode == 0, err[-2000:]
    assert b"gui smoke: window shown" in out
    _says_nothing(home, err)
    log = (_logs(home) / "axross.log").read_text()
    assert f"Startup guard: process {hung_pid} ended" in log
    settings = json.loads((home / ".config" / "axross" / "extensions.json").read_text())
    assert settings["enabled"] == ["user:sleeper"]
    assert settings["suspended"] == ["user:sleeper"]


def _detached_hung_start(home: Path, bound: float) -> tuple[subprocess.Popen, str, bytes]:
    """A detached start (from a terminal) that hangs in the sleeper: the
    parent, its marker, and what the terminal showed until the parent ended."""
    import pty

    _with_sleeper(home)
    marker = _new_marker()
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "main.py")],
        stdin=slave, stdout=slave, stderr=slave, cwd=ROOT, env=_env(home, marker, bound),
    )
    os.close(slave)
    output = b""
    try:
        end = time.time() + bound + MESSAGE_GRACE + SG.DETACH_GRACE_SECONDS
        while time.time() < end and proc.poll() is None:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    output += os.read(master, 65536)
                except OSError:
                    break
        try:
            output += os.read(master, 65536)
        except OSError:
            pass
    finally:
        os.close(master)
    return proc, marker, output


def test_sad_e2e_a_detached_start_tells_the_terminal(home):
    for attempt, bound in enumerate(HUNG_BOUNDS):
        home_now = _attempt_home(home, attempt)
        proc, marker, output = _detached_hung_start(home_now, bound)
        if bound == HUNG_BOUNDS[-1] or not _reached_too_late(output, home_now):
            break
        _kill_all(marker)
    assert proc.wait(timeout=5) == 0
    assert f"has not appeared after {bound:g} s".encode() in output, output[-3000:]
    assert b'"Sleeper" (user:sleeper)' in output
    # Not the short-lived Qt Multimedia check (core.multimedia_probe).
    child = [p for p in _marked(marker) if p != proc.pid and not _is_probe_child(p)]
    assert child, "the background start should keep running"


def test_sad_e2e_a_restored_folder_on_a_dead_mount_does_not_hold_the_window(home, tmp_path):
    # The dead mount: stat/lstat/listdir/scandir below DEAD block forever,
    # in any thread, like a hard NFS mount whose server is gone.
    dead = f"/axross-dead-{uuid.uuid4().hex[:8]}"
    wrapper = tmp_path / "dead_mount_main.py"
    wrapper.write_text(textwrap.dedent(f"""
        import os, runpy, sys, threading
        DEAD = {dead!r}
        never = threading.Event()

        def wrap(real):
            def blocked(path, *args, **kwargs):
                text = path if isinstance(path, str) else (
                    os.fsdecode(path) if isinstance(path, (bytes, os.PathLike)) else "")
                if text.startswith(DEAD):
                    never.wait()
                return real(path, *args, **kwargs)
            return blocked

        for name in ("stat", "lstat", "listdir", "scandir"):
            setattr(os, name, wrap(getattr(os, name)))
        sys.path.insert(0, {str(ROOT)!r})
        sys.argv = [{str(ROOT / "main.py")!r}]
        runpy.run_path(sys.argv[0], run_name="__main__")
    """))
    (home / ".config" / "axross" / "session.json").write_text(json.dumps({
        "window": {"width": 1000, "height": 700},
        "workspaces": [{"name": "W1", "current": True, "splitter": {
            "type": "splitter", "children": [
                {"type": "pane", "local": True, "path": f"{dead}/projects", "active": True},
                {"type": "pane", "local": True, "path": str(home)},
                {"type": "terminal", "local": True, "cwd": f"{dead}/build"},
            ]}}],
    }))
    marker = _new_marker()
    proc = subprocess.Popen(
        [sys.executable, str(wrapper)], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
        env=_env(home, marker, None, AXROSS_SMOKE_GUI_MS="2000"),
    )
    out, err = _read_until(proc, b"gui smoke: window shown", READY_SECONDS)
    assert b"gui smoke: window shown" in out, err[-3000:]
    _says_nothing(home, err)


# --- edge ------------------------------------------------------------------


def test_edge_e2e_a_watchdog_switched_off_says_nothing_even_when_hung(home):
    _with_sleeper(home)
    proc, marker = _start(home, AXROSS_SMOKE_GUI_MS="0", **{SG.WATCHDOG_ENV: "0"})
    out, err = _read_until(proc, b"has not appeared", BOUND + 8)
    assert b"has not appeared" not in err
    assert proc.poll() is None  # still hung, as asked: nobody watches
    _kill_all(marker)


def test_edge_e2e_the_detached_parent_returns_once_the_window_is_shown(home):
    import pty

    marker = _new_marker()
    master, slave = pty.openpty()
    started = time.time()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "main.py")],
        stdin=slave, stdout=slave, stderr=slave, cwd=ROOT, env=_env(home, marker, None),
    )
    os.close(slave)
    try:
        assert proc.wait(timeout=READY_SECONDS) == 0
        took = time.time() - started
        if "has not appeared" in _read_log(home):  # the parent stopped waiting
            _says_nothing(home, b"has not appeared")
        log = (_logs(home) / "axross.log").read_text()
        # it returned because the child's window was up, not on a timer
        assert "Application ready" in log
        assert took < SG.WATCHDOG_SECONDS + SG.DETACH_GRACE_SECONDS
        output = b""
        while select.select([master], [], [], 0.2)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        assert output == b""
    finally:
        os.close(master)
