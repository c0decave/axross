"""Started from a terminal, axross gives the terminal back at once.

Operator (punch list 50): "axross soll beim normalen aufruf praktisch im
hintergrund laufen und man soll auf der cli (es sei denn es wurde z.b. mit
verbose oder debug gestartet und oder --foreground) keinen output haben und
die cli wieder normal nutzen können."

Before, ``axross`` in a shell kept the prompt until the window closed and
printed Qt's warnings into it. Now the GUI start re-executes itself in a new
session with stdin/stdout/stderr on /dev/null and the first process exits
0 without a word; logs still go to the log file. These tests start the real
``main.py`` on a pseudo-terminal, with an isolated HOME and offscreen Qt.
"""

from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc and opens a pty"
)

#: The parent of a detached start returns this fast (it imports no Qt).
PARENT_SECONDS = 20.0
#: How long a GUI start may take to log "Application ready" on a busy host.
READY_SECONDS = 120.0


def _env(tmp_path: Path, marker: str, **extra) -> dict:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
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
        **extra,
    )
    return env


def _log_file(tmp_path: Path) -> Path:
    return tmp_path / "home" / ".local" / "state" / "axross" / "logs" / "axross.log"


def _marked(marker: str) -> list[int]:
    """Live processes whose environment carries *marker*."""
    found = []
    needle = f"AXROSS_TEST_MARKER={marker}".encode()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            environ = Path(f"/proc/{entry}/environ").read_bytes()
            state = Path(f"/proc/{entry}/stat").read_text().split(")")[-1].split()[0]
        except OSError:
            continue
        if needle in environ.split(b"\0") and state != "Z":
            found.append(int(entry))
    return found


def _kill(pids) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    end = time.time() + 15
    while time.time() < end and any(Path(f"/proc/{p}").exists() and _alive(p) for p in pids):
        time.sleep(0.1)
    for pid in pids:
        if _alive(pid):
            os.kill(pid, signal.SIGKILL)


def _alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0]
    except OSError:
        return False
    return state != "Z"


class _Terminal:
    """``main.py`` with a pseudo-terminal as stdin, stdout and stderr."""

    def __init__(self, tmp_path: Path, *args: str, **env_extra) -> None:
        import pty

        self.marker = uuid.uuid4().hex
        self.tmp_path = tmp_path
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "main.py"), *args],
            stdin=slave, stdout=slave, stderr=slave, cwd=ROOT,
            env=_env(tmp_path, self.marker, **env_extra),
        )
        os.close(slave)
        self.output = b""

    def read(self, seconds: float = 0.5) -> bytes:
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:  # every slave end closed
                    break
                if not chunk:
                    break
                self.output += chunk
        return self.output

    def wait(self, seconds: float) -> int | None:
        try:
            return self.proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            return None

    def wait_ready(self) -> bool:
        log = _log_file(self.tmp_path)
        end = time.time() + READY_SECONDS
        while time.time() < end:
            self.read(0.2)
            if log.exists() and "Application ready" in log.read_text(errors="replace"):
                return True
        return False

    def close(self) -> None:
        pids = _marked(self.marker)
        if self.proc.poll() is None:
            pids.append(self.proc.pid)
        _kill(pids)
        self.proc.wait(timeout=15)
        os.close(self.master)


@pytest.fixture
def terminal(tmp_path):
    started: list[_Terminal] = []

    def start(*args: str, **env_extra) -> _Terminal:
        term = _Terminal(tmp_path, *args, **env_extra)
        started.append(term)
        return term

    yield start
    for term in started:
        term.close()


# --- happy -----------------------------------------------------------------


def test_happy_e2e_a_plain_start_returns_at_once_silent_and_the_window_lives_on(terminal):
    term = terminal()
    start = time.time()
    code = term.wait(PARENT_SECONDS)
    assert code == 0, term.read()
    assert time.time() - start < PARENT_SECONDS
    assert term.wait_ready(), "the detached child never logged 'Application ready'"
    (child,) = [p for p in _marked(term.marker) if p != term.proc.pid]
    assert _alive(child)
    assert os.getsid(child) == child  # its own session: no controlling terminal
    for fd in (0, 1, 2):
        assert os.readlink(f"/proc/{child}/fd/{fd}") == "/dev/null"
    assert term.read(1.0) == b""  # not one byte on the terminal


def test_happy_e2e_foreground_keeps_the_terminal(terminal):
    term = terminal("--foreground")
    assert term.wait_ready()
    assert term.proc.poll() is None  # the started process IS the window
    assert _marked(term.marker) == [term.proc.pid]


@pytest.mark.parametrize("flag", ["--debug", "--verbose"])
def test_happy_e2e_debug_and_verbose_stay_and_talk(terminal, flag):
    term = terminal(flag)
    assert term.wait_ready()
    assert term.proc.poll() is None
    assert _marked(term.marker) == [term.proc.pid]
    assert b"Starting Axross" in term.read(1.0)


# --- sad: modes that print or talk over stdio never detach -----------------


@pytest.mark.parametrize(
    ("args", "expect"),
    [
        (("--version",), b"axross "),
        (("--help",), b"usage:"),
        (("--mcp-list-tools",), b'"tools"'),
    ],
)
def test_sad_printing_modes_print_and_exit_in_the_terminal(terminal, args, expect):
    term = terminal(*args)
    code = term.wait(READY_SECONDS)
    assert code == 0
    assert expect in term.read(1.0)
    assert _marked(term.marker) == []


def test_sad_a_script_runs_in_the_terminal(terminal, tmp_path):
    script = tmp_path / "job.py"
    script.write_text("print('from the script')\nraise SystemExit(3)\n")
    term = terminal("--script", str(script))
    assert term.wait(READY_SECONDS) == 3
    assert b"from the script" in term.read(1.0)
    assert _marked(term.marker) == []


def test_sad_the_analysis_worker_keeps_its_stdio_channel(terminal):
    term = terminal("--analysis-worker")
    # It reads requests from stdin until EOF (or stops at once without sift):
    # either way in this process, never in a detached one.
    term.wait(5.0)
    assert [p for p in _marked(term.marker) if p != term.proc.pid] == []


def test_sad_output_to_a_pipe_is_not_a_terminal_start(tmp_path):
    """A launcher or a script that reads axross's output (the bundle smoke,
    systemd, a desktop file) waits for the process it started: no detach."""
    marker = uuid.uuid4().hex
    proc = subprocess.run(
        [sys.executable, str(ROOT / "main.py")],
        capture_output=True, text=True, timeout=READY_SECONDS, cwd=ROOT,
        env=_env(tmp_path, marker, AXROSS_SMOKE_GUI_MS="0"),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "gui smoke: window shown" in proc.stdout
    assert _marked(marker) == []


# --- edge ------------------------------------------------------------------


def _args(*argv):
    import main

    return main.build_parser().parse_args(list(argv))


class _Stream:
    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


TTY, PIPE = _Stream(True), _Stream(False)


X11 = {"DISPLAY": ":0"}


@pytest.mark.parametrize(
    ("argv", "environ", "streams", "system", "detach"),
    [
        ((), X11, (TTY, TTY), "linux", True),
        ((), {"WAYLAND_DISPLAY": "wayland-0"}, (TTY, TTY), "linux", True),
        ((), {"QT_QPA_PLATFORM": "offscreen"}, (TTY, TTY), "linux", True),
        ((), {}, (TTY, TTY), "darwin", True),  # macOS: no DISPLAY to look at
        ((), X11, (PIPE, TTY), "linux", True),  # axross > file: stderr still a tty
        ((), X11, (PIPE, PIPE), "linux", False),
        ((), {}, (TTY, TTY), "linux", False),  # ssh without X: the error must show
        (("--foreground",), X11, (TTY, TTY), "linux", False),
        (("--debug",), X11, (TTY, TTY), "linux", False),
        (("--verbose",), X11, (TTY, TTY), "linux", False),
        (("--script", "x.py"), X11, (TTY, TTY), "linux", False),
        (("--mcp-server",), X11, (TTY, TTY), "linux", False),
        (("--mcp-list-tools",), X11, (TTY, TTY), "linux", False),
        ((), {**X11, "AXROSS_MCP": "1"}, (TTY, TTY), "linux", False),
        ((), {**X11, "AXROSS_SMOKE_GUI_MS": "0"}, (TTY, TTY), "linux", False),
        ((), {**X11, "AXROSS_DETACHED": "1"}, (TTY, TTY), "linux", False),  # the child
    ],
)
def test_edge_who_detaches(argv, environ, streams, system, detach):
    import main

    assert main.should_detach(_args(*argv), environ, streams, "posix", system) is detach


def test_edge_windows_never_detaches():
    import main

    assert main.should_detach(_args(), X11, (TTY, TTY), "nt", "win32") is False


def test_edge_a_failed_spawn_falls_back_to_the_foreground(monkeypatch):
    import main

    def refuse(*_a, **_k):
        raise OSError("fork failed")

    monkeypatch.setattr(main.subprocess, "Popen", refuse)
    assert main.detach_from_terminal() is False


def test_edge_the_child_command_is_the_same_start(monkeypatch):
    import main

    seen = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs) -> None:
            seen.update(cmd=cmd, **kwargs)

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="axross", timeout=timeout)

    monkeypatch.setattr(main.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(sys, "orig_argv", [sys.executable, "-X", "utf8", "main.py", "/srv"])
    assert main.detach_from_terminal() is True
    assert seen["cmd"] == [sys.executable, "-X", "utf8", "main.py", "/srv"]
    assert seen["start_new_session"] is True
    assert seen["stdin"] is seen["stdout"] is seen["stderr"] is subprocess.DEVNULL
    assert seen["env"]["AXROSS_DETACHED"] == "1"
    assert "AXROSS_DETACHED" not in os.environ


def test_edge_a_frozen_child_extracts_itself_again(monkeypatch):
    # dist/axross-full 0.13.22 started from a shell showed only "Unexpected
    # Error: FileNotFoundError ... _MEI.../base_library.zip": the child used
    # the first process's extraction folder, deleted when that one exited.
    import main

    seen = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs) -> None:
            seen.update(cmd=cmd, **kwargs)

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="axross", timeout=timeout)

    monkeypatch.setattr(main.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", ["/opt/axross-full"])
    monkeypatch.setenv("_PYI_APPLICATION_HOME_DIR", "/tmp/_MEIparent")
    monkeypatch.setenv("_PYI_ARCHIVE_FILE", "/opt/axross-full")
    assert main.detach_from_terminal() is True
    env = seen["env"]
    assert env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert not [k for k in env if k.startswith("_PYI_")]
    assert env["AXROSS_DETACHED"] == "1"


def test_sad_a_child_that_dies_at_once_is_not_hidden(monkeypatch, capsys):
    # A child that ends within the first moment with an error would vanish
    # without a word (its stdio is /dev/null): the start runs in the
    # foreground instead, where the error reaches the terminal.
    import main

    class DeadPopen:
        def __init__(self, cmd, **kwargs) -> None:
            pass

        def wait(self, timeout=None):
            return 1

    monkeypatch.setattr(main.subprocess, "Popen", DeadPopen)
    assert main.detach_from_terminal() is False
    assert "foreground" in capsys.readouterr().err


def test_edge_a_child_that_ends_cleanly_at_once_counts_as_started(monkeypatch):
    import main

    class QuickPopen:
        def __init__(self, cmd, **kwargs) -> None:
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(main.subprocess, "Popen", QuickPopen)
    assert main.detach_from_terminal() is True


_FROZEN_BINARY = os.environ.get("AXROSS_FROZEN_BINARY", "")


@pytest.mark.skipif(not (_FROZEN_BINARY and os.access(_FROZEN_BINARY, os.X_OK)),
                    reason="set AXROSS_FROZEN_BINARY to a built axross-full/slim")
def test_happy_e2e_the_frozen_binary_detaches_and_keeps_its_files(tmp_path):
    # The real one-file binary on a pty: the parent returns 0, the child logs
    # "Application ready", and every extraction folder a live axross process
    # points at still exists after the parent and its bootloader are gone.
    import pty

    marker = uuid.uuid4().hex
    master, slave = pty.openpty()
    env = _env(tmp_path, marker, TMPDIR=str(tmp_path))
    proc = subprocess.Popen([_FROZEN_BINARY], stdin=slave, stdout=slave, stderr=slave, env=env)
    os.close(slave)
    try:
        assert proc.wait(timeout=PARENT_SECONDS) == 0
        log = _log_file(tmp_path)
        end = time.time() + READY_SECONDS
        while time.time() < end and not (log.exists() and "Application ready" in log.read_text(
                errors="replace")):
            time.sleep(0.2)
        time.sleep(5)  # the first process's bootloader cleans up meanwhile
        text = log.read_text(errors="replace") if log.exists() else ""
        assert "Application ready" in text
        assert "base_library.zip" not in text and "FileNotFoundError" not in text
        live = [p for p in _marked(marker) if p != proc.pid]
        assert live, "no axross process lives on"
        for pid in live:
            home = dict(v.split(b"=", 1) for v in
                        Path(f"/proc/{pid}/environ").read_bytes().split(b"\0") if b"=" in v)
            folder = home.get(b"_PYI_APPLICATION_HOME_DIR")
            if folder:
                assert Path(folder.decode()).is_dir(), f"{pid} runs from a deleted {folder!r}"
    finally:
        _kill(_marked(marker))
        os.close(master)


def test_edge_the_child_forgets_the_marker_so_its_own_children_can_detach(monkeypatch):
    import main

    environ = {"AXROSS_DETACHED": "1", "PATH": "/bin"}
    assert main.consume_detached_marker(environ) is True
    assert environ == {"PATH": "/bin"}
    assert main.consume_detached_marker(environ) is False
