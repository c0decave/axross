"""The startup watchdog: a main window that does not come up is reported.

A GUI start that hangs before its window is shown looks like nothing at
all: the process runs, no window comes, and nobody says a word (seen with
an NVIDIA driver that hung in cuInit inside an extension's activate()).
:class:`StartupWatchdog` is armed by main.py before anything of the GUI is
built and cancelled once the event loop runs with the window shown. When
the bound passes first it

* writes every thread's stack to crash.log, after a header line,
* says on stderr and in the log what happened, where the stacks are and
  what the user can do (``--safe-mode`` loads no extension; an extension
  that was being activated is skipped on the next start anyway), and
* tells the parent of a detached start (main.detach_from_terminal), whose
  stderr is still the user's terminal, through an inherited pipe:
  JSON lines ``{"event": "shown"}`` and ``{"event": "stalled",
  "message": ...}``. :func:`await_detached_child` is that parent's side.

Two layers write the stacks: a Python thread (it also writes the message;
PyQt releases the GIL while Qt runs, so it gets to run while the main
thread hangs in native code) and faulthandler's own C timer
:data:`BACKSTOP_SECONDS` later, for a main thread that holds the GIL. The
Python thread cancels the backstop once it has written them.

Qt-free: main.py uses it before Qt is imported.
"""

from __future__ import annotations

import json
import logging
import math
import os
import stat
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)

#: How long a GUI start may take until its window is shown. A warm start
#: with a restored layout and every bundled extension takes about 1 s
#: (0.75-1.05 s measured from "Starting Axross" to "Application ready");
#: 20 s leaves a cold start on a slow disk room and still reports a hang
#: while the user is waiting for the window. The watchdog only reports, it
#: never ends the process: a false alarm costs a message, not the window.
WATCHDOG_SECONDS = 20.0
#: Seconds as a number; 0 switches the watchdog off.
WATCHDOG_ENV = "AXROSS_STARTUP_WATCHDOG_SECONDS"
#: How much later faulthandler's own timer writes the stacks when the
#: Python watchdog thread could not run.
BACKSTOP_SECONDS = 5.0
#: The write end of the pipe to the parent of a detached start.
NOTIFY_FD_ENV = "AXROSS_DETACHED_NOTIFY_FD"
#: How much longer than the child's bound the parent of a detached start
#: waits: the child arms its watchdog only after the interpreter (or a
#: frozen one-file build, which unpacks itself first) has started.
DETACH_GRACE_SECONDS = 10.0
#: The header of the watchdog's block in crash.log.
CRASH_HEADER = "startup watchdog: the main window"


def watchdog_seconds(environ=os.environ) -> float:
    """The bound from :data:`WATCHDOG_ENV`: a number of seconds, 0 for
    off; anything else (no number, negative, nan, inf) is the default."""
    raw = environ.get(WATCHDOG_ENV)
    if raw is None:
        return WATCHDOG_SECONDS
    try:
        value = float(raw)
    except ValueError:
        return WATCHDOG_SECONDS
    if not math.isfinite(value) or value < 0:
        return WATCHDOG_SECONDS
    return value


def wait_for(cond: Callable[[], bool], seconds: float, step: float = 0.02) -> bool:
    """Poll *cond* until it holds or *seconds* pass; its last value."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(step)
    return bool(cond())


def take_notify_fd(environ=os.environ) -> int | None:
    """The detached parent's pipe, from :data:`NOTIFY_FD_ENV`; the variable
    is removed either way. Only an open pipe counts (a stale number could
    name any descriptor), and it is made non-inheritable at once: a shell
    or worker started later must not hold the parent's pipe open."""
    raw = environ.pop(NOTIFY_FD_ENV, None)
    if raw is None:
        return None
    try:
        fd = int(raw)
        if fd < 0 or not stat.S_ISFIFO(os.fstat(fd).st_mode):
            return None
        os.set_inheritable(fd, False)
    except (ValueError, OSError):
        return None
    return fd


def _current_activation():
    """The extension being activated right now, from core.extensions -
    only when that module is loaded already (never imported from here)."""
    module = sys.modules.get("core.extensions")
    probe = getattr(module, "current_activation", None)
    return probe() if callable(probe) else None


def _how_to_end(pid: int) -> str:
    if os.name == "nt":
        return f"end it in the Task Manager (pid {pid})"
    return f'end it with "kill {pid}"'


def stall_message(seconds: float, pid: int, crash_path, activation=None) -> str:
    """What the user reads when the window has not come within *seconds*."""
    lines = [f"axross: the main window has not appeared after {seconds:g} s (pid {pid})."]
    if activation:
        ext_id, name, _running = activation
        lines.append(
            f'It is stuck activating the extension "{name}" ({ext_id}); '
            "the next start does not load it."
        )
    if crash_path:
        lines.append(f"Every thread's stack is in {crash_path} (below \"{CRASH_HEADER}\").")
    else:
        lines.append("The stacks could not be written (no crash log).")
    lines.append(
        "What you can do: wait a little longer (a slow disk or network can take "
        f"this long), or {_how_to_end(pid)} and start \"axross --safe-mode\", which "
        "loads no extension."
        + (f" Please attach {crash_path} to a bug report." if crash_path else "")
    )
    return "\n".join(lines)


def _send(fd: int | None, event: dict) -> bool:
    """One JSON line to the detached parent; False when it is gone."""
    if fd is None:
        return False
    try:
        os.write(fd, (json.dumps(event) + "\n").encode("utf-8"))
    except OSError:  # EPIPE: the parent exited; EBADF: closed
        return False
    return True


class StartupWatchdog:
    """Reports a main window that is not shown within *seconds*.

    ``start()`` arms it; ``window_shown()`` (from the first event-loop pass
    after ``show()``) disarms it, or - after it fired - notes the late
    window. *seconds* 0 means off. *crash_file* is crash.log's open text
    handle (main.enable_crash_traces), *notify_fd* the detached parent's
    pipe, *activation* a callable naming the extension being activated.
    """

    def __init__(
        self,
        seconds: float,
        *,
        crash_file=None,
        crash_path: Path | str | None = None,
        notify_fd: int | None = None,
        stderr=None,
        activation: Callable[[], tuple | None] | None = None,
    ) -> None:
        self.seconds = float(seconds)
        self._crash_file = crash_file
        self._crash_path = crash_path
        self._notify_fd = notify_fd
        self._stderr = stderr if stderr is not None else sys.stderr
        self._activation = activation if activation is not None else _current_activation
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._started_at: float | None = None
        self._fired = False
        self._shown = False
        self._backstop = False
        self._thread: threading.Thread | None = None

    @property
    def fired(self) -> bool:
        return self._fired

    def start(self) -> None:
        with self._lock:
            if self._started_at is not None or self.seconds <= 0:
                return
            self._started_at = time.monotonic()
            self._arm_backstop()
            self._thread = threading.Thread(
                target=self._run, name="axross-startup-watchdog", daemon=True
            )
            self._thread.start()

    def _arm_backstop(self) -> None:
        if self._crash_file is None:
            return
        import faulthandler

        try:
            faulthandler.dump_traceback_later(
                self.seconds + BACKSTOP_SECONDS, repeat=False, file=self._crash_file
            )
            self._backstop = True
        except (OSError, ValueError, RuntimeError, AttributeError):
            log.debug("startup watchdog: no faulthandler backstop", exc_info=True)

    def _cancel_backstop(self) -> None:
        if self._backstop:
            import faulthandler

            faulthandler.cancel_dump_traceback_later()
            self._backstop = False

    def _run(self) -> None:
        if self._done.wait(self.seconds):
            return
        with self._lock:
            if self._shown or self._fired:
                return
            self._fired = True
        self._fire()

    def _fire(self) -> None:
        pid = os.getpid()
        try:
            activation = self._activation()
        except Exception:  # noqa: BLE001 - the report must come regardless
            activation = None
        crash_path = self._crash_path if self._write_stacks(pid, activation) else None
        message = stall_message(self.seconds, pid, crash_path, activation)
        # The log last: a main thread hung inside a log handler holds its
        # lock, and the parent and the terminal must hear it regardless.
        with self._lock:  # window_shown closes the descriptor under the same lock
            _send(self._notify_fd, {"event": "stalled", "message": message})
        try:
            print(message, file=self._stderr, flush=True)
        except (OSError, ValueError, AttributeError):  # closed or missing stderr
            pass
        log.error("%s", message)

    def _write_stacks(self, pid: int, activation) -> bool:
        handle = self._crash_file
        if handle is None:
            return False
        import faulthandler

        what = f"; activating {activation[0]}" if activation else ""
        try:
            handle.write(
                f"--- {CRASH_HEADER} has not appeared after {self.seconds:g} s "
                f"(pid {pid}, {time.strftime('%Y-%m-%d %H:%M:%S %z')}{what}); "
                "every thread's stack: ---\n"
            )
            handle.flush()
            faulthandler.dump_traceback(file=handle, all_threads=True)
            handle.flush()
        except (OSError, ValueError):
            return False
        self._cancel_backstop()
        return True

    def window_shown(self) -> None:
        with self._lock:
            if self._shown:
                return
            self._shown = True
            fired = self._fired
            self._done.set()
            self._cancel_backstop()
        if fired and self._started_at is not None:
            took = time.monotonic() - self._started_at
            log.warning("The main window appeared after all, after %.1f s", took)
            if self._crash_file is not None:
                try:
                    self._crash_file.write(
                        f"--- window shown after {took:.1f} s (pid {os.getpid()}) ---\n"
                    )
                    self._crash_file.flush()
                except (OSError, ValueError):
                    pass
        with self._lock:
            _send(self._notify_fd, {"event": "shown"})
            if self._notify_fd is not None:
                try:
                    os.close(self._notify_fd)
                except OSError:
                    pass
                self._notify_fd = None


def _exit_code(child, seconds: float) -> int | None:
    import subprocess

    try:
        return child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        return None


def no_word_message(seconds: float, pid: int, crash_path) -> str:
    """The detached parent's message when the child said nothing in time
    (its watchdog could not run, or it is switched off)."""
    where = f" to {crash_path}" if crash_path else ""
    return (
        f"axross: the main window has not appeared after {seconds:g} s; the background "
        f"start (pid {pid}) keeps running.\n"
        f"If no window comes: \"kill -USR1 {pid}\" writes every thread's stack{where}; "
        f"then {_how_to_end(pid)} and start \"axross --safe-mode\" (loads no extension) "
        "or \"axross --foreground\" to see its messages here."
    )


def await_detached_child(
    child, read_fd: int, seconds: float, stderr, *, crash_path, report_timeout: bool = True
) -> bool:
    """The parent of a detached start: wait until *child* reports its window
    shown (True), reports a stall (its message goes to *stderr*, True: it
    keeps running), or ends. A child that ends with an error returns False
    - its output went nowhere, so the caller runs in the foreground. No
    word within *seconds*: True, with a message of its own unless
    *report_timeout* is off (the watchdog is switched off: a quiet check
    for an immediate failure, as before the watchdog)."""
    deadline = time.monotonic() + seconds
    buffer = b""
    import select

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if report_timeout:
                print(no_word_message(seconds, child.pid, crash_path), file=stderr)
            return True
        ready, _, _ = select.select([read_fd], [], [], min(remaining, 0.25))
        if not ready:
            code = child.poll()
            if code is None:
                continue
            return _ended(code, stderr)
        try:
            chunk = os.read(read_fd, 65536)
        except OSError:
            chunk = b""
        if not chunk:  # EOF: the child ended (or closed the pipe)
            return _ended(_exit_code(child, 2.0), stderr)
        buffer += chunk
        *lines, buffer = buffer.split(b"\n")
        for line in lines:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get("event") == "shown":
                return True
            if event.get("event") == "stalled":
                print(str(event.get("message", "")), file=stderr)
                return True


def _ended(code: int | None, stderr) -> bool:
    if code is None or code == 0:
        return True
    print(
        f"axross: the background start ended with status {code}; "
        "starting in the foreground instead (--foreground does this directly).",
        file=stderr,
    )
    return False


__all__ = [
    "BACKSTOP_SECONDS",
    "CRASH_HEADER",
    "DETACH_GRACE_SECONDS",
    "NOTIFY_FD_ENV",
    "StartupWatchdog",
    "WATCHDOG_ENV",
    "WATCHDOG_SECONDS",
    "await_detached_child",
    "no_word_message",
    "stall_message",
    "take_notify_fd",
    "wait_for",
    "watchdog_seconds",
]
