"""Run a saved script in its own interpreter — the Scripts dock's runner.

The REPL runs code on the GUI thread: a script that loops or waits on a
slow host freezes the window, and nothing can stop it. The Scripts dock
therefore starts every run as a child process. Stop terminates it (and
kills it after a grace period), closing the window ends it, and the GUI
only ever reads its output.

Same rules as the Analysis dock's worker (core.analysis_worker): a new
interpreter, never a fork of the Qt process (a fork copies one thread
and leaves Qt's locks held in the child), and output that is bounded
before it reaches a widget.

The child runs with the namespace ``axross --script`` gives a script
(:func:`execute_source` is shared with main.py), in the script
directory, under ``python -I``: the script directory is the working
directory, and without isolation a saved script called ``json`` would
replace the stdlib module for every other script. ``-I`` also drops the
user site, so the parent's ``sys.path`` is handed over explicitly —
the child sees the modules the GUI sees, and nothing from the cwd.

Nothing here imports Qt. The dock drives the command through QProcess.
The MCP ``script_run`` tool uses :func:`run_bounded`: the same child,
waited for with a wall-clock timeout, a process group killed as a whole,
bounded output, and an outcome record (exit status, uncaught exception)
the child writes to a pipe of its own.
"""

from __future__ import annotations

import atexit
import codecs
import json
import math
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Sequence
from dataclasses import dataclass, field

#: Longest line the output pane shows; the rest of that line is cut once.
MAX_LINE_CHARS = 1_000
#: Most lines the output pane keeps (its maximumBlockCount). A chunk that
#: holds more lines than this only contributes its newest ones.
MAX_OUTPUT_LINES = 10_000
#: Seconds between Stop's terminate and the kill that follows it.
STOP_GRACE_SECONDS = 3.0
#: Appended where a line is cut.
LINE_CUT_MARKER = " …[line cut]"
#: Seconds a bounded run waits for its output pipes to reach end of file
#: once the process group is gone (a process that left the group may
#: still hold them).
OUTPUT_DRAIN_SECONDS = 2.0
#: Bounds of the outcome record a child reports (see RESULT_FD_ENV).
MAX_NAMESPACE_KEYS = 500
MAX_NAMESPACE_KEY_CHARS = 200
MAX_TRACEBACK_CHARS = 16_000
MAX_ERROR_CHARS = 2_000
#: Prefixed where the oldest part of a long traceback is cut.
TRACEBACK_CUT_MARKER = "…[traceback cut]\n"
#: Environment variable naming the file descriptor a child reports its
#: outcome on (see :func:`child_main`). Unset for the Scripts dock, which
#: reads the output streams only.
RESULT_FD_ENV = "AXROSS_SCRIPT_RESULT_FD"
#: Most bytes the parent reads of that outcome record.
MAX_RESULT_RECORD_BYTES = 256 * 1024
#: Bytes of an example's call the child reads from stdin.
MAX_EXAMPLE_CALL_BYTES = 64 * 1024
#: Environment variable with the seconds after which a bounded run's child
#: ends itself (:func:`child_deadline`): the parent enforces the time limit
#: from a thread of its own, which dies with axross.
DEADLINE_ENV = "AXROSS_SCRIPT_DEADLINE"
#: Seconds the child's own deadline lies past the parent's soft stop and
#: its grace, so the parent's SIGTERM normally comes first.
CHILD_DEADLINE_MARGIN = 2.0
#: First line of the section "Copy to My Scripts" appends: the example's
#: Usage block, commented out (some name hosts to scan or profiles to open).
TRY_IT_HEADER = "# --- Try it: remove the # in front of the lines below, adjust them, then Run ---"

_BOOTSTRAP = (
    "import json, sys\n"
    "_paths = json.loads(sys.argv[1])\n"
    "sys.path[:] = _paths + [p for p in sys.path if p not in _paths]\n"
    "from core.script_runner import child_main\n"
    "raise SystemExit(child_main(sys.argv[2:]))\n"
)


@dataclass(frozen=True)
class ChildCommand:
    """How to start one run: argv, working directory, text for stdin."""

    argv: list[str]
    cwd: str
    #: Fed to the child's stdin before it is closed; ``None`` closes it at once.
    stdin_text: str | None = None


def _package_root() -> str:
    """The directory that holds the ``core`` package."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _child_sys_path(script_dir: str) -> list[str]:
    """The parent's import path for the child: absolute entries only (a
    relative one would resolve against the script directory), never the
    script directory itself, and the package root first."""
    blocked = os.path.realpath(script_dir)
    out = [_package_root()]
    for entry in sys.path:
        if not entry or not os.path.isabs(entry):
            continue
        if os.path.realpath(entry) == blocked or entry in out:
            continue
        out.append(entry)
    return out


def usage_block(source: str) -> str:
    """The code of the ``Usage::`` block in *source*'s module docstring,
    dedented (empty when there is none or *source* is not Python). The
    bundled examples only define functions; this block is how they are
    called."""
    import ast
    import textwrap

    try:
        doc = ast.get_docstring(ast.parse(source), clean=False) or ""
    except (SyntaxError, ValueError):
        return ""
    lines = doc.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if "Usage" in line and line.rstrip().endswith("::")), None)
    if start is None:
        return ""
    block: list[str] = []
    for line in lines[start + 1:]:
        if line.strip() and not line[:1].isspace():
            break  # the first unindented line ends the block
        block.append(line)
    return textwrap.dedent("\n".join(block)).strip("\n")


def only_defines(source: str) -> list[str]:
    """The names *source* defines when all it does is define them -
    functions, classes, constants and imports, no call and no
    ``if __name__ == "__main__"`` block; else (or not Python) ``[]``."""
    import ast

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    names: list[str] = []
    for index, node in enumerate(tree.body):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and not any(
                isinstance(n, ast.Call) for n in ast.walk(node)):
            continue
        elif (index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
              and isinstance(node.value.value, str)):
            continue  # the docstring
        else:
            return []
    return names


def build_example_command(name: str, call: str) -> ChildCommand:
    """The command that runs bundled example ``name`` followed by *call*
    (its adjusted Usage block) in a child process. The call goes in on
    stdin, never on the command line - it may name hosts or credentials.

    Raises ``ValueError`` for a name that is no bundled example and
    ``OSError`` when it cannot be read, before anything is built."""
    from core import scripting

    safe = scripting._validate_script_name(name)
    scripting._load_bundled_script(safe)  # exists and is readable
    directory = scripting.script_dir()
    if getattr(sys, "frozen", False):
        bootstrap = (
            "from core.script_runner import child_main\n"
            f"raise SystemExit(child_main(['--example', {safe!r}], call={call!r}))\n"
        )
        return ChildCommand([sys.executable, "--script", "-"], directory, bootstrap)
    argv = [sys.executable, "-I", "-u", "-c", _BOOTSTRAP,
            json.dumps(_child_sys_path(directory)), "--example", safe]
    return ChildCommand(argv, directory, call)


def build_command(name: str, args: Sequence[str] = ()) -> ChildCommand:
    """The command that runs saved script ``name`` in a child process;
    the script sees ``args`` as ``sys.argv[1:]``.

    Raises ``ValueError`` for a name ``_validate_script_name`` refuses,
    before anything is built. A frozen build has no ``-c``: it runs its
    own ``--script -`` and reads the same bootstrap from stdin.
    """
    from core import scripting

    safe = scripting._validate_script_name(name)
    script_args = [str(a) for a in args]
    directory = scripting.script_dir()
    if getattr(sys, "frozen", False):
        bootstrap = (
            "from core.script_runner import child_main\n"
            f"raise SystemExit(child_main({[safe, *script_args]!r}))\n"
        )
        return ChildCommand([sys.executable, "--script", "-"], directory, bootstrap)
    argv = [
        sys.executable,
        "-I",
        "-u",
        "-c",
        _BOOTSTRAP,
        json.dumps(_child_sys_path(directory)),
        safe,
        *script_args,
    ]
    return ChildCommand(argv, directory)


def child_env(policy_name: str, *, watched: bool = False) -> dict:
    """The child's environment: the loader variables a frozen build
    rewrites are restored, and the security mode is the one in force
    *now* — a toggle in the GUI changes no environment variable.

    ``watched=True`` (the Scripts dock) marks a run whose output a human
    sees live and can stop: the production tarpit's countdown then runs
    instead of refusing (``core.ui_helpers.can_watch_countdown``)."""
    from core.subprocess_env import clean_child_env
    from core.ui_helpers import ENV_WATCHED

    env = clean_child_env(AXROSS_SECURITY_MODE=policy_name)
    if watched:
        env[ENV_WATCHED] = "1"
    else:
        env.pop(ENV_WATCHED, None)  # never inherited from the parent
    return env


def execute_source(source: str, filename: str, namespace: dict | None = None) -> int:
    """Run ``source`` as a script with ``axross`` in its namespace.

    Returns the exit status the way the interpreter derives it from
    ``SystemExit``: ``None`` is 0, an int is the status, anything else is
    printed on stderr and gives 1. Other exceptions propagate. Pass
    ``namespace`` to look at the names the script left behind.
    """
    import core.scripting as _scripting

    if namespace is None:
        namespace = {}
    namespace.update({"__name__": "__main__", "__file__": filename, "axross": _scripting})
    try:
        exec(compile(source, filename, "exec"), namespace)  # noqa: S102 — the user's own script
    except SystemExit as exc:
        if exc.code is None:
            return 0
        if isinstance(exc.code, int):
            return exc.code
        print(exc.code, file=sys.stderr)
        return 1
    return 0


def _script_traceback_text() -> str:
    """The current exception without this module's own frames: the user
    wants to see their script, not the runner around it."""
    etype, exc, tb = sys.exc_info()
    here = os.path.abspath(__file__)
    while tb is not None and os.path.abspath(tb.tb_frame.f_code.co_filename) == here:
        tb = tb.tb_next
    return "".join(traceback.format_exception(etype, exc, tb))


def _safe_str(exc: BaseException) -> str:
    """``str(exc)``, or a placeholder when the exception's own ``__str__``
    fails."""
    try:
        return str(exc)
    except Exception:  # noqa: BLE001 — a broken __str__ must not hide the outcome
        return f"<unprintable {type(exc).__name__}>"


def _cut_front(text: str, limit: int, marker: str) -> str:
    """``text`` within ``limit`` characters, keeping the end (the part of
    a traceback that names the exception) and marking the cut."""
    return text if len(text) <= limit else marker + text[-limit:]


def _namespace_keys(namespace: dict) -> list[str]:
    """The names a script left behind, without dunders, private names and
    ``axross`` itself; bounded in count and length."""
    keys = sorted(
        k
        for k in namespace
        if isinstance(k, str) and not k.startswith("_") and k != "axross"
        and len(k) <= MAX_NAMESPACE_KEY_CHARS
    )
    return keys[:MAX_NAMESPACE_KEYS]


def child_deadline(timeout_s: float) -> float:
    """Seconds after which a run bounded by *timeout_s* ends itself."""
    return float(timeout_s) + STOP_GRACE_SECONDS + CHILD_DEADLINE_MARGIN


def _arm_own_deadline() -> float | None:
    """In the child: end this process once :data:`DEADLINE_ENV` seconds have
    passed, even when axross - which enforces the limit - is gone (quit,
    crashed, killed); a faulthandler timer is a C thread that needs no GIL.
    The variable is removed, so what the script starts does not inherit it.
    Returns the seconds armed, or None."""
    raw = os.environ.pop(DEADLINE_ENV, None)
    try:
        seconds = float(raw) if raw else 0.0
    except ValueError:
        return None
    if not math.isfinite(seconds) or seconds <= 0:
        return None
    import faulthandler

    faulthandler.dump_traceback_later(seconds, exit=True)
    return seconds


#: Process groups of the bounded runs in flight (their leaders' pids).
_LIVE_GROUPS: set[int] = set()
_LIVE_LOCK = threading.Lock()


def _kill_live_groups() -> None:
    """atexit: kill the process group of every bounded run still in flight -
    the thread that would stop it at its limit ends with this process."""
    with _LIVE_LOCK:
        groups = list(_LIVE_GROUPS)
        _LIVE_GROUPS.clear()
    for pid in groups:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


atexit.register(_kill_live_groups)


def _take_result_fd() -> int | None:
    """The descriptor named by ``RESULT_FD_ENV``, removed from the
    environment and made non-inheritable, so neither the script nor a
    process it starts sees it; ``None`` when unset or unusable."""
    raw = os.environ.pop(RESULT_FD_ENV, None)
    if raw is None:
        return None
    try:
        fd = int(raw)
        os.set_inheritable(fd, False)
    except (ValueError, OSError):
        return None
    return fd


def _report(fd: int | None, record: dict) -> None:
    """Write the outcome record to the parent; never fails the run."""
    if fd is None:
        return
    try:
        data = json.dumps(record).encode("utf-8")
        while data:
            data = data[os.write(fd, data) :]
    except (OSError, TypeError, ValueError):
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def child_main(argv: list[str], *, call: str | None = None) -> int:
    """Entry point inside the child: run saved script ``argv[0]`` with
    ``argv[1:]`` as its ``sys.argv[1:]``. ``["--example", name]`` runs
    bundled example *name* followed by *call* (read from stdin when not
    given: :func:`build_example_command`).

    When the parent passed a descriptor in ``RESULT_FD_ENV`` the child
    writes one JSON object to it before it ends: ``exit`` (the exact
    SystemExit status, not cut to 0..255), ``namespace_keys`` and, for
    an uncaught exception, ``error_type``, ``error`` and ``traceback``.
    """
    _arm_own_deadline()
    result_fd = _take_result_fd()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    if not argv:
        print("usage: child_main([script_name, *args])", file=sys.stderr)
        _report(result_fd, {"exit": 2, "error_type": "ValueError", "error": "no script name"})
        return 2
    from core.security_mode import current_policy

    policy = current_policy()
    if not policy.allow_scripts:
        message = f"Security mode '{policy.name}' blocks script execution."
        print(message, file=sys.stderr)
        _report(result_fd, {"exit": 2, "error_type": "PermissionError", "error": message})
        return 2
    from core import scripting

    name = argv[0]
    try:
        if name == "--example" and len(argv) >= 2:
            name, argv = argv[1], argv[1:2]
            if call is None:
                call = sys.stdin.read(MAX_EXAMPLE_CALL_BYTES + 1)
                if len(call) > MAX_EXAMPLE_CALL_BYTES:
                    raise ValueError("the example's call is too long")
            source = scripting._load_bundled_script(name) + "\n\n" + call + "\n"
            path = os.path.join(scripting._bundled_scripts_dir(), f"{name}.py")
        else:
            source = scripting.load_script(name)
            path = os.path.join(scripting.script_dir(), f"{name}.py")
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        print(f"cannot load script {name!r}: {exc}", file=sys.stderr)
        error = _safe_str(exc)[:MAX_ERROR_CHARS]
        _report(result_fd, {"exit": 2, "error_type": type(exc).__name__, "error": error})
        return 2
    from core.backend_registry import init_registry

    init_registry()
    sys.argv = [path, *argv[1:]]
    namespace: dict = {}
    try:
        status = int(execute_source(source, path, namespace))
    except BaseException as exc:  # noqa: BLE001 — shown like the interpreter would
        text = _script_traceback_text()
        sys.stderr.write(text)
        _report(
            result_fd,
            {
                "exit": 1,
                "error_type": type(exc).__name__,
                "error": _safe_str(exc)[:MAX_ERROR_CHARS],
                "traceback": _cut_front(text, MAX_TRACEBACK_CHARS, TRACEBACK_CUT_MARKER),
                "namespace_keys": _namespace_keys(namespace),
            },
        )
        return 1
    _report(result_fd, {"exit": status, "namespace_keys": _namespace_keys(namespace)})
    return status


# ---------------------------------------------------------------------------
# A bounded run without Qt (MCP script_run)
# ---------------------------------------------------------------------------


@dataclass
class BoundedRun:
    """Outcome of :func:`run_bounded`."""

    #: The script's exit status: the exact SystemExit code the child
    #: reported, else the process status (negative signal number when a
    #: signal ended it, as in :attr:`subprocess.Popen.returncode`).
    exit: int
    timed_out: bool = False
    cancelled: bool = False
    #: ``"stdout"`` or ``"stderr"`` when that stream passed its cap; the
    #: run was stopped there.
    output_exceeded: str | None = None
    duration_ms: int = 0
    stdout: str = ""
    stderr: str = ""
    namespace_keys: list[str] = field(default_factory=list)
    #: Set when the script ended with an uncaught exception.
    error_type: str | None = None
    error: str | None = None
    traceback: str | None = None


class _StreamReader:
    """Reads one pipe of the child to its end on a daemon thread.

    Text mode decodes UTF-8 across chunk borders (invalid bytes become
    U+FFFD) and keeps at most ``limit`` characters; byte mode keeps at
    most ``limit`` bytes. Past the limit it keeps draining - a child
    blocked on a full pipe would never reach the kill - but stores
    nothing more, sets ``exceeded`` and wakes the waiting run.
    """

    def __init__(self, stream, limit: int, wake: threading.Event, *, text: bool) -> None:
        # The reader owns ``stream`` and closes it at end of file; nobody
        # else may close it, or a blocked read could continue on a
        # reused descriptor number.
        self._stream = stream
        self._limit = limit
        self._wake = wake
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace") if text else None
        self._parts: list = []
        self._size = 0
        self.exceeded = False
        self.thread = threading.Thread(target=self._pump, name="script-run-reader", daemon=True)
        self.thread.start()

    def _pump(self) -> None:
        try:
            while True:
                read = getattr(self._stream, "read1", self._stream.read)
                chunk = read(65536)
                if not chunk:
                    break
                self._add(self._decoder.decode(chunk) if self._decoder else chunk)
            if self._decoder:
                self._add(self._decoder.decode(b"", final=True))
        except (OSError, ValueError):
            pass
        finally:
            try:
                self._stream.close()
            except (OSError, ValueError):
                pass

    def _add(self, piece) -> None:
        if self.exceeded or not piece:
            return
        room = self._limit - self._size
        if len(piece) > room:
            piece = piece[:room]
            self.exceeded = True
            self._wake.set()
        self._parts.append(piece)
        self._size += len(piece)

    def value(self):
        return ("" if self._decoder else b"").join(self._parts)


def _has_exited(proc: subprocess.Popen) -> bool:
    """True once the child ended - without reaping it where the platform
    allows, so its process group id cannot be reused before the group is
    killed."""
    if proc.returncode is not None:
        return True
    waitid = getattr(os, "waitid", None)
    if waitid is not None:
        try:
            return waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
        except ChildProcessError:
            pass
    return proc.poll() is not None


def _signal_group(proc: subprocess.Popen, *, hard: bool) -> None:
    """Terminate (or kill) the child's whole process group, so processes
    the script started go down with it."""
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL if hard else signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        return
    try:  # no process groups to signal: the child itself
        proc.kill() if hard else proc.terminate()
    except OSError:
        pass


def _parse_record(raw: bytes) -> dict:
    """The child's outcome record, type-checked and bounded; ``{}`` when
    there is none or it is not one (the script owns the child, so the
    record is data from it, not a trusted answer)."""
    try:
        record = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {}
    if not isinstance(record, dict):
        return {}
    out: dict = {}
    if type(record.get("exit")) is int:
        out["exit"] = record["exit"]
    for key, limit in (
        ("error_type", MAX_NAMESPACE_KEY_CHARS),
        ("error", MAX_ERROR_CHARS),
        ("traceback", MAX_TRACEBACK_CHARS + len(TRACEBACK_CUT_MARKER)),
    ):
        if isinstance(record.get(key), str):
            out[key] = record[key][:limit]
    keys = record.get("namespace_keys")
    if isinstance(keys, list):
        out["namespace_keys"] = [
            k for k in keys if isinstance(k, str) and len(k) <= MAX_NAMESPACE_KEY_CHARS
        ][:MAX_NAMESPACE_KEYS]
    return out


def run_bounded(
    name: str,
    *,
    args: Sequence[str] = (),
    timeout_s: float,
    max_output_chars: int,
    cancel_event: threading.Event | None = None,
    env_overrides: dict[str, str] | None = None,
) -> BoundedRun:
    """Run saved script ``name`` in a child and wait for it, within bounds.

    The child is the one the Scripts dock starts (:func:`build_command`,
    :func:`child_env`), with stdin on ``/dev/null`` (a frozen build gets
    its bootstrap and then end of file), in a process group of its own.
    At ``timeout_s``, when ``cancel_event`` is set, or when stdout or
    stderr passes ``max_output_chars``, the group is terminated and
    killed ``STOP_GRACE_SECONDS`` later. When the child ends by itself
    the rest of its group is killed too: nothing a run started outlives
    it (a process that left the group with ``setsid`` is out of reach).

    Raises ``ValueError`` for a name the validator refuses or a bad
    ``timeout_s``, before anything starts.
    """
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)):
        raise ValueError("timeout_s must be a number of seconds")
    if not math.isfinite(timeout_s) or timeout_s <= 0:
        raise ValueError("timeout_s must be a positive, finite number of seconds")
    cmd = build_command(name, args)
    from core.security_mode import current_policy

    env = child_env(current_policy().name)
    env.update(env_overrides or {})
    env[DEADLINE_ENV] = f"{child_deadline(timeout_s):.3f}"
    posix = os.name == "posix"
    extra: dict = {}
    result_read = result_write = None
    if posix:
        result_read, result_write = os.pipe()
        env[RESULT_FD_ENV] = str(result_write)
        extra.update(pass_fds=(result_write,), start_new_session=True)
    else:
        extra["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd.argv,
            cwd=cmd.cwd,
            env=env,
            stdin=subprocess.PIPE if cmd.stdin_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **extra,
        )
    except BaseException:
        if result_read is not None:
            os.close(result_read)
        raise
    finally:
        if result_write is not None:
            os.close(result_write)  # the child holds its own copy
    if posix:
        # Until it is stopped below: a normal exit of axross kills the group
        # (the thread that enforces the limit dies with the process).
        with _LIVE_LOCK:
            _LIVE_GROUPS.add(proc.pid)
    try:
        wake = threading.Event()
        out = _StreamReader(proc.stdout, max_output_chars, wake, text=True)
        err = _StreamReader(proc.stderr, max_output_chars, wake, text=True)
        readers = [out, err]
        record_reader = None
        if result_read is not None:
            record_reader = _StreamReader(
                open(result_read, "rb", buffering=0), MAX_RESULT_RECORD_BYTES, wake, text=False
            )
            readers.append(record_reader)
        if cmd.stdin_text is not None:
            try:
                proc.stdin.write(cmd.stdin_text.encode("utf-8"))
            except OSError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

        deadline = started + float(timeout_s)
        stop: str | None = None
        while not _has_exited(proc):
            if out.exceeded or err.exceeded:
                stop = "output"
                break
            if cancel_event is not None and cancel_event.is_set():
                stop = "cancel"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stop = "timeout"
                break
            wake.wait(min(0.05, remaining))
        if stop is not None:
            _signal_group(proc, hard=False)
            grace_end = time.monotonic() + STOP_GRACE_SECONDS
            while not _has_exited(proc) and time.monotonic() < grace_end:
                time.sleep(0.02)
        _signal_group(proc, hard=True)
        try:
            proc.wait(timeout=STOP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL is not ignorable
            pass
    finally:
        with _LIVE_LOCK:
            _LIVE_GROUPS.discard(proc.pid)
    duration_ms = int((time.monotonic() - started) * 1000)
    drain_end = time.monotonic() + OUTPUT_DRAIN_SECONDS
    for reader in readers:
        reader.thread.join(max(0.0, drain_end - time.monotonic()))
    record = {}
    if record_reader is not None and not record_reader.thread.is_alive():
        if not record_reader.exceeded:
            record = _parse_record(record_reader.value())
    status = proc.returncode if proc.returncode is not None else -1
    exit_status = record.get("exit", status) if stop is None else status
    exceeded = "stdout" if out.exceeded else ("stderr" if err.exceeded else None)
    return BoundedRun(
        exit=exit_status,
        timed_out=stop == "timeout",
        cancelled=stop == "cancel",
        output_exceeded=exceeded,
        duration_ms=duration_ms,
        stdout=out.value(),
        stderr=err.value(),
        namespace_keys=record.get("namespace_keys", []),
        error_type=record.get("error_type") if stop is None else None,
        error=record.get("error") if stop is None else None,
        traceback=record.get("traceback") if stop is None else None,
    )


class OutputLimiter:
    """Turns a child's output bytes into text the output pane can hold.

    Decodes UTF-8 across chunk borders (a character split between two
    reads stays whole; invalid bytes become U+FFFD), cuts a line longer
    than ``max_line_chars`` once, and when one chunk holds more than
    ``max_lines`` lines keeps only the newest — the pane keeps no more
    than that anyway, and appending what it drops again at once is the
    work that would make a flooding script freeze the window.
    """

    def __init__(
        self, *, max_line_chars: int = MAX_LINE_CHARS, max_lines: int = MAX_OUTPUT_LINES
    ) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._max_line = max_line_chars
        self._max_lines = max_lines
        #: Characters of the unfinished current line already passed on.
        self._line_len = 0
        self._line_cut = False
        self.total_bytes = 0

    def feed(self, data: bytes) -> str:
        self.total_bytes += len(data)
        return self._clip(self._decoder.decode(data))

    def flush(self) -> str:
        return self._clip(self._decoder.decode(b"", final=True))

    def _clip(self, text: str) -> str:
        if not text:
            return ""
        newlines = text.count("\n")
        skipped = 0
        if newlines > self._max_lines:
            # Keep the newest lines only: drop everything up to and
            # including the newline that ends the oldest line we skip.
            skipped = newlines - self._max_lines
            cut_at = -1
            for _ in range(skipped):
                cut_at = text.index("\n", cut_at + 1)
            text = text[cut_at + 1 :]
            self._line_len = 0
            self._line_cut = False
        out: list[str] = []
        if skipped:
            out.append(f"[… {skipped} lines skipped …]\n")
        for piece in text.split("\n")[:-1]:
            out.append(self._take(piece))
            out.append("\n")
            self._line_len = 0
            self._line_cut = False
        out.append(self._take(text.rsplit("\n", 1)[-1]))
        return "".join(out)

    def _take(self, piece: str) -> str:
        """The part of ``piece`` (no newline) that still fits the line."""
        room = self._max_line - self._line_len
        if len(piece) <= room:
            self._line_len += len(piece)
            return piece
        kept = piece[: max(room, 0)]
        self._line_len += len(kept)
        if self._line_cut:
            return kept
        self._line_cut = True
        return kept + LINE_CUT_MARKER


_TRACEBACK_FILE = re.compile(r'^\s*File "(?P<path>[^"]+)", line (?P<line>\d+)')


def script_line_in(text: str, script_path: str) -> int | None:
    """The line number a traceback line points at in ``script_path``,
    or ``None`` when the line is about another file or no traceback line."""
    match = _TRACEBACK_FILE.match(text or "")
    if match is None:
        return None
    if os.path.normpath(match.group("path")) != os.path.normpath(script_path):
        return None
    line = int(match.group("line"))
    return line if line > 0 else None


__all__ = [
    "LINE_CUT_MARKER",
    "MAX_ERROR_CHARS",
    "MAX_LINE_CHARS",
    "MAX_NAMESPACE_KEYS",
    "MAX_NAMESPACE_KEY_CHARS",
    "MAX_OUTPUT_LINES",
    "MAX_RESULT_RECORD_BYTES",
    "MAX_TRACEBACK_CHARS",
    "OUTPUT_DRAIN_SECONDS",
    "RESULT_FD_ENV",
    "STOP_GRACE_SECONDS",
    "TRACEBACK_CUT_MARKER",
    "BoundedRun",
    "ChildCommand",
    "OutputLimiter",
    "build_command",
    "child_env",
    "child_main",
    "execute_source",
    "run_bounded",
    "script_line_in",
]
