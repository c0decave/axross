"""Try Qt Multimedia in a child process before the GUI process touches it.

Qt Multimedia starts its backend in the thread that creates the first
multimedia object - for axross the GUI thread - and that start runs host
code nobody bounds: the GPU drivers (an NVIDIA driver hung in cuInit inside
QAudioDecoder(), and axross-full showed no window; see core.multimedia_env)
and the audio server (measured: a PulseAudio / PipeWire socket that accepts
and never answers makes QMediaDevices.audioOutputs() and QAudioOutput()
hang for ever). Qt's integration cannot be moved to another thread, so a
hang there freezes the whole window.

So before the first in-process multimedia object, a child process creates
the same objects axross uses - QAudioDecoder (the backend start),
QMediaPlayer, the audio device lists and a QAudioOutput - with this
process's environment, under a bound (:func:`probe_seconds`). A child that
does not answer in time is killed (its whole process group), and the
callers show :func:`unavailable_text` instead of a player. The result is
kept for the process: one probe per run.

The child is ``python -m core.multimedia_probe``; a frozen build has no
``python -m`` and answers ``--multimedia-probe`` itself (main.py, after
core.multimedia_env applied its defaults - the child sees what the GUI
process would see). It prints JSON lines on stdout: ``{"step": name}``
before each step and ``{"ok": true, "outputs": n, "inputs": n}`` or
``{"ok": false, "error": text}`` at the end. Its stderr is read for the
message of a child that dies without a reply.

A passed probe does not prove the in-process start cannot hang (the GUI
process talks to the display server too); it removes every hang that does
not depend on that, which covers both measured ones.
"""

from __future__ import annotations

import atexit
import faulthandler
import json
import logging
import math
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from core.i18n import tr
from core.subprocess_env import worker_env

log = logging.getLogger(__name__)

#: Seconds the child may take. Measured on the development host (source
#: tree, 20 cores at load ~4, 15 runs): the whole child - interpreter,
#: PyQt6, Qt's FFmpeg backend, the device lists, with and without a
#: PipeWire session - took 0.12-0.24 s; a frozen one-file worker reuses
#: the running process's unpacked folder (core.subprocess_env.worker_env),
#: so it adds no extraction. 15 s is a margin of 60x for a cold disk cache
#: or a busy machine, and short enough that the user learns why there is no
#: sound while still looking at the player. The bound never blocks the
#: window: only the player waits for it.
PROBE_SECONDS = 15.0
#: The bound can be changed through this variable (seconds, clamped).
SECONDS_ENV = "AXROSS_MULTIMEDIA_PROBE_SECONDS"
MIN_PROBE_SECONDS = 1.0
MAX_PROBE_SECONDS = 300.0
#: Seconds a killed child gets to be reaped and to close its pipes.
_REAP_SECONDS = 5.0
#: The child's own deadline in seconds (set by :func:`run_probe`): past it
#: the child ends itself, also when no parent is left to kill it.
DEADLINE_ENV = "AXROSS_MULTIMEDIA_PROBE_DEADLINE"
#: Seconds the child's own deadline lies past the parent's bound, so a
#: living parent always kills first and reads the step it hung at.
_DEADLINE_MARGIN = 2.0
#: Characters of the child's stderr quoted in a message.
_STDERR_QUOTED = 300

#: The child's steps, in order, and what the message says it hung at.
STEP_LABELS = {
    "start": "starting",
    "decoder": "starting its media backend and the GPU drivers",
    "player": "creating a media player",
    "audio devices": "listing the audio devices of the audio server",
    "audio output": "opening an audio output on the audio server",
}


@dataclass(frozen=True)
class AudioDeviceInfo:
    """An audio device as the child saw it. *device_id* is QAudioDevice.id()
    as text - the same under PulseAudio and PipeWire."""

    device_id: str
    description: str
    is_default: bool = False


@dataclass(frozen=True)
class ProbeResult:
    """What the child found. *reason* is a sentence fragment for the user
    ("" when *ok*). *backend* is the QT_AUDIO_BACKEND the child ran with
    ("" - Qt's own choice)."""

    ok: bool
    reason: str = ""
    seconds: float = 0.0
    outputs: int = 0
    inputs: int = 0
    backend: str = ""
    output_devices: tuple[AudioDeviceInfo, ...] = ()
    input_devices: tuple[AudioDeviceInfo, ...] = ()
    step: str = ""  # the step a failed child stopped at ("" when ok)


#: The steps that talk to the audio server: only a failure there is worth
#: trying another audio backend for (the decoder step hangs in the GPU
#: drivers whatever the backend).
AUDIO_STEPS = frozenset({"audio devices", "audio output"})
#: The backends' names in messages.
BACKEND_NAMES = {"pipewire": "PipeWire", "pulseaudio": "PulseAudio", "": "Qt Multimedia"}
#: The child names the process allowed to debug it (core: a native stack of a hung child).
PARENT_ENV = "AXROSS_MULTIMEDIA_PROBE_PARENT"
#: Seconds the child gives an empty device list to fill (a backend that lists
#: devices as its server announces them).
_DEVICE_SETTLE_SECONDS = 1.0
#: Seconds all native stacks of a hung child may take together (the
#: message waits for them), and the lines logged.
_STACK_SECONDS = 3.0
_STACK_LINES = 80


def pipewire_running(environ: dict | None = None) -> bool:
    """Whether a PipeWire daemon listens: its socket (or PIPEWIRE_REMOTE)."""
    environ = os.environ if environ is None else environ
    if environ.get("PIPEWIRE_REMOTE"):
        return True
    runtime = environ.get("XDG_RUNTIME_DIR")
    return bool(runtime) and os.path.exists(os.path.join(runtime, "pipewire-0"))


def backend_order(setting: str, environ: dict | None = None, *, platform: str | None = None,
                  pipewire: bool | None = None) -> list[str]:
    """The QT_AUDIO_BACKEND values the probe tries, in order. Linux only
    ("" elsewhere: Qt has one backend there). The user's own variable and
    an explicit setting are tried alone; "auto" tries PipeWire where its
    daemon runs, then PulseAudio (which pipewire-pulse also serves)."""
    from core.multimedia_env import users_audio_backend

    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    if not platform.startswith("linux"):
        return [""]
    own = users_audio_backend(environ)
    if own is not None:
        return [own]
    if setting in ("pulseaudio", "pipewire"):
        return [setting]
    running = pipewire_running(environ) if pipewire is None else pipewire
    return ["pipewire", "pulseaudio"] if running else ["pulseaudio"]


def probe_seconds() -> float:
    """The bound: :data:`PROBE_SECONDS`, or :data:`SECONDS_ENV` clamped to
    [MIN, MAX]; a value that is no positive finite number is ignored."""
    raw = os.environ.get(SECONDS_ENV)
    if raw is None:
        return PROBE_SECONDS
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value <= 0:
        log.warning("%s=%r is no number of seconds; using %s", SECONDS_ENV, raw, PROBE_SECONDS)
        return PROBE_SECONDS
    return min(MAX_PROBE_SECONDS, max(MIN_PROBE_SECONDS, value))


def probe_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--multimedia-probe"]
    return [sys.executable, "-m", "core.multimedia_probe"]


def _package_root() -> str:
    return str(Path(__file__).resolve().parent.parent)


def _seconds_text(seconds: float) -> str:
    return f"{seconds:g}"


def _signal_name(number: int) -> str:
    try:
        return signal.Signals(number).name
    except ValueError:
        return f"signal {number}"


def child_deadline(timeout: float) -> float:
    """The deadline a child started with the bound *timeout* gets."""
    return timeout + _DEADLINE_MARGIN


#: Probe children still running. A hung child must never outlive this
#: process: the watcher thread that kills it after the bound is a daemon
#: and dies with the process (measured: a child stuck in cuInit was still
#: there 25 s after the app quit, parent pid 1).
_LIVE: set[subprocess.Popen] = set()
_live_lock = threading.Lock()


def _kill_live() -> None:
    """Kill every probe child still running (atexit)."""
    with _live_lock:
        live = list(_LIVE)
    for proc in live:
        if proc.poll() is None:
            _kill(proc)


atexit.register(_kill_live)


def _kill(proc: subprocess.Popen) -> None:
    """End the child and everything it started (its own process group)."""
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _parse(stdout: str) -> tuple[str, dict | None]:
    """(the last step the child began, its final reply or None)."""
    step, reply = "start", None
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue  # a library's stray print
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        if isinstance(message.get("step"), str):
            step = message["step"]
        elif isinstance(message.get("ok"), bool):
            reply = message
    return step, reply


def _devices(reply: dict, key: str) -> tuple[AudioDeviceInfo, ...]:
    """The well-formed entries of the device list under *key*."""
    found = []
    entries = reply.get(key)
    for entry in entries if isinstance(entries, list) else ():
        if (isinstance(entry, dict) and isinstance(entry.get("id"), str)
                and isinstance(entry.get("description"), str)):
            found.append(AudioDeviceInfo(entry["id"], entry["description"],
                                         entry.get("default") is True))
    return tuple(found)


def _result_from_reply(reply: dict, seconds: float) -> ProbeResult:
    """The result of a child that answered ok."""
    backend = reply.get("backend") if isinstance(reply.get("backend"), str) else ""
    return ProbeResult(True, "", seconds, _count(reply, "outputs"), _count(reply, "inputs"),
                       backend=backend, output_devices=_devices(reply, "output_devices"),
                       input_devices=_devices(reply, "input_devices"))


def _descendants(pid: int) -> list[int]:
    """*pid* and every process below it (Linux; a one-file binary runs its
    Python in a child of its own)."""
    found, todo = [], [pid]
    while todo:
        current = todo.pop()
        found.append(current)
        try:
            text = Path(f"/proc/{current}/task/{current}/children").read_text()
        except OSError:
            continue
        todo.extend(int(p) for p in text.split())
    return found


def _native_stack(pid: int) -> str:
    """The native stacks of *pid* and its children by eu-stack or gdb, ""
    when neither is there or may attach. The child allowed this process
    (and what it starts) to attach (:func:`_allow_parent_debugger`)."""
    if not sys.platform.startswith("linux"):
        return ""
    import shutil

    from core.subprocess_env import clean_child_env

    # No symbol downloads: they took seconds (the user waits for the
    # message) and would send the build ids of every library to a server.
    env = clean_child_env()
    env.pop("DEBUGINFOD_URLS", None)
    deadline = time.monotonic() + _STACK_SECONDS
    texts = []
    for target in _descendants(pid):
        for tool in (["eu-stack", "-p", str(target)],
                     ["gdb", "-p", str(target), "-batch", "-ex", "thread apply all bt 30"]):
            left = deadline - time.monotonic()
            if left <= 0:
                return "\n".join(texts)
            found = shutil.which(tool[0])
            if not found:
                continue
            try:
                run = subprocess.run([found, *tool[1:]], capture_output=True, text=True, errors="replace",
                                     timeout=left, env=env, stdin=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired):
                continue
            frames = [ln for ln in run.stdout.splitlines()
                      if ln.startswith(("TID", "Thread", "#"))]
            if frames:
                texts.append(f"pid {target} ({tool[0]}):\n" + "\n".join(frames[:_STACK_LINES]))
                break
    return "\n".join(texts)


def _log_native_stack(pid: int) -> None:
    try:
        stack = _native_stack(pid)
    except Exception:  # noqa: BLE001 - a diagnosis must not break the probe
        log.debug("no native stack of the Qt Multimedia check", exc_info=True)
        return
    if stack:
        log.warning("The Qt Multimedia check hung; its native stacks:\n%s", stack)


def _count(reply: dict, key: str) -> int:
    value = reply.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def run_probe(timeout: float | None = None, *, command: list[str] | None = None,
              env: dict | None = None, backend: str = "") -> ProbeResult:
    """Run the child once (no cache) and return what it found. Blocks for
    up to *timeout* seconds (default :func:`probe_seconds`) plus the reap
    of a killed child - call it off the GUI thread. *backend* is the
    QT_AUDIO_BACKEND it runs with ("" - this process's environment)."""
    timeout = probe_seconds() if timeout is None else float(timeout)
    command = command or probe_command()
    child_env = dict(worker_env() if env is None else env)
    if backend:
        child_env["QT_AUDIO_BACKEND"] = backend
    child_env[PARENT_ENV] = str(os.getpid())
    root = _package_root()
    child_env["PYTHONPATH"] = root + (os.pathsep + child_env["PYTHONPATH"]
                                      if child_env.get("PYTHONPATH") else "")
    # No window and no display connection: only Qt Multimedia is tried.
    child_env["QT_QPA_PLATFORM"] = "offscreen"
    child_env[DEADLINE_ENV] = _seconds_text(child_deadline(timeout))
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=child_env, cwd=root, close_fds=True, start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        return ProbeResult(False, tr("the Qt Multimedia check could not start: {error}")
                           .format(error=exc))
    with _live_lock:
        _LIVE.add(proc)
    try:
        result = _wait(proc, timeout, start)
        return replace(result, backend=backend or child_env.get("QT_AUDIO_BACKEND", ""))
    finally:
        with _live_lock:
            _LIVE.discard(proc)


def _wait(proc: subprocess.Popen, timeout: float, start: float) -> ProbeResult:
    """Wait for the started child under the bound and read its answer."""
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _log_native_stack(proc.pid)
        # Killed while it is still unreaped: its pid is the group's id and
        # cannot belong to anyone else yet.
        _kill(proc)
        try:
            out, err = proc.communicate(timeout=_REAP_SECONDS)
        except subprocess.TimeoutExpired:  # a grandchild outside the group holds the pipe
            out, err = b"", b""
            try:
                proc.wait(timeout=_REAP_SECONDS)
            except subprocess.TimeoutExpired:
                log.warning("the Qt Multimedia check (pid %s) did not end", proc.pid)
    seconds = time.monotonic() - start
    step, reply = _parse(out.decode("utf-8", "replace") if out else "")
    if timed_out:
        label = tr(STEP_LABELS.get(step, step))
        return ProbeResult(False, tr("Qt Multimedia did not answer within {seconds} s "
                                     "(it hung while {step})")
                           .format(seconds=_seconds_text(timeout), step=label), seconds,
                           step=step)
    if reply is not None:
        if reply["ok"]:
            return _result_from_reply(reply, seconds)
        error = str(reply.get("error") or "")[:_STDERR_QUOTED] or tr("unknown error")
        return ProbeResult(False, tr("Qt Multimedia failed: {error}").format(error=error),
                           seconds, step=step)
    code = proc.returncode
    if code is not None and code < 0:
        return ProbeResult(False, tr("the Qt Multimedia check crashed ({signal}) while {step}")
                           .format(signal=_signal_name(-code),
                                   step=tr(STEP_LABELS.get(step, step))), seconds, step=step)
    tail = (err or b"").decode("utf-8", "replace").strip().splitlines()
    quoted = tail[-1][:_STDERR_QUOTED] if tail else ""
    text = tr("the Qt Multimedia check ended with status {code} and no answer").format(code=code)
    return ProbeResult(False, f"{text}: {quoted}" if quoted else text, seconds, step=step)


# -- the process-wide result ---------------------------------------------------------------

_run_lock = threading.Lock()
_result: ProbeResult | None = None
#: Counts :func:`reset` calls: a probe that ran across one is not kept.
_generation = 0
#: The backend of the first probe that answered ok in this process: the one
#: Qt uses here (it reads QT_AUDIO_BACKEND once per process, and no
#: multimedia object exists before a probe answered ok). Never reset.
_active_backend: str | None = None


def cached() -> ProbeResult | None:
    """The result of this run's probe, None while there is none yet."""
    return _result


def active_backend() -> str | None:
    """The QT_AUDIO_BACKEND this process plays through ("" - Qt's own
    choice), None while no probe answered ok. A later check that answered
    with another backend does not change it: that takes a restart."""
    return _active_backend


def probe(timeout: float | None = None) -> ProbeResult:
    """This run's result; the first caller runs the child, concurrent
    callers wait for the same answer. Blocks - not on the GUI thread."""
    global _result, _active_backend
    result = _result
    if result is not None:
        return result
    with _run_lock:
        if _result is not None:
            return _result
        generation = _generation
        result = _probe_backends(timeout)
        if result.ok:
            log.info("Qt Multimedia answered in %.2f s (audio backend: %s)", result.seconds,
                     BACKEND_NAMES.get(result.backend, result.backend))
            if _active_backend is None:
                # The first answer is what this process plays through: Qt
                # reads QT_AUDIO_BACKEND once, so a later check (another
                # saved backend) must not change it for this process or the
                # workers it starts - that takes a restart.
                _active_backend = result.backend
                if result.backend:
                    from core.multimedia_env import apply_audio_backend

                    apply_audio_backend(result.backend)
        else:
            log.warning("Qt Multimedia is off for this run: %s", result.reason)
        if generation == _generation:
            _result = result
        return result


def _saved_backend() -> str:
    try:
        from core.audio_settings import AudioSettings

        return AudioSettings.load().backend
    except Exception:  # noqa: BLE001 - a broken settings file is "auto"
        return "auto"


def _probe_backends(timeout: float | None) -> ProbeResult:
    """Try each backend of :func:`backend_order` until one answers; the
    failure names every backend tried."""
    failures = []
    for backend in backend_order(_saved_backend()):
        result = run_probe(timeout, backend=backend)
        if result.ok:
            if failures:
                log.warning("Qt Multimedia: %s; using %s", "; ".join(failures),
                            BACKEND_NAMES.get(backend, backend))
            return result
        failures.append(f"{BACKEND_NAMES.get(backend, backend)}: {result.reason}")
        if result.step not in AUDIO_STEPS:
            break  # not the audio server: another backend would hang the same way
    if len(failures) == 1:
        return result
    return ProbeResult(False, "; ".join(failures), result.seconds, step=result.step)


def reset() -> None:
    """Forget the result: the next :func:`probe` runs the child again (a
    probe still running answers its callers but is not kept)."""
    global _result, _generation
    _generation += 1
    _result = None


_start_lock = threading.Lock()
_starter: threading.Thread | None = None


def start() -> None:
    """Begin this run's probe in the background, if it is neither known
    nor running; returns at once. For a caller that only polls
    :func:`cached` later."""
    global _starter
    if _result is not None:
        return
    with _start_lock:
        if _starter is not None and _starter.is_alive():
            return
        _starter = threading.Thread(target=_probe_quietly, name="multimedia-probe", daemon=True)
        _starter.start()


def _probe_quietly() -> None:
    try:
        probe()
    except Exception:  # noqa: BLE001 - a thread of its own: nobody else hears it
        log.exception("Qt Multimedia probe failed")


#: The relays waiting for a probe (they must outlive the request).
_RELAYS: set = set()
_relay_class = None


def _relay():
    """A QObject whose signal carries a result to the GUI thread (made in
    the calling thread, so a worker's emit is queued there)."""
    global _relay_class
    if _relay_class is None:
        from PyQt6.QtCore import QObject, pyqtSignal

        class _Relay(QObject):
            done = pyqtSignal(object)

        _relay_class = _Relay
    return _relay_class()


def probe_async(on_done: Callable[[ProbeResult], None], context=None) -> None:
    """Call *on_done(result)* on the GUI thread once this run's probe is
    known: at once (synchronously) when it is, else from a worker thread's
    result. With *context* (a QObject) the call is dropped when that
    object was deleted meanwhile. Call it from the GUI thread."""
    result = _result
    if result is not None:
        on_done(result)
        return
    from PyQt6 import sip

    relay = _relay()
    _RELAYS.add(relay)

    def deliver(value) -> None:
        _RELAYS.discard(relay)
        relay.deleteLater()
        if context is not None and sip.isdeleted(context):
            return
        on_done(value)

    relay.done.connect(deliver)

    def work() -> None:
        try:
            value = probe()
        except Exception as exc:  # noqa: BLE001 - the caller must hear something
            log.exception("Qt Multimedia probe failed")
            value = ProbeResult(False, tr("the Qt Multimedia check failed: {error}")
                                .format(error=exc))
        try:
            relay.done.emit(value)
        except RuntimeError:  # the application is gone
            pass

    threading.Thread(target=work, name="multimedia-probe", daemon=True).start()


def unavailable_text(result: ProbeResult) -> str:
    """The sentence a component shows when the probe failed ("" when ok)."""
    if result.ok:
        return ""
    return tr("Audio and video do not start on this system: {reason}.").format(
        reason=result.reason)


# -- the child -------------------------------------------------------------------------------


def _say(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def _own_deadline() -> float | None:
    """The child's deadline from :data:`DEADLINE_ENV`; None when unset or
    no positive finite number."""
    try:
        value = float(os.environ.get(DEADLINE_ENV, ""))
    except ValueError:
        return None
    return value if math.isfinite(value) and value > 0 else None


def _die_with_parent() -> None:
    """Linux: the kernel kills this child when its parent dies (a crash or
    SIGKILL of axross skips atexit). Elsewhere a no-op; the own deadline
    still ends the child."""
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        pr_set_pdeathsig = 1
        libc.prctl(pr_set_pdeathsig, signal.SIGKILL, 0, 0, 0)
    except (OSError, AttributeError):
        return
    if os.getppid() == 1:  # the parent died before prctl took hold
        os._exit(1)


def _allow_parent_debugger() -> None:
    """Linux with Yama (ptrace_scope 1): let the axross process that started
    this child - and the eu-stack it starts - read this child's native
    stack when it hangs. Without it only an ancestor may attach."""
    if not sys.platform.startswith("linux"):
        return
    try:
        parent = int(os.environ.get(PARENT_ENV, ""))
    except ValueError:
        return
    try:
        import ctypes

        pr_set_ptracer = 0x59616D61
        ctypes.CDLL(None, use_errno=True).prctl(pr_set_ptracer, parent, 0, 0, 0)
    except (OSError, AttributeError):
        pass


def _device_entries(devices) -> list[dict]:
    return [{"id": bytes(d.id()).decode("utf-8", "replace"), "description": d.description(),
             "default": bool(d.isDefault())} for d in devices]


def _child_main() -> int:
    """Create what axross creates, step by step, and say how far it got."""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    _die_with_parent()
    _allow_parent_debugger()
    deadline = _own_deadline()
    if deadline is not None:
        # A C thread: it needs no GIL, so a hang inside a native Qt call
        # cannot stop it. It writes the stacks to stderr and calls _exit.
        faulthandler.dump_traceback_later(deadline, exit=True)
    try:
        _say({"step": "start"})
        from PyQt6.QtGui import QGuiApplication

        app = QGuiApplication.instance() or QGuiApplication([sys.argv[0] or "axross"])
        # Deliver one event first. PyQt's QGuiApplication.notify() asks
        # Python (under the GIL) whether it is overridden, once per object,
        # and caches the answer. Qt 6.10's PipeWire backend sends an event
        # from its own thread while holding its loop lock, and the main
        # thread waits for that lock inside QMediaDevices holding the GIL:
        # a fresh app that never delivered an event deadlocked there
        # (measured on the release binary; the running GUI had long made
        # the check).
        from PyQt6.QtCore import QCoreApplication, QEvent

        QCoreApplication.sendEvent(app, QEvent(QEvent.Type.User))
        from PyQt6.QtMultimedia import (
            QAudioDecoder,
            QAudioOutput,
            QMediaDevices,
            QMediaPlayer,
        )

        _say({"step": "decoder"})
        decoder = QAudioDecoder()
        _say({"step": "player"})
        player = QMediaPlayer()
        _say({"step": "audio devices"})
        outputs = QMediaDevices.audioOutputs()
        settle = time.monotonic() + _DEVICE_SETTLE_SECONDS
        while not outputs and time.monotonic() < settle:
            app.processEvents()
            time.sleep(0.05)
            outputs = QMediaDevices.audioOutputs()
        QMediaDevices.defaultAudioOutput()
        inputs = QMediaDevices.audioInputs()
        QMediaDevices.defaultAudioInput()
        _say({"step": "audio output"})
        output = QAudioOutput()
        player.setAudioOutput(output)
        outputs, inputs = list(outputs), list(inputs)
        del decoder, player, output
    except Exception as exc:  # noqa: BLE001 - reported to the parent
        _say({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 1
    _say({"ok": True, "outputs": len(outputs), "inputs": len(inputs),
          "backend": os.environ.get("QT_AUDIO_BACKEND", ""),
          "output_devices": _device_entries(outputs), "input_devices": _device_entries(inputs)})
    return 0


__all__ = [
    "BACKEND_NAMES", "DEADLINE_ENV", "PROBE_SECONDS", "SECONDS_ENV", "STEP_LABELS",
    "AudioDeviceInfo", "ProbeResult", "active_backend", "backend_order", "cached", "child_deadline",
    "pipewire_running", "probe",
    "probe_async", "probe_command", "probe_seconds", "reset", "run_probe", "start",
    "unavailable_text",
]


if __name__ == "__main__":
    sys.exit(_child_main())
