"""Run sift file analyses in a separate, killable process.

sift (``sift.summarize.summarize_path``) bounds its own work between steps;
a piece that hangs inside C code - zlib, sqlite3, Pillow's header read, a
regex - or a read that never returns (a FIFO) is not interrupted. So the
analysis runs in one long-lived child process: the parent kills it once a
wall-clock bound has passed (in LLM mode: once the child has been silent
too long, see llm_silence_bound) and starts a fresh one for the next file. The
child also carries a CPU bound per file (RLIMIT_CPU: the kernel ends a
piece that spins) and writes no core dump.

Not a fork of the GUI process: a fork copies only the calling thread, and
Qt's threads would leave their locks held in the child. The child is a new
interpreter (``python -m core.analysis_worker``).

The pipe carries JSON lines, not pickle: the child reads files from
anywhere, and nothing it sends back is ever unpickled. Replies are capped
in size. The child prints nothing on stdout but replies; a stray print
from a library goes to stderr.

Request:  {"id": n, "path": str, "display_name": str, "time_budget": s,
           "cpu_seconds": s, "llm": {provider, endpoint, model, api_key,
           temperature, timeout, max_output_tokens, allow_model_load} | null,
           "model_time_budget": s (LLM mode only),
           "sift": {max_bytes, vision, context_tokens, tags, categories,
           cache} (each optional; the Analysis settings, core.analysis_settings)}
Event:    {"id": n, "event": "progress", "answer": chars, "reasoning": chars}
          {"id": n, "event": "call", "usage": {...}}       (LLM mode only)
Reply:    {"id": n, "ok": bool, "summary": dict | null, "error": str,
           "from_cache": bool, "elapsed": s, "calls": [usage, ...]}

Progress carries counts, never text: sift removes secrets from what the
model said only once the answer is complete, so a live view of the raw
answer would show what sift is about to hide. The API key travels in the
request over the pipe - never in argv or the environment - and nothing
the child sends back contains it.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import math
import os
import selectors
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from core.secure_storage import ensure_private_dir
from core.subprocess_env import worker_env

log = logging.getLogger(__name__)

#: Seconds sift may spend on one file (its own, cooperative bound).
DEFAULT_TIME_BUDGET = 60.0
#: The parent's wall-clock bound beyond sift's own: start-up, a slow read.
WALL_MARGIN = 30.0
#: CPU seconds one file may use in the child before the kernel ends it.
DEFAULT_CPU_SECONDS = 120
#: Address space of the child (bytes). sift caps pypdf at 1 GiB.
ADDRESS_SPACE_LIMIT = 4 * 1024**3
#: sift's bound on the model's work for one file. Sent with every LLM
#: request and set as the child's Config.model_time_budget: one number.
MODEL_TIME_BUDGET = 900.0
#: Seconds sift's model client waits for the server's next byte (Config.timeout).
DEFAULT_LLM_TIMEOUT = 180.0
#: Most HTTP requests sift's model client makes in a row without a streamed
#: piece between them, each waiting up to that timeout: the model inventory,
#: two requests (Ollama /api/tags + /api/ps in sift/llm/ollama.py inventory();
#: LM Studio /api/v0/models, else /models, in sift/llm/openai_compat.py
#: inventory()), then the chat request, sent twice when a server refuses
#: stream_options (openai_compat._collect).
SIFT_SILENT_REQUESTS = 4
#: Least time between two progress events from the child.
PROGRESS_INTERVAL = 0.15
#: Largest reply line accepted from the child.
MAX_REPLY_BYTES = 8 * 1024**2
#: How long a fresh child may take to import sift and answer its first file.
STARTUP_SECONDS = 30.0
#: The keys of a request's "sift" options that set a field of sift's Config
#: of the same name (core.analysis_settings); anything else is not passed on.
SIFT_OPTIONS = ("max_bytes", "vision", "context_tokens", "tags", "categories")


class WorkerProtocolError(Exception):
    """The child sent something that is not a valid reply."""


def worker_argv() -> list[str]:
    """The command that starts the analysis child. A frozen build has no
    ``python -m``: the binary itself answers ``--analysis-worker`` (main.py)."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--analysis-worker"]
    return [sys.executable, "-m", "core.analysis_worker"]


def sift_available() -> bool:
    """True when sift can be imported and a worker can be started - from
    source, or in a frozen build that bundles sift (axross-full)."""
    try:
        return importlib.util.find_spec("sift") is not None
    except (ImportError, ValueError):
        return False


def sift_version() -> str:
    try:
        import sift

        return str(getattr(sift, "__version__", ""))
    except ImportError:
        return ""


@dataclass
class WorkerResult:
    ok: bool
    summary: dict | None = None
    error: str = ""
    from_cache: bool = False
    elapsed: float = 0.0
    calls: list = field(default_factory=list)


class _LineReader:
    """Splits bytes into lines; refuses a line longer than ``limit``."""

    def __init__(self, limit: int = MAX_REPLY_BYTES) -> None:
        self._buf = bytearray()
        self._limit = limit

    def feed(self, data: bytes) -> None:
        self._buf += data

    def next_line(self) -> bytes | None:
        pos = self._buf.find(b"\n")
        if pos < 0:
            if len(self._buf) > self._limit:
                raise WorkerProtocolError(f"reply longer than {self._limit} bytes")
            return None
        if pos > self._limit:
            raise WorkerProtocolError(f"reply longer than {self._limit} bytes")
        line = bytes(self._buf[:pos])
        del self._buf[: pos + 1]
        return line


def llm_silence_bound(llm_timeout: float, time_budget: float) -> float:
    """Longest an LLM analysis may go without a word from the child.

    No total wall-clock bound fits a healthy LLM analysis. sift checks its
    model-time budget only *before* each map call of a long file, so the
    last map call starts with the budget nearly spent and the reduce call
    always follows it; and its per-call timeout (``llm_timeout``) bounds the
    wait for the server's next byte, not the call. A model streaming
    slowly but steadily makes every call as long as it takes.

    What is bounded is silence. The child sends an event per streamed
    piece (throttled to PROGRESS_INTERVAL) and one per finished call. It is
    silent while sift does its own work - at most ``time_budget`` for the
    whole file - and while requests wait for the server's next byte: at
    most ``llm_timeout`` each, then sift gives the request up, and at most
    SIFT_SILENT_REQUESTS of them in a row. Anything longer is a hang the
    parent ends. The numbers are the ones sent to the child.
    """
    return float(time_budget) + SIFT_SILENT_REQUESTS * float(llm_timeout) + WALL_MARGIN


def cpu_seconds_for(time_budget: float) -> int:
    """The CPU bound of one file for a time budget: the default's ratio
    (DEFAULT_CPU_SECONDS for DEFAULT_TIME_BUDGET), never below the default -
    a larger budget set in the Analysis settings is not ended by the kernel
    before sift's own bound."""
    ratio = DEFAULT_CPU_SECONDS / DEFAULT_TIME_BUDGET
    return max(DEFAULT_CPU_SECONDS, math.ceil(ratio * float(time_budget)))


def _package_root() -> str:
    """The directory that holds the ``core`` package, for the child's path."""
    return str(Path(__file__).resolve().parent.parent)


class AnalysisWorker:
    """Parent side: starts the child on demand, one request at a time.

    ``analyse`` blocks; call it from a background thread. ``cancel`` may be
    called from any thread and ends a running request (the child is killed).
    """

    def __init__(
        self,
        cache_dir: str | os.PathLike | None = None,
        *,
        command: list[str] | None = None,
    ) -> None:
        self._cache_dir = os.fspath(cache_dir) if cache_dir is not None else None
        self._command = command or worker_argv()
        self._proc: subprocess.Popen | None = None
        self._reader = _LineReader()
        self._call_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._next_id = 0
        self._closed = False
        #: The cancel event of the request in flight (None when idle).
        self._current_cancel: threading.Event | None = None

    # -- lifecycle ---------------------------------------------------------
    @property
    def pid(self) -> int | None:
        proc = self._proc
        return proc.pid if proc is not None and proc.poll() is None else None

    def _start(self) -> subprocess.Popen:
        # The frozen child reuses this process's extraction folder and its
        # libraries: the loader variables stay (core.subprocess_env.worker_env).
        env = worker_env()
        root = _package_root()
        env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        env.pop("AXROSS_SIFT_CACHE", None)
        if self._cache_dir:
            # sift's results describe the files' content: a folder of the
            # user's own, 0700, or no cache at all.
            try:
                ensure_private_dir(self._cache_dir)
                env["AXROSS_SIFT_CACHE"] = self._cache_dir
            except OSError as exc:
                log.warning("sift's cache folder %s is not usable: %s", self._cache_dir, exc)
        proc = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=root,
            close_fds=True,
        )
        self._reader = _LineReader()
        log.debug("analysis worker started (pid %s)", proc.pid)
        return proc

    def _kill(self) -> None:
        with self._state_lock:
            proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log.warning("analysis worker %s did not exit after SIGKILL", proc.pid)
        for stream in (proc.stdin, proc.stdout):
            try:
                stream.close()
            except (OSError, AttributeError):
                pass

    def close(self) -> None:
        """Kill the child; later requests start nothing (thread-safe).

        ``_closed`` is set under the state lock, where analyse() starts a
        child: either the start sees it, or the kill below ends that child.
        """
        with self._state_lock:
            self._closed = True
        current = self._current_cancel
        if current is not None:
            current.set()
        self._kill()

    def cancel(self) -> None:
        """End the request in flight, if any (thread-safe). An idle child is left alone."""
        current = self._current_cancel
        if current is not None:
            current.set()

    # -- requests ----------------------------------------------------------
    def analyse(
        self,
        path: str,
        display_name: str,
        *,
        time_budget: float = DEFAULT_TIME_BUDGET,
        timeout: float | None = None,
        cpu_seconds: int = DEFAULT_CPU_SECONDS,
        llm: dict | None = None,
        sift: dict | None = None,
        on_event: Callable[[dict], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> WorkerResult:
        """``cancel_event`` set (by the caller, or by cancel()) ends this request only.

        ``sift`` holds the Analysis settings the child sets in sift's Config
        (SIFT_OPTIONS) and ``cache``: False keeps this file out of sift's cache.

        ``timeout`` bounds the whole request. Left out, it is
        ``time_budget + WALL_MARGIN`` without ``llm``; with ``llm`` there is
        no total bound but a bound on silence (:func:`llm_silence_bound`),
        derived from the very ``timeout`` and ``time_budget`` the child gets.
        """
        silence: float | None = None
        if timeout is None:
            if llm:
                silence = llm_silence_bound(
                    float(llm.get("timeout", DEFAULT_LLM_TIMEOUT)), time_budget
                )
            else:
                timeout = time_budget + WALL_MARGIN
        cancel = cancel_event if cancel_event is not None else threading.Event()
        with self._call_lock:
            if self._closed:
                return WorkerResult(False, error="analysis worker closed")
            if cancel.is_set():
                return WorkerResult(False, error="analysis cancelled")
            self._current_cancel = cancel
            started = time.monotonic()
            first_wait = timeout if silence is None else silence
            try:
                with self._state_lock:
                    if self._closed:  # close() ran after the check above: start nothing
                        raise _Closed
                    if self._proc is None or self._proc.poll() is not None:
                        self._proc = self._start()
                        first_wait += STARTUP_SECONDS
                    proc = self._proc
                self._next_id += 1
                request = {
                    "id": self._next_id,
                    "path": path,
                    "display_name": display_name,
                    "time_budget": time_budget,
                    "cpu_seconds": cpu_seconds,
                    "llm": llm,
                }
                if llm:
                    request["model_time_budget"] = MODEL_TIME_BUDGET
                if sift:
                    request["sift"] = sift
                proc.stdin.write(json.dumps(request).encode() + b"\n")
                proc.stdin.flush()
                reply = self._read_reply(
                    proc, self._next_id, started + first_wait, on_event, cancel, silence
                )
                return _result_from(reply)
            except _Closed:
                return WorkerResult(False, error="analysis worker closed")
            except _Timeout:
                self._kill()
                error = (
                    f"analysis timed out after {first_wait:.0f} s"
                    if silence is None
                    else f"analysis stopped answering for {silence:.0f} s"
                )
                return WorkerResult(False, error=error, elapsed=time.monotonic() - started)
            except (OSError, ValueError, WorkerProtocolError, _ChildGone) as exc:
                cancelled = cancel.is_set()
                self._kill()
                if cancelled:
                    return WorkerResult(
                        False, error="analysis cancelled", elapsed=time.monotonic() - started
                    )
                return WorkerResult(
                    False,
                    error=f"analysis process failed: {exc}",
                    elapsed=time.monotonic() - started,
                )
            finally:
                self._current_cancel = None

    def _read_reply(
        self,
        proc: subprocess.Popen,
        request_id: int,
        deadline: float,
        on_event: Callable[[dict], None] | None = None,
        cancel: threading.Event | None = None,
        silence: float | None = None,
    ) -> dict:
        fd = proc.stdout.fileno()
        # A selector, not select.select: that refuses a descriptor past
        # FD_SETSIZE (1024), which a process with many open files gets.
        selector = selectors.DefaultSelector()
        try:
            selector.register(fd, selectors.EVENT_READ)
            return self._read_until(
                proc, fd, selector, request_id, deadline, on_event, cancel, silence
            )
        finally:
            selector.close()

    def _read_until(
        self, proc, fd, selector, request_id, deadline, on_event, cancel, silence=None
    ) -> dict:
        """``silence`` set: every line of this request moves the deadline to
        ``silence`` seconds from now (see llm_silence_bound)."""
        while True:
            line = self._reader.next_line()
            if line is not None:
                try:
                    reply = json.loads(line)
                except RecursionError as exc:  # nesting deeper than the decoder's stack
                    raise WorkerProtocolError("reply nested too deeply") from exc
                if not isinstance(reply, dict):
                    raise WorkerProtocolError("reply is not an object")
                if reply.get("id") != request_id:
                    continue  # a late reply to a request that was given up on
                if silence is not None:
                    deadline = time.monotonic() + silence
                if "event" in reply:
                    if on_event is not None:
                        try:
                            on_event(reply)
                        except Exception:  # a display hook must not end the request
                            log.exception("analysis event handler failed")
                    continue
                return reply
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Timeout
            ready = selector.select(min(remaining, 0.2))
            if cancel is not None and cancel.is_set():
                raise _ChildGone("cancelled")
            if not ready:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                # The pipe closes before the exit status can be collected.
                try:
                    code = proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    code = None
                raise _ChildGone(f"exit status {code}")
            self._reader.feed(chunk)


def _result_from(reply: dict) -> WorkerResult:
    """The child's reply as a WorkerResult; a value of the wrong type is a
    protocol error (the child is then replaced), never an exception here."""
    elapsed = reply.get("elapsed") or 0.0
    calls = reply.get("calls") or []
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
        raise WorkerProtocolError(f"elapsed is not a number: {type(elapsed).__name__}")
    if not isinstance(calls, list):
        raise WorkerProtocolError(f"calls is not a list: {type(calls).__name__}")
    return WorkerResult(
        ok=bool(reply.get("ok")),
        summary=reply.get("summary") if isinstance(reply.get("summary"), dict) else None,
        error=str(reply.get("error") or ""),
        from_cache=bool(reply.get("from_cache")),
        elapsed=float(elapsed),
        calls=[c for c in calls if isinstance(c, dict)],
    )


class _Closed(Exception):
    pass


class _Timeout(Exception):
    pass


class _ChildGone(Exception):
    pass


# -- child side -------------------------------------------------------------
def _limit_resources() -> None:
    try:
        import resource
    except ImportError:  # pragma: no cover - not POSIX
        return
    for name, value in (("RLIMIT_CORE", 0), ("RLIMIT_AS", ADDRESS_SPACE_LIMIT)):
        limit = getattr(resource, name, None)
        if limit is None:
            continue
        try:
            _soft, hard = resource.getrlimit(limit)
            if hard != resource.RLIM_INFINITY:
                value = min(value, hard)
            resource.setrlimit(limit, (value, hard))
        except (ValueError, OSError):
            pass


def _cpu_bound(seconds: int) -> None:
    """Let the next file use ``seconds`` more CPU time than so far."""
    try:
        import resource
    except ImportError:  # pragma: no cover
        return
    usage = resource.getrusage(resource.RUSAGE_SELF)
    soft = int(usage.ru_utime + usage.ru_stime) + max(1, int(seconds))
    try:
        _s, hard = resource.getrlimit(resource.RLIMIT_CPU)
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
    except (ValueError, OSError):
        pass


def _usage(call) -> dict:
    """A sift CallUsage as plain JSON values."""
    from dataclasses import asdict, is_dataclass

    data = asdict(call) if is_dataclass(call) else {}
    data["tokens_per_second"] = getattr(call, "tokens_per_second", None)
    return data


def _config_for(request: dict):
    """sift's Config for one request: the time limits are the ones the
    parent sent and bounds its wait with (llm_silence_bound), the request's
    "sift" options (SIFT_OPTIONS) set the fields of the same name. sift
    checks those options by its own rules (sift.config.validate on a Config
    holding them; ConfigError for a value it refuses) - the options alone:
    the LLM profile's values reach sift as they did before the options."""
    from sift.config import Config, validate

    llm = request.get("llm") if isinstance(request.get("llm"), dict) else None
    if llm:
        config = Config(
            provider=str(llm.get("provider") or "ollama"),
            endpoint=str(llm.get("endpoint") or ""),
            model=str(llm.get("model") or ""),
            api_key=str(llm.get("api_key") or ""),
            temperature=float(llm.get("temperature", 0.2)),
            timeout=float(llm.get("timeout", DEFAULT_LLM_TIMEOUT)),
            max_output_tokens=int(llm.get("max_output_tokens", 2000)),
            allow_model_load=bool(llm.get("allow_model_load", False)),
            stream=True,
        )
        config.model_time_budget = float(request.get("model_time_budget") or MODEL_TIME_BUDGET)
    else:
        config = Config(no_llm=True, provider="none")
    config.time_budget = float(request.get("time_budget") or DEFAULT_TIME_BUDGET)
    raw = request.get("sift") if isinstance(request.get("sift"), dict) else {}
    options = {
        key: list(raw[key]) if isinstance(raw[key], list) else raw[key]
        for key in SIFT_OPTIONS
        if key in raw
    }
    if options:
        validate(Config(**options))
        for key, value in options.items():
            setattr(config, key, value)
    return config


def _child_main() -> int:
    out = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)  # print() and C-level writes to fd 1 go to stderr now
    sys.stdout = sys.stderr
    _limit_resources()

    from sift.cache import SummaryCache
    from sift.llm import build_client
    from sift.summarize import summarize_path

    cache_dir = os.environ.get("AXROSS_SIFT_CACHE")
    cache = SummaryCache(directory=Path(cache_dir)) if cache_dir else None

    for raw in sys.stdin.buffer:
        try:
            request = json.loads(raw)
            request_id = request["id"]
        except (ValueError, KeyError, TypeError):
            continue
        started = time.monotonic()
        reply: dict = {"id": request_id}
        calls: list[dict] = []

        def emit(obj: dict, _id=request_id) -> None:
            out.write(json.dumps({"id": _id, **obj}, default=str).encode() + b"\n")

        try:
            _cpu_bound(int(request.get("cpu_seconds") or DEFAULT_CPU_SECONDS))
            llm = request.get("llm") if isinstance(request.get("llm"), dict) else None
            client = None
            config = _config_for(request)
            if llm:
                client = build_client(config)
                if client is not None:
                    counts = {"answer": 0, "reasoning": 0, "last": 0.0}

                    def progress(answer: int, reasoning: int = 0, counts=counts) -> None:
                        counts["answer"] += int(answer or 0)
                        counts["reasoning"] += int(reasoning or 0)
                        now = time.monotonic()
                        if now - counts["last"] >= PROGRESS_INTERVAL:
                            counts["last"] = now
                            emit(
                                {
                                    "event": "progress",
                                    "answer": counts["answer"],
                                    "reasoning": counts["reasoning"],
                                }
                            )

                    def on_call(usage) -> None:
                        data = _usage(usage)
                        data.pop("api_key", None)
                        calls.append(data)
                        emit({"event": "call", "usage": data})

                    client.on_progress = progress
                    client.on_call = on_call
            options = request.get("sift") if isinstance(request.get("sift"), dict) else {}
            summary = summarize_path(
                Path(request["path"]),
                config,
                client,
                cache if options.get("cache", True) is not False else None,
                display_name=str(request.get("display_name") or ""),
            )
            if client is not None:  # the last counts, whatever the throttle held back
                emit(
                    {
                        "event": "progress",
                        "answer": counts["answer"],
                        "reasoning": counts["reasoning"],
                    }
                )
            reply.update(
                ok=True,
                summary=summary.to_dict(),
                error="",
                calls=calls,
                from_cache=bool(getattr(summary, "from_cache", False)),
            )
        except Exception as exc:  # sift promises not to raise; this is the backstop
            reply.update(ok=False, summary=None, error=f"{type(exc).__name__}: {exc}")
        reply["elapsed"] = time.monotonic() - started
        out.write(json.dumps(reply, default=str).encode() + b"\n")
    return 0


if __name__ == "__main__":
    sys.exit(_child_main())
