"""Run a client's regular expression in a killable child process.

Python's ``re`` has no time limit and cannot be interrupted: a pattern
that backtracks catastrophically - ``(?:(a)+)+$``, ``(a|a)+$``,
``(a+){2,}$`` - spends seconds to hours inside one ``search()`` call on a
line of a few dozen characters, holding the GIL, and neither the tool's
timeout nor a cancel reaches it. A cheap shape check (the MCP grep tool's
``_REDOS_NESTED_QUANTIFIER``) catches only the textbook form.

So the matching runs in a child interpreter: the parent sends the text of
one file, the child answers with the numbers of the lines that match, and
the parent kills the child when one file takes longer than its bound (or
the call is cancelled). The child is started with ``-I -S`` and runs only
the stdlib code in :data:`_CHILD_SOURCE` (a frozen build answers
``--regex-worker``, main.py); it reads nothing but its stdin, and its
address space and CPU time are capped (RLIMIT_AS; RLIMIT_CPU per text,
so the bound holds when the parent is gone), and it ends with its parent
(PR_SET_PDEATHSIG on Linux, a kill-on-close job object on Windows).

Protocol over the pipes (all integers big-endian):

* parent -> child, once: ``u32 len`` + the pattern (UTF-8, surrogatepass);
  the child answers ``u32 0`` when it compiled, else ``u32 1`` + ``u32
  len`` + the error text.
* parent -> child, per file: ``u32 limit`` + ``u32 len`` + the text
  (UTF-8); the child answers ``u32 count`` + ``count`` x ``u32 line_no``
  (1-based, at most ``limit``) - the lines of ``str.splitlines()``.
"""

from __future__ import annotations

import logging
import os
import queue
import struct
import subprocess
import sys
import threading
import time
from typing import Callable

from core.subprocess_env import worker_env

log = logging.getLogger(__name__)

#: Seconds one file's matching may take before the child is killed.
DEFAULT_SECONDS_PER_FILE = 5.0
#: Seconds a fresh child may take to start and compile the pattern.
STARTUP_SECONDS = 15.0
#: Address space of the child (bytes): a pattern and one 4 MiB file.
ADDRESS_SPACE_LIMIT = 1024**3
#: Most line numbers one answer may carry.
MAX_LIMIT = 1 << 20

_CHILD_SOURCE = r'''
import os, re, struct, sys
_parent, _cpu = int(sys.argv[-3]), int(sys.argv[-2])
if sys.platform.startswith("linux"):
    # End with the parent: a server killed while this child backtracks
    # must not leave it spinning (PR_SET_PDEATHSIG = 1).
    try:
        import ctypes, signal
        ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGKILL), 0, 0, 0)
    except Exception:
        pass
if _parent and os.getppid() != _parent:
    raise SystemExit(0)
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (int(sys.argv[-1]), int(sys.argv[-1])))
except Exception:
    pass
def cpu_budget(seconds):
    # The CPU time this child may still use: what it used so far plus
    # *seconds* (SIGXCPU ends it) - the bound holds without the parent.
    try:
        import resource
        used = resource.getrusage(resource.RUSAGE_SELF)
        soft = int(used.ru_utime + used.ru_stime) + seconds
        hard = resource.getrlimit(resource.RLIMIT_CPU)[1]
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
    except Exception:
        pass
cpu_budget(_cpu)
inp, out = sys.stdin.buffer, sys.stdout.buffer
def read(n):
    data = inp.read(n)
    if len(data) != n:
        raise SystemExit(0)
    return data
def u32():
    return struct.unpack(">I", read(4))[0]
pattern = read(u32()).decode("utf-8", "surrogatepass")
try:
    search = re.compile(pattern).search
except (re.error, OverflowError, RecursionError, ValueError) as exc:
    msg = str(exc).encode("utf-8", "replace")[:4096]
    out.write(struct.pack(">II", 1, len(msg)) + msg); out.flush()
    raise SystemExit(0)
out.write(struct.pack(">I", 0)); out.flush()
while True:
    limit = u32()
    text = read(u32()).decode("utf-8", "replace")
    cpu_budget(_cpu)
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if search(line):
            hits.append(n)
            if len(hits) >= limit:
                break
    out.write(struct.pack(">I", len(hits)) + b"".join(struct.pack(">I", h) for h in hits))
    out.flush()
'''


class RegexTimeout(Exception):
    """The pattern ran longer than its bound on one text (the child was killed)."""


class RegexCancelled(Exception):
    """The caller cancelled while the child was matching (the child was killed)."""


def cpu_seconds_for(seconds_per_text: float) -> int:
    """The CPU seconds the child may spend on one text (or on compiling the
    pattern): the wall-clock bound with room to spare - the parent's timer
    normally ends the child first, this limit ends it when the parent is
    gone (RLIMIT_CPU, POSIX)."""
    return int(max(seconds_per_text, STARTUP_SECONDS)) * 2 + 5


def worker_argv(seconds_per_text: float = DEFAULT_SECONDS_PER_FILE) -> list[str]:
    """The command that starts the matcher child. A frozen build has no
    ``python -c``: the binary itself answers ``--regex-worker`` (main.py).
    The last three arguments: this process's pid (the child ends when its
    parent is gone), the CPU seconds per text, the address-space limit."""
    tail = [str(os.getpid()), str(cpu_seconds_for(seconds_per_text)), str(ADDRESS_SPACE_LIMIT)]
    if getattr(sys, "frozen", False):
        return [sys.executable, "--regex-worker", *tail]
    return [sys.executable, "-I", "-S", "-c", _CHILD_SOURCE, *tail]


def _kill_with_parent_windows(proc: subprocess.Popen) -> None:
    """Windows has neither PR_SET_PDEATHSIG nor RLIMIT_CPU: put the child in
    a job object that kills it when the last handle to the job - this
    process's - closes, i.e. when this process ends however it ends. A
    watchdog thread in the child cannot do it: ``re`` holds the GIL for the
    whole backtracking search."""
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        class _BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                        ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class _IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", _BasicLimits),
                        ("IoInfo", _IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW")
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info),
                                                ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), "SetInformationJobObject")
        if not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle))):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject")
        proc._axross_job = job  # the handle stays open as long as this process
    except Exception as exc:  # noqa: BLE001 - best effort; the parent's timer still applies
        log.warning("regex worker %s: no kill-on-exit job object: %s", proc.pid, exc)


def _child_main() -> int:
    """The frozen build's ``--regex-worker`` entry point."""
    exec(compile(_CHILD_SOURCE, "<regex-worker>", "exec"), {"__name__": "__regex_worker__"})
    return 0


class RegexMatcher:
    """One compiled pattern in one child process; use as a context manager.

    :meth:`matching_lines` returns the 1-based numbers of the lines of a
    text that the pattern finds something in (``re.search``), at most
    *limit*. A bad pattern raises ``ValueError`` from the constructor.
    *is_cancelled* is polled while the child works.
    """

    def __init__(
        self,
        pattern: str,
        *,
        seconds_per_text: float = DEFAULT_SECONDS_PER_FILE,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self._seconds = float(seconds_per_text)
        self._is_cancelled = is_cancelled or (lambda: False)
        self._replies: queue.Queue = queue.Queue()
        self._proc = subprocess.Popen(
            worker_argv(self._seconds),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=worker_env(),
            close_fds=True,
        )
        _kill_with_parent_windows(self._proc)
        self._reader = threading.Thread(target=self._read_loop, name="regex-worker-reader",
                                        daemon=True)
        self._reader.start()
        try:
            data = pattern.encode("utf-8", "surrogatepass")
            self._send(struct.pack(">I", len(data)) + data)
            status = self._wait(STARTUP_SECONDS)
            if status != 0:
                raise ValueError(self._wait(STARTUP_SECONDS) or "the pattern does not compile")
        except BaseException:
            self.close()
            raise

    # -- the pipe -----------------------------------------------------
    def _read_exact(self, n: int) -> bytes | None:
        stream = self._proc.stdout
        data = b""
        while len(data) < n:
            chunk = stream.read(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _read_loop(self) -> None:
        """Turn the child's answers into queue items: an int status, an
        error text, a list of line numbers; None when the pipe ended."""
        try:
            head = self._read_exact(4)
            if head is None:
                return
            (status,) = struct.unpack(">I", head)
            self._replies.put(status)
            if status != 0:
                size = self._read_exact(4)
                if size is not None:
                    text = self._read_exact(min(struct.unpack(">I", size)[0], 4096)) or b""
                    self._replies.put(text.decode("utf-8", "replace"))
                return
            while True:
                head = self._read_exact(4)
                if head is None:
                    return
                (count,) = struct.unpack(">I", head)
                if count > MAX_LIMIT:
                    return
                body = self._read_exact(4 * count) if count else b""
                if body is None:
                    return
                self._replies.put(list(struct.unpack(f">{count}I", body)))
        except (OSError, ValueError, struct.error):
            return
        finally:
            self._replies.put(None)

    def _send(self, data: bytes) -> None:
        try:
            self._proc.stdin.write(data)
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise OSError(f"the regex worker is gone: {exc}") from exc

    def _wait(self, seconds: float):
        deadline = time.monotonic() + seconds
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self.close()
                raise RegexTimeout(f"the pattern ran longer than {seconds:g} s")
            try:
                reply = self._replies.get(timeout=min(left, 0.1))
            except queue.Empty:
                if self._is_cancelled():
                    self.close()
                    raise RegexCancelled("cancelled while matching") from None
                continue
            if reply is None:
                raise OSError("the regex worker ended unexpectedly")
            return reply

    # -- the API ------------------------------------------------------
    def matching_lines(self, text: str, limit: int) -> list[int]:
        """Line numbers (1-based, ``str.splitlines``) of *text* the pattern
        finds a match in; at most *limit*. RegexTimeout / RegexCancelled
        end this matcher."""
        limit = max(1, min(int(limit), MAX_LIMIT))
        data = text.encode("utf-8", "surrogatepass")
        self._send(struct.pack(">II", limit, len(data)) + data)
        reply = self._wait(self._seconds)
        if not isinstance(reply, list):
            raise OSError("the regex worker sent no line numbers")
        return reply

    def close(self) -> None:
        proc = self._proc
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            log.warning("regex worker %s did not end after kill", proc.pid)
        self._reader.join(timeout=1)
        for stream in (proc.stdin, proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    def __enter__(self) -> "RegexMatcher":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


__all__ = ["DEFAULT_SECONDS_PER_FILE", "RegexCancelled", "RegexMatcher", "RegexTimeout",
           "worker_argv"]
