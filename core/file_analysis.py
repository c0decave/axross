"""Explain one file with sift: which bytes the analysis worker gets.

* A file on the local file system is analysed where it is - a regular
  file only; a FIFO, a device, a directory or a dangling path is refused
  before the worker sees it.
* A file on any other backend is copied to a private temporary directory,
  at most ``max_remote_bytes`` (the size sift reads anyway), and the copy
  is removed afterwards. A file the listing shows as larger is not
  downloaded at all; one that turns out larger while copying is refused.
* The copy runs on its own thread, bounded by ``copy_timeout`` and ended
  by the caller's cancel event: a read that hangs on a dead connection is
  left behind (it reads no further and removes its copy once it
  returns) and never holds the caller.
* Results are kept for the session, keyed by backend (the object itself,
  through a weak reference), path, size, modification time and mode, so
  going back to a file costs nothing. An LLM request is kept only when the
  model answered - sift's fallback to its own analysis is not the model's
  answer. sift's own cache (by content hash) sits behind that in the worker.

No Qt here: the dock calls :meth:`FileAnalyzer.analyse` from a background
thread.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable

from core.analysis_worker import AnalysisWorker, WorkerResult

#: sift's default read limit (Config.max_bytes); a remote copy never exceeds it.
MAX_REMOTE_BYTES = 25_000_000
SESSION_CACHE_SIZE = 512
#: Longest a remote copy may take before the analysis gives up on it.
COPY_TIMEOUT = 300.0
_COPY_CHUNK = 1024 * 1024
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]")


@dataclass(frozen=True)
class _Run:
    llm: dict | None
    on_event: Callable[[dict], None] | None
    cancel: threading.Event


@dataclass(frozen=True)
class Target:
    backend: Any
    path: str
    name: str
    size: int
    mtime: float


@dataclass
class AnalysisResult:
    ok: bool
    summary: dict | None = None
    error: str = ""
    from_cache: bool = False
    from_session_cache: bool = False
    elapsed: float = 0.0
    calls: list = field(default_factory=list)


def is_local_backend(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _temp_name(name: str) -> str:
    """A file name safe inside the temp dir that keeps the extension."""
    base = os.path.basename(name.replace("\x00", "").replace("\\", "/"))
    base = _UNSAFE_NAME.sub("_", base).strip(". ")
    return base[:200] or "file"


class FileAnalyzer:
    def __init__(
        self,
        worker: AnalysisWorker | None = None,
        *,
        max_remote_bytes: int = MAX_REMOTE_BYTES,
        session_cache_size: int = SESSION_CACHE_SIZE,
        copy_timeout: float = COPY_TIMEOUT,
    ) -> None:
        self._worker = worker if worker is not None else AnalysisWorker()
        self._max_remote = max_remote_bytes
        self._copy_timeout = copy_timeout
        #: key -> (weak reference to the backend, result)
        self._session: OrderedDict[tuple, tuple] = OrderedDict()
        self._session_size = session_cache_size
        self._lock = threading.Lock()
        self._closed = False
        self._active_cancel: threading.Event | None = None

    #: Request fields that do not change the model's answer: the key (never
    #: kept in a cache key) and how long the parent waits.
    _NOT_THE_ANSWER = frozenset({"api_key", "timeout"})

    @classmethod
    def _key(cls, target: Target, llm: dict | None = None) -> tuple:
        """Every request field that shapes the answer - provider, endpoint,
        model, temperature, output limit, model loading - is part of it."""
        mode = (
            ("llm",)
            + tuple(
                sorted((k, repr(v)) for k, v in llm.items() if k not in cls._NOT_THE_ANSWER)
            )
            if llm
            else ("heuristic",)
        )
        return (id(target.backend), target.path, target.size, target.mtime, mode)

    def cached(self, target: Target, llm: dict | None = None) -> AnalysisResult | None:
        key = self._key(target, llm)
        with self._lock:
            entry = self._session.get(key)
            if entry is None:
                return None
            ref, result = entry
            if ref() is not target.backend:  # another object at a reused address
                del self._session[key]
                return None
            self._session.move_to_end(key)
            return result

    def analyse(
        self,
        target: Target,
        *,
        force: bool = False,
        llm: dict | None = None,
        on_event: Callable[[dict], None] | None = None,
        cancel: threading.Event | None = None,
    ) -> AnalysisResult:
        """``llm`` is a worker request (see core.llm_profiles.worker_request);
        ``cancel`` set ends this request (copy or analysis) only."""
        if self._closed:
            return AnalysisResult(False, error="analysis closed")
        if not force:
            hit = self.cached(target, llm)
            if hit is not None:
                return AnalysisResult(**{**hit.__dict__, "from_session_cache": True})
        run = _Run(llm, on_event, cancel if cancel is not None else threading.Event())
        self._active_cancel = run.cancel
        try:
            if is_local_backend(target.backend):
                result = self._analyse_local(target, run)
            else:
                result = self._analyse_remote(target, run)
        finally:
            self._active_cancel = None
        model_answered = bool(isinstance(result.summary, dict) and result.summary.get("llm_used"))
        if result.ok and (llm is None or model_answered):
            self._remember(target, llm, result)
        return result

    def _remember(self, target: Target, llm: dict | None, result: AnalysisResult) -> None:
        try:
            ref = weakref.ref(target.backend)
        except TypeError:  # a backend without weak references is not cached
            return
        key = self._key(target, llm)
        with self._lock:
            self._session[key] = (ref, result)
            self._session.move_to_end(key)
            while len(self._session) > self._session_size:
                self._session.popitem(last=False)

    def cancel(self) -> None:
        """End the request in flight - its copy or its analysis (thread-safe)."""
        active = self._active_cancel
        if active is not None:
            active.set()

    def close(self) -> None:
        self._closed = True
        self.cancel()
        self._worker.close()

    # -- local -------------------------------------------------------------
    def _analyse_local(self, target: Target, run: "_Run") -> AnalysisResult:
        try:
            st = os.stat(target.path)
        except OSError as exc:
            return AnalysisResult(False, error=f"cannot read {target.name}: {exc.strerror or exc}")
        if not stat.S_ISREG(st.st_mode):
            return AnalysisResult(False, error=f"{target.name} is not a regular file")
        return self._run(target.path, target.name, run)

    # -- remote ------------------------------------------------------------
    def _analyse_remote(self, target: Target, run: "_Run") -> AnalysisResult:
        if target.size > self._max_remote:
            return AnalysisResult(False, error=self._too_large(target.size))
        copy = copy_bounded(target, self._max_remote, run.cancel, self._copy_timeout)
        try:
            if copy.status == "cancelled":
                return AnalysisResult(False, error="analysis cancelled")
            if copy.status == "timeout":
                return AnalysisResult(
                    False, error=f"timed out copying {target.name} after {self._copy_timeout:.0f} s"
                )
            if copy.status == "error":
                return AnalysisResult(False, error=f"cannot read {target.name}: {copy.error}")
            if copy.status == "too_large":
                return AnalysisResult(False, error=self._too_large(copy.total))
            return self._run(copy.path, target.name, run)
        finally:
            copy.cleanup()

    def _too_large(self, size: int) -> str:
        return (
            f"too large for automatic analysis of a remote file "
            f"({size / 1e6:.1f} MB, limit {self._max_remote / 1e6:.0f} MB)"
        )

    def _run(self, path: str, name: str, run: "_Run") -> AnalysisResult:
        llm = run.llm
        kwargs: dict = {}
        if llm:
            # No total timeout: the worker bounds an LLM analysis by the
            # child's silence (analysis_worker.llm_silence_bound), since sift
            # gives a healthy streaming map-reduce no total bound.
            kwargs = {"llm": llm, "on_event": run.on_event}
        res: WorkerResult = self._worker.analyse(path, name, cancel_event=run.cancel, **kwargs)
        return AnalysisResult(
            ok=res.ok,
            summary=res.summary,
            error=res.error,
            from_cache=res.from_cache,
            elapsed=res.elapsed,
            calls=res.calls,
        )


@dataclass
class BoundedCopy:
    """Outcome of :func:`copy_bounded`.

    ``status`` is ``"ok"`` (``path`` holds the whole file), ``"too_large"``
    (more than the limit; ``total`` is limit + 1), ``"error"`` (``error``
    says why), ``"cancelled"`` or ``"timeout"``. :meth:`cleanup` removes
    the private temp directory; a copy still reading when its caller gave
    up removes it itself once the read returns.
    """

    status: str
    path: str = ""
    tmpdir: str = ""
    total: int = 0
    error: str = ""

    def cleanup(self) -> None:
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)


def copy_bounded(
    target: Target,
    limit: int,
    cancel: threading.Event,
    timeout: float,
    *,
    prefix: str = "axross-analysis-",
) -> BoundedCopy:
    """Copy at most ``limit`` bytes of a remote file into a private temp dir.

    The read runs on its own thread, so a backend that hangs never holds
    the caller past ``timeout`` or a set ``cancel``. One byte beyond the
    limit is read to tell a file of exactly ``limit`` bytes from a longer one.
    """
    tmpdir = tempfile.mkdtemp(prefix=prefix)
    local = os.path.join(tmpdir, _temp_name(target.name))
    copy = _Copy(target, local, limit + 1, cancel)
    thread = threading.Thread(target=copy.run, name="axross-bounded-copy", daemon=True)
    thread.start()
    deadline = time.monotonic() + timeout
    while not copy.done.wait(0.1):
        if cancel.is_set() or time.monotonic() >= deadline:
            break
    with copy.lock:
        if not copy.done.is_set():  # still reading: leave it, it cleans up after itself
            copy.abandoned = True
            return BoundedCopy("cancelled" if cancel.is_set() else "timeout", total=copy.total)
    result = BoundedCopy("ok", path=local, tmpdir=tmpdir, total=copy.total)
    if cancel.is_set():
        result.status = "cancelled"
    elif copy.error is not None:
        result.status, result.error = "error", str(copy.error)
    elif copy.total > limit:
        result.status = "too_large"
    return result


class _Copy:
    """Copies at most ``limit`` bytes of a remote file; runs on its own thread.

    A caller that stops waiting sets ``abandoned``; the thread then removes
    the copy's directory itself once the read returns.
    """

    def __init__(self, target: Target, local: str, limit: int, cancel: threading.Event) -> None:
        self.target, self.local, self.limit, self.cancel = target, local, limit, cancel
        self.total = 0
        self.error: OSError | None = None
        self.done = threading.Event()
        self.lock = threading.Lock()
        self.abandoned = False

    def run(self) -> None:
        try:
            fd = os.open(self.local, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                src = self.target.backend.open_read(self.target.path)
                try:
                    # A copy given up on (timed out) reads no further: the
                    # backend's connection is free again once the read in
                    # flight returns.
                    while (
                        self.total < self.limit
                        and not self.cancel.is_set()
                        and not self.abandoned
                    ):
                        chunk = src.read(min(_COPY_CHUNK, self.limit - self.total))
                        if not chunk:
                            break
                        out.write(chunk)
                        self.total += len(chunk)
                finally:
                    close = getattr(src, "close", None)
                    if close is not None:
                        close()
        except OSError as exc:
            self.error = exc
        except Exception as exc:  # a backend raising something else is a read error too
            self.error = OSError(f"{type(exc).__name__}: {exc}")
        finally:
            with self.lock:
                self.done.set()
                if self.abandoned:
                    shutil.rmtree(os.path.dirname(self.local), ignore_errors=True)
