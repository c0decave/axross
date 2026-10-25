"""Start long-lived children from a thread that lives as long as axross.

``prctl(PR_SET_PDEATHSIG)`` - bubblewrap's ``--die-with-parent``, and any
child that asks to die with its parent - fires when the *thread* that
forked the child ends, not the process (proc(5): "the parent thread").
axross starts its agent worker and MCP servers from short-lived threads (a
tab's run thread ends after each task), so the sandbox was killed (-9)
after every task. :func:`popen` forks from one daemon thread instead: the
signal then fires when axross itself ends, which is what it is for.
"""

from __future__ import annotations

import queue
import subprocess
import threading
from typing import Callable


class _Launcher:
    """One daemon thread that runs the calls handed to it, in order."""

    def __init__(self) -> None:
        self._jobs: queue.SimpleQueue = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _ensure(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._loop, name="axross-launcher",
                                                daemon=True)
                self._thread.start()

    def _loop(self) -> None:
        while True:
            func, done, box = self._jobs.get()
            try:
                box["result"] = func()
            except BaseException as exc:  # noqa: BLE001 - handed back to the caller
                box["error"] = exc
            done.set()

    def call(self, func: Callable):
        """*func()* on the launcher thread; its result, or its exception
        raised here. From the launcher thread itself it runs directly."""
        if threading.current_thread() is self._thread:
            return func()
        self._ensure()
        done, box = threading.Event(), {}
        self._jobs.put((func, done, box))
        done.wait()
        if "error" in box:
            raise box["error"]
        return box["result"]


_LAUNCHER = _Launcher()


def popen(args, **kwargs) -> subprocess.Popen:
    """``subprocess.Popen(args, **kwargs)``, forked from the launcher thread."""
    return _LAUNCHER.call(lambda: subprocess.Popen(args, **kwargs))


__all__ = ["popen"]
