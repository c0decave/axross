"""Backend-agnostic filesystem watching.

Emits change notifications for files or directories on any
:class:`FileBackend`. The default implementation polls the backend's
``list_dir`` + ``stat`` so it works over every protocol. Backends
that have a push mechanism (inotify for LocalFS, Dropbox
longpoll_delta, Microsoft Graph subscriptions, S3 SNS) can register
their own watcher via :func:`register_watcher_factory` to skip
polling when the user has the right environment.

Events are simple 3-tuples: ``(event_type, path, kind)``:

  event_type  "created" | "modified" | "deleted"
  path        absolute path inside the backend
  kind        "file" | "dir"

Usage::

    def on_change(event_type, path, kind):
        print(event_type, path)

    w = watch(session, "/data", on_change, interval=2.0)
    ...
    w.stop()
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from models.watch_tick_state import WatchTickState

if TYPE_CHECKING:  # pragma: no cover
    pass

log = logging.getLogger(__name__)


EventCallback = Callable[[str, str, str], None]


@dataclass
class _Snapshot:
    """What we observed last tick. Maps path -> (size, mtime_iso, is_dir)."""

    entries: dict[str, tuple[int, str, bool]]


class Watcher:
    """Abstract base. Subclasses implement ``_run`` to publish events
    via ``self._emit(event_type, path, kind)``."""

    def __init__(self, backend, path: str, callback: EventCallback) -> None:
        self._backend = backend
        self._path = path
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run_safe,
            daemon=True,
            name=f"watch:{self._path}",
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._on_stop()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _on_stop(self) -> None:
        """Subclasses override to release any condition waiters parked on
        per-subclass state (e.g., PollingWatcher's tick condition)."""
        return None

    def _run_safe(self) -> None:
        try:
            self._run()
        except Exception as exc:  # pragma: no cover — defensive
            log.error("Watcher crashed for %s: %s", self._path, exc)

    def _run(self) -> None:  # pragma: no cover — abstract
        raise NotImplementedError

    def _emit(self, event_type: str, path: str, kind: str) -> None:
        try:
            self._callback(event_type, path, kind)
        except Exception as exc:
            log.warning("watch callback raised for %s %s: %s", event_type, path, exc)


class PollingWatcher(Watcher):
    """Default watcher: ``list_dir`` + ``stat`` diff on an interval.

    Works over every backend; cost is one directory listing per
    interval per watched path. Suitable for small-ish directories;
    callers watching huge trees should register a push watcher.
    """

    def __init__(self, backend, path, callback, interval: float = 2.0) -> None:
        super().__init__(backend, path, callback)
        self._interval = max(0.2, interval)
        self._initial: _Snapshot | None = None
        self._tick_cond = threading.Condition()
        self._tick_state = WatchTickState()

    def start(self) -> None:
        # Take the initial snapshot synchronously so callers can rely on
        # "any change made after start() returns is observable by the next
        # poll tick." Without this, the worker thread races with the caller
        # under load and changes made just after start() can be missed.
        if self._initial is None:
            self._initial = self._snapshot()
        super().start()

    def _on_stop(self) -> None:
        # Wake any wait_for_tick() callers so they observe shutdown rather
        # than blocking until their timeout expires.
        with self._tick_cond:
            self._tick_cond.notify_all()

    def wait_for_tick(self, ticks: int = 1, timeout: float = 10.0) -> bool:
        """Block until the worker has completed at least ``ticks`` more
        poll iterations after this call, or until ``timeout`` elapses.

        Returns True if the target tick count was reached, False on timeout.
        Tests use this to deterministically wait for a poll cycle rather than
        guessing how long the worker needs to schedule under load.
        """
        if ticks < 1:
            return True
        with self._tick_cond:
            # If a tick is currently in flight (started but not yet
            # completed), its snapshot may have been taken BEFORE this
            # call — list_dir/stat already issued, captured state predates
            # the caller's mutation. Counting that tick toward the target
            # would let wait_for_tick return success while the mutation
            # is invisible. WatchTickState.target_after applies
            # max(started, completed) + ticks so the in-flight tick is
            # consumed but does not satisfy the wait.
            target = self._tick_state.target_after(ticks)
            self._tick_cond.wait_for(
                lambda: (
                    self._tick_state.completed_at_least(target)
                    or self._stop_event.is_set()
                ),
                timeout=timeout,
            )
            return self._tick_state.completed_at_least(target)

    def _snapshot(self) -> _Snapshot:
        entries: dict[str, tuple[int, str, bool]] = {}
        try:
            items = self._backend.list_dir(self._path)
        except OSError as exc:
            log.debug("PollingWatcher: list_dir(%s) failed: %s", self._path, exc)
            return _Snapshot(entries={})
        for it in items:
            name = getattr(it, "name", None)
            if not name:
                continue
            modified = getattr(it, "modified", None)
            try:
                mtime = modified.isoformat() if modified else ""
            except Exception:
                mtime = ""
            size = int(getattr(it, "size", 0) or 0)
            is_dir = bool(getattr(it, "is_dir", False))
            entries[name] = (size, mtime, is_dir)
        return _Snapshot(entries=entries)

    def _run(self) -> None:
        prev = self._initial if self._initial is not None else self._snapshot()
        while not self._stop_event.wait(self._interval):
            with self._tick_cond:
                self._tick_state.mark_started()
            curr = self._snapshot()
            # created
            for name, props in curr.entries.items():
                if name not in prev.entries:
                    kind = "dir" if props[2] else "file"
                    self._emit("created", _join(self._path, name), kind)
                elif prev.entries[name] != props:
                    kind = "dir" if props[2] else "file"
                    self._emit("modified", _join(self._path, name), kind)
            # deleted
            for name, props in prev.entries.items():
                if name not in curr.entries:
                    kind = "dir" if props[2] else "file"
                    self._emit("deleted", _join(self._path, name), kind)
            prev = curr
            with self._tick_cond:
                self._tick_state.mark_completed()
                self._tick_cond.notify_all()


def _join(parent: str, child: str) -> str:
    # Backend-agnostic join; the registered POSIX-path family uses "/"
    # while SMB/Azure Files use "\" — the watcher's callback gets back
    # the path in whatever form the backend's list_dir returned.
    if parent.endswith("/") or parent.endswith("\\"):
        return parent + child
    return f"{parent}/{child}"


# Registry of per-protocol push-watcher factories. Backends that want
# to replace polling register here during import; callers (the watch()
# function below) consult this registry before falling back to
# PollingWatcher.
_WATCHER_FACTORIES: dict[str, Callable[..., Watcher]] = {}


def register_watcher_factory(
    protocol_id: str,
    factory: Callable[..., Watcher],
) -> None:
    """Register a push watcher for a backend protocol.

    ``factory`` is called as ``factory(backend, path, callback,
    interval=...)`` and must return a :class:`Watcher` instance.
    """
    _WATCHER_FACTORIES[protocol_id] = factory


def _resolve_protocol_id(backend) -> str:
    """Find the protocol_id for *backend* via the registry, or ``""``
    if the backend isn't registered (plain LocalFS, test doubles)."""
    from core import backend_registry

    class_name = type(backend).__name__
    # Direct match on registered class name
    for info in backend_registry.all_backends():
        if info.class_name == class_name:
            return info.protocol_id
    # MRO fallback — test doubles subclass LocalFS / SSHSession etc.
    for cls in type(backend).__mro__[1:]:
        for info in backend_registry.all_backends():
            if info.class_name == cls.__name__:
                return info.protocol_id
    # LocalFS is special: not protocol-registered but well-known.
    if class_name == "LocalFS" or any(c.__name__ == "LocalFS" for c in type(backend).__mro__):
        return "local"
    return ""


def watch(
    backend, path: str, callback: EventCallback, interval: float = 2.0, force_polling: bool = False
) -> Watcher:
    """Start watching *path* on *backend*. Returns a running
    :class:`Watcher` — call ``.stop()`` when done.

    Picks the most efficient watcher available: a per-protocol push
    watcher when one is registered, otherwise :class:`PollingWatcher`.
    Pass ``force_polling=True`` to ignore registered push watchers
    (useful for testing the polling path regardless of environment).
    """
    if not force_polling:
        proto = _resolve_protocol_id(backend)
        factory = _WATCHER_FACTORIES.get(proto)
        if factory is not None:
            w = factory(backend, path, callback, interval=interval)
            w.start()
            return w

    w = PollingWatcher(backend, path, callback, interval=interval)
    w.start()
    return w


# ---------------------------------------------------------------------------
# Optional: inotify-backed watcher for LocalFS via the watchdog package.
# Activated transparently when ``watchdog`` is installed; falls back to
# polling otherwise.
# ---------------------------------------------------------------------------
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer as _WatchdogObserver
except ImportError:  # pragma: no cover — optional dep
    _WatchdogObserver = None  # type: ignore[assignment]


if _WatchdogObserver is not None:

    class _LocalFSInotifyWatcher(Watcher):
        """watchdog-backed watcher for LocalFS. Uses inotify on Linux,
        FSEvents on macOS, ReadDirectoryChangesW on Windows."""

        def __init__(self, backend, path, callback, interval: float = 2.0) -> None:
            super().__init__(backend, path, callback)
            self._observer = _WatchdogObserver()

        def _map(self, event_name: str) -> str:
            return {
                "created": "created",
                "modified": "modified",
                "deleted": "deleted",
                "moved": "modified",
            }.get(event_name, "modified")

        def _run(self) -> None:
            watcher_self = self

            class _Handler(FileSystemEventHandler):
                def on_created(self, ev):
                    watcher_self._emit(
                        "created",
                        ev.src_path,
                        "dir" if ev.is_directory else "file",
                    )

                def on_modified(self, ev):
                    watcher_self._emit(
                        "modified",
                        ev.src_path,
                        "dir" if ev.is_directory else "file",
                    )

                def on_deleted(self, ev):
                    watcher_self._emit(
                        "deleted",
                        ev.src_path,
                        "dir" if ev.is_directory else "file",
                    )

            self._observer.schedule(_Handler(), self._path, recursive=False)
            self._observer.start()
            try:
                while not self._stop_event.wait(0.5):
                    pass
            finally:
                self._observer.stop()
                self._observer.join(timeout=5)

    register_watcher_factory("sftp", lambda *a, **kw: PollingWatcher(*a, **kw))
    register_watcher_factory("local", _LocalFSInotifyWatcher)
