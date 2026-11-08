"""Wait for a backend call without freezing the window.

Some actions must finish before their caller goes on - Save returns
whether the file was written, and closing a tab or the window depends on
that answer - so they cannot simply move to a background job and report
later. :func:`run_off_gui` gives them the same answer without holding the
GUI thread: the call runs on a worker thread while a local event loop
keeps the windows painting, their timers running and the window manager
answered (no "not responding"). User input (keys, clicks, drops) is held
back meanwhile and delivered afterwards, so nobody edits a text while it
is being written, and no second Save starts inside the first.

A close is held back too: the window manager's close (Alt+F4, the title
bar's X, the taskbar) is no user input to Qt, and neither is a close()
from a timer, so either ran the window's closeEvent inside the wait - a
viewer or editor with WA_DeleteOnClose was gone when its call returned,
and an editor's close asked to save and started a second, parallel Save.
Every window shown when the (outermost) wait starts now refuses its
close for the time of the wait (:class:`_CloseHold`); the close is
replayed once the wait is over and its caller went back to the event
loop, so it runs exactly as if it had come a moment later. Windows that
open during the wait (a host-key question) close as usual.

Used by the editor (save, save as, reload), the hex editor's save and
the pane's encrypt / decrypt.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import TypeVar

from PyQt6 import sip
from PyQt6.QtCore import (
    QCoreApplication,
    QEvent,
    QEventLoop,
    QObject,
    Qt,
    QTimer,
    pyqtSignal,
)

log = logging.getLogger(__name__)

T = TypeVar("T")

#: After this long a wait cursor shows that something is going on.
BUSY_CURSOR_AFTER_MS = 300


class _Done(QObject):
    """Emitted from the worker; delivered (queued) in the waiting thread."""

    done = pyqtSignal()


class _CloseHold(QObject):
    """While a run_off_gui wait runs: the windows shown when it started
    ignore their close (an application event filter), which is replayed
    once the outermost wait is over. Nested waits (a timer starts one
    inside another) share it; the windows go free when the last ends."""

    def __init__(self, app) -> None:
        super().__init__()
        self._app = app
        self._depth = 0
        #: id(window) -> window, for the windows held in this wait.
        self._windows: dict[int, QObject] = {}
        #: The held windows asked to close meanwhile, in that order.
        self._closed: list[QObject] = []

    def enter(self) -> list[int]:
        """Hold the shown windows; returns the ones this wait added."""
        from PyQt6.QtWidgets import QApplication

        if self._depth == 0:
            self._app.installEventFilter(self)
        self._depth += 1
        added: list[int] = []
        if isinstance(self._app, QApplication):
            for window in QApplication.topLevelWidgets():
                if window.isVisible() and id(window) not in self._windows:
                    self._windows[id(window)] = window
                    added.append(id(window))
        return added

    def leave(self, added: list[int]) -> None:
        """Free the windows *added* by the wait that ends; replay the
        closes they refused."""
        self._depth -= 1
        freed = [self._windows.pop(key) for key in added if key in self._windows]
        if self._depth == 0:
            self._app.removeEventFilter(self)
            freed.extend(self._windows.values())
            self._windows = {}
        replay = [w for w in self._closed if any(w is f for f in freed)]
        self._closed = [w for w in self._closed if not any(w is r for r in replay)]
        for window in replay:
            # Posted: the caller of the wait finishes with its window
            # first, then the close runs as if it came now.
            QTimer.singleShot(0, lambda w=window: _replay_close(w))

    def eventFilter(self, watched, event) -> bool:
        if (event.type() == QEvent.Type.Close
                and self._windows.get(id(watched)) is watched):
            event.ignore()
            if not any(w is watched for w in self._closed):
                log.info("Close of %s held until its background call is done",
                         type(watched).__name__)
                self._closed.append(watched)
            return True
        return False


def _replay_close(window) -> None:
    if not sip.isdeleted(window):
        window.close()


_hold: _CloseHold | None = None


def _close_hold(app) -> _CloseHold:
    global _hold
    if _hold is None or sip.isdeleted(_hold) or _hold._app is not app:  # noqa: SLF001
        _hold = _CloseHold(app)
    return _hold


def run_off_gui(fn: Callable[[], T], *, status: Callable[[str], None] | None = None,
                text: str = "") -> T:
    """``fn()`` run on a worker thread; its result, or its exception raised
    here. On the GUI thread the windows stay live meanwhile (see the module
    docstring); anywhere else - no application, another thread - it simply
    runs ``fn()``. *status(text)* is told *text* when the call takes longer
    than BUSY_CURSOR_AFTER_MS, and "" when it is over."""
    app = QCoreApplication.instance()
    if app is None or threading.current_thread() is not threading.main_thread():
        return fn()
    outcome: dict = {}
    signal = _Done()
    loop = QEventLoop()
    signal.done.connect(loop.quit, Qt.ConnectionType.QueuedConnection)

    def work() -> None:
        try:
            outcome["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - raised in the caller
            outcome["error"] = exc
        finally:
            try:
                signal.done.emit()
            except RuntimeError:  # pragma: no cover - the waiting side is gone
                pass

    worker = threading.Thread(target=work, name="off-gui", daemon=True)
    busy: list[bool] = []

    def show_busy() -> None:
        if "value" in outcome or "error" in outcome:
            return
        busy.append(True)
        from PyQt6.QtWidgets import QApplication

        if isinstance(app, QApplication):
            QApplication.setOverrideCursor(Qt.CursorShape.BusyCursor)
        if status is not None and text:
            status(text)

    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(show_busy)
    timer.start(BUSY_CURSOR_AFTER_MS)
    started = time.monotonic()
    hold = _close_hold(app)
    held = hold.enter()
    try:
        # In here: a thread that cannot start ("can't start new thread")
        # left the close hold entered, and every window refused its close
        # for the rest of the session.
        worker.start()
        while worker.is_alive() and "value" not in outcome and "error" not in outcome:
            loop.exec(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
    finally:
        hold.leave(held)
        timer.stop()
        if busy:
            from PyQt6.QtWidgets import QApplication

            if isinstance(app, QApplication):
                QApplication.restoreOverrideCursor()
            if status is not None and text:
                status("")
        if worker.ident is not None:  # started (join() raises on one that never was)
            worker.join(timeout=1.0)
    log.debug("off the GUI thread for %.0f ms", (time.monotonic() - started) * 1000)
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def connect_off_gui(manager, profile, *, password: str = "", key_passphrase: str = "",
                    prompt=None, password_from_keyring: bool = False,
                    status: Callable[[str], None] | None = None):
    """``manager.connect(profile, ...)`` off the GUI thread (run_off_gui):
    a handshake - and a dead host's whole connect timeout - no longer
    freezes the windows. *prompt(error) -> bool*, the unknown-host
    question, is asked on the GUI thread (core.connect_worker
    .HostKeyPrompt, as every connect worker does). With
    *password_from_keyring* the stored password is read on the worker too
    (the Secret Service may wait for an unlock)."""
    from core.connect_worker import HostKeyPrompt

    bridge = None
    if prompt is not None:
        bridge = HostKeyPrompt()
        bridge.set_prompt(prompt)
        bridge.request.connect(bridge.handle_request, Qt.ConnectionType.QueuedConnection)

    def connect():
        secret = password
        if password_from_keyring:
            secret = profile.get_password() or ""
        kwargs = {"password": secret, "key_passphrase": key_passphrase}
        if bridge is not None:
            kwargs["on_unknown_host"] = bridge.ask
        return manager.connect(profile, **kwargs)

    name = getattr(profile, "name", "") or getattr(profile, "host", "")
    return run_off_gui(connect, status=status, text=f"Connecting to {name}…")


__all__ = ["BUSY_CURSOR_AFTER_MS", "connect_off_gui", "run_off_gui"]
