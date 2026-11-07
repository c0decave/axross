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

Used by the editor (save, save as, reload), the hex editor's save and
the pane's encrypt / decrypt.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import TypeVar

from PyQt6.QtCore import QCoreApplication, QEventLoop, QObject, Qt, QTimer, pyqtSignal

log = logging.getLogger(__name__)

T = TypeVar("T")

#: After this long a wait cursor shows that something is going on.
BUSY_CURSOR_AFTER_MS = 300


class _Done(QObject):
    """Emitted from the worker; delivered (queued) in the waiting thread."""

    done = pyqtSignal()


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
    worker.start()
    try:
        while worker.is_alive() and "value" not in outcome and "error" not in outcome:
            loop.exec(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
    finally:
        timer.stop()
        if busy:
            from PyQt6.QtWidgets import QApplication

            if isinstance(app, QApplication):
                QApplication.restoreOverrideCursor()
            if status is not None and text:
                status("")
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
