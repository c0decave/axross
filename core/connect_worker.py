"""Asynchronous connection worker so the GUI stays responsive.

Problem: :meth:`ConnectionManager.connect` does blocking I/O — TCP
connect, SSH transport handshake, SFTP channel open, bucket probe for
S3, OAuth token refresh, etc. Called directly from the UI thread,
these stall Qt's event loop for seconds. The user can't switch to
the log pane, resize the window, or cancel.

Solution: run the whole call on a :class:`QThread`. The worker emits
two signals the UI hooks into:

    succeeded(session)     — connection established
    failed(exception)      — something went wrong

Host-key confirmation (paramiko's TOFU prompt) is interactive and has
to happen on the GUI thread. Rather than refactoring every backend,
the worker routes the callback through an :class:`HostKeyPrompt` that
blocks the worker thread until the GUI thread answers.

Usage
-----
::

    from core.connect_worker import run_connect

    self._connect_task = run_connect(
        self._connection_manager,
        profile,
        password=password,
        key_passphrase=key_passphrase,
        host_key_prompt=self._confirm_unknown_host_gui,
        on_success=self._on_connect_succeeded,
        on_failure=self._on_connect_failed,
    )

The caller keeps the returned handle alive (so Qt doesn't GC the
thread mid-run). Call :meth:`ConnectTask.cancel_requested` if you
wire a "Cancel" button — the worker can't forcibly terminate the
underlying network call but it'll refuse to emit ``succeeded`` and
disconnect as soon as the attempt completes.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal, pyqtSlot

log = logging.getLogger(__name__)

HOST_KEY_PROMPT_TIMEOUT_S = 120.0


# ---------------------------------------------------------------------------
# Host-key prompt bridge
# ---------------------------------------------------------------------------


class HostKeyPrompt(QObject):
    """Route paramiko's UnknownHostKeyError prompt back to the GUI.

    Lives on the GUI thread. Worker thread calls :meth:`ask` which
    emits ``request`` (handled in the GUI thread via a QueuedConnection)
    and then blocks on a threading.Event until the GUI returns an
    answer via :meth:`reply`.

    Why not :class:`Qt.ConnectionType.BlockingQueuedConnection`? That
    works too, but requires ``@pyqtSlot`` with the exact argument
    signature and fails silently if the signal graph is off. The
    Event-based version is a three-line contract any Python reader can
    follow.
    """

    request = pyqtSignal(object)  # emits the exception; GUI handles it

    def __init__(
        self,
        parent: QObject | None = None,
        *,
        reply_timeout_s: float = HOST_KEY_PROMPT_TIMEOUT_S,
    ) -> None:
        super().__init__(parent)
        self._event = threading.Event()
        self._answer: bool = False
        self._reply_timeout_s = max(0.0, float(reply_timeout_s))
        self._prompt: Callable[[Any], bool] | None = None

    def set_prompt(self, prompt: Callable[[Any], bool] | None) -> None:
        self._prompt = prompt

    def ask(self, exc: Any) -> bool:
        """Called from the worker thread. Blocks until GUI replies.

        If the GUI side never answers, fail closed instead of leaving
        the connect worker stuck forever.
        """
        self._event.clear()
        self._answer = False
        # Qt.QueuedConnection auto-selected because the emitter is on
        # a different thread than the receiver.
        self.request.emit(exc)
        if not self._event.wait(self._reply_timeout_s):
            log.error(
                "host_key_prompt timed out after %.1fs; denying by default",
                self._reply_timeout_s,
            )
            return False
        return self._answer

    @pyqtSlot(object)
    def handle_request(self, exc: Any) -> None:
        """GUI-thread receiver for worker-side host-key questions."""
        answer = False
        try:
            if self._prompt is not None:
                answer = bool(self._prompt(exc))
        except Exception as handler_exc:  # noqa: BLE001
            log.error(
                "host_key_prompt raised: %s; denying by default",
                handler_exc,
                exc_info=True,
            )
        self.reply(answer)

    @pyqtSlot(bool)
    def reply(self, ok: bool) -> None:
        """Called from the GUI thread with the user's answer."""
        self._answer = bool(ok)
        self._event.set()


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------


class _ConnectWorker(QObject):
    """Executes ``ConnectionManager.connect`` on a QThread."""

    succeeded = pyqtSignal(object)  # session
    failed = pyqtSignal(object)  # exception
    finished = pyqtSignal()  # always fires on exit (even cancelled)

    def __init__(
        self,
        cm: Any,
        profile: Any,
        password: str,
        key_passphrase: str,
        host_key_callback: Callable[[Any], bool] | None,
    ) -> None:
        super().__init__()
        self._cm = cm
        self._profile = profile
        self._password = password
        self._key_passphrase = key_passphrase
        self._host_key_callback = host_key_callback
        self._cancelled = False

    def cancel(self) -> None:
        """Stop emitting succeeded; the in-flight call can't be forcibly
        interrupted because most network libs don't surface that."""
        self._cancelled = True

    @pyqtSlot()
    def run(self) -> None:
        try:
            try:
                session = self._cm.connect(
                    self._profile,
                    password=self._password,
                    key_passphrase=self._key_passphrase,
                    on_unknown_host=self._host_key_callback,
                )
            except Exception as exc:  # noqa: BLE001 — we forward everything
                log.info("connect_worker: connect failed: %s", exc)
                if not self._cancelled:
                    self.failed.emit(exc)
                return

            if self._cancelled:
                # User cancelled while the connect was blocking. Release
                # the freshly-opened session so we don't leak it.
                try:
                    self._cm.release(self._profile)
                except Exception as exc:  # noqa: BLE001
                    log.debug(
                        "connect_worker: post-cancel release failed: %s",
                        exc,
                    )
                return

            self.succeeded.emit(session)
        finally:
            # ``finished`` must fire on every exit path so the owning
            # thread can quit cleanly. Missing this would leak the
            # QThread (and crash the process on teardown).
            self.finished.emit()


# ---------------------------------------------------------------------------
# Handle — keeps worker + thread + bridge alive together
# ---------------------------------------------------------------------------


@dataclass
class ConnectTask:
    """Handle returned by :func:`run_connect`.

    Pin this to ``self._connect_task`` on the widget that triggered
    the connect; letting it get GC'd while the network call is still
    running leaks the worker and prints ``QThread: Destroyed while
    thread is still running``.
    """

    worker: _ConnectWorker
    thread: QThread
    bridge: HostKeyPrompt

    def cancel_requested(self) -> None:
        """Mark the task as cancelled. The actual network call will
        still run to completion, but no ``succeeded`` will fire and
        the resulting session is released immediately."""
        self.worker.cancel()

    def __del__(self) -> None:
        # Ensure the thread finished before Python/C++ release the
        # QThread object. Without this we race with deleteLater and
        # Qt complains or crashes on teardown.
        try:
            thread = self.thread
            if thread is not None and thread.isRunning():
                thread.quit()
                thread.wait(2000)
        except Exception:
            # Object may already be partially destructed; nothing to do.
            pass


def run_connect(
    connection_manager: Any,
    profile: Any,
    *,
    password: str = "",
    key_passphrase: str = "",
    host_key_prompt: Callable[[Any], bool] | None = None,
    on_success: Callable[[Any], None] | None = None,
    on_failure: Callable[[Exception], None] | None = None,
) -> ConnectTask:
    """Start a non-blocking connect and wire up success / failure.

    ``host_key_prompt`` runs on the GUI thread; the worker blocks
    until it returns. ``on_success`` / ``on_failure`` both run on the
    GUI thread too.
    """
    bridge = HostKeyPrompt()
    # Worker-side callback that routes to the GUI thread.
    worker_side_cb: Callable[[Any], bool] | None = None
    if host_key_prompt is not None:
        bridge.set_prompt(host_key_prompt)
        bridge.request.connect(
            bridge.handle_request,
            Qt.ConnectionType.QueuedConnection,
        )
        worker_side_cb = bridge.ask

    worker = _ConnectWorker(
        connection_manager,
        profile,
        password,
        key_passphrase,
        worker_side_cb,
    )
    thread = QThread()
    worker.moveToThread(thread)
    thread.started.connect(worker.run)

    if on_success is not None:
        worker.succeeded.connect(on_success)
    if on_failure is not None:
        worker.failed.connect(on_failure)

    # Cleanup: quit the thread when the worker signals finished
    # (always fires, even when cancelled). We deliberately do NOT
    # use deleteLater on the thread here — that races with
    # ``ConnectTask.__del__``. The worker IS deleteLater'd because
    # it lives on the worker thread and its pending queued slots
    # need to drain before Python drops it.
    worker.finished.connect(thread.quit)
    thread.finished.connect(worker.deleteLater)

    thread.start()
    return ConnectTask(worker=worker, thread=thread, bridge=bridge)


__all__ = [
    "ConnectTask",
    "HostKeyPrompt",
    "run_connect",
]
