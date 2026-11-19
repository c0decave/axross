"""axross.toast() and axross.message() from a worker thread build their
widgets on the GUI thread.

Reproduced 2026-11-19 (independent review): an extension's background
work, an agent tool handler (it runs on the agent's thread) or a thread a
REPL user starts called toast() / message(), and the QFrame / QMessageBox
was built - and message()'s exec() run - on that worker thread: Qt
widgets off the GUI thread, a crash or a hang. Now toast() is posted to
the GUI thread (core.thread_relay.GuiCall) and message() from a worker
waits there until the GUI thread's box is answered; on the GUI thread it
shows the box directly (posting and waiting would deadlock).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _pump_until(app, done, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not done() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    app.processEvents()


def _run_in_worker(app, func):
    errors: list[BaseException] = []

    def work():
        try:
            func()
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    worker = threading.Thread(target=work)
    worker.start()
    _pump_until(app, lambda: not worker.is_alive())
    assert not worker.is_alive()
    assert errors == []


def test_happy_a_toast_from_a_worker_is_built_on_the_gui_thread(app, monkeypatch):
    from core import ui_helpers

    built: list[threading.Thread] = []
    real = ui_helpers._show_toast

    def recording(*args, **kwargs):
        built.append(threading.current_thread())
        return real(*args, **kwargs)

    monkeypatch.setattr(ui_helpers, "_show_toast", recording)
    _run_in_worker(app, lambda: ui_helpers.toast("done", timeout=0.5))
    _pump_until(app, lambda: built)
    assert built == [threading.main_thread()]


def test_happy_a_message_from_a_worker_waits_for_the_gui_threads_box(app, monkeypatch):
    from core import ui_helpers

    events: list[tuple[str, threading.Thread]] = []

    def exec_(box):
        events.append(("exec", threading.current_thread()))
        return 0

    monkeypatch.setattr(QMessageBox, "exec", exec_)

    def worker():
        ui_helpers.message("done")
        events.append(("returned", threading.current_thread()))

    _run_in_worker(app, worker)
    assert [name for name, _ in events] == ["exec", "returned"]
    assert events[0][1] is threading.main_thread()
    assert events[1][1] is not threading.main_thread()


def test_edge_a_message_on_the_gui_thread_shows_directly(app, monkeypatch):
    """No post-and-wait on the GUI thread: that would wait for itself."""
    from core import ui_helpers

    shown = []
    monkeypatch.setattr(QMessageBox, "exec", lambda box: shown.append(box.text()) or 0)
    ui_helpers.message("here")
    assert shown == ["here"]


def test_sad_a_failing_box_does_not_leave_the_worker_waiting(app, monkeypatch, caplog):
    """The box fails on the GUI thread: logged there, and the worker
    returns instead of waiting for an answer that never comes."""
    from core import ui_helpers

    def broken(_box):
        raise RuntimeError("no display")

    monkeypatch.setattr(QMessageBox, "exec", broken)
    with caplog.at_level("ERROR", logger="core.ui_helpers"):
        _run_in_worker(app, lambda: ui_helpers.message("x"))
    assert "no display" in caplog.text
