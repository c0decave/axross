"""detach_running_thread: which threads are handed over, and when.

Inside Qt's finish phase isRunning() is already False while the thread
still has to delete its worker (which needs the GIL); a thread treated as
done there was destroyed with the GIL held and deadlocked. Only wait(0)
tells a thread that is really done.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QThread  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import thread_lifetime as TL  # noqa: E402

# A QApplication like every other test: a bare QCoreApplication first
# makes later GUI tests abort.
APP = QApplication.instance() or QApplication([])
REPO = Path(__file__).resolve().parent.parent


class _Sleeper(QThread):
    def __init__(self, seconds: float) -> None:
        super().__init__()
        self.seconds = seconds

    def run(self) -> None:
        time.sleep(self.seconds)


def _released_after_it_ends(thread: QThread, timeout: float = 5.0) -> bool:
    """Wait for *thread* to end, then pump events until it was released.

    The deadline is checked after pumping, never instead of it: in a long
    run one processEvents() call first works off what earlier tests left
    queued (measured: 8.6 s), and a deadline checked before pumping ran
    out before the release could be delivered at all.
    """
    if not thread.wait(int(timeout * 1000)):
        return False
    deadline = time.monotonic() + timeout
    while True:
        # Delivers the queued finished -> deleteLater call ...
        APP.processEvents()
        # ... and the deletion itself: no event loop runs here, and
        # processEvents() alone does not reliably send DeferredDelete.
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        if thread not in TL._DETACHED or time.monotonic() >= deadline:
            return thread not in TL._DETACHED
        time.sleep(0.01)


def test_happy_a_running_thread_is_handed_over_and_released_when_done() -> None:
    thread = _Sleeper(0.2)
    thread.start()
    assert TL.detach_running_thread(thread) is True
    assert thread in TL._DETACHED
    assert _released_after_it_ends(thread)


def test_edge_a_slow_event_backlog_does_not_eat_the_release() -> None:
    from PyQt6.QtCore import QTimer

    # Stands in for what earlier tests left queued: the first pump takes
    # longer than the whole deadline, and the thread ends during it. A
    # deadline checked before pumping gave up here every time.
    QTimer.singleShot(0, lambda: time.sleep(0.4))
    thread = _Sleeper(0.05)
    thread.start()
    assert TL.detach_running_thread(thread) is True
    assert _released_after_it_ends(thread, timeout=0.2)


def test_sad_nothing_or_a_finished_thread_is_not_handed_over() -> None:
    assert TL.detach_running_thread(None) is False
    thread = _Sleeper(0)
    thread.start()
    assert thread.wait(5000)
    assert TL.detach_running_thread(thread) is False
    assert thread not in TL._DETACHED


def test_edge_a_thread_in_its_finish_phase_is_handed_over_without_deadlock() -> None:
    # Run in a child: the deadlock holds the GIL and cannot be interrupted.
    script = textwrap.dedent(
        """
        import sys, threading, time
        from PyQt6.QtCore import QCoreApplication, QEvent, QObject, QThread, Qt
        from core import thread_lifetime as TL

        app = QCoreApplication(sys.argv[:1])
        thread = QThread()
        worker = QObject()
        worker.moveToThread(thread)
        thread.finished.connect(worker.deleteLater)
        in_finish = threading.Event()

        def slow_finished():
            in_finish.set()
            time.sleep(0.3)

        thread.finished.connect(slow_finished, Qt.ConnectionType.DirectConnection)
        thread.start()
        thread.quit()
        while not in_finish.is_set():
            time.sleep(0.005)
        assert not thread.isRunning() and not thread.wait(0)
        assert TL.detach_running_thread(thread, keep=(worker,)) is True
        del thread, worker
        deadline = time.monotonic() + 5
        while TL._DETACHED and time.monotonic() < deadline:
            app.processEvents()
            app.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
            time.sleep(0.01)
        assert not TL._DETACHED, "the thread was never released"
        print("released", flush=True)
        """
    )
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(REPO), env.get("PYTHONPATH")]))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("detaching a thread in its finish phase deadlocked")
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "released" in proc.stdout
