"""Closing the window while a connect or a scheduled job still runs.

Reported from a real session: an SFTP connect with problems, then
"QThread: Destroyed while thread '' is still running" and an abort. The
connect worker's QThread had no parent and lived only in a ConnectTask;
ConnectTask.__del__ waited 2 s and then let the QThread be destroyed while
the blocking network call was still inside it. The scheduler's job thread
was parented to the window and died with it the same way.

Each case runs in a child process: the failure is an abort.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

_PRELUDE = """
import gc, os, sys, threading, time
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, {root!r})
from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])


def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        time.sleep(0.01)
"""


def _run(body: str) -> subprocess.CompletedProcess:
    script = textwrap.dedent(_PRELUDE).format(root=str(ROOT)) + textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
    )


def _assert_clean(done: subprocess.CompletedProcess) -> None:
    assert "Destroyed while thread" not in done.stderr, done.stderr[-2000:]
    assert done.returncode == 0, (done.returncode, done.stderr[-2000:])
    assert "survived" in done.stdout


def test_happy_closing_the_window_during_a_hanging_connect_does_not_abort() -> None:
    done = _run(
        """
        from core import connection_manager as CM
        from ui import thread_lifetime as TL
        from core.profiles import ConnectionProfile
        from ui.main_window import MainWindow

        def slow_connect(self, profile, **kw):
            time.sleep(1.5)        # an SFTP server that answers late
            return object()

        CM.ConnectionManager.connect = slow_connect
        CM.ConnectionManager.release = lambda self, profile: print("released", flush=True)
        win = MainWindow()
        win._reconnect_timer.stop()
        win._run_connect_async(
            ConnectionProfile(name="p", protocol="sftp", host="h", username="u"),
            "", "", lambda s: print("late success"), lambda e: print("late failure"),
        )
        task = win._connect_tasks[0]
        pump(0.3)
        win.close()
        assert task.worker._cancelled
        assert task.thread in TL._DETACHED
        del task
        win.deleteLater()
        del win
        gc.collect()
        end = time.time() + 5
        while TL._DETACHED and time.time() < end:
            pump(0.05)
        assert not TL._DETACHED, TL._DETACHED
        print("survived", flush=True)
        """
    )
    _assert_clean(done)
    assert "late success" not in done.stdout
    assert "released" in done.stdout  # the session opened too late is closed


def test_edge_a_host_key_question_after_close_is_denied_at_once() -> None:
    done = _run(
        """
        from core import connection_manager as CM
        from core.profiles import ConnectionProfile
        from ui import main_window as MW

        answers = []

        def asking_connect(self, profile, *, on_unknown_host=None, **kw):
            time.sleep(0.6)        # the question comes after the close
            started = time.time()
            answers.append((on_unknown_host(OSError("unknown key")), time.time() - started))
            raise OSError("host key rejected")

        CM.ConnectionManager.connect = asking_connect
        MW.MainWindow._confirm_unknown_host = lambda self, exc: print("prompt shown") or True
        win = MW.MainWindow()
        win._reconnect_timer.stop()
        win._run_connect_async(
            ConnectionProfile(name="p", protocol="sftp", host="h", username="u"),
            "", "", lambda s: None, lambda e: print("late failure"),
        )
        pump(0.2)
        win.close()
        end = time.time() + 5
        while not answers and time.time() < end:
            pump(0.05)
        assert answers and answers[0][0] is False and answers[0][1] < 1.0, answers
        pump(0.3)
        print("survived", flush=True)
        """
    )
    _assert_clean(done)
    assert "prompt shown" not in done.stdout
    assert "late failure" not in done.stdout


def test_sad_a_dropped_connect_task_does_not_abort() -> None:
    done = _run(
        """
        from core.connect_worker import run_connect

        class CM:
            def connect(self, profile, **kw):
                time.sleep(5)
                return object()
            def release(self, profile):
                pass

        task = run_connect(CM(), object())
        pump(0.2)
        del task
        gc.collect()
        pump(0.3)
        print("survived", flush=True)
        """
    )
    _assert_clean(done)


def test_edge_closing_the_window_during_a_scheduled_job_does_not_abort() -> None:
    done = _run(
        """
        from types import SimpleNamespace
        from ui import main_window as MW
        import core.scheduler as S

        ran_on = {}

        def slow_job(job, runner, on_finished):
            ran_on["thread"] = threading.get_ident()
            time.sleep(5)
            on_finished(job, True, "done")

        S.run_job = slow_job
        win = MW.MainWindow()
        win._reconnect_timer.stop()
        win._run_scheduled_job(SimpleNamespace(job_id="j", name="j", kind="script", target="x"))
        pump(0.3)
        assert ran_on.get("thread") not in (None, threading.get_ident()), ran_on
        win.close()
        del win
        gc.collect()
        pump(0.3)
        print("survived", flush=True)
        """
    )
    _assert_clean(done)
