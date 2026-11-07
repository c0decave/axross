"""Ctrl+Z talks to the server off the GUI thread.

Audit (feedback: does everything really run async?): finding the entry
to undo asked each trash entry's connection whether it was still there,
and carrying it out restored (or renamed) on the server - all on the GUI
thread, the window held for the round trips. Both run on a worker now
(MainWindow._undo_step); the question in between stays on the GUI thread.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class SlowFS(LocalFS):
    """A connection whose every look at the server takes a while; its home
    (and so its trash) is the test's own - parallel tests empty theirs."""

    delay = 0.25

    def __init__(self, home: str = "") -> None:
        super().__init__()
        self.threads: list[str] = []
        self._home = home

    def home(self):
        return self._home or super().home()

    def _note(self) -> None:
        self.threads.append(threading.current_thread().name)
        time.sleep(self.delay)

    def exists(self, path):
        self._note()
        return super().exists(path)

    def rename(self, src, dst):
        self._note()
        return super().rename(src, dst)


@pytest.fixture
def window(tmp_path, monkeypatch):
    import ui.main_window as mw

    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "journal.jsonl"))
    (tmp_path / "home").mkdir()
    fs = SlowFS(str(tmp_path / "home"))
    target = tmp_path / "gone.txt"
    target.write_text("data")
    T.trash(fs, str(target))
    fs.threads.clear()
    said: list[tuple[str, str]] = []
    questions: list[str] = []

    def question(*a, **_k):
        questions.append(threading.current_thread().name)
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", question)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: said.append(("info", a[2])))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: said.append(("warn", a[2])))

    class Window:
        _undo_last_operation = mw.MainWindow._undo_last_operation
        _undo_refusal = staticmethod(mw.MainWindow._undo_refusal)
        _undo_source_backend = mw.MainWindow._undo_source_backend
        _undo_step = mw.MainWindow._undo_step
        _undo_status = mw.MainWindow._undo_status
        _undo_picked = mw.MainWindow._undo_picked
        _undo_apply = mw.MainWindow._undo_apply
        _panes: list = []

        def __init__(self) -> None:
            self.finished: list = []

        def _backends_by_label(self):
            return {fs.name: (fs, None)}

        def _finish_undo(self, plan, pane, jobs=()):
            self.finished.append(plan.source)

    w = Window()
    w.fs, w.target, w.said, w.questions = fs, target, said, questions
    return w


def _settle(window, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if not getattr(window, "_undo_busy", False) and (window.finished or window.said):
            return
        time.sleep(0.01)


def test_happy_ctrl_z_returns_at_once_and_restores_off_the_gui_thread(window):
    start = time.perf_counter()
    window._undo_last_operation()
    assert time.perf_counter() - start < 0.2
    assert not window.target.exists()  # not yet
    _settle(window)
    assert window.target.read_text() == "data"
    assert window.finished == [str(window.target)]
    assert window.questions == ["MainThread"]  # the question stays on the GUI thread
    assert window.fs.threads and "MainThread" not in window.fs.threads


def test_sad_a_second_ctrl_z_while_one_runs_does_not_start_another(window):
    window._undo_last_operation()
    window._undo_last_operation()
    _settle(window)
    assert window.finished == [str(window.target)]
    assert len(window.questions) == 1


def test_sad_a_failing_server_is_reported(window, monkeypatch):
    monkeypatch.setattr(T, "restore", lambda *a, **k: (_ for _ in ()).throw(OSError("link down")))
    window._undo_last_operation()
    _settle(window)
    assert ("warn", "link down") in window.said
    assert window.finished == []


def test_edge_nothing_to_undo_is_said_after_the_search(window):
    T.empty_trash(window.fs)
    window._undo_last_operation()
    _settle(window)
    assert window.said and window.said[0][0] == "info"
    assert window.questions == []
