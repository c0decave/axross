"""New Folder, New File and Rename run their backend calls off the GUI
thread.

Audit (feedback: does everything really run async?): F7 asked the backend
whether the name was taken and then made the folder, F2 checked the
target and moved - all on the GUI thread: two round trips to a server,
the window held meanwhile. They run on the pane's op job now
(FilePaneWidget._run_op); the dialogs (the name, the production
countdown, a warning) stay on the GUI thread, between the steps.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication, QInputDialog  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from tests.off_gui_wait import _drain_op  # noqa: E402

APP = QApplication.instance() or QApplication([])


class SlowFS(LocalFS):
    """Every call that touches the server takes a while; who asked is noted."""

    delay = 0.3

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[str] = []

    def _note(self) -> None:
        self.threads.append(threading.current_thread().name)
        time.sleep(self.delay)

    def exists(self, path):
        self._note()
        return super().exists(path)

    def mkdir(self, path):
        self._note()
        return super().mkdir(path)

    def rename(self, src, dst):
        self._note()
        return super().rename(src, dst)


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "old.txt").write_text("o")
    (tmp_path / "taken.txt").write_text("t")
    p = FilePaneWidget(SlowFS())
    p.navigate(str(tmp_path))
    yield p
    p.shutdown()
    p.deleteLater()


def _select(pane, name: str) -> None:
    proxy = pane._proxy
    index = next(proxy.index(r, 0) for r in range(proxy.rowCount())
                 if proxy.index(r, 0).data() == name)
    pane._table.selectionModel().setCurrentIndex(
        index, QItemSelectionModel.SelectionFlag.ClearAndSelect
        | QItemSelectionModel.SelectionFlag.Rows)


def _answer(text: str):
    return mock.patch.object(QInputDialog, "getText", return_value=(text, True))


def _timed(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


# -- happy ------------------------------------------------------------------------------------


def test_happy_new_folder_does_not_hold_the_window(pane, tmp_path):
    with _answer("made"):
        assert _timed(pane._create_folder) < 0.2
        assert not (tmp_path / "made").exists()  # not yet
        assert _drain_op(pane)
    assert (tmp_path / "made").is_dir()
    assert pane._backend.threads and "MainThread" not in pane._backend.threads


def test_happy_new_file_does_not_hold_the_window(pane, tmp_path):
    with _answer("empty.txt"):
        assert _timed(pane._create_empty_file) < 0.2
        assert _drain_op(pane)
    assert (tmp_path / "empty.txt").read_bytes() == b""
    assert "MainThread" not in pane._backend.threads


def test_happy_rename_checks_and_moves_off_the_gui_thread(pane, tmp_path):
    _select(pane, "old.txt")
    with _answer("new.txt"):
        assert _timed(pane._rename_selected) < 0.2
        assert _drain_op(pane)
    assert (tmp_path / "new.txt").read_text() == "o" and not (tmp_path / "old.txt").exists()
    assert "MainThread" not in pane._backend.threads


def test_happy_the_production_question_comes_between_check_and_move(pane, tmp_path):
    asked: list[str] = []

    def gate(description):
        asked.append(threading.current_thread().name)
        return True

    pane._production_ok = gate
    _select(pane, "old.txt")
    with _answer("new.txt"):
        pane._rename_selected()
        assert _drain_op(pane)
    assert asked == ["MainThread"]
    assert (tmp_path / "new.txt").exists()


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_taken_name_is_refused_with_the_old_message(pane, tmp_path):
    _select(pane, "old.txt")
    with _answer("taken.txt"), mock.patch("ui.file_pane.QMessageBox.warning") as warning:
        pane._rename_selected()
        assert _drain_op(pane)
    warning.assert_called_once()
    assert warning.call_args.args[1:] == ("Rename", "Target already exists:\ntaken.txt")
    assert (tmp_path / "old.txt").exists() and (tmp_path / "taken.txt").read_text() == "t"


def test_sad_a_server_error_is_shown(pane, tmp_path):
    def refused(path):
        raise PermissionError(13, "Permission denied", path)

    pane._backend.mkdir = refused
    with _answer("nope"), mock.patch("ui.file_pane.QMessageBox.warning") as warning:
        pane._create_folder()
        assert _drain_op(pane)
    warning.assert_called_once()
    assert warning.call_args.args[1] == "New Folder"
    assert warning.call_args.args[2].startswith("Could not create folder:\n")
    assert "Permission denied" in warning.call_args.args[2]


def test_sad_a_second_change_while_one_runs_is_refused_with_a_word(pane, tmp_path):
    with _answer("one"):
        pane._create_folder()
    with _answer("two"):
        pane._create_folder()
        assert pane._status.text() == "Another change is still running in this pane."
    assert _drain_op(pane)
    assert (tmp_path / "one").is_dir() and not (tmp_path / "two").exists()


def test_sad_a_closed_pane_shows_nothing(pane, tmp_path):
    pane._backend.mkdir = lambda path: (_ for _ in ()).throw(OSError("late"))
    with _answer("x"), mock.patch("ui.file_pane.QMessageBox.warning") as warning:
        pane._create_folder()
        pane.shutdown()
        time.sleep(SlowFS.delay + 0.3)
        APP.processEvents()
    warning.assert_not_called()


# -- edge -------------------------------------------------------------------------------------


def test_edge_a_bug_in_the_backend_still_reaches_the_error_dialog(pane, monkeypatch):
    """Only an OSError is the server's answer; anything else is a bug and
    goes where every uncaught exception goes (PyQt hands it to
    sys.excepthook: axross's error dialog)."""
    seen: list = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: seen.append(exc[1]))
    pane._backend.mkdir = lambda path: (_ for _ in ()).throw(RuntimeError("bug"))
    with _answer("x"), mock.patch("ui.file_pane.QMessageBox.warning") as warning:
        pane._create_folder()
        _drain_op(pane)
    warning.assert_not_called()
    assert [str(e) for e in seen] == ["bug"]


def test_edge_the_status_line_comes_back_after_the_change(pane):
    with _answer("made"):
        pane._create_folder()
        assert _drain_op(pane)
    deadline = time.time() + 3
    while not pane._status.text().endswith("items") and time.time() < deadline:
        APP.processEvents()
        time.sleep(0.01)
    assert pane._status.text().endswith("items")
