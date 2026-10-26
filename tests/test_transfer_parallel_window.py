"""Parallel transfers in the main window: the setting on Edit > Settings >
Files & Panes reaches the running transfer manager, and the conflict prompts
of two copies started back to back come one after the other, never one
dialog on top of another (docs/plans/future-design-decisions.md, entry 3).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QDialogButtonBox  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.fixture
def win(stores):
    return stores.make_window()


def _type_into(spin, text: str) -> None:
    spin.setFocus()
    spin.selectAll()
    QTest.keyClicks(spin, text)
    QTest.keyClick(spin, Qt.Key.Key_Tab)


# --- the setting -------------------------------------------------------------


def test_e2e_the_files_page_sets_parallel_transfers_on_the_running_manager(stores, win) -> None:
    from core import transfer_pool as TP

    assert win._transfer_manager.max_parallel == 1
    dialog = stores.settings_dialog(win, "files")
    dialog.show()
    spin = dialog.page("files").parallel_transfers_spin
    assert (spin.minimum(), spin.maximum(), spin.value()) == (1, TP.MAX_PARALLEL, 1)
    _type_into(spin, "3")
    assert spin.value() == 3
    dialog.buttons.button(QDialogButtonBox.StandardButton.Apply).click()
    assert dialog.error_text() == ""
    assert TP.parallel_transfers() == 3
    assert win._transfer_manager.max_parallel == 3  # jobs starting from now
    assert len(win._transfer_manager._pool) == 3
    # The next start reads it as well.
    assert stores.make_window()._transfer_manager.max_parallel == 3


def test_edge_the_page_cannot_go_outside_one_to_eight(stores, win) -> None:
    dialog = stores.settings_dialog(win, "files")
    dialog.show()
    spin = dialog.page("files").parallel_transfers_spin
    _type_into(spin, "12")
    assert spin.value() <= 8
    spin.setValue(0)
    assert spin.value() == 1


def test_sad_cancel_changes_neither_the_store_nor_the_manager(stores, win) -> None:
    from core import transfer_pool as TP

    dialog = stores.settings_dialog(win, "files")
    dialog.page("files").parallel_transfers_spin.setValue(5)
    dialog.reject()
    assert TP.parallel_transfers() == 1
    assert win._transfer_manager.max_parallel == 1


def test_happy_the_setting_is_found_by_the_filter(stores, win) -> None:
    dialog = stores.settings_dialog(win)
    dialog.filter_edit.setText("parallel transfers")
    assert "files" in dialog.visible_page_ids()


# --- conflict prompts, one at a time -------------------------------------------


class _Window:
    def __init__(self, tmp: Path) -> None:
        from ui import column_prefs as CP
        from ui import main_window as MW

        self.MW = MW
        self.tmp = tmp
        self._patches = [
            mock.patch.dict(os.environ,
                            {"AXROSS_OPERATION_JOURNAL": str(tmp / "operations.jsonl")}),
            mock.patch.object(CP, "DEFAULT_PATH", tmp / "cols.json"),
        ]
        for p in self._patches:
            p.start()
        home = tmp / "home"
        home.mkdir()
        with mock.patch("pathlib.Path.home", return_value=home):
            self.win = MW.MainWindow()
        self.win._reconnect_timer.stop()
        for pane in list(self.win._panes)[1:]:
            self.win._close_pane(pane)
        self.a = tmp / "a"
        self.b = tmp / "b"
        self.a.mkdir()
        self.b.mkdir()
        self.left = self.win._panes[0]
        self.left.navigate(str(self.a))
        self.right = self.win._add_pane_to_splitter(
            self.win._root_splitter, type(self.left.backend)()
        )
        self.right.navigate(str(self.b))
        self.win._set_active_pane(self.left)
        self.win._set_target_pane(self.right)

    def close(self) -> None:
        self.win.close()
        self.win.deleteLater()
        for p in reversed(self._patches):
            p.stop()


def _pump(predicate, timeout: float = 15.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


@pytest.fixture
def window():
    tmp = Path(tempfile.mkdtemp()).resolve()
    w = _Window(tmp)
    yield w
    w.close()
    shutil.rmtree(tmp, ignore_errors=True)


def _prompt(answers, record):
    """A conflict prompt that, like QDialog.exec, runs the event loop while
    it is open, and records how many prompts are open at once."""

    def ask(_win, conflict, remaining):
        record["open"] += 1
        record["most"] = max(record["most"], record["open"])
        record["asked"].append(conflict.name)
        try:
            end = time.monotonic() + 0.4
            while time.monotonic() < end:
                APP.processEvents()
                time.sleep(0.01)
        finally:
            record["open"] -= 1
        return answers.pop(0) if answers else None

    return ask


def _idle(w) -> bool:
    from core.transfer_worker import TransferStatus

    if getattr(w.win, "_conflict_checks", None) or getattr(w.win, "_conflict_waiting", None):
        return False
    if w.win._transfer_manager._walks:  # jobs not registered yet
        return False
    return all(j.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE)
               for j in w.win._transfer_manager.all_jobs())


def test_happy_two_copies_started_together_ask_one_prompt_at_a_time(window) -> None:
    from core.transfer_conflicts import ConflictAction

    w = window
    w.win._transfer_manager.set_max_parallel(4)
    for name in ("f.txt", "g.txt"):
        (w.a / name).write_text("new " + name)
        (w.b / name).write_text("old")
    record = {"open": 0, "most": 0, "asked": []}
    answers = [(ConflictAction.OVERWRITE, False), (ConflictAction.OVERWRITE, False)]
    with mock.patch.object(w.MW.MainWindow, "_ask_transfer_conflict",
                           _prompt(answers, record), create=True):
        w.win._transfer_from_pane(w.left, [str(w.a / "f.txt")])
        w.win._transfer_from_pane(w.left, [str(w.a / "g.txt")])
        assert _pump(lambda: len(record["asked"]) == 2 and _idle(w))
    assert record["most"] == 1, record
    # In the order the destination checks finished (two threads).
    assert sorted(record["asked"]) == ["f.txt", "g.txt"]
    assert (w.b / "f.txt").read_text() == "new f.txt"
    assert (w.b / "g.txt").read_text() == "new g.txt"


def test_sad_cancel_at_the_first_prompt_still_asks_the_second_copy(window) -> None:
    from core.transfer_conflicts import ConflictAction

    w = window
    w.win._transfer_manager.set_max_parallel(4)
    for name in ("f.txt", "g.txt"):
        (w.a / name).write_text("new " + name)
        (w.b / name).write_text("old")
    record = {"open": 0, "most": 0, "asked": []}
    answers = [None, (ConflictAction.OVERWRITE, False)]  # Cancel, then Overwrite
    with mock.patch.object(w.MW.MainWindow, "_ask_transfer_conflict",
                           _prompt(answers, record), create=True):
        w.win._transfer_from_pane(w.left, [str(w.a / "f.txt")])
        w.win._transfer_from_pane(w.left, [str(w.a / "g.txt")])
        assert _pump(lambda: len(record["asked"]) == 2 and _idle(w))
    assert record["most"] == 1, record
    cancelled, overwritten = record["asked"]
    assert (w.b / cancelled).read_text() == "old"
    assert (w.b / overwritten).read_text() == "new " + overwritten


def test_edge_cancel_all_while_a_prompt_is_open_drops_the_waiting_copy(window) -> None:
    from core.transfer_conflicts import ConflictAction

    w = window
    w.win._transfer_manager.set_max_parallel(4)
    for name in ("f.txt", "g.txt"):
        (w.a / name).write_text("new " + name)
        (w.b / name).write_text("old")
    record = {"open": 0, "most": 0, "asked": []}

    def ask(_win, conflict, remaining):
        record["asked"].append(conflict.name)
        end = time.monotonic() + 0.4
        while time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.01)
        w.win._transfer_manager.cancel_all()  # pressed while this prompt is open
        return ConflictAction.OVERWRITE, False

    with mock.patch.object(w.MW.MainWindow, "_ask_transfer_conflict", ask, create=True):
        w.win._transfer_from_pane(w.left, [str(w.a / "f.txt")])
        w.win._transfer_from_pane(w.left, [str(w.a / "g.txt")])
        assert _pump(lambda: _idle(w) and record["asked"])
        _pump(lambda: False, 0.5)
    assert len(record["asked"]) == 1  # the waiting copy was dropped, not asked
    waiting = ({"f.txt", "g.txt"} - set(record["asked"])).pop()
    assert (w.b / waiting).read_text() == "old"
