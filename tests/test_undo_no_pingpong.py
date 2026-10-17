"""Undoing a move does not make the move back the next thing to undo.

Before: undo of a transfer-engine move sends the data back through the
transfer engine, which journals that as a new "move". ``record_undone``
dropped the original from the history, but the move back was now the
newest reversible entry: the next Ctrl+Z moved the file forward again,
the one after that back again, forever, and the operations below it were
never reached.

Now the undo record names the operations the undo itself ran
(``details["by"]``) and ``undoable`` drops those too; the main window
passes the operation ids of the jobs it queued for the undo.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import operation_journal as OJ  # noqa: E402
from core.undo import pick_undoable, record_undone, undoable  # noqa: E402

_APP = None


def _move(op_id: str, src: str, dst: str) -> list[dict]:
    details = {"direction": "RELAY", "source_backend": "Local"}
    return [
        {"operation_id": op_id, "phase": "start", "operation": "move", "backend": "Local",
         "source": src, "dest": dst, "details": details, "status": "active"},
        {"operation_id": op_id, "phase": "finish", "operation": "move", "backend": "Local",
         "source": src, "dest": dst, "details": {}, "status": "done"},
    ]


def _trash(op_id: str, path: str) -> list[dict]:
    return [
        {"operation_id": op_id, "phase": "finish", "operation": "trash", "backend": "Local",
         "source": path, "dest": "", "details": {"trash_id": "t1"}, "status": "done"},
    ]


def _undo_record(journal) -> dict:
    return [e for e in OJ.read_recent(50, journal_path=journal) if e["operation"] == "undo"][-1]


def test_happy_after_undoing_a_move_the_next_undo_reaches_the_older_operation(
    tmp_path, monkeypatch
):
    journal = tmp_path / "journal.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    events = _trash("older", "/a/older.txt") + _move("fwd", "/a/r.txt", "/b/r.txt")
    plan = pick_undoable(undoable(events), {"Local"})
    assert plan.operation_id == "fwd"
    # The undo's own transfer back is journaled as a move by the engine.
    events += _move("back", "/b/r.txt", "/a/r.txt")
    record_undone(plan, by=["back"])
    events += OJ.read_recent(50, journal_path=journal)
    nxt = pick_undoable(undoable(events), {"Local"})
    assert nxt.operation_id == "older"


def test_sad_without_the_reverse_ids_the_move_back_is_offered(tmp_path, monkeypatch):
    # What happens when the caller does not name the reverse operation:
    # the old behaviour, kept for undo records written before.
    journal = tmp_path / "journal.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    events = _move("fwd", "/a/r.txt", "/b/r.txt")
    plan = pick_undoable(undoable(events), {"Local"})
    events += _move("back", "/b/r.txt", "/a/r.txt")
    record_undone(plan)
    events += OJ.read_recent(50, journal_path=journal)
    assert pick_undoable(undoable(events), {"Local"}).operation_id == "back"


def test_edge_the_undo_record_lists_its_reverse_operations(tmp_path, monkeypatch):
    journal = tmp_path / "journal.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    plan = pick_undoable(undoable(_move("fwd", "/a/r.txt", "/b/r.txt")), {"Local"})
    record_undone(plan, by=["back1", "", "back2"])
    record = _undo_record(journal)
    assert record["details"]["undone"] == "fwd"
    assert record["details"]["by"] == ["back1", "back2"]


def test_edge_a_malformed_by_field_is_ignored():
    events = _move("fwd", "/a/r.txt", "/b/r.txt") + [
        {"operation_id": "u1", "phase": "finish", "operation": "undo", "status": "done",
         "details": {"undone": "other", "by": "fwd"}},
    ]
    # "by" must be a list; a string is not split into characters.
    assert pick_undoable(undoable(events), {"Local"}).operation_id == "fwd"


class _Window:
    """MainWindow's undo bookkeeping without the window."""

    def __init__(self) -> None:
        import ui.main_window as mw

        self._finish_undo_impl = mw.MainWindow._finish_undo
        self._await = mw.MainWindow._await_undo_jobs
        self._on_finished = mw.MainWindow._on_undo_job_finished
        self._undo_waits: list = []
        self._panes: list = []

    def _finish_undo(self, plan, pane, jobs=()):
        return self._finish_undo_impl(self, plan, pane, jobs)

    def statusBar(self):  # noqa: N802 - Qt name
        class _Bar:
            def showMessage(self, *_a):  # noqa: N802 - Qt name
                pass

        return _Bar()


def test_happy_the_window_records_the_jobs_it_queued_for_the_undo(tmp_path, monkeypatch):
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    global _APP  # a QApplication nobody references is collected at once
    _APP = QApplication.instance() or QApplication([])
    from core.transfer_worker import TransferJob, TransferStatus

    journal = tmp_path / "journal.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    plan = pick_undoable(undoable(_move("fwd", "/a/r.txt", "/b/r.txt")), {"Local"})
    win = _Window()
    job = TransferJob.__new__(TransferJob)
    job.job_id = "job-1"
    job.operation_id = "back"
    job.status = TransferStatus.PENDING
    job.error_message = ""
    win._await(win, plan, [job], None)
    win._on_finished(win, "job-1")
    assert _undo_record(journal)["details"]["by"] == ["back"]
