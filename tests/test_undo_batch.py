"""Ctrl+Z undoes a whole user operation: a folder move, a trashed selection.

Review round 3: F6 of a folder ``proj`` with three files, then Ctrl+Z,
asked "Undo the last move? transfer b/proj/x.txt back to a/proj/x.txt"
and put back ONE file: the journal holds one entry per file and
``core.undo`` made one plan per entry. ``b/proj`` with two files stayed,
and ``a/proj`` came back with one. The tours and USAGE promise that Ctrl+Z
reverses the newest move. Moving two files to the trash took two Ctrl+Z.

Now the entries of one user operation (one ``transfer_files`` call - one
F5 / F6 / drop / Paste - and one Move to Trash run) share a journal batch
id, a move journals the folders it creates (``move_folder``), and
``undoable`` offers the batch as one plan: one question, every file back
at its own path, the folders the move created removed where they are
empty, the source folders made again. A name that is there again refuses
the whole batch before anything moves. Entries written before the batch
id existed are still undone one by one.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import operation_journal as OJ  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.undo import pick_undoable, record_undone, undoable  # noqa: E402
from tests.test_undo_window_targets import _WindowBase  # noqa: E402

_DETAILS = {"direction": "DOWNLOAD", "source_backend": "Local"}


def _move(op_id, src, dst, batch="", operation="move", status="done"):
    details = {**_DETAILS, **({"batch": batch} if batch else {})}
    return [
        {"operation_id": op_id, "phase": "start", "operation": operation, "backend": "Local",
         "source": src, "dest": dst, "details": details, "status": "active"},
        {"operation_id": op_id, "phase": "finish", "operation": operation, "backend": "Local",
         "source": src, "dest": dst, "details": details, "status": status},
    ]


def _folder(op_id, src, dst, batch):
    return [{"operation_id": op_id, "phase": "finish", "operation": "move_folder",
             "backend": "Local", "source": src, "dest": dst, "status": "done",
             "details": {**_DETAILS, "batch": batch}}]


def _folder_move_events(batch="b1"):
    return (_folder("f1", "/a/proj", "/b/proj", batch)
            + _move("m1", "/a/proj/x.txt", "/b/proj/x.txt", batch)
            + _move("m2", "/a/proj/y.txt", "/b/proj/y.txt", batch))


# --- core.undo ---------------------------------------------------------------


def test_happy_the_entries_of_one_batch_are_one_plan():
    [plan] = undoable(_folder_move_events())
    assert (plan.action, plan.operation, plan.operation_id) == ("batch", "move", "b1")
    assert sorted(p.operation_id for p in plan.parts) == ["f1", "m1", "m2"]
    assert (plan.source, plan.dest) == ("/a/proj", "/b/proj")
    assert "/b/proj" in plan.reason and "2 files" in plan.reason


def test_happy_recording_the_batch_undone_reaches_the_operation_before(tmp_path, monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    events = _move("old", "/a/old.txt", "/b/old.txt") + _folder_move_events()
    plan = pick_undoable(undoable(events), {"Local"})
    assert plan.operation_id == "b1"
    record_undone(plan, by=["back1", "back2"], by_batches=["b2"])
    events += OJ.read_recent(50, journal_path=journal)
    events += _move("back1", "/b/proj/x.txt", "/a/proj/x.txt", "b2")
    events += _folder("back-folder", "/b/proj", "/a/proj", "b2")
    nxt = pick_undoable(undoable(events), {"Local"})
    assert nxt.operation_id == "old"


def test_sad_a_copy_batch_is_one_entry_that_cannot_be_undone():
    events = (_move("c1", "/a/x.txt", "/b/x.txt", "b9", operation="transfer")
              + _move("c2", "/a/y.txt", "/b/y.txt", "b9", operation="transfer"))
    [plan] = undoable(events)
    assert not plan.reversible
    assert "copy cannot be undone" in plan.reason


def test_sad_entries_that_failed_stay_out_of_the_batch():
    events = (_folder_move_events()
              + _move("m3", "/a/proj/z.txt", "/b/proj/z.txt", "b1", status="error"))
    [plan] = undoable(events)
    assert sorted(p.operation_id for p in plan.parts) == ["f1", "m1", "m2"]


def test_edge_entries_written_before_batches_are_undone_one_by_one():
    events = (_move("l1", "/a/1.txt", "/b/1.txt") + _move("l2", "/a/2.txt", "/b/2.txt")
              + _folder_move_events())
    plans = undoable(events)
    assert [p.operation_id for p in plans] == ["b1", "l2", "l1"]
    assert plans[1].action == "transfer_back"


def test_edge_transfer_files_journals_one_batch_and_the_folders_it_made(tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QApplication

    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferStatus

    app = QApplication.instance() or QApplication([])
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    (tmp_path / "a" / "proj" / "sub").mkdir(parents=True)
    (tmp_path / "a" / "proj" / "x.txt").write_text("x")
    (tmp_path / "a" / "proj" / "sub" / "y.txt").write_text("y")
    (tmp_path / "b").mkdir()
    mgr = TransferManager()
    try:
        jobs = mgr.transfer_files(LocalFS(), LocalFS(), [str(tmp_path / "a" / "proj")],
                                  str(tmp_path / "b"), move=True)
        end = time.time() + 20
        while time.time() < end and any(
                j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()
    finally:
        mgr.shutdown()
    rows = [json.loads(line) for line in journal.read_text().splitlines()]
    finishes = [r for r in rows if r["phase"] == "finish"]
    assert {r["details"]["batch"] for r in finishes} == {jobs[0].batch_id}
    folders = sorted(r["dest"] for r in finishes if r["operation"] == "move_folder")
    assert folders == [str(tmp_path / "b" / "proj"), str(tmp_path / "b" / "proj" / "sub")]


# --- the window: Ctrl+Z ------------------------------------------------------


class BatchUndoWindowTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.a, self.b = self.tmp / "a", self.tmp / "b"
        (self.a / "proj" / "sub").mkdir(parents=True)
        self.b.mkdir()
        for name in ("x.txt", "y.txt", "sub/z.txt"):
            (self.a / "proj" / name).write_text(name)
        self.go(self.local, self.a)
        self.other = self.add_pane(LocalFS())
        self.go(self.other, self.b)

    def tree(self) -> list[str]:
        return sorted(str(p.relative_to(self.tmp)) for root in (self.a, self.b)
                      for p in root.rglob("*"))

    def move_proj(self) -> None:
        self.win._start_transfer_between(self.local, self.other, [str(self.a / "proj")],
                                         move=True)
        self.assertTrue(self.wait_for(
            lambda: not (self.a / "proj").exists() and self.transfers_idle()))

    def test_happy_ctrl_z_after_a_folder_move_puts_the_whole_folder_back(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        before = self.tree()
        self.move_proj()
        yes = QMessageBox.StandardButton.Yes
        with mock.patch("ui.main_window.QMessageBox.question", return_value=yes) as asked, \
                mock.patch("ui.main_window.QMessageBox.information"), \
                mock.patch("ui.main_window.QMessageBox.warning") as warn:
            self.win._undo_last_operation()
            self.assertTrue(self.wait_for(lambda: self.tree() == before))
            self.assertTrue(self.wait_for(lambda: not getattr(self.win, "_undo_busy", False)))
        self.assertFalse(warn.called, warn.call_args)
        self.assertEqual(asked.call_count, 1)
        self.assertIn("3 files, 2 folders", asked.call_args[0][2])
        self.assertEqual(self.tree(), before)  # b/proj is gone, a/proj whole again

    def test_happy_ctrl_z_after_trashing_a_selection_restores_all_of_it(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        for name in ("x.txt", "y.txt"):
            (self.b / name).write_text(name)
        self.go(self.other, self.b)
        self.assertTrue(self.wait_for(lambda: not self.other.is_loading))
        from PyQt6.QtCore import QItemSelectionModel

        yes = QMessageBox.StandardButton.Yes
        table = self.other._table
        self.assertTrue(self.wait_for(lambda: table.model().rowCount() >= 3))
        flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
        for row in range(table.model().rowCount()):
            if table.model().index(row, 0).data() in ("x.txt", "y.txt"):
                table.selectionModel().select(table.model().index(row, 0), flags)
        with mock.patch("ui.file_pane.QMessageBox.question", return_value=yes):
            self.other._trash_selected()
            self.assertTrue(self.wait_for(
                lambda: not (self.b / "x.txt").exists() and not (self.b / "y.txt").exists()
                and not self.other.removal_running))
        _info, warn = self.undo()
        self.assertTrue(self.wait_for(
            lambda: (self.b / "x.txt").exists() and (self.b / "y.txt").exists()))
        self.assertFalse(warn.called, warn.call_args)

    def test_sad_a_name_that_is_there_again_refuses_the_whole_batch(self) -> None:
        self.move_proj()
        (self.a / "proj").mkdir()
        (self.a / "proj" / "y.txt").write_text("new y")
        _info, warn = self.undo()
        self.assertTrue(warn.called)
        self.assertIn("exist(s) again", str(warn.call_args))
        # Nothing moved: not one file of the batch went back.
        self.assertEqual(sorted(p.name for p in (self.b / "proj").rglob("*.txt")),
                         ["x.txt", "y.txt", "z.txt"])
        self.assertEqual((self.a / "proj" / "y.txt").read_text(), "new y")

    def test_edge_older_entries_without_a_batch_still_go_one_by_one(self) -> None:
        # Two moves journaled before batches existed (no batch id).
        for name in ("old1.txt", "old2.txt"):
            (self.b / name).write_text(name)
            OJ.finish_operation(OJ.new_operation_id(), "move", status="done",
                                source=str(self.a / name), dest=str(self.b / name),
                                backend="Local", details=dict(_DETAILS))
        self.move_proj()
        self.undo()
        self.assertTrue(self.wait_for(lambda: (self.a / "proj" / "sub" / "z.txt").exists()))
        self.assertFalse((self.b / "proj").exists())
        self.undo()
        self.assertTrue(self.wait_for(lambda: (self.a / "old2.txt").exists()))
        self.assertTrue((self.b / "old1.txt").exists())  # the older one waits its turn
