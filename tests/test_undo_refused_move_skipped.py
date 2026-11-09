"""Ctrl+Z does not get stuck on a move it can never undo.

Measured before (review round 8): F6 of a.txt, then F6 of b.txt, then the
user edited the moved b.txt. Ctrl+Z refused b.txt ("is not the file the
move put there") - and so did every further Ctrl+Z: the move of a.txt
could never be undone. Once b.txt was deleted, Ctrl+Z showed "[Errno 2]
No such file or d…". The same for a Move to Trash whose entries' places
were taken by new files.

Now such an operation is passed over with a note ("… could not be undone
and was skipped: <reason>"), journaled as a skipped undo so it is not
offered again, and Ctrl+Z reaches the operation before it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.undo import (  # noqa: E402
    entry_identity,
    gone_reason,
    plan_undo,
    record_skipped,
    undoable,
)
from tests.test_undo_window_targets import _WindowBase  # noqa: E402

_SKIPPED = "could not be undone and was skipped"


def _event(src, dst, identity, op="op-1"):
    return {"operation_id": op, "phase": "finish", "operation": "move", "status": "done",
            "backend": "Local", "source": str(src), "dest": str(dst),
            "details": {"direction": "DOWNLOAD", "source_backend": "Local",
                        "dest_identity": identity}}


# --- core.undo ---------------------------------------------------------------------------


def test_happy_a_move_whose_entry_is_unchanged_is_not_gone(tmp_path):
    fs = LocalFS()
    moved = tmp_path / "b.txt"
    moved.write_text("B")
    plan = plan_undo(_event(tmp_path / "a" / "b.txt", moved, entry_identity(fs, str(moved))))
    refused: list = []
    assert gone_reason(plan, fs, refused) == "" and refused == []


def test_sad_an_edited_or_deleted_destination_makes_the_move_gone(tmp_path):
    fs = LocalFS()
    moved = tmp_path / "b.txt"
    moved.write_text("B")
    plan = plan_undo(_event(tmp_path / "a" / "b.txt", moved, entry_identity(fs, str(moved))))
    moved.write_text("B edited by the user")
    refused: list = []
    assert "is not the file the move put there" in gone_reason(plan, fs, refused)
    assert len(refused) == 1
    moved.unlink()
    refused.clear()
    assert "is no longer where the move put it" in gone_reason(plan, fs, refused)
    assert len(refused) == 1


def test_sad_a_skipped_move_is_not_offered_again(tmp_path, monkeypatch):
    from core import operation_journal as OJ

    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    for op, name in (("op-a", "a.txt"), ("op-b", "b.txt")):
        event = _event(tmp_path / "x" / name, tmp_path / "y" / name, {"kind": "file"}, op)
        OJ.finish_operation(op, "move", status="done", source=event["source"],
                            dest=event["dest"], backend="Local", details=event["details"])
    plans = undoable(OJ.read_recent(100))
    assert [p.operation_id for p in plans if p.reversible] == ["op-b", "op-a"]
    record_skipped(plans[0], "b.txt is no longer where the move put it")
    plans = undoable(OJ.read_recent(100))
    assert [p.operation_id for p in plans if p.reversible] == ["op-a"]
    # The skipped undo record itself reads as an undo, not "did not complete".
    assert plans[0].reason == "an undo is not itself undoable"


def test_edge_a_backend_that_cannot_answer_does_not_skip_the_move(tmp_path):
    plan = plan_undo(_event(tmp_path / "a.txt", tmp_path / "b.txt", {"kind": "file"}))

    class _Broken:
        def exists(self, _path):
            raise OSError("connection lost")

    refused: list = []
    assert gone_reason(plan, _Broken(), refused) == "" and refused == []


# --- the window ---------------------------------------------------------------------------


class RefusedMoveWindowTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.a, self.b = self.tmp / "A", self.tmp / "B"
        self.a.mkdir()
        self.b.mkdir()
        (self.a / "a.txt").write_text("A")
        (self.a / "b.txt").write_text("B")
        self.go(self.local, self.a)
        self.other = self.add_pane(LocalFS())
        self.go(self.other, self.b)
        self.move(self.local, self.other, self.a / "a.txt")
        self.move(self.local, self.other, self.a / "b.txt")

    def undo_rows(self) -> list[dict]:
        rows = [json.loads(line) for line in self.journal.read_text().splitlines() if line]
        return [r for r in rows if r.get("operation") == "undo"]

    def _check_skips_to_the_older_move(self, reason: str) -> None:
        from unittest import mock

        from PyQt6.QtWidgets import QMessageBox

        asked: list[str] = []
        with mock.patch("ui.main_window.QMessageBox.question",
                        side_effect=lambda *a, **k: asked.append(a[2])
                        or QMessageBox.StandardButton.Yes), \
                mock.patch("ui.main_window.QMessageBox.information") as info, \
                mock.patch("ui.main_window.QMessageBox.warning") as warn:
            self.win._undo_last_operation()
            self.assertTrue(self.wait_for(lambda: not getattr(self.win, "_undo_busy", False)))
            self.assertTrue(self.wait_for(self.transfers_idle))
            self.wait_for(lambda: False, timeout=0.3)
        self.assertFalse(warn.called, warn.call_args)
        self.assertFalse(info.called, info.call_args)
        self.assertEqual(len(asked), 1, asked)
        self.assertIn(_SKIPPED, asked[0])
        self.assertIn(reason, asked[0])
        self.assertIn(str(self.b / "a.txt"), asked[0])  # the older move is offered
        self.assertTrue(self.wait_for(lambda: (self.a / "a.txt").exists()))
        self.assertTrue(self.wait_for(lambda: len(self.undo_rows()) == 2))
        self.assertEqual(sorted(r["status"] for r in self.undo_rows()), ["done", "skipped"])
        # The next Ctrl+Z does not offer b.txt again.
        info, warn = self.undo()
        self.assertFalse(warn.called, warn.call_args)
        self.assertNotIn("b.txt", str(info.call_args))

    def test_sad_an_edited_destination_is_skipped_once(self) -> None:
        (self.b / "b.txt").write_text("B edited by the user")
        self._check_skips_to_the_older_move("is not the file the move put there")
        self.assertEqual((self.b / "b.txt").read_text(), "B edited by the user")
        self.assertFalse((self.a / "b.txt").exists())

    def test_sad_a_deleted_destination_is_skipped_without_a_raw_error(self) -> None:
        (self.b / "b.txt").unlink()
        self._check_skips_to_the_older_move("b.txt is no longer where the move put it")
        self.assertFalse((self.a / "b.txt").exists())

    def test_edge_a_job_error_is_said_as_a_sentence(self) -> None:
        """An undo transfer that fails anyway (the file vanished after the
        check) names the error as core.user_errors.describe() does."""
        from unittest import mock

        from core.transfer_worker import TransferJob

        job = TransferJob(source_path=str(self.b / "b.txt"), dest_path=str(self.a / "b.txt"))
        job.error = FileNotFoundError(2, "No such file or directory", str(self.b / "b.txt"))
        plan = plan_undo(_event(self.a / "b.txt", self.b / "b.txt", {"kind": "file"}))
        self.win._undo_waits.append({"plan": plan, "pending": {job.job_id}, "pane": None,
                                     "jobs": [job], "record": True})
        with mock.patch.object(self.win._transfer_manager, "get_job", return_value=job), \
                mock.patch("ui.main_window.QMessageBox.warning") as warn:
            self.win._on_undo_job_error(job.job_id, "[Errno 2] No such file or directory")
        text = str(warn.call_args)
        self.assertNotIn("[Errno", text)
        self.assertIn("b.txt", text)


class TrashPlaceTakenWindowTest(_WindowBase):
    def test_sad_a_trash_undo_whose_places_are_taken_is_skipped_once(self) -> None:
        from core import trash as T

        folder = self.tmp / "A"
        folder.mkdir()
        (folder / "a.txt").write_text("ORIGINAL")
        home = self.tmp / "home"
        root = str(home / ".axross-trash")
        fs = self.local.backend
        T.trash(fs, str(folder / "a.txt"), root=root)
        (folder / "a.txt").write_text("NEW FILE BY OTHER PROGRAM")
        from unittest import mock

        with mock.patch("pathlib.Path.home", return_value=home):
            info, warn = self.undo()
            self.assertFalse(warn.called, warn.call_args)
            self.assertIn(_SKIPPED, str(info.call_args))
            self.assertIn("stays in the trash", str(info.call_args))
            info, warn = self.undo()
        self.assertNotIn(_SKIPPED, str(info.call_args))
        self.assertEqual((folder / "a.txt").read_text(), "NEW FILE BY OTHER PROGRAM")
        self.assertEqual(len(T.list_trash(fs, root=root)), 1)
