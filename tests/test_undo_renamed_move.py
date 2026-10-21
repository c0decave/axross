"""Ctrl+Z puts back a file that a move stored under a new name.

Reported: a move whose name was taken at the destination, answered with
"Rename" at the conflict prompt, stored ``a.txt`` as ``a (1).txt``. Ctrl+Z
then refused with "a (1).txt no longer has the name it was moved under" -
although nothing had changed since. The window's transfer back required
the file to have its original name, because ``transfer_files`` names its
result after the source; a move under another name could never be undone.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from tests.test_undo_window_targets import _WindowBase  # noqa: E402


class RenamedMoveUndoTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.x = self.tmp / "x"
        self.y = self.tmp / "y"
        self.x.mkdir()
        self.y.mkdir()
        (self.x / "a.txt").write_bytes(b"MOVED")
        (self.y / "a.txt").write_bytes(b"ALREADY THERE")
        self.go(self.local, self.x)
        self.other = self.add_pane(LocalFS())
        self.go(self.other, self.y)

    def move_with_rename(self) -> None:
        from core.transfer_conflicts import ConflictAction, ConflictPlan, scan_conflicts

        scan = scan_conflicts(LocalFS(), LocalFS(), [str(self.x / "a.txt")], str(self.y))
        plan = ConflictPlan(self.other.backend, scan)
        plan.decide(scan.conflicts[0], ConflictAction.RENAME)
        self.win._start_transfer_between(
            self.local, self.other, [str(self.x / "a.txt")], move=True, conflict_plan=plan
        )
        self.assertTrue(
            self.wait_for(lambda: not (self.x / "a.txt").exists() and self.transfers_idle())
        )
        self.assertEqual((self.y / "a (1).txt").read_bytes(), b"MOVED")

    def undo_rows(self) -> list[dict]:
        rows = [json.loads(line) for line in self.journal.read_text().splitlines()]
        return [r for r in rows if r.get("operation") == "undo"]

    def test_happy_undo_puts_the_renamed_file_back_under_its_name(self) -> None:
        self.move_with_rename()
        _info, warn = self.undo()
        self.assertFalse(warn.called, warn.call_args)
        self.assertTrue(self.wait_for(lambda: len(self.undo_rows()) == 1))
        self.assertEqual((self.x / "a.txt").read_bytes(), b"MOVED")
        self.assertFalse((self.y / "a (1).txt").exists())
        # The file whose name was taken is not touched.
        self.assertEqual((self.y / "a.txt").read_bytes(), b"ALREADY THERE")
        self.assertEqual(sorted(os.listdir(self.x)), ["a.txt"])

    def test_sad_an_occupied_original_name_is_not_replaced(self) -> None:
        self.move_with_rename()
        (self.x / "a.txt").write_bytes(b"NEW FILE")
        _info, warn = self.undo()
        self.assertTrue(warn.called)
        self.assertIn("exists again", str(warn.call_args))
        self.assertEqual((self.x / "a.txt").read_bytes(), b"NEW FILE")
        self.assertEqual((self.y / "a (1).txt").read_bytes(), b"MOVED")
        self.assertEqual(self.undo_rows(), [])

    def test_edge_a_renamed_file_that_is_gone_fails_without_a_trace(self) -> None:
        self.move_with_rename()
        os.remove(self.y / "a (1).txt")
        _info, warn = self.undo()
        self.assertTrue(warn.called)
        self.assertFalse((self.x / "a.txt").exists())
        self.assertEqual(sorted(os.listdir(self.x)), [])
        self.assertEqual((self.y / "a.txt").read_bytes(), b"ALREADY THERE")
        self.assertEqual(self.undo_rows(), [])
