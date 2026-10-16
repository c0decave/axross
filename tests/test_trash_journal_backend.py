"""Every trash journal event names the connection it ran on.

Undo reads the newest 200 journal lines and pairs each finish event with
its start event. A trash whose start event has scrolled out of that
window must still be attributed to its connection; without a label the
undo either refuses (several connections open) or aims the restore at
whichever single connection happens to be open.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from core import trash as T
from core.local_fs import LocalFS
from core.operation_journal import read_recent
from core.undo import pick_undoable, undoable


class _NamedLocal(LocalFS):
    @property
    def name(self) -> str:  # type: ignore[override]
        return "Local A"


class TrashJournalBackendTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = os.path.join(self._tmp.name, "root")
        os.mkdir(self.root)
        self.journal = os.path.join(self._tmp.name, "ops.jsonl")
        patch = mock.patch.dict(os.environ, {"AXROSS_OPERATION_JOURNAL": self.journal})
        patch.start()
        self.addCleanup(patch.stop)
        self.backend = _NamedLocal()

    def _file(self, name: str) -> str:
        path = os.path.join(self.root, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("x")
        return path

    def _finish_events(self) -> list[dict]:
        # The sidecar write journals its own atomic_write events.
        return [
            e
            for e in read_recent(limit=200)
            if e.get("phase") == "finish" and e.get("operation") == "trash"
        ]

    def test_happy_finish_event_carries_the_backend_label(self) -> None:
        T.trash(self.backend, self._file("a.txt"), root=self.root)
        finishes = self._finish_events()
        self.assertEqual(len(finishes), 1)
        self.assertEqual(finishes[0]["status"], "done")
        self.assertEqual(finishes[0]["backend"], "Local A")

    def test_happy_undo_without_the_start_event_still_finds_the_connection(self) -> None:
        T.trash(self.backend, self._file("a.txt"), root=self.root)
        # Only the finish line is left in the window undo reads.
        plans = undoable(self._finish_events())
        self.assertEqual(plans[0].backend, "Local A")
        self.assertIs(pick_undoable(plans, {"Remote B"}), None)
        self.assertEqual(pick_undoable(plans, {"Local A", "Remote B"}).backend, "Local A")

    def test_sad_error_finish_event_carries_the_backend_label(self) -> None:
        with self.assertRaises(OSError):
            T.trash(self.backend, os.path.join(self.root, "missing.txt"), root=self.root)
        finishes = self._finish_events()
        self.assertEqual(len(finishes), 1)
        self.assertEqual(finishes[0]["status"], "error")
        self.assertEqual(finishes[0]["backend"], "Local A")

    def test_edge_backend_without_a_name_uses_its_type_name_on_both_events(self) -> None:
        class _Anon(LocalFS):
            name = ""

        T.trash(_Anon(), self._file("b.txt"), root=self.root)
        events = [e for e in read_recent(limit=200) if e.get("operation") == "trash"]
        labels = {(e["phase"], e["backend"]) for e in events}
        self.assertEqual(labels, {("start", "_Anon"), ("finish", "_Anon")})


if __name__ == "__main__":
    unittest.main()
