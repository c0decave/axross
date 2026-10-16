"""Ctrl+Z in the main window puts a moved file back where it came from.

Found in review (round 2):

* A move through the transfer engine is undone as a "transfer back". The
  journal named only the destination host, so the window guessed the
  source as "the first open connection with another label". A move between
  two local panes (label "Local" on both ends) therefore had a remote pane
  picked as its source as soon as one was open, and Ctrl+Z shipped the
  file to that host.
* The transfer back was enqueued into whatever folder the other pane was
  browsing (``_start_transfer_between`` uses ``target.current_path``), not
  into the folder the file came from; a same-named file there was
  overwritten.
* A journal entry without a backend label was applied to whichever
  backend was open first.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _FakeRemote:
    """A "remote" connection that stores its files in a local temp dir.

    Not a LocalFS, so the window picks UPLOAD / DOWNLOAD directions for it
    exactly as it does for SFTP."""

    name = "SFTP: fake"

    def __init__(self) -> None:
        from core.local_fs import LocalFS

        self._fs = LocalFS()

    def __getattr__(self, attr):
        return getattr(self._fs, attr)


class _WindowBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui import main_window as MW

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.journal = self.tmp / "operations.jsonl"
        env = mock.patch.dict(os.environ, {"AXROSS_OPERATION_JOURNAL": str(self.journal)})
        env.start()
        self.addCleanup(env.stop)
        p = mock.patch.object(CP, "DEFAULT_PATH", self.tmp / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        home = self.tmp / "home"
        home.mkdir()
        with mock.patch("pathlib.Path.home", return_value=home):
            self.win = MW.MainWindow()
        # close() stops the window's worker threads first.
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.win._reconnect_timer.stop()
        # Exactly the panes each test asks for.
        for pane in list(self.win._panes)[1:]:
            self.win._close_pane(pane)
        self.local = self.win._panes[0]

    def add_pane(self, backend):
        return self.win._add_pane_to_splitter(self.win._root_splitter, backend)

    def go(self, pane, path: Path) -> None:
        pane.navigate(str(path))

    def wait_for(self, predicate, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def transfers_idle(self) -> bool:
        from core.transfer_worker import TransferStatus

        jobs = list(self.win._transfer_manager._jobs.values())
        return all(
            j.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs
        )

    def move(self, source, target, path: Path) -> None:
        """F6 from *source* to *target* for one file."""
        self.win._start_transfer_between(source, target, [str(path)], move=True)
        self.assertTrue(self.wait_for(lambda: not path.exists() and self.transfers_idle()))

    def undo(self, answer=None):
        """Ctrl+Z with "Yes" on the confirmation; returns the info/warning mocks."""
        from PyQt6.QtWidgets import QMessageBox

        yes = QMessageBox.StandardButton.Yes
        with mock.patch("ui.main_window.QMessageBox.question", return_value=answer or yes), \
                mock.patch("ui.main_window.QMessageBox.information") as info, \
                mock.patch("ui.main_window.QMessageBox.warning") as warn:
            self.win._undo_last_operation()
            self.assertTrue(self.wait_for(self.transfers_idle))
            # The debounced refresh and the transfer engine settle.
            self.wait_for(lambda: False, timeout=0.3)
        return info, warn


class LocalToLocalMoveTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.a = self.tmp / "a"
        self.b = self.tmp / "b"
        self.r = self.tmp / "remote"
        for d in (self.a, self.b, self.r):
            d.mkdir()
        (self.a / "f.txt").write_text("payload")
        self.go(self.local, self.a)
        self.other_local = self.add_pane(type(self.local.backend)())
        self.go(self.other_local, self.b)

    def test_sad_an_open_remote_pane_is_not_taken_for_the_source(self) -> None:
        self.move(self.local, self.other_local, self.a / "f.txt")
        self.assertEqual((self.b / "f.txt").read_text(), "payload")
        remote = self.add_pane(_FakeRemote())
        self.go(remote, self.r)

        self.undo()

        self.assertFalse((self.r / "f.txt").exists(), "undo shipped the file to the remote pane")
        self.assertEqual((self.a / "f.txt").read_text(), "payload")
        self.assertFalse((self.b / "f.txt").exists())

    def test_happy_two_local_panes_undo_puts_the_file_back(self) -> None:
        self.move(self.local, self.other_local, self.a / "f.txt")
        self.undo()
        self.assertEqual((self.a / "f.txt").read_text(), "payload")
        self.assertFalse((self.b / "f.txt").exists())

    def test_edge_the_original_place_taken_again_is_not_overwritten(self) -> None:
        self.move(self.local, self.other_local, self.a / "f.txt")
        (self.a / "f.txt").write_text("new file")
        _info, warn = self.undo()
        self.assertEqual((self.a / "f.txt").read_text(), "new file")
        self.assertEqual((self.b / "f.txt").read_text(), "payload")
        self.assertTrue(warn.called)


class RemoteToLocalMoveTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.local_dir = self.tmp / "local"
        self.data = self.tmp / "remote" / "data"
        self.other = self.tmp / "remote" / "other"
        for d in (self.local_dir, self.data, self.other):
            d.mkdir(parents=True)
        (self.data / "f.txt").write_text("moved")
        (self.other / "f.txt").write_text("keep me")
        self.go(self.local, self.local_dir)
        self.remote = self.add_pane(_FakeRemote())
        self.go(self.remote, self.data)

    def test_sad_undo_does_not_land_in_the_folder_the_pane_shows_now(self) -> None:
        self.move(self.remote, self.local, self.data / "f.txt")
        self.go(self.remote, self.other)

        self.undo()

        self.assertEqual((self.other / "f.txt").read_text(), "keep me")
        self.assertEqual((self.data / "f.txt").read_text(), "moved")
        self.assertFalse((self.local_dir / "f.txt").exists())

    def test_happy_the_journal_names_both_ends_of_the_move(self) -> None:
        self.move(self.remote, self.local, self.data / "f.txt")
        rows = [json.loads(line) for line in self.journal.read_text().splitlines()]
        finish = [r for r in rows if r["phase"] == "finish"][-1]
        self.assertEqual(finish["backend"], "Local")
        self.assertEqual(finish["details"].get("source_backend"), "SFTP: fake")

    def test_sad_the_source_connection_closed_refuses_instead_of_guessing(self) -> None:
        self.move(self.remote, self.local, self.data / "f.txt")
        self.win._close_pane(self.remote)
        third = self.add_pane(_FakeRemote())
        third.backend.name = "SFTP: other"
        self.go(third, self.other)

        info, warn = self.undo()

        self.assertEqual((self.local_dir / "f.txt").read_text(), "moved")
        self.assertEqual((self.other / "f.txt").read_text(), "keep me")
        self.assertTrue(info.called or warn.called)


class LegacyJournalTest(_WindowBase):
    """Entries written before the journal named the source connection."""

    def write(self, **event) -> None:
        from core.operation_journal import finish_operation, start_operation

        op = start_operation("move", **{k: v for k, v in event.items() if k != "status"})
        finish_operation(op, "move", status="done",
                         **{k: v for k, v in event.items() if k != "status"})

    def test_sad_a_move_without_a_recorded_source_is_refused(self) -> None:
        a = self.tmp / "a"
        b = self.tmp / "b"
        a.mkdir()
        b.mkdir()
        (b / "f.txt").write_text("payload")
        self.go(self.local, b)
        remote = self.add_pane(_FakeRemote())
        self.go(remote, self.tmp)
        self.write(source=str(a / "f.txt"), dest=str(b / "f.txt"), backend="Local",
                   details={"direction": "DOWNLOAD"})

        info, warn = self.undo()

        self.assertEqual((b / "f.txt").read_text(), "payload")
        self.assertFalse((self.tmp / "f.txt").exists())
        self.assertTrue(info.called or warn.called)

    def test_sad_an_entry_without_a_backend_label_is_refused_with_two_connections(self) -> None:
        a = self.tmp / "a"
        a.mkdir()
        (a / "moved.txt").write_text("x")
        self.go(self.local, a)
        remote = self.add_pane(_FakeRemote())
        self.go(remote, self.tmp)
        # A same-backend rename journaled without a label.
        self.write(source=str(a / "orig.txt"), dest=str(a / "moved.txt"))

        info, _warn = self.undo()

        self.assertTrue((a / "moved.txt").exists())
        self.assertFalse((a / "orig.txt").exists())
        self.assertTrue(info.called)

    def test_edge_an_entry_without_a_label_with_one_connection_still_works(self) -> None:
        a = self.tmp / "a"
        a.mkdir()
        (a / "moved.txt").write_text("x")
        self.go(self.local, a)
        self.write(source=str(a / "orig.txt"), dest=str(a / "moved.txt"))

        self.undo()

        self.assertTrue((a / "orig.txt").exists())
        self.assertFalse((a / "moved.txt").exists())


if __name__ == "__main__":
    unittest.main()
