"""The pane asks when a backend wants a yes for a delete (ConfirmationRequired).

Review round 9, maintainer: a recursive delete of IMAP INBOX (whose
folders all live below it) or of an SMB DFS link is not forbidden - the
person decides. The backend raises ConfirmationRequired before anything is
deleted; the pane then shows the backend's explanation as a question
(default No). Yes deletes again with the backend's keyword; No deletes
nothing. Neither shows an error box.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_pane_async_delete import GatedRemoveFS, _Base  # noqa: E402

_EXPLANATION = ("INBOX is the INBOX. An IMAP server never deletes the INBOX, and on this "
                "server 1 other folder lives below it. Yes deletes that folder with all its "
                "messages; the INBOX itself and the messages in it stay.")


class AskingFS(GatedRemoveFS):
    """A recursive remove of the folder "plain" asks, as IMAP does for INBOX."""

    def __init__(self) -> None:
        super().__init__()
        self.asked: list[tuple] = []

    def remove(self, path: str, recursive: bool = False, *,
               keep_namespace_root: bool = False) -> None:
        if Path(path).name == "plain" and recursive and not keep_namespace_root:
            from core.backend import ConfirmationRequired

            self.asked.append((path, recursive))
            raise ConfirmationRequired("imap_namespace_root", path, _EXPLANATION,
                                       option="keep_namespace_root",
                                       details={"subfolders": 1})
        super().remove(path, recursive=recursive)


class PaneAsksTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.fs = AskingFS()
        self.pane = self.make_pane(self.fs)

    def answers(self, *replies):
        from unittest import mock

        from PyQt6.QtWidgets import QMessageBox

        yes, no = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No
        return mock.patch("ui.file_pane.QMessageBox.question",
                          side_effect=[yes if r else no for r in replies])

    def test_happy_yes_deletes_with_the_keyword_and_shows_no_error(self) -> None:
        self.select("plain")
        with self.answers(True, True) as question, self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.wait(lambda: question.call_count == 2 and self.idle()))
            self.assertTrue(self.idle())
        warning.assert_not_called()
        asked = question.call_args_list[1][0]
        self.assertIn("INBOX itself and the messages in it stay", asked[2])
        self.assertIn("Go ahead?", asked[2])
        # default No: Enter on a reflex keeps everything
        from PyQt6.QtWidgets import QMessageBox

        self.assertEqual(question.call_args_list[1][0][4], QMessageBox.StandardButton.No)
        self.assertEqual(len(self.fs.asked), 1)
        self.assertFalse((self.root / "plain").exists())
        self.assertIn(str(self.root / "plain"), self.fs.removed)

    def test_sad_no_deletes_nothing_and_shows_no_error(self) -> None:
        self.select("plain")
        with self.answers(True, False) as question, self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.wait(lambda: question.call_count == 2))
            self.assertTrue(self.idle())
        warning.assert_not_called()
        self.assertTrue((self.root / "plain" / "x.txt").exists())
        self.assertEqual(self.fs.removed, [])

    def test_edge_the_other_entries_go_and_only_the_asking_one_waits(self) -> None:
        self.select("a.txt", "plain")
        with self.answers(True, False) as question, self.warning() as warning:
            self.pane._delete_selected()
            self.assertTrue(self.wait(lambda: question.call_count == 2))
            self.assertTrue(self.idle())
        warning.assert_not_called()
        self.assertFalse((self.root / "a.txt").exists())
        self.assertTrue((self.root / "plain").exists())
        self.assertIn("1 item deleted", self.pane._status.text())


if __name__ == "__main__":
    unittest.main()
