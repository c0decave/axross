"""F5 / F6 with both panes on one folder copies nothing onto itself.

Measured before (UX review round 4): at the first start both panes show
the home folder; F5 on a file asked "Overwrite?" for the file itself and
the transfer then ended "0 copied, 1 failed". The window now sees that the
source folder is the destination folder before it asks anything and says
so in the status bar, in the interface language. Cancel at the conflict
prompt now also says that nothing was copied.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_transfer_conflict_window import _Window  # noqa: E402


class SameFolderTest(_Window):
    def same_folder(self) -> None:
        self.right.navigate(str(self.a))
        self.wait_for(lambda: self.right.current_path == str(self.a))

    def test_happy_f5_into_the_same_folder_copies_nothing_and_says_so(self) -> None:
        (self.a / "f.txt").write_text("mine")
        self.same_folder()
        self.answer()
        self.copy("f.txt")
        self.assertEqual(self.asked, [])  # no "Overwrite?" for the file itself
        self.assertEqual(self.win._transfer_manager._jobs, {})
        self.assertEqual((self.a / "f.txt").read_text(), "mine")
        message = self.win.statusBar().currentMessage()
        self.assertIn("same folder", message)
        self.assertIn(str(self.a), message)

    def test_sad_f6_into_the_same_folder_moves_nothing(self) -> None:
        (self.a / "f.txt").write_text("mine")
        self.same_folder()
        self.answer()
        self.move("f.txt")
        self.assertEqual(self.asked, [])
        self.assertTrue((self.a / "f.txt").exists())
        self.assertIn("Nothing moved", self.win.statusBar().currentMessage())

    def test_edge_the_message_is_german_in_the_german_window(self) -> None:
        from core import i18n

        (self.a / "f.txt").write_text("mine")
        self.same_folder()
        self.answer()
        i18n.install("de")
        try:
            self.copy("f.txt")
        finally:
            i18n.install("en")
        self.assertIn("derselbe Ordner", self.win.statusBar().currentMessage())

    def test_edge_cancel_at_the_conflict_prompt_says_nothing_was_copied(self) -> None:
        (self.a / "f.txt").write_text("new")
        (self.b / "f.txt").write_text("old")
        self.answer(None)  # Cancel
        self.copy("f.txt")
        self.assertEqual(len(self.asked), 1)
        self.assertEqual((self.b / "f.txt").read_text(), "old")
        self.assertIn("nothing was copied", self.win.statusBar().currentMessage())


if __name__ == "__main__":
    unittest.main()
