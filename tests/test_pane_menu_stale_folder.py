"""A right-click menu acts on the folder it was opened in, or not at all.

Found in review (round 1, UI): the menu is built for the selection in
folder A, but a folder load the user started earlier can finish while the
menu is open. The item-based entries (Encrypt, Decrypt, Show Checksum,
Show Versions, Extract) captured the FileItem and joined its name onto
the folder current at CLICK time, so Encrypt on A/x.txt encrypted B/x.txt.
The selection-based entries (Rename, Delete, Pack, ...) read a selection
that no longer belongs to the menu. A menu built for another folder or
connection now has its entries disabled the moment the pane moves on.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_pane_stale_targets import _Base, _HomeFS  # noqa: E402


def _all_actions(menu):
    for action in menu.actions():
        sub = action.menu()
        if sub is not None:
            yield from _all_actions(sub)
        elif not action.isSeparator():
            yield action


def _find(menu, prefix: str):
    return next(a for a in _all_actions(menu) if a.text().startswith(prefix))


class MenuStaleFolderTest(_Base):
    def menu_for(self, name: str):
        self.select(name)
        menu = self.pane._build_context_menu()
        self.addCleanup(menu.deleteLater)
        return menu

    def test_happy_menu_in_the_same_folder_stays_enabled(self) -> None:
        menu = self.menu_for("top.txt")
        self.assertTrue(_find(menu, "Show Checksum").isEnabled())
        self.assertTrue(_find(menu, "Rename").isEnabled())
        self.assertTrue(_find(menu, "Encrypt").isEnabled())

    def test_sad_encrypt_after_a_folder_change_touches_neither_file(self) -> None:
        menu = self.menu_for("top.txt")
        encrypt = _find(menu, "Encrypt")
        self.pane.navigate(str(self.root / "b"))
        self.assertTrue(self.settle())
        with mock.patch(
            "PyQt6.QtWidgets.QInputDialog.getText", return_value=("pw", True)
        ), mock.patch("ui.file_pane.QMessageBox"):
            encrypt.trigger()
        self.assertEqual(sorted(os.listdir(self.root / "b")), ["top.txt"])
        self.assertNotIn("top.txt.axenc", os.listdir(self.root))

    def test_sad_every_entry_of_a_stale_menu_is_disabled(self) -> None:
        menu = self.menu_for("top.txt")
        self.pane.navigate(str(self.root / "b"))
        self.assertTrue(self.settle())
        for prefix in ("Show Checksum", "Show Versions", "Rename", "Move to Trash",
                       "Delete Permanently", "Permissions", "Encrypt", "Pack as ZIP"):
            self.assertFalse(_find(menu, prefix).isEnabled(), prefix)

    def test_edge_refresh_of_the_same_folder_keeps_the_menu(self) -> None:
        menu = self.menu_for("top.txt")
        self.pane.refresh()
        self.assertTrue(self.settle())
        self.assertTrue(_find(menu, "Show Checksum").isEnabled())

    def test_edge_reconnect_retires_the_menu(self) -> None:
        menu = self.menu_for("top.txt")
        self.pane.set_backend(_HomeFS(str(self.root)))
        self.assertTrue(self.settle())
        self.assertFalse(_find(menu, "Show Checksum").isEnabled())

    def test_edge_a_new_menu_in_the_new_folder_is_enabled(self) -> None:
        self.menu_for("top.txt")
        self.pane.navigate(str(self.root / "b"))
        self.assertTrue(self.settle())
        menu = self.menu_for("top.txt")
        self.assertTrue(_find(menu, "Show Checksum").isEnabled())

    def test_edge_deleted_menu_does_not_break_navigation(self) -> None:
        self.select("top.txt")
        menu = self.pane._build_context_menu()
        menu.deleteLater()
        self.app.processEvents()
        from PyQt6.QtCore import QCoreApplication, QEvent

        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        self.pane.navigate(str(self.root / "b"))
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, str(self.root / "b"))


if __name__ == "__main__":
    unittest.main()
