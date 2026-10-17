"""File operations act on the item the user picked, not on a folder or
connection the pane moved to in the meantime.

Found in review:

* ``set_backend`` (the auto-reconnect path) switched ``_current_path`` to
  the new backend's home at once but left the OLD listing on screen until
  the background load arrived. A Delete pressed in that window joined the
  selected name onto the new folder and removed a different file. The
  directory watcher kept polling the dead connection as well.
* Rename / Encrypt / Decrypt resolved the selected item's path only
  after their input dialog closed. A folder load that finished while the
  dialog was open moved ``_current_path``, so the old folder's item name
  was applied to the new folder.
"""

from __future__ import annotations

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

from tests.test_pane_async_navigation import SlowFS  # noqa: E402


class _HomeFS(SlowFS):
    """A fresh connection whose home is a chosen folder."""

    def __init__(self, home: str) -> None:
        super().__init__()
        self._home = home

    def home(self) -> str:
        return self._home


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui.file_pane import FilePaneWidget

        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / "b").mkdir()
        (self.root / "top.txt").write_text("root copy")
        (self.root / "exists.txt").write_text("root exists")
        # The same name in the folder the pane moves to: the wrong target.
        (self.root / "b" / "top.txt").write_text("b copy")
        p = mock.patch.object(CP, "DEFAULT_PATH", self.root / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        self.fs = SlowFS()
        self.pane = FilePaneWidget(self.fs)
        self.addCleanup(self.pane.deleteLater)
        self.pane.resize(800, 500)
        self.pane.show()
        self.pane.navigate(str(self.root))
        self.app.processEvents()

    def settle(self, timeout=3.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if not self.pane.is_loading:
                return True
            time.sleep(0.002)
        return False

    def select(self, name: str) -> None:
        m = self.pane._proxy
        row = next(r for r in range(m.rowCount()) if m.data(m.index(r, 0)) == name)
        self.pane._table.selectRow(row)
        self.pane._table.setFocus()

    def names(self) -> set[str]:
        m = self.pane._proxy
        return {m.data(m.index(r, 0)) for r in range(m.rowCount())}

    def press(self, key, mods=None) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        QTest.keyClick(self.pane._table, key, mods or Qt.KeyboardModifier.NoModifier)

    def finish_load_then(self, gate, value):
        """A stand-in for a modal input dialog during which the pane's
        pending folder load finishes, as it does in the real event loop."""

        def fake(*_args, **_kwargs):
            gate.set()
            self.assertTrue(self.settle())
            self.assertEqual(self.pane.current_path, str(self.root / "b"))
            return value

        return fake


class ReconnectTest(_Base):
    """``set_backend``: the auto-reconnect swaps the connection."""

    def test_sad_delete_during_the_reconnect_load_does_not_hit_the_new_folder(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QMessageBox

        self.select("top.txt")
        new_fs = _HomeFS(str(self.root / "b"))
        gate = new_fs.hold(str(self.root / "b"))
        self.pane.set_backend(new_fs)
        with mock.patch(
            "ui.file_pane.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes
        ):
            self.press(Qt.Key.Key_Delete)
        gate.set()
        self.assertTrue(self.settle())
        self.assertEqual((self.root / "b" / "top.txt").read_text(), "b copy")
        self.assertEqual((self.root / "top.txt").read_text(), "root copy")

    def test_edge_the_old_listing_is_not_offered_while_the_new_one_loads(self) -> None:
        self.select("top.txt")
        new_fs = _HomeFS(str(self.root / "b"))
        gate = new_fs.hold(str(self.root / "b"))
        self.pane.set_backend(new_fs)
        self.assertEqual(self.pane.selected_items(), [])
        self.assertNotIn("exists.txt", self.names())
        self.assertEqual(self.pane._path_edit.text(), self.pane.current_path)
        gate.set()
        self.assertTrue(self.settle())

    def test_happy_reconnect_lands_on_the_previous_folder_with_one_load(self) -> None:
        new_fs = _HomeFS(str(self.root / "b"))
        self.pane.set_backend(new_fs, str(self.root))
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, str(self.root))
        self.assertIn("top.txt", self.names())
        self.assertIs(self.pane.backend, new_fs)
        self.assertEqual(new_fs.calls, [str(self.root)])

    def test_happy_the_watcher_follows_the_new_connection(self) -> None:
        old_watcher = self.pane._watcher
        self.assertIsNotNone(old_watcher)
        self.assertIs(old_watcher._backend, self.fs)
        new_fs = _HomeFS(str(self.root / "b"))
        # The two calls the 0.7.21 auto-reconnect made.
        self.pane.set_backend(new_fs)
        self.pane.navigate_async(str(self.root))
        self.assertTrue(self.settle())
        self.assertEqual(self.pane.current_path, str(self.root))
        self.assertIsNotNone(self.pane._watcher)
        self.assertIs(self.pane._watcher._backend, new_fs)

    def test_sad_a_failed_reconnect_load_leaves_a_consistent_empty_pane(self) -> None:
        new_fs = _HomeFS(str(self.root / "b"))
        new_fs.fail[str(self.root)] = OSError("gone")
        self.pane.set_backend(new_fs, str(self.root))
        self.assertTrue(self.settle())
        # Nothing of the old connection's listing is left to act on.
        self.assertNotIn("top.txt", self.names())
        self.assertIn("gone", self.pane._status.text())


class AutoReconnectWindowTest(_Base):
    """The real caller: MainWindow._check_connections."""

    def test_happy_auto_reconnect_reloads_the_previous_folder_on_the_new_session(self) -> None:
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            win = MW.MainWindow()
        # close() stops the window's worker threads; a bare deleteLater
        # destroys them while they run and aborts the process.
        self.addCleanup(win.deleteLater)
        self.addCleanup(win.close)
        pane = win._panes[0]
        pane.navigate(str(self.root))

        class _Dropped(SlowFS):
            connected = False

        pane._backend = _Dropped()
        win._pane_profiles[pane] = mock.Mock(host="h")
        new_fs = _HomeFS(str(self.root / "b"))
        self.addCleanup(win._pane_profiles.clear)  # closeEvent cannot save a Mock profile
        with mock.patch.object(MW, "_is_ssh_session", return_value=True), mock.patch.object(
            win._connection_manager, "connect", return_value=new_fs
        ), mock.patch.object(win._connection_manager, "release"):
            win._check_connections()
            # The reconnect runs on a worker thread: wait for it to land.
            end = time.time() + 3
            while (pane.backend is not new_fs or pane.is_loading) and time.time() < end:
                self.app.processEvents()
                time.sleep(0.002)
        self.assertIs(pane.backend, new_fs)
        self.assertEqual(pane.current_path, str(self.root))
        self.assertEqual(new_fs.calls, [str(self.root)])
        win._pane_profiles.clear()


class ModalDialogTest(_Base):
    """Rename / Encrypt / Decrypt keep the item they were opened on."""

    def start_slow_navigation_to_b(self):
        gate = self.fs.hold(str(self.root / "b"))
        self.pane.navigate_async(str(self.root / "b"))
        self.assertTrue(self.pane.is_loading)
        return gate

    def test_happy_rename_without_navigation_still_renames(self) -> None:
        from PyQt6.QtCore import Qt

        self.select("top.txt")
        with mock.patch(
            "PyQt6.QtWidgets.QInputDialog.getText", return_value=("renamed.txt", True)
        ):
            self.press(Qt.Key.Key_F2)
        self.assertTrue((self.root / "renamed.txt").exists())
        self.assertFalse((self.root / "top.txt").exists())

    def test_sad_rename_finishing_after_a_folder_change_renames_the_picked_file(self) -> None:
        from PyQt6.QtCore import Qt

        self.select("top.txt")
        gate = self.start_slow_navigation_to_b()
        with mock.patch(
            "PyQt6.QtWidgets.QInputDialog.getText",
            side_effect=self.finish_load_then(gate, ("renamed.txt", True)),
        ):
            self.press(Qt.Key.Key_F2)
        self.assertEqual((self.root / "renamed.txt").read_text(), "root copy")
        self.assertEqual((self.root / "b" / "top.txt").read_text(), "b copy")
        self.assertFalse((self.root / "b" / "renamed.txt").exists())

    def test_edge_rename_collision_is_checked_in_the_picked_files_folder(self) -> None:
        from PyQt6.QtCore import Qt

        self.select("top.txt")
        gate = self.start_slow_navigation_to_b()
        with mock.patch(
            "PyQt6.QtWidgets.QInputDialog.getText",
            side_effect=self.finish_load_then(gate, ("exists.txt", True)),
        ), mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            self.press(Qt.Key.Key_F2)
        warning.assert_called_once()
        self.assertEqual((self.root / "exists.txt").read_text(), "root exists")
        self.assertEqual((self.root / "top.txt").read_text(), "root copy")
        self.assertEqual((self.root / "b" / "top.txt").read_text(), "b copy")
        self.assertFalse((self.root / "b" / "exists.txt").exists())

    def test_sad_encrypt_finishing_after_a_folder_change_encrypts_the_picked_file(self) -> None:
        from ui.file_pane import FileItem

        self.select("top.txt")
        item = self.pane.selected_file_items()[0]
        self.assertIsInstance(item, FileItem)
        gate = self.start_slow_navigation_to_b()
        answers = iter([("pw", True), ("pw", True)])

        def fake(*args, **kwargs):
            value = next(answers)
            if not gate.is_set():
                return self.finish_load_then(gate, value)()
            return value

        with mock.patch("PyQt6.QtWidgets.QInputDialog.getText", side_effect=fake), mock.patch(
            "ui.file_pane.QMessageBox.information"
        ), mock.patch("ui.file_pane.QMessageBox.critical") as critical:
            self.pane._encrypt_selected_file(item)
        critical.assert_not_called()
        self.assertTrue((self.root / "top.txt.axenc").exists())
        self.assertFalse((self.root / "b" / "top.txt.axenc").exists())

    def test_sad_decrypt_finishing_after_a_folder_change_writes_next_to_the_picked_file(
        self,
    ) -> None:
        from core import encrypted_overlay as E
        from core.local_fs import LocalFS

        E.write_encrypted(LocalFS(), str(self.root / "plain.txt"), b"secret", "pw")
        self.pane.navigate(str(self.root))
        self.select("plain.txt" + E.ENC_SUFFIX)
        item = self.pane.selected_file_items()[0]
        gate = self.start_slow_navigation_to_b()
        with mock.patch(
            "PyQt6.QtWidgets.QInputDialog.getText",
            side_effect=self.finish_load_then(gate, ("pw", True)),
        ), mock.patch("ui.file_pane.QMessageBox.critical") as critical, mock.patch(
            "ui.file_pane.QMessageBox.warning"
        ) as warning:
            self.pane._decrypt_selected_file(item)
        critical.assert_not_called()
        warning.assert_not_called()
        self.assertEqual((self.root / "plain.txt").read_bytes(), b"secret")
        self.assertFalse((self.root / "b" / "plain.txt").exists())


if __name__ == "__main__":
    unittest.main()
