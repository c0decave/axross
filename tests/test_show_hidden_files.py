"""View > Show Hidden Files is one window-wide switch every file pane follows.

Operator report (item 29): with the switch on, hidden files did not show,
also on a remote connection; it took off and on again to see them. The
window applied the switch only to the panes that existed when it toggled
(``MainWindow._toggle_hidden``); the start switched it on while only the
first pane existed, and every pane made later - a split, a connection, a
restored layout, a layout preset - began with the model default "off"
while the menu said "on". Toggling went through every pane again, which is
why off-and-on cured it.

Also here: an entry the platform or the protocol marks hidden without a
leading dot (Windows/SMB FILE_ATTRIBUTE_HIDDEN, macOS/BSD UF_HIDDEN) is
hidden too, read from the listing the backend already makes.
"""

from __future__ import annotations

import json
import os
import shutil
import stat as stat_module
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from models.file_item import FileItem  # noqa: E402

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_DIRECTORY = 0x10
UF_HIDDEN = 0x8000


def _destroy(win) -> None:
    """Delete *win* now; deleteLater alone waits for an event loop."""
    from PyQt6 import sip
    from PyQt6.QtCore import QCoreApplication, QEvent

    if win is None or sip.isdeleted(win):
        return
    win.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _visible_names(pane) -> set[str]:
    proxy, model = pane._proxy, pane._model
    names = set()
    for row in range(proxy.rowCount()):
        item = model.get_item(proxy.mapToSource(proxy.index(row, 0)).row())
        if item is not None:
            names.add(item.name)
    return names


class _QtCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


# --- the model filter -----------------------------------------------------


class ProxyFilterTest(_QtCase):
    def setUp(self) -> None:
        from models.file_table_model import FileSortProxyModel, FileTableModel

        self.model = FileTableModel()
        self.proxy = FileSortProxyModel()
        self.proxy.setSourceModel(self.model)

    def shown(self, items, show_hidden: bool) -> set[str]:
        self.model.set_items(items)
        self.proxy.show_hidden = show_hidden
        return {
            self.model.get_item(self.proxy.mapToSource(self.proxy.index(r, 0)).row()).name
            for r in range(self.proxy.rowCount())
        }

    def test_happy_attribute_hidden_entries_follow_the_switch(self) -> None:
        items = [
            FileItem(name="pagefile.sys", attr_hidden=True),
            FileItem(name="Desktop", is_dir=True),
            FileItem(name=".bashrc"),
        ]
        self.assertEqual(self.shown(items, False), {"Desktop"})
        self.assertEqual(self.shown(items, True), {"pagefile.sys", "Desktop", ".bashrc"})

    def test_sad_an_entry_without_flags_is_judged_by_its_name_only(self) -> None:
        items = [FileItem(name="plain.txt"), FileItem(name=".dot")]
        self.assertEqual(self.shown(items, False), {"plain.txt"})

    def test_edge_dot_dot_stays_and_a_lone_dot_follows_the_dot_rule(self) -> None:
        items = [FileItem(name="..", is_dir=True), FileItem(name=".", is_dir=True)]
        self.assertEqual(self.shown(items, False), {".."})
        self.assertEqual(self.shown(items, True), {"..", "."})

    def test_edge_the_text_filter_still_applies_to_hidden_entries(self) -> None:
        from PyQt6.QtCore import QRegularExpression

        self.proxy.setFilterRegularExpression(QRegularExpression("sys"))
        items = [FileItem(name="pagefile.sys", attr_hidden=True), FileItem(name="a.txt")]
        self.assertEqual(self.shown(items, True), {"pagefile.sys"})
        self.assertEqual(self.shown(items, False), set())


class FileItemHiddenTest(unittest.TestCase):
    def test_happy_dot_name_or_flag_makes_an_entry_hidden(self) -> None:
        self.assertTrue(FileItem(name=".profile").is_hidden)
        self.assertTrue(FileItem(name="NTUSER.DAT", attr_hidden=True).is_hidden)
        self.assertFalse(FileItem(name="notes.txt").is_hidden)

    def test_edge_the_default_is_not_attribute_hidden(self) -> None:
        self.assertFalse(FileItem(name="x").attr_hidden)


# --- where the flag comes from --------------------------------------------


class LocalFlagTest(unittest.TestCase):
    def _st(self, **extra):
        base = dict(
            st_mode=stat_module.S_IFREG | 0o644, st_size=1, st_mtime=0.0, st_atime=0.0,
            st_uid=os.getuid() if hasattr(os, "getuid") else 0,
            st_gid=os.getgid() if hasattr(os, "getgid") else 0,
        )
        base.update(extra)
        return SimpleNamespace(**base)

    def test_happy_windows_hidden_attribute(self) -> None:
        from core.local_fs import LocalFS, stat_hidden_flag

        st = self._st(st_file_attributes=FILE_ATTRIBUTE_HIDDEN | 0x20)
        self.assertTrue(stat_hidden_flag(st))
        self.assertTrue(LocalFS()._stat_to_item("desktop.ini", st).attr_hidden)

    def test_happy_macos_bsd_uf_hidden_flag(self) -> None:
        from core.local_fs import LocalFS, stat_hidden_flag

        st = self._st(st_flags=UF_HIDDEN)
        self.assertTrue(stat_hidden_flag(st))
        self.assertTrue(LocalFS()._stat_to_item("Library", st).attr_hidden)

    def test_sad_unknown_or_garbage_attributes_do_not_crash(self) -> None:
        from core.local_fs import stat_hidden_flag

        for extra in (
            {},  # Linux: neither field
            {"st_file_attributes": None},
            {"st_flags": "hidden"},
            {"st_file_attributes": 0x20, "st_flags": 0},  # archive bit only
            {"st_flags": 0x20000},  # SF_ARCHIVED, not UF_HIDDEN
        ):
            with self.subTest(extra=str(extra)):
                self.assertFalse(stat_hidden_flag(self._st(**extra)))

    def test_edge_dotfile_inside_a_hidden_folder_lists_from_disk(self) -> None:
        from core.local_fs import LocalFS

        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        inner = root / ".config"
        inner.mkdir()
        (inner / ".hidden").write_text("h")
        (inner / "visible").write_text("v")
        items = {i.name: i for i in LocalFS().list_dir(str(inner))}
        self.assertEqual(set(items), {".hidden", "visible"})
        self.assertTrue(items[".hidden"].is_hidden)
        self.assertFalse(items["visible"].is_hidden)


class SmbFlagTest(unittest.TestCase):
    def _entry(self, name: str, attrs):
        info = SimpleNamespace(
            last_write_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
            file_attributes=attrs,
            end_of_file=5,
        )
        return SimpleNamespace(name=name, smb_info=info)

    def test_happy_hidden_attribute_from_the_directory_query(self) -> None:
        from core.smb_client import SmbSession

        item = SmbSession._dir_info_to_item(self._entry("Thumbs.db", FILE_ATTRIBUTE_HIDDEN | 0x20))
        self.assertTrue(item.attr_hidden)
        folder = SmbSession._dir_info_to_item(
            self._entry("$RECYCLE.BIN", FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY | 0x4)
        )
        self.assertTrue(folder.attr_hidden and folder.is_dir)

    def test_happy_hidden_attribute_from_stat(self) -> None:
        from core.smb_client import SmbSession

        st = SimpleNamespace(
            st_mode=stat_module.S_IFREG | 0o666, st_mtime_ns=0, st_size=1,
            st_file_attributes=FILE_ATTRIBUTE_HIDDEN,
        )
        self.assertTrue(SmbSession._stat_to_item("x", st).attr_hidden)

    def test_sad_a_stat_without_attributes_is_not_hidden(self) -> None:
        from core.smb_client import SmbSession

        st = SimpleNamespace(st_mode=stat_module.S_IFREG | 0o666, st_mtime_ns=0, st_size=1)
        self.assertFalse(SmbSession._stat_to_item("x", st).attr_hidden)

    def test_edge_plain_entry_is_not_hidden(self) -> None:
        from core.smb_client import SmbSession

        self.assertFalse(SmbSession._dir_info_to_item(self._entry("a.txt", 0x20)).attr_hidden)


class WinRmFlagTest(unittest.TestCase):
    def _row(self, **extra):
        row = {"Name": "x", "IsDir": False, "Size": 1, "Mtime": "2026-01-01T00:00:00.0000000Z"}
        row.update(extra)
        return row

    def test_happy_the_listing_script_asks_for_the_hidden_attribute(self) -> None:
        from core.winrm_client import WinRMSession

        scripts: list[str] = []
        session = WinRMSession.__new__(WinRMSession)
        session._run_ps = lambda script: scripts.append(script) or "[]"
        session.list_dir("C:\\")
        self.assertIn("[IO.FileAttributes]::Hidden", scripts[0])
        self.assertIn("IsHidden", scripts[0])

    def test_happy_is_hidden_true_marks_the_item(self) -> None:
        from core.winrm_client import WinRMSession

        self.assertTrue(WinRMSession._parse_listing_row(self._row(IsHidden=True)).attr_hidden)

    def test_sad_missing_or_non_bool_is_hidden_is_not_hidden(self) -> None:
        from core.winrm_client import WinRMSession

        for row in (self._row(), self._row(IsHidden="True"), self._row(IsHidden=1)):
            with self.subTest(row=str(row)):
                self.assertFalse(WinRMSession._parse_listing_row(row).attr_hidden)


# --- the window-wide switch -----------------------------------------------


class _WindowCase(_QtCase):
    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui import main_window as MW

        self.MW = MW
        self.home = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.session = self.home / "session.json"
        for target, name, value in (
            (MW.MainWindow, "_SESSION_FILE", self.session),
            (MW.MainWindow, "_RECENTS_FILE", self.home / "recents.json"),
            (CP, "DEFAULT_PATH", self.home / "cols.json"),
        ):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.folder = self.home / "data"
        self.folder.mkdir()
        (self.folder / ".dotfile").write_text("d")
        (self.folder / "plain.txt").write_text("p")
        self.windows: list = []

    def tearDown(self) -> None:
        from PyQt6.QtGui import QCloseEvent

        for win in self.windows:
            win.closeEvent(QCloseEvent())
            _destroy(win)

    def make_window(self):
        with mock.patch("pathlib.Path.home", return_value=self.home):
            win = self.MW.MainWindow()
        self.windows.append(win)
        return win

    def settle(self, pane, timeout: float = 5.0) -> None:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if not pane.is_loading:
                return
            time.sleep(0.005)
        self.fail("pane did not finish loading")

    def show_folder(self, pane) -> set[str]:
        self.settle(pane)
        pane.navigate(str(self.folder))
        self.app.processEvents()
        return _visible_names(pane)

    def states(self, win) -> list[bool]:
        return [p._proxy.show_hidden for p in win._panes]


class NewPanesFollowTest(_WindowCase):
    def test_happy_a_split_pane_made_after_the_start_shows_dotfiles(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        self.assertTrue(win._hidden_action.isChecked())
        win._split_pane(Qt.Orientation.Horizontal)
        new = win._panes[-1]
        self.assertTrue(new._proxy.show_hidden)
        self.assertIn(".dotfile", self.show_folder(new))

    def test_happy_a_remote_style_pane_follows_the_switch(self) -> None:
        from core.ram_fs import RamFsSession

        ram = RamFsSession()
        ram.mkdir("/srv")
        with ram.open_write("/srv/.env") as fh:
            fh.write(b"x")
        with ram.open_write("/srv/app.py") as fh:
            fh.write(b"y")
        win = self.make_window()
        pane = win._add_pane_to_splitter(win._root_splitter, ram)
        self.settle(pane)
        pane.navigate("/srv")
        self.assertEqual(_visible_names(pane) - {".."}, {".env", "app.py"})

    def test_happy_layout_preset_and_restored_panes_follow_the_switch(self) -> None:
        """The operator's start: the switch is on, the layout comes back
        from session.json - and its panes hid dotfiles."""
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._split_pane(Qt.Orientation.Horizontal)
        win._save_session()
        self.assertTrue(win.restore_layout_on_start())
        self.assertEqual(len(win._panes), 2)
        self.assertTrue(win._hidden_action.isChecked())
        self.assertEqual(self.states(win), [True, True])
        self.assertIn(".dotfile", self.show_folder(win._panes[-1]))
        preset_pane = win._preset_make_file_pane()
        self.addCleanup(preset_pane.deleteLater)
        self.assertTrue(preset_pane._proxy.show_hidden)

    def test_edge_restoring_a_session_brings_its_switch_back(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._hidden_action.setChecked(False)
        win._split_pane(Qt.Orientation.Horizontal)
        win._save_session()
        win._hidden_action.setChecked(True)
        self.assertTrue(win.restore_layout_on_start())
        self.assertFalse(win._hidden_action.isChecked())
        self.assertEqual(self.states(win), [False, False])

    def test_sad_switched_off_new_panes_hide_dotfiles(self) -> None:
        from PyQt6.QtCore import Qt

        win = self.make_window()
        win._hidden_action.setChecked(False)
        win._split_pane(Qt.Orientation.Horizontal)
        self.assertEqual(self.states(win), [False, False])
        self.assertNotIn(".dotfile", self.show_folder(win._panes[-1]))

    def test_edge_ctrl_h_toggles_the_window_switch_once_and_every_pane(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        win = self.make_window()
        win.show()
        win.activateWindow()
        win._split_pane(Qt.Orientation.Horizontal)
        self.app.processEvents()
        toggles: list[bool] = []
        win._hidden_action.toggled.connect(toggles.append)
        table = win._panes[0]._table
        table.setFocus()
        self.app.processEvents()
        QTest.keyClick(table, Qt.Key.Key_H, Qt.KeyboardModifier.ControlModifier)
        self.app.processEvents()
        self.assertEqual(toggles, [False])
        self.assertFalse(win._hidden_action.isChecked())
        self.assertEqual(self.states(win), [False, False])
        QTest.keyClick(table, Qt.Key.Key_H, Qt.KeyboardModifier.ControlModifier)
        self.app.processEvents()
        self.assertEqual(toggles, [False, True])
        self.assertEqual(self.states(win), [True, True])


class PaneKeyTest(_QtCase):
    def test_sad_the_pane_has_no_private_ctrl_h_toggle(self) -> None:
        """Ctrl+H belongs to the window: a pane that flipped its own filter
        would disagree with the menu check and with every other pane."""
        from PyQt6.QtCore import QEvent, Qt
        from PyQt6.QtGui import QKeyEvent

        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        pane.set_show_hidden(True)
        event = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_H, Qt.KeyboardModifier.ControlModifier)
        pane.eventFilter(pane._table, event)
        self.assertTrue(pane._proxy.show_hidden)


class PersistenceTest(_WindowCase):
    def test_happy_the_switch_survives_a_restart(self) -> None:
        win = self.make_window()
        win._hidden_action.setChecked(False)
        win._save_session()
        self.assertIs(json.loads(self.session.read_text())["window"]["show_hidden"], False)
        again = self.make_window()
        self.assertFalse(again._hidden_action.isChecked())
        self.assertEqual(self.states(again), [False])

    def test_sad_a_garbage_value_keeps_the_default_on(self) -> None:
        self.session.write_text(json.dumps({"window": {"show_hidden": "nope"}}))
        win = self.make_window()
        self.assertTrue(win._hidden_action.isChecked())
        self.assertEqual(self.states(win), [True])

    def test_edge_an_old_session_without_the_key_starts_with_hidden_files_shown(self) -> None:
        self.session.write_text(json.dumps({"window": {"compact": False}}))
        win = self.make_window()
        self.assertTrue(win._hidden_action.isChecked())
        self.assertEqual(self.states(win), [True])


if __name__ == "__main__":
    unittest.main()
