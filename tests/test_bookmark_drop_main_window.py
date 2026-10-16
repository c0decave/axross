"""Bookmark drops in the main window: create bookmarks from dragged
folders (local and remote, with the profile identity) and transfer dropped
items into a bookmarked folder through the normal transfer path.

The operator's main concern: "darauf achten wenn es remote systeme sind
oder ungemounted das es nicht crasht". A bookmark whose folder is gone,
whose remote is slow or not connected must never freeze or crash the
window; nothing is stat'ed or listed on the GUI thread while the drop is
handled, an unavailable target is reported and nothing else happens.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark  # noqa: E402


class _Window(unittest.TestCase):
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

        self.MW = MW
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Runs last: without an event loop deleteLater() never happens, and
        # every earlier test's window would keep running in the background.
        self.addCleanup(self._flush_deletes)
        orig = BM.BOOKMARKS_FILE
        BM.BOOKMARKS_FILE = self.tmp / "bookmarks.json"
        self.addCleanup(setattr, BM, "BOOKMARKS_FILE", orig)
        env = mock.patch.dict(
            os.environ, {"AXROSS_OPERATION_JOURNAL": str(self.tmp / "operations.jsonl")}
        )
        env.start()
        self.addCleanup(env.stop)
        p = mock.patch.object(CP, "DEFAULT_PATH", self.tmp / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        home = self.tmp / "home"
        home.mkdir()
        with mock.patch("pathlib.Path.home", return_value=home):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.win._reconnect_timer.stop()
        self.win.resize(1200, 700)
        self.win.show()
        for pane in list(self.win._panes)[1:]:
            self.win._close_pane(pane)
        self.a = self.tmp / "a"
        self.b = self.tmp / "b"
        (self.a / "sub").mkdir(parents=True)
        (self.b / "inbox").mkdir(parents=True)
        (self.a / "f.txt").write_text("payload")
        self.left = self.win._panes[0]
        self.left.navigate(str(self.a))
        self.assertTrue(self.wait_for(lambda: self.row_of(self.left, "f.txt") is not None))
        self.side = self.win._bookmark_sidebar
        self.manager = self.win._bookmark_manager
        self.asked: list = []
        p = mock.patch.object(
            MW.MainWindow,
            "_ask_transfer_conflict",
            lambda _w, conflict, remaining: self.asked.append(conflict.name),
            create=True,
        )
        p.start()
        self.addCleanup(p.stop)
        self.warnings: list = []
        p = mock.patch.object(
            MW.QMessageBox,
            "warning",
            side_effect=lambda *a, **k: self.warnings.append(a[2] if len(a) > 2 else a),
        )
        p.start()
        self.addCleanup(p.stop)

    # -- helpers -------------------------------------------------------------
    def _flush_deletes(self) -> None:
        from PyQt6.QtCore import QCoreApplication, QEvent

        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        self.app.processEvents()

    def wait_for(self, predicate, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def settle(self) -> None:
        from core.transfer_worker import TransferStatus

        def idle() -> bool:
            if getattr(self.win, "_conflict_checks", None):
                return False
            jobs = list(self.win._transfer_manager._jobs.values())
            return all(
                j.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs
            )

        self.assertTrue(self.wait_for(idle))
        self.wait_for(lambda: False, timeout=0.2)
        self.assertTrue(self.wait_for(idle))

    @staticmethod
    def row_of(pane, name: str):
        proxy = pane._table.model()
        for row in range(proxy.rowCount()):
            if proxy.index(row, 0).data() == name:
                return row
        return None

    def status(self) -> str:
        return self.win.statusBar().currentMessage()

    def ram_pane(self, label: str, profile_name: str | None = None, backend=None):
        from core.profiles import ConnectionProfile
        from core.ram_fs import RamFsSession

        backend = backend or RamFsSession(label)
        profile = ConnectionProfile(name=profile_name, protocol="sftp") if profile_name else None
        pane = self.win._add_pane_to_splitter(self.win._root_splitter, backend, profile=profile)
        self.wait_for(lambda: False, timeout=0.1)
        return pane

    def bookmark_drop(self, pane, paths, group=None, index=None) -> None:
        self.side.bookmark_drop_requested.emit([str(p) for p in paths], str(id(pane)), group, index)
        self.app.processEvents()

    def transfer_drop(self, pane, paths, bookmark, *, move: bool = True) -> None:
        self.side.transfer_drop_requested.emit(
            [str(p) for p in paths], str(id(pane)), bookmark, move
        )
        self.app.processEvents()


class CreateBookmarkTest(_Window):
    def test_happy_a_local_folder_becomes_a_local_bookmark(self) -> None:
        self.bookmark_drop(self.left, [self.a / "sub"])
        (bm,) = self.manager.all()
        self.assertEqual(
            (bm.name, bm.path, bm.backend_name, bm.profile_name),
            ("sub", str(self.a / "sub"), "Local", ""),
        )
        self.assertIn("1", self.status())
        # The sidebar and the Bookmarks menu show it.
        self.assertEqual(self.side._tree.topLevelItem(0).text(0), "sub")
        menu_texts = [a.text() for a in self.win._bookmarks_menu.actions()]
        self.assertTrue(any(t.startswith("sub") for t in menu_texts), menu_texts)

    def test_happy_a_remote_folder_carries_backend_and_profile(self) -> None:
        ram = self.ram_pane("srv", profile_name="srv-profile")
        ram.backend.mkdir("/data")
        self.bookmark_drop(ram, ["/data"])
        (bm,) = self.manager.all()
        self.assertEqual(
            (bm.name, bm.path, bm.backend_name, bm.profile_name),
            ("data", "/data", "RAM:srv", "srv-profile"),
        )

    def test_happy_several_folders_keep_their_order_at_the_drop_position(self) -> None:
        self.manager.add(Bookmark("first", "/first"))
        self.manager.add(Bookmark("last", "/last"))
        (self.a / "two").mkdir()
        self.bookmark_drop(self.left, [self.a / "sub", self.a / "two"], None, 1)
        self.assertEqual([b.name for b in self.manager.all()], ["first", "sub", "two", "last"])

    def test_happy_into_a_group(self) -> None:
        group = self.manager.add_group("G")
        self.bookmark_drop(self.left, [self.a / "sub"], group, None)
        self.assertEqual([b.name for b in group.children], ["sub"])

    def test_sad_an_existing_bookmark_is_not_added_twice(self) -> None:
        self.bookmark_drop(self.left, [self.a / "sub"])
        self.bookmark_drop(self.left, [self.a / "sub"])
        self.assertEqual(len(self.manager.all()), 1)
        self.assertIn("already", self.status())

    def test_sad_a_source_pane_that_is_gone_changes_nothing(self) -> None:
        self.side.bookmark_drop_requested.emit([str(self.a / "sub")], "123", None, None)
        self.app.processEvents()
        self.assertEqual(self.manager.all(), [])
        self.assertIn("no longer open", self.status())

    def test_edge_a_group_deleted_meanwhile_falls_back_to_the_top_level(self) -> None:
        group = self.manager.add_group("G")
        self.manager.remove_group(group)
        self.bookmark_drop(self.left, [self.a / "sub"], group, 0)
        self.assertEqual([b.name for b in self.manager.tree()], ["sub"])

    def test_edge_an_end_to_end_drag_onto_the_sidebar(self) -> None:
        """Real drag events: the sidebar is empty (only the hint shows)."""
        from PyQt6.QtCore import QMimeData, QPoint, QPointF, Qt
        from PyQt6.QtGui import QDragEnterEvent, QDragMoveEvent, QDropEvent

        from ui.file_pane import TRANSFER_MIME_TYPE

        mime = QMimeData()
        mime.setData(
            TRANSFER_MIME_TYPE,
            self.left._encode_transfer_payload(
                [str(self.a / "sub"), str(self.a / "f.txt")], dirs=[str(self.a / "sub")]
            ),
        )
        hint = self.side._hint
        acts = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
        args = (acts, mime, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
        hint.dragEnterEvent(QDragEnterEvent(QPoint(4, 4), *args))
        move = QDragMoveEvent(QPoint(4, 4), *args)
        hint.dragMoveEvent(move)
        self.assertTrue(move.isAccepted())
        hint.dropEvent(QDropEvent(QPointF(4, 4), *args))
        self.assertTrue(self.wait_for(lambda: len(self.manager.all()) == 1))
        self.assertEqual(self.manager.all()[0].path, str(self.a / "sub"))
        self.assertTrue((self.a / "f.txt").exists())  # files are never moved by this


class F8KeepsTheProfileTest(_Window):
    """The window-wide "Add Current Directory" (F8) used ``sender()`` to
    find the pane; from the menu action that is the QAction, so a remote
    bookmark lost its profile and could not be reopened later."""

    def test_happy_f8_on_a_remote_pane_keeps_the_profile(self) -> None:
        ram = self.ram_pane("srv", profile_name="srv-profile")
        self.win._set_active_pane(ram)
        from PyQt6.QtWidgets import QDialog

        with mock.patch.object(self.MW, "BookmarkEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Accepted
            cls.return_value.result_bookmark.side_effect = lambda: cls.call_args.args[0]
            cls.return_value.result_group.return_value = None
            self.win._bookmark_active_dir()
        (bm,) = self.manager.all()
        self.assertEqual((bm.backend_name, bm.profile_name), ("RAM:srv", "srv-profile"))

    def test_edge_f8_on_a_local_pane_has_no_profile(self) -> None:
        self.win._set_active_pane(self.left)
        from PyQt6.QtWidgets import QDialog

        with mock.patch.object(self.MW, "BookmarkEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Accepted
            cls.return_value.result_bookmark.side_effect = lambda: cls.call_args.args[0]
            cls.return_value.result_group.return_value = None
            self.win._bookmark_active_dir()
        (bm,) = self.manager.all()
        self.assertEqual((bm.backend_name, bm.profile_name, bm.path), ("Local", "", str(self.a)))


class TransferIntoBookmarkTest(_Window):
    def inbox(self) -> Bookmark:
        bm = Bookmark("inbox", str(self.b / "inbox"))
        self.manager.add(bm)
        return bm

    def test_happy_a_plain_drop_moves_into_the_bookmarked_folder(self) -> None:
        self.transfer_drop(self.left, [self.a / "f.txt"], self.inbox())
        self.settle()
        self.assertFalse((self.a / "f.txt").exists())
        self.assertEqual((self.b / "inbox" / "f.txt").read_text(), "payload")

    def test_happy_ctrl_copies(self) -> None:
        self.transfer_drop(self.left, [self.a / "f.txt"], self.inbox(), move=False)
        self.settle()
        self.assertEqual((self.a / "f.txt").read_text(), "payload")
        self.assertEqual((self.b / "inbox" / "f.txt").read_text(), "payload")

    def test_happy_an_existing_name_is_put_to_the_user_first(self) -> None:
        (self.b / "inbox" / "f.txt").write_text("old")
        self.transfer_drop(self.left, [self.a / "f.txt"], self.inbox())
        self.settle()
        self.assertEqual(self.asked, ["f.txt"])
        self.assertEqual((self.b / "inbox" / "f.txt").read_text(), "old")

    def test_happy_a_local_bookmark_from_a_remote_pane_downloads(self) -> None:
        ram = self.ram_pane("srv", profile_name="srv-profile")
        with ram.backend.open_write("/r.txt") as fh:
            fh.write(b"remote")
        self.transfer_drop(ram, ["/r.txt"], self.inbox(), move=False)
        self.settle()
        self.assertEqual((self.b / "inbox" / "r.txt").read_bytes(), b"remote")

    def test_happy_a_remote_bookmark_with_an_open_session_uploads(self) -> None:
        ram = self.ram_pane("srv", profile_name="srv-profile")
        ram.backend.mkdir("/drop")
        bm = Bookmark("drop", "/drop", backend_name="RAM:srv", profile_name="srv-profile")
        self.manager.add(bm)
        self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        self.settle()
        self.assertFalse((self.a / "f.txt").exists())
        with ram.backend.open_read("/drop/f.txt") as fh:
            self.assertEqual(fh.read(), b"payload")

    def test_sad_a_missing_or_unmounted_folder_is_reported_and_nothing_moves(self) -> None:
        for target in (self.tmp / "unmounted" / "share", self.a / "f.txt"):
            with self.subTest(target=target):
                self.warnings.clear()
                bm = Bookmark(target.name, str(target))
                self.manager.add(bm)
                self.transfer_drop(self.left, [self.a / "sub"], bm)
                self.settle()
                self.assertEqual(len(self.warnings), 1, self.warnings)
                self.assertIn(str(target), self.warnings[0])
                self.assertTrue((self.a / "sub").is_dir())
                self.assertTrue((self.a / "f.txt").is_file())
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])

    def test_sad_a_folder_dropped_onto_its_own_bookmark_or_below_is_refused(self) -> None:
        (self.a / "sub" / "deeper").mkdir()
        # A hand-edited bookmark path may end in a slash.
        for target in (str(self.a / "sub"), str(self.a / "sub" / "deeper"), f"{self.a}/sub/"):
            with self.subTest(target=target):
                bm = Bookmark("t", target)
                self.manager.add(bm)
                self.transfer_drop(self.left, [self.a / "sub"], bm)
                self.settle()
                self.assertIn("itself", self.status())
        self.assertTrue((self.a / "sub" / "deeper").is_dir())
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])

    def test_edge_items_already_in_the_bookmarked_folder_do_nothing(self) -> None:
        for target in (str(self.a), f"{self.a}/"):
            with self.subTest(target=target):
                bm = Bookmark("a", target)
                self.manager.add(bm)
                self.transfer_drop(self.left, [self.a / "f.txt"], bm)
                self.settle()
                self.assertIn("already", self.status())
                self.manager.remove_node(bm)
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])

    def test_sad_a_bookmark_deleted_meanwhile_changes_nothing(self) -> None:
        bm = self.inbox()
        self.manager.remove_node(bm)
        self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        self.settle()
        self.assertTrue((self.a / "f.txt").exists())
        self.assertIn("no longer exists", self.status())

    def test_sad_a_source_pane_that_is_gone_changes_nothing(self) -> None:
        self.side.transfer_drop_requested.emit([str(self.a / "f.txt")], "1", self.inbox(), True)
        self.app.processEvents()
        self.settle()
        self.assertTrue((self.a / "f.txt").exists())
        self.assertIn("no longer open", self.status())

    def test_edge_a_local_bookmark_without_a_local_pane_opens_one(self) -> None:
        ram = self.ram_pane("srv", profile_name="srv-profile")
        with ram.backend.open_write("/r.txt") as fh:
            fh.write(b"remote")
        self.win._close_pane(self.left)
        from core.local_fs import LocalFS

        self.assertFalse(any(isinstance(p.backend, LocalFS) for p in self.win._panes))
        self.transfer_drop(ram, ["/r.txt"], self.inbox(), move=False)
        self.settle()
        self.assertTrue(any(isinstance(p.backend, LocalFS) for p in self.win._panes))
        self.assertEqual((self.b / "inbox" / "r.txt").read_bytes(), b"remote")


class _BlockingRam:
    """RamFS whose ``list_dir`` of the drop folder hangs like a dead link,
    and which records every call made on the GUI thread."""

    def __init__(self, label: str, hang_path: str):
        from core.ram_fs import RamFsSession

        class Hanging(RamFsSession):
            def list_dir(inner, path):  # noqa: N805
                gui_calls.append(("list_dir", path)) if _on_gui() else None
                if path == hang_path:
                    release.wait(30)
                return super().list_dir(path)

            def stat(inner, path):  # noqa: N805
                gui_calls.append(("stat", path)) if _on_gui() else None
                return super().stat(path)

        gui_calls: list = []
        release = threading.Event()
        self.backend = Hanging(label)
        self.gui_calls = gui_calls
        self.release = release


def _on_gui() -> bool:
    return threading.current_thread() is threading.main_thread()


class UnavailableTargetTest(_Window):
    def test_edge_a_hanging_remote_does_not_freeze_the_window(self) -> None:
        slow = _BlockingRam("slow", "/drop")
        self.addCleanup(slow.release.set)
        ram = self.ram_pane("slow", profile_name="slow-profile", backend=slow.backend)
        slow.backend.mkdir("/drop")
        bm = Bookmark("drop", "/drop", backend_name="RAM:slow", profile_name="slow-profile")
        self.manager.add(bm)
        slow.gui_calls.clear()
        started = time.monotonic()
        self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        for _ in range(5):
            self.app.processEvents()
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(slow.gui_calls, [])
        self.assertTrue(self.win._conflict_checks)  # still waiting on the remote
        self.assertTrue((self.a / "f.txt").exists())
        slow.release.set()
        self.settle()
        with ram.backend.open_read("/drop/f.txt") as fh:
            self.assertEqual(fh.read(), b"payload")

    def test_sad_a_dead_remote_session_is_reported_and_nothing_moves(self) -> None:
        from core.ram_fs import RamFsSession

        class Dead(RamFsSession):
            def list_dir(self, path):
                if path == "/drop":
                    raise EOFError("connection closed by remote host")  # not an OSError
                return super().list_dir(path)

        backend = Dead("dead")
        backend.mkdir("/drop")
        self.ram_pane("dead", profile_name="dead-profile", backend=backend)
        bm = Bookmark("drop", "/drop", backend_name="RAM:dead", profile_name="dead-profile")
        self.manager.add(bm)
        self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        self.settle()
        self.assertEqual(len(self.warnings), 1, self.warnings)
        self.assertIn("connection closed", self.warnings[0])
        self.assertTrue((self.a / "f.txt").exists())
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])

    def test_edge_a_hanging_local_mount_is_never_touched_on_the_gui_thread(self) -> None:
        from core.local_fs import LocalFS

        hang = str(self.b / "inbox")
        release = threading.Event()
        self.addCleanup(release.set)
        gui_calls: list = []
        real = {n: getattr(LocalFS, n) for n in ("list_dir", "stat", "is_dir", "exists")}

        def wrap(name):
            def method(fs, path, *a, **k):
                if _on_gui():
                    gui_calls.append((name, path))
                if name == "list_dir" and path == hang:
                    release.wait(30)
                return real[name](fs, path, *a, **k)

            return method

        bm = Bookmark("inbox", hang)
        self.manager.add(bm)
        with mock.patch.multiple(LocalFS, **{n: wrap(n) for n in real}):
            self.transfer_drop(self.left, [self.a / "f.txt"], bm)
            for _ in range(5):
                self.app.processEvents()
            self.assertEqual(gui_calls, [])
            self.assertTrue(self.win._conflict_checks)
            release.set()
            self.assertTrue(self.wait_for(lambda: not self.win._conflict_checks))
        self.settle()
        self.assertEqual((self.b / "inbox" / "f.txt").read_text(), "payload")


class RemoteWithoutSessionTest(_Window):
    def remote_bookmark(self, profile_name: str = "far") -> Bookmark:
        bm = Bookmark("far", "/drop", backend_name="RAM:far", profile_name=profile_name)
        self.manager.add(bm)
        return bm

    def profile(self, name: str = "far"):
        from core.profiles import ConnectionProfile

        return ConnectionProfile(name=name, protocol="sftp")

    def test_happy_connects_through_the_profile_then_transfers(self) -> None:
        from core.ram_fs import RamFsSession

        bm = self.remote_bookmark()
        with (
            mock.patch.object(self.win._profile_manager, "get", return_value=self.profile()),
            mock.patch.object(self.win, "_quick_connect_profile") as connect,
        ):
            self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(connect.call_args.args[0].name, "far")
        post_connect = connect.call_args.kwargs["post_connect"]
        self.assertTrue((self.a / "f.txt").exists())  # nothing before the session is up
        session = RamFsSession("far")
        session.mkdir("/drop")
        pane = self.ram_pane("far", profile_name="far", backend=session)
        post_connect(pane)
        self.settle()
        self.assertFalse((self.a / "f.txt").exists())
        with session.open_read("/drop/f.txt") as fh:
            self.assertEqual(fh.read(), b"payload")

    def test_sad_no_profile_on_the_bookmark_is_reported(self) -> None:
        bm = self.remote_bookmark(profile_name="")
        with mock.patch.object(self.win, "_quick_connect_profile") as connect:
            self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        connect.assert_not_called()
        self.assertEqual(len(self.warnings), 1)
        self.assertIn("profile", self.warnings[0])
        self.assertTrue((self.a / "f.txt").exists())

    def test_sad_a_profile_that_no_longer_exists_is_reported(self) -> None:
        bm = self.remote_bookmark()
        with (
            mock.patch.object(self.win._profile_manager, "get", return_value=None),
            mock.patch.object(self.win, "_quick_connect_profile") as connect,
        ):
            self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        connect.assert_not_called()
        self.assertEqual(len(self.warnings), 1)
        self.assertIn("far", self.warnings[0])

    def test_edge_the_source_pane_closed_while_connecting_does_nothing(self) -> None:
        from core.ram_fs import RamFsSession

        bm = self.remote_bookmark()
        other = self.win._add_pane_to_splitter(self.win._root_splitter, type(self.left.backend)())
        other.navigate(str(self.a))
        with (
            mock.patch.object(self.win._profile_manager, "get", return_value=self.profile()),
            mock.patch.object(self.win, "_quick_connect_profile") as connect,
        ):
            self.transfer_drop(other, [self.a / "f.txt"], bm)
        self.win._close_pane(other)
        session = RamFsSession("far")
        session.mkdir("/drop")
        pane = self.ram_pane("far", profile_name="far", backend=session)
        connect.call_args.kwargs["post_connect"](pane)
        self.settle()
        self.assertTrue((self.a / "f.txt").exists())
        self.assertFalse(session.exists("/drop/f.txt"))
        self.assertIn("no longer open", self.status())

    def test_edge_a_session_for_another_host_is_not_used(self) -> None:
        from core.ram_fs import RamFsSession

        bm = self.remote_bookmark()
        with (
            mock.patch.object(self.win._profile_manager, "get", return_value=self.profile()),
            mock.patch.object(self.win, "_quick_connect_profile") as connect,
        ):
            self.transfer_drop(self.left, [self.a / "f.txt"], bm)
        session = RamFsSession("elsewhere")
        session.mkdir("/drop")
        pane = self.ram_pane("elsewhere", profile_name="far", backend=session)
        connect.call_args.kwargs["post_connect"](pane)
        self.settle()
        self.assertTrue((self.a / "f.txt").exists())
        self.assertFalse(session.exists("/drop/f.txt"))
        self.assertIn("RAM:elsewhere", self.status())


if __name__ == "__main__":
    unittest.main()
