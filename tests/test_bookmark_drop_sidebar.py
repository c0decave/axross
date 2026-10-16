"""Dragging files and folders from a pane onto the bookmark sidebar.

Operator: "drag+drop auch in bookmarks, das wäre cool" and "aber darauf
achten wenn es remote systeme sind oder ungemounted das es nicht crasht".

This file covers the parts that need no main window: the bookmark model
(insert at a position), the drag payload (which dragged paths are
folders) and the sidebar, which only reads the payload and the tree under
the cursor - it never touches a backend - and reports what the drop means:
"bookmark these folders here" or "transfer these items into that
bookmark". Foreign payloads (text, URLs from another program) are ignored.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark, BookmarkManager  # noqa: E402

_REPO = Path(__file__).resolve().parent.parent


class _Store(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = BM.BOOKMARKS_FILE
        self._tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        BM.BOOKMARKS_FILE = Path(self._tmp) / "bookmarks.json"
        self.addCleanup(setattr, BM, "BOOKMARKS_FILE", self._orig)
        self.m = BookmarkManager()


class ManagerInsertTest(_Store):
    """``add`` takes a position and says whether it added anything."""

    def test_happy_add_appends_and_reports_true(self) -> None:
        self.assertTrue(self.m.add(Bookmark("a", "/a")))
        self.assertTrue(self.m.add(Bookmark("b", "/b")))
        self.assertEqual([b.name for b in self.m.all()], ["a", "b"])

    def test_happy_add_at_an_index_inserts_there_and_persists(self) -> None:
        self.m.add(Bookmark("a", "/a"))
        self.m.add(Bookmark("c", "/c"))
        self.assertTrue(self.m.add(Bookmark("b", "/b"), index=1))
        self.assertEqual([b.name for b in BookmarkManager().all()], ["a", "b", "c"])

    def test_happy_add_at_an_index_inside_a_group(self) -> None:
        group = self.m.add_group("G")
        self.m.add(Bookmark("x", "/x"), group=group)
        self.m.add(Bookmark("w", "/w"), group=group, index=0)
        self.assertEqual([b.name for b in group.children], ["w", "x"])

    def test_sad_a_duplicate_is_skipped_and_reported_false(self) -> None:
        self.m.add(Bookmark("a", "/a"))
        self.assertFalse(self.m.add(Bookmark("again", "/a")))
        self.assertEqual(len(self.m.all()), 1)

    def test_edge_the_same_path_on_another_backend_is_no_duplicate(self) -> None:
        self.m.add(Bookmark("a", "/a"))
        self.assertTrue(self.m.add(Bookmark("a", "/a", backend_name="u@h", profile_name="h")))

    def test_edge_an_out_of_range_index_is_clamped(self) -> None:
        self.m.add(Bookmark("a", "/a"))
        self.m.add(Bookmark("z", "/z"), index=99)
        self.m.add(Bookmark("first", "/f"), index=-5)
        self.assertEqual([b.name for b in self.m.all()], ["first", "a", "z"])


class _Qt(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


class PayloadTest(_Qt):
    """The drag payload names the dragged folders, taken from the listing."""

    def mime(self, raw: bytes):
        from PyQt6.QtCore import QMimeData

        from ui.file_pane import TRANSFER_MIME_TYPE

        mime = QMimeData()
        mime.setData(TRANSFER_MIME_TYPE, raw)
        return mime

    def test_happy_dirs_round_trip(self) -> None:
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget, decode_transfer_payload

        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        raw = pane._encode_transfer_payload(["/x/dir", "/x/f.txt"], dirs=["/x/dir"])
        payload = decode_transfer_payload(self.mime(raw))
        self.assertEqual(payload["paths"], ["/x/dir", "/x/f.txt"])
        self.assertEqual(payload["dirs"], ["/x/dir"])
        self.assertEqual(payload["source_pane_id"], str(id(pane)))

    def test_sad_dirs_that_are_not_dragged_paths_are_dropped(self) -> None:
        from ui.file_pane import decode_transfer_payload

        raw = json.dumps(
            {"paths": ["/a"], "source_pane_id": "1", "dirs": ["/a", "/etc", 5]}
        ).encode()
        self.assertEqual(decode_transfer_payload(self.mime(raw))["dirs"], ["/a"])

    def test_sad_a_malformed_dirs_field_means_no_folders(self) -> None:
        from ui.file_pane import decode_transfer_payload

        raw = json.dumps({"paths": ["/a"], "source_pane_id": "1", "dirs": "/a"}).encode()
        self.assertEqual(decode_transfer_payload(self.mime(raw))["dirs"], [])

    def test_edge_a_payload_without_dirs_still_decodes(self) -> None:
        from ui.file_pane import FilePaneWidget, decode_transfer_payload

        raw = json.dumps({"paths": ["/a"], "source_pane_id": "1"}).encode()
        payload = decode_transfer_payload(self.mime(raw))
        self.assertEqual(payload["dirs"], [])
        # The pane's own static decoder is the same function.
        self.assertEqual(FilePaneWidget._decode_transfer_payload(self.mime(raw)), payload)

    def test_sad_garbage_decodes_to_none(self) -> None:
        from ui.file_pane import decode_transfer_payload

        for raw in (b"\xff\xfe", b"not json", b"[1, 2]", b'{"paths": "x"}'):
            self.assertIsNone(decode_transfer_payload(self.mime(raw)), raw)

    def test_happy_a_drag_from_the_pane_marks_its_folders(self) -> None:
        import time

        from PyQt6.QtCore import QItemSelectionModel, Qt

        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget, decode_transfer_payload

        tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "dir").mkdir()
        (tmp / "f.txt").write_text("x")
        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        pane.navigate(str(tmp))
        proxy = pane._table.model()
        end = time.time() + 10
        while proxy.rowCount() < 2 and time.time() < end:
            self.app.processEvents()
        sel = pane._table.selectionModel()
        for row in range(proxy.rowCount()):
            if proxy.index(row, 0).data() in ("dir", "f.txt"):
                sel.select(
                    proxy.index(row, 0),
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )
        seen = []

        def fake_exec(drag, *_a):
            seen.append(decode_transfer_payload(drag.mimeData()))
            return Qt.DropAction.IgnoreAction

        with mock.patch("ui.file_pane.QDrag.exec", fake_exec):
            pane._start_drag()
        self.assertEqual(sorted(seen[0]["paths"]), [str(tmp / "dir"), str(tmp / "f.txt")])
        self.assertEqual(seen[0]["dirs"], [str(tmp / "dir")])


class _Sidebar(_Qt, _Store):
    def setUp(self) -> None:
        _Store.setUp(self)
        self.work = self.m.add_group("Work")
        self.m.add(Bookmark("logs", "/var/log"), group=self.work)
        self.m.add(Bookmark("home", "/home"))
        self.m.add(Bookmark("tmp", "/tmp"))
        from ui.bookmark_sidebar import BookmarkSidebar

        self.side = BookmarkSidebar(self.m)
        self.addCleanup(self.side.deleteLater)
        self.side.resize(300, 500)
        self.side.show()
        self.app.processEvents()
        self.tree = self.side._tree
        self.bookmark_drops: list = []
        self.transfer_drops: list = []
        self.side.bookmark_drop_requested.connect(lambda *a: self.bookmark_drops.append(a))
        self.side.transfer_drop_requested.connect(lambda *a: self.transfer_drops.append(a))

    # -- helpers -------------------------------------------------------------
    def item(self, name: str):
        from PyQt6.QtWidgets import QTreeWidgetItemIterator

        it = QTreeWidgetItemIterator(self.tree)
        while it.value():
            if it.value().text(0) == name:
                return it.value()
            it += 1
        self.fail(f"no item {name!r}")

    def node(self, name: str):
        return self.item(name).data(0, __import__("PyQt6.QtCore").QtCore.Qt.ItemDataRole.UserRole)

    def at(self, name: str | None, where: str = "onto"):
        from PyQt6.QtCore import QPoint

        if name is None:
            return QPoint(10, self.tree.viewport().height() - 3)
        rect = self.tree.visualItemRect(self.item(name))
        x = rect.center().x()
        if where == "above":
            return QPoint(x, rect.top() + 1)
        if where == "below":
            return QPoint(x, rect.bottom() - 1)
        return rect.center()

    def transfer_mime(self, paths, dirs=(), source="4242"):
        from PyQt6.QtCore import QMimeData

        from ui.file_pane import TRANSFER_MIME_TYPE

        mime = QMimeData()
        raw = json.dumps(
            {"paths": list(paths), "source_pane_id": source, "dirs": list(dirs)}
        ).encode()
        mime.setData(TRANSFER_MIME_TYPE, raw)
        return mime

    def deliver(self, widget, mime, pos, *, ctrl: bool = False) -> tuple[bool, bool]:
        """dragEnter, dragMove and (when accepted) drop at *pos*.
        Returns (move accepted, drop accepted)."""
        from PyQt6.QtCore import QPointF, Qt
        from PyQt6.QtGui import QDragEnterEvent, QDragMoveEvent, QDropEvent

        mods = Qt.KeyboardModifier.ControlModifier if ctrl else Qt.KeyboardModifier.NoModifier
        actions = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
        enter = QDragEnterEvent(pos, actions, mime, Qt.MouseButton.LeftButton, mods)
        widget.dragEnterEvent(enter)
        move = QDragMoveEvent(pos, actions, mime, Qt.MouseButton.LeftButton, mods)
        widget.dragMoveEvent(move)
        drop = QDropEvent(QPointF(pos), actions, mime, Qt.MouseButton.LeftButton, mods)
        drop.setDropAction(move.dropAction())
        widget.dropEvent(drop)
        for _ in range(3):
            self.app.processEvents()
        return move.isAccepted(), drop.isAccepted()


class SidebarBookmarkDropTest(_Sidebar):
    def test_happy_folders_dropped_on_empty_space_are_bookmarked_at_the_end(self) -> None:
        mime = self.transfer_mime(["/srv/a", "/srv/f.txt"], dirs=["/srv/a"])
        self.assertEqual(self.deliver(self.tree, mime, self.at(None)), (True, True))
        self.assertEqual(self.bookmark_drops, [(["/srv/a"], "4242", None, None)])
        self.assertEqual(self.transfer_drops, [])

    def test_happy_folders_dropped_onto_a_group_go_into_it(self) -> None:
        mime = self.transfer_mime(["/srv/a"], dirs=["/srv/a"])
        self.deliver(self.tree, mime, self.at("Work"))
        self.assertEqual(len(self.bookmark_drops), 1)
        paths, source, group, index = self.bookmark_drops[0]
        self.assertIs(group, self.work)
        self.assertIsNone(index)

    def test_edge_folders_dropped_between_entries_land_at_that_position(self) -> None:
        mime = self.transfer_mime(["/srv/a"], dirs=["/srv/a"])
        self.deliver(self.tree, mime, self.at("home", "above"))
        self.deliver(self.tree, mime, self.at("home", "below"))
        self.deliver(self.tree, mime, self.at("logs", "below"))
        self.assertEqual(
            [(g, i) for _p, _s, g, i in self.bookmark_drops],
            [(None, 1), (None, 2), (self.work, 1)],
        )

    def test_sad_only_files_on_empty_space_are_refused(self) -> None:
        mime = self.transfer_mime(["/srv/f.txt"], dirs=[])
        self.assertEqual(self.deliver(self.tree, mime, self.at(None)), (False, False))
        self.assertEqual(self.bookmark_drops, [])

    def test_edge_the_empty_state_hint_accepts_folder_drops(self) -> None:
        for _d, g in list(self.m.groups()):
            self.m.remove_group(g)
        while self.m.all():
            self.m.remove(0)
        self.side.rebuild()
        self.assertTrue(self.side._hint.isVisible())
        from PyQt6.QtCore import QPoint

        mime = self.transfer_mime(["/srv/a"], dirs=["/srv/a"])
        self.assertEqual(self.deliver(self.side._hint, mime, QPoint(5, 5)), (True, True))
        self.assertEqual(self.bookmark_drops, [(["/srv/a"], "4242", None, None)])
        files = self.transfer_mime(["/srv/f.txt"])
        self.assertEqual(self.deliver(self.side._hint, files, QPoint(5, 5)), (False, False))


class SidebarTransferDropTest(_Sidebar):
    def test_happy_a_plain_drop_onto_a_bookmark_requests_a_move(self) -> None:
        mime = self.transfer_mime(["/srv/f.txt"])
        self.assertEqual(self.deliver(self.tree, mime, self.at("home")), (True, True))
        self.assertEqual(len(self.transfer_drops), 1)
        paths, source, bookmark, is_move = self.transfer_drops[0]
        self.assertEqual((paths, source, is_move), (["/srv/f.txt"], "4242", True))
        self.assertIs(bookmark, self.node("home"))

    def test_happy_ctrl_requests_a_copy(self) -> None:
        mime = self.transfer_mime(["/srv/f.txt", "/srv/d"], dirs=["/srv/d"])
        self.deliver(self.tree, mime, self.at("logs"), ctrl=True)
        self.assertEqual(self.transfer_drops[0][3], False)
        self.assertEqual(self.transfer_drops[0][0], ["/srv/f.txt", "/srv/d"])
        self.assertEqual(self.bookmark_drops, [])

    def test_edge_files_near_the_edge_of_a_bookmark_still_go_into_it(self) -> None:
        mime = self.transfer_mime(["/srv/f.txt"])
        self.deliver(self.tree, mime, self.at("home", "above"))
        self.assertEqual(len(self.transfer_drops), 1)
        self.assertIs(self.transfer_drops[0][2], self.node("home"))

    def test_edge_the_drop_handler_touches_no_filesystem(self) -> None:
        """The sidebar must not stat or list anything: a dead mount or a
        remote path would freeze the window."""
        mime = self.transfer_mime(["/srv/f.txt", "/srv/d"], dirs=["/srv/d"])
        boom = mock.Mock(side_effect=AssertionError("filesystem touched"))
        with (
            mock.patch("os.stat", boom),
            mock.patch("os.scandir", boom),
            mock.patch("os.path.exists", boom),
            mock.patch("os.path.isdir", boom),
        ):
            self.deliver(self.tree, mime, self.at("home"))
            self.deliver(self.tree, mime, self.at(None))
        boom.assert_not_called()
        self.assertEqual(len(self.transfer_drops), 1)
        self.assertEqual(len(self.bookmark_drops), 1)


class SidebarDropMarkerTest(_Sidebar):
    def move_only(self, mime, pos) -> bool:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QDragMoveEvent

        acts = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
        move = QDragMoveEvent(
            pos, acts, mime, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier
        )
        self.tree.dragMoveEvent(move)
        return move.isAccepted()

    def test_happy_the_marker_follows_the_target_and_paints(self) -> None:
        mime = self.transfer_mime(["/srv/a"], dirs=["/srv/a"])
        self.assertTrue(self.move_only(mime, self.at("home")))
        self.assertEqual(self.tree._drop_marker[1], "onto")
        self.assertFalse(self.tree.viewport().grab().isNull())  # paintEvent with a marker
        self.move_only(mime, self.at("home", "above"))
        self.assertEqual(self.tree._drop_marker[1], "above")
        self.move_only(mime, self.at(None))
        self.assertEqual(self.tree._drop_marker[1], "end")
        self.assertFalse(self.tree.viewport().grab().isNull())

    def test_sad_a_refused_position_clears_the_marker(self) -> None:
        self.move_only(self.transfer_mime(["/srv/a"], dirs=["/srv/a"]), self.at("home"))
        self.assertFalse(self.move_only(self.transfer_mime(["/srv/f.txt"]), self.at(None)))
        self.assertIsNone(self.tree._drop_marker)

    def test_edge_leaving_the_tree_clears_the_marker(self) -> None:
        from PyQt6.QtGui import QDragLeaveEvent

        self.move_only(self.transfer_mime(["/srv/a"], dirs=["/srv/a"]), self.at("home"))
        self.tree.dragLeaveEvent(QDragLeaveEvent())
        self.assertIsNone(self.tree._drop_marker)


class SidebarForeignPayloadTest(_Sidebar):
    def foreign(self, kind: str):
        from PyQt6.QtCore import QMimeData, QUrl

        from ui.file_pane import TRANSFER_MIME_TYPE

        mime = QMimeData()
        if kind == "text":
            mime.setText("/etc/passwd")
        elif kind == "urls":
            mime.setUrls([QUrl.fromLocalFile("/etc"), QUrl("https://example.org/x")])
        elif kind == "garbage":
            mime.setData(TRANSFER_MIME_TYPE, b"\x00\xffnot-json")
        elif kind == "wrong-shape":
            mime.setData(TRANSFER_MIME_TYPE, b'{"paths": [1, 2], "source_pane_id": 3}')
        return mime

    def test_sad_foreign_and_malformed_payloads_are_ignored_everywhere(self) -> None:
        # A selected bookmark must not be moved by a foreign drop either.
        self.tree.setCurrentItem(self.item("tmp"))
        before = [n.name for n in self.m.tree()]
        for kind in ("text", "urls", "garbage", "wrong-shape"):
            for name in ("home", "Work", None):
                with self.subTest(kind=kind, at=name):
                    accepted = self.deliver(self.tree, self.foreign(kind), self.at(name))
                    self.assertEqual(accepted, (False, False))
        self.assertEqual(self.bookmark_drops, [])
        self.assertEqual(self.transfer_drops, [])
        self.assertEqual([n.name for n in self.m.tree()], before)

    def test_sad_the_hint_ignores_foreign_payloads(self) -> None:
        from PyQt6.QtCore import QPoint

        for kind in ("text", "urls", "garbage"):
            self.assertEqual(
                self.deliver(self.side._hint, self.foreign(kind), QPoint(3, 3)), (False, False)
            )
        self.assertEqual(self.bookmark_drops, [])


class SidebarReorderStillWorksTest(_Sidebar):
    def test_happy_an_internal_drag_still_reorders(self) -> None:
        from PyQt6.QtCore import QEvent, QPointF, Qt
        from PyQt6.QtGui import QDragMoveEvent, QDropEvent

        home_item = self.item("home")
        mime = self.tree.mimeData([home_item])
        target = self.tree.visualItemRect(self.item("Work")).center()
        self.tree.setCurrentItem(home_item)
        move = QDragMoveEvent(
            target,
            Qt.DropAction.MoveAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
            QEvent.Type.DragMove,
        )
        self.tree.dragMoveEvent(move)
        drop = QDropEvent(
            QPointF(target),
            Qt.DropAction.MoveAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
        self.tree.dropEvent(drop)
        self.app.processEvents()
        self.assertIn("home", [n.name for n in self.work.children])
        self.assertEqual(self.bookmark_drops, [])
        self.assertEqual(self.transfer_drops, [])


class SidebarLifetimeTest(unittest.TestCase):
    """The drop is handed over on the next event-loop turn; a sidebar that
    is destroyed in between must not raise inside Qt (without main.py's
    excepthook, as here, that aborts the process; with it, the user gets an
    error dialog)."""

    def test_edge_sidebar_deleted_before_the_deferred_drop_fires(self) -> None:
        self.assertIn("SURVIVED 0", self._run("external"))

    def test_edge_sidebar_deleted_before_a_deferred_reorder_fires(self) -> None:
        """Same for the tree's own reordering drop (it used a bare
        ``QTimer.singleShot`` lambda, which raised and aborted)."""
        self.assertIn("SURVIVED 0", self._run("internal"))

    def _run(self, mode: str) -> str:
        script = textwrap.dedent(
            """
            import json, os, sys, tempfile
            from pathlib import Path
            os.environ["QT_QPA_PLATFORM"] = "offscreen"
            sys.path.insert(0, %r)
            import core.bookmarks as BM
            BM.BOOKMARKS_FILE = Path(tempfile.mkdtemp()) / "b.json"
            from PyQt6 import sip
            from PyQt6.QtCore import QMimeData, QPoint, QPointF, Qt
            from PyQt6.QtGui import QDragMoveEvent, QDropEvent
            from PyQt6.QtWidgets import QApplication
            app = QApplication([])
            from core.bookmarks import Bookmark, BookmarkManager
            from ui.bookmark_sidebar import BookmarkSidebar
            from ui.file_pane import TRANSFER_MIME_TYPE
            m = BookmarkManager()
            m.add(Bookmark("home", "/home"))
            m.add(Bookmark("tmp", "/tmp"))
            side = BookmarkSidebar(m)
            side.resize(300, 400); side.show(); app.processEvents()
            got = []
            mode = %r
            side.transfer_drop_requested.connect(lambda *a: got.append(a))
            side.changed.connect(lambda: got.append("changed"))
            tree = side._tree
            pos = tree.visualItemRect(tree.topLevelItem(0)).center()
            if mode == "internal":
                dragged = tree.topLevelItem(1)
                tree.setCurrentItem(dragged)
                mime = tree.mimeData([dragged])
            else:
                mime = QMimeData()
                mime.setData(TRANSFER_MIME_TYPE, json.dumps(
                    {"paths": ["/x"], "source_pane_id": "1", "dirs": []}).encode())
            acts = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
            mv = QDragMoveEvent(pos, acts, mime, Qt.MouseButton.LeftButton,
                                Qt.KeyboardModifier.NoModifier)
            tree.dragMoveEvent(mv)
            drop = QDropEvent(QPointF(pos), acts, mime, Qt.MouseButton.LeftButton,
                              Qt.KeyboardModifier.NoModifier)
            tree.dropEvent(drop)
            sip.delete(side)
            for _ in range(5):
                app.processEvents()
            print("SURVIVED", len(got))
            """
            % (str(_REPO), mode)
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=120,
            env=dict(os.environ),
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        return result.stdout


if __name__ == "__main__":
    unittest.main()
