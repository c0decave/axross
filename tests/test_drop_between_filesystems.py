"""A drop between two filesystems is never "onto itself".

Reproduced 2026-10-17: a folder /srv/x/proj dragged from a RAM (remote)
pane onto the folder /srv/x/proj of a local pane was refused - the drop
target compared the remote path with the local one as if both lived on one
filesystem, and the same path string looked like "a folder into itself".
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _Ev:
    """The parts of a QDropEvent FilePaneWidget.dropEvent reads."""

    def __init__(self, mime) -> None:
        self._mime = mime
        self.accepted: bool | None = None

    def mimeData(self):  # noqa: N802 - Qt API
        return self._mime

    def modifiers(self):
        from PyQt6.QtCore import Qt

        return Qt.KeyboardModifier.ControlModifier  # Ctrl: copy

    def position(self):
        from PyQt6.QtCore import QPointF

        return QPointF(1, 1)

    def accept(self) -> None:
        self.accepted = True

    def ignore(self) -> None:
        self.accepted = False

    def setDropAction(self, _action) -> None:  # noqa: N802 - Qt API
        pass

    def acceptProposedAction(self) -> None:  # noqa: N802 - Qt API
        self.accepted = True


class DropBetweenFilesystemsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.local_fs import LocalFS
        from core.ram_fs import RamFsSession
        from ui.file_pane import FilePaneWidget

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "proj" / "sub").mkdir(parents=True)
        self.work = str(self.tmp)
        self.proj = str(self.tmp / "proj")
        self.local = FilePaneWidget(LocalFS())
        self.addCleanup(self.local.deleteLater)
        self.local.navigate(self.work)
        self.ram = RamFsSession()
        self.ram.mkdir(self.proj, parents=True)  # same path string, other filesystem
        self.remote = FilePaneWidget(self.ram)
        self.addCleanup(self.remote.deleteLater)
        self.remote.navigate(self.work)
        self.emitted: list = []
        self.local.drop_transfer_requested.connect(lambda *a: self.emitted.append(a))

    def payload(self, pane, *paths) -> dict:
        from ui.file_pane import decode_transfer_payload

        return decode_transfer_payload(self.mime(pane._encode_transfer_payload(list(paths))))

    @staticmethod
    def mime(raw: bytes):
        from PyQt6.QtCore import QMimeData

        from ui.file_pane import TRANSFER_MIME_TYPE

        mime = QMimeData()
        mime.setData(TRANSFER_MIME_TYPE, raw)
        return mime

    # -- happy -----------------------------------------------------------------

    def test_happy_a_remote_folder_drops_onto_the_local_folder_with_the_same_path(self) -> None:
        event = _Ev(self.mime(self.remote._encode_transfer_payload([self.proj])))
        self.local.dropEvent(event, self.proj)
        self.assertTrue(event.accepted)
        self.assertEqual(len(self.emitted), 1)
        paths, target, source_id, is_move, dest = self.emitted[0]
        self.assertEqual((paths, target, source_id, is_move, dest),
                         ([self.proj], self.local, str(id(self.remote)), False, self.proj))

    def test_happy_a_remote_file_drops_into_the_local_folder_it_has_the_name_of(self) -> None:
        inside = self.proj + "/sub"
        self.assertEqual(
            self.local._drop_target(self.payload(self.remote, self.proj), inside), inside
        )

    # -- sad -------------------------------------------------------------------

    def test_sad_on_one_filesystem_a_folder_onto_or_into_itself_is_still_refused(self) -> None:
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        other_local = FilePaneWidget(LocalFS())  # another pane, another LocalFS, same disk
        self.addCleanup(other_local.deleteLater)
        payload = self.payload(other_local, self.proj)
        self.assertIsNone(self.local._drop_target(payload, self.proj))
        self.assertIsNone(self.local._drop_target(payload, self.proj + "/sub"))
        event = _Ev(self.mime(other_local._encode_transfer_payload([self.proj])))
        self.local.dropEvent(event, self.proj)
        self.assertFalse(event.accepted)
        self.assertEqual(self.emitted, [])

    def test_sad_a_payload_that_does_not_name_its_filesystem_keeps_the_guard(self) -> None:
        raw = json.dumps({"paths": [self.proj], "source_pane_id": "1"}).encode()
        from ui.file_pane import decode_transfer_payload

        payload = decode_transfer_payload(self.mime(raw))
        self.assertIsNone(self.local._drop_target(payload, self.proj))

    # -- edge ------------------------------------------------------------------

    def test_edge_the_payload_names_the_filesystem_of_its_pane(self) -> None:
        self.assertEqual(self.payload(self.local, "/a")["filesystem"], "Local")
        self.assertEqual(self.payload(self.remote, "/a")["filesystem"], "remote:RAM:ramfs")
        raw = json.dumps({"paths": ["/a"], "source_pane_id": "1", "filesystem": 5}).encode()
        from ui.file_pane import decode_transfer_payload

        self.assertIsNone(decode_transfer_payload(self.mime(raw))["filesystem"])

    def test_edge_a_remote_backend_named_local_is_not_the_local_disk(self) -> None:
        from core.ram_fs import RamFsSession
        from ui.file_pane import FilePaneWidget, filesystem_key

        class NamedLocal(RamFsSession):
            @property
            def name(self) -> str:
                return "Local"

        impostor = FilePaneWidget(NamedLocal())
        self.addCleanup(impostor.deleteLater)
        self.assertNotEqual(filesystem_key(impostor.backend), filesystem_key(self.local.backend))
        self.assertEqual(
            self.local._drop_target(self.payload(impostor, self.proj), self.proj), self.proj
        )

    def test_edge_two_panes_on_one_remote_filesystem_keep_the_guard(self) -> None:
        from ui.file_pane import FilePaneWidget

        second = FilePaneWidget(self.ram)
        self.addCleanup(second.deleteLater)
        self.assertIsNone(second._drop_target(self.payload(self.remote, self.proj), self.proj))


if __name__ == "__main__":
    unittest.main()
