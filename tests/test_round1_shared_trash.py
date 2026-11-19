"""The trash of a share (S3, SMB, WebDAV, FTP ...) is said to be one.

Measured before: Move to Trash on such a connection asked only "Move 1 item
to the trash?" - the file then went to <share root>/.axross-trash, under the
root's permissions, though it may have been in a folder only its owner may
open (the private 0700 trash holds for this machine's disk and SFTP only).
Remove Metadata in place put the original - with all its metadata - there
without a word. Both now name the folder, say that the file has that
folder's permissions there, and offer the alternative (Delete Permanently;
a cleaned copy instead)."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Share(RamFsSession):
    """A connection whose trash is a folder of a share (as S3, SMB, WebDAV)."""

    trash_is_private = False


def _pump(predicate, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_happy_which_trash_is_private():
    assert T.trash_is_private(LocalFS())
    assert T.trash_is_private(RamFsSession())
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    assert T.trash_is_private(SSHSession(ConnectionProfile(name="t", protocol="sftp",
                                                           host="h", username="u")))
    assert not T.trash_is_private(_Share())
    assert T.shared_trash_folder(LocalFS()) is None
    assert T.shared_trash_folder(_Share()) == "/" + T.TRASH_DIRNAME


def _click(label: str, seen: list):
    def fake_exec(box):
        seen.append(box.text())
        for button in box.buttons():
            if button.text().replace("&", "") == label:
                button.click()
                return 0
        raise AssertionError(f"no button {label!r} in {[b.text() for b in box.buttons()]}")

    return fake_exec


def _pane_with_file():
    from ui.file_pane import FilePaneWidget

    share = _Share()
    share.mkdir("/team")
    share.mkdir("/team/private")
    with share.open_write("/team/private/plan.txt") as fh:
        fh.write(b"plan")
    pane = FilePaneWidget(share)
    pane.navigate("/team/private")
    assert _pump(lambda: not pane.is_loading and pane.current_path == "/team/private")
    from PyQt6.QtCore import QItemSelectionModel

    model, selection = pane._proxy, pane._table.selectionModel()
    for row in range(model.rowCount()):
        if model.data(model.index(row, 0)) == "plan.txt":
            selection.select(model.index(row, 0), QItemSelectionModel.SelectionFlag.Select
                             | QItemSelectionModel.SelectionFlag.Rows)
    return pane, share


@pytest.mark.parametrize("choice", ["Move to Trash", "Delete Permanently"])
def test_sad_move_to_trash_on_a_share_names_the_folder_and_offers_delete(choice):
    pane, share = _pane_with_file()
    seen: list = []
    try:
        with mock.patch.object(QMessageBox, "exec", _click(choice, seen)), \
                mock.patch("ui.file_pane.QMessageBox.question",
                           return_value=QMessageBox.StandardButton.Yes) as question, \
                mock.patch("ui.file_pane.QMessageBox.warning",
                           return_value=QMessageBox.StandardButton.Yes):
            pane._trash_selected()
            assert _pump(lambda: not pane.removal_running and seen)
            _pump(lambda: not pane.removal_running)
        assert seen and "/" + T.TRASH_DIRNAME in seen[0]
        assert "permissions" in seen[0] and "Delete Permanently" in seen[0]
        assert not share.exists("/team/private/plan.txt")
        trashed = [e.original_path for e in T.list_trash(share)]
        if choice == "Move to Trash":
            assert trashed == ["/team/private/plan.txt"]
        else:
            assert trashed == []
            # Delete Permanently asks its own question (default No) first.
            assert question.called
    finally:
        pane.close()
        pane.deleteLater()


def test_happy_move_to_trash_on_this_disk_asks_as_before(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "home").mkdir()
    (tmp_path / "a.txt").write_text("a")
    backend = LocalFS()
    backend.home = lambda: str(tmp_path / "home")
    pane = FilePaneWidget(backend)
    pane.navigate(str(tmp_path))
    try:
        assert _pump(lambda: not pane.is_loading)
        from PyQt6.QtCore import QItemSelectionModel

        model, selection = pane._proxy, pane._table.selectionModel()
        for row in range(model.rowCount()):
            if model.data(model.index(row, 0)) == "a.txt":
                selection.select(model.index(row, 0), QItemSelectionModel.SelectionFlag.Select
                                 | QItemSelectionModel.SelectionFlag.Rows)
        with mock.patch.object(QMessageBox, "exec",
                               side_effect=AssertionError("no extra question")), \
                mock.patch("ui.file_pane.QMessageBox.question",
                           return_value=QMessageBox.StandardButton.Yes):
            pane._trash_selected()
            assert _pump(lambda: not pane.removal_running and not (tmp_path / "a.txt").exists())
    finally:
        pane.close()
        pane.deleteLater()


@pytest.mark.parametrize("choice", ["Keep Originals in the Trash", "Cleaned Copies Instead"])
def test_sad_remove_metadata_in_place_on_a_share_says_where_the_original_goes(choice, tmp_path,
                                                                             monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import metadata_testkit as K

    from core import metadata_tools as MT
    from ui import metadata_dialog as MD

    monkeypatch.setattr(MT, "write_mode", lambda: MT.MODE_IN_PLACE)
    monkeypatch.setattr(MT, "confirm_before_remove", lambda: False)
    share = _Share()
    share.mkdir("/team")
    with share.open_write("/team/photo.jpg") as fh:
        fh.write(K.jpeg_bytes())
    seen: list = []
    with mock.patch.object(QMessageBox, "exec", _click(choice, seen)):
        mode = MD._ask_to_remove(None, 1, share)
    assert seen and "/" + T.TRASH_DIRNAME in seen[0] and "permissions" in seen[0]
    assert mode == (MT.MODE_IN_PLACE if choice.startswith("Keep") else MT.MODE_COPY)
    with mock.patch.object(QMessageBox, "exec", side_effect=AssertionError("asked")):
        assert MD._ask_to_remove(None, 1, LocalFS()) == MT.MODE_IN_PLACE


def test_sad_the_duplicate_finder_says_a_share_s_trash_is_shared(tmp_path, monkeypatch):
    """Measured before: Move Selected to Trash in the Duplicate Finder said
    "Move 1 file(s) ... to the axross trash?" on a share as on this disk.
    It now adds where that trash is and that the files have its permissions
    there (it never deletes permanently: no other choice is offered)."""
    from core import cas as CAS
    from ui import cas_dialog as CD

    class _ShareFS(LocalFS):
        trash_is_private = False

    monkeypatch.setattr(CAS, "_DEFAULT_DB", tmp_path / "cas.sqlite")
    tree = tmp_path / "tree"
    tree.mkdir()
    for name in ("a.txt", "b.txt"):
        (tree / name).write_text("same content")
    fs = _ShareFS()
    fs.home = lambda: str(tmp_path)
    CAS.rebuild(fs, str(tree), backend_id=CAS.backend_id_for(fs))

    class _Pane:
        backend = fs
        current_path = str(tree)

    dialog = CD.CasDuplicatesDialog(_Pane())
    try:
        assert _pump(lambda: dialog._tree.topLevelItemCount() > 0)
        group = dialog._tree.topLevelItem(0)
        group.child(group.childCount() - 1).setSelected(True)
        with mock.patch("ui.cas_dialog.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.No) as question:
            dialog._delete_selected()
        text = question.call_args[0][2]
        assert T.TRASH_DIRNAME in text and "permissions" in text, text
    finally:
        dialog.deleteLater()
