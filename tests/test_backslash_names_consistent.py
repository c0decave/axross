"""A backslash is an ordinary character of a local name on POSIX: a copy
keeps "a\\b" (core.path_policy.transfer_leaf), and now Rename, New Folder,
New File and Batch Rename take it too - they refused it. A backend that
may hand the name to a server splitting on it still refuses it, as the
transfers do."""
from __future__ import annotations

import os
import sys
from unittest import mock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets")
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX names")

from PyQt6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.path_policy import transfer_leaf  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _Remote:
    """A backend without literal backslashes (an SFTP or SMB session)."""

    def separator(self):
        return "/"


def test_happy_the_rules_agree_with_the_transfers(tmp_path):
    from ui.batch_rename_dialog import _validate_new_name
    from ui.file_pane import _is_safe_leaf_name

    fs = LocalFS()
    assert transfer_leaf(fs, fs, "a\\b") == "a\\b"
    assert _is_safe_leaf_name("a\\b", fs)
    _validate_new_name("a\\b", fs)
    with pytest.raises(ValueError):
        transfer_leaf(fs, _Remote(), "a\\b")
    assert not _is_safe_leaf_name("a\\b", _Remote())
    with pytest.raises(ValueError):
        _validate_new_name("a\\b", _Remote())
    for bad in ("..", "a/b", "x\x00y"):
        assert not _is_safe_leaf_name(bad, fs)


def test_happy_new_folder_and_rename_take_a_backslash(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "plain.txt").write_text("x")
    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    warned = []
    try:
        with mock.patch.object(QInputDialog, "getText", return_value=("dir\\one", True)), \
                mock.patch.object(QMessageBox, "warning", lambda *a: warned.append(a)):
            pane._create_folder()
            _wait(lambda: (tmp_path / "dir\\one").is_dir())
    finally:
        pane.shutdown()
        pane.deleteLater()
    pane = FilePaneWidget(LocalFS())  # one operation at a time per pane
    pane.navigate(str(tmp_path))
    try:
        item = FileItem(name="plain.txt", size=1)
        with mock.patch.object(pane, "selected_file_items", return_value=[item]), \
                mock.patch.object(QInputDialog, "getText", return_value=("pl\\ain.txt", True)), \
                mock.patch.object(QMessageBox, "critical", lambda *a: warned.append(a)), \
                mock.patch.object(QMessageBox, "warning", lambda *a: warned.append(a)):
            pane._rename_selected()
            _wait(lambda: (tmp_path / "pl\\ain.txt").exists())
    finally:
        pane.shutdown()
        pane.deleteLater()
    assert not warned, [w[2] for w in warned]
    assert (tmp_path / "dir\\one").is_dir() and (tmp_path / "pl\\ain.txt").exists()


def _wait(cond, timeout=10.0):
    import time

    end = time.monotonic() + timeout
    while time.monotonic() < end and not cond():
        APP.processEvents()
        time.sleep(0.02)
