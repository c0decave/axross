"""An editor whose file could not be read must not open at all.

Found in review: ``_load_file`` reported the error and called
``reject()`` from inside ``__init__`` - but the caller's ``exec()`` came
after that and showed the dialog anyway, with an empty buffer. Typing
and pressing Save then wrote over a file nobody had seen (the conflict
check could not read it either and "proceeded").
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])

skip_as_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root reads mode-000 files"
)


class _FailingReadFS(LocalFS):
    """open_read fails for chosen paths, as a dropped link or EACCES would."""

    def __init__(self, failing: set[str]) -> None:
        super().__init__()
        self.failing = failing

    def open_read(self, path):
        if path in self.failing:
            raise PermissionError(13, "Permission denied", path)
        return super().open_read(path)


def _exec_with_watchdog(dlg) -> tuple[int, bool]:
    """Run ``dlg.exec()``; a watchdog closes it if it really opens.

    Returns ``(result, was_shown)``."""
    seen = {"shown": False}

    def watchdog():
        if dlg.isVisible():
            seen["shown"] = True
            dlg._modified = False
            if hasattr(dlg, "_hex_widget"):
                dlg._hex_widget._modified_offsets.clear()
            dlg.done(0)

    # Parented to the dialog, so the timer dies with it when exec()
    # returns at once and the dialog is deleted before the timeout.
    timer = QTimer(dlg)
    timer.setSingleShot(True)
    timer.timeout.connect(watchdog)
    timer.start(200)
    result = dlg.exec()
    timer.stop()
    APP.processEvents()
    return result, seen["shown"]


# -- text editor ----------------------------------------------------------


def test_sad_an_unreadable_file_does_not_open_an_empty_editor(tmp_path):
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "secret.txt"
    path.write_bytes(b"original\n")
    fs = _FailingReadFS({str(path)})
    with mock.patch("ui.text_editor.QMessageBox.critical") as critical:
        dlg = TextEditorDialog(fs, str(path))
        result, shown = _exec_with_watchdog(dlg)
    critical.assert_called_once()
    assert not shown
    assert not result
    dlg.deleteLater()


def test_sad_a_save_without_a_successful_load_writes_nothing(tmp_path):
    """Defence in depth: even a caller that shows the dialog anyway
    cannot write a buffer that never held the file."""
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "secret.txt"
    path.write_bytes(b"original\n")
    fs = _FailingReadFS({str(path)})
    with mock.patch("ui.text_editor.QMessageBox.critical"):
        dlg = TextEditorDialog(fs, str(path))
    dlg._editor.insertPlainText("typed over it")
    with mock.patch("ui.text_editor.QMessageBox.critical"), mock.patch(
        "ui.text_editor.QMessageBox.warning"
    ) as warning:
        dlg._save_file()
    warning.assert_called_once()
    assert path.read_bytes() == b"original\n"
    dlg._modified = False
    dlg.deleteLater()


@skip_as_root
def test_edge_a_write_only_local_file_is_not_overwritten_blind(tmp_path):
    """The real-world shape: mode 0200, readable by nobody."""
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "wo.txt"
    path.write_bytes(b"original\n")
    path.chmod(0o200)
    try:
        with mock.patch("ui.text_editor.QMessageBox.critical"):
            dlg = TextEditorDialog(LocalFS(), str(path))
            _result, shown = _exec_with_watchdog(dlg)
        assert not shown
        dlg._editor.insertPlainText("typed")
        with mock.patch("ui.text_editor.QMessageBox.warning"):
            dlg._save_file()
    finally:
        path.chmod(0o600)
    assert path.read_bytes() == b"original\n"
    dlg._modified = False
    dlg.deleteLater()


def test_happy_a_readable_file_still_opens_and_saves(tmp_path):
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "ok.txt"
    path.write_bytes(b"one\n")
    dlg = TextEditorDialog(LocalFS(), str(path))
    result, shown = _exec_with_watchdog(dlg)
    assert shown
    dlg._editor.insertPlainText("x")
    dlg._save_file()
    assert path.read_bytes() == b"xone\n"
    dlg._modified = False
    dlg.deleteLater()


def test_edge_a_failed_reload_keeps_the_edits_saveable(tmp_path):
    """Only a dialog that never loaded is blocked: after a good load a
    transient reload failure must not lock the user's work in."""
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "ok.txt"
    path.write_bytes(b"one\n")
    fs = _FailingReadFS(set())
    dlg = TextEditorDialog(fs, str(path))
    fs.failing.add(str(path))
    with mock.patch("ui.text_editor.QMessageBox.critical"), mock.patch.object(
        dlg, "_confirm_discard_changes", return_value=True
    ):
        dlg._reload_file()
    fs.failing.clear()
    dlg._editor.insertPlainText("x")
    dlg._save_file()
    assert path.read_bytes() == b"xone\n"
    dlg._modified = False
    dlg.deleteLater()


def test_edge_a_file_over_the_size_limit_does_not_open_either(tmp_path):
    from core import open_limits as OL
    from ui.text_editor import TextEditorDialog

    path = tmp_path / "big.txt"
    path.write_bytes(b"x" * (2 * 1024 * 1024))
    with mock.patch.object(OL, "max_open_bytes", return_value=1024), mock.patch(
        "ui.text_editor.max_open_bytes", return_value=1024
    ), mock.patch("ui.text_editor.QMessageBox.warning") as warning:
        dlg = TextEditorDialog(LocalFS(), str(path))
        _result, shown = _exec_with_watchdog(dlg)
    warning.assert_called_once()
    assert not shown
    dlg.deleteLater()


# -- hex editor -----------------------------------------------------------


def test_sad_the_hex_editor_does_not_open_on_an_unreadable_file(tmp_path):
    from ui.hex_editor import HexEditorDialog

    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00\x01")
    fs = _FailingReadFS({str(path)})
    with mock.patch("ui.hex_editor.QMessageBox.critical") as critical:
        dlg = HexEditorDialog(fs, str(path))
        result, shown = _exec_with_watchdog(dlg)
    critical.assert_called_once()
    assert not shown
    assert not result
    dlg.deleteLater()


def test_happy_the_hex_editor_still_opens_a_readable_file(tmp_path):
    from ui.hex_editor import HexEditorDialog

    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00\x01")
    dlg = HexEditorDialog(LocalFS(), str(path))
    _result, shown = _exec_with_watchdog(dlg)
    assert shown
    dlg.deleteLater()
