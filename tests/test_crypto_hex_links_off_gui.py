"""Encrypt, decrypt, the hex editor's save and Show Link Target no longer
freeze the window.

Audit (feedback: no blocked windows): Encrypt read the file, derived the
key (scrypt: slow on purpose) and wrote the ciphertext on the GUI thread;
Decrypt the same the other way; the hex editor read the file again for
its conflict check and wrote it there; Show Link Target asked readlink
per link there. Each needs its answer before it goes on (the next
question, the result), so each waits in ui.off_gui.run_off_gui: the call
on a worker, the windows painting meanwhile.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])

# TICKS_NOTE: a timer that ticked at all ran during the wait - a GUI thread
# held by the call gets none (the timer stops before the loop runs again).
# How often it ticked depends on the host's load, so only "at all" counts.


class SlowFS(LocalFS):
    """A server: reads, writes and lookups take a while; who called is noted."""

    delay = 0.3

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[str] = []

    def _note(self) -> None:
        self.threads.append(threading.current_thread().name)
        time.sleep(self.delay)

    def open_read(self, path):
        self._note()
        return super().open_read(path)

    def open_write(self, path, *args, **kwargs):
        self._note()
        return super().open_write(path, *args, **kwargs)

    def exists(self, path):
        self._note()
        return super().exists(path)

    def readlink(self, path):
        self._note()
        return super().readlink(path)


def _ticks_during(fn):
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(1))
    timer.start()
    try:
        value = fn()
    finally:
        timer.stop()
    return value, len(ticks)


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "secret.txt").write_text("plain words")
    (tmp_path / "link").symlink_to(tmp_path / "secret.txt")
    p = FilePaneWidget(SlowFS())
    p.backend_delay = SlowFS.delay
    p._backend.delay = 0.0
    p.navigate(str(tmp_path))
    p._backend.delay = SlowFS.delay
    p._backend.threads.clear()
    yield p
    p.shutdown()
    p.deleteLater()


def _passphrases(*answers):
    queue = iter(answers)
    return mock.patch.object(QInputDialog, "getText",
                             side_effect=lambda *a, **k: (next(queue), True))


def test_happy_encrypt_and_decrypt_keep_the_window_live(pane, tmp_path):
    with _passphrases("pw", "pw"), mock.patch.object(QMessageBox, "information") as info:
        _none, ticks = _ticks_during(
            lambda: pane._encrypt_selected_file(FileItem(name="secret.txt")))
    info.assert_called_once()
    assert (tmp_path / "secret.txt.axenc").exists()
    assert ticks >= 1 and "MainThread" not in pane._backend.threads

    (tmp_path / "secret.txt").unlink()
    pane._backend.threads.clear()
    with _passphrases("pw"):
        _none, ticks = _ticks_during(
            lambda: pane._decrypt_selected_file(FileItem(name="secret.txt.axenc")))
    assert (tmp_path / "secret.txt").read_text() == "plain words"
    assert ticks >= 1 and "MainThread" not in pane._backend.threads


def test_sad_a_wrong_passphrase_is_still_said(pane, tmp_path):
    with _passphrases("pw", "pw"), mock.patch.object(QMessageBox, "information"):
        pane._encrypt_selected_file(FileItem(name="secret.txt"))
    with _passphrases("wrong"), mock.patch.object(QMessageBox, "warning") as warning:
        pane._decrypt_selected_file(FileItem(name="secret.txt.axenc"))
    warning.assert_called_once()
    assert "Wrong passphrase" in warning.call_args.args[2]


def test_sad_an_existing_ciphertext_is_still_asked_about(pane, tmp_path):
    (tmp_path / "secret.txt.axenc").write_bytes(b"older")
    with _passphrases("pw", "pw"), mock.patch.object(
            QMessageBox, "question", return_value=QMessageBox.StandardButton.No) as question:
        pane._encrypt_selected_file(FileItem(name="secret.txt"))
    question.assert_called_once()
    assert (tmp_path / "secret.txt.axenc").read_bytes() == b"older"


def test_happy_show_link_target_reads_off_the_gui_thread(pane, tmp_path):
    from PyQt6.QtCore import QItemSelectionModel

    proxy = pane._proxy
    index = next(proxy.index(r, 0) for r in range(proxy.rowCount())
                 if proxy.index(r, 0).data() == "link")
    pane._table.selectionModel().setCurrentIndex(
        index, QItemSelectionModel.SelectionFlag.ClearAndSelect
        | QItemSelectionModel.SelectionFlag.Rows)
    with mock.patch.object(QMessageBox, "information") as info:
        _none, ticks = _ticks_during(pane._show_link_target)
    assert info.call_args.args[2] == f"link -> {tmp_path / 'secret.txt'}"
    assert ticks >= 1 and pane._backend.threads == ["off-gui"]


def test_happy_the_hex_editor_saves_off_the_gui_thread(tmp_path):
    from PyQt6.QtTest import QTest

    from ui.hex_editor import HexEditorDialog

    path = tmp_path / "blob.bin"
    path.write_bytes(b"original")
    fs = SlowFS()
    fs.delay = 0.0
    dlg = HexEditorDialog(fs, str(path))
    dlg.show()
    try:
        dlg._hex_widget.setFocus()
        QTest.keyClicks(dlg._hex_widget, "00")
        fs.delay = SlowFS.delay
        fs.threads.clear()
        _none, ticks = _ticks_during(dlg._save_file)
        assert path.read_bytes() == b"\x00riginal"
        assert dlg._status_label.text() == "Saved"
        assert ticks >= 1 and fs.threads and "MainThread" not in fs.threads
    finally:
        dlg.close()
        dlg.deleteLater()
