"""Smaller UI findings of review round 2.

* Properties of one folder showed its size as exact although subfolders it
  could not list counted as zero; the multi-selection summary already said
  "at least". Now one folder says so too.
* A click on a traceback line from a run of a bundled example looked the
  script up among the user's scripts: it failed ("no longer exists") or
  opened a user script of the same name. Now the example the traceback
  names is opened at that line.
* The archive dock's title showed the archive's name with its bidi
  controls intact: ``invoice\\u202efdp.exe`` read as "invoiceexe.pdf". Now
  it goes through ``core.remote_name.sanitize_for_display`` as the file
  table's names do.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(predicate, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return predicate()


# -- Properties: "at least" for one folder -----------------------------------------


class _LockedFS(LocalFS):
    def list_dir(self, path):
        if path.endswith("locked"):
            raise PermissionError(13, "Permission denied", path)
        return super().list_dir(path)


def _folder(tmp_path):
    big = tmp_path / "big"
    (big / "locked").mkdir(parents=True)
    (big / "small.bin").write_bytes(b"x" * 1000)
    (big / "locked" / "huge.bin").write_bytes(b"x" * 5000)
    return big


def test_sad_a_folder_with_an_unreadable_subfolder_shows_at_least(tmp_path):
    from ui.properties_dialog import PropertiesDialog

    fs = _LockedFS()
    big = _folder(tmp_path)
    item = next(i for i in fs.list_dir(str(tmp_path)) if i.name == "big")
    dlg = PropertiesDialog(fs, str(big), item)
    try:
        dlg.wait_for_size()
        assert dlg.general_fields()["Size"] == "at least 1000 bytes"
    finally:
        dlg.close()
        dlg.deleteLater()


def test_happy_a_folder_read_in_full_shows_its_exact_size(tmp_path):
    from ui.properties_dialog import PropertiesDialog, _SizeWorker

    fs = LocalFS()
    big = _folder(tmp_path)
    item = next(i for i in fs.list_dir(str(tmp_path)) if i.name == "big")
    dlg = PropertiesDialog(fs, str(big), item)
    try:
        dlg.wait_for_size()
        assert dlg.general_fields()["Size"].startswith("6000 bytes")
    finally:
        dlg.close()
        dlg.deleteLater()
    got: list = []
    worker = _SizeWorker(_LockedFS(), str(big))
    worker.done.connect(got.append)
    worker.run()
    assert got == [(1000, False)]


# -- a traceback of a bundled example ----------------------------------------------


@pytest.fixture()
def dock():
    from ui import scripts_dock as SD

    d = SD.ScriptsDock(scheduled_jobs=lambda: {})
    d._warn = lambda *_a, **_k: None
    d.resize(900, 600)
    d.show()
    APP.processEvents()
    yield d
    d.shutdown()
    d.close()
    d.deleteLater()
    APP.processEvents()


def test_sad_a_traceback_line_of_an_example_opens_that_example(dock):
    from core import scripting

    example = scripting._list_bundled_scripts()[0]
    # A user script of the same name must not be the one opened.
    user_copy = example
    had_user_copy = user_copy in scripting.list_scripts()
    if not had_user_copy:
        scripting.save_script(user_copy, "# the user's own script\n" * 3)
    try:
        assert dock.open_example(example)
        dock._ask_example_call = lambda name, usage: "undefined_name_here()"
        dock.run()
        assert _wait(lambda: not dock.is_running())
        path = dock.last_run_path()
        assert path.endswith(os.path.join("resources", "scripts", f"{example}.py"))
        assert dock.jump_to_traceback_line(f'  File "{path}", line 3, in <module>')
        assert dock.current() == ("example", example)
        assert dock.editor.textCursor().blockNumber() == 2
        # The line of the call itself is past the example's own lines.
        beyond = dock.editor.blockCount() + 3
        assert not dock.jump_to_traceback_line(f'  File "{path}", line {beyond}, in <module>')
        assert dock.current() == ("example", example)
        assert "call" in dock.status_text()
    finally:
        if not had_user_copy:
            scripting.delete_script(user_copy)


# -- the archive dock's title ---------------------------------------------------------


def test_sad_the_archive_dock_title_shows_no_bidi_override(tmp_path):
    import zipfile

    from ui import main_window as MW

    name = "invoice\u202efdp.exe.zip"
    archive = tmp_path / name
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "x")
    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "session.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "recents.json"):
        win = MW.MainWindow()
    try:
        win._reconnect_timer.stop()
        win.open_archive_pane(str(archive))
        title = win._archive_dock.windowTitle()
        assert "\u202e" not in title
        assert title.startswith("Archive: invoice\ufffdfdp.exe")
        bar = win._archive_dock.titleBarWidget()
        texts = [label.text() for label in bar.findChildren(QLabel)] if bar else []
        assert texts and not any("\u202e" in text for text in texts)
    finally:
        win._quit_with_transfers = True
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
