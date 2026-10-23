"""Every viewer and editor window is a window of its own.

Operator: *„wenn z.b. open as hex und vorher open as text aufgemacht worden
ist, hängt der text editor solange hex nicht geschloßen ist. warum ist das
noch immer so? alle diese teile sollten doch unabhängig voneinander
funktionieren."*

Root cause: ``FilePaneWidget._open_hex_editor`` ran ``HexEditorDialog.exec()``
- an application-modal dialog with a nested event loop - so the editor
window (and the main window) took no input until the hex window closed. The
image viewer, the properties sheet, the checksum and elevated viewers, the
archive-member viewers and the single-file text dialog did the same. They
now show non-modal (``ui.viewer_window.show_independent``), parented to the
main window rather than the pane, and the hex editor and the editor window
read the file off the GUI thread.
"""

from __future__ import annotations

import ast
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

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QCoreApplication, QEvent, Qt  # noqa: E402
from PyQt6.QtGui import QImage  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
ROOT = Path(__file__).resolve().parent.parent


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


def wait_until(predicate, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


class GatedFS(LocalFS):
    """open_read waits until the test opens the gate: a slow remote file."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = threading.Event()
        self.reads_started = threading.Event()

    def open_read(self, path):
        self.reads_started.set()
        if not self.gate.wait(10):
            raise TimeoutError("the test never opened the gate")
        return super().open_read(path)


class FailingFS(LocalFS):
    def open_read(self, path):
        raise PermissionError(13, "Permission denied", path)


#: Viewers found modal by the watchdog below (it closes them, so a modal
#: viewer fails the test instead of hanging it in a nested event loop).
MODAL_SEEN: list = []


@pytest.fixture(autouse=True)
def modal_watchdog():
    from PyQt6.QtCore import QTimer

    MODAL_SEEN.clear()

    def check():
        modal = QApplication.activeModalWidget()
        if modal is not None and type(modal).__name__ != "QMessageBox":
            MODAL_SEEN.append(type(modal).__name__)
            _forget_edits(modal)
            modal.done(0)

    timer = QTimer()
    timer.timeout.connect(check)
    timer.start(150)
    yield
    timer.stop()
    assert MODAL_SEEN == [], f"modal viewer windows: {MODAL_SEEN}"


@pytest.fixture
def folder(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "notes.txt").write_text("hello\n")
    (data / "blob.bin").write_bytes(b"\x00\x01\x02\x03" * 8)
    return data


@pytest.fixture
def window(tmp_path):
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.show()
    yield win
    from ui import viewer_window as VW

    for other in VW.independent_windows():
        _forget_edits(other)
        other.close()
    editor = getattr(win, "_editor_window", None)
    if editor is not None and not sip.isdeleted(editor):
        for tab in editor._tabs():
            tab.editor.document().setModified(False)
    win.close()
    win.deleteLater()
    pump()


def _forget_edits(widget) -> None:
    hexw = getattr(widget, "_hex_widget", None)
    if hexw is not None:
        hexw._modified_offsets.clear()
    if hasattr(widget, "_modified"):
        widget._modified = False


def _hex_windows():
    from ui import viewer_window as VW
    from ui.hex_editor import HexEditorDialog

    return [w for w in VW.independent_windows() if isinstance(w, HexEditorDialog)]


def _press(target_window, *keys) -> None:
    """Keys as the window system delivers them: modal blocking applies."""
    handle = target_window.windowHandle()
    assert handle is not None
    for key in keys:
        QTest.keyClick(handle, key)
    APP.processEvents()


def _open_text_then_hex(window, folder):
    pane = window._active_pane
    pane.navigate(str(folder))
    pane._open_editor(str(folder / "notes.txt"))
    editor = window._editor_window
    assert wait_until(lambda: editor.tabs.count() == 1)
    tab = editor.current_tab()
    pane._open_hex_editor(str(folder / "blob.bin"))
    assert wait_until(lambda: _hex_windows() and _hex_windows()[0].loaded)
    return pane, editor, tab, _hex_windows()[0]


# -- e2e: the operator's case -----------------------------------------------------------


def test_e2e_the_text_editor_takes_keys_while_hex_is_open(window, folder):
    pane = window._active_pane
    pane.navigate(str(folder))
    pane._open_editor(str(folder / "notes.txt"))
    editor = window._editor_window
    assert wait_until(lambda: editor.tabs.count() == 1)
    tab = editor.current_tab()
    editor.activateWindow()
    tab.editor.setFocus()
    _press(editor, Qt.Key.Key_A)  # positive control: keys arrive without hex
    assert tab.editor.toPlainText() == "ahello\n"

    pane._open_hex_editor(str(folder / "blob.bin"))  # returns: no nested loop
    assert wait_until(lambda: _hex_windows() and _hex_windows()[0].loaded)
    hex_window = _hex_windows()[0]
    assert hex_window.isVisible()
    assert QApplication.activeModalWidget() is None

    editor.activateWindow()
    tab.editor.setFocus()
    _press(editor, Qt.Key.Key_B, Qt.Key.Key_C)
    assert tab.editor.toPlainText() == "abchello\n"
    assert hex_window.isVisible()  # both stay open side by side

    hex_window.activateWindow()
    hex_window._hex_widget.setFocus()
    _press(hex_window, Qt.Key.Key_F, Qt.Key.Key_F)
    assert hex_window._hex_widget.get_data()[:1] == b"\xff"


def test_e2e_the_main_window_takes_keys_while_hex_and_text_are_open(window, folder):
    pane, editor, tab, hex_window = _open_text_then_hex(window, folder)
    window.activateWindow()
    pane._filter_edit.setFocus()
    _press(window, Qt.Key.Key_X)
    assert pane._filter_edit.text() == "x"


# -- happy ------------------------------------------------------------------------------


def test_happy_the_hex_window_is_non_modal_owned_by_the_main_window(window, folder):
    pane, editor, tab, hex_window = _open_text_then_hex(window, folder)
    assert hex_window.windowModality() == Qt.WindowModality.NonModal
    assert not hex_window.isModal()
    assert hex_window.testAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    # Owned by the main window: closing the pane does not take it along.
    assert hex_window.parentWidget() is window


def test_happy_a_hex_save_refreshes_the_pane(window, folder):
    pane = window._active_pane
    with mock.patch.object(type(pane), "refresh_after_change") as refresh:
        pane, editor, tab, hex_window = _open_text_then_hex(window, folder)
        refresh.reset_mock()
        hex_window._hex_widget.setFocus()
        QTest.keyClicks(hex_window._hex_widget, "41")
        hex_window._save_file()
    assert (folder / "blob.bin").read_bytes()[:1] == b"\x41"
    refresh.assert_called()


def test_happy_hex_reads_off_the_gui_thread(window, folder):
    fs = GatedFS()
    pane = window._active_pane
    pane._backend = fs
    started = time.monotonic()
    pane._open_hex_editor(str(folder / "blob.bin"))
    assert time.monotonic() - started < 2  # did not wait for the read
    assert fs.reads_started.wait(5)
    (hex_window,) = _hex_windows()
    assert hex_window.isVisible() and not hex_window.loaded
    assert "Loading" in hex_window._status_label.text()
    fs.gate.set()
    assert wait_until(lambda: hex_window.loaded)
    assert hex_window._hex_widget.get_data() == (folder / "blob.bin").read_bytes()


def test_happy_the_editor_window_reads_off_the_gui_thread(window, folder):
    fs = GatedFS()
    started = time.monotonic()
    assert window.open_in_editor(fs, str(folder / "notes.txt")) is None
    assert time.monotonic() - started < 2
    assert fs.reads_started.wait(5)
    editor = window._editor_window
    assert editor.tabs.count() == 0
    fs.gate.set()
    assert wait_until(lambda: editor.tabs.count() == 1)
    assert editor.isVisible()
    assert editor.current_tab().editor.toPlainText() == "hello\n"


def test_happy_the_image_viewer_is_non_modal(window, folder):
    image = QImage(8, 8, QImage.Format.Format_RGB32)
    image.fill(0x336699)
    assert image.save(str(folder / "pic.png"))
    pane = window._active_pane
    pane.navigate(str(folder))
    assert pane._open_image_viewer(str(folder / "pic.png"))
    from ui.image_viewer import ImageViewerDialog

    (viewer,) = [w for w in _all_independent() if isinstance(w, ImageViewerDialog)]
    assert viewer.isVisible() and QApplication.activeModalWidget() is None
    assert viewer._pane is pane  # delete and drag still work on the pane


def test_happy_properties_are_non_modal_and_ok_refreshes(window, folder):
    from models.file_item import FileItem
    from ui.properties_dialog import PropertiesDialog

    pane = window._active_pane
    pane.navigate(str(folder))
    item = FileItem(name="notes.txt", size=6)
    with mock.patch.object(type(pane), "selected_file_items", return_value=[item]), \
            mock.patch.object(type(pane), "refresh_after_change") as refresh:
        pane._show_properties()
        (sheet,) = [w for w in _all_independent() if isinstance(w, PropertiesDialog)]
        assert sheet.isVisible() and QApplication.activeModalWidget() is None
        refresh.assert_not_called()
        sheet.accept()
        pump()
    refresh.assert_called_once()


def test_happy_checksum_and_elevated_viewers_are_non_modal(window, folder):
    from core import elevated_io as E
    from models.file_item import FileItem
    from ui.checksum_dialog import ChecksumDialog
    from ui.elevated_viewer import ElevatedViewerDialog

    pane = window._active_pane
    pane.navigate(str(folder))
    with mock.patch.object(pane._backend, "checksum", return_value="sha256:" + "a" * 64):
        pane._show_checksum(FileItem(name="notes.txt", size=6))
    with mock.patch.object(E, "elevated_read", return_value=b"root:x:0:0\n"):
        pane._open_as_root(str(folder / "notes.txt"))
    kinds = {type(w) for w in _all_independent() if w.isVisible()}
    assert {ChecksumDialog, ElevatedViewerDialog} <= kinds
    assert QApplication.activeModalWidget() is None


def test_happy_archive_member_viewers_are_non_modal(window, folder):
    from ui.file_pane import open_local_file_in_viewer
    from ui.hex_editor import HexEditorDialog
    from ui.text_editor import TextEditorDialog

    open_local_file_in_viewer(window, str(folder / "notes.txt"))
    open_local_file_in_viewer(window, str(folder / "blob.bin"))
    kinds = {type(w) for w in _all_independent() if w.isVisible()}
    assert {TextEditorDialog, HexEditorDialog} <= kinds
    assert QApplication.activeModalWidget() is None


def test_happy_the_text_dialog_of_a_pane_without_main_window_is_non_modal(folder):
    from ui.file_pane import FilePaneWidget
    from ui.text_editor import TextEditorDialog

    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(folder))
    try:
        with mock.patch.object(type(pane), "refresh_after_change") as refresh:
            pane._open_editor(str(folder / "notes.txt"))
            (dialog,) = [w for w in _all_independent() if isinstance(w, TextEditorDialog)]
            assert dialog.isVisible() and QApplication.activeModalWidget() is None
            dialog._editor.setPlainText("changed\n")
            dialog._save_file()
        assert (folder / "notes.txt").read_text() == "changed\n"
        refresh.assert_called()
        dialog.close()
    finally:
        pane.deleteLater()
        pump()


def test_happy_report_text_windows_are_non_modal(window):
    from core.profiles import ConnectionProfile

    report = window._show_text_dialog("Diagnostics", "all good")
    with mock.patch.object(window._profile_manager, "all_profiles",
                           return_value=[ConnectionProfile(name="srv", host="h")]):
        window._view_all_profiles()
    shown = [w for w in _all_independent() if w.isVisible()]
    titles = {w.windowTitle() for w in shown}
    assert report in shown and {"Diagnostics", "All Profiles (1)"} <= titles
    assert QApplication.activeModalWidget() is None
    from PyQt6.QtWidgets import QToolButton

    for title in ("Diagnostics", "All Profiles (1)"):
        (text_window,) = [w for w in shown if w.windowTitle() == title]
        assert text_window.findChild(QToolButton, "axCloseCorner") is not None


def _all_independent():
    from ui import viewer_window as VW

    return VW.independent_windows()


# -- sad --------------------------------------------------------------------------------


def test_sad_a_hex_read_error_closes_the_window_with_a_message(window, folder):
    pane = window._active_pane
    pane._backend = FailingFS()
    with mock.patch("ui.hex_editor.QMessageBox.critical") as critical:
        pane._open_hex_editor(str(folder / "blob.bin"))
        assert wait_until(lambda: critical.called)
    assert "Permission denied" in critical.call_args.args[2]
    assert wait_until(lambda: not any(w.isVisible() for w in _hex_windows()))


def test_sad_a_too_large_file_is_refused_in_the_background_too(window, folder):
    pane = window._active_pane
    with mock.patch("ui.hex_editor.max_open_bytes", return_value=4), \
            mock.patch("ui.hex_editor.QMessageBox.warning") as warning:
        pane._open_hex_editor(str(folder / "blob.bin"))
        assert wait_until(lambda: warning.called)
    assert "File Too Large" in warning.call_args.args[1]
    assert wait_until(lambda: not any(w.isVisible() for w in _hex_windows()))


def test_sad_the_editor_window_reports_an_unreadable_file_and_adds_no_tab(window, folder):
    with mock.patch("ui.editor_window.QMessageBox.warning") as warning:
        window.open_in_editor(FailingFS(), str(folder / "notes.txt"))
        assert wait_until(lambda: warning.called)
    editor = window._editor_window
    assert editor.tabs.count() == 0


def test_sad_an_image_that_cannot_be_decoded_opens_no_window(window, folder):
    (folder / "broken.png").write_bytes(b"not a png")
    pane = window._active_pane
    pane.navigate(str(folder))
    from ui.image_viewer import ImageViewerDialog

    with mock.patch("ui.image_viewer.QMessageBox.warning"):
        pane._open_image_viewer(str(folder / "broken.png"))
    pump()
    assert not [w for w in _all_independent()
                if isinstance(w, ImageViewerDialog) and w.isVisible()]


def test_sad_closing_the_main_window_asks_for_unsaved_hex_edits(window, folder):
    pane, editor, tab, hex_window = _open_text_then_hex(window, folder)
    hex_window._hex_widget.setFocus()
    QTest.keyClicks(hex_window._hex_widget, "41")
    assert hex_window._hex_widget.is_modified
    with mock.patch("ui.hex_editor.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.No) as question:
        assert not window.close()
    question.assert_called_once()
    assert window.isVisible() and hex_window.isVisible()


# -- edge -------------------------------------------------------------------------------


def test_edge_closing_hex_while_it_loads_drops_the_result(window, folder):
    fs = GatedFS()
    pane = window._active_pane
    pane._backend = fs
    pane._open_hex_editor(str(folder / "blob.bin"))
    assert fs.reads_started.wait(5)
    (hex_window,) = _hex_windows()
    hex_window.close()
    pump()
    fs.gate.set()
    pump(0.3)
    assert sip.isdeleted(hex_window) or not hex_window.isVisible()
    assert not [w for w in _hex_windows() if w.isVisible()]


def test_edge_the_same_file_twice_while_it_loads_is_one_tab(window, folder):
    fs = GatedFS()
    path = str(folder / "notes.txt")
    window.open_in_editor(fs, path)
    window.open_in_editor(fs, path)
    fs.gate.set()
    editor = window._editor_window
    assert wait_until(lambda: editor.tabs.count() == 1)
    pump(0.3)
    assert editor.tabs.count() == 1


def test_edge_two_files_on_their_way_keep_the_status_until_both_are_read(window, folder):
    first, second = GatedFS(), GatedFS()
    (folder / "more.txt").write_text("more\n")
    window.open_in_editor(first, str(folder / "notes.txt"))
    window.open_in_editor(second, str(folder / "more.txt"))
    editor = window._editor_window
    first.gate.set()
    assert wait_until(lambda: editor.tabs.count() == 1)
    assert "more.txt" in editor.statusBar().currentMessage()
    second.gate.set()
    assert wait_until(lambda: editor.tabs.count() == 2)
    assert editor.statusBar().currentMessage() == ""


def test_edge_closing_the_last_tab_while_a_file_is_on_its_way_keeps_the_window(window, folder):
    """The last tab closing takes the editor window along (the stack's
    editor), and closing it abandons running reads: the file asked for
    meanwhile never opened."""
    window.open_in_editor(LocalFS(), str(folder / "notes.txt"))
    editor = window._editor_window
    assert wait_until(lambda: editor.tabs.count() == 1)
    fs = GatedFS()
    (folder / "more.txt").write_text("more\n")
    window.open_in_editor(fs, str(folder / "more.txt"))
    assert fs.reads_started.wait(5)
    editor.close_tab(0)
    assert editor.isVisible()
    fs.gate.set()
    assert wait_until(lambda: editor.tabs.count() == 1)
    assert editor.current_tab().path.endswith("more.txt") and editor.isVisible()


def test_edge_the_hex_window_outlives_its_pane(window, folder):
    pane, editor, tab, hex_window = _open_text_then_hex(window, folder)
    window._add_pane_to_splitter(window._root_splitter, LocalFS())
    window._close_pane(pane)
    pump()
    assert pane not in window._panes
    assert not sip.isdeleted(hex_window) and hex_window.isVisible()


def test_edge_a_viewer_closed_by_its_user_leaves_the_registry(window, folder):
    pane, editor, tab, hex_window = _open_text_then_hex(window, folder)
    hex_window.close()
    pump()
    assert hex_window not in _all_independent()


def test_edge_no_viewer_or_editor_window_is_run_with_exec():
    """Tree gate: a viewer started with ``.exec()`` is modal again."""
    viewers = {"HexEditorDialog", "TextEditorDialog", "ImageViewerDialog",
               "ElevatedViewerDialog", "ChecksumDialog", "PropertiesDialog",
               "MetadataDialog", "MediaViewerDialog"}
    found = []
    for path in sorted((ROOT / "ui").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for scope in ast.walk(tree):
            if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Names bound to a viewer in this function (a name like "dialog"
            # means another class in the next function).
            made: dict[str, str] = {}
            for node in ast.walk(scope):
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Name)
                        and node.value.func.id in viewers):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            made[target.id] = node.value.func.id
            for node in ast.walk(scope):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "exec"):
                    continue
                owner = node.func.value
                if isinstance(owner, ast.Call) and isinstance(owner.func, ast.Name) \
                        and owner.func.id in viewers:
                    found.append(f"{path.name}:{node.lineno} ({owner.func.id})")
                elif isinstance(owner, ast.Name) and owner.id in made:
                    found.append(f"{path.name}:{node.lineno} ({made[owner.id]})")
    assert sorted(set(found)) == []
