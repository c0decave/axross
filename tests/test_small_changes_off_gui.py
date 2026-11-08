"""New Symlink, New Hardlink, Create XLink, chmod, Delete in the media
viewer, Diagnostics and the Recovery Scan talk to the server off the GUI
thread.

Found by the second audit (feedback: no blocked windows): each made its
backend call(s) on the GUI thread - one or a few round trips, the window
frozen meanwhile. Each waits in ui.off_gui.run_off_gui now: the call on
a worker, the windows painting; its answer and messages as before.
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import datetime
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


class Recording(LocalFS):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, str]] = []

    def _note(self, name: str) -> None:
        self.calls.append((name, threading.current_thread().name))

    def symlink(self, target, link):
        self._note("symlink")
        return super().symlink(target, link)

    def hardlink(self, target, link):
        self._note("hardlink")
        return super().hardlink(target, link)

    def chmod(self, path, mode):
        self._note("chmod")
        return super().chmod(path, mode)

    def remove(self, path, recursive=False):
        self._note("remove")
        return super().remove(path, recursive=recursive)

    def list_dir(self, path):
        self._note("list_dir")
        return super().list_dir(path)


def _off_gui(fs, name):
    threads = [t for n, t in fs.calls if n == name]
    return threads and all(t != "MainThread" for t in threads)


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "target.txt").write_text("t")
    p = FilePaneWidget(Recording())
    p.navigate(str(tmp_path))
    p._backend.calls.clear()
    yield p
    p.shutdown()
    p.deleteLater()


def _answers(*values):
    queue = iter(values)
    return mock.patch.object(QInputDialog, "getText",
                             side_effect=lambda *a, **k: (next(queue), True))


def test_happy_new_symlink_and_hardlink(pane, tmp_path):
    with _answers(str(tmp_path / "target.txt"), "soft"):
        pane._create_symlink()
    with _answers(str(tmp_path / "target.txt"), "hard"):
        pane._create_hardlink()
    assert (tmp_path / "soft").is_symlink() and (tmp_path / "hard").read_text() == "t"
    assert _off_gui(pane._backend, "symlink") and _off_gui(pane._backend, "hardlink")


def test_sad_a_failing_link_is_still_reported(pane, tmp_path):
    with _answers(str(tmp_path / "target.txt"), "target.txt"), \
            mock.patch.object(QMessageBox, "warning") as warning:
        pane._create_symlink()
    warning.assert_called_once()


def test_happy_chmod_runs_off_the_gui_thread(tmp_path):
    from ui.permissions_dialog import PermissionsWidget

    path = tmp_path / "target.txt"
    path.write_text("t")
    path.chmod(0o644)
    fs = Recording()
    item = FileItem(name="target.txt", size=1, modified=datetime(2026, 1, 1), permissions=0o644)
    widget = PermissionsWidget(fs, str(path), item)
    widget._octal_edit.setText("600")
    assert widget.apply() is None
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert _off_gui(fs, "chmod")
    widget.deleteLater()


def test_happy_delete_in_the_viewer_runs_off_the_gui_thread(tmp_path):
    from ui import viewer_file_actions as VFA

    path = tmp_path / "gone.jpg"
    path.write_bytes(b"x")
    fs = Recording()
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        assert VFA.delete_file(None, fs, str(path), None) is True
    assert not path.exists() and _off_gui(fs, "remove")


def test_happy_recovery_scan_runs_off_the_gui_thread(tmp_path):
    from ui.main_window import MainWindow

    class Window:
        _run_recovery_scan = MainWindow._run_recovery_scan

        def __init__(self, pane) -> None:
            self._active_pane = pane
            self.shown: list = []

        def statusBar(self):  # noqa: N802 - Qt name
            return mock.MagicMock()

        def _show_text_dialog(self, title, text, **_how):
            self.shown.append(title)

    fs = Recording()
    window = Window(mock.MagicMock(backend=fs, current_path=str(tmp_path)))
    window._run_recovery_scan()
    assert window.shown == ["Recovery Scan"] and _off_gui(fs, "list_dir")


def test_happy_the_viewers_move_watch_asks_the_backend_off_the_gui_thread(tmp_path):
    """Found by the second audit: after a file was dragged out of a viewer
    as a move, every listing of the source pane asked exists() per watched
    file on the GUI thread. It asks on a worker; gone() comes here."""
    import time as _time

    from PyQt6.QtCore import QObject, pyqtSignal

    from ui.viewer_file_actions import MoveWatch

    class Pane(QObject):
        path_changed = pyqtSignal(str)

    class Asking:
        def __init__(self) -> None:
            self.asked_on: list[str] = []

        def exists(self, path):
            self.asked_on.append(threading.current_thread().name)
            _time.sleep(0.1)
            return path.endswith("kept.jpg")

    owner, pane, backend = QObject(), Pane(), Asking()
    gone: list[tuple[str, str]] = []
    watch = MoveWatch(owner, backend, pane,
                      lambda p: gone.append((p, threading.current_thread().name)))
    watch.watch("/x/moved.jpg")
    watch.watch("/x/kept.jpg")
    pane.path_changed.emit("/x")
    deadline = _time.monotonic() + 5
    while not gone and _time.monotonic() < deadline:
        APP.processEvents()
        _time.sleep(0.01)
    assert gone == [("/x/moved.jpg", "MainThread")]
    assert backend.asked_on and "MainThread" not in backend.asked_on
