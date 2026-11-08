"""A close during a background wait waits for the wait (ui.off_gui).

Before: ``run_off_gui`` waited in a local event loop that held back only
user input. A close from the window manager (Alt+F4, the title bar's X,
the taskbar) - and a close() from a timer - is no user input, so the
window's closeEvent ran inside the wait. A viewer or editor with
WA_DeleteOnClose was deleted while its call ran, and the caller then used
the deleted widgets (the image viewer's Next: "wrapped C/C++ object of
type QLabel has been deleted"). Ctrl+S on a slow server followed by
Alt+F4 even started a second, parallel Save: the editor's closeEvent
asked about the unsaved tab and saved it again.

Now every window shown when the wait starts refuses its close while the
wait runs; the close is replayed once the wait is over and its caller is
done, and the callers check ``sip.isdeleted`` after their waits.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent, Qt, QTimer  # noqa: E402
from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget  # noqa: E402

from core import previews as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from ui.off_gui import run_off_gui  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        time.sleep(0.005)


def _window() -> QWidget:
    w = QWidget()
    w.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    w.show()
    return w


def _slow(seconds: float, value="done"):
    def fn():
        time.sleep(seconds)
        return value
    return fn


def test_happy_a_close_in_the_wait_runs_after_it(monkeypatch):
    w = _window()
    seen: list[bool] = []
    QTimer.singleShot(50, w.close)  # what Alt+F4 does, as far as the wait sees
    # A window opened during the wait (a host-key question) closes as usual.
    late: list[QWidget] = []

    def open_and_close_late():
        q = QWidget()
        q.show()
        late.append(q)
        seen.append(q.close())

    QTimer.singleShot(80, open_and_close_late)
    assert run_off_gui(_slow(0.4)) == "done"
    assert not sip.isdeleted(w) and w.isVisible()  # still whole for the caller
    assert seen == [True] and not late[0].isVisible()
    _pump()
    assert sip.isdeleted(w)  # the held close ran once the wait was over
    late[0].deleteLater()


def test_edge_a_nested_wait_does_not_free_the_outer_one():
    w = _window()
    inner: list = []
    QTimer.singleShot(30, lambda: inner.append(run_off_gui(_slow(0.1, "inner"))))
    QTimer.singleShot(60, w.close)
    assert run_off_gui(_slow(0.5)) == "done"
    assert inner == ["inner"]
    assert not sip.isdeleted(w) and w.isVisible()
    _pump()
    assert sip.isdeleted(w)


def test_sad_a_close_refused_by_the_window_is_not_forced():
    """The replay is a plain close(): a window that says no stays open."""

    class Keeper(QWidget):
        asked = 0

        def closeEvent(self, event):  # noqa: N802 - Qt
            Keeper.asked += 1
            event.ignore()

    w = Keeper()
    w.show()
    QTimer.singleShot(50, w.close)
    run_off_gui(_slow(0.3))
    assert Keeper.asked == 0  # not inside the wait
    _pump()
    assert Keeper.asked == 1 and w.isVisible()
    w.deleteLater()
    _pump(0.05)


# -- the image viewer ------------------------------------------------------------


def test_sad_closing_the_image_viewer_during_a_decode_breaks_nothing(tmp_path, monkeypatch):
    from ui import viewer_window as VW
    from ui.image_viewer import ImageViewerDialog

    paths = []
    for n in "ab":
        image = QImage(40, 40, QImage.Format.Format_RGB32)
        image.fill(QColor("red"))
        path = tmp_path / f"{n}.png"
        image.save(str(path))
        paths.append(str(path))
    viewer = ImageViewerDialog(LocalFS(), paths[0], paths)
    VW.show_independent(viewer)
    real = P.decode_image

    def slow(backend, path, **kw):
        time.sleep(0.4)
        return real(backend, path, **kw)

    monkeypatch.setattr(P, "decode_image", slow)
    QTimer.singleShot(100, viewer.close)
    viewer._next()  # the decode waits; the close comes meanwhile
    # (conftest fails the test on an exception escaping into Qt)
    assert not sip.isdeleted(viewer)
    assert viewer.current_path() == paths[1] and viewer._original is not None
    _pump()
    assert sip.isdeleted(viewer)


# -- the editor ------------------------------------------------------------------


def test_sad_alt_f4_during_a_save_starts_no_second_save(tmp_path, monkeypatch):
    from ui.editor_window import EditorWindow

    path = tmp_path / "f.txt"
    path.write_text("hello\n")
    window = EditorWindow()
    window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    window.show()
    tab = window.open_file(LocalFS(), str(path))
    tab.editor.setPlainText("changed\n")
    tab.mark_modified()
    real = tab.document.save
    calls: list[str] = []

    def slow(*a, **k):
        calls.append(threading.current_thread().name)
        time.sleep(0.4)
        return real(*a, **k)

    tab.document.save = slow
    asked: list = []
    monkeypatch.setattr(QMessageBox, "question", staticmethod(
        lambda *a, **k: (asked.append(a), QMessageBox.StandardButton.Save)[1]))
    QTimer.singleShot(100, window.close)
    assert window.save_tab(tab) is True
    assert len(calls) == 1  # no second save inside the first
    assert asked == []  # the close came after the save: nothing unsaved to ask about
    _pump()
    assert sip.isdeleted(window)
    assert path.read_text() == "changed\n"


def test_edge_the_editor_survives_its_window_going_during_a_save(tmp_path):
    """The guard behind the hold: a window deleted another way while the
    save runs (here: the C++ object, as a parent's deletion would) is not
    used afterwards."""
    from ui.editor_window import EditorWindow

    path = tmp_path / "g.txt"
    path.write_text("x\n")
    window = EditorWindow()
    window.show()
    tab = window.open_file(LocalFS(), str(path))
    tab.editor.setPlainText("y\n")
    tab.mark_modified()
    real = tab.document.save

    def slow(*a, **k):
        time.sleep(0.3)
        return real(*a, **k)

    tab.document.save = slow
    QTimer.singleShot(50, lambda: sip.delete(window))
    with mock.patch.object(QMessageBox, "critical") as critical:
        assert window.save_tab(tab) is True  # written; nothing left to update
    critical.assert_not_called()
    assert path.read_text() == "y\n"
