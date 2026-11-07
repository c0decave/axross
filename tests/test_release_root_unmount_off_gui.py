"""Closing a remote pane, Open as root and Unmount FUSE wait off the GUI
thread.

Found by the second audit (feedback: no blocked windows): closing a
pane released its connection on the GUI thread - the last reference
disconnects, a logout round trip and a dead link's whole timeout; Open
as root waited for pkexec (the polkit prompt) there; Unmount ran
fusermount -u, umount and the serving thread's join there (up to about
15 s). Each waits in ui.off_gui.run_off_gui now.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_happy_a_closing_panes_connection_is_released_off_the_gui_thread():
    from ui.main_window import MainWindow

    released: list[str] = []

    class Window:
        _release_pane_connection = MainWindow._release_pane_connection

        @staticmethod
        def _editors_use(backend) -> bool:  # no editor works on it
            return False

        def __init__(self) -> None:
            self._transfer_manager = SimpleNamespace(busy=lambda backend: False)
            self._connection_manager = SimpleNamespace(
                release=lambda profile: (time.sleep(0.2),
                                         released.append(threading.current_thread().name)))

    Window()._release_pane_connection(SimpleNamespace(name="srv"), object())
    assert released and released[0] != "MainThread"


def test_happy_open_as_root_waits_for_pkexec_off_the_gui_thread(tmp_path):
    from core import elevated_io as E
    from ui.file_pane import FilePaneWidget

    seen: list[str] = []

    def read(backend, path):
        seen.append(threading.current_thread().name)
        return b"root:x:0:0\n"

    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    try:
        with mock.patch.object(E, "elevated_read", read), \
                mock.patch("ui.viewer_window.show_independent"):
            pane._open_as_root(str(tmp_path / "shadow"))
        assert seen and seen[0] != "MainThread"
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_happy_unmount_runs_off_the_gui_thread(tmp_path):
    from ui.file_pane import FilePaneWidget

    seen: list[str] = []
    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    try:
        pane._fuse_handle = SimpleNamespace(
            unmount=lambda: seen.append(threading.current_thread().name),
            mount_point=str(tmp_path))
        with mock.patch.object(QMessageBox, "information"), \
                mock.patch.object(QMessageBox, "warning"):
            pane._unmount_fuse()
        assert seen and seen[0] != "MainThread"
        assert pane._fuse_handle is None
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_happy_switching_auto_refresh_on_lists_nothing_on_the_gui_thread(tmp_path):
    """Found by the same audit: the watcher made its first picture by
    listing the folder on the GUI thread; the listing shown is that picture
    now."""
    from ui.file_pane import FilePaneWidget

    class Counting(LocalFS):
        def __init__(self) -> None:
            super().__init__()
            self.listed_on: list[str] = []

        def list_dir(self, path):
            self.listed_on.append(threading.current_thread().name)
            return super().list_dir(path)

    (tmp_path / "a.txt").write_text("a")
    fs = Counting()
    pane = FilePaneWidget(fs)
    pane.navigate(str(tmp_path))
    try:
        pane._on_watch_toggled(False)
        fs.listed_on.clear()
        pane._on_watch_toggled(True)
        assert "MainThread" not in fs.listed_on
        assert pane._watcher is not None
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_happy_the_proxy_route_is_resolved_off_the_gui_thread_and_a_closed_pane_skipped():
    """Found by the same audit: the pane's proxy label resolved the route
    on the GUI thread - an expired PAC file is fetched over HTTP, up to
    10 s, after every connect."""
    from core import proxy_settings
    from ui.main_window import MainWindow
    from ui.scan_job import ScanJob

    resolved_on: list[str] = []

    def resolve(profile):
        resolved_on.append(threading.current_thread().name)
        time.sleep(0.2)
        return SimpleNamespace(config=None, description="Direct")

    class Window(ScanJob):  # a QObject, as the window is
        _refresh_proxy_indicator = MainWindow._refresh_proxy_indicator

        def __init__(self) -> None:
            super().__init__()
            self._pane_profiles = {}

    window = Window()
    kept, closed = mock.MagicMock(), mock.MagicMock()
    profile = SimpleNamespace(name="srv")
    window._pane_profiles[kept] = profile
    window._pane_profiles[closed] = profile
    with mock.patch.object(proxy_settings, "resolve_for_profile", resolve):
        window._refresh_proxy_indicator(kept)
        window._refresh_proxy_indicator(closed)
        del window._pane_profiles[closed]  # the pane goes while it resolves
        deadline = time.monotonic() + 5
        while any(j.running for j in window._proxy_jobs) and time.monotonic() < deadline:
            APP.processEvents()
            time.sleep(0.01)
        APP.processEvents()
    assert resolved_on and "MainThread" not in resolved_on
    kept.set_proxy_info.assert_called_once_with("", "Direct")
    closed.set_proxy_info.assert_not_called()


def test_happy_a_release_deferred_until_the_transfers_end_does_not_wait_in_their_slot():
    """Found by the review: the release kept until a pane's transfers were
    done waited (in a nested event loop) inside the transfer manager's
    job_finished slot - the next finished jobs re-entered the manager,
    which reported all_finished twice. It runs on a thread of its own."""
    from ui.main_window import MainWindow

    released: list[str] = []
    gate = threading.Event()

    def release(profile):
        gate.wait(2)
        released.append(threading.current_thread().name)

    class Window:
        _release_idle_connections = MainWindow._release_idle_connections
        _release_quietly = MainWindow._release_quietly

        def __init__(self) -> None:
            backend = object()
            self._deferred_releases = [(SimpleNamespace(name="srv"), backend)]
            self._transfer_manager = SimpleNamespace(busy=lambda b: False)
            self._connection_manager = SimpleNamespace(release=release)

    window = Window()
    start = time.perf_counter()
    window._release_idle_connections()
    assert time.perf_counter() - start < 0.2 and window._deferred_releases == []
    gate.set()
    deadline = time.monotonic() + 3
    while not released and time.monotonic() < deadline:
        time.sleep(0.01)
    assert released == ["release-connection"]
