"""A double-click, F3 or F4 reads what a file is - and where a link leads -
off the GUI thread.

Audit (feedback: does everything really run async?): a file without a
known extension was sniffed by reading its first 512 bytes through the
backend on the GUI thread, and a link was followed with readlink + stat
there: one or two round trips to a server, the window held meanwhile.
They are read on a worker now; the viewer opens when the answer is in -
unless the pane moved to another folder meanwhile, or a second
double-click replaced the first. A name that decides (.txt, .png)
opens at once, as before.
"""

from __future__ import annotations

import io
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

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from tests.off_gui_wait import _drain_scan_job  # noqa: E402

APP = QApplication.instance() or QApplication([])


class SlowFS(LocalFS):
    """Reads and link lookups that take a server's time; who asked is noted."""

    delay = 0.4

    def __init__(self) -> None:
        super().__init__()
        self.threads: list[str] = []

    def _note(self) -> None:
        self.threads.append(threading.current_thread().name)
        time.sleep(self.delay)

    def open_read(self, path):
        self._note()
        return super().open_read(path)

    def readlink(self, path):
        self._note()
        return super().readlink(path)


@pytest.fixture
def folder(tmp_path):
    (tmp_path / "notes").write_text("plain text, no extension\n")
    (tmp_path / "blob").write_bytes(b"\x00\x01\x02binary")
    (tmp_path / "readme.txt").write_text("known")
    (tmp_path / "dir").mkdir()
    (tmp_path / "to-dir").symlink_to(tmp_path / "dir")
    (tmp_path / "to-notes").symlink_to(tmp_path / "notes")
    (tmp_path / "elsewhere").mkdir()
    return tmp_path


@pytest.fixture
def pane(folder):
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(SlowFS())
    p.navigate(str(folder))
    opened: list[tuple[str, str]] = []
    p._open_editor = lambda path, read_only=False: opened.append(("text", Path(path).name))
    p._open_hex_editor = lambda path, read_only=False: opened.append(("hex", Path(path).name))
    p.opened = opened
    yield p
    p.shutdown()
    p.deleteLater()


def _row(pane, name: str):
    proxy = pane._proxy
    return next(proxy.index(r, 0) for r in range(proxy.rowCount())
                if proxy.index(r, 0).data() == name)


def _select(pane, name: str) -> None:
    from PyQt6.QtCore import QItemSelectionModel

    pane._table.selectionModel().setCurrentIndex(
        _row(pane, name),
        QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows)


def _drain(pane) -> None:
    if pane._probe_job is not None:
        assert _drain_scan_job(pane._probe_job)
    APP.processEvents()


def _timed(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_double_click_on_an_unknown_file_does_not_hold_the_window(pane):
    assert _timed(lambda: pane._on_double_click(_row(pane, "notes"))) < 0.2
    assert pane.opened == []  # not yet: the first bytes are on their way
    assert pane._status.text() in ("Opening notes…", pane._items_text())
    _drain(pane)
    assert pane.opened == [("text", "notes")]
    assert pane._backend.threads and "MainThread" not in pane._backend.threads
    assert pane._status.text() == pane._items_text() == "7 items"  # not the "." / ".." rows


def test_happy_f3_and_f4_sniff_off_the_gui_thread_too(pane):
    _select(pane, "blob")
    assert _timed(pane._view_selected) < 0.2
    _drain(pane)
    _select(pane, "notes")
    assert _timed(pane._edit_selected) < 0.2
    _drain(pane)
    assert pane.opened == [("hex", "blob"), ("text", "notes")]
    assert "MainThread" not in pane._backend.threads


def test_happy_a_link_to_a_folder_is_followed_off_the_gui_thread(pane, folder):
    assert _timed(lambda: pane._on_double_click(_row(pane, "to-dir"))) < 0.2
    _drain(pane)
    deadline = time.time() + 5
    while pane._current_path != str(folder / "to-dir") and time.time() < deadline:
        APP.processEvents()
        time.sleep(0.01)
    assert pane._current_path == str(folder / "to-dir")
    assert "MainThread" not in pane._backend.threads


def test_happy_a_link_to_a_file_opens_the_file(pane):
    pane._on_double_click(_row(pane, "to-notes"))
    _drain(pane)  # where it leads
    _drain(pane)  # what it is
    assert pane.opened == [("text", "to-notes")]


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_pane_that_moved_on_opens_nothing(pane, folder):
    pane._on_double_click(_row(pane, "notes"))
    pane.navigate(str(folder / "elsewhere"))
    _drain(pane)
    assert pane.opened == []


def test_sad_an_unreadable_file_opens_as_text_as_before(pane):
    def broken(path):
        raise PermissionError(13, "denied", path)

    pane._backend.open_read = broken
    pane._on_double_click(_row(pane, "notes"))
    _drain(pane)
    assert pane.opened == [("text", "notes")]


def test_sad_a_closed_pane_opens_nothing(pane):
    pane._on_double_click(_row(pane, "notes"))
    pane.shutdown()
    time.sleep(SlowFS.delay + 0.2)
    APP.processEvents()
    assert pane.opened == []


# -- edge -------------------------------------------------------------------------------------


def test_edge_a_name_that_decides_opens_at_once_without_a_read(pane):
    pane._on_double_click(_row(pane, "readme.txt"))
    assert pane.opened == [("text", "readme.txt")]
    assert pane._backend.threads == [] and pane._probe_job is None


def test_edge_a_second_double_click_replaces_the_first(pane):
    pane._on_double_click(_row(pane, "notes"))
    pane._on_double_click(_row(pane, "blob"))
    _drain(pane)
    time.sleep(SlowFS.delay + 0.2)  # the first read ends too: its answer is dropped
    APP.processEvents()
    assert pane.opened == [("hex", "blob")]


def test_edge_the_sync_check_still_answers_for_scripts(pane, folder):
    assert pane._is_binary_file(str(folder / "blob"), "blob") is True
    assert pane._is_binary_file(str(folder / "notes"), "notes") is False
    with mock.patch.object(pane._backend, "open_read", side_effect=OSError("gone")):
        assert pane._is_binary_file(str(folder / "x"), "x") is False
    assert pane._link_points_to_directory(str(folder / "to-dir")) is True
    assert pane._link_points_to_directory(str(folder / "to-notes")) is False


def test_edge_a_binary_header_by_its_magic_bytes():
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget.__new__(FilePaneWidget)  # the check needs no widget
    assert FilePaneWidget._header_is_binary(pane, b"\x89PNG\r\n\x1a\n....")
    assert not FilePaneWidget._header_is_binary(pane, b"just text")
    assert not FilePaneWidget._header_is_binary(pane, b"")
    assert FilePaneWidget._header_is_binary(pane, io.BytesIO(b"a\x00b").getvalue())
