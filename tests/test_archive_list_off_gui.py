"""The window lists an archive on a worker.

Audit (feedback: no blocked windows): the archive view listed the archive
in its constructor on the GUI thread - a .tar.gz is decompressed to its
end for that, a large one took minutes with every window frozen. The
window builds the view with background=True now: it shows "Reading the
archive…" at once and fills the tree when the listing is in; failures
are reported as before. Without it (scripts, tests) the listing is there
when the constructor returns, as before.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import archive as ARCH  # noqa: E402
from ui import archive_pane as AP  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def zip_path(tmp_path):
    path = tmp_path / "pack.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", "a")
        zf.writestr("dir/b.txt", "bb")
    return path


def _slow_listing(seconds: float):
    threads: list[str] = []
    real = AP.list_archive

    def slow(path, **kw):  # kw: the pane's cancel (review 2 of 0.15.176)
        threads.append(threading.current_thread().name)
        time.sleep(seconds)
        return real(path, **kw)

    return mock.patch.object(AP, "list_archive", slow), threads


def _wait(pane, timeout=10.0):
    deadline = time.time() + timeout
    while pane.loading and time.time() < deadline:
        APP.processEvents()
        time.sleep(0.01)
    APP.processEvents()
    return not pane.loading


def test_happy_background_shows_at_once_and_fills_later(zip_path):
    patch, threads = _slow_listing(0.4)
    with patch:
        start = time.perf_counter()
        pane = AP.ArchivePaneWidget(str(zip_path), background=True)
        assert time.perf_counter() - start < 0.2
        assert pane.loading and pane._status_label.text() == "Reading the archive…"
        assert pane._tree.model().rowCount() == 0
        assert _wait(pane)
    assert pane._status_label.text() == "Ready"
    assert "2 entries" in pane._header_label.text()
    assert threads and "MainThread" not in threads
    pane.deleteLater()


def test_happy_without_background_it_is_listed_on_return(zip_path):
    pane = AP.ArchivePaneWidget(str(zip_path))
    assert not pane.loading and pane._status_label.text() == "Ready"
    pane.deleteLater()


@pytest.mark.parametrize("error, shown", [
    (ARCH.UnsafeArchive("path escapes"), "Archive rejected: path escapes"),
    (OSError("truncated"), "Archive could not be read: truncated"),
])
def test_sad_a_failed_background_listing_is_reported_as_before(zip_path, error, shown):
    def broken(path, **_kw):
        raise error

    with mock.patch.object(AP, "list_archive", broken):
        pane = AP.ArchivePaneWidget(str(zip_path), background=True)
        assert _wait(pane)
    assert pane.load_error == shown and pane._status_label.text() == shown
    assert pane._tree.model().rowCount() == 0
    pane.deleteLater()


def test_edge_closing_while_it_lists_drops_the_answer(zip_path):
    patch, _threads = _slow_listing(0.3)
    with patch:
        pane = AP.ArchivePaneWidget(str(zip_path), background=True)
        pane.close()
        time.sleep(0.5)
        APP.processEvents()
    assert pane._tree.model().rowCount() == 0
    pane.deleteLater()
