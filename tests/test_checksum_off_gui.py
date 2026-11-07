"""Show Checksum runs off the GUI thread.

Audit (feedback: does everything really run async?): the backend's
checksum ran on the GUI thread under a wait cursor - SFTP runs sha256sum
on the server, so a large file froze the window for minutes - and the
stream hash read the file there a megabyte at a time. Both run on the
pane's ScanJob now; the status line says how far it is and Cancel stops
it (the stream hash between two chunks; the server's answer is dropped).
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

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from tests.off_gui_wait import _drain_checksum  # noqa: E402

APP = QApplication.instance() or QApplication([])


class SlowFS(LocalFS):
    """A backend whose checksum and reads take their time (a server)."""

    def __init__(self, native: str = "", delay: float = 0.6) -> None:
        super().__init__()
        self.native, self.delay = native, delay
        self.threads: list[str] = []
        self.release = threading.Event()

    def checksum(self, path, algorithm="sha256"):
        self.threads.append(threading.current_thread().name)
        self.release.wait(self.delay)
        return self.native

    def open_read(self, path):
        fs = self

        class Slow(io.BytesIO):
            def read(self, n=-1):
                time.sleep(0.05)
                fs.threads.append(threading.current_thread().name)
                return super().read(n)

        return Slow(b"x" * (3 * 1024 * 1024))


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(SlowFS("sha256:" + "b" * 64))
    p.navigate(str(tmp_path))
    yield p
    p.deleteLater()


def test_happy_the_window_is_not_held_while_the_server_works(pane):
    shown: list = []
    with mock.patch("ui.viewer_window.show_independent", shown.append):
        start = time.perf_counter()
        pane._show_checksum(FileItem(name="big.iso", size=10))
        assert time.perf_counter() - start < 0.3  # it returned: the event loop runs
        assert pane._cancel_checksum_btn.isVisibleTo(pane)
        assert "big.iso" in pane._status.text()
        assert _drain_checksum(pane)
    assert len(shown) == 1 and shown[0].windowTitle()
    assert pane._backend.threads and "MainThread" not in pane._backend.threads
    assert not pane._cancel_checksum_btn.isVisibleTo(pane)


def test_happy_the_stream_hash_counts_bytes_in_the_status_line(tmp_path):
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(SlowFS(""))
    pane.navigate(str(tmp_path))
    texts: list[str] = []
    try:
        pane._ensure_checksum_job().progress.connect(texts.append)
        with mock.patch("ui.file_pane.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Yes), \
                mock.patch("ui.viewer_window.show_independent") as show:
            pane._show_checksum(FileItem(name="disk.img", size=3 * 1024 * 1024))
            assert _drain_checksum(pane)
        show.assert_called_once()
        assert any("Hashing disk.img…" in t and " of 3.0 MB" in t for t in texts), texts
        assert "MainThread" not in pane._backend.threads
    finally:
        pane.deleteLater()


def test_sad_cancel_while_the_server_works_drops_its_answer(pane):
    with mock.patch("ui.viewer_window.show_independent") as show:
        pane._show_checksum(FileItem(name="big.iso", size=10))
        pane._cancel_checksum()
        pane._backend.release.set()
        assert _drain_checksum(pane)
    show.assert_not_called()
    assert pane._status.text() == "Checksum cancelled"


def test_sad_a_second_checksum_while_one_runs_is_refused_with_a_word(pane):
    with mock.patch("ui.viewer_window.show_independent") as show:
        pane._show_checksum(FileItem(name="a.iso", size=10))
        pane._show_checksum(FileItem(name="b.iso", size=10))
        assert pane._status.text() == "A checksum is still running in this pane."
        pane._backend.release.set()
        assert _drain_checksum(pane)
    assert show.call_count == 1


def test_edge_a_pane_closed_meanwhile_shows_nothing(pane):
    with mock.patch("ui.viewer_window.show_independent") as show:
        pane._show_checksum(FileItem(name="a.iso", size=10))
        pane.shutdown()  # what closing the pane does: its jobs are abandoned
        pane._backend.release.set()
        time.sleep(0.2)
        APP.processEvents()
    show.assert_not_called()


def test_edge_the_stream_hash_reads_the_backend_it_was_asked_on(tmp_path):
    """Found by the review: the stream hash after the question read through
    the pane's backend at that moment - after a switch of connection while
    the server's checksum ran, the path was hashed on the other one."""
    from ui.file_pane import FilePaneWidget

    asked = SlowFS("", delay=0.3)
    other = SlowFS("", delay=0.0)
    pane = FilePaneWidget(asked)
    pane.navigate(str(tmp_path))
    try:
        with mock.patch("ui.file_pane.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Yes), \
                mock.patch("ui.viewer_window.show_independent"):
            pane._show_checksum(FileItem(name="disk.img", size=10))
            pane._backend = other  # the pane connected elsewhere meanwhile
            assert _drain_checksum(pane)
        assert asked.threads.count("scan-job") >= 2  # checksum + the reads
        assert other.threads == []
    finally:
        pane._backend = asked
        pane.deleteLater()
