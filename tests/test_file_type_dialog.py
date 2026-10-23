"""The pane's *Identify File Type…* entry and its dialog.

The dialog lists one row per selected entry. Detection runs on a
:class:`~ui.scan_job.ScanJob` (a daemon thread), so a dead remote never
freezes the window and closing the dialog early never touches a running
QThread.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import file_type as FT  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from ui.file_pane import FilePaneWidget  # noqa: E402
from ui.file_type_dialog import COLUMNS, FileTypeDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
LABEL = "Identify File Type…"


def _wait(predicate, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return predicate()


class _HangingBackend:
    def __init__(self) -> None:
        self.release = threading.Event()

    def stat(self, path):
        return FileItem(name=os.path.basename(path), size=1)

    def open_read(self, path):
        self.release.wait(30)
        raise OSError("connection reset")


class _FailingBackend:
    def stat(self, path):
        raise ConnectionError("remote end closed the connection")


@pytest.fixture()
def tree(tmp_path):
    (tmp_path / "photo.txt").write_bytes(PNG)
    (tmp_path / "notes.txt").write_bytes(b"hello\r\nworld\r\n")
    (tmp_path / "sub").mkdir()
    return tmp_path


@pytest.fixture()
def pane(tree):
    widget = FilePaneWidget(LocalFS())
    widget.resize(600, 400)
    widget.show()
    APP.processEvents()
    widget.navigate(str(tree))
    APP.processEvents()
    try:
        yield widget
    finally:
        for dlg in list(getattr(widget, "file_type_dialogs", [])):
            dlg.close()
        widget.close()
        widget.deleteLater()
        APP.processEvents()


def _texts(widget) -> list[str]:
    return [a.text().replace("&", "") for a in widget._build_context_menu().actions()]


def _column(name: str) -> int:
    return COLUMNS.index(name)


# --------------------------------------------------------------------------
# happy path
# --------------------------------------------------------------------------


def test_happy_entry_is_offered_for_a_selected_file(pane):
    pane._restore_selection({"photo.txt"}, "photo.txt")
    assert LABEL in _texts(pane)


def test_happy_two_files_give_two_rows_with_the_mismatch_flagged(pane, tree):
    pane._restore_selection({"photo.txt", "notes.txt"}, "photo.txt")
    action = next(a for a in pane._build_context_menu().actions() if a.text().replace("&", "") == LABEL)
    action.trigger()
    assert _wait(lambda: pane.file_type_dialogs and pane.file_type_dialogs[-1].idle)
    dlg = pane.file_type_dialogs[-1]
    assert dlg.table.rowCount() == 2
    rows = {dlg.row_texts(r)[_column("File")]: dlg.row_texts(r) for r in range(2)}
    photo, notes = rows["photo.txt"], rows["notes.txt"]
    assert photo[_column("MIME type")] == "image/png"
    assert photo[_column("Verdict")].startswith("mismatch")
    assert "text/plain" in photo[_column("Extension claims")]
    assert notes[_column("Verdict")] == "match"
    assert notes[_column("Encoding")] == "ASCII"
    assert notes[_column("Line endings")] == "CRLF"
    assert notes[_column("Size")]
    # the mismatch is visible, not just a word in a cell
    row = [r for r in range(2) if dlg.row_texts(r)[0] == "photo.txt"][0]
    cell = dlg.table.item(row, _column("Verdict"))
    assert cell.font().bold()
    assert "image/png" in cell.toolTip()
    assert "1 mismatch" in dlg.status_label.text()


def test_happy_copy_puts_the_rows_on_the_clipboard(tree):
    dlg = FileTypeDialog(LocalFS(), [str(tree / "photo.txt")], use_file_command=False)
    try:
        dlg.start()
        assert _wait(lambda: dlg.idle)
        dlg.copy_rows()
        text = QApplication.clipboard().text()
        assert text.splitlines()[0].split("\t")[0] == "File"
        assert "image/png" in text
    finally:
        dlg.close()


# --------------------------------------------------------------------------
# sad path
# --------------------------------------------------------------------------


def test_sad_entry_is_not_offered_without_a_selection(pane):
    assert LABEL not in _texts(pane)


def test_sad_hanging_remote_does_not_freeze_and_times_out():
    backend = _HangingBackend()
    dlg = FileTypeDialog(backend, ["/stuck.bin"], timeout=0.3)
    try:
        started = time.monotonic()
        dlg.show()
        dlg.start()
        APP.processEvents()
        assert time.monotonic() - started < 1.0  # the GUI thread never waited
        assert "detecting" in dlg.row_texts(0)[_column("Detected type")]
        assert _wait(lambda: dlg.idle, timeout=5)
        assert dlg.row_texts(0)[_column("Detected type")] == "timed out"
    finally:
        backend.release.set()
        dlg.close()


def test_sad_failing_backend_gives_an_error_row():
    dlg = FileTypeDialog(_FailingBackend(), ["/a.bin"])
    try:
        dlg.start()
        assert _wait(lambda: dlg.idle)
        texts = dlg.row_texts(0)
        assert texts[_column("Detected type")] == "cannot read"
        assert "remote end closed" in dlg.table.item(0, _column("Detected type")).toolTip()
    finally:
        dlg.close()


def test_sad_cancel_marks_the_rest_cancelled():
    backend = _HangingBackend()
    dlg = FileTypeDialog(backend, ["/a", "/b"], timeout=30)
    try:
        dlg.start()
        APP.processEvents()
        dlg.job.cancel()
        assert _wait(lambda: dlg.idle, timeout=5)
        assert [dlg.row_texts(r)[_column("Detected type")] for r in range(2)] == [
            "cancelled",
            "cancelled",
        ]
    finally:
        backend.release.set()
        dlg.close()


# --------------------------------------------------------------------------
# edge cases
# --------------------------------------------------------------------------


def test_edge_selected_folder_gives_a_clear_row(pane):
    pane._restore_selection({"sub"}, "sub")
    assert LABEL in _texts(pane)
    dlg = pane.identify_file_type()
    assert _wait(lambda: dlg.idle)
    assert dlg.row_texts(0)[_column("Detected type")] == "Folder"
    assert dlg.row_texts(0)[_column("Verdict")] == ""


def test_edge_empty_file_row(tmp_path):
    (tmp_path / "empty.txt").write_bytes(b"")
    dlg = FileTypeDialog(LocalFS(), [str(tmp_path / "empty.txt")], use_file_command=False)
    try:
        dlg.start()
        assert _wait(lambda: dlg.idle)
        assert dlg.row_texts(0)[_column("MIME type")] == "application/x-zerosize"
        assert dlg.row_texts(0)[_column("Verdict")] == "unknown"
    finally:
        dlg.close()


def test_edge_identify_with_nothing_selected_returns_none(pane):
    assert pane.identify_file_type() is None


_CLOSE_EARLY = textwrap.dedent(
    """
    import os, sys, threading, time
    sys.path.insert(0, {root!r})
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from PyQt6.QtWidgets import QApplication, QWidget
    from models.file_item import FileItem
    from ui.file_type_dialog import FileTypeDialog

    app = QApplication([])
    release = threading.Event()
    reading = threading.Event()

    class Hanging:
        def stat(self, path):
            return FileItem(name="x", size=1)
        def open_read(self, path):
            reading.set()
            release.wait(30)
            return open(os.devnull, "rb")

    owner = QWidget()
    dlg = FileTypeDialog(Hanging(), ["/a", "/b"], parent=owner, timeout=20)
    dlg.show()
    dlg.start()
    assert reading.wait(5), "detection never started"
    dlg.close()            # closed while the read is blocked
    owner.deleteLater()    # and its parent goes away too
    for _ in range(20):
        app.processEvents()
        time.sleep(0.01)
    release.set()          # the late result arrives with nobody listening
    time.sleep(0.5)
    for _ in range(20):
        app.processEvents()
        time.sleep(0.01)
    print("survived")
    """
)


def test_edge_dialog_closed_while_detection_runs_does_not_crash(tmp_path):
    script = tmp_path / "close_early.py"
    script.write_text(_CLOSE_EARLY.format(root=str(ROOT)))
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=60,
        env=dict(os.environ, QT_QPA_PLATFORM="offscreen"),
    )
    assert proc.returncode == 0, proc.stderr
    assert "survived" in proc.stdout
    assert "Destroyed while thread" not in proc.stderr
    assert "Traceback" not in proc.stderr


def test_edge_result_rows_come_from_core_identify(monkeypatch, tmp_path):
    """The dialog shows what core.file_type.identify says, nothing else."""
    seen = []

    def fake_identify(backend, path, **kwargs):
        seen.append((path, kwargs.get("max_bytes"), kwargs.get("timeout")))
        return FT.FileTypeInfo(path=path, name="x", kind=FT.KIND_FILE, description="Fake")

    monkeypatch.setattr(FT, "identify", fake_identify)
    dlg = FileTypeDialog(LocalFS(), ["/x"], max_bytes=123, timeout=4.5)
    try:
        dlg.start()
        assert _wait(lambda: dlg.idle)
        assert seen == [("/x", 123, 4.5)]
        assert dlg.row_texts(0)[_column("Detected type")] == "Fake"
    finally:
        dlg.close()
