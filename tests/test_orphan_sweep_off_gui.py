"""The crash-recovery sweep of a listing runs off the GUI thread, and only
when the listing holds a candidate.

Found by the second audit (feedback: no blocked windows): every listing
ran core.atomic_recovery.sweep_orphans on the GUI thread, and an orphan
found was removed there - a remove() per file on a server. A name check
on the listing (no I/O) decides now, and the sweep runs on a thread of
its own; it only ever logged.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
ORPHAN = ".axross-atomic-0123456789ab.tmp"


class Removing(LocalFS):
    def __init__(self) -> None:
        super().__init__()
        self.removed_on: list[str] = []

    def remove(self, path, recursive=False):
        self.removed_on.append(threading.current_thread().name)
        return super().remove(path, recursive=recursive)


def _pane(fs, folder):
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(fs)
    pane.navigate(str(folder))
    return pane


def test_happy_an_old_orphan_is_swept_off_the_gui_thread(tmp_path):
    orphan = tmp_path / ORPHAN
    orphan.write_bytes(b"half")
    old = time.time() - 7200
    os.utime(orphan, (old, old))
    fs = Removing()
    pane = _pane(fs, tmp_path)
    try:
        deadline = time.monotonic() + 5
        while orphan.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not orphan.exists()
        assert fs.removed_on == ["orphan-sweep"]
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_edge_a_listing_without_a_candidate_starts_no_sweep(tmp_path):
    (tmp_path / "plain.txt").write_text("p")
    before = {t.name for t in threading.enumerate()}
    pane = _pane(Removing(), tmp_path)
    try:
        assert not any(t.name == "orphan-sweep" for t in threading.enumerate()
                       if t.name not in before)
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_sad_a_young_orphan_stays(tmp_path):
    orphan = tmp_path / ORPHAN
    orphan.write_bytes(b"in progress")
    fs = Removing()
    pane = _pane(fs, tmp_path)
    try:
        time.sleep(0.3)
        assert orphan.exists() and fs.removed_on == []
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_happy_quick_connect_reads_the_keyring_off_the_gui_thread():
    """Found by the second audit: Quick Connect and Restore Session read the
    stored password from the keyring on the GUI thread - the Secret
    Service may wait for an unlock there."""
    from unittest import mock

    from core import credentials
    from ui.main_window import MainWindow

    read_on: list[str] = []

    def stored(name):
        read_on.append(threading.current_thread().name)
        return "pw"

    asked: list = []

    class Window:
        _quick_connect_profile = MainWindow._quick_connect_profile

        def __getattr__(self, name):  # everything after the password: recorded
            return lambda *a, **k: asked.append(name)

    from core.profiles import ConnectionProfile

    profile = ConnectionProfile(name="srv", protocol="ftp", host="h", username="u")
    with mock.patch.object(credentials, "get_password", stored):
        try:
            Window()._quick_connect_profile(profile)
        except Exception:  # noqa: BLE001 - the fake window ends the flow; the read is what counts
            pass
    assert read_on and "MainThread" not in read_on
