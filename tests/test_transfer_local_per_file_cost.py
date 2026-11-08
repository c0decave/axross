"""Local work per copied file: the same-entry check, the umask, the dock fit.

Measured before (worker profile, 1 000 local 4 KiB files):
storage_identity.same_entry 14 % (os.path.realpath of both folders, a
Python walk with an lstat per path component), process_umask 7 % (a
text-mode read of /proc/self/status, twice per file); and with 2 000
queued jobs the Transfers dock's column fit measured ~14 000 cells
(Qt's default of 1 000 sampled rows x 7 columns).

What must not change: same_entry gives the verdict of the realpath version
on every case below, the umask is read anew each time (it can change while
axross runs), and the dock still fits its columns from real rows.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import storage_identity as SI  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import copy_mode, process_umask  # noqa: E402


def _old_same_local(a: str, b: str) -> bool:
    """storage_identity before the change, verbatim in effect."""
    entry_a, entry_b = SI._local_entry(a), SI._local_entry(b)
    if entry_a == entry_b:
        return True
    try:
        return os.path.samestat(os.lstat(entry_a), os.lstat(entry_b))
    except OSError:
        return False


@pytest.fixture
def tree(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "f.txt").write_text("f")
    (real / "g.txt").write_text("g")
    os.link(real / "f.txt", real / "hard.txt")
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    (real / "link.txt").symlink_to(real / "f.txt")
    (real / "sub").mkdir()
    return tmp_path


CASES = [
    ("real/f.txt", "real/f.txt", True),
    ("real/f.txt", "alias/f.txt", True),          # a folder under two paths
    ("real/f.txt", "real/hard.txt", True),        # a hard link
    ("real/f.txt", "real/g.txt", False),
    ("real/f.txt", "real/new.txt", False),        # the usual destination
    ("real/f.txt", "alias/new.txt", False),
    ("real/new.txt", "alias/new.txt", True),      # neither there: one name in one folder
    ("real/link.txt", "real/f.txt", False),       # a symlink is its own entry
    ("real/sub/../f.txt", "real/f.txt", True),
    ("real/f.txt", "missing/f.txt", False),
    ("real/f.txt", "real/f.txt/x", False),
]


@pytest.mark.parametrize("a, b, want", CASES)
def test_happy_same_entry_gives_the_realpath_verdict(tree, a, b, want):
    pa, pb = str(tree / a), str(tree / b)
    assert _old_same_local(pa, pb) is want
    assert SI.same_entry(LocalFS(), pa, LocalFS(), pb) is want
    assert SI.same_entry(LocalFS(), pb, LocalFS(), pa) is want


def test_edge_a_relative_path_is_taken_from_the_working_folder(tree, monkeypatch):
    monkeypatch.chdir(tree / "real")
    assert SI.same_entry(LocalFS(), "f.txt", LocalFS(), str(tree / "alias" / "f.txt"))
    assert not SI.same_entry(LocalFS(), "f.txt", LocalFS(), "g.txt")


def test_edge_the_umask_is_read_anew_on_every_call():
    old = os.umask(0o027)
    try:
        assert process_umask() == 0o027
        assert copy_mode(0o100666) == 0o640
        os.umask(0o002)
        assert process_umask() == 0o002
        assert copy_mode(0o100666) == 0o664
    finally:
        os.umask(old)


def test_sad_without_proc_the_umask_comes_from_the_fallback(monkeypatch):
    import core.transfer_worker as TW

    real_open = os.open

    def no_proc(path, *a, **k):
        if str(path).startswith("/proc/"):
            raise FileNotFoundError(path)
        return real_open(path, *a, **k)

    monkeypatch.setattr(os, "open", no_proc)
    monkeypatch.setattr(TW, "_FALLBACK_UMASK", None)
    old = os.umask(0o022)
    try:
        assert process_umask() == 0o022
    finally:
        os.umask(old)


def test_happy_the_transfer_table_fits_from_a_sample_of_rows():
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])  # noqa: F841 - kept alive
    from PyQt6.QtCore import QObject, pyqtSignal

    from ui.transfer_dock import TABLE_FIT_ROWS, TransferDock

    class _Signals(QObject):
        job_added = pyqtSignal(object)
        job_updated = pyqtSignal(str)
        job_finished = pyqtSignal(str)
        job_error = pyqtSignal(str, str)

        def all_jobs(self):
            return []

    dock = TransferDock(_Signals())
    try:
        header = dock._table.horizontalHeader()
        assert header.resizeContentsPrecision() == TABLE_FIT_ROWS == 100
    finally:
        dock.close()
