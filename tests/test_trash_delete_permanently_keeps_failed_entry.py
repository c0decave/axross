"""Delete Permanently in the Trash window keeps an entry it could not delete.

Before: ``TrashBrowserDialog._do_delete_permanent`` removed the data and
then the ``.meta.json`` sidecar regardless - also when removing the data
failed (a read-only folder inside, a server refusing the delete). The
entry vanished from the Trash window while its data was still in the
trash folder, and Empty Trash keeps data without a sidecar for good:
hidden, never deleted.

Now both go through ``core.trash.delete_entry``, the per-entry code that
``empty_trash`` uses since round 1: the data first, the sidecar only once
the data is gone. A failed entry stays listed, and the error is shown.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QCoreApplication  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _StuckFS(LocalFS):
    """Refuses to remove trash data (the sidecar goes)."""

    def remove(self, path, recursive=False):
        if ".axross-trash" in path and not path.endswith(T.META_SUFFIX):
            raise PermissionError(13, "Permission denied", path)
        return super().remove(path, recursive)


def _trashed(fs, tmp_path, monkeypatch, *, folder: bool = True):
    monkeypatch.setenv("HOME", str(tmp_path))
    victim = tmp_path / "w" / "proj"
    if folder:
        (victim / "sub").mkdir(parents=True)
        (victim / "sub" / "a.txt").write_text("x")
    else:
        victim.parent.mkdir(parents=True)
        victim.write_text("x")
    root = str(tmp_path / ".axross-trash")
    trash_id = T.trash(fs, str(victim), root=root, journal=False)
    return trash_id, root


def test_sad_delete_entry_keeps_the_sidecar_when_the_data_stays(tmp_path, monkeypatch):
    fs = _StuckFS()
    trash_id, root = _trashed(fs, tmp_path, monkeypatch)
    with pytest.raises(OSError):
        T.delete_entry(fs, trash_id, root=root)
    assert [e.trash_id for e in T.list_trash(fs, root=root)] == [trash_id]


def test_happy_delete_entry_removes_data_and_sidecar(tmp_path, monkeypatch):
    fs = LocalFS()
    for folder in (True, False):
        trash_id, root = _trashed(fs, tmp_path / str(folder), monkeypatch, folder=folder)
        assert T.delete_entry(fs, trash_id, root=root) is True
        assert T.list_trash(fs, root=root) == []
        assert os.listdir(root) == []


def test_sad_the_trash_window_keeps_listing_an_entry_it_could_not_delete(
        tmp_path, monkeypatch):
    from ui.trash_browser import TrashBrowserDialog

    fs = _StuckFS()
    trash_id, root = _trashed(fs, tmp_path, monkeypatch)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    warnings: list = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warnings.append(a[2]))
    dlg = TrashBrowserDialog(fs)
    assert dlg._trash_root() == root  # the home of this test
    deadline = time.monotonic() + 5
    while dlg.loading and time.monotonic() < deadline:
        QCoreApplication.processEvents()
    dlg._table.selectRow(0)
    dlg._do_delete_permanent()
    deadline = time.monotonic() + 5
    while (dlg.busy or dlg.loading) and time.monotonic() < deadline:
        QCoreApplication.processEvents()
    assert [e.trash_id for e in T.list_trash(fs, root=root)] == [trash_id]
    assert len(warnings) == 1 and "Permission denied" in warnings[0]
    dlg.close()
    dlg.deleteLater()
