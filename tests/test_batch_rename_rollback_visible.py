"""Batch rename never leaves a file under a hidden temporary name.

When the final rename of one entry fails and its original name has
meanwhile been taken by another entry of the same batch (a chain such
as ``a -> b``, ``b -> c``), the rollback cannot restore the original
name. The file must then land under a visible name next to it, and the
error report must say where it went.
"""

from __future__ import annotations

import os

import pytest
from PyQt6.QtWidgets import QApplication, QMessageBox

from core.local_fs import LocalFS
from models.file_item import FileItem
from ui.batch_rename_dialog import BatchRenameDialog


class _FailingRenameFS(LocalFS):
    """LocalFS whose rename into one chosen leaf name fails."""

    def __init__(self, fail_leaf: str, fail_also: tuple[str, ...] = ()):
        super().__init__()
        self._fail = {fail_leaf, *fail_also}

    def rename(self, src: str, dst: str) -> None:
        if os.path.basename(dst) in self._fail:
            raise OSError(f"simulated failure renaming into {os.path.basename(dst)}")
        super().rename(src, dst)


class _Holder:
    """Keeps dialogs alive for the test and closes them afterwards."""

    def __init__(self):
        self._widgets = []

    def addWidget(self, widget):  # noqa: N802 - mirrors the qtbot name
        self._widgets.append(widget)

    def close_all(self):
        for widget in self._widgets:
            widget.close()
            widget.deleteLater()


_APP: list = []


@pytest.fixture
def qtbot():
    if not _APP:
        _APP.append(QApplication.instance() or QApplication([]))
    holder = _Holder()
    yield holder
    holder.close_all()


def _make(tmp_path, names):
    for name in names:
        (tmp_path / name).write_text(name)
    return [FileItem(name=n) for n in names]


def _run(qtbot, backend, tmp_path, items, find, replace, monkeypatch):
    warnings: list[str] = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda _parent, _title, text, *a, **k: warnings.append(text)),
    )
    dlg = BatchRenameDialog(backend, str(tmp_path), items)
    qtbot.addWidget(dlg)
    dlg._find_edit.setText(find)
    dlg._replace_edit.setText(replace)
    dlg._apply()
    return warnings


def _hidden_leftovers(tmp_path):
    return sorted(p.name for p in tmp_path.iterdir() if ".rename-" in p.name)


def test_chain_failure_with_taken_rollback_name_lands_visible(qtbot, tmp_path, monkeypatch):
    # "a1" -> "a2" succeeds; "a2" -> "a3" fails; "a2" is now taken by
    # the former "a1", so the original "a2" content cannot go back.
    items = _make(tmp_path, ["a1", "a2"])
    backend = _FailingRenameFS("a3")
    warnings: list[str] = []
    dlg = BatchRenameDialog(backend, str(tmp_path), items)
    qtbot.addWidget(dlg)
    monkeypatch.setattr(
        dlg, "_compute_new_names", lambda: [("a1", "a2"), ("a2", "a3")],
    )
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda _parent, _title, text, *a, **k: warnings.append(text)),
    )
    dlg._apply()

    assert _hidden_leftovers(tmp_path) == []
    assert (tmp_path / "a2").read_text() == "a1"
    recovered = [p for p in tmp_path.iterdir() if p.read_text() == "a2"]
    assert len(recovered) == 1
    assert not recovered[0].name.startswith(".")
    assert warnings and recovered[0].name in warnings[0]


def test_failure_with_free_rollback_name_restores_original(qtbot, tmp_path, monkeypatch):
    items = _make(tmp_path, ["x1"])
    backend = _FailingRenameFS("x2")
    warnings = _run(qtbot, backend, tmp_path, items, "x1", "x2", monkeypatch)
    assert _hidden_leftovers(tmp_path) == []
    assert (tmp_path / "x1").read_text() == "x1"
    assert len(warnings) == 1 and "x1" in warnings[0]


def test_successful_batch_leaves_no_temp_files(qtbot, tmp_path, monkeypatch):
    items = _make(tmp_path, ["f1.txt", "f2.txt"])
    warnings = _run(qtbot, LocalFS(), tmp_path, items, ".txt", ".md", monkeypatch)
    assert warnings == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f1.md", "f2.md"]


def test_recovery_name_also_failing_reports_hidden_name(qtbot, tmp_path, monkeypatch):
    # Edge: even the visible recovery rename fails. The file stays under
    # the temporary name, but the report must name that exact path so
    # the user can find it.
    items = _make(tmp_path, ["b1", "b2"])
    backend = _FailingRenameFS("b3", fail_also=("b2 (1)",))
    warnings: list[str] = []
    monkeypatch.setattr(
        QMessageBox, "warning",
        staticmethod(lambda _parent, _title, text, *a, **k: warnings.append(text)),
    )
    dlg = BatchRenameDialog(backend, str(tmp_path), items)
    qtbot.addWidget(dlg)
    monkeypatch.setattr(dlg, "_compute_new_names", lambda: [("b1", "b2"), ("b2", "b3")])
    dlg._apply()
    leftovers = _hidden_leftovers(tmp_path)
    assert len(leftovers) == 1
    assert warnings and leftovers[0] in warnings[0]
