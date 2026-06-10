"""Tests for the archive-preview pane (Task A3).

The headless Qt platform MUST be selected BEFORE PyQt6 is imported,
otherwise instantiating widgets on a CI box with no display aborts the
process. A single shared :class:`QApplication` is created for the whole
module (Qt forbids more than one).
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import zipfile

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QTreeView

import core.archive as archive_mod
from core.archive import ArchiveEntry, RarUnavailable
from ui.archive_pane import (
    COL_NAME,
    ArchivePaneWidget,
    build_archive_tree,
    selected_member_names,
)

# One QApplication for the module; reuse any pre-existing instance.
APP = QApplication.instance() or QApplication([])


# --------------------------------------------------------------------------
# Fixtures / helpers
# --------------------------------------------------------------------------


def _sample_entries() -> list[ArchiveEntry]:
    """Flat member list exercising implied + explicit directories."""
    return [
        ArchiveEntry(name="top.txt", size=100, compressed=40, mtime=None, is_dir=False),
        ArchiveEntry(name="d/a.txt", size=200, compressed=50, mtime=None, is_dir=False),
        ArchiveEntry(name="d/sub/b.txt", size=300, compressed=60, mtime=None, is_dir=False),
        ArchiveEntry(name="e/", size=0, compressed=0, mtime=None, is_dir=True),
    ]


def _name_item_at(model, row: int, parent_item=None):
    """Return the Name QStandardItem at *row* under *parent_item* (or the
    invisible root when None)."""
    if parent_item is None:
        return model.item(row, COL_NAME)
    return parent_item.child(row, COL_NAME)


def _find_child(parent_item, label: str):
    """Find a direct child Name item by visible label."""
    for r in range(parent_item.rowCount()):
        child = parent_item.child(r, COL_NAME)
        if child is not None and child.text() == label:
            return child
    return None


def _find_top(model, label: str):
    """Find a top-level (root) Name item by visible label."""
    for r in range(model.rowCount()):
        item = model.item(r, COL_NAME)
        if item is not None and item.text() == label:
            return item
    return None


# --------------------------------------------------------------------------
# build_archive_tree
# --------------------------------------------------------------------------


def test_build_archive_tree_hierarchy_and_implied_dirs():
    model = build_archive_tree(_sample_entries())

    # Top-level rows: top.txt (file), d (implied folder), e (explicit folder).
    assert model.rowCount() == 3

    top = _find_top(model, "top.txt")
    d = _find_top(model, "d")
    e = _find_top(model, "e")
    assert top is not None and d is not None and e is not None

    # top.txt is a file row carrying its full member name in UserRole.
    assert top.data(Qt.ItemDataRole.UserRole) == "top.txt"
    assert top.rowCount() == 0

    # d was IMPLIED (no explicit d/ entry) yet created as a folder, with
    # its dir prefix on the UserRole.
    assert d.data(Qt.ItemDataRole.UserRole) == "d/"
    # d has child a.txt and subfolder sub.
    a = _find_child(d, "a.txt")
    sub = _find_child(d, "sub")
    assert a is not None and sub is not None
    assert d.rowCount() == 2

    # a.txt full member name recoverable from UserRole.
    assert a.data(Qt.ItemDataRole.UserRole) == "d/a.txt"

    # sub was implied too; holds b.txt.
    assert sub.data(Qt.ItemDataRole.UserRole) == "d/sub/"
    b = _find_child(sub, "b.txt")
    assert b is not None
    assert sub.rowCount() == 1
    assert b.data(Qt.ItemDataRole.UserRole) == "d/sub/b.txt"

    # Explicit empty dir e/ became a folder row with no children.
    assert e.data(Qt.ItemDataRole.UserRole) == "e/"
    assert e.rowCount() == 0

    # Five columns.
    assert model.columnCount() == 5


def test_build_archive_tree_size_and_ratio_formatting():
    model = build_archive_tree(
        [ArchiveEntry(name="x.bin", size=2048, compressed=512, mtime=None, is_dir=False)]
    )
    row = 0
    name = model.item(row, COL_NAME)
    assert name.text() == "x.bin"
    # 2048 bytes -> "2.0 KiB"; ratio 1 - 512/2048 = 0.75 -> "75%".
    size_cell = model.item(row, 1)
    ratio_cell = model.item(row, 3)
    assert size_cell.text() == "2.0 KiB"
    assert ratio_cell.text() == "75%"


# --------------------------------------------------------------------------
# selected_member_names
# --------------------------------------------------------------------------


def _view_for(entries):
    model = build_archive_tree(entries)
    view = QTreeView()
    view.setModel(model)
    view.expandAll()
    return view, model


def test_selected_member_names_folder_returns_descendant_files():
    view, model = _view_for(_sample_entries())
    d = _find_top(model, "d")
    assert d is not None

    sel = view.selectionModel()
    sel.select(
        d.index(),
        sel.SelectionFlag.ClearAndSelect | sel.SelectionFlag.Rows,
    )

    got = selected_member_names(view)
    # Folder d -> all descendant FILES, de-duped, order-insensitive.
    assert set(got) == {"d/a.txt", "d/sub/b.txt"}
    # The folder prefix itself must NOT appear.
    assert "d/" not in got


def test_selected_member_names_file_returns_itself():
    view, model = _view_for(_sample_entries())
    top = _find_top(model, "top.txt")
    assert top is not None

    sel = view.selectionModel()
    sel.select(
        top.index(),
        sel.SelectionFlag.ClearAndSelect | sel.SelectionFlag.Rows,
    )

    assert selected_member_names(view) == ["top.txt"]


def test_selected_member_names_dedup_folder_plus_descendant():
    view, model = _view_for(_sample_entries())
    d = _find_top(model, "d")
    a = _find_child(d, "a.txt")
    assert d is not None and a is not None

    sel = view.selectionModel()
    sel.select(d.index(), sel.SelectionFlag.Select | sel.SelectionFlag.Rows)
    sel.select(a.index(), sel.SelectionFlag.Select | sel.SelectionFlag.Rows)

    got = selected_member_names(view)
    # a.txt selected both directly and via folder d -> appears once.
    assert set(got) == {"d/a.txt", "d/sub/b.txt"}
    assert got.count("d/a.txt") == 1


# --------------------------------------------------------------------------
# ArchivePaneWidget — real zip
# --------------------------------------------------------------------------


def _make_zip(path: str) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("top.txt", b"hello top")
        zf.writestr("d/a.txt", b"a" * 200)
        zf.writestr("d/sub/b.txt", b"b" * 300)


def test_widget_populates_real_zip(tmp_path):
    zpath = str(tmp_path / "sample.zip")
    _make_zip(zpath)

    w = ArchivePaneWidget(zpath)
    assert w.load_error is None

    model = w._tree.model()
    assert model is not None
    # Top-level rows: top.txt + folder d.
    assert model.rowCount() >= 2
    assert model.columnCount() == 5

    # Selecting everything via the public accessor yields the 3 files.
    w._tree.selectAll()
    assert set(w.selected_members()) == {"top.txt", "d/a.txt", "d/sub/b.txt"}


def test_widget_graceful_rar_unavailable(tmp_path, monkeypatch):
    # Monkeypatch the symbol the widget actually calls (imported into the
    # ui.archive_pane namespace) so list_archive raises RarUnavailable.
    def _boom(_path):
        raise RarUnavailable("no unrar")

    monkeypatch.setattr("ui.archive_pane.list_archive", _boom)
    # Also patch the source module for completeness / defense in depth.
    monkeypatch.setattr(archive_mod, "list_archive", _boom, raising=True)

    w = ArchivePaneWidget(str(tmp_path / "x.rar"))
    assert w.load_error is not None
    assert "no unrar" in w.load_error

    model = w._tree.model()
    assert model is not None
    # Empty tree (header-only), no crash, no traceback.
    assert model.rowCount() == 0


def test_widget_graceful_corrupt_archive(tmp_path):
    # A .zip that isn't a real zip -> BadZipFile -> caught generically.
    bad = tmp_path / "broken.zip"
    bad.write_bytes(b"not a real zip at all")

    w = ArchivePaneWidget(str(bad))
    assert w.load_error is not None
    assert w._tree.model().rowCount() == 0


# --------------------------------------------------------------------------
# Signals
# --------------------------------------------------------------------------


def test_extract_selected_signal_emits_member_list(tmp_path):
    zpath = str(tmp_path / "sig.zip")
    _make_zip(zpath)
    w = ArchivePaneWidget(zpath)

    received: list[list[str]] = []
    w.extract_selected.connect(received.append)

    model = w._tree.model()
    d = _find_top(model, "d")
    assert d is not None
    sel = w._tree.selectionModel()
    sel.select(
        d.index(),
        sel.SelectionFlag.ClearAndSelect | sel.SelectionFlag.Rows,
    )

    # Trigger the "Auswahl extrahieren" button.
    w._btn_selected.click()

    assert len(received) == 1
    assert set(received[0]) == {"d/a.txt", "d/sub/b.txt"}


def test_extract_all_and_extract_to_signals(tmp_path):
    zpath = str(tmp_path / "sig2.zip")
    _make_zip(zpath)
    w = ArchivePaneWidget(zpath)

    fired: list[str] = []
    w.extract_all.connect(lambda: fired.append("all"))
    w.extract_to.connect(lambda: fired.append("to"))

    w._btn_all.click()
    w._btn_to.click()

    assert fired == ["all", "to"]


def test_open_member_signal_on_file_double_click(tmp_path):
    zpath = str(tmp_path / "dbl.zip")
    _make_zip(zpath)

    opened: list[str] = []
    w = ArchivePaneWidget(zpath, on_open_member=opened.append)

    received: list[str] = []
    w.open_member.connect(received.append)

    model = w._tree.model()
    top = _find_top(model, "top.txt")
    assert top is not None
    # Simulate a double-click on the file row.
    w._on_double_clicked(top.index())

    assert received == ["top.txt"]
    assert opened == ["top.txt"]


def test_double_click_folder_does_not_emit(tmp_path):
    zpath = str(tmp_path / "dbl2.zip")
    _make_zip(zpath)
    w = ArchivePaneWidget(zpath)

    received: list[str] = []
    w.open_member.connect(received.append)

    model = w._tree.model()
    d = _find_top(model, "d")
    assert d is not None
    w._on_double_clicked(d.index())

    assert received == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
