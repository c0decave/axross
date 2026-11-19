"""Batch Rename takes the tags along.

Review: a tagged file renamed through Batch Rename had no tag under its
new name (F2 rename moves them, core.tags rename_path). Now each entry
that was renamed takes its tags along - also in a chain a -> b, b -> c,
where moving them one by one would hand a's tags to c.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import tags as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "tags.json"
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    yield T.store()
    T.reset_cache()


def _dialog(folder: Path, names: list[str]):
    from ui.batch_rename_dialog import BatchRenameDialog

    fs = LocalFS()
    items = [i for i in fs.list_dir(str(folder)) if i.name in names]
    return fs, BatchRenameDialog(fs, str(folder), items)


def test_happy_a_renamed_file_keeps_its_tags(tmp_path, store):
    folder = tmp_path / "d"
    folder.mkdir()
    (folder / "report.txt").write_text("x")
    (folder / "other.txt").write_text("y")
    store.define("review", "#ff0000")
    fs = LocalFS()
    store.tag_many(fs.name, "", [str(folder / "report.txt")], "review")
    fs, dlg = _dialog(folder, ["report.txt", "other.txt"])
    dlg._find_edit.setText("report")
    dlg._replace_edit.setText("summary")
    dlg._apply()
    assert (folder / "summary.txt").exists()
    assert store.tags_of(fs.name, str(folder / "summary.txt")) == ["review"]
    assert store.tags_of(fs.name, str(folder / "report.txt")) == []


def test_edge_a_chain_of_renames_keeps_each_files_own_tags(tmp_path, store):
    """x -> xx while xx -> xxx: moved one after the other, x's tags
    would land on xx and then go on to xxx with xx's."""
    folder = tmp_path / "d"
    folder.mkdir()
    for name in ("x", "xx"):
        (folder / name).write_text(name)
    store.define("one", "#ff0000")
    store.define("two", "#00ff00")
    fs = LocalFS()
    store.tag_many(fs.name, "", [str(folder / "x")], "one")
    store.tag_many(fs.name, "", [str(folder / "xx")], "two")
    fs, dlg = _dialog(folder, ["x", "xx"])
    dlg._case_sensitive.setChecked(True)
    dlg._replace_all.setChecked(False)
    dlg._find_edit.setText("x")
    dlg._replace_edit.setText("xx")
    assert dict(dlg._compute_new_names()) == {"x": "xx", "xx": "xxx"}
    dlg._apply()
    assert (folder / "xx").read_text() == "x" and (folder / "xxx").read_text() == "xx"
    assert store.tags_of(fs.name, str(folder / "xx")) == ["one"]
    assert store.tags_of(fs.name, str(folder / "xxx")) == ["two"]
    assert store.tags_of(fs.name, str(folder / "x")) == []
