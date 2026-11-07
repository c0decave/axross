"""The Duplicate Finder finds identical folders.

Feedback: a flag "identical folders" - recursively the same relative paths
and names, each file with the same hash; the folder's own name may differ.
Context menu: open in pane, bookmark, delete.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import cas as CAS  # noqa: E402
from core import cas_folders as CF  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _tree(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


PHOTOS = {"a.jpg": b"A", "sub/b.jpg": b"B", "sub/deeper/c.txt": b"C"}


@pytest.fixture
def index(tmp_path):
    db = tmp_path / "cas.sqlite"
    data = tmp_path / "data"
    _tree(data / "photos", PHOTOS)
    _tree(data / "backup" / "photos-2024", PHOTOS)  # another name, same content
    _tree(data / "other", {"a.jpg": b"A", "sub/b.jpg": b"B"})  # one file less
    _tree(data / "renamed", {"a.jpg": b"A", "sub/b2.jpg": b"B", "sub/deeper/c.txt": b"C"})
    CAS.rebuild(LocalFS(), str(data), backend_id="local", db_path=db)
    return db, data


def _paths(group) -> list[str]:
    return [copy.path for copy, _entries in group]


def test_happy_same_structure_and_content_is_one_group(index):
    db, data = index
    groups = CF.identical_folders(db)
    assert [_paths(g) for g in groups] == [
        [str(data / "backup" / "photos-2024"), str(data / "photos")],
        # "renamed" differs in sub/, but its sub/deeper is a third copy
        [str(data / "backup" / "photos-2024" / "sub" / "deeper"),
         str(data / "photos" / "sub" / "deeper"), str(data / "renamed" / "sub" / "deeper")],
    ]
    copy, entries = groups[0][0]
    assert copy.files == 3 and copy.size == 3 and len(entries) == 3


def test_edge_nested_matches_show_only_the_outermost(index):
    """photos/sub == photos-2024/sub too, but that is inside the match."""
    db, data = index
    names = {p for g in CF.identical_folders(db) for p in _paths(g)}
    assert str(data / "photos" / "sub") not in names


def test_sad_a_folder_above_the_scanned_part_is_not_compared(tmp_path):
    db = tmp_path / "cas.sqlite"
    _tree(tmp_path / "a" / "x", {"f": b"1"})
    _tree(tmp_path / "b" / "x", {"f": b"1"})
    (tmp_path / "a" / "unscanned.txt").write_bytes(b"only in a")
    CAS.rebuild(LocalFS(), str(tmp_path / "a" / "x"), backend_id="local", db_path=db)
    CAS.rebuild(LocalFS(), str(tmp_path / "b" / "x"), backend_id="local", db_path=db)
    groups = CF.identical_folders(db)
    # a/x and b/x are the scan roots - their parents a and b were never
    # scanned whole and must not show as copies.
    assert [_paths(g) for g in groups] == [[str(tmp_path / "a" / "x"), str(tmp_path / "b" / "x")]]


def test_sad_a_cancelled_scan_does_not_count(tmp_path):
    db = tmp_path / "cas.sqlite"
    _tree(tmp_path / "p", PHOTOS)
    _tree(tmp_path / "q", PHOTOS)
    CAS.rebuild(LocalFS(), str(tmp_path), backend_id="local", db_path=db)
    with CAS._connect(db) as conn:
        conn.execute("UPDATE scans SET status=?", (CAS.SCAN_CANCELLED,))
    assert CF.identical_folders(db) == []


def test_happy_trash_a_verified_copy(index, tmp_path):
    db, data = index
    group = CF.identical_folders(db)[0]
    keep, remove = group[1], group[0]  # keep photos, remove backup/photos-2024
    outcome = CF.trash_identical_folder({"local": LocalFS()}, remove, keep, db_path=db,
                                        trash_root=str(tmp_path))
    assert outcome.removed, outcome.reason
    assert not (data / "backup" / "photos-2024").exists()
    assert (data / "photos" / "sub" / "deeper" / "c.txt").read_bytes() == b"C"
    assert [_paths(g) for g in CF.identical_folders(db)] == [
        [str(data / "photos" / "sub" / "deeper"), str(data / "renamed" / "sub" / "deeper")]]


@pytest.mark.parametrize("change", ["extra", "edited", "kept-edited", "link"])
def test_sad_a_folder_that_changed_is_refused(index, tmp_path, change):
    db, data = index
    group = CF.identical_folders(db)[0]
    keep, remove = group[1], group[0]
    gone = data / "backup" / "photos-2024"
    if change == "extra":
        (gone / "new.txt").write_bytes(b"new since indexing")
    elif change == "edited":
        (gone / "a.jpg").write_bytes(b"Z")
    elif change == "kept-edited":
        (data / "photos" / "sub" / "b.jpg").write_bytes(b"Z")
    else:
        os.symlink(str(data / "photos"), str(gone / "loop"))
    outcome = CF.trash_identical_folder({"local": LocalFS()}, remove, keep, db_path=db,
                                        trash_root=str(tmp_path))
    assert not outcome.removed and outcome.reason
    assert gone.exists()


def test_sad_without_the_backend_nothing_is_removed(index, tmp_path):
    db, data = index
    group = CF.identical_folders(db)[0]
    outcome = CF.trash_identical_folder({}, group[0], group[1], db_path=db)
    assert not outcome.removed
    assert (data / "backup" / "photos-2024").exists()


def test_edge_folder_scope(index):
    db, data = index
    assert CF.identical_folders(db, folder=str(data / "backup")) == []
    assert len(CF.identical_folders(db, folder=str(data))) == 2
    assert CF.identical_folders(db, folder=str(data / "photos")) == []


def test_edge_ancestors_stop_at_the_root():
    got = list(CF._ancestors("/r/a/b/f.txt", "/r"))
    assert got == [("/r/a/b", "f.txt"), ("/r/a", "b/f.txt"), ("/r", "a/b/f.txt")]
    assert list(CF._ancestors("/f.txt", "/")) == [("/", "f.txt")]


# -- the dialog --------------------------------------------------------------------------------


@pytest.fixture
def dialog(index, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    db, data = index
    monkeypatch.setattr(CAS, "_DEFAULT_DB", db)
    from ui.cas_dialog import CasDuplicatesDialog

    d = CasDuplicatesDialog(backends=[LocalFS()])
    d._app = app
    yield d, data
    d.deleteLater()


def _wait(app, cond, seconds=10.0):
    import time

    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def test_happy_the_dialog_lists_identical_folders_and_opens_one(dialog):
    from PyQt6.QtCore import Qt

    d, data = dialog
    d._folders_check.setChecked(True)
    tree = d._tree
    assert tree.topLevelItemCount() == 2
    top = tree.topLevelItem(0)
    assert top.text(0).startswith("2 identical folders")
    opened = []
    d.open_folder_requested.connect(lambda bid, path: opened.append(path))
    d._on_double_click(top.child(1), 0)
    assert opened == [str(data / "photos")]
    actions = [a.text() for a in d.build_context_menu(top.child(0)).actions()]
    assert "Open in Pane" in actions and "Bookmark Folder…" in actions
    assert top.child(0).data(0, Qt.ItemDataRole.UserRole)[0] == "folder"
    d._folders_check.setChecked(False)
    assert all(tree.topLevelItem(i).text(0).startswith("[sha256]")
               for i in range(tree.topLevelItemCount()))


def test_happy_trash_from_the_dialog_keeps_the_unselected_folder(dialog, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox

    d, data = dialog
    d._backends = {"local": LocalFS()}
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    shown = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    import core.trash as T

    real = T.trash
    monkeypatch.setattr(T, "trash", lambda b, p, root=None, **k: real(b, p, root=str(data.parent)))
    d._folders_check.setChecked(True)
    top = d._tree.topLevelItem(0)
    top.child(0).setSelected(True)  # backup/photos-2024
    d._trash_selected_folders()
    assert _wait(d._app, lambda: shown)
    assert "1 folder(s) moved" in shown[0]
    assert not (data / "backup" / "photos-2024").exists()
    assert (data / "photos").exists()
