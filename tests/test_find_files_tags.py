"""Find Files filtered by a tag (punch-list item 14 meets 51).

Decided for item 14: coloured tags on any file, *filterable in pane and
search*. The pane has its ``tag:`` filter; here the Find Files dialog gets a
Tag choice, and a Smart Folder keeps it.
"""

from __future__ import annotations

import io
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import file_search as FS  # noqa: E402
from core import tags as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.search_federation import SearchQuery  # noqa: E402
from ui import find_files_dialog as FD  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(T, "tags_file", lambda: tmp_path / "tags.json")
    T.reset_cache()
    yield T.store()
    T.reset_cache()


@pytest.fixture
def folder(tmp_path):
    root = tmp_path / "data"
    (root / "sub").mkdir(parents=True)
    for name in ("a.txt", "b.txt", "sub/c.txt"):
        (root / name).write_text("x")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("inside.txt", "y")
    (root / "pack.zip").write_bytes(buf.getvalue())
    return root


def run(dlg) -> list[str]:
    dlg.start_search()
    end = time.time() + 20
    while (dlg.is_running or dlg._queue) and time.time() < end:
        APP.processEvents()
        time.sleep(0.02)
    APP.processEvents()
    return sorted(os.path.basename(h.archive_path or h.path) + (f"!{h.member}" if h.member else "")
                  for _s, h in dlg._rows)


def dialog(folder):
    dlg = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(folder))])
    dlg.name_edit.setText("*.txt")
    return dlg


# -- happy ------------------------------------------------------------------------------


def test_happy_only_files_with_the_tag(store, folder):
    store.tag("Local", "", str(folder / "a.txt"), "Important")
    store.tag("Local", "", str(folder / "sub" / "c.txt"), "Important")
    store.tag("Local", "", str(folder / "b.txt"), "Review later")
    dlg = dialog(folder)
    try:
        assert dlg.tag_combo.itemText(0) == "Any tag"
        assert [dlg.tag_combo.itemText(i) for i in range(1, dlg.tag_combo.count())] == \
            ["Important", "Review later"]
        assert run(dlg) == ["a.txt", "b.txt", "c.txt"]
        dlg.tag_combo.setCurrentText("Important")
        assert run(dlg) == ["a.txt", "c.txt"]
    finally:
        dlg.close()


def test_happy_a_smart_folder_keeps_the_tag(store, folder):
    store.tag("Local", "", str(folder / "a.txt"), "Important")
    dlg = dialog(folder)
    saved = []
    dlg.save_smart_folder_requested.connect(lambda name, data: saved.append(data))
    try:
        dlg.tag_combo.setCurrentText("Important")
        assert dlg.save_as_smart_folder("tagged")
        assert saved[0]["tag"] == "Important"
    finally:
        dlg.close()
    again = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(folder))], saved=saved[0])
    try:
        assert again.tag_combo.currentText() == "Important"
        assert run(again) == ["a.txt"]
    finally:
        again.close()


def test_happy_saved_search_round_trip_in_core():
    data = FS.saved_search_to_dict(SearchQuery(name="*.txt"), [], tag="Review later")
    _q, _s, options = FS.saved_search_from_dict(data)
    assert options == {"use_index": False, "tag": "Review later"}


# -- sad --------------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [3, "x" * (T.MAX_NAME + 1), "a\nb"])
def test_sad_a_damaged_tag_is_refused(bad):
    data = FS.saved_search_to_dict(SearchQuery(name="*"), [])
    data["tag"] = bad
    with pytest.raises(ValueError, match="tag"):
        FS.saved_search_from_dict(data)
    with pytest.raises(ValueError, match="tag"):
        FS.saved_search_to_dict(SearchQuery(name="*"), [], tag=bad)


def test_sad_a_tag_that_no_longer_exists(store, folder):
    data = FS.saved_search_to_dict(SearchQuery(name="*.txt"), [], tag="Gone")
    dlg = FD.FindFilesDialog([FD.ScopeChoice(LocalFS(), str(folder))], saved=data)
    try:
        assert dlg.tag_combo.currentText() == "Gone"  # kept, so nothing untagged slips in
        assert run(dlg) == []
    finally:
        dlg.close()


# -- edge -------------------------------------------------------------------------------


def test_edge_an_archive_member_counts_with_its_archive_tag(store, folder):
    store.tag("Local", "", str(folder / "pack.zip"), "Important")
    dlg = dialog(folder)
    try:
        dlg.archives_box.setChecked(True)
        dlg.tag_combo.setCurrentText("Important")
        assert run(dlg) == ["pack.zip!inside.txt"]
    finally:
        dlg.close()


def test_edge_older_saved_searches_have_no_tag():
    data = FS.saved_search_to_dict(SearchQuery(name="*"), [])
    del data["tag"]
    assert FS.saved_search_from_dict(data)[2]["tag"] == ""


# -- round-2 verification ---------------------------------------------------------------


def test_edge_untagged_matches_do_not_use_up_the_hit_limit(store, tmp_path, monkeypatch):
    """The tag decides before a hit counts: with many untagged files that
    match the rest of the query, the tagged one must still be found, and the
    status line must count only what is shown."""
    import dataclasses

    @dataclasses.dataclass
    class SmallLimits(FS.SearchLimits):
        max_hits: int = 3

    monkeypatch.setattr(FS, "SearchLimits", SmallLimits)
    monkeypatch.setattr(FS, "find_tool", lambda name: None)  # sorted walk: z.txt comes last
    root = tmp_path / "many"
    root.mkdir()
    for i in range(10):
        (root / f"a{i}.txt").write_text("x")
    (root / "z.txt").write_text("x")
    store.tag("Local", "", str(root / "z.txt"), "Important")
    dlg = dialog(root)
    try:
        dlg.tag_combo.setCurrentText("Important")
        assert run(dlg) == ["z.txt"]
        assert dlg.status_label.text().startswith("1 found")
        assert "limit" not in dlg.status_label.text()
    finally:
        dlg.close()


def test_edge_offline_index_hits_follow_the_tag_too(store, tmp_path):
    """Index hits are named by the index's backend id ("LocalFS:Local"); the
    tag filter applies to them like to every other hit."""
    from core import metadata_index as MX

    db = tmp_path / "index.sqlite"
    for name in ("kept.txt", "other.txt"):
        MX.upsert(db, "LocalFS:Local", f"/gone/{name}", name=name, size=1, is_dir=False)
    store.tag("Local", "", "/gone/kept.txt", "Important")
    dlg = FD.FindFilesDialog([], index_db=db)
    try:
        dlg.name_edit.setText("*.txt")
        dlg.index_box.setChecked(True)
        assert run(dlg) == ["kept.txt", "other.txt"]
        dlg.tag_combo.setCurrentText("Important")
        assert run(dlg) == ["kept.txt"]
    finally:
        dlg.close()
