"""Tagging many selected files writes tags.json once, not once per file.

``FilePaneWidget.toggle_tag`` and ``new_tag_for_selection`` called
``TagStore.tag`` / ``untag`` per selected path, and each call rewrote the
whole file: tagging 3000 selected files serialised 4.5 million entries
(6 s of CPU on the GUI thread, measured). ``tag_many`` / ``untag_many`` do
the same changes with one write; the file they leave is byte for byte the
one the per-path calls left, and their errors are the per-path calls'.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import tags as T  # noqa: E402


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "tags.json"
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    yield T.store()
    T.reset_cache()


def _counted(store):
    return mock.patch.object(store, "_save", wraps=store._save)


def _sequential_file(tmp_path, steps) -> bytes:
    """The file the former per-path calls leave after *steps*."""
    reference = T.TagStore(tmp_path / "reference.json")
    for method, args in steps:
        getattr(reference, method)(*args)
    return (tmp_path / "reference.json").read_bytes()


PATHS = [f"/srv/data/file{i:03d}.txt" for i in range(60)]


class TestTagMany:
    def test_happy_one_write_and_the_per_path_file(self, store, tmp_path):
        with mock.patch("core.tags.time.time", return_value=1000.0):
            store.tag("Local", "", PATHS[5], "Review later")  # an entry that exists already
            with _counted(store) as save:
                store.tag_many("Local", "nas", PATHS, "Important")
            expected = _sequential_file(tmp_path, [
                ("tag", ("Local", "", PATHS[5], "Review later")),
                *(("tag", ("Local", "nas", p, "Important")) for p in PATHS)])
        assert save.call_count == 1
        assert (tmp_path / "tags.json").read_bytes() == expected

    def test_happy_untag_many_one_write_and_the_per_path_file(self, store, tmp_path):
        with mock.patch("core.tags.time.time", return_value=5.0):
            store.tag_many("Local", "", PATHS, "Important")
            store.tag("Local", "", PATHS[0], "Review later")
        with _counted(store) as save:
            store.untag_many("Local", PATHS[:40], "Important")
        assert save.call_count == 1
        with mock.patch("core.tags.time.time", return_value=5.0):
            expected = _sequential_file(tmp_path, [
                *(("tag", ("Local", "", p, "Important")) for p in PATHS),
                ("tag", ("Local", "", PATHS[0], "Review later")),
                *(("untag", ("Local", p, "Important")) for p in PATHS[:40])])
        assert (tmp_path / "tags.json").read_bytes() == expected
        assert store.tags_of("Local", PATHS[0]) == ["Review later"]
        assert store.tags_of("Local", PATHS[1]) == []
        assert store.tags_of("Local", PATHS[59]) == ["Important"]

    def test_sad_an_unknown_tag_raises_and_writes_nothing(self, store, tmp_path):
        with _counted(store) as save, pytest.raises(KeyError):
            store.tag_many("Local", "", PATHS, "Nope")
        assert save.call_count == 0 and store.items_with("Important") == []
        assert not (tmp_path / "tags.json").exists()

    def test_sad_a_failed_write_raises_like_the_per_path_call(self, store, tmp_path):
        store.tag("Local", "", "/before", "Important")
        before = (tmp_path / "tags.json").read_bytes()
        with mock.patch("core.tags.tempfile.mkstemp", side_effect=OSError("disk full")):
            with pytest.raises(OSError, match="disk full"):
                store.tag_many("Local", "", PATHS, "Important")
            with pytest.raises(OSError, match="disk full"):
                store.untag_many("Local", ["/before"], "Important")
        assert (tmp_path / "tags.json").read_bytes() == before

    def test_edge_the_item_ceiling_keeps_what_fitted_and_raises(self, store, tmp_path, monkeypatch):
        monkeypatch.setattr(T, "MAX_ITEMS", 10)
        with _counted(store) as save, pytest.raises(ValueError, match="more than 10"):
            store.tag_many("Local", "", PATHS, "Important")
        assert save.call_count == 1
        T.reset_cache()
        again = T.TagStore(tmp_path / "tags.json")
        assert [e.path for e in again.items_with("Important")] == PATHS[:10]

    def test_edge_nothing_to_change_writes_nothing(self, store):
        store.tag_many("Local", "", PATHS[:3], "Important")
        with _counted(store) as save:
            store.tag_many("Local", "", [], "Important")
            store.tag_many("Local", "", PATHS[:3], "Important")  # all have it already
            store.untag_many("Local", [], "Important")
            store.untag_many("Local", PATHS[10:20], "Important")  # none has it
        assert save.call_count == 0

    def test_edge_a_profile_is_remembered_even_without_a_new_tag(self, store, tmp_path):
        """tag() takes the profile of a file that already carries the tag
        (in memory, written with the next change) - so does tag_many."""
        store.tag("alice@nas", "", "/x", "Important")
        store.tag_many("alice@nas", "nas", ["/x"], "Important")
        assert store.items_with("Important")[0].profile_name == "nas"

    def test_edge_a_path_listed_twice_is_tagged_once(self, store):
        store.tag_many("Local", "", ["/a", "/a", "/b"], "Important")
        assert [e.path for e in store.items_with("Important")] == ["/a", "/b"]
        assert store.tags_of("Local", "/a") == ["Important"]


# -- the pane ------------------------------------------------------------------------


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    for i in range(40):
        (d / f"f{i:02d}.txt").write_text("x")
    return d


def _window(tmp_path):
    from ui import main_window as MW

    patches = [
        mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"),
        mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"),
        mock.patch("pathlib.Path.home", return_value=tmp_path),
    ]
    for p in patches:
        p.start()
    try:
        return MW.MainWindow()
    finally:
        for p in patches:
            p.stop()


def test_e2e_tagging_and_untagging_forty_selected_files_writes_twice(store, tmp_path, folder):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        app.processEvents()
        pane._table.selectAll()
        selected = pane.selected_items()
        assert len(selected) == 40
        with _counted(store) as save:
            pane.toggle_tag("Important")
            assert save.call_count == 1
            assert sorted(e.path for e in store.items_with("Important")) == sorted(selected)
            pane.toggle_tag("Important")  # all carry it: off again
            assert save.call_count == 2
        assert store.items_with("Important") == []
        started = time.process_time()
        with mock.patch("ui.tag_ui.ask_new_tag", return_value=store.define("Case 9", "#00aa00")), \
                _counted(store) as save:
            pane.new_tag_for_selection()
        assert save.call_count == 1
        assert sorted(e.path for e in store.items_with("Case 9")) == sorted(selected)
        assert time.process_time() - started < 5
    finally:
        win.close()
        win.deleteLater()
