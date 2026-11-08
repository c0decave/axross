"""Duplicate Finder dialog: filters, sorting, keep rules, sizes, a live
window with thousands of groups, and a rebuild report that says what was
left out.

The request was to perfect the Duplicate Finder. Driven here on the real
dialog (offscreen):

* groups come largest waste first, each with the bytes it would free, and
  the status line sums them up;
* Filter (text or ``*.jpg`` patterns), "At least" (size) and Sort narrow
  and order the groups; empty files and hard-link-only groups are hidden
  unless asked;
* "Mark, Keeping…" and the context menu mark by rule: newest, shortest
  path, the copy inside a folder, or the copies inside a folder;
* thousands of groups: the first rows show at once, the rest are added a
  chunk per event-loop turn, and marking them all takes one selection
  change (one per row took seconds per thousand rows);
* the rebuild runs with byte counts and reports unreadable files, unlisted
  folders and files without a checksum; the delete shows "n of m";
* keyboard: Enter opens the containing folder, Ctrl+F goes to the filter.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import cas as CAS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests.markup_probe import shown  # noqa: E402

BID = "LocalFS:Local"


def _write(path: Path, data: bytes, mtime: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.utime(path, (mtime, mtime))
    return path


@pytest.fixture
def app():
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


@pytest.fixture
def boxes(monkeypatch):
    """Every QMessageBox / QInputDialog the finder opens, answered."""
    from PyQt6.QtWidgets import QInputDialog, QMessageBox

    seen: dict[str, list] = {"question": [], "information": [], "warning": [], "input": []}
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: (
        seen["question"].append(a[2]), QMessageBox.StandardButton.Yes)[1])
    for name in ("information", "warning"):
        monkeypatch.setattr(QMessageBox, name, lambda *a, _n=name, **k: seen[_n].append(a[2]))
    answer = {"text": "", "ok": True}

    def get_text(*a, **k):
        seen["input"].append(a[2])
        return answer["text"], answer["ok"]

    monkeypatch.setattr(QInputDialog, "getText", get_text)
    seen["answer"] = answer
    return seen


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """Three groups: big (2 x 3000 B), mid (3 x 1000 B), small (2 x 10 B);
    plus empty files and a hard link pair."""
    root = tmp_path / "tree"
    f = {
        "big_old": _write(root / "videos" / "clip.mp4", b"V" * 3000, 1000),
        "big_new": _write(root / "backup" / "clip.mp4", b"V" * 3000, 5000),
        "mid_a": _write(root / "photos" / "a.jpg", b"P" * 1000, 1000),
        "mid_b": _write(root / "downloads" / "a (1).jpg", b"P" * 1000, 2000),
        "mid_c": _write(root / "downloads" / "deep" / "er" / "a.jpg", b"P" * 1000, 3000),
        "small_a": _write(root / "notes.txt", b"n" * 10, 1000),
        "small_b": _write(root / "downloads" / "notes.txt", b"n" * 10, 2000),
        "empty_a": _write(root / "pkg" / "__init__.py", b"", 1000),
        "empty_b": _write(root / "lib" / "__init__.py", b"", 1000),
        "link_a": _write(root / "solo.bin", b"L" * 50, 1000),
    }
    os.link(f["link_a"], root / "solo-link.bin")
    f["link_b"] = root / "solo-link.bin"
    db = tmp_path / "cas.sqlite"
    monkeypatch.setattr(CAS, "_DEFAULT_DB", db)
    monkeypatch.setattr(LocalFS, "home", lambda _self: str(tmp_path))
    CAS.rebuild(LocalFS(), str(root), backend_id=BID)
    f["root"] = root
    return f


def _finder(app, root: Path, **kw):
    from ui.cas_dialog import CasDuplicatesDialog

    fs = LocalFS()

    class _Pane:
        backend = fs
        current_path = str(root)

    dlg = CasDuplicatesDialog(_Pane(), **kw)
    return dlg


@pytest.fixture
def finder(app, tree, boxes):
    dlg = _finder(app, tree["root"])
    yield dlg
    dlg._job.abandon()
    dlg.deleteLater()


def _groups(dlg) -> list[list[str]]:
    from PyQt6.QtCore import Qt

    from ui.cas_dialog import COL_NAME

    out = []
    for i in range(dlg._tree.topLevelItemCount()):
        group = dlg._tree.topLevelItem(i)
        out.append([group.child(j).data(COL_NAME, Qt.ItemDataRole.UserRole)[1].path
                    for j in range(group.childCount())])
    return out


def _names(dlg) -> list[set[str]]:
    return [{Path(p).name for p in g} for g in _groups(dlg)]


def _selected(dlg) -> list[str]:
    return sorted(e.path for e in dlg.selected_entries())


def _wait(app, cond, seconds=10.0) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


# --------------------------------------------------------------------------
# What is shown, and in which order
# --------------------------------------------------------------------------


def test_happy_largest_waste_first_with_bytes_per_group_and_in_total(finder):
    assert _names(finder) == [{"clip.mp4"}, {"a.jpg", "a (1).jpg"}, {"notes.txt"}]
    head = finder._tree.topLevelItem(1).text(0)
    assert head.startswith("[sha256] 3 copies") and "2.0 KiB to reclaim" in head
    # 3000 + 2 x 1000 + 10 bytes
    assert "4.9 KiB to reclaim" in finder._status.text()
    assert finder._status.text().startswith("3 duplicate groups covering 7 files")


def test_happy_empty_files_and_hard_links_only_when_asked(finder, tree):
    assert not any("__init__.py" in n for g in _names(finder) for n in g)
    finder._empty_check.setChecked(True)
    assert {"__init__.py"} in _names(finder)
    finder._links_check.setChecked(True)
    assert {"solo.bin", "solo-link.bin"} in _names(finder)
    links = next(finder._tree.topLevelItem(i) for i in range(finder._tree.topLevelItemCount())
                 if "hard link" in finder._tree.topLevelItem(i).text(0))
    assert "to reclaim" not in links.text(0)
    assert links.child(1).text(2).endswith("hard link")


def test_happy_filter_by_text_and_by_pattern(finder, app):
    finder._filter_edit.setText("*.jpg")
    assert _wait(app, lambda: _names(finder) == [{"a.jpg", "a (1).jpg"}])
    finder._filter_edit.setText("VIDEOS")  # part of a path, any case
    finder._apply_view()
    assert _names(finder) == [{"clip.mp4"}]
    finder._filter_edit.setText("*.txt *.mp4")
    finder._apply_view()
    assert _names(finder) == [{"clip.mp4"}, {"notes.txt"}]
    # notes.txt, plus the empty files and the hard links (hidden by default)
    assert "3 more hidden by the filters" in finder._status.text()


def test_happy_at_least_a_size_and_other_sort_orders(finder):
    finder._min_size_combo.setCurrentIndex(1)  # 1 KiB: the 1000-byte photos go too
    assert _names(finder) == [{"clip.mp4"}]
    finder._min_size_combo.setCurrentIndex(0)
    keys = [finder._sort_combo.itemData(i) for i in range(finder._sort_combo.count())]
    finder._sort_combo.setCurrentIndex(keys.index("copies"))
    assert _names(finder)[0] == {"a.jpg", "a (1).jpg"}
    finder._sort_combo.setCurrentIndex(keys.index("name"))
    assert [sorted(n)[0] for n in _names(finder)] == ["a (1).jpg", "clip.mp4", "notes.txt"]


def test_edge_the_rows_of_a_group_stay_in_survivor_order_whatever_the_sort(finder, tree):
    keys = [finder._sort_combo.itemData(i) for i in range(finder._sort_combo.count())]
    for key in keys:
        finder._sort_combo.setCurrentIndex(keys.index(key))
        mid = next(g for g in _groups(finder) if len(g) == 3)
        assert mid[0] == str(tree["mid_a"]), key  # the oldest copy is first


def test_edge_path_matcher_rules():
    from ui.cas_dialog import path_matcher

    assert path_matcher("  ") is None
    match = path_matcher("*.JPG")
    assert match("/x/IMG.jpg") and not match("/x.jpg/readme")
    in_photos = path_matcher("photos/*.jpg")
    assert in_photos("~/photos/a.jpg") and not in_photos("~/a.jpg")
    assert path_matcher("[ab].txt")("/a.txt")


def test_edge_sizes_have_one_decimal():
    from ui.cas_dialog import _format_size

    assert _format_size(0) == "0 B"
    assert _format_size(1023) == "1023 B"
    assert _format_size(1536) == "1.5 KiB"
    assert _format_size(int(1.9 * 1024**3)) == "1.9 GiB"
    assert _format_size(3 * 1024**4) == "3.0 TiB"


# --------------------------------------------------------------------------
# Keep rules
# --------------------------------------------------------------------------


def test_happy_keep_the_newest_from_the_button_menu(finder, tree):
    labels = {a.text(): a for a in finder._keep_menu.actions() if not a.isSeparator()}
    labels["Keep the Newest Copy"].trigger()
    assert _selected(finder) == sorted(str(tree[k]) for k in
                                       ("big_old", "mid_a", "mid_b", "small_a"))
    assert "4 duplicates marked" in finder._status.text()


def test_happy_mark_the_copies_inside_a_folder_asks_for_it(finder, tree, boxes):
    boxes["answer"]["text"] = str(tree["root"] / "downloads")
    assert finder.mark("mark-in-folder") == 3
    assert _selected(finder) == sorted(str(tree[k]) for k in ("mid_b", "mid_c", "small_b"))
    assert boxes["input"], "the folder was not asked for"
    assert "1 group has no copy inside" in finder._status.text()


def test_happy_the_context_menu_marks_every_copy_in_this_folder(finder, tree):
    row = next(finder._tree.topLevelItem(1).child(j) for j in range(3)
               if shown(finder._tree.topLevelItem(1).child(j).toolTip(0)) == str(tree["mid_b"]))
    acts = {a.text(): a for a in finder.build_context_menu(row).actions() if not a.isSeparator()}
    acts["Mark Every Copy Inside This Folder"].trigger()  # subfolders too
    assert _selected(finder) == sorted(str(tree[k]) for k in ("mid_b", "mid_c", "small_b"))
    acts["Keep One Copy Inside This Folder, Mark the Others"].trigger()
    assert _selected(finder) == sorted(str(tree[k]) for k in ("mid_a", "mid_c", "small_a"))


def test_sad_cancelling_the_folder_prompt_marks_nothing(finder, boxes):
    finder._tree.clearSelection()
    boxes["answer"]["ok"] = False
    assert finder.mark("keep-in-folder") == 0
    assert finder.selected_entries() == []


def test_edge_mark_all_never_marks_a_hard_link_of_the_kept_copy(finder, tree):
    finder._links_check.setChecked(True)
    finder._mark_all_duplicates()
    picked = _selected(finder)
    assert str(tree["link_b"]) not in picked and str(tree["link_a"]) not in picked
    group = next(finder._tree.topLevelItem(i) for i in range(finder._tree.topLevelItemCount())
                 if "hard link" in finder._tree.topLevelItem(i).text(0))
    finder._select_all_but_one([group])
    assert finder.selected_entries() == []


# --------------------------------------------------------------------------
# Many groups: a live window, fast marking
# --------------------------------------------------------------------------


@pytest.fixture
def many(app, tmp_path, monkeypatch, boxes):
    """A factory: the dialog is made in the test itself, so that no event
    loop turn (pytest-qt runs one after each setup) adds rows before it
    looks."""
    db = tmp_path / "cas.sqlite"
    monkeypatch.setattr(CAS, "_DEFAULT_DB", db)
    rows = []
    for g in range(1500):
        for c in range(3):
            rows.append((BID, f"/data/d{c}/f{g}.bin", "sha256", f"{g:064x}", 100 + g,
                         "2024-01-01T00:00:00", 1000.0 + c, None, None))
    with CAS._connect(db) as conn:
        conn.executemany(CAS._UPSERT_SQL, rows)
    import ui.cas_dialog as D

    monkeypatch.setattr(D, "RENDER_CHUNK", 100)
    made = []

    def make():
        made.append(D.CasDuplicatesDialog(None))
        return made[-1]

    yield make
    for dlg in made:
        dlg.deleteLater()


def test_happy_thousands_of_groups_show_the_first_at_once_the_rest_by_chunks(many, app):
    many = many()
    assert many._rendered == 100 and many._tree.topLevelItemCount() == 100
    assert "adding the rest" in many._status.text()
    # Largest waste first: the biggest files are at the top already.
    assert shown(many._tree.topLevelItem(0).child(0).toolTip(0)) == "/data/d0/f1499.bin"
    turns = 0
    while many._rendered < 1500 and turns < 1000:
        app.processEvents()
        turns += 1
    assert many._tree.topLevelItemCount() == 1500
    assert turns >= 14, "the rows were not added a chunk per event-loop turn"
    assert "adding the rest" not in many._status.text()


def test_happy_mark_all_on_thousands_of_groups_is_one_selection_change(many):
    many = many()
    changes = []
    many._tree.itemSelectionChanged.connect(lambda: changes.append(1))
    many._mark_all_duplicates()  # adds the rows still missing first
    assert len(many.selected_entries()) == 3000
    assert len(changes) == 1
    first = many._tree.topLevelItem(0)
    assert not first.child(0).isSelected() and first.child(1).isSelected()


def test_edge_a_new_filter_while_rows_are_still_added_starts_over(many, app):
    many = many()
    assert many._rendered < len(many._view)
    many._filter_edit.setText("f14*")
    many._apply_view()
    assert _wait(app, lambda: many._rendered == len(many._view))
    want = {"f14.bin"} | {f"f14{i}.bin" for i in range(10)} | {
        f"f14{i:02d}.bin" for i in range(100)}
    names = [Path(g[0]).name for g in _groups(many)]
    assert sorted(names) == sorted(want)  # no row of the old view is left over


# --------------------------------------------------------------------------
# Rebuild report, delete progress, keyboard, details
# --------------------------------------------------------------------------


def test_happy_the_rebuild_reports_counts_and_bytes(finder, app, boxes):
    from tests.off_gui_wait import _drain_scan_job

    finder._do_rebuild_active()
    assert _drain_scan_job(finder._job)
    text = boxes["information"][-1]
    assert text.startswith("Indexed 11 file(s)")
    assert "unchanged since the last scan" in text


def test_sad_unreadable_files_and_unlisted_folders_are_reported_as_a_warning():
    from ui.cas_dialog import rebuild_report

    stats = CAS.RebuildStats(scanned=5, hashed=2, bytes_hashed=2048)
    stats.note_unreadable("/x/secret", PermissionError(13, "Permission denied"))
    stats.note_unlisted("/x/locked", PermissionError(13, "Permission denied"))
    stats.special, stats.no_checksum, stats.unique_size, stats.pruned = 1, 2, 3, 4
    text, trouble = rebuild_report(2, "/x", stats, False, "SMB:nas")
    assert trouble
    for part in ("Indexed 2 file(s) under /x.", "2 hashed (2.0 KiB)",
                 "/x/secret: Permission denied", "1 folder(s) could not be listed",
                 "/x/locked: Permission denied", "1 special file(s)",
                 "2 file(s) skipped: [SMB:nas] has no content checksum",
                 "3 file(s) without a checksum were not read", "4 index entries"):
        assert part in text, part


def test_edge_a_clean_rebuild_report_is_no_warning():
    from ui.cas_dialog import rebuild_report

    text, trouble = rebuild_report(3, "/x", CAS.RebuildStats(hashed=3), True)
    assert not trouble and text.startswith("Cancelled — 3 file(s) indexed so far")


def test_happy_progress_shows_bytes_and_the_delete_counts_n_of_m(finder):
    finder._rebuild_stats = CAS.RebuildStats(bytes_hashed=5 * 1024**2, unchanged=3)
    finder._job_kind = "rebuild"
    text = finder._format_progress({"scanned": 9, "indexed": 7, "path": "/p"})
    assert "7 indexed" in text and "5.0 MiB hashed" in text and "3 unchanged" in text
    finder._rebuild_stats.phase, finder._rebuild_stats.read_total = "read", 4
    finder._rebuild_stats.read_done = 1
    assert "1 of 4" in finder._format_progress({"scanned": 9, "indexed": 7, "path": "/p"})
    assert finder._busy_bar.maximum() == 4
    finder._job_kind, finder._delete_total = "delete", 10
    text = finder._format_progress({"scanned": 3, "indexed": 2, "path": "/p"})
    assert "3 of 10 checked, 2 moved" in text
    assert (finder._busy_bar.maximum(), finder._busy_bar.value()) == (10, 3)


def test_happy_delete_says_how_much_it_moves_and_frees(finder, app, tree, boxes):
    from tests.off_gui_wait import _drain_scan_job

    finder._mark_all_duplicates()
    finder._delete_selected()
    assert "(4.9 KiB)" in boxes["question"][-1]
    assert _drain_scan_job(finder._job)
    assert "4 file(s) moved to the axross trash (4.9 KiB)" in boxes["information"][-1]
    assert not tree["big_new"].exists() and tree["big_old"].exists()


def test_happy_enter_opens_the_containing_folder_and_ctrl_f_filters(finder, app, tree):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    finder.show()
    finder.activateWindow()
    opened = []
    finder.open_requested.connect(lambda bid, path: opened.append(path))
    row = finder._tree.topLevelItem(0).child(0)
    finder._tree.setFocus()
    _wait(app, finder._tree.hasFocus, 2.0)
    finder._tree.setCurrentItem(row)
    QTest.keyClick(finder._tree, Qt.Key.Key_Return)
    assert opened == [str(tree["big_old"])]
    QTest.keyClick(finder._tree, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
    assert _wait(app, finder._filter_edit.hasFocus, 2.0)


def test_edge_the_details_line_shows_the_exact_size_and_the_hard_link(finder, tree):
    finder._links_check.setChecked(True)
    group = next(finder._tree.topLevelItem(i) for i in range(finder._tree.topLevelItemCount())
                 if "hard link" in finder._tree.topLevelItem(i).text(0))
    finder._tree.setCurrentItem(group.child(0))
    text = finder._details.text()
    assert "50 bytes" in text and "same file as" in text
    finder._tree.setCurrentItem(group)
    assert "ax-cas://sha256:" in finder._details.text()


def test_edge_remove_from_index_is_one_transaction(finder, tree, monkeypatch):
    calls = []
    real = CAS.remove_many
    monkeypatch.setattr(CAS, "remove_many", lambda db, keys: calls.append(list(keys)) or
                        real(db, keys))
    finder._mark_all_duplicates()
    finder._forget_selected()
    assert len(calls) == 1 and len(calls[0]) == 4
    assert tree["big_new"].exists()
    assert "Removed 4 rows" in finder._status.text()
