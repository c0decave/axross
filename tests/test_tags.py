"""Tags on files - "Tags überall" (punch-list item 14).

Operator: *„bookmark important files zu späterer analyse, funktion
dafuer"*; decided: coloured tags for any file, filterable in the pane (and
the search); bookmarks of files become a tag.

- core/tags.py: the tag definitions (name, colour) and which file (backend
  name, profile, path) carries which tags, in ~/.config/axross/tags.json
  (private, atomic). "Important" and "Review later" exist from the start.
- The pane: right-click > Tags > (tick a tag, New Tag…); coloured dots in
  the Name column; "tag:Important" in the filter field shows only those.
- View > Tagged Files…: every tag and its files, double-click goes there.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import tags as T  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def store(tmp_path, monkeypatch):
    path = tmp_path / "tags.json"
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    yield T.store()
    T.reset_cache()


# -- the store -----------------------------------------------------------------------


class TestStore:
    def test_happy_defaults_tag_untag_and_persist(self, store, tmp_path):
        assert [t.name for t in store.tags()] == ["Important", "Review later"]
        store.tag("Local", "", "/srv/a.txt", "Important")
        store.tag("Local", "", "/srv/b.txt", "Important")
        store.tag("alice@nas", "nas", "/x", "Review later")
        assert store.tags_of("Local", "/srv/a.txt") == ["Important"]
        assert [e.path for e in store.items_with("Important")] == ["/srv/a.txt", "/srv/b.txt"]
        assert store.items_with("Review later")[0].profile_name == "nas"
        store.untag("Local", "/srv/a.txt", "Important")
        assert store.tags_of("Local", "/srv/a.txt") == []
        T.reset_cache()
        again = T.store()
        assert [e.path for e in again.items_with("Important")] == ["/srv/b.txt"]
        assert stat.S_IMODE((tmp_path / "tags.json").stat().st_mode) == 0o600

    def test_happy_define_rename_and_delete_a_tag(self, store):
        store.define("Evidence", "#123abc")
        store.tag("Local", "", "/e", "Evidence")
        store.rename("Evidence", "Case 42")
        assert store.tags_of("Local", "/e") == ["Case 42"]
        assert store.colour("Case 42") == "#123abc"
        store.delete("Case 42")
        assert store.tags_of("Local", "/e") == [] and "Case 42" not in [t.name for t in store.tags()]

    @pytest.mark.parametrize("name", ["", " ", "x" * 41, "bad\nname", "tab\tname"])
    def test_sad_bad_tag_names_are_refused(self, store, name):
        with pytest.raises(ValueError):
            store.define(name, "#ff0000")

    @pytest.mark.parametrize("colour", ["red", "#12345", "#gggggg", ""])
    def test_sad_bad_colours_are_refused(self, store, colour):
        with pytest.raises(ValueError):
            store.define("Ok", colour)

    def test_sad_tagging_with_an_unknown_tag_or_a_duplicate_name(self, store):
        with pytest.raises(KeyError):
            store.tag("Local", "", "/a", "Nope")
        with pytest.raises(ValueError, match="exists"):
            store.define("important", "#000000")  # case-insensitive clash
        with pytest.raises(ValueError, match="exists"):
            store.rename("Important", "Review later")

    def test_sad_a_corrupt_file_reads_as_the_defaults_and_is_kept_aside(self, store, tmp_path):
        (tmp_path / "tags.json").write_text("{broken")
        T.reset_cache()
        fresh = T.store()
        assert [t.name for t in fresh.tags()] == ["Important", "Review later"]
        assert list(tmp_path.glob("tags.json.corrupt-*"))

    def test_edge_bad_entries_in_the_file_are_skipped(self, store, tmp_path):
        (tmp_path / "tags.json").write_text(json.dumps({
            "tags": [{"name": "Good", "color": "#00ff00"}, {"name": "", "color": "#000000"}, "x"],
            "items": [
                {"backend": "Local", "profile": "", "path": "/ok", "tags": ["Good", "Unknown"]},
                {"backend": "Local", "path": 5, "tags": ["Good"]},
                "garbage",
            ],
        }))
        T.reset_cache()
        fresh = T.store()
        assert [t.name for t in fresh.tags()] == ["Good"]
        assert fresh.tags_of("Local", "/ok") == ["Good"]

    def test_edge_tagging_twice_is_once_and_untag_of_nothing_is_fine(self, store):
        store.tag("Local", "", "/a", "Important")
        store.tag("Local", "", "/a", "Important")
        assert len(store.items_with("Important")) == 1
        store.untag("Local", "/zzz", "Important")

    def test_edge_moved_or_renamed_paths_follow_with_rename_path(self, store):
        store.tag("Local", "", "/old/a.txt", "Important")
        store.tag("Local", "", "/old/sub/b.txt", "Important")
        store.rename_path("Local", "/old", "/new")
        assert sorted(e.path for e in store.items_with("Important")) == ["/new/a.txt", "/new/sub/b.txt"]

    def test_edge_rename_path_with_a_trailing_slash_and_windows_separators(self, store):
        store.tag("Local", "", "/old/a.txt", "Important")
        store.tag("Local", "", "/older/x.txt", "Important")  # a sibling, not below /old
        store.tag("Local", "", "C:\\Data\\case\\img.e01", "Important")
        store.rename_path("Local", "/old/", "/new")
        store.rename_path("Local", "C:\\Data\\case", "C:\\Data\\case-42")
        assert sorted(e.path for e in store.items_with("Important")) == [
            "/new/a.txt", "/older/x.txt", "C:\\Data\\case-42\\img.e01"]
        store.rename_path("Local", "/new/a.txt", "/new/b.txt")
        assert store.tags_of("Local", "/new/b.txt") == ["Important"]

    def test_edge_a_posix_name_with_a_backslash_is_not_below_a_folder(self, store):
        """On POSIX "\\" is a character of a name: the file "/a\\b" sits next to
        the folder "/a", not inside it, and stays when "/a" is renamed."""
        store.tag("Local", "", "/a\\b", "Important")
        store.tag("Local", "", "/a/c", "Important")
        store.rename_path("Local", "/a", "/z")
        assert sorted(e.path for e in store.items_with("Important")) == ["/a\\b", "/z/c"]


# -- the pane ------------------------------------------------------------------------


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


def _names(pane):
    proxy, model = pane._proxy, pane._model
    return [model.get_item(proxy.mapToSource(proxy.index(r, 0)).row()).name
            for r in range(proxy.rowCount())]


def _select(pane, name):
    from PyQt6.QtCore import QItemSelectionModel

    pane._table.clearSelection()
    for r in range(pane._proxy.rowCount()):
        index = pane._proxy.index(r, 0)
        if pane._model.get_item(pane._proxy.mapToSource(index).row()).name == name:
            pane._table.selectionModel().select(
                index, QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (d / name).write_text(name)
    return d


def test_happy_tag_from_the_context_menu_filter_and_tooltip(store, tmp_path, folder):
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        _select(pane, "a.txt")
        menu = pane._build_context_menu()
        tags_menu = next(a.menu() for a in menu.actions() if a.text().replace("&", "") == "Tags")
        important = next(a for a in tags_menu.actions() if a.text() == "Important")
        assert important.isCheckable() and not important.isChecked()
        important.trigger()
        assert store.tags_of("Local", str(folder / "a.txt")) == ["Important"]
        assert "Important" in pane._model.data(pane._model.index(
            next(r for r in range(pane._model.rowCount()) if pane._model.get_item(r).name == "a.txt"), 0),
            __import__("PyQt6.QtCore", fromlist=["Qt"]).Qt.ItemDataRole.ToolTipRole)
        pane._filter_edit.setText("tag:important")
        APP.processEvents()
        assert [n for n in _names(pane) if n != ".."] == ["a.txt"]
        pane._filter_edit.setText("")
        assert {"a.txt", "b.txt", "c.txt"} <= set(_names(pane))
        # Untick again
        _select(pane, "a.txt")
        menu = pane._build_context_menu()
        tags_menu = next(a.menu() for a in menu.actions() if a.text().replace("&", "") == "Tags")
        important = next(a for a in tags_menu.actions() if a.text() == "Important")
        assert important.isChecked()
        important.trigger()
        assert store.tags_of("Local", str(folder / "a.txt")) == []
    finally:
        win.close()
        win.deleteLater()


def test_happy_several_selected_files_are_tagged_at_once(store, tmp_path, folder):
    from PyQt6.QtCore import QItemSelectionModel

    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        _select(pane, "a.txt")
        for r in range(pane._proxy.rowCount()):
            index = pane._proxy.index(r, 0)
            if pane._model.get_item(pane._proxy.mapToSource(index).row()).name == "b.txt":
                pane._table.selectionModel().select(
                    index, QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
        pane.toggle_tag("Review later")
        assert [e.path for e in store.items_with("Review later")] == [str(folder / "a.txt"), str(folder / "b.txt")]
    finally:
        win.close()
        win.deleteLater()


def test_e2e_tag_dots_are_painted_in_the_name_column(store, tmp_path, folder):
    store.define("Hot", "#ff00ff")
    store.tag("Local", "", str(folder / "b.txt"), "Hot")
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        pane.resize(700, 300)
        pane.setParent(None)
        pane.show()
        APP.processEvents()
        view = pane._table
        row = next(r for r in range(pane._proxy.rowCount())
                   if pane._model.get_item(pane._proxy.mapToSource(pane._proxy.index(r, 0)).row()).name == "b.txt")
        rect = view.visualRect(pane._proxy.index(row, 0))
        img = view.viewport().grab().toImage()
        colours = {img.pixelColor(x, y).name() for x in range(rect.left(), rect.right())
                   for y in range(rect.top(), rect.bottom())}
        assert "#ff00ff" in colours
        pane.close()
    finally:
        win.close()
        win.deleteLater()


def test_sad_filter_for_an_unknown_tag_shows_nothing_but_dot_dot(store, tmp_path, folder):
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        pane._filter_edit.setText("tag:nothing-like-this")
        assert [n for n in _names(pane) if n != ".."] == []
    finally:
        win.close()
        win.deleteLater()


def test_edge_a_new_tag_from_the_menu(store, tmp_path, folder):
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        _select(pane, "c.txt")
        with mock.patch("ui.tag_ui.QInputDialog.getText", return_value=("Case 7", True)), \
                mock.patch("ui.tag_ui.QColorDialog.getColor",
                           return_value=__import__("PyQt6.QtGui", fromlist=["QColor"]).QColor("#00aa00")):
            pane.new_tag_for_selection()
        assert store.colour("Case 7") == "#00aa00"
        assert store.tags_of("Local", str(folder / "c.txt")) == ["Case 7"]
    finally:
        win.close()
        win.deleteLater()


def test_e2e_tagged_files_window_lists_and_navigates(store, tmp_path, folder):
    store.tag("Local", "", str(folder / "b.txt"), "Important")
    win = _window(tmp_path)
    try:
        win._show_tagged_files()
        dlg = win._tagged_files_dialog
        dlg.select_tag("Important")
        assert dlg.files.rowCount() == 1 and dlg.files.item(0, 0).text() == "b.txt"
        dlg.files.selectRow(0)
        dlg.go_to_selected()
        end = time.time() + 5
        while time.time() < end and win._active_pane.current_path != str(folder):
            APP.processEvents()
            time.sleep(0.01)
        assert win._active_pane.current_path == str(folder)
        dlg.close()
    finally:
        win.close()
        win.deleteLater()


def test_edge_a_model_without_a_pane_shows_name_tooltips():
    """FileTableModel outside a file pane (nobody set tag_lookup): the Name
    tooltip works. A merge once left ``self.tag_lookup = None`` as dead code
    behind a return, so a bare model raised AttributeError here."""
    from PyQt6.QtCore import Qt as _Qt

    from core.backend import FileItem
    from models.file_table_model import FileTableModel

    model = FileTableModel()
    model.set_items([FileItem(name="plain.txt", size=3)])
    tip = model.data(model.index(0, 0), _Qt.ItemDataRole.ToolTipRole)
    assert "plain.txt" in str(tip)


# -- round-2 verification ------------------------------------------------------------


@pytest.mark.parametrize("what", ["file", "folder"])
def test_e2e_a_tag_follows_a_rename_in_the_pane(store, tmp_path, folder, what):
    """"Bookmark important files for later analysis": renaming a tagged file
    (or the folder holding one) in the pane must not lose the tag -
    TagStore.rename_path exists for exactly this."""
    (folder / "sub").mkdir()
    (folder / "sub" / "inner.txt").write_text("x")
    if what == "file":
        old, new_name = folder / "a.txt", "renamed.txt"
        tagged_old, tagged_new = old, folder / new_name
    else:
        old, new_name = folder / "sub", "moved"
        tagged_old, tagged_new = folder / "sub" / "inner.txt", folder / "moved" / "inner.txt"
    store.tag("Local", "", str(tagged_old), "Important")
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        _select(pane, old.name)
        with mock.patch("PyQt6.QtWidgets.QInputDialog.getText", return_value=(new_name, True)):
            pane._rename_selected()
        assert (folder / new_name).exists()
        assert store.tags_of("Local", str(tagged_new)) == ["Important"]
        assert store.tags_of("Local", str(tagged_old)) == []
    finally:
        win.close()
        win.deleteLater()


def test_sad_a_failed_rename_keeps_the_tag_where_it_was(store, tmp_path, folder):
    store.tag("Local", "", str(folder / "a.txt"), "Important")
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        _select(pane, "a.txt")
        with mock.patch("PyQt6.QtWidgets.QInputDialog.getText", return_value=("b.txt", True)), \
                mock.patch("ui.file_pane.QMessageBox.warning"):
            pane._rename_selected()  # b.txt exists: refused
        assert store.tags_of("Local", str(folder / "a.txt")) == ["Important"]
        assert store.tags_of("Local", str(folder / "b.txt")) == []
    finally:
        win.close()
        win.deleteLater()


# -- tags follow moves, not only renames (verification round: F6 / drag-move
# orphaned the tags of moved files and folders) ------------------------------------


def test_happy_move_path_across_backends(tmp_path):
    from core import tags as TG

    s = TG.TagStore(tmp_path / "tags.json")
    s.tag("Local", "", "/a/dir/x.txt", "Important")
    s.tag("Local", "", "/a/dir", "Review later")
    s.move_path("Local", "/a/dir", "/srv/in/dir", dest_backend="alice@nas", dest_profile="nas")
    assert s.tags_of("alice@nas", "/srv/in/dir") == ["Review later"]
    assert s.tags_of("alice@nas", "/srv/in/dir/x.txt") == ["Important"]
    assert s.tags_of("Local", "/a/dir/x.txt") == []
    assert s.items_with("Important")[0].profile_name == "nas"
    assert s.has_tags_under("alice@nas", "/srv") and not s.has_tags_under("Local", "/a")


def test_edge_move_path_into_a_windows_share(tmp_path):
    from core import tags as TG

    s = TG.TagStore(tmp_path / "tags.json")
    s.tag("Local", "", "/home/u/d/f.txt", "Important")
    s.move_path("Local", "/home/u/d", "C:\\Users\\u\\d", dest_backend="win")
    assert s.tags_of("win", "C:\\Users\\u\\d\\f.txt") == ["Important"]


def _wait_moves(win, timeout=30.0):
    import time

    from PyQt6.QtWidgets import QApplication

    end = time.time() + timeout
    while time.time() < end:
        QApplication.processEvents()
        if not win._tag_moves and not win._tag_folder_moves:
            return True
        time.sleep(0.02)
    return False


def test_e2e_tags_follow_an_f6_move(tmp_path, monkeypatch):
    from PyQt6.QtCore import Qt as _Qt

    from core import tags as TG
    from ui.main_window import MainWindow

    monkeypatch.setattr(TG, "tags_file", lambda: tmp_path / "tags.json")
    TG.reset_cache()
    src, dst = tmp_path / "src", tmp_path / "dst"
    (src / "folder").mkdir(parents=True)
    dst.mkdir()
    (src / "a.txt").write_text("a")
    (src / "folder" / "b.txt").write_text("b")
    store = TG.store()
    store.tag("Local", "", str(src / "a.txt"), "Important")
    store.tag("Local", "", str(src / "folder"), "Review later")
    store.tag("Local", "", str(src / "folder" / "b.txt"), "Important")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        left = win._active_pane
        left.navigate(str(src))
        win._split_pane(_Qt.Orientation.Horizontal)
        right = win._active_pane
        right.navigate(str(dst))
        win._set_active_pane(left)
        win._set_target_pane(right)
        win._start_transfer_between(left, right, [str(src / "a.txt"), str(src / "folder")],
                                    move=True)
        import time

        from PyQt6.QtWidgets import QApplication

        end = time.time() + 30
        while time.time() < end and not ((dst / "folder" / "b.txt").exists()
                                         and not (src / "a.txt").exists()
                                         and not (src / "folder" / "b.txt").exists()):
            QApplication.processEvents()
            time.sleep(0.02)
        assert _wait_moves(win)
        for _ in range(20):
            QApplication.processEvents()
            time.sleep(0.02)
        assert store.tags_of("Local", str(dst / "a.txt")) == ["Important"]
        assert store.tags_of("Local", str(dst / "folder")) == ["Review later"]
        assert store.tags_of("Local", str(dst / "folder" / "b.txt")) == ["Important"]
        assert store.tags_of("Local", str(src / "a.txt")) == []
    finally:
        win.close()
        win.deleteLater()
        TG.reset_cache()


def test_sad_a_failed_move_job_keeps_the_tags(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from core import tags as TG
    from core.transfer_worker import TransferStatus
    from ui.main_window import MainWindow

    monkeypatch.setattr(TG, "tags_file", lambda: tmp_path / "tags.json")
    TG.reset_cache()
    store = TG.store()
    store.tag("Local", "", "/s/d/f.txt", "Important")
    store.tag("Local", "", "/s/d", "Review later")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        job = SimpleNamespace(job_id="j1", move=True, status=TransferStatus.ERROR, skipped=False,
                              source_path="/s/d/f.txt", dest_path="/t/d/f.txt")
        win._tag_moves["j1"] = ("Local", "Local", "", job.source_path, job.dest_path)
        win._tag_folder_moves.append({"src": "Local", "dst": "Local", "profile": "",
                                      "old": "/s/d", "new": "/t/d", "pending": {"j1"},
                                      "failed": False})
        monkeypatch.setattr(win._transfer_manager, "get_job", lambda jid: job)
        win._tags_on_move_error("j1", "disk full")
        from PyQt6.QtWidgets import QApplication

        QApplication.processEvents()  # ended jobs are applied on the next event-loop turn
        assert store.tags_of("Local", "/s/d/f.txt") == ["Important"]
        assert store.tags_of("Local", "/s/d") == ["Review later"]
        assert not win._tag_moves and not win._tag_folder_moves
    finally:
        win.close()
        win.deleteLater()
        TG.reset_cache()


# -- the dots take room of their own (no dot is painted over the name) ---------------
#
# Reported: in a fitted Name column a tagged "budget.csv" showed its dots on
# top of the last letters. The delegate measured the name without the dots
# and painted them over the text's right end.


def _dots_pane(colours):
    """A stand-in for the pane: a QObject (the delegate's parent) that
    answers tag_colours_at."""
    from PyQt6.QtCore import QObject

    pane = QObject()
    pane.tag_colours_at = lambda _index: list(colours)
    return pane


def _dots_view(name, colours, width=None):
    from PyQt6.QtCore import QModelIndex, Qt
    from PyQt6.QtGui import QColor, QPalette, QStandardItem, QStandardItemModel
    from PyQt6.QtWidgets import QTableView

    from ui.tag_ui import TagDotsDelegate

    model = QStandardItemModel(1, 1)
    model.setItem(0, 0, QStandardItem(name))
    view = QTableView()
    palette = view.palette()
    palette.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#000000"))
    view.setPalette(palette)
    # A MainWindow made by an earlier test leaves its theme as the app's
    # style sheet, which beats the palette: pin the colours here too.
    view.setStyleSheet("QTableView, QTableView::item { background: #ffffff; color: #000000; }")
    view.setModel(model)
    view.setShowGrid(False)
    view.setSelectionMode(QTableView.SelectionMode.NoSelection)
    view.setFocusPolicy(Qt.FocusPolicy.NoFocus)
    view.horizontalHeader().hide()
    view.verticalHeader().hide()
    pane = _dots_pane(colours)
    delegate = TagDotsDelegate(pane)
    view._dots_pane = pane  # keep the parent alive with the view
    view.setItemDelegateForColumn(0, delegate)
    view.resize(400, 80)
    view.show()
    APP.processEvents()
    index = model.index(0, 0)
    view.setColumnWidth(0, width if width is not None else view.sizeHintForIndex(index).width())
    view.setCurrentIndex(QModelIndex())
    APP.processEvents()
    return view, delegate, index


def _text_pixels_in_dot_strip(view, index, n_dots):
    """Dark pixels - the black text on the white base, nothing selected - in
    the strip at the cell's right edge where the dots are painted. The
    magenta dots and their anti-aliased edges keep red and blue light."""
    from ui.tag_ui import dots_width

    rect = view.visualRect(index)
    img = view.viewport().grab().toImage()
    found = 0
    for x in range(rect.right() - dots_width(n_dots) + 1, rect.right()):
        for y in range(rect.top(), rect.bottom()):
            c = img.pixelColor(x, y)
            if max(c.red(), c.green(), c.blue()) < 160:
                found += 1
    return found


def test_happy_a_tagged_name_measures_its_dots_too():
    from ui.tag_ui import dots_width

    view, _delegate, index = _dots_view("budget.csv", ["#ff00ff", "#00aa00"])
    bare, _bare_delegate, bare_index = _dots_view("budget.csv", [])
    try:
        assert (view.sizeHintForIndex(index).width()
                == bare.sizeHintForIndex(bare_index).width() + dots_width(2))
    finally:
        bare.close()
        view.close()


def test_happy_at_its_fitted_width_no_dot_covers_the_name():
    view, _delegate, index = _dots_view("budget.csv", ["#ff00ff", "#00aa00"])
    try:
        assert _text_pixels_in_dot_strip(view, index, 2) == 0
    finally:
        view.close()


def test_sad_a_name_too_long_for_the_cell_is_cut_before_the_dots():
    view, _delegate, index = _dots_view("a-very-long-file-name-that-never-fits.csv", ["#ff00ff"], width=90)
    try:
        assert _text_pixels_in_dot_strip(view, index, 1) == 0
    finally:
        view.close()


def test_sad_an_untagged_name_keeps_its_width():
    from PyQt6.QtWidgets import QStyledItemDelegate

    view, _delegate, index = _dots_view("budget.csv", [])
    try:
        plain = QStyledItemDelegate()
        view.setItemDelegateForColumn(0, plain)
        width_plain = view.sizeHintForIndex(index).width()
        view.setItemDelegateForColumn(0, _delegate)
        assert view.sizeHintForIndex(index).width() == width_plain
    finally:
        view.close()


def test_edge_dots_width_grows_per_dot_and_is_zero_without():
    from ui.tag_ui import DOT, dots_width

    assert dots_width(0) == 0
    assert dots_width(1) > DOT
    assert dots_width(3) - dots_width(2) == dots_width(2) - dots_width(1) == DOT + 3


def test_e2e_tagging_a_file_refits_the_name_column(store, tmp_path, folder):
    from ui.tag_ui import dots_width

    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        APP.processEvents()
        before = pane._content_width(0)
        row = next(r for r in range(pane._proxy.rowCount())
                   if pane._model.get_item(pane._proxy.mapToSource(pane._proxy.index(r, 0)).row()).name == "a.txt")
        a_bare = pane._table.sizeHintForIndex(pane._proxy.index(row, 0)).width()
        _select(pane, "a.txt")
        pane.toggle_tag("Important")
        APP.processEvents()
        assert pane._content_width(0) == max(before, a_bare + dots_width(1)) > before
    finally:
        win.close()
        win.deleteLater()


# -- a hand-edited tags.json with the wrong shapes ------------------------------------
# {"tags": 5} or {"items": 7} raised TypeError out of TG.store() ("'int' object is
# not iterable"): the loops read data.get(...) or [] without asking for a list.


@pytest.mark.parametrize("data", [
    {"tags": 5, "items": 7},
    {"tags": "Important", "items": "abc"},
    {"tags": {"name": "x"}, "items": {"backend": "Local"}},
    {"tags": None, "items": None},
])
def test_sad_wrong_shapes_load_as_empty_without_an_error(tmp_path, monkeypatch, data):
    path = tmp_path / "tags.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    try:
        store = T.store()
        assert store.tags_of("Local", "/x") == []
        assert [t.name for t in store.tags()]  # the default tags are there
    finally:
        T.reset_cache()


def test_edge_a_wrong_items_shape_keeps_good_tag_definitions(tmp_path, monkeypatch):
    path = tmp_path / "tags.json"
    path.write_text(json.dumps({"tags": [{"name": "Mine", "color": "#112233"}], "items": 7}))
    monkeypatch.setattr(T, "tags_file", lambda: path)
    T.reset_cache()
    try:
        assert [t.name for t in T.store().tags()] == ["Mine"]
    finally:
        T.reset_cache()
