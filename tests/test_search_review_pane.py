"""Search review (the operator: "die Suchfunktion in axross funktioniert
nicht richtig"): the pane's live filter and type-to-find, the settings
search and the handbook's find field, end to end.

- **The filter went along into the next folder.** Typing "proj" to find a
  folder and opening it showed that folder filtered by "proj" - mostly
  empty ("0 of 1 item"). Opening another folder now clears the filter; a
  refresh of the same folder keeps it, and a filter typed while the next
  folder is still loading is the one for that folder and stays.
- **Umlauts in decomposed form.** Names written by macOS (and many SMB/NFS
  shares or archives made there) carry "ä" as "a" + U+0308. The filter
  and type-to-find compared code points, so "äpf" typed on a keyboard
  (one code point) never found "Äpfel.txt". Both compare NFC now.
- **Patterns.** "*.pdf" in the filter showed nothing (no name holds a
  "*"); a text with * or ? is a set of name patterns now ("*.jpg *.png"),
  as in Find Files and the Duplicate Finder. "[" stays a plain character.
- **Type-to-find in a big folder** asked the Python model for every row
  (200-270 ms per key at 50,000 entries); it reads the names the filter
  already keeps.
- **Settings search** marked a setting on a tab not shown (the Agent page's
  Access tab): the page opened, nothing visible was marked. The tab of the
  first hit is shown now.
- **Handbook find**: "Not found" stayed under a text already changed, and
  a longer text skipped the match that the shorter one had selected.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import unicodedata
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtGui import QKeyEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])

NFD_APFEL = unicodedata.normalize("NFD", "Äpfel.txt")
NAMES = (NFD_APFEL, "Birne.txt", "Straße.md", "proj")


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


def wait_for(predicate, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def shown(pane) -> list[str]:
    proxy = pane._table.model()
    return sorted(
        proxy.index(r, 0).data() for r in range(proxy.rowCount())
        if proxy.index(r, 0).data() not in (".", "..")
    )


def type_text(widget, text: str) -> None:
    """Key events carrying *text* (QTest.keyClicks knows no umlauts)."""
    for ch in text:
        for kind in (QEvent.Type.KeyPress, QEvent.Type.KeyRelease):
            APP.sendEvent(widget, QKeyEvent(kind, Qt.Key.Key_unknown,
                                            Qt.KeyboardModifier.NoModifier, ch))
    APP.processEvents()


class _GatedFS(LocalFS):
    """LocalFS whose listing of one folder waits for a gate."""

    def __init__(self, slow: str) -> None:
        super().__init__()
        self.slow = slow
        self.gate = threading.Event()

    def list_dir(self, path):
        if os.path.normpath(path) == os.path.normpath(self.slow):
            self.gate.wait(10)
        return super().list_dir(path)


def _make_folder(tmp_path: Path) -> Path:
    for name in NAMES:
        if name == "proj":
            (tmp_path / name).mkdir()
            (tmp_path / name / "inner.txt").write_text("x")
            (tmp_path / name / "proj-notes.txt").write_text("x")
        else:
            (tmp_path / name).write_text(name)
    return tmp_path


def _pane(backend, folder: Path):
    from ui.file_pane import FilePaneWidget

    widget = FilePaneWidget(backend)
    widget.resize(800, 500)
    widget.show()
    widget.navigate(str(folder))
    assert wait_for(lambda: len(shown(widget)) == len(NAMES))
    return widget


def _close(widget) -> None:
    widget.close()
    widget.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


@pytest.fixture
def pane(tmp_path):
    widget = _pane(LocalFS(), _make_folder(tmp_path))
    yield widget
    _close(widget)


# --- the filter and the next folder ------------------------------------------


def test_happy_e2e_opening_a_folder_found_by_the_filter_shows_all_of_it(pane, tmp_path) -> None:
    pane._filter_edit.setFocus()
    pane._filter_edit.setText("proj")
    pump()
    assert shown(pane) == ["proj"]
    pane.navigate_async(str(tmp_path / "proj"))
    assert wait_for(lambda: pane.current_path == str(tmp_path / "proj") and not pane.is_loading)
    assert pane._filter_edit.text() == ""
    assert shown(pane) == ["inner.txt", "proj-notes.txt"]
    from PyQt6.QtWidgets import QToolButton

    clear_button = pane._filter_edit.findChildren(QToolButton)[0]
    assert wait_for(lambda: clear_button.property("opacity") == 0.0)  # faded out
    pane.navigate(str(tmp_path))  # back up: the whole folder, too
    assert shown(pane) == sorted(NAMES)


def test_happy_a_tag_filter_is_cleared_with_the_folder_too(pane, tmp_path) -> None:
    pane._filter_edit.setText("tag:nothing-has-this")
    pump()
    assert shown(pane) == []
    pane.navigate(str(tmp_path / "proj"))
    assert pane._filter_edit.text() == "" and pane._proxy._tag_filter is None
    assert shown(pane) == ["inner.txt", "proj-notes.txt"]


def test_sad_a_refresh_of_the_same_folder_keeps_the_filter(pane) -> None:
    pane._filter_edit.setText("birne")
    pump()
    pane.refresh()
    pane.refresh_async()
    assert wait_for(lambda: not pane.is_loading)
    assert pane._filter_edit.text() == "birne"
    assert shown(pane) == ["Birne.txt"]


def test_edge_a_filter_typed_while_the_next_folder_loads_is_kept(tmp_path) -> None:
    folder = _make_folder(tmp_path)
    backend = _GatedFS(str(folder / "proj"))
    backend.gate.set()
    widget = _pane(backend, folder)
    try:
        backend.gate.clear()
        widget._filter_edit.setText("bir")  # a filter of this folder
        pump()
        widget.navigate_async(str(folder / "proj"))
        pump(0.1)
        assert widget.is_loading
        widget._filter_edit.setText("notes")  # meant for the folder on its way
        pump()
        backend.gate.set()
        assert wait_for(lambda: not widget.is_loading)
        assert widget._filter_edit.text() == "notes"
        assert shown(widget) == ["proj-notes.txt"]
    finally:
        backend.gate.set()
        _close(widget)


# --- umlauts in either form ---------------------------------------------------


@pytest.mark.parametrize("text", ["äpf", "ÄPFEL", unicodedata.normalize("NFD", "äpf")])
def test_happy_the_filter_finds_a_decomposed_umlaut_name(pane, text) -> None:
    pane._filter_edit.setText(text)
    pump()
    assert shown(pane) == [NFD_APFEL]


def test_happy_a_decomposed_filter_text_finds_a_composed_name(tmp_path) -> None:
    (tmp_path / "Größe.txt").write_text("x")
    (tmp_path / "other.txt").write_text("x")
    from ui.file_pane import FilePaneWidget

    widget = FilePaneWidget(LocalFS())
    try:
        widget.navigate(str(tmp_path))
        widget._filter_edit.setText(unicodedata.normalize("NFD", "größe"))
        pump()
        assert shown(widget) == ["Größe.txt"]
    finally:
        _close(widget)


def test_happy_type_to_find_jumps_to_a_decomposed_umlaut_name(pane) -> None:
    pane._table.setFocus()
    pump()
    type_text(pane._table, "äp")
    assert pane._table.currentIndex().data() == NFD_APFEL


def test_edge_type_to_find_still_works_for_plain_names_and_case(pane) -> None:
    pane._table.setFocus()
    pump()
    type_text(pane._table, "BI")
    assert pane._table.currentIndex().data() == "Birne.txt"
    pump(0.6)  # the type-ahead buffer runs out
    type_text(pane._table, "str")
    assert pane._table.currentIndex().data() == "Straße.md"


def test_sad_type_to_find_without_a_match_keeps_the_current_row(pane) -> None:
    pane._table.setFocus()
    pump()
    type_text(pane._table, "bi")
    assert pane._table.currentIndex().data() == "Birne.txt"
    pump(0.6)
    type_text(pane._table, "zz")
    assert pane._table.currentIndex().data() == "Birne.txt"


def test_edge_type_to_find_in_a_big_folder_does_not_hold_the_window() -> None:
    """The proxy's match() reads the names the filter keeps: no Python
    data() call per row (50,000 rows took 200-270 ms per key)."""
    from models.file_item import FileItem
    from models.file_table_model import FileSortProxyModel, FileTableModel

    model = FileTableModel()
    model.set_items([FileItem(name=f"file_{i:05d}.dat") for i in range(50_000)])
    proxy = FileSortProxyModel()
    proxy.setSourceModel(model)
    flags = Qt.MatchFlag.MatchStartsWith | Qt.MatchFlag.MatchWrap
    start = time.perf_counter()
    for _ in range(5):
        assert proxy.match(proxy.index(0, 0), Qt.ItemDataRole.DisplayRole, "zz", 1, flags) == []
    elapsed = (time.perf_counter() - start) / 5
    assert elapsed < 0.05, f"{elapsed * 1000:.0f} ms per key"
    hit = proxy.match(proxy.index(10, 0), Qt.ItemDataRole.DisplayRole, "FILE_0000", 1, flags)
    assert [i.data() for i in hit] == ["file_00000.dat"]  # wrapped round


def test_edge_type_to_find_after_a_click_in_another_column_finds_names(pane) -> None:
    """A click in the Size or Modified column makes that cell current; the
    letters typed then went to that column's texts."""
    from PyQt6.QtCore import QItemSelectionModel

    proxy = pane._proxy
    row = next(r for r in range(proxy.rowCount()) if proxy.index(r, 0).data() == "Straße.md")
    pane._table.selectionModel().setCurrentIndex(
        proxy.index(row, 3), QItemSelectionModel.SelectionFlag.ClearAndSelect
        | QItemSelectionModel.SelectionFlag.Rows)
    pane._table.setFocus()
    pump()
    type_text(pane._table, "bi")
    assert proxy.index(pane._table.currentIndex().row(), 0).data() == "Birne.txt"


# --- Edit > Settings: "Find a setting" ----------------------------------------


@pytest.fixture
def stores(tmp_path, monkeypatch):
    from tests.settings_testkit import isolate

    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.mark.parametrize("lang, text", [("en", "Add folder"), ("de", "Ordner hinzufügen"),
                                        ("en", "Rescan")])
def test_happy_settings_search_shows_the_tab_of_a_hit(stores, lang, text) -> None:
    """The Agent page's settings live on tabs: a hit on the Access tab
    opened the page at its first tab, nothing marked in sight."""
    from core import i18n

    i18n.install(lang)
    try:
        win = stores.make_window()
        dialog = stores.settings_dialog(win)
        dialog.filter_edit.setText(text)
        APP.processEvents()
        page_id = dialog.current_page_id()
        page = dialog._pages[page_id]
        assert dialog.marked_texts(), text
        assert any(w.isVisibleTo(page) for w in dialog._marked), (
            text, page_id, dialog.marked_texts())
        dialog.reject()
    finally:
        i18n.install(i18n.DEFAULT_LANGUAGE)


def test_sad_settings_search_leaves_the_tab_alone_when_a_hit_is_in_sight(stores) -> None:
    """A user on the Sandboxes tab searching "Add folder" (a button there
    and on Access) stays on Sandboxes."""
    win = stores.make_window()
    dialog = stores.settings_dialog(win)
    dialog.show_page("agent", "sandboxes")
    tabs = dialog._pages["agent"].tabs
    shown_tab = tabs.currentIndex()
    dialog.filter_edit.setText("Add folder")
    APP.processEvents()
    page = dialog._pages["agent"]
    assert dialog.current_page_id() == "agent"
    assert tabs.currentIndex() == shown_tab
    assert any(w.isVisibleTo(page) for w in dialog._marked)
    dialog.reject()


# --- the handbook's find field ------------------------------------------------


@pytest.fixture(scope="module")
def handbook():
    from ui.handbook import HandbookDialog

    dialog = HandbookDialog(None, language="en")
    dialog.show()
    APP.processEvents()
    yield dialog
    dialog.close()
    dialog.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _from_start(dialog) -> None:
    dialog.search.clear()
    dialog.show_contents()


def test_happy_handbook_a_longer_text_keeps_the_match_in_view(handbook) -> None:
    """"Trans" found "Transfers"; typing on to "Transfers" jumped past it to
    the next one."""
    _from_start(handbook)
    handbook.search.setText("Trans")
    assert handbook.find_next()
    first = handbook.view.textCursor().selectionStart()
    plain = handbook.view.toPlainText()
    assert plain[first:first + len("Transfers")] == "Transfers"
    handbook.search.setText("Transfers")
    assert handbook.find_next()
    assert handbook.view.textCursor().selectionStart() == first
    assert handbook.find_next()  # Return again: the next one
    assert handbook.view.textCursor().selectionStart() > first


def test_sad_handbook_not_found_goes_when_the_text_changes(handbook) -> None:
    _from_start(handbook)
    handbook.search.setText("no-such-text-anywhere-xyz")
    assert handbook.find_next() is False
    assert handbook.search_hint.text() == "Not found"
    handbook.search.setText("Transfers")
    assert handbook.search_hint.text() == ""


def test_edge_handbook_find_is_case_blind_and_knows_umlauts() -> None:
    from ui.handbook import HandbookDialog

    dialog = HandbookDialog(None, language="de")
    try:
        for text in ("größe", "GRÖßE", "EINSTELLUNGEN"):
            dialog.search.setText(text)
            assert dialog.find_next(), text
            assert dialog.view.textCursor().selectedText().casefold() == text.casefold()
    finally:
        dialog.close()
        dialog.deleteLater()


# --- patterns in the pane filter ----------------------------------------------


@pytest.mark.parametrize("text, expected", [
    ("*.txt", [NFD_APFEL, "Birne.txt"]),
    ("*.TXT *.md", [NFD_APFEL, "Birne.txt", "Straße.md"]),
    ("?irne*", ["Birne.txt"]),
    ("äpfel.*", [NFD_APFEL]),
    ("*.pdf", []),
])
def test_happy_the_filter_takes_name_patterns(pane, text, expected) -> None:
    """"*.pdf" - the habit from every other file manager and from Find
    Files and the Duplicate Finder here - showed nothing at all."""
    pane._filter_edit.setText(text)
    pump()
    assert shown(pane) == sorted(expected)


def test_sad_brackets_and_plain_text_stay_plain(tmp_path) -> None:
    (tmp_path / "Film [1080p].mkv").write_text("x")
    (tmp_path / "other.mkv").write_text("x")
    from ui.file_pane import FilePaneWidget

    widget = FilePaneWidget(LocalFS())
    try:
        widget.navigate(str(tmp_path))
        widget._filter_edit.setText("[1080")
        pump()
        assert shown(widget) == ["Film [1080p].mkv"]
        widget._filter_edit.setText("*[1080p]*")  # a pattern: [ is a character
        pump()
        assert shown(widget) == ["Film [1080p].mkv"]
    finally:
        _close(widget)


def test_edge_a_pattern_after_a_plain_text_is_not_narrowed_by_it(pane) -> None:
    """The filter narrows the previous result while a plain text grows;
    "t" then "t*" (no longer a part of the name) must look at every row."""
    pane._filter_edit.setText("t")
    pump()
    pane._filter_edit.setText("*t")
    pump()
    assert shown(pane) == sorted([NFD_APFEL, "Birne.txt"])
    pane._filter_edit.setText("*t*")
    pump()
    assert shown(pane) == sorted([NFD_APFEL, "Birne.txt", "Straße.md"])
