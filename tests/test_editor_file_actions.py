"""The editor's New, Open…, Save As… and auto-indent (wish-list item 45).

Operator: *„brauchen einen fullblown editor in axross, mit tab support,
syntax higlighting, copy/paste etc.pp. allen wichtigen funktionen"*. The
editor window (ui/editor_window.py) had tabs, Pygments, find/replace, go to
line, wrap, zoom, encodings - but no way to start a file, open one without a
pane, or save under another name, and Enter started every line at column 0.

Decided here:
- New (Ctrl+N): an untitled tab; its first save asks where (local file system).
- Open… (Ctrl+O): a local file dialog. axross has no remote file-picker
  dialog; remote files are opened from their pane (Edit / F4), the pane is
  that backend's browser.
- Save As… (Ctrl+Shift+S): a local tab gets the file dialog, a remote tab a
  path on the same backend (the editor saves through the tab's backend, so
  Save As does too). An existing target asks before it is overwritten.
  Save All moved from Ctrl+Shift+S to Ctrl+L (Kate's key).
- Auto-indent on Enter: the new line keeps the leading whitespace before the
  cursor; after ":" (Python) or "{" (brace languages) one more level.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QAction  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.text_document import TextDocument  # noqa: E402

APP = QApplication.instance() or QApplication([])
FS = LocalFS()
YES, NO = QMessageBox.StandardButton.Yes, QMessageBox.StandardButton.No


@pytest.fixture
def window():
    from ui.editor_window import EditorWindow

    win = EditorWindow()
    win.show()
    yield win
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Discard):
        win.close()
    win.deleteLater()
    APP.processEvents()


def _ram():
    from core.ram_fs import RamFsSession

    return RamFsSession()


def _ram_file(ram, path: str, data: bytes) -> None:
    with ram.open_write(path) as fh:
        fh.write(data)


def _ram_read(ram, path: str) -> bytes:
    with ram.open_read(path) as fh:
        return fh.read()


def _action(win, text: str) -> QAction:
    for action in win.findChildren(QAction):
        if action.text().replace("&", "") == text:
            return action
    raise AssertionError(f"no action {text!r}")


# -- the document: new and save as ------------------------------------------------------


def test_happy_a_new_document_saves_as_utf8_lf(tmp_path):
    doc = TextDocument.untitled()
    target = tmp_path / "new.txt"
    doc.save_as(FS, str(target), ["one", "two", ""])
    assert target.read_bytes() == b"one\ntwo\n"
    assert doc.backend is FS and doc.path == str(target) and doc.loaded
    # Now an ordinary file: a later save checks for changes on disk again.
    target.write_text("changed elsewhere\n")
    assert doc.save(["x"]) == "conflict"


def test_sad_an_untitled_document_cannot_save_in_place():
    doc = TextDocument.untitled()
    with pytest.raises(PermissionError):
        doc.save(["x"])


def test_edge_save_as_keeps_encoding_bom_and_line_endings(tmp_path):
    source = tmp_path / "w.txt"
    source.write_bytes(b"\xef\xbb\xbfa\r\nb\r\n")
    doc = TextDocument(FS, str(source))
    text = doc.load()
    copy = tmp_path / "copy.txt"
    doc.save_as(FS, str(copy), doc.blocks_of(text))
    assert copy.read_bytes() == b"\xef\xbb\xbfa\r\nb\r\n"
    assert source.read_bytes() == b"\xef\xbb\xbfa\r\nb\r\n"  # untouched


def test_edge_save_as_to_a_remote_backend():
    ram = _ram()
    _ram_file(ram, "/a.txt", b"remote\n")
    doc = TextDocument(ram, "/a.txt")
    doc.load()
    doc.save_as(ram, "/b.txt", ["remote", "more", ""])
    assert _ram_read(ram, "/b.txt") == b"remote\nmore\n"
    assert _ram_read(ram, "/a.txt") == b"remote\n"


# -- New ---------------------------------------------------------------------------------


def test_happy_new_opens_an_untitled_tab_and_its_save_asks_where(window, tmp_path):
    tab = window.new_tab()
    assert window.tabs.count() == 1 and window.current_tab() is tab
    assert window.tabs.tabText(0) == "Untitled-1" and not tab.is_modified()
    tab.editor.insertPlainText("hello")
    assert window.tabs.tabText(0) == "Untitled-1 *"
    target = tmp_path / "hello.py"
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(target))) as asked:
        assert window.save_current() is True
    asked.assert_called_once()
    assert target.read_text() == "hello"
    assert window.tabs.tabText(0) == "hello.py" and tab.path == str(target)
    assert tab.editor.language == "Python"  # follows the new name


def test_sad_cancelling_the_save_dialog_of_an_untitled_tab_saves_nothing(window, tmp_path):
    tab = window.new_tab()
    tab.editor.insertPlainText("draft")
    with mock.patch.object(window, "_ask_save_path", return_value=None):
        assert window.save_current() is False
    assert tab.is_modified() and tab.path == ""
    assert list(tmp_path.iterdir()) == []


def test_sad_closing_a_modified_untitled_tab_asks_and_save_then_cancel_keeps_it(window):
    tab = window.new_tab()
    tab.editor.insertPlainText("draft")
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Save), \
            mock.patch.object(window, "_ask_save_path", return_value=None):
        assert window.close_tab(window.tabs.indexOf(tab)) is False
    assert window.tabs.count() == 1


def test_edge_new_numbers_untitled_tabs_and_an_empty_one_closes_unasked(window):
    first, second = window.new_tab(), window.new_tab()
    assert [window.tabs.tabText(i) for i in range(2)] == ["Untitled-1", "Untitled-2"]
    with mock.patch("ui.editor_window.QMessageBox.question") as asked:
        assert window.close_tab(window.tabs.indexOf(first)) is True
    assert not asked.called
    assert window.new_tab() is not second and window.tabs.count() == 2


def test_edge_save_all_asks_where_for_a_modified_untitled_tab(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("x\n")
    named = window.open_file(FS, str(p))
    named.editor.insertPlainText("y")
    untitled = window.new_tab()
    untitled.editor.insertPlainText("new")
    target = tmp_path / "n.txt"
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(target))):
        assert window.save_all() is True
    assert target.read_text() == "new" and p.read_text().startswith("y")


# -- Open… -------------------------------------------------------------------------------


def test_happy_open_dialog_opens_a_local_file_in_a_tab(window, tmp_path):
    p = tmp_path / "o.json"
    p.write_text('{"a": 1}\n')
    with mock.patch.object(window, "_ask_open_paths", return_value=[str(p)]):
        tabs = window.open_dialog()
    assert len(tabs) == 1 and tabs[0].path == str(p) and type(tabs[0].backend) is LocalFS
    assert tabs[0].editor.language == "JSON"


def test_sad_open_dialog_cancelled_opens_nothing(window):
    with mock.patch.object(window, "_ask_open_paths", return_value=[]):
        assert window.open_dialog() == []
    assert window.tabs.count() == 0


def test_edge_open_dialog_of_an_already_open_file_selects_its_tab(window, tmp_path):
    p = tmp_path / "o.txt"
    p.write_text("x\n")
    first = window.open_file(LocalFS(), str(p))
    window.new_tab()
    with mock.patch.object(window, "_ask_open_paths", return_value=[str(p)]):
        assert window.open_dialog() == [first]
    assert window.current_tab() is first and window.tabs.count() == 2


# -- Save As… ----------------------------------------------------------------------------


def test_happy_save_as_writes_a_new_local_file_and_the_tab_follows(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("one\n")
    tab = window.open_file(FS, str(p))
    tab.editor.insertPlainText("zero ")
    saved = []
    window.saved.connect(lambda b, path: saved.append(path))
    target = tmp_path / "b.txt"
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(target))):
        assert window.save_as() is True
    assert target.read_text() == "zero one\n" and p.read_text() == "one\n"
    assert tab.path == str(target) and not tab.is_modified()
    assert window.tabs.tabText(0) == "b.txt" and str(target) in window.tabs.tabToolTip(0)
    assert saved == [str(target)]


def test_happy_save_as_on_a_remote_tab_asks_for_a_path_on_the_same_backend(window):
    ram = _ram()
    _ram_file(ram, "/dir/a.txt", b"remote\n")
    tab = window.open_file(ram, "/dir/a.txt")
    with mock.patch("ui.editor_window.QInputDialog.getText",
                    return_value=("/dir/b.txt", True)) as asked:
        assert window.save_as() is True
    assert asked.call_args.kwargs.get("text") == "/dir/a.txt"
    assert _ram_read(ram, "/dir/b.txt") == b"remote\n"
    assert tab.backend is ram and tab.path == "/dir/b.txt"


def test_sad_save_as_over_an_existing_file_asks_and_no_keeps_it(window, tmp_path):
    p, other = tmp_path / "a.txt", tmp_path / "b.txt"
    p.write_text("mine\n")
    other.write_text("theirs\n")
    tab = window.open_file(FS, str(p))
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(other))), \
            mock.patch("ui.editor_window.QMessageBox.question", return_value=NO) as asked:
        assert window.save_as() is False
    asked.assert_called_once()
    assert other.read_text() == "theirs\n" and tab.path == str(p)
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(other))), \
            mock.patch("ui.editor_window.QMessageBox.question", return_value=YES):
        assert window.save_as() is True
    assert other.read_text() == "mine\n"


def test_sad_save_as_onto_a_file_open_in_another_tab_is_refused(window, tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("a\n")
    b.write_text("b\n")
    window.open_file(FS, str(b))
    tab_a = window.open_file(FS, str(a))
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(b))), \
            mock.patch("ui.editor_window.QMessageBox.warning") as warned:
        assert window.save_as(tab_a) is False
    warned.assert_called_once()
    assert b.read_text() == "b\n"


def test_sad_save_as_of_a_read_only_tab_is_refused(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("a\n")
    window.open_file(FS, str(p), read_only=True)
    with mock.patch.object(window, "_ask_save_path") as asked:
        assert window.save_as() is False
    assert not asked.called


def test_sad_save_as_into_a_missing_folder_reports_the_error(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("a\n")
    tab = window.open_file(FS, str(p))
    target = tmp_path / "missing" / "b.txt"
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(target))), \
            mock.patch("ui.editor_window.QMessageBox.critical") as said:
        assert window.save_as() is False
    said.assert_called_once()
    assert tab.path == str(p)


def test_edge_save_as_to_its_own_path_is_a_plain_save(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("a\n")
    tab = window.open_file(FS, str(p))
    tab.editor.insertPlainText("b")
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(p))), \
            mock.patch("ui.editor_window.QMessageBox.question") as asked:
        assert window.save_as() is True
    assert not asked.called  # no "overwrite?" for the file itself
    assert p.read_text() == "ba\n"


def test_edge_a_remote_save_as_with_an_empty_path_saves_nothing(window):
    ram = _ram()
    _ram_file(ram, "/a.txt", b"x\n")
    tab = window.open_file(ram, "/a.txt")
    with mock.patch("ui.editor_window.QInputDialog.getText", return_value=("   ", True)):
        assert window.save_as() is False
    assert tab.path == "/a.txt" and not ram.exists("/   ")


# -- shortcuts ---------------------------------------------------------------------------


def test_happy_file_menu_shortcuts(window):
    keys = {name: _action(window, name).shortcut().toString()
            for name in ("New", "Open…", "Save", "Save As…", "Save All", "Close Tab")}
    assert keys == {"New": "Ctrl+N", "Open…": "Ctrl+O", "Save": "Ctrl+S",
                    "Save As…": "Ctrl+Shift+S", "Save All": "Ctrl+L", "Close Tab": "Ctrl+W"}


def test_sad_no_shortcut_or_mnemonic_is_bound_twice_in_the_editor(window):
    from tests.test_menu_audit import _mnemonic

    owners: dict[str, list[str]] = {}
    for action in window.findChildren(QAction):
        for seq in action.shortcuts():
            owners.setdefault(seq.toString(), []).append(action.text())
    assert {k: v for k, v in owners.items() if len(v) > 1} == {}

    def walk(menu):
        letters: dict[str, list[str]] = {}
        for action in menu.actions():
            if action.isSeparator():
                continue
            if _mnemonic(action.text()):
                letters.setdefault(_mnemonic(action.text()), []).append(action.text())
            if action.menu() is not None:
                walk(action.menu())
        assert {k: v for k, v in letters.items() if len(v) > 1} == {}, menu.title()

    for top in window.menuBar().actions():
        walk(top.menu())


# -- auto-indent -------------------------------------------------------------------------


@pytest.mark.parametrize("before, language, indent", [
    ("    x = 1", "Python", "    "),
    ("def f():", "Python", "    "),
    ("    if x:  ", "Python", "        "),
    ("int main() {", "C", "    "),
    ("\tif (x) {", "Go", "\t\t"),
    ("  key: value", "YAML", "  "),
    ("parent:", "YAML", "  "),
    ("plain", "Text only", ""),
])
def test_happy_auto_indent_of_the_next_line(before, language, indent):
    from ui.code_editor import auto_indent

    assert auto_indent(before, language) == indent


@pytest.mark.parametrize("before, language, indent", [
    ("    ends with a colon:", "Text only", "    "),  # no extra level without a language rule
    ("int x = {", "Python", ""),                       # "{" is no block in Python
    ("    # comment:", "Python", "    "),              # a comment's colon opens nothing
    ("s = '{'", "JavaScript", ""),                     # the line does not end with "{"
])
def test_sad_no_extra_level_where_the_language_has_none(before, language, indent):
    from ui.code_editor import auto_indent

    assert auto_indent(before, language) == indent


@pytest.mark.parametrize("before, language, indent", [
    ("", "Python", ""),
    ("    ", "Python", "    "),       # cursor inside the indentation
    (" \t x", "Text only", " \t "),   # mixed whitespace is kept as it is
    (":", "Python", "    "),
])
def test_edge_auto_indent_corner_cases(before, language, indent):
    from ui.code_editor import auto_indent

    assert auto_indent(before, language) == indent


def test_e2e_enter_in_the_editor_window_indents_and_undo_takes_it_back(window, tmp_path):
    p = tmp_path / "m.py"
    p.write_text("class A:\n    def f(self):")
    tab = window.open_file(FS, str(p))
    editor = tab.editor
    cursor = editor.textCursor()
    cursor.movePosition(cursor.MoveOperation.End)
    editor.setTextCursor(cursor)
    QTest.keyClick(editor, Qt.Key.Key_Return)
    QTest.keyClicks(editor, "return 1")
    assert tab.blocks()[-1] == "        return 1"
    QTest.keyClick(editor, Qt.Key.Key_Enter, Qt.KeyboardModifier.KeypadModifier)
    assert tab.blocks()[-1] == "        "
    editor.undo()
    assert tab.blocks()[-1] == "        return 1"  # the newline and its indent: one step


def test_e2e_shortcuts_drive_new_type_save_as_and_open(window, tmp_path):
    """Ctrl+N, typing with auto-indent, Ctrl+S (asks where), Ctrl+Shift+S,
    Ctrl+O - each through the window's real key handling."""
    window.activateWindow()
    window.tabs.setFocus()
    APP.processEvents()
    QTest.keyClick(window.tabs, Qt.Key.Key_N, Qt.KeyboardModifier.ControlModifier)
    assert window.tabs.count() == 1
    editor = window.current_tab().editor
    QTest.keyClicks(editor, "if x {")
    QTest.keyClick(editor, Qt.Key.Key_Return)
    QTest.keyClicks(editor, "y")
    first = tmp_path / "first.txt"
    with mock.patch("ui.editor_window.QFileDialog.getSaveFileName",
                    return_value=(str(first), "")):
        QTest.keyClick(editor, Qt.Key.Key_S, Qt.KeyboardModifier.ControlModifier)
    assert first.read_text() == "if x {\ny"  # Text only: no extra level for "{"
    second = tmp_path / "second.txt"
    with mock.patch("ui.editor_window.QFileDialog.getSaveFileName",
                    return_value=(str(second), "")):
        QTest.keyClick(editor, Qt.Key.Key_S,
                       Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
    assert second.read_text() == first.read_text()
    assert window.current_tab().path == str(second)
    with mock.patch("ui.editor_window.QFileDialog.getOpenFileNames",
                    return_value=([str(first)], "")):
        QTest.keyClick(editor, Qt.Key.Key_O, Qt.KeyboardModifier.ControlModifier)
    assert window.tabs.count() == 2 and window.current_tab().path == str(first)


def test_edge_a_remote_save_as_with_a_bare_name_stays_in_the_tabs_folder(window):
    ram = _ram()
    ram.mkdir("/dir")
    _ram_file(ram, "/dir/a.txt", b"x\n")
    tab = window.open_file(ram, "/dir/a.txt")
    with mock.patch("ui.editor_window.QInputDialog.getText", return_value=("c.txt", True)):
        assert window.save_as() is True
    assert tab.path == "/dir/c.txt" and _ram_read(ram, "/dir/c.txt") == b"x\n"


def test_edge_reload_of_an_untitled_tab_does_nothing(window):
    tab = window.new_tab()
    tab.editor.insertPlainText("keep")
    window.reload_current()
    assert tab.blocks() == ["keep"] and tab.is_modified()


# -- reaching the editor without a file ----------------------------------------------------


@pytest.fixture
def main_window(tmp_path):
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.show()
    yield win
    editor = getattr(win, "_editor_window", None)
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Discard):
        if editor is not None:
            editor.close()
        win.close()
    win.deleteLater()
    APP.processEvents()


def _tools_action(win, text):
    tools = next(a.menu() for a in win.menuBar().actions() if a.text().replace("&", "") == "Tools")
    return next(a for a in tools.actions() if a.text().replace("&", "") == text)


def test_e2e_tools_text_editor_opens_the_editor_with_an_untitled_tab(main_window, tmp_path):
    win = main_window
    _tools_action(win, "Text Editor").trigger()
    editor = win._editor_window
    assert editor.isVisible() and editor.tabs.count() == 1 and editor.current_tab().untitled
    editor.current_tab().editor.insertPlainText("note")
    target = tmp_path / "note.txt"
    with mock.patch("ui.editor_window.QFileDialog.getSaveFileName", return_value=(str(target), "")):
        assert editor.save_current() is True
    assert target.read_text() == "note"


def test_edge_tools_text_editor_again_adds_no_second_untitled_tab(main_window, tmp_path):
    win = main_window
    win.show_editor()
    win.show_editor()
    assert win._editor_window.tabs.count() == 1


def test_sad_closing_the_main_window_asks_for_a_modified_untitled_tab(main_window):
    win = main_window
    win.show_editor()
    win._editor_window.current_tab().editor.insertPlainText("draft")
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Cancel) as asked:
        assert win.close() is False
    assert asked.call_count == 1 and win._editor_window.isVisible()


# -- round-2 review ----------------------------------------------------------------------


def test_sad_save_as_onto_a_folder_is_refused_without_asking_to_replace(window, tmp_path):
    p = tmp_path / "a.txt"
    p.write_text("a\n")
    (tmp_path / "folder").mkdir()
    tab = window.open_file(FS, str(p))
    with mock.patch.object(window, "_ask_save_path", return_value=(FS, str(tmp_path / "folder"))), \
            mock.patch("ui.editor_window.QMessageBox.question") as asked, \
            mock.patch("ui.editor_window.QMessageBox.warning") as warned:
        assert window.save_as() is False
    assert not asked.called and warned.call_count == 1
    assert (tmp_path / "folder").is_dir() and tab.path == str(p)


def test_edge_a_relative_remote_save_as_path_is_below_the_tabs_folder(window):
    ram = _ram()
    ram.mkdir("/dir")
    ram.mkdir("/dir/sub")
    _ram_file(ram, "/dir/a.txt", b"x\n")
    tab = window.open_file(ram, "/dir/a.txt")
    with mock.patch("ui.editor_window.QInputDialog.getText", return_value=("sub/c.txt", True)):
        assert window.save_as() is True
    assert tab.path == "/dir/sub/c.txt" and _ram_read(ram, "/dir/sub/c.txt") == b"x\n"
