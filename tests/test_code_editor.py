"""The full editor (punch-list item 48).

Operator: *„brauchen einen fullblown editor in axross, mit tab support,
syntax higlighting, copy/paste etc.pp. allen wichtigen funktionen"*. Decided:
QPlainTextEdit + Pygments (QScintilla is GPL; axross is Apache-2.0).

- core/text_document.py: load, encode and save of one text file through any
  backend - the save fidelity of the old dialog (each line keeps its own
  ending, BOM, NBSP, conflict check, atomic write) moved here so the tabs
  and the old dialog share it; plus switching line endings and encoding.
- ui/code_editor.py: the text widget - line numbers, current line,
  Pygments highlighting, zoom.
- ui/editor_window.py: one window of tabs per main window - open from the
  panes, Save/Save All, find/replace with regex, go to line, wrap, line
  ending and encoding menus, read-only tabs; closing asks for unsaved tabs.
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

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.text_document import TextDocument  # noqa: E402

APP = QApplication.instance() or QApplication([])
FS = LocalFS()


# -- the document ---------------------------------------------------------------------


@pytest.mark.parametrize("raw", [
    b"a\r\nb\r\nc\r\n", b"a\nb\nc", b"a\rb\r", b"\xef\xbb\xbfbom\nline\n",
    b"mixed\r\nends\nhere\r", b"nbsp\xc2\xa0and\xe2\x80\xa8sep\n", b"latin \xe9\xa0\n", b"",
])
def test_happy_an_untouched_document_saves_its_own_bytes(tmp_path, raw):
    path = tmp_path / "f.txt"
    path.write_bytes(raw)
    doc = TextDocument(FS, str(path))
    text = doc.load()
    assert doc.encode(doc.blocks_of(text)) == raw


def test_happy_encoding_detection_and_bom(tmp_path):
    (tmp_path / "u.txt").write_bytes("über\n".encode())
    (tmp_path / "l.txt").write_bytes("caf\xe9\n".encode("latin-1"))
    (tmp_path / "b.txt").write_bytes(b"\xef\xbb\xbfx\n")
    (tmp_path / "w.txt").write_bytes("wide\n".encode("utf-16"))
    docs = {n: TextDocument(FS, str(tmp_path / n)) for n in ("u.txt", "l.txt", "b.txt", "w.txt")}
    assert docs["u.txt"].load() == "über\n" and docs["u.txt"].encoding == "utf-8"
    assert docs["l.txt"].load() == "café\n" and docs["l.txt"].encoding == "latin-1"
    assert docs["b.txt"].load() == "x\n" and docs["b.txt"].bom
    assert docs["w.txt"].load() == "wide\n" and docs["w.txt"].encoding == "utf-16"


def test_happy_save_writes_and_remembers(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"one\r\ntwo\r\n")
    doc = TextDocument(FS, str(path))
    doc.load()
    assert doc.save(["one", "two!", ""]) == "saved"
    assert path.read_bytes() == b"one\r\ntwo!\r\n"
    assert doc.save(["one", "two!", "three"]) == "saved"
    assert path.read_bytes() == b"one\r\ntwo!\r\nthree"


def test_sad_a_file_changed_on_disk_is_a_conflict_until_forced(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"one\n")
    doc = TextDocument(FS, str(path))
    doc.load()
    path.write_bytes(b"someone else\n")
    assert doc.save(["mine", ""]) == "conflict"
    assert path.read_bytes() == b"someone else\n"
    assert doc.save(["mine", ""], force=True) == "saved"
    assert path.read_bytes() == b"mine\n"


def test_sad_unencodable_text_raises_and_writes_nothing(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"caf\xe9\n")
    doc = TextDocument(FS, str(path))
    doc.load()
    with pytest.raises(UnicodeEncodeError):
        doc.save(["日本", ""])
    assert path.read_bytes() == b"caf\xe9\n"


def test_sad_a_never_loaded_document_refuses_to_save(tmp_path):
    doc = TextDocument(FS, str(tmp_path / "missing.txt"))
    with pytest.raises(OSError):
        doc.load()
    with pytest.raises(PermissionError):
        doc.save(["x"])


def test_edge_line_ending_conversion(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"a\nb\r\nc\n")
    doc = TextDocument(FS, str(path))
    doc.load()
    doc.set_newline("\r\n")
    assert doc.newline_name == "CRLF"
    doc.save(["a", "b", "c", ""])
    assert path.read_bytes() == b"a\r\nb\r\nc\r\n"


def test_edge_encoding_change(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"caf\xe9\n")
    doc = TextDocument(FS, str(path))
    doc.load()
    doc.set_encoding("utf-8", bom=True)
    doc.save(["café", ""])
    assert path.read_bytes() == b"\xef\xbb\xbfcaf\xc3\xa9\n"
    with pytest.raises(LookupError):
        doc.set_encoding("no-such-codec")


def test_edge_the_open_limit_holds(tmp_path, monkeypatch):
    from core import open_limits

    monkeypatch.setattr(open_limits, "max_open_bytes", lambda: 10)
    path = tmp_path / "big.txt"
    path.write_bytes(b"x" * 11)
    with pytest.raises(OSError, match="limit|cap|large"):
        TextDocument(FS, str(path)).load()


def test_edge_a_remote_backend_round_trip():
    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    with ram.open_write("/r.txt") as fh:
        fh.write(b"remote\r\n")
    doc = TextDocument(ram, "/r.txt")
    assert doc.load() == "remote\r\n"
    doc.save(["remote edited", ""])
    with ram.open_read("/r.txt") as fh:
        assert fh.read() == b"remote edited\r\n"


# -- highlighting and the widget -------------------------------------------------------


def test_happy_language_by_name_and_shebang():
    from ui.code_editor import language_for

    assert language_for("x.py", "") == "Python"
    assert language_for("run", "#!/bin/bash\necho\n") == "Bash"
    assert language_for("Makefile", "") == "Makefile"
    assert language_for("notes.unknownext", "plain words") == "Text only"


@pytest.mark.parametrize("first_line, language", [
    ("#!/usr/bin/env python3", "Python"),
    ("#! /bin/sh", "Bash"),  # a space after "#!" is allowed and common
    ("#!   /usr/bin/perl -w", "Perl"),
    ("#!/usr/bin/env -S python3 -u", "Python"),  # env with options
    ("#!/usr/bin/env LC_ALL=C bash", "Bash"),  # env with a variable
])
def test_edge_shebang_forms_pick_the_interpreter(first_line, language):
    """Bughunt 2026-10-22: "#! /bin/sh" and env with options were plain text."""
    from ui.code_editor import language_for

    assert language_for("script", first_line + "\necho\n") == language


@pytest.mark.parametrize("text", ["#!", "#!\n", "#!/usr/bin/env", "#! ", "#!/usr/bin/env -i"])
def test_sad_a_shebang_without_an_interpreter_is_plain_text(text):
    from ui.code_editor import TEXT_ONLY, language_for

    assert language_for("script", text) == TEXT_ONLY


def test_happy_keywords_get_a_format():
    from ui.code_editor import CodeEditor

    ed = CodeEditor()
    ed.set_language("Python")
    ed.setPlainText("def f():\n    return 1\n")
    APP.processEvents()
    formats = ed.document().firstBlock().layout().formats()
    assert any(r.start == 0 and r.length == 3 for r in formats), [(r.start, r.length) for r in formats]
    ed.set_language("Text only")
    APP.processEvents()
    assert ed.document().firstBlock().layout().formats() == []


def test_edge_line_numbers_grow_with_the_document():
    from ui.code_editor import CodeEditor

    ed = CodeEditor()
    ed.setPlainText("x\n" * 5)
    narrow = ed.line_number_width()
    ed.setPlainText("x\n" * 5000)
    assert ed.line_number_width() > narrow
    ed.show()
    APP.processEvents()
    assert ed.extraSelections()  # the current line


def test_edge_zoom_changes_the_font():
    from ui.code_editor import CodeEditor

    ed = CodeEditor()
    size = ed.font().pointSizeF()
    ed.zoom(2)
    assert ed.font().pointSizeF() == size + 2
    ed.zoom(-100)
    assert ed.font().pointSizeF() >= 6


# -- the window ------------------------------------------------------------------------


@pytest.fixture
def window():
    from ui.editor_window import EditorWindow

    win = EditorWindow()
    win.show()
    yield win
    with mock.patch("ui.editor_window.QMessageBox.question", return_value=QMessageBox.StandardButton.Discard):
        win.close()
    win.deleteLater()
    APP.processEvents()


def _type_at_end(tab, text):
    cursor = tab.editor.textCursor()
    cursor.movePosition(cursor.MoveOperation.End)
    tab.editor.setTextCursor(cursor)
    tab.editor.insertPlainText(text)


def test_happy_tabs_modified_marker_and_save(window, tmp_path):
    a, b = tmp_path / "a.py", tmp_path / "b.txt"
    a.write_text("print(1)\n")
    b.write_text("bee\n")
    ta = window.open_file(FS, str(a))
    tb = window.open_file(FS, str(b))
    assert window.tabs.count() == 2 and window.tabs.tabText(0) == "a.py"
    assert window.open_file(FS, str(a)) is ta and window.tabs.count() == 2  # no duplicate
    _type_at_end(ta, "# x")
    assert window.tabs.tabText(window.tabs.indexOf(ta)).endswith("*")
    window.tabs.setCurrentWidget(ta)
    window.save_current()
    assert a.read_text() == "print(1)\n# x"
    assert not window.tabs.tabText(window.tabs.indexOf(ta)).endswith("*")
    _type_at_end(tb, "!")
    window.save_all()
    assert b.read_text() == "bee\n!"
    assert ta.editor.language == "Python"


def test_edge_one_local_file_opened_from_two_panes_is_one_tab(window, tmp_path):
    """Bughunt 2026-10-22: every local pane has a LocalFS of its own, and the
    tab lookup compared backends by identity - the same file opened from two
    panes became two tabs, each with its own unsaved edits."""
    path = tmp_path / "same.txt"
    path.write_text("one\n")
    first = window.open_file(LocalFS(), str(path))
    second = window.open_file(LocalFS(), str(path))
    assert second is first and window.tabs.count() == 1


def test_sad_another_backend_with_the_same_path_is_another_tab(window, tmp_path):
    from core.mtp_client import MtpSession

    path = tmp_path / "same.txt"
    path.write_text("one\n")
    local = window.open_file(LocalFS(), str(path))
    other = MtpSession.__new__(MtpSession)  # a LocalFS subclass: not the same files
    assert not window._same_backend(local.backend, other)
    assert window._same_backend(local.backend, LocalFS())


def test_happy_find_and_replace_with_regex(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("cat hat cat\nCat bat\n")
    tab = window.open_file(FS, str(p))
    bar = window.find_bar
    window.show_find(replace=True)
    bar.find_edit.setText("c.t")
    bar.regex.setChecked(True)
    assert bar.find_next()
    assert tab.editor.textCursor().selectedText() == "cat"
    bar.case.setChecked(False)
    bar.replace_edit.setText("dog")
    assert bar.replace_all() == 3
    assert tab.editor.toPlainText() == "dog hat dog\ndog bat\n"


def test_happy_case_and_whole_word(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("Cat cat concat\n")
    window.open_file(FS, str(p))
    bar = window.find_bar
    bar.find_edit.setText("cat")
    bar.case.setChecked(True)
    bar.whole_word.setChecked(True)
    bar.replace_edit.setText("X")
    assert bar.replace_all() == 1
    assert window.current_tab().editor.toPlainText() == "Cat X concat\n"


def test_sad_an_invalid_regex_is_said(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("x\n")
    window.open_file(FS, str(p))
    bar = window.find_bar
    bar.regex.setChecked(True)
    bar.find_edit.setText("(unclosed")
    assert not bar.find_next()
    assert "regex" in bar.message.text().lower()


def test_sad_closing_a_modified_tab_asks_and_cancel_keeps_it(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("x\n")
    tab = window.open_file(FS, str(p))
    _type_at_end(tab, "y")
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Cancel):
        window.close_tab(window.tabs.indexOf(tab))
    assert window.tabs.count() == 1
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Save):
        window.close_tab(window.tabs.indexOf(tab))
    assert window.tabs.count() == 0 and p.read_text() == "x\ny"


def test_sad_a_conflict_asks_before_overwriting(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("x\n")
    tab = window.open_file(FS, str(p))
    p.write_text("changed elsewhere\n")
    _type_at_end(tab, "y")
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.No):
        window.save_current()
    assert p.read_text() == "changed elsewhere\n"


def test_sad_read_only_tabs_cannot_change(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("x\n")
    tab = window.open_file(FS, str(p), read_only=True)
    assert tab.editor.isReadOnly()
    window.save_current()
    assert p.read_text() == "x\n"
    assert "[read-only]" in window.tabs.tabText(window.tabs.indexOf(tab))


def test_edge_go_to_line_and_status(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_text("".join(f"line {i}\n" for i in range(1, 101)))
    tab = window.open_file(FS, str(p))
    window.go_to_line(42)
    assert tab.editor.textCursor().blockNumber() == 41
    assert "Ln 42" in window.position_label.text()
    window.go_to_line(100000)
    assert tab.editor.textCursor().blockNumber() == tab.editor.document().blockCount() - 1


def test_edge_line_ending_and_encoding_menus(window, tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"a\nb\n")
    tab = window.open_file(FS, str(p))
    window.set_newline("\r\n")
    assert window.tabs.tabText(window.tabs.indexOf(tab)).endswith("*")
    window.save_current()
    assert p.read_bytes() == b"a\r\nb\r\n"
    window.set_encoding("utf-16")
    window.save_current()
    assert p.read_bytes().decode("utf-16") == "a\r\nb\r\n"
    assert "CRLF" in window.eol_label.text() and "UTF-16" in window.encoding_label.text().upper()


def test_edge_wrap_toggle(window, tmp_path):
    from PyQt6.QtWidgets import QPlainTextEdit

    p = tmp_path / "f.txt"
    p.write_text("x\n")
    tab = window.open_file(FS, str(p))
    window.wrap_action.setChecked(True)
    assert tab.editor.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth


def test_edge_a_file_that_cannot_be_read_opens_no_tab(window, tmp_path):
    with mock.patch("ui.editor_window.QMessageBox.warning") as warned:
        assert window.open_file(FS, str(tmp_path / "missing.txt")) is None
    warned.assert_called_once()
    assert window.tabs.count() == 0


# -- e2e: from the pane --------------------------------------------------------------


def test_e2e_edit_from_the_pane_opens_a_tab_and_refreshes_after_save(tmp_path):
    from ui import main_window as MW

    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "code.py").write_text("x = 1\n")
    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        pane._open_editor(str(folder / "code.py"))
        editor = win._editor_window
        # The file is read off the GUI thread; the editor shows with the tab.
        end = time.time() + 5
        while time.time() < end and editor.tabs.count() == 0:
            APP.processEvents()
            time.sleep(0.01)
        assert editor.isVisible() and editor.tabs.count() == 1
        tab = editor.current_tab()
        assert tab.editor.language == "Python"
        _type_at_end(tab, "y = 2\n")
        editor.save_current()
        assert (folder / "code.py").read_text() == "x = 1\ny = 2\n"

        def size_of_code():
            for r in range(pane._model.rowCount()):
                item = pane._model.get_item(r)
                if item.name == "code.py":
                    return item.size
            return None

        end = time.time() + 5
        while time.time() < end and size_of_code() != len("x = 1\ny = 2\n"):
            APP.processEvents()
            time.sleep(0.01)
        assert size_of_code() == len("x = 1\ny = 2\n")
        pane._open_editor(str(folder / "code.py"))
        assert editor.tabs.count() == 1  # the same tab again
        with mock.patch("ui.editor_window.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Discard):
            editor.close()
    finally:
        win.close()
        win.deleteLater()


# -- round-2 verification: byte fidelity beyond UTF-8 ------------------------------------


def test_edge_a_utf16_big_endian_file_keeps_its_byte_order_after_an_edit(tmp_path):
    path = tmp_path / "be.txt"
    path.write_bytes(b"\xfe\xff" + "ab\n".encode("utf-16-be"))
    doc = TextDocument(FS, str(path))
    assert doc.load() == "ab\n"
    assert doc.save(["ab", "c"]) == "saved"
    assert path.read_bytes() == b"\xfe\xff" + "ab\nc".encode("utf-16-be")


def test_edge_utf16_little_endian_round_trips_and_new_utf16_is_little_endian(tmp_path):
    path = tmp_path / "le.txt"
    raw = b"\xff\xfe" + "x\r\ny".encode("utf-16-le")
    path.write_bytes(raw)
    doc = TextDocument(FS, str(path))
    assert doc.encode(doc.blocks_of(doc.load())) == raw
    other = tmp_path / "u8.txt"
    other.write_bytes(b"q\n")
    doc = TextDocument(FS, str(other))
    doc.load()
    doc.set_encoding("utf-16")
    doc.save(["q", ""])
    assert other.read_bytes() == b"\xff\xfe" + "q\n".encode("utf-16-le")


@pytest.mark.parametrize("raw", [b"\xff\xfeA\x00B", b"\xfe\xff\xd8\x00", b"\xff\xfe\x00\xdc"])
def test_sad_a_broken_utf16_file_opens_byte_faithful_instead_of_raising(tmp_path, raw):
    path = tmp_path / "broken.txt"
    path.write_bytes(raw)
    doc = TextDocument(FS, str(path))
    text = doc.load()
    assert doc.encoding == "latin-1"
    assert doc.encode(doc.blocks_of(text)) == raw


def test_edge_frame_marks_qt_turns_into_block_breaks_survive_a_save(tmp_path):
    from ui.editor_window import EditorTab

    path = tmp_path / "frame.txt"
    raw = "a﷐b﷑c\n".encode()
    path.write_bytes(raw)
    doc = TextDocument(FS, str(path))
    tab = EditorTab(FS, str(path), doc.load(), doc, read_only=False)
    assert doc.encode(tab.blocks()) == raw


def test_edge_replace_all_leaves_nbsp_and_line_separators_alone(window, tmp_path):
    path = tmp_path / "n.txt"
    path.write_bytes("a b c x\n".encode())
    window.open_file(FS, str(path))
    bar = window.find_bar
    bar.find_edit.setText("x")
    bar.replace_edit.setText("y")
    assert bar.replace_all() == 1
    window.save_current()
    assert path.read_bytes() == "a b c y\n".encode()


def test_e2e_a_utf16_file_with_a_cut_last_byte_opens_in_a_tab(window, tmp_path):
    path = tmp_path / "cut.txt"
    path.write_bytes(b"\xff\xfeh\x00i\x00\n")
    with mock.patch("ui.editor_window.QMessageBox.warning") as warned:
        tab = window.open_file(FS, str(path))
    assert tab is not None and not warned.called
    _type_at_end(tab, "!")
    window.save_current()
    assert path.read_bytes() == b"\xff\xfeh\x00i\x00\n!"


# -- large files: lexing never blocks the window (verification round: 2.9 s per
# typing pause at 117 KB, 38-43 s at 1.9 MB, on the GUI thread) -----------------


def _wait(cond, timeout=30.0):
    import time

    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def _big_python(lines=20_000) -> str:
    return "".join(f"def f{i}(x):\n    return x + {i}  # comment\n" for i in range(lines // 2))


def _formats_of(editor, block_number):
    block = editor.document().findBlockByNumber(block_number)
    return [r.format.foreground().color().name() for r in block.layout().formats()]


def test_happy_a_large_file_is_lexed_off_the_gui_thread():
    import time

    from ui.code_editor import SYNC_LEX_CHARS, CodeEditor

    editor = CodeEditor()
    editor.set_language("Python")
    text = _big_python()
    assert len(text) > SYNC_LEX_CHARS
    start = time.perf_counter()
    editor.setPlainText(text)
    blocked = time.perf_counter() - start
    hl = editor.highlighter
    assert hl.lexing  # the work runs elsewhere
    assert _wait(lambda: not hl.lexing)
    assert _formats_of(editor, 0)  # "def" is coloured once the result is in
    assert blocked < 2.0, blocked  # setPlainText itself, never the lexing


def test_edge_a_stale_result_is_dropped():
    from ui.code_editor import CodeEditor

    editor = CodeEditor()
    editor.set_language("Python")
    editor.setPlainText(_big_python())
    hl = editor.highlighter
    first = hl.generation
    editor.setPlainText(_big_python(30_000))  # replaced before the first result is in
    assert hl.generation > first
    assert _wait(lambda: not hl.lexing)
    assert hl.applied_generation == hl.generation


def test_edge_a_replaced_text_stops_its_lexing_thread():
    """Bughunt 2026-10-22: a lexing thread ran to its end after a newer text
    replaced its own - every typing pause in a large file started one more
    full-text lex, and they all competed for the interpreter with the GUI."""
    import threading

    from ui.code_editor import CodeEditor

    before = set(threading.enumerate())

    def lexers():
        return [t for t in threading.enumerate() if t.name == "axross-lex" and t not in before]

    editor = CodeEditor()
    editor.set_language("Python")
    for extra in range(4):
        editor.setPlainText(_big_python(20_000 + 2 * extra))
    hl = editor.highlighter
    assert _wait(lambda: len(lexers()) <= 1, timeout=5.0), len(lexers())
    assert _wait(lambda: not hl.lexing)
    assert hl.applied_generation == hl.generation and _formats_of(editor, 0)


def _format_spans(editor, block_number):
    block = editor.document().findBlockByNumber(block_number)
    return [(r.start, r.length) for r in block.layout().formats()]


def test_edge_colours_stay_on_their_text_after_an_emoji():
    """Bughunt 2026-10-22: token offsets are Python indexes, block offsets
    QTextCursor positions; each emoji before a token shifted its colour one
    character to the left, on its line and every line below."""
    from ui.code_editor import CodeEditor

    editor = CodeEditor()
    editor.set_language("Python")
    editor.setPlainText("s = '\U0001f600\U0001f600\U0001f600'  # \U0001f600 x\nx = 1  # note\n")
    line = editor.document().findBlockByNumber(1).text()
    assert (line.index("#"), len("# note")) in _format_spans(editor, 1)
    first = editor.document().findBlockByNumber(0).text()
    hash_at = first.index("#")

    def units(text):  # Qt counts each emoji as two
        return len(text.encode("utf-16-le")) // 2

    assert (units(first[:hash_at]), units(first[hash_at:])) in _format_spans(editor, 0)


def test_edge_colours_after_an_emoji_in_a_large_file_lexed_off_the_gui_thread():
    from ui.code_editor import SYNC_LEX_CHARS, CodeEditor

    editor = CodeEditor()
    editor.set_language("Python")
    text = "s = '\U0001f600'\n" + _big_python(4_000)
    assert len(text) > SYNC_LEX_CHARS
    editor.setPlainText(text)
    assert _wait(lambda: not editor.highlighter.lexing)
    line = editor.document().findBlockByNumber(2).text()  # "    return x + 0  # comment"
    assert (line.index("#"), len("# comment")) in _format_spans(editor, 2)


def test_sad_a_small_file_is_still_coloured_at_once():
    from ui.code_editor import CodeEditor

    editor = CodeEditor()
    editor.set_language("Python")
    editor.setPlainText("def f():\n    return 1\n")
    assert not editor.highlighter.lexing and _formats_of(editor, 0)


def _paint_of(editor):
    """Every block's (start, length, colour, bold, italic) as the layout shows it."""
    out, block = [], editor.document().begin()
    while block.isValid():
        out.append([(r.start, r.length, r.format.foreground().color().name(),
                     r.format.fontWeight(), r.format.fontItalic()) for r in block.layout().formats()])
        block = block.next()
    return out


def _settled(editor):
    hl = editor.highlighter
    assert _wait(lambda: not hl.lexing and not hl._timer.isActive())


def _fresh(text):
    from ui.code_editor import CodeEditor

    editor = CodeEditor()
    editor.set_language("Python")
    editor.setPlainText(text)
    _settled(editor)
    return editor


def _type_at(editor, line, column, text):
    from PyQt6.QtGui import QTextCursor

    cursor = QTextCursor(editor.document().findBlockByNumber(line))
    cursor.movePosition(QTextCursor.MoveOperation.Right, n=column)
    cursor.insertText(text)


def _delete_line(editor, line):
    from PyQt6.QtGui import QTextCursor

    cursor = QTextCursor(editor.document().findBlockByNumber(line))
    cursor.movePosition(QTextCursor.MoveOperation.NextBlock, QTextCursor.MoveMode.KeepAnchor)
    cursor.removeSelectedText()


def _relex_now(editor):
    editor.highlighter.relex()
    _settled(editor)


_EDITS = {
    "a keystroke in a line": lambda e: _type_at(e, 7, 4, "y"),
    "a new line": lambda e: _type_at(e, 7, 0, "z = 1\n"),
    "a deleted line": lambda e: _delete_line(e, 5),
    "a triple quote that turns the rest into a string": lambda e: _type_at(e, 3, 0, '"""'),
    "several edits before one pause": lambda e: (_type_at(e, 2, 0, "a = 2\n"), _delete_line(e, 9),
                                                 _type_at(e, 12, 3, "#"), _type_at(e, 1, 0, "\n\n")),
}


@pytest.mark.parametrize("lines", [40, 6_000], ids=["small, lexed at once", "large, lexed off the thread"])
@pytest.mark.parametrize("edit", list(_EDITS), ids=list(_EDITS))
def test_happy_after_an_edit_every_line_shows_what_a_fresh_editor_shows(edit, lines):
    """The relex after a typing pause repaints only the lines whose colours
    changed - the result must be the paint of a fresh editor with that text."""
    editor = _fresh(_big_python(lines))
    _EDITS[edit](editor)
    _relex_now(editor)
    assert _paint_of(editor) == _paint_of(_fresh(editor.toPlainText()))


def test_edge_an_edit_while_the_lexer_runs_still_ends_in_the_fresh_paint():
    editor = _fresh(_big_python(6_000))
    editor.highlighter.relex()  # lexing starts on the old text ...
    _type_at(editor, 4, 0, "q = 3\n")  # ... and the text changes under it
    _delete_line(editor, 20)
    _settled(editor)
    _relex_now(editor)
    assert _paint_of(editor) == _paint_of(_fresh(editor.toPlainText()))


def test_edge_a_line_without_colours_that_gains_some_is_repainted():
    editor = _fresh("x\n" * 30 + "y = 1\n")
    _type_at(editor, 10, 0, "def ")
    _relex_now(editor)
    assert _paint_of(editor) == _paint_of(_fresh(editor.toPlainText()))
    assert _paint_of(editor)[10]


def test_edge_switching_dark_and_light_repaints_every_line_in_the_new_colours():
    text = _big_python(40)
    editor = _fresh(text)
    dark = editor.palette().base().color().lightness() < 128
    before = _paint_of(editor)
    editor.highlighter.set_dark(not dark)
    _settled(editor)
    other = _fresh(text)
    other.highlighter.set_dark(not dark)
    _settled(other)
    assert _paint_of(editor) == _paint_of(other) != before


def _count_highlights(editor, act):
    from ui.code_editor import PygmentsHighlighter

    calls = []
    original = PygmentsHighlighter.highlightBlock

    def counting(self, text):
        calls.append(self.currentBlock().blockNumber())
        return original(self, text)

    with mock.patch.object(PygmentsHighlighter, "highlightBlock", counting):
        act()
    return calls


@pytest.mark.parametrize("edit", ["a keystroke in a line", "a new line", "a deleted line"])
def test_perf_a_typing_pause_in_a_large_file_repaints_a_few_lines_not_all(edit):
    """2026-10-25 performance round: each typing pause in a 2 MB file held
    the GUI thread 0.4 s - the relex repainted all 45,000 lines although one
    had changed. Counted, not timed: the host's load moves timings."""
    editor = _fresh(_big_python(20_000))
    _EDITS[edit](editor)
    calls = _count_highlights(editor, lambda: _relex_now(editor))
    assert len(calls) <= 10, len(calls)
    assert _paint_of(editor) == _paint_of(_fresh(editor.toPlainText()))


def test_perf_sad_a_change_of_every_line_still_repaints_every_line():
    """Negative control: the count above catches a relex that skips lines
    it must repaint - a triple quote at the top recolours the whole file."""
    editor = _fresh(_big_python(20_000))
    _type_at(editor, 0, 0, '"""')
    calls = _count_highlights(editor, lambda: _relex_now(editor))
    assert len(calls) >= 19_000, len(calls)


# -- find and replace where Python and Qt count differently (bughunt 2026-10-22:
# the find bar mixed Python string indexes with QTextCursor positions, which
# count a character outside the BMP - an emoji - as two; and a match across a
# line break never equalled the selection, which holds U+2029 there) -------------


def test_happy_find_selects_the_match_after_an_emoji(window, tmp_path):
    path = tmp_path / "e.txt"
    path.write_text("\U0001f600 x needle y \U0001f601\U0001f602 needle\n")
    tab = window.open_file(FS, str(path))
    bar = window.find_bar
    window.show_find()
    bar.find_edit.setText("needle")
    assert bar.find_next()
    assert tab.editor.textCursor().selectedText() == "needle"
    first = tab.editor.textCursor().selectionStart()
    assert bar.find_next()  # on to the second one, past two more emoji
    assert tab.editor.textCursor().selectedText() == "needle"
    assert tab.editor.textCursor().selectionStart() > first
    assert bar.find_next(backwards=True)
    assert tab.editor.textCursor().selectionStart() == first


def test_happy_replace_one_after_an_emoji_replaces_the_match(window, tmp_path):
    path = tmp_path / "e.txt"
    path.write_text("\U0001f600 cat \U0001f600 cat\n")
    tab = window.open_file(FS, str(path))
    bar = window.find_bar
    window.show_find(replace=True)
    bar.find_edit.setText("cat")
    bar.replace_edit.setText("dog")
    assert bar.find_next()
    bar.replace_one()
    bar.replace_one()
    assert tab.editor.toPlainText() == "\U0001f600 dog \U0001f600 dog\n"


def test_edge_replace_one_replaces_a_match_across_a_line_break(window, tmp_path):
    path = tmp_path / "m.txt"
    path.write_text("a\nb\nc\n")
    tab = window.open_file(FS, str(path))
    bar = window.find_bar
    window.show_find(replace=True)
    bar.regex.setChecked(True)
    bar.find_edit.setText(r"a\nb")
    bar.replace_edit.setText("X")
    assert bar.find_next()
    bar.replace_one()
    assert tab.editor.toPlainText() == "X\nc\n"


def test_edge_replace_one_with_a_no_break_space_in_the_match(window, tmp_path):
    # toPlainText(), which find searches, shows a no-break space as a space.
    path = tmp_path / "n.txt"
    path.write_bytes("one\u00a0two\n".encode())
    tab = window.open_file(FS, str(path))
    bar = window.find_bar
    window.show_find(replace=True)
    bar.find_edit.setText("one two")
    bar.replace_edit.setText("three")
    assert bar.find_next()
    bar.replace_one()
    assert tab.editor.toPlainText() == "three\n"


def test_sad_find_after_an_emoji_that_is_not_there_says_not_found(window, tmp_path):
    path = tmp_path / "e.txt"
    path.write_text("\U0001f600\U0001f600 only\n")
    tab = window.open_file(FS, str(path))
    bar = window.find_bar
    window.show_find()
    bar.find_edit.setText("missing")
    assert not bar.find_next()
    assert bar.message.text() == "Not found"
    assert not tab.editor.textCursor().hasSelection()


# -- closing the main window asks for the editor first (bughunt 2026-10-22:
# MainWindow.closeEvent tore everything down - connections, shells, panes - and
# only then did Qt's quit close the editor window, whose Save then wrote through
# a disconnected backend and whose Cancel left an editor next to a dead, hidden
# main window) --------------------------------------------------------------------


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


def _edited_tab(win, path):
    path.write_text("kept\n")
    win.open_in_editor(FS, str(path))  # read in the background
    end = time.time() + 5
    while time.time() < end and win._editor_window.tabs.count() == 0:
        APP.processEvents()
        time.sleep(0.01)
    tab = win._editor_window.current_tab()
    _type_at_end(tab, "more")
    return tab


def test_sad_closing_the_main_window_asks_for_unsaved_tabs_and_cancel_keeps_it_open(
        main_window, tmp_path):
    win = main_window
    tab = _edited_tab(win, tmp_path / "a.txt")
    pane = win._active_pane
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Cancel) as asked:
        assert win.close() is False
    assert asked.call_count == 1
    assert win.isVisible() and win._editor_window.isVisible() and tab.is_modified()
    assert not pane._shutting_down  # nothing was torn down
    assert (tmp_path / "a.txt").read_text() == "kept\n"


def test_happy_save_on_closing_the_main_window_writes_before_the_teardown(
        main_window, tmp_path):
    win = main_window
    _edited_tab(win, tmp_path / "a.txt")
    pane = win._active_pane
    torn_down_at_save = []
    real_save = TextDocument.save

    def save(doc, blocks, **kwargs):
        torn_down_at_save.append(pane._shutting_down)
        return real_save(doc, blocks, **kwargs)

    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Save), \
            mock.patch.object(TextDocument, "save", save):
        assert win.close() is True
    assert (tmp_path / "a.txt").read_text() == "kept\nmore"
    assert torn_down_at_save == [False]


def test_edge_an_editor_without_changes_closes_with_the_main_window_unasked(
        main_window, tmp_path):
    win = main_window
    (tmp_path / "b.txt").write_text("same\n")
    win.open_in_editor(FS, str(tmp_path / "b.txt"))
    with mock.patch("ui.editor_window.QMessageBox.question") as asked:
        assert win.close() is True
    assert not asked.called and not win._editor_window.isVisible()
