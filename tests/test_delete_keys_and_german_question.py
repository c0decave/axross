"""Del moves to the trash, Shift+Del deletes permanently (default No), and
the question speaks the interface language.

UX review round 5 (blocker): the Delete / Move to Trash flow was English and
garbled in German - title "Delete", "Delete 1 item(s)?", "löschen: 1 item(s);
1 file(s), 0 dir(s); 300 byte(s)", "Move to Trash: versteckte Einträge",
"Move to Trash abgebrochen…", "Deleted 1 of 1 item(s).". Del deleted
permanently, and the permanent delete's question had no default button, so
Enter said Yes.

Now Del moves the selection to the trash where the connection has one (a
connection without rename - POP3, TFTP, … - has none: there Del asks for a
permanent delete), Shift+Del deletes permanently after a question whose
default is No, and every text goes through tr()/tr_n with sizes such as
"180,1 KB".
"""

from __future__ import annotations

import html
import os
import re
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(done, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def window(tmp_path):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        win = MW.MainWindow()
    win._reconnect_timer.stop()
    win._quit_with_transfers = True
    folder = tmp_path / "a"
    folder.mkdir()
    (folder / "todo.txt").write_bytes(b"x" * 300)
    (folder / "big.bin").write_bytes(b"x" * 184_401)
    pane = win._panes[0]
    pane.navigate(str(folder))
    assert _wait(lambda: pane._table.model().rowCount() >= 3)
    win.test_folder = folder
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.fixture
def german(monkeypatch):
    from core import i18n

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))


def _select(pane, *names) -> None:
    table = pane._table
    table.clearSelection()
    flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
    for row in range(table.model().rowCount()):
        index = table.model().index(row, 0)
        if index.data() in names:
            table.selectionModel().setCurrentIndex(
                index, QItemSelectionModel.SelectionFlag.NoUpdate)
            table.selectionModel().select(index, flags)
    table.setFocus()


def _ask(pane, key=None, mods=Qt.KeyboardModifier.NoModifier, answer=QMessageBox.StandardButton.No):
    """Press *key* (or start nothing) and return each question as
    (title, text, default button)."""
    asked = []

    def question(_parent, title, text, _buttons=None, default=None, *a, **k):
        # ui.markup_guard may wrap the text in <qt …> to keep its line breaks.
        text = html.unescape(re.sub(r"</?qt[^>]*>", "", text))
        asked.append((title, text, default))
        return answer

    with mock.patch("ui.file_pane.QMessageBox.question", side_effect=question):
        QTest.keyClick(pane._table, key, mods)
        assert _wait(lambda: bool(asked) and not pane.removal_running)
    return asked


# --- happy -----------------------------------------------------------------


def test_happy_del_moves_to_the_trash_and_shift_del_deletes_permanently(window):
    pane = window._panes[0]
    _select(pane, "todo.txt")
    calls = []
    with mock.patch.object(pane, "_start_removal", side_effect=lambda trash: calls.append(trash)):
        QTest.keyClick(pane._table, Qt.Key.Key_Delete)
        QTest.keyClick(pane._table, Qt.Key.Key_Delete, Qt.KeyboardModifier.ShiftModifier)
    assert calls == [True, False]


def test_happy_the_permanent_delete_question_defaults_to_no(window):
    pane = window._panes[0]
    _select(pane, "todo.txt")
    [(title, text, default)] = _ask(pane, Qt.Key.Key_Delete, Qt.KeyboardModifier.ShiftModifier)
    assert default == QMessageBox.StandardButton.No
    assert title == "Delete Permanently"
    assert text.startswith("Delete 1 item permanently? This cannot be undone.")
    assert "In total: 1 file, 300 B" in text
    assert (window.test_folder / "todo.txt").exists()  # No kept it


def test_happy_the_trash_question_in_german(window, german):
    pane = window._panes[0]
    _select(pane, "big.bin")
    [(title, text, default)] = _ask(pane, Qt.Key.Key_Delete)
    assert title == "In den Trash verschieben"
    assert text.startswith("1 Element in den Trash verschieben?")
    assert "Insgesamt: 1 Datei, 180,1 KB" in text
    assert default == QMessageBox.StandardButton.Yes  # the trash can be undone


# --- sad -------------------------------------------------------------------


def test_sad_no_english_or_item_s_in_the_german_delete_flow(window, german):
    pane = window._panes[0]
    _select(pane, "todo.txt", "big.bin")
    [(title, text, _default)] = _ask(
        pane, Qt.Key.Key_Delete, Qt.KeyboardModifier.ShiftModifier,
        answer=QMessageBox.StandardButton.Yes)
    for english in ("item(s)", "file(s)", "dir(s)", "byte(s)", "Delete", "delete:"):
        assert english not in title + text, english
    assert text.startswith("2 Elemente endgültig löschen?")
    assert _wait(lambda: not (window.test_folder / "todo.txt").exists())
    assert _wait(lambda: "gelöscht" in pane._status.text())
    assert pane._status.text().startswith("2 von 2 Elementen gelöscht")


def test_sad_a_cancelled_trash_says_so_in_german(window, german):
    pane = window._panes[0]
    _select(pane, "todo.txt")
    _ask(pane, Qt.Key.Key_Delete)  # answered No
    from ui.file_pane import _removal_cancelled_text

    assert _removal_cancelled_text(True) == (
        "Verschieben in den Trash abgebrochen – nichts wurde angefasst.")
    assert "Move to Trash" not in _removal_cancelled_text(True)


# --- edge ------------------------------------------------------------------


def test_edge_a_connection_without_trash_asks_for_a_permanent_delete_on_del(window):
    from core.trash import supports_trash

    pane = window._panes[0]
    assert pane.can_trash()  # local: a trash
    with mock.patch.object(type(pane._backend), "supports_trash", False, create=True):
        assert not supports_trash(pane._backend)
        _select(pane, "todo.txt")
        menu = pane._build_context_menu()
        commands = {a.property("axCommand"): a for a in menu.actions()}
        assert "trash" not in commands
        assert commands["delete"].shortcut().toString() == "Del"
        menu.deleteLater()
        [(title, _text, default)] = _ask(pane, Qt.Key.Key_Delete)
    assert title == "Delete Permanently" and default == QMessageBox.StandardButton.No


def test_edge_backends_without_rename_have_no_trash():
    from core.trash import supports_trash

    class Pop3Session:  # the class name the registry gives POP3
        pass

    class Flagged:
        supports_trash = True

    assert not supports_trash(Pop3Session())
    assert not supports_trash(None)
    assert supports_trash(Flagged())


def test_edge_the_preview_text_is_human_readable(german):
    from core.destructive_preview import OperationPreview
    from ui.file_pane import removal_preview_text

    preview = OperationPreview("delete", ["/x"], files=3, dirs=1, bytes_total=184_401,
                               hidden_count=1)
    assert removal_preview_text(preview) == (
        "Insgesamt: 3 Dateien, 1 Ordner, 180,1 KB; davon 1 versteckt")
