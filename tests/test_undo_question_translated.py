"""Ctrl+Z then Enter undoes - in the interface language.

UX review round 6 (high): after a Move to Trash the German undo asked
"Die letzte Aktion (trash) widerrufen? … restore /…/todo.txt from the
trash" - the operation id and the reason in English - and "No" was the
default, so Ctrl+Z then Enter restored nothing while the status bar kept
saying "Suche die Aktion zum Widerrufen…". Now the reason and the
operation's name are translated (core.undo.operation_name), Yes is the
default (the undo is itself the reversal, and it refuses an entry that
changed since), and the status is cleared or says that nothing was undone.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import i18n  # noqa: E402
from core import trash as T  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.1) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "journal.jsonl"))
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    win._active_pane.navigate(str(home))
    pump()
    victim = home / "todo.txt"
    victim.write_text("keep me")
    win.victim = victim
    yield win
    _ROUND[0] += 1  # stop this test's question watcher (_answer)
    win._quit_with_transfers = True
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _trash(window) -> None:
    backend = window._active_pane.backend
    T.trash(backend, str(window.victim))
    assert not window.victim.exists()


#: Bumped when a test ends: a watcher still waiting for its question (the
#: test failed before it showed) must not answer the next test's question -
#: in a full run one such leftover pressed Enter on the next test's "No"
#: question and failed two more tests.
_ROUND = [0]


def _answer(seen: list, key=Qt.Key.Key_Return, button=None) -> None:
    """Record the question when it shows, then press *key* (or click the
    standard *button*)."""
    round_ = _ROUND[0]

    def look() -> None:
        if _ROUND[0] != round_:
            return
        box = QApplication.activeModalWidget()
        if not isinstance(box, QMessageBox):
            QTimer.singleShot(30, look)
            return
        default = box.defaultButton()
        seen.append((box.text(), box.standardButton(default) if default else None))
        if button is not None:
            box.button(button).click()
        else:
            QTest.keyClick(box, key)

    QTimer.singleShot(30, look)


def _undo_and_wait(window, until, timeout: float = 15.0) -> None:
    window._undo_last_operation()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pump(0.05)
        if until() and not getattr(window, "_undo_busy", False):
            break
    pump(0.3)


# -- happy ------------------------------------------------------------------------------------


def test_happy_ctrl_z_then_enter_restores_the_trashed_file(window):
    _trash(window)
    seen: list = []
    _answer(seen)
    _undo_and_wait(window, lambda: window.victim.exists())
    assert window.victim.read_text() == "keep me"
    text, default = seen[0]
    assert default == QMessageBox.StandardButton.Yes
    assert text.startswith("Undo the last move to the trash?"), text
    assert "Looking for the operation" not in window.statusBar().currentMessage()


def test_happy_german_question_is_german_and_enter_restores(window, monkeypatch):
    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    _trash(window)
    seen: list = []
    _answer(seen)
    _undo_and_wait(window, lambda: window.victim.exists())
    assert window.victim.exists()
    text, default = seen[0]
    assert default == QMessageBox.StandardButton.Yes
    assert "(Verschieben in den Papierkorb)" in text, text
    assert "aus dem Papierkorb wiederherstellen" in text, text
    for english in ("(trash)", "restore", "from the trash", "Trash"):
        assert english not in text, (english, text)
    assert window.statusBar().currentMessage() != "Suche die Aktion zum Widerrufen…"


# -- sad --------------------------------------------------------------------------------------


def test_sad_no_keeps_the_file_in_the_trash_and_says_so(window, monkeypatch):
    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    _trash(window)
    seen: list = []
    _answer(seen, button=QMessageBox.StandardButton.No)
    _undo_and_wait(window, lambda: bool(seen))
    assert not window.victim.exists()
    assert window.statusBar().currentMessage() == "Nichts wurde widerrufen."


def test_sad_the_undo_question_is_a_reviewed_exception_of_the_default_no_guard():
    """tests/test_destructive_questions_default_no.py: Yes as the default
    only where the question restores - the undo question is no destructive
    question, and its source says why Yes is the default."""
    source = (Path(__file__).resolve().parents[1] / "ui" / "main_window.py").read_text("utf-8")
    start = source.index('tr("Undo the last {operation}?')
    block = source[source.rindex("# Yes is the default", 0, start):start + 400]
    assert "QMessageBox.StandardButton.Yes,\n        ) != QMessageBox.StandardButton.Yes" in block


# -- edge -------------------------------------------------------------------------------------


def test_edge_nothing_to_undo_clears_the_search_status(window, monkeypatch):
    said: list = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: said.append(a[2]))
    _undo_and_wait(window, lambda: bool(said))
    assert said
    assert window.statusBar().currentMessage() != "Looking for the operation to undo…"


@pytest.mark.parametrize(("operation", "english", "german"), [
    ("trash", "move to the trash", "Verschieben in den Papierkorb"),
    ("move", "file move", "Verschieben"),
    ("transfer", "file copy", "Kopieren"),
    ("atomic_write", "file save", "Speichern"),
    ("frobnicate", "frobnicate", "frobnicate"),
])
def test_edge_operation_ids_have_translated_names(monkeypatch, operation, english, german):
    from core.undo import operation_name

    assert operation_name(operation) == english
    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    assert operation_name(operation) == german


def test_edge_a_refused_copy_names_its_reason_in_german(monkeypatch):
    from core.undo import plan_undo

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    plan = plan_undo({"operation": "transfer", "status": "done", "source": "/a", "dest": "/b"})
    assert not plan.reversible
    assert plan.reason.startswith("Ein Kopieren lässt sich nicht automatisch widerrufen")
