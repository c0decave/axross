"""A destructive "Yes" is never the default answer.

Round-5 review: the Encrypt / Decrypt "'name' already exists. Overwrite?"
questions of the file pane and the trash window's Delete Permanently and
Empty Trash passed no default button - QMessageBox.question then makes Yes
the default, so Enter on a reflex overwrote or deleted. Every such
question in ui/ now names No (or another safe answer) as its default; the
guard below keeps it so.
"""

from __future__ import annotations

import ast
import os
import re
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

#: Words that make a Yes destructive.
_DESTRUCTIVE = re.compile(r"overwrite|delete|remove|replace|discard|empty|unsaved", re.I)
#: Defaults that answer the destructive question with "do it".
_UNSAFE_DEFAULTS = {"Yes", "YesToAll", "Ok", "Discard", "Apply", "Reset"}


def _question_calls():
    files = sorted((ROOT / "ui").glob("*.py")) + [ROOT / "main.py"]
    for path in files:
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "question"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "QMessageBox"):
                yield path, node, ast.get_source_segment(source, node)


def _default_of(node):
    for keyword in node.keywords:
        if keyword.arg == "defaultButton":
            return keyword.value
    return node.args[4] if len(node.args) >= 5 else None


# -- happy ------------------------------------------------------------------------------------


def test_happy_every_destructive_question_names_a_safe_default():
    missing, unsafe = [], []
    for path, node, text in _question_calls():
        if not _DESTRUCTIVE.search(text):
            continue
        where = f"{path.relative_to(ROOT)}:{node.lineno}"
        default = _default_of(node)
        if default is None:
            missing.append(where)
        elif isinstance(default, ast.Attribute) and default.attr in _UNSAFE_DEFAULTS:
            unsafe.append(where)
    assert not missing, f"QMessageBox.question without a default button: {missing}"
    assert not unsafe, f"QMessageBox.question defaulting to a destructive answer: {unsafe}"


def test_happy_the_guard_sees_the_reported_questions():
    texts = {f"{p.name}:{t}" for p, _n, t in _question_calls()}
    assert any("file_pane.py" in t and "Overwrite?" in t for t in texts)
    assert any("trash_browser.py" in t and "Empty Trash" in t for t in texts)


# -- sad --------------------------------------------------------------------------------------


@pytest.fixture()
def app():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _press_enter_on_the_question(app, seen: list) -> None:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication, QMessageBox

    def press() -> None:
        box = QApplication.activeModalWidget()
        if not isinstance(box, QMessageBox):
            QTimer.singleShot(50, press)
            return
        seen.append(box.defaultButton().text() if box.defaultButton() else None)
        QTest.keyClick(box, Qt.Key.Key_Return)

    QTimer.singleShot(50, press)


def _settle(app, dlg) -> None:
    end = time.monotonic() + 10
    while dlg.busy and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)
    app.processEvents()


def test_sad_enter_on_empty_trash_keeps_the_trash(app):
    from core import trash as T
    from core.local_fs import LocalFS
    from ui.trash_browser import TrashBrowserDialog

    with tempfile.TemporaryDirectory() as tmp:
        fs = LocalFS()
        fs.home = lambda: tmp
        victim = Path(tmp) / "keep.txt"
        victim.write_text("x")
        T.trash(fs, str(victim))
        dlg = TrashBrowserDialog(fs)
        try:
            _settle(app, dlg)
            seen: list = []
            _press_enter_on_the_question(app, seen)
            dlg._do_empty()
            _settle(app, dlg)
            assert seen and seen[0] is not None and "Yes" not in seen[0]
            assert len(T.list_trash(fs)) == 1
        finally:
            dlg.close()


def test_sad_enter_on_delete_permanently_keeps_the_entry(app):
    from core import trash as T
    from core.local_fs import LocalFS
    from ui.trash_browser import TrashBrowserDialog

    with tempfile.TemporaryDirectory() as tmp:
        fs = LocalFS()
        fs.home = lambda: tmp
        victim = Path(tmp) / "keep.txt"
        victim.write_text("x")
        T.trash(fs, str(victim))
        dlg = TrashBrowserDialog(fs)
        try:
            _settle(app, dlg)
            dlg._selected_entries = lambda: T.list_trash(fs)
            seen: list = []
            _press_enter_on_the_question(app, seen)
            dlg._do_delete_permanent()
            _settle(app, dlg)
            assert seen and "Yes" not in (seen[0] or "Yes")
            assert len(T.list_trash(fs)) == 1
        finally:
            dlg.close()


# -- edge -------------------------------------------------------------------------------------


def test_edge_a_conditional_default_passes_the_guard_but_a_plain_yes_does_not():
    good = ast.parse("QMessageBox.question(a, b, 'Delete?', B, X.Yes if trash else X.No)")
    bad = ast.parse("QMessageBox.question(a, b, 'Delete?', B, QMessageBox.StandardButton.Yes)")
    good_default = _default_of(good.body[0].value)
    bad_default = _default_of(bad.body[0].value)
    assert isinstance(good_default, ast.IfExp)
    assert isinstance(bad_default, ast.Attribute) and bad_default.attr in _UNSAFE_DEFAULTS
