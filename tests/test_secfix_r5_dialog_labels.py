"""Round-5 finding: an attacker-named file crashed or froze the app through
the label of a progress or input dialog (ui/markup_guard.py).

QProgressDialog and QInputDialog make their label (a QLabel, AutoText) in
C++, so the QLabel wrappers of the markup guard never saw its text: an
archive member named ``<img src="&#47;dev&#47;zero">x`` in "Opening …"
made Qt read /dev/zero until the process aborted (std::bad_alloc, exit 134);
a remote file of that name did the same in the Encrypt/Decrypt passphrase
prompt; a FIFO froze it. The labels are shown as written now - by the
guard for every such dialog and by the call sites themselves.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtGui import QTextDocument  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QInputDialog,
    QLabel,
    QLineEdit,
    QProgressDialog,
    QWidget,
)

import ui  # noqa: E402,F401 - installs the guard
from tests.test_markup_guard import assert_survives  # noqa: E402
from ui import markup_guard as MG  # noqa: E402
from ui.plain_text import as_written  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: A name as an archive author or a remote server writes it (no "/").
NAME = '<img src="&#47;dev&#47;zero">readme.txt'


def _rendered(text: str) -> str:
    if not Qt.mightBeRichText(text):
        return text
    doc = QTextDocument()
    doc.setHtml(text)
    return doc.toPlainText()


def _label_texts(dialog) -> list[str]:
    return [label.text() for label in dialog.findChildren(QLabel)]


def _assert_shown_as_written(dialog, expected: str) -> None:
    texts = [t for t in _label_texts(dialog) if t]
    assert texts, "the dialog has no label"
    for text in texts:
        assert "<img" not in text or not Qt.mightBeRichText(text) or text.startswith("<qt"), text
    assert any(_rendered(t) == expected for t in texts), texts


# -- the decision ---------------------------------------------------------------------------

def test_happy_our_own_dialog_labels_are_left_as_they_are():
    for text in ("Copying report.pdf…", "Passphrase for 'a & b':", "x < y", ""):
        assert MG.show_as_written(text) == text
    dialog = QProgressDialog("Copying report.pdf…", "Cancel", 0, 0)
    assert "Copying report.pdf…" in _label_texts(dialog)
    already = as_written("Opening " + NAME)
    assert MG.show_as_written(already) == already
    assert MG.show_as_written(MG.defuse("x" + NAME)) == MG.defuse("x" + NAME)


def test_sad_markup_in_a_dialog_label_is_shown_as_written():
    for text in ("Opening " + NAME, "<b>bold</b> name", "x <a href='https://e.example'>y</a>",
                 "<qt style='background:url(/dev/zero)'>x</qt>"):
        out = MG.show_as_written(text)
        assert out != text and _rendered(out) == text


# -- the labels Qt makes in C++ -------------------------------------------------------------

def test_sad_a_progress_dialog_label_shows_the_name_as_written():
    text = "Opening " + NAME + "…"
    _assert_shown_as_written(QProgressDialog(text, "Cancel", 0, 0), text)
    dialog = QProgressDialog()
    dialog.setLabelText(text)
    _assert_shown_as_written(dialog, text)


def test_sad_an_input_dialog_label_shows_the_name_as_written():
    text = "Passphrase for '" + NAME + "':"
    dialog = QInputDialog()
    dialog.setLabelText(text)
    _assert_shown_as_written(dialog, text)


def _answer_static(call, seen: list) -> None:
    """Run the static dialog *call*; record its label texts, then close it."""
    def close():
        for widget in APP.topLevelWidgets():
            if isinstance(widget, QInputDialog) and widget.isVisible():
                seen.append(_label_texts(widget))
                widget.reject()
    timer = QTimer()
    timer.timeout.connect(close)
    timer.start(50)
    try:
        call()
    finally:
        timer.stop()


@pytest.mark.parametrize("kind", ["getText", "getText-kw", "getMultiLineText", "getItem",
                                  "getInt", "getDouble"])
def test_sad_the_static_input_dialogs_show_the_label_as_written(kind):
    label = "File " + NAME
    host = QWidget()
    calls = {
        "getText": lambda: QInputDialog.getText(host, "t", label, QLineEdit.EchoMode.Password),
        "getText-kw": lambda: QInputDialog.getText(host, "t", label, text="<b>x</b>"),
        "getMultiLineText": lambda: QInputDialog.getMultiLineText(host, "t", label),
        "getItem": lambda: QInputDialog.getItem(host, "t", label, ["a", "b"], 0, False),
        "getInt": lambda: QInputDialog.getInt(host, "t", label, 1),
        "getDouble": lambda: QInputDialog.getDouble(host, "t", label, 1.0),
    }
    seen: list = []
    _answer_static(calls[kind], seen)
    # In one full parallel run the static call returned at once in a worker
    # (never reproduced alone or pairwise): say what getText was then.
    assert seen, ("the dialog never showed", QInputDialog.__dict__.get(kind.split("-")[0]),
                  [type(w).__name__ for w in APP.topLevelWidgets() if w.isVisible()])
    texts = [t for t in seen[0] if t]
    assert any(_rendered(t) == label for t in texts), texts
    assert not any("<img" in t and not t.startswith("<qt") for t in texts), texts


def test_edge_a_dialog_switched_to_plain_text_shows_the_original():
    """agent_dock._ask_user and plain_text.plain_item set the label, then
    switch the labels to PlainText: the original comes back - and a label
    set afterwards is left alone (it is plain already)."""
    text = "Which file? " + NAME
    dialog = QInputDialog()
    dialog.setLabelText(text)
    for label in dialog.findChildren(QLabel):
        label.setTextFormat(Qt.TextFormat.PlainText)
    assert text in _label_texts(dialog)
    dialog.setLabelText(text + "!")
    assert text + "!" in _label_texts(dialog)


# -- the call sites -------------------------------------------------------------------------

def test_happy_the_open_archive_progress_escapes_the_member_name_itself():
    """ui/main_window.py _extract_off_the_gui_thread: the label is escaped
    there (as_written), not only by the guard."""
    from ui.main_window import MainWindow

    host = QWidget()
    seen: list = []

    def look():
        for dialog in host.findChildren(QProgressDialog):
            seen.extend(_label_texts(dialog))

    QTimer.singleShot(400, look)
    import time

    text = "Opening " + NAME + "…"
    result = MainWindow._extract_off_the_gui_thread(host, text, lambda progress: time.sleep(0.8) or 7)
    assert result == 7
    assert as_written(text) in seen, seen


# -- the crashes, each in a child with a memory limit ---------------------------------------

def test_e2e_open_archive_progress_with_a_dev_zero_member_survives():
    assert_survives(f"""
        import time
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QMainWindow, QProgressDialog
        win = QMainWindow(); win.show()
        dialog = QProgressDialog("Opening " + {NAME!r} + "…", "Cancel", 0, 0, win)
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.setMinimumDuration(0)
        dialog.setValue(0)
        end = time.time() + 1
        while time.time() < end:
            pump(1); time.sleep(0.02)
    """)


def test_e2e_passphrase_prompt_for_a_dev_zero_file_survives():
    assert_survives(f"""
        from PyQt6.QtCore import QTimer
        from PyQt6.QtWidgets import QInputDialog, QLineEdit, QWidget
        w = QWidget(); w.show()
        QTimer.singleShot(800, lambda: [d.reject() for d in app.topLevelWidgets()
                                        if isinstance(d, QInputDialog)])
        QInputDialog.getText(w, "Decrypt File", "Passphrase for '" + {NAME!r} + "':",
                             QLineEdit.EchoMode.Password)
    """)
