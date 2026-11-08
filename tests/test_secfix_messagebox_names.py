"""A remote file name in a message box is shown as written, never as markup.

Measured before (pre-release security review): the Checksum question
("{name}: this backend has no native checksum ...") and the two Overwrite
questions of Encrypt / Decrypt put the backend's file name into a
``QMessageBox.question`` text unescaped. Qt guessed rich text, so a name
like ``inv<br><b><font color=green>axross verified this file</font></b>
<a href=https:evil.example>open the report</a>`` rendered as a styled fake
notice with a live link (a name holds no "/", unclosed tags render too) - and a QMessageBox label opens links in the web
browser on a click (``openExternalLinks``). ui.markup_guard let it through:
it only stopped texts that load a resource or bomb the layout.

Now the prompts escape the name (ui.plain_text.as_written), and for the
whole class a message box text that holds a link is shown as written
(markup_guard.defuse_message) and the labels of a box made in Python do not
open links.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

import ui  # noqa: E402,F401  (installs the markup guard)
from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QTextDocument  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402
from ui import markup_guard as MG  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: A name a server can hand out (no "/"), styled like a notice of axross.
HOSTILE = ("inv<br><br><b><font color=green>axross verified this file"
           "<br><a href=https:evil.example>open the report<font size=1>")


def _shown(text: str) -> tuple[str, str]:
    """(what the user reads, the document's HTML) of a label in AutoText."""
    doc = QTextDocument()
    if Qt.mightBeRichText(text):
        doc.setHtml(text)
    else:
        doc.setPlainText(text)
    return doc.toPlainText(), doc.toHtml()


def _assert_as_written(text: str, name: str) -> None:
    plain, rich = _shown(text)
    assert name in plain, plain
    assert "href" not in rich.split("<body", 1)[-1].replace("&lt;a href", ""), rich


# -- the guard: links in message boxes ---------------------------------------------------------

def test_happy_a_message_without_a_link_is_left_as_it_is():
    for text in ("<b>Bold</b> and plain", "a < b", "plain", ""):
        assert MG.defuse_message(text) == text


def test_sad_a_message_box_text_with_a_link_is_shown_as_written():
    text = HOSTILE + ": this backend has no native checksum."
    assert MG.defuse_message(text) != text
    box = QMessageBox(QMessageBox.Icon.Question, "Checksum", text)
    labels = [label for label in box.findChildren(QLabel) if label.text()]
    assert labels and all(label.text() != text for label in labels)
    shown = [_shown(label.text())[0] for label in labels]
    assert any(HOSTILE in s for s in shown), shown
    box.deleteLater()


def test_sad_set_text_and_informative_text_with_a_link_are_defused():
    box = QMessageBox()
    box.setText("<a href='https://evil.example'>click</a>")
    box.setInformativeText("x <A\nHREF=https://evil.example>y</A>")
    assert box.text() != "<a href='https://evil.example'>click</a>"
    assert "&lt;" in box.text() and "&lt;" in box.informativeText()
    box.deleteLater()


def test_edge_message_box_labels_do_not_open_external_links():
    box = QMessageBox(QMessageBox.Icon.Information, "t", "<b>ours</b>")
    box.setInformativeText("<i>more</i>")
    labels = box.findChildren(QLabel)
    assert labels and not any(label.openExternalLinks() for label in labels)
    box.deleteLater()


def test_edge_plain_text_format_gets_the_original_back():
    box = QMessageBox(QMessageBox.Icon.Information, "t", HOSTILE)
    assert box.text() != HOSTILE  # AutoText: defused
    box.setTextFormat(Qt.TextFormat.PlainText)
    assert box.text() == HOSTILE
    box.deleteLater()


# -- the prompts of the file pane --------------------------------------------------------------

class _NoNativeChecksum(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        return ""


@pytest.fixture
def folder():
    root = Path(tempfile.mkdtemp()).resolve()
    yield root
    shutil.rmtree(root, ignore_errors=True)


def _pane(backend, root: Path):
    from ui import column_prefs as CP
    from ui.file_pane import FilePaneWidget

    with mock.patch.object(CP, "DEFAULT_PATH", root / "cols.json"):
        pane = FilePaneWidget(backend)
        pane.navigate(str(root))
        for _ in range(3000):
            if not pane.is_loading:
                break
            APP.processEvents()
    return pane


def test_sad_the_checksum_question_shows_the_remote_name_as_written(folder):
    from tests.off_gui_wait import _drain_checksum

    (folder / HOSTILE).write_bytes(b"x")
    pane = _pane(_NoNativeChecksum(), folder)
    try:
        with mock.patch("ui.file_pane.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.No) as question:
            pane._show_checksum(FileItem(name=HOSTILE, size=1))
            _drain_checksum(pane)
        question.assert_called_once()
        _assert_as_written(question.call_args.args[2], HOSTILE)
    finally:
        pane.deleteLater()


def test_sad_the_encrypt_overwrite_question_shows_the_name_as_written(folder):
    from core import encrypted_overlay as E

    fs = LocalFS()
    (folder / HOSTILE).write_bytes(b"plain")
    E.write_encrypted(fs, str(folder / HOSTILE), b"old", "old-pw")
    pane = _pane(fs, folder)
    try:
        with mock.patch("PyQt6.QtWidgets.QInputDialog.getText",
                        side_effect=[("pw", True), ("pw", True)]), \
                mock.patch("ui.file_pane.QMessageBox.question",
                           return_value=QMessageBox.StandardButton.No) as question, \
                mock.patch("ui.file_pane.QMessageBox.critical") as critical:
            pane._encrypt_selected_file(FileItem(name=HOSTILE, size=5))
        critical.assert_not_called()
        question.assert_called_once()
        _assert_as_written(question.call_args.args[2], HOSTILE + E.ENC_SUFFIX)
    finally:
        pane.deleteLater()


def test_sad_the_decrypt_overwrite_question_shows_the_name_as_written(folder):
    from core import encrypted_overlay as E

    fs = LocalFS()
    (folder / HOSTILE).write_bytes(b"current")
    E.write_encrypted(fs, str(folder / HOSTILE), b"secret", "pw")
    pane = _pane(fs, folder)
    try:
        with mock.patch("PyQt6.QtWidgets.QInputDialog.getText", return_value=("pw", True)), \
                mock.patch("ui.file_pane.QMessageBox.question",
                           return_value=QMessageBox.StandardButton.No) as question, \
                mock.patch("ui.file_pane.QMessageBox.critical") as critical, \
                mock.patch("ui.file_pane.QMessageBox.warning") as warning:
            pane._decrypt_selected_file(FileItem(name=HOSTILE + E.ENC_SUFFIX, size=5))
        critical.assert_not_called()
        warning.assert_not_called()
        question.assert_called_once()
        _assert_as_written(question.call_args.args[2], HOSTILE)
        assert (folder / HOSTILE).read_bytes() == b"current"
    finally:
        pane.deleteLater()
