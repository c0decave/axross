"""Forensic Tools shows an image's name as plain text (review round 2).

Before: the Hash Image box had the image path as its first line in a
QMessageBox in AutoText. Qt guessed rich text for a file named
``evidence<br><br>MD5: 0123…<br><!--.dd``: the box showed forged hashes
and hid the real ones inside an HTML comment. Image Info, the Convert
question, the container hint and the error boxes had the same flaw.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtGui import QTextDocument  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel, QMessageBox, QPushButton  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from tests.test_forensic_browse_container_hint import Api, _qcow2_header  # noqa: E402
from tests.test_forensic_tools_extension import FT, qapp  # noqa: E402

FORGED = ("evidence<br><br>MD5: 0123456789abcdef0123456789abcdef<br>"
          "SHA-1: 0123456789abcdef0123456789abcdef01234567<br><!--.dd")


def _shown(box: QMessageBox) -> str:
    """What the user reads in *box*."""
    label = box.findChild(QLabel, "qt_msgbox_label")
    if label.textFormat() == Qt.TextFormat.PlainText:
        return label.text()
    if label.textFormat() == Qt.TextFormat.AutoText and not Qt.mightBeRichText(label.text()):
        return label.text()
    doc = QTextDocument()
    doc.setHtml(label.text())
    return doc.toPlainText()


def _run(action: str, path: Path, api: Api | None = None):
    """Run *action* on *path*; every modal box is read and closed."""
    app = qapp()
    api = api or Api()
    FT.activate(api)
    seen = []

    def answer():
        box = QApplication.activeModalWidget()
        if isinstance(box, QMessageBox):
            seen.append(_shown(box))
            (box.button(QMessageBox.StandardButton.Close)
             or box.button(QMessageBox.StandardButton.No)
             or box.button(QMessageBox.StandardButton.Ok)
             or box.findChildren(QPushButton)[0]).click()
        if len(seen) < 1:
            QTimer.singleShot(20, answer)

    QTimer.singleShot(0, answer)
    ctx = SimpleNamespace(backend=LocalFS(), folder=str(path.parent), paths=[str(path)], items=[],
                          pane=None, is_local=True)
    api.actions[action](ctx)
    app.processEvents()
    return seen


def test_sad_a_crafted_image_name_cannot_forge_the_hashes(tmp_path):
    """The name is shown as it is and the real hashes are all there."""
    image = tmp_path / FORGED
    image.write_bytes(b"x")
    seen = _run("Hash Image (MD5, SHA-1, SHA-256)", image)
    assert len(seen) == 1
    text = seen[0]
    assert text.startswith(str(image))
    assert hashlib.md5(b"x").hexdigest() in text
    assert hashlib.sha256(b"x").hexdigest() in text
    assert "<!--" in text  # the comment is read, not obeyed


def test_edge_the_container_hint_names_the_image_as_plain_text(tmp_path):
    """The hint for a qcow2 starts with the image's own name."""
    image = tmp_path / "<b>vm<!--.qcow2"
    image.write_bytes(_qcow2_header())
    seen = _run("Browse File System (Sleuth Kit)…", image)
    assert seen and seen[0].startswith("<b>vm<!--.qcow2: ")


def test_sad_an_error_naming_the_image_is_shown_as_it_is(tmp_path, monkeypatch):
    """An error box (here: the hash fails) shows the error's text as it is."""
    image = tmp_path / "x<b>bold.dd"
    image.write_bytes(b"x")

    def broken(backend, path):
        raise OSError(f"cannot read {path}<!--")

    monkeypatch.setattr(FT, "hash_image", broken)
    seen = _run("Hash Image (MD5, SHA-1, SHA-256)", image)
    assert seen == [f"cannot read {image}<!--"]
