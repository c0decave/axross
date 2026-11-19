"""An extension's manifest text is shown as text, never as markup.

Review 2026-11-20 (extensions round 2): the Extensions table set each
cell's tooltip to the manifest's name, version, source and description
as they are, and the "not loaded on this start" notice put the name into
an AutoText message box. Qt renders such text as rich text when it looks
like markup: a manifest name ``<img src=x width=4000 height=4000>`` made a
tooltip four thousand pixels wide, ``<b>`` restyled the notice and
``<!--`` hid the rest of it - text written by whoever wrote the extension,
before the user ever decided to switch it on. Both show the text as it is
now (ui.plain_text), with bidi overrides and controls visible.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QTextDocument  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])

NAME = "<img src=x width=4000 height=4000>Evil"
DESCRIPTION = "<b>bold</b><!-- hidden"


def _shown(tooltip: str) -> str:
    """What a tooltip shows: Qt renders it as rich text when it might be."""
    if Qt.mightBeRichText(tooltip):
        doc = QTextDocument()
        doc.setHtml(tooltip)
        return doc.toPlainText()
    return tooltip


@pytest.fixture
def hostile(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    folder = EX.extensions_dir()
    folder.mkdir(parents=True)
    (folder / "evil.py").write_text(
        f"EXTENSION = {{'name': {NAME!r}, 'version': '<i>1</i>', "
        f"'description': {DESCRIPTION!r}}}\n\ndef activate(api):\n    pass\n",
        encoding="utf-8",
    )
    return folder


def test_sad_the_table_tooltips_show_the_manifest_as_written(hostile):
    from ui.extensions_dialog import ExtensionsDialog

    host = SimpleNamespace(error=lambda _id: "", module=lambda _id: None)
    dlg = ExtensionsDialog(host)
    try:
        row = next(r for r in range(dlg.table.rowCount())
                   if NAME in dlg.table.item(r, 1).text())
        name_tip = _shown(dlg.table.item(row, 1).toolTip())
        assert NAME in name_tip and str(hostile / "evil.py") in name_tip
        assert _shown(dlg.table.item(row, 2).toolTip()) == "<i>1</i>"
        assert _shown(dlg.table.item(row, 4).toolTip()) == DESCRIPTION
    finally:
        dlg.deleteLater()


def test_sad_the_start_notice_names_the_extension_as_written():
    from ui.extension_host import ExtensionHost

    window = QMainWindow()
    host = ExtensionHost.__new__(ExtensionHost)
    host.window = window
    host._pending_notices = [SimpleNamespace(name=DESCRIPTION, ext_id="user:evil")]
    host._show_start_notices()
    try:
        box = window.findChild(QMessageBox, "axExtensionStartNotice")
        assert box is not None
        text = box.text()
        if box.textFormat() != Qt.TextFormat.PlainText and Qt.mightBeRichText(text):
            doc = QTextDocument()
            doc.setHtml(text)
            text = doc.toPlainText()
        assert DESCRIPTION in text
        assert "was not loaded" in text
    finally:
        window.deleteLater()


def test_happy_a_plain_manifest_reads_as_before(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    folder = EX.extensions_dir()
    folder.mkdir(parents=True)
    (folder / "nice.py").write_text(
        "EXTENSION = {'name': 'Nice', 'version': '2.0', 'description': 'a b  c'}\n"
        "def activate(api):\n    pass\n", encoding="utf-8")
    from ui.extensions_dialog import ExtensionsDialog

    host = SimpleNamespace(error=lambda _id: "", module=lambda _id: None)
    dlg = ExtensionsDialog(host)
    try:
        row = next(r for r in range(dlg.table.rowCount())
                   if dlg.table.item(r, 1).text() == "Nice")
        assert _shown(dlg.table.item(row, 4).toolTip()) == "a b  c"
    finally:
        dlg.deleteLater()
