"""Properties shows a path, link target, owner and group as text that
fits the screen.

Found in review (round 2 of the 2026-11 reviews, UI shell; a nested path
of 1,700 characters, a server's link target or owner):

- the value labels word-wrap, but a path has no blank to wrap at: the
  dialog opened 1,964 px wide, past a 1024 px screen;
- they guessed the text format: a link target or owner holding
  ``<img width=4000 ...>`` or ``<b>`` was rendered as markup;
- a bidi override in the name read the title and the path reversed.

Now the values are plain text, defused as the pane shows a name (U+FFFD),
inside the window (the whole value in the tooltip); the title too.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from ui.properties_dialog import PropertiesDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"


class _Backend:
    name = "Fake"
    supports_symlinks = True

    def join(self, a: str, b: str) -> str:
        return f"{a.rstrip('/')}/{b}"

    def list_dir(self, path: str):
        return []


def _open(path: str, item: FileItem) -> PropertiesDialog:
    dlg = PropertiesDialog(_Backend(), path, item)
    dlg.show()
    APP.processEvents()
    return dlg


def _f(name: str, **kw) -> FileItem:
    kw.setdefault("modified", datetime(2026, 3, 4, 5, 6, 7))
    return FileItem(name=name, **kw)


def test_happy_a_plain_path_is_shown_as_it_is():
    dlg = _open("/data/report.pdf", _f("report.pdf", owner="alice"))
    assert dlg.general_fields()["Path"] == "/data/report.pdf"
    assert dlg.windowTitle() == "Properties: report.pdf"
    dlg.deleteLater()


def test_sad_a_long_path_keeps_the_dialog_on_the_screen():
    path = "/" + "/".join(("d" * 240) + str(i) for i in range(7)) + "/a.txt"
    dlg = _open(path, _f("a.txt"))
    assert dlg.minimumSizeHint().width() < 1024
    assert dlg.width() < 1024
    assert dlg._value_labels["Path"].text() == path
    assert "d" * 240 in dlg._value_labels["Path"].toolTip()
    dlg.deleteLater()


def test_sad_markup_from_the_server_is_text():
    item = _f("ln", is_link=True, link_target="<img width=4000 height=4000 src=x>",
              owner="<b>root</b>", group="<i>wheel</i>")
    dlg = _open("/srv/ln", item)
    for key in ("Link target", "Owner", "Group", "Path"):
        assert dlg._value_labels[key].textFormat() == Qt.TextFormat.PlainText, key
    assert dlg._value_labels["Owner"].text() == "<b>root</b>"
    assert dlg.minimumSizeHint().width() < 1024
    dlg.deleteLater()


def test_edge_a_bidi_override_is_u_fffd_in_the_title_and_the_path():
    name = f"inv{RLO}fdp.exe"
    dlg = _open(f"/srv/{name}", _f(name))
    assert RLO not in dlg.windowTitle() and "inv\ufffdfdp.exe" in dlg.windowTitle()
    assert dlg._value_labels["Path"].text() == "/srv/inv\ufffdfdp.exe"
    assert dlg.general_fields()["Path"] == f"/srv/{name}"
    dlg.deleteLater()
