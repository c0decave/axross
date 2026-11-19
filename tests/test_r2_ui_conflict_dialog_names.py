"""The "File Already Exists" question names the file as the pane does.

Found in review (round 2 of the 2026-11 reviews, UI shell): its headline
was a QLabel guessing the text format - a remote file named
``<b>report</b>.pdf`` was drawn bold (``<img width=4000 ...>`` laid the
window out 4,000 px wide), a bidi override read the name reversed right
where the user decides to overwrite it, and a long folder path without
blanks made the window as wide as the path.

Now the headline is plain text, defused (U+FFFD), and wraps inside the
window.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel  # noqa: E402

from core.transfer_conflicts import TransferConflict  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"


def _dialog(name: str, dest_dir: str = "/b"):
    from ui.transfer_conflict_dialog import TransferConflictDialog

    conflict = TransferConflict(
        name=name, source_path=f"/a/{name}", dest_path=f"{dest_dir}/{name}", dest_dir=dest_dir,
        source_is_dir=False, dest_is_dir=False, source_size=3, dest_size=1536,
        source_mtime=2.0e9, dest_mtime=1.0e9,
    )
    dlg = TransferConflictDialog(conflict, 0)
    dlg.show()
    APP.processEvents()
    return dlg


def _headline(dlg):
    # A WrapAnywhereLabel since round 3: a long path is wrapped, not cut.
    from ui.elided_label import WrapAnywhereLabel

    return dlg.findChildren(WrapAnywhereLabel)[0]


def test_happy_a_plain_name():
    dlg = _dialog("f.txt")
    assert _headline(dlg).text() == "“f.txt” already exists in /b."
    dlg.deleteLater()


def test_sad_markup_in_a_name_is_text():
    dlg = _dialog("<img width=4000 height=4000 src=x>.pdf")
    head = _headline(dlg)
    assert head.textFormat() == Qt.TextFormat.PlainText
    assert "<img width=4000" in head.text()
    assert dlg.width() < 1024
    dlg.deleteLater()


def test_sad_a_bidi_override_is_u_fffd():
    dlg = _dialog(f"inv{RLO}fdp.exe")
    assert "inv\ufffdfdp.exe" in _headline(dlg).text()
    assert RLO not in _headline(dlg).text()
    dlg.deleteLater()


def test_edge_a_long_folder_keeps_the_window_on_the_screen():
    folder = "/" + "/".join(("d" * 240) + str(i) for i in range(7))
    dlg = _dialog("f.txt", folder)
    assert dlg.minimumSizeHint().width() < 1024
    assert dlg.width() < 1024
    dlg.deleteLater()
