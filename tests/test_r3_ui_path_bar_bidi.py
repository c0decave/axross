"""Round 3 (low from round 2): the path bar showed a path with a bidi
override as it is - ``/data/inv\\u202efdp.exe`` read "/data/invexe.pdf" -
while the list shows U+FFFD there. The bar must keep the path as it is
(it is edited and entered as typed), so it says so beside it instead: a
mark at its end and a tooltip naming the path as the pane shows it. An
ordinary path has neither."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"


def _wait(done, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.01)
    return done()


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    widget = FilePaneWidget(LocalFS())
    widget.resize(700, 400)
    widget.show()
    yield widget
    widget.close()
    widget.deleteLater()
    APP.processEvents()


def test_sad_a_bidi_path_keeps_its_text_and_gets_a_mark_and_a_defused_tooltip(pane, tmp_path):
    folder = tmp_path / f"inv{RLO}fdp.exe"
    folder.mkdir()
    pane.navigate(str(folder))
    assert _wait(lambda: pane.current_path == str(folder))
    edit = pane._path_edit
    assert edit.text() == str(folder)                 # editable as it is
    tip = edit.toolTip()
    assert RLO not in tip
    assert "inv\ufffdfdp.exe" in tip
    mark = pane._path_hidden_mark
    assert mark.isVisible()
    assert RLO not in mark.toolTip() and "\ufffd" in mark.toolTip()


def test_happy_an_ordinary_path_has_no_mark(pane, tmp_path):
    folder = tmp_path / f"inv{RLO}fdp.exe"
    folder.mkdir()
    (tmp_path / "plain").mkdir()
    pane.navigate(str(folder))
    assert _wait(lambda: pane.current_path == str(folder))
    pane.navigate(str(tmp_path / "plain"))
    assert _wait(lambda: pane.current_path == str(tmp_path / "plain"))
    assert not pane._path_hidden_mark.isVisible()
    assert "\ufffd" not in pane._path_edit.toolTip()


def test_edge_typing_a_bidi_character_shows_the_mark_at_once(pane, tmp_path):
    pane.navigate(str(tmp_path))
    assert _wait(lambda: pane.current_path == str(tmp_path))
    pane._path_edit.setText(str(tmp_path) + "/a" + RLO + "b")
    assert pane._path_hidden_mark.isVisible()
    pane._path_edit.setText(str(tmp_path))
    assert not pane._path_hidden_mark.isVisible()
