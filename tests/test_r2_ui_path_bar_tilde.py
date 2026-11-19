"""The path bar of a local pane expands ``~``.

Found in review (round 2 of the 2026-11 reviews, UI shell): typing
``~`` or ``~/Documents`` into a local pane's path bar and pressing Enter
said "Error: ... not found" - the path was taken as written. A shell,
the file dialogs and Total Commander go to the home folder.

A relative path is below the folder the pane shows (it was resolved
against axross's own working folder).

A remote pane keeps ``~`` as written: there it is a name like any other
(an SFTP server's home is its own, and the local one means nothing).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(done, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.005)
    return False


@pytest.fixture
def setup(tmp_path):
    from ui import main_window as MW

    home = tmp_path / "home"
    (home / "Documents").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
        window._reconnect_timer.stop()
        window._quit_with_transfers = True
        window.show()
        pane = window._panes[0]
        pane.navigate(str(elsewhere))
        assert _wait(lambda: not pane.is_loading)
        yield pane, home, elsewhere
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _type(pane, text: str) -> None:
    pane._path_edit.setFocus()
    pane._path_edit.setText(text)
    QTest.keyClick(pane._path_edit, Qt.Key.Key_Return)
    _wait(lambda: False, 0.05)
    assert _wait(lambda: not pane.is_loading)


def test_happy_tilde_goes_home(setup):
    pane, home, _ = setup
    _type(pane, "~")
    assert pane.current_path == str(home)


def test_happy_tilde_slash_goes_below_home(setup):
    pane, home, _ = setup
    _type(pane, "~/Documents")
    assert pane.current_path == str(home / "Documents")


def test_sad_a_missing_folder_below_home_stays_and_says_so(setup):
    pane, home, elsewhere = setup
    _type(pane, "~/nope")
    assert pane.current_path == str(elsewhere)
    assert "nope" in pane._status.text()


def test_sad_a_relative_path_is_below_the_folder_shown(setup):
    pane, _, elsewhere = setup
    (elsewhere / "sub").mkdir()
    _type(pane, "sub")
    assert pane.current_path == str(elsewhere / "sub")


def test_edge_a_tilde_inside_a_path_is_a_name(setup, tmp_path):
    pane, home, elsewhere = setup
    odd = elsewhere / "a~b"
    odd.mkdir()
    _type(pane, str(odd))
    assert pane.current_path == str(odd)
