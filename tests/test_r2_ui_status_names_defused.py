"""Names in status lines and messages are shown as the pane shows them.

Found in review (round 2 of the 2026-11 reviews, UI shell): the list
shows a control, bidi override or invisible character of a name as
U+FFFD, but the status lines used the raw name - Reveal of the hidden
``.inv<RLO>fdp.exe`` said "Hidden entries shown in this folder to show
.invexe.pdf" (reversed), a name with a line break broke the one-line
status, and the same went into the window's status bar and into the
message boxes that quote a name (``as_written``).

Now the pane's status line, the window's status bar and ``as_written``
/ ``plain_message`` defuse what they show: a bidi override, control or
invisible character becomes U+FFFD; a status line keeps to one line; a
message keeps its own line breaks.
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

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"
ZWSP = "\u200b"


def _wait(done, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.005)
    return False


@pytest.fixture
def pane(tmp_path):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    window._quit_with_transfers = True
    window.show()
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / f".inv{RLO}fdp.exe").write_text("x")
    (sub / "plain.txt").write_text("x")
    p = window._panes[0]
    window.set_show_hidden(False)
    p.navigate(str(sub))
    assert _wait(lambda: p.current_path == str(sub) and not p.is_loading)
    p.test_sub = sub
    p.test_window = window
    yield p
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _clean(text: str) -> bool:
    return RLO not in text and "\n" not in text and ZWSP not in text


def test_happy_a_plain_name_is_shown_as_it_is(pane):
    pane.status_message("Opened plain.txt")
    assert pane._status.text() == "Opened plain.txt"
    assert pane.test_window.statusBar().currentMessage() == "Opened plain.txt"


def test_sad_reveal_of_a_hidden_bidi_name_says_it_defused(pane):
    pane.reveal_path(str(pane.test_sub / f".inv{RLO}fdp.exe"))
    assert _wait(lambda: "Hidden entries shown" in pane._status.text())
    assert ".inv\ufffdfdp.exe" in pane._status.text()
    assert _clean(pane._status.text())
    assert _clean(pane.test_window.statusBar().currentMessage())


def test_sad_a_name_not_in_the_folder_is_defused(pane):
    assert pane._make_visible(f"gone{RLO}\nx") == "gone\ufffd\ufffdx is not in this folder"


def test_sad_any_status_text_keeps_to_one_line_and_shows_no_override(pane):
    pane.status_message(f"Error: a{RLO}b\nsecond line{ZWSP}")
    assert _clean(pane._status.text())
    assert "a\ufffdb" in pane._status.text()
    pane._feedback(f"x{RLO}y")
    assert pane._status.text() == "x\ufffdy"
    pane.test_window.statusBar().showMessage(f"Undoing: rename {RLO}fdp.exe", 1000)
    assert pane.test_window.statusBar().currentMessage() == "Undoing: rename \ufffdfdp.exe"


def test_edge_messages_keep_their_line_breaks_and_defuse_the_rest():
    from ui.plain_text import as_written, plain_message

    shown = as_written(f"Path already exists:\nevil{RLO}gpj.exe")
    assert RLO not in shown and "evil\ufffdgpj.exe" in shown and "\n" in shown
    box = plain_message(None, QMessageBox.Icon.Warning, "t", f"Could not rename\n{RLO}a{ZWSP}")
    assert box.text() == "Could not rename\n\ufffda\ufffd"
    box.deleteLater()
    # right-to-left marks and tabs are no hiding place and stay
    assert "\u200f" in as_written("\u05d0\u200f1\t2")
    assert "\t" in as_written("a\tb")
