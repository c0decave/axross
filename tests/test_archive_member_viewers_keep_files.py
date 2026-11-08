"""An archive member's file stays as long as its viewer is open.

Before: ``MainWindow._extract_single_member`` removed the previous
member's temp dir whenever the next member was opened
(``_reap_last_member_tempdir``), on the assumption that one member viewer
is open at a time. The viewers are independent windows now: opening a
second member deleted the first one's file while its viewer still showed
it (a Reload or a hex edit then failed, the text editor lost its file).

Now each member's temp dir is removed when the viewer showing it is
destroyed (its ``destroyed`` signal; for a text member the editor tab);
the close-time cleanup stays as the safety net.
"""

from __future__ import annotations

import os
import sys
import time
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _settle(seconds: float = 0.3) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        time.sleep(0.005)


@pytest.fixture
def win(tmp_path):
    from ui import main_window as MW

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._quit_with_transfers = True
    yield window
    window._cleanup_archive_tempdirs()
    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", home / "session.json"):
        window.close()
    window.deleteLater()
    _settle(0.05)


@pytest.fixture
def archive(tmp_path) -> str:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("one.txt", "first member\n")
        zf.writestr("two.txt", "second\n")
    return str(path)


def _new_viewer(before: list):
    from ui import viewer_window as VW

    new = [w for w in VW.independent_windows() if not any(w is b for b in before)]
    assert len(new) == 1
    return new[0]


def test_sad_a_second_member_keeps_the_first_members_file(win, archive):
    from ui import viewer_window as VW

    before = VW.independent_windows()
    win._archive_open_member(archive, "one.txt", view="hex")
    _settle()
    first = _new_viewer(before)
    first_path = first._file_path
    assert os.path.isfile(first_path)

    before = VW.independent_windows()
    win._archive_open_member(archive, "two.txt", view="hex")
    _settle()
    second = _new_viewer(before)
    assert first.isVisible()
    assert os.path.isfile(first_path)  # was deleted under the open viewer
    assert os.path.isfile(second._file_path)

    # Closing a viewer removes its own member's dir, not the other one.
    second_path = second._file_path
    first.close()
    _settle()
    assert not os.path.exists(first_path)
    assert os.path.isfile(second_path)
    second.close()
    _settle()
    assert not os.path.exists(second_path)
    assert win._archive_member_tempdirs == []


def test_edge_a_text_member_keeps_its_file_while_its_tab_is_open(win, archive):
    win._archive_open_member(archive, "one.txt", view="text")
    _settle()
    editor = win._editor()
    assert editor.tabs.count() == 1
    first_tab = editor.tabs.widget(0)
    first_path = first_tab.path
    win._archive_open_member(archive, "two.txt", view="text")
    _settle()
    assert editor.tabs.count() == 2
    assert os.path.isfile(first_path)
    assert first_tab.read_only  # an archive member is shown, not edited
    editor.close_tab(editor.tabs.indexOf(first_tab))
    _settle()
    assert not os.path.exists(first_path)
    assert len(win._archive_member_tempdirs) == 1
