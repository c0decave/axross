"""The Agent dock works in the active pane's folder, as USAGE.md says.

Found while taking screenshots: the dock read the folder once, when the
main window was built, so after navigating the pane to ~/Documents the
dock still offered ~ - the model then looked for "Notes.md" in the wrong
folder. The folder now follows the active pane (activation and
navigation) and the dock's appearance, until the user types a folder of
their own.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import llm_profiles as LP  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


def _dock(folder: list[str]):
    from ui.agent_dock import AgentDock

    settings = LP.LLMSettings([LP.LLMProfile(name="local", provider="lmstudio")], "local")
    import tempfile

    from core.agent_session import SessionStore

    return AgentDock(settings_loader=lambda: settings, settings_saver=lambda s: None,
                     key_lookup=lambda n: "", root_provider=lambda: folder[0],
                     session_store=SessionStore(Path(tempfile.mkdtemp()) / "sessions"))


# -- happy ---------------------------------------------------------------------


def test_happy_the_folder_follows_the_provider(tmp_path):
    folder = [str(tmp_path)]
    dock = _dock(folder)
    assert dock.root_edit.text() == str(tmp_path)
    folder[0] = str(tmp_path / "Documents")
    dock.follow_folder()
    assert dock.root_edit.text() == str(tmp_path / "Documents")
    dock.deleteLater()


def test_happy_the_main_window_passes_the_active_pane_folder(tmp_path):
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Music").mkdir()
    from core import bookmarks as BM
    from ui.main_window import MainWindow

    with (
        mock.patch("pathlib.Path.home", return_value=tmp_path),
        mock.patch.object(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json"),
    ):
        win = MainWindow()
        win.show()
        try:
            pane = win._active_pane
            pane.navigate(str(tmp_path / "Documents"))
            _pump()
            win._agent_dock.show()
            _pump()
            assert win._agent_dock.root_edit.text() == str(tmp_path / "Documents")
            # Navigating on while the dock is open follows as well.
            pane.navigate(str(tmp_path / "Music"))
            _pump()
            assert win._agent_dock.root_edit.text() == str(tmp_path / "Music")
        finally:
            win._agent_dock.shutdown()
            win.close()
            win.deleteLater()
            _pump()


# -- sad -----------------------------------------------------------------------


def test_sad_a_folder_typed_by_the_user_is_kept(tmp_path):
    folder = [str(tmp_path)]
    dock = _dock(folder)
    dock.root_edit.setFocus()
    dock.root_edit.selectAll()
    from PyQt6.QtTest import QTest

    QTest.keyClicks(dock.root_edit, "/srv/data")
    assert dock.root_edit.text() == "/srv/data"
    folder[0] = str(tmp_path / "elsewhere")
    dock.follow_folder()
    assert dock.root_edit.text() == "/srv/data"
    dock.deleteLater()


# -- edge ----------------------------------------------------------------------


def test_edge_clearing_the_typed_folder_follows_again(tmp_path):
    folder = [str(tmp_path)]
    dock = _dock(folder)
    from PyQt6.QtTest import QTest

    QTest.keyClicks(dock.root_edit, "x")
    dock.root_edit.selectAll()
    QTest.keyClick(dock.root_edit, Qt.Key.Key_Backspace)
    assert dock.root_edit.text() == ""
    folder[0] = str(tmp_path / "next")
    dock.follow_folder()
    assert dock.root_edit.text() == str(tmp_path / "next")
    dock.deleteLater()


def test_edge_a_broken_provider_keeps_the_folder(tmp_path):
    folder = [str(tmp_path)]
    dock = _dock(folder)

    def broken():
        raise RuntimeError("pane is gone")

    dock.root_provider = broken
    dock.follow_folder()
    assert dock.root_edit.text() == str(tmp_path)
    dock.deleteLater()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
