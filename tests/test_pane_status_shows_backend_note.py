"""The pane's status line carries what a backend says about its state.

Round 5: a Git URL session whose origin could not be reached opened the
stale cache with nothing to say so, and commits that never reached origin
were invisible. GitFsSession.status_note() names both ("offline: cached
copy, read-only", "not pushed to origin: main (1)"); the pane's status
line shows it after the entry count. A backend without one (or one whose
note fails) shows the count alone.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


class NotedFS(LocalFS):
    note = "offline: cached copy, read-only"

    def status_note(self) -> str:
        if isinstance(self.note, Exception):
            raise self.note
        return self.note


@pytest.fixture
def pane(tmp_path):
    from ui.file_pane import FilePaneWidget

    (tmp_path / "a.txt").write_text("a")
    backend = NotedFS()
    p = FilePaneWidget(backend)
    p.navigate(str(tmp_path))
    yield p
    p.shutdown()
    p.deleteLater()


def test_happy_the_backend_note_follows_the_count(pane):
    assert pane._items_text() == "1 item · offline: cached copy, read-only"


def test_edge_no_note_or_a_failing_one_leaves_the_count(pane):
    pane._backend.note = ""
    assert pane._items_text() == "1 item"
    pane._backend.note = OSError("boom")
    assert pane._items_text() == "1 item"
