"""The Move to Trash question sums itself up as a move to the trash.

Review round 3: "Move 2 item(s) to trash? x.txt, y.txt - delete: 2 item(s);
2 file(s), 0 dir(s); 10 byte(s)". The summary line of
``core.destructive_preview`` always named the action "delete", and the
pane's busy text said "Checking 2 item(s) before the delete…" - for an
action that deletes nothing.

Now ``preview_delete`` takes the verb, and the pane passes "move to trash"
for Move to Trash; Delete Permanently keeps "delete".
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

from core.destructive_preview import preview_delete  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def test_happy_the_summary_names_the_verb_it_is_given(tmp_path):
    (tmp_path / "x.txt").write_text("x")
    preview = preview_delete(LocalFS(), [str(tmp_path / "x.txt")], verb="move to trash")
    assert preview.summary().startswith("move to trash: 1 item(s)")
    assert preview_delete(LocalFS(), [str(tmp_path / "x.txt")]).summary().startswith("delete:")


@pytest.fixture
def pane(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtCore import QEvent
    from PyQt6.QtWidgets import QApplication

    from ui import main_window as MW

    app = QApplication.instance() or QApplication([])
    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._reconnect_timer.stop()
    window._quit_with_transfers = True
    folder = tmp_path / "a"
    folder.mkdir()
    for name in ("x.txt", "y.txt"):
        (folder / name).write_text(name)
    p = window._panes[0]
    p.navigate(str(folder))
    p.test_app = app
    p.test_wait = lambda done, t=10.0: _wait(app, done, t)
    assert p.test_wait(lambda: p._table.model().rowCount() >= 4)
    yield p
    window.close()
    window.deleteLater()
    app.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _wait(app, done, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.processEvents()
        if done():
            return True
        time.sleep(0.01)
    return False


def _ask(pane, trash: bool) -> tuple[str, list[str]]:
    """Select x.txt and y.txt, start the removal, answer No; returns the
    question's text and the busy texts shown before it."""
    from PyQt6.QtCore import QItemSelectionModel
    from PyQt6.QtWidgets import QMessageBox

    table = pane._table
    flags = QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows
    for row in range(table.model().rowCount()):
        if table.model().index(row, 0).data() in ("x.txt", "y.txt"):
            table.selectionModel().select(table.model().index(row, 0), flags)
    asked: list[str] = []
    busy: list[str] = []
    real_busy = pane._show_removal_busy

    def note_busy(text, *a, **k):
        busy.append(text)
        return real_busy(text, *a, **k)

    def question(_parent, _title, text, *a, **k):
        asked.append(text)
        return QMessageBox.StandardButton.No

    with mock.patch("ui.file_pane.QMessageBox.question", side_effect=question), \
            mock.patch.object(pane, "_show_removal_busy", side_effect=note_busy):
        pane._start_removal(trash=trash)
        assert pane.test_wait(lambda: bool(asked) and not pane.removal_running)
    return asked[0], busy


def test_sad_the_trash_question_does_not_say_delete(pane):
    text, _busy = _ask(pane, trash=True)
    assert "Move 2 items to the trash?" in text
    assert "In total: 2 files" in text
    assert "delete" not in text.lower()


def test_edge_delete_permanently_keeps_delete_and_the_busy_text_follows(pane):
    _text, busy = _ask(pane, trash=True)
    assert busy and "trash" in busy[0] and "delete" not in busy[0]
    text, busy = _ask(pane, trash=False)
    assert "Delete 2 items permanently?" in text
    assert "before the delete" in busy[0]
