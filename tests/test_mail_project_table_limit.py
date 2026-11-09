"""The mail project's table lists at most ROW_LIMIT messages.

Before: it stopped at 1000 rows (MailProject.messages' limit) and the
status line said "1000 messages" - a project of 5000 looked like one of
1000. Now the status says "Showing 1000 of 5000 messages", and an
import's result line stays above that count.
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

from core.mail_project import MailProject  # noqa: E402
from ui import mail_project as UMP  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _project(folder: Path, n: int) -> None:
    with MailProject(folder) as p:
        for i in range(n):
            p.add_bytes(f"From: a{i}@x.example\nSubject: m{i}\n\nbody {i}\n".encode(), f"f{i}.eml")


def test_happy_count_is_every_message_the_search_matches(tmp_path):
    """MailProject had no way to say how many messages a listing left out."""
    _project(tmp_path / "p", 12)
    with MailProject(tmp_path / "p") as p:
        assert len(p.messages(limit=5)) == 5
        assert p.count() == 12 and p.count(search="m1") == 3      # m1, m10, m11


def test_sad_a_cut_table_says_how_many_it_shows(tmp_path, monkeypatch):
    """The table stopped at the limit and the status said "N messages"
    with N the limit, not the project's size."""
    monkeypatch.setattr(UMP, "ROW_LIMIT", 5, raising=False)
    _project(tmp_path / "p", 12)
    dlg = UMP.MailProjectDialog(folder=str(tmp_path / "p"))
    try:
        assert dlg.table.rowCount() == 5
        assert dlg.status.text() == "Showing 5 of 12 messages – search to narrow them down."
        dlg.search.setText("m1")            # 3 matches: all shown
        dlg.refresh()
        assert dlg.table.rowCount() == 3 and dlg.status.text() == "3 messages"
    finally:
        dlg.done(0)


def test_edge_an_import_line_stays_and_the_cut_count_goes_below_it(tmp_path, monkeypatch):
    """After an import the status holds its result line; a cut table's
    count is added below it (and replaced, not added again, on the next
    refresh)."""
    monkeypatch.setattr(UMP, "ROW_LIMIT", 5, raising=False)
    _project(tmp_path / "p", 12)
    dlg = UMP.MailProjectDialog(folder=str(tmp_path / "p"))
    try:
        dlg.status.setText("Imported 12 messages.")
        dlg.refresh()
        dlg.refresh()
        assert dlg.status.text() == ("Imported 12 messages.\n"
                                     "Showing 5 of 12 messages – search to narrow them down.")
    finally:
        dlg.done(0)
