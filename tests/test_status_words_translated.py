"""The transfer dock's Status cell and the pane's status line in the
interface language, with the reason of a failed transfer.

Review round 3 (German UI): the Status cell said "error" - in English, and
without what went wrong; the reason sat in ``job.error_message`` and was
shown nowhere in the row. The pane's status line said "1 items" and "Copied
1 path(s) to clipboard", its badges SOURCE / TARGET and "Free: 2.9 GB /
4.0 GB (27% used)" stayed English under German menus: none of them went
through ``tr()``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import i18n  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def german(monkeypatch):
    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))


def _cell(job: TransferJob, column: int, role=Qt.ItemDataRole.DisplayRole):
    from models.transfer_model import TransferModel

    model = TransferModel()
    model.add_job(job)
    return model.data(model.index(0, column), role)


def _failed(reason: str = "Permission denied: /srv/out/a.txt") -> TransferJob:
    return TransferJob(filename="a.txt", status=TransferStatus.ERROR, error_message=reason)


def test_happy_a_failed_transfer_says_why_in_its_status_cell():
    from models.transfer_model import COL_STATUS

    job = _failed()
    assert _cell(job, COL_STATUS) == "error: Permission denied: /srv/out/a.txt"
    tip = _cell(job, COL_STATUS, Qt.ItemDataRole.ToolTipRole)
    assert tip == "error: Permission denied: /srv/out/a.txt"


def test_happy_the_status_words_and_headers_are_german(german):
    from models.transfer_model import COL_DIR, COL_PROGRESS, COL_STATUS, TransferModel

    assert _cell(_failed("Kein Platz"), COL_STATUS) == "Fehler: Kein Platz"
    assert _cell(TransferJob(status=TransferStatus.DONE), COL_STATUS) == "fertig"
    assert _cell(TransferJob(status=TransferStatus.DONE), COL_PROGRESS) == "Fertig"
    assert _cell(TransferJob(status=TransferStatus.ACTIVE), COL_STATUS) == "läuft"
    assert _cell(TransferJob(status=TransferStatus.PENDING), COL_STATUS) == "wartet"
    header = TransferModel().headerData(COL_DIR, Qt.Orientation.Horizontal)
    assert header == "Richtung"


def test_edge_a_long_reason_shows_its_first_line_and_the_tooltip_all_of_it():
    from models.transfer_model import COL_STATUS

    job = _failed("Connection lost\nwhile writing block 7")
    assert _cell(job, COL_STATUS) == "error: Connection lost"
    assert "while writing block 7" in _cell(job, COL_STATUS, Qt.ItemDataRole.ToolTipRole)


def test_edge_a_cancel_shows_its_reason_but_not_the_word_twice():
    from models.transfer_model import COL_STATUS

    job = TransferJob(status=TransferStatus.CANCELLED, error_message="Cancelled")
    assert _cell(job, COL_STATUS) == "cancelled"  # not "cancelled: Cancelled"
    assert _cell(job, COL_STATUS, Qt.ItemDataRole.ToolTipRole) is None
    job = TransferJob(status=TransferStatus.CANCELLED, error_message="the source vanished")
    assert _cell(job, COL_STATUS) == "cancelled: the source vanished"


def test_sad_a_failure_without_a_reason_shows_the_bare_word_translated(german):
    from models.transfer_model import COL_STATUS

    job = TransferJob(status=TransferStatus.ERROR, error_message="")
    assert _cell(job, COL_STATUS) == "Fehler"
    assert _cell(job, COL_STATUS, Qt.ItemDataRole.ToolTipRole) is None


def _pane(tmp_path):
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    (tmp_path / "only.txt").write_text("x")
    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    return pane


def test_happy_the_pane_status_line_counts_one_item_in_the_singular(tmp_path):
    pane = _pane(tmp_path)
    try:
        assert pane._items_text() == "1 item"
    finally:
        pane.deleteLater()


def test_happy_the_pane_status_strings_are_german(tmp_path, german, monkeypatch):
    pane = _pane(tmp_path)
    try:
        assert pane._items_text() == "1 Element"
        monkeypatch.setattr(pane, "selected_items", lambda: [str(tmp_path / "only.txt")])
        pane._copy_paths_to_clipboard()
        assert pane._status.text().startswith("1 Pfad in die Zwischenablage kopiert")
        pane.set_pane_role("source")
        assert pane._role_label.text() == "QUELLE"
        pane.set_pane_role("target")
        assert pane._role_label.text() == "ZIEL"
        pane._show_disk_usage((4 * 1024 ** 3, 1024 ** 3, 3 * 1024 ** 3))
        # The German decimal comma (core.i18n.format_decimal, review round 4).
        assert pane._disk_label.text() == "Frei: 3,0 GB / 4,0 GB (25 % belegt)"
    finally:
        pane.deleteLater()


def test_edge_two_copied_paths_take_the_plural(tmp_path, monkeypatch):
    pane = _pane(tmp_path)
    try:
        monkeypatch.setattr(pane, "selected_items", lambda: ["/a", "/b"])
        pane._copy_paths_to_clipboard()
        assert pane._status.text().startswith("Copied 2 paths to the clipboard")
    finally:
        pane.deleteLater()
