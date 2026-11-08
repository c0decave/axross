"""German numbers, key names, the local pane's name and failed transfers.

UX review round 4 (German UI): sizes read "1.1 MB" and "1536 bytes" next to
German text, the menus said "Ctrl+Shift+Del" where the rest of the window
says "Strg+Umschalt+Entf", the pane header said "Local", and a failed
transfer showed the raw "[Errno 13] Permission denied: '/x'" in the
Transfers panel. Each is checked in both languages.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import i18n  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def german():
    i18n.install("de")
    yield
    i18n.install("en")


def test_happy_sizes_have_the_german_decimal_comma(german):
    from models.file_item import FileItem
    from ui.format_utils import format_size, human_bytes

    assert human_bytes(1536) == "1,5 KB"
    assert FileItem(name="a", size=1_200_000).size_human == "1,1 MB"
    assert format_size(1536) == "1.536 Bytes (1,5 KB)"
    assert format_size(1) == "1 Byte"
    assert i18n.format_decimal(2.5) == "2,5"


def test_sad_english_keeps_its_formats():
    from models.file_item import FileItem
    from ui.format_utils import format_size, human_bytes

    i18n.install("en")
    assert human_bytes(1536) == "1.5 KB"
    assert FileItem(name="a", size=1_200_000).size_human == "1.1 MB"
    assert format_size(2048) == "2048 bytes (2.0 KB)"
    assert format_size(1) == "1 byte"


def test_happy_menu_shortcuts_use_the_german_key_names(german):
    from PyQt6.QtGui import QKeySequence

    from ui.qt_translations import install_qt_translator

    translator = install_qt_translator(APP)
    try:
        native = QKeySequence.SequenceFormat.NativeText
        assert QKeySequence("Ctrl+Shift+Del").toString(native) == "Strg+Umschalt+Entf"
        # Stored and parsed shortcuts stay portable.
        assert QKeySequence("Ctrl+Shift+Del").toString() == "Ctrl+Shift+Del"
        assert QKeySequence("F5").toString(native) == "F5"
    finally:
        APP.removeTranslator(translator)


def test_edge_an_unknown_key_name_is_left_to_qt(german):
    from ui.qt_translations import CatalogueTranslator

    translator = CatalogueTranslator()
    assert translator.translate("QShortcut", "Media Play") is None
    assert translator.translate("QShortcut", "Ctrl") == "Strg"
    assert translator.translate("QShortcut", "") is None


def test_happy_the_local_pane_is_lokal_in_german(german):
    from ui.format_utils import backend_label

    assert backend_label("Local") == "Lokal"
    assert backend_label("bob@host") == "bob@host"


def test_sad_a_failed_transfer_says_why_in_german(german):
    from PyQt6.QtCore import Qt

    from core.transfer_worker import TransferJob, TransferStatus, _without_traceback
    from models.transfer_model import COL_STATUS, TransferModel

    try:
        raise PermissionError(errno.EACCES, "Permission denied", "/srv/x")
    except PermissionError as exc:
        error = _without_traceback(exc)
    assert error.__traceback__ is None
    job = TransferJob(filename="x", status=TransferStatus.ERROR, error_message=str(error),
                      error=error)
    model = TransferModel()
    model.add_job(job)
    cell = model.data(model.index(0, COL_STATUS))
    assert cell.startswith("Fehler: ") and "/srv/x" in cell and "[Errno" not in cell
    tip = model.data(model.index(0, COL_STATUS), Qt.ItemDataRole.ToolTipRole)
    assert "[Errno 13]" in tip  # the raw text stays in the tooltip


def test_edge_a_job_without_its_exception_shows_its_text():
    from core.transfer_worker import TransferJob, TransferStatus
    from models.transfer_model import status_text

    i18n.install("en")
    job = TransferJob(status=TransferStatus.ERROR, error_message="Disk on fire")
    assert status_text(job) == "error: Disk on fire"
