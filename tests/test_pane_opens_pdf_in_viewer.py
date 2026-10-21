"""Opening a PDF from a pane (double-click, F3) shows it in the media viewer.

Operator items 28 / 35: the media viewer renders PDFs, but a PDF opened from
the pane went to the hex editor (``FilePaneWidget._on_double_click`` routed it
as a binary file). The PDF now opens on its own in the media viewer
("document mode"); the hex editor stays the fallback when QtPdf cannot be
loaded or the security mode blocks the media viewer.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import open_limits as OL  # noqa: E402
from core import security_mode  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import PDF  # noqa: E402
from tests.media_testkit import write_image, write_pdf  # noqa: E402
from ui import media_viewer as MV  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_until(cond, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


def _dialogs() -> list:
    return [w for w in QApplication.topLevelWidgets() if isinstance(w, MV.MediaViewerDialog)]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from ui import column_prefs as CP

    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(CP, "DEFAULT_PATH", tmp_path / "cols.json")
    previous = security_mode.current_policy().name
    security_mode.set_policy("normal")
    yield
    security_mode.set_policy(previous)
    for w in _dialogs():
        w.close()
    APP.processEvents()


@pytest.fixture
def folder(tmp_path) -> Path:
    root = tmp_path / "docs"
    write_pdf(root / "report.pdf", pages=3)
    write_pdf(root / "other.pdf", pages=1)
    write_image(root / "photo.png")
    (root / "blob.bin").write_bytes(b"\x00\x01\x02" * 50)
    return root


@pytest.fixture
def pane(folder):
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(LocalFS())
    p.navigate(str(folder))
    yield p
    p.deleteLater()


def _index_of(pane, name: str):
    proxy = pane._proxy
    assert wait_until(
        lambda: any(proxy.data(proxy.index(r, 0)) == name for r in range(proxy.rowCount()))
    )
    row = next(r for r in range(proxy.rowCount()) if proxy.data(proxy.index(r, 0)) == name)
    return proxy.index(row, 0)


def _select(pane, name: str) -> None:
    pane._table.setCurrentIndex(_index_of(pane, name))
    pane._table.selectRow(_index_of(pane, name).row())


# -- happy -------------------------------------------------------------------


def test_happy_double_click_opens_the_pdf_alone_in_the_media_viewer(pane):
    with mock.patch.object(type(pane), "_open_hex_editor") as hex_editor:
        pane._on_double_click(_index_of(pane, "report.pdf"))
    hex_editor.assert_not_called()
    assert wait_until(lambda: len(_dialogs()) == 1)
    dlg = _dialogs()[0]
    assert wait_until(lambda: dlg.scan_finished)
    viewer = dlg.viewer
    assert dlg.stack.currentWidget() is viewer
    assert [i.name for i in viewer.items()] == ["report.pdf"]
    assert wait_until(lambda: viewer.mode == "pdf")
    assert viewer.page_count == 3 and viewer.page_bar.isVisible()
    assert not viewer.slideshow_active


def test_happy_f3_views_the_pdf_in_the_media_viewer_too(pane):
    _select(pane, "report.pdf")
    with mock.patch.object(type(pane), "_open_hex_editor") as hex_editor:
        pane._view_selected()
    hex_editor.assert_not_called()
    assert wait_until(lambda: len(_dialogs()) == 1)
    dlg = _dialogs()[0]
    assert wait_until(lambda: dlg.scan_finished)
    assert [i.kind for i in dlg.viewer.items()] == [PDF]


# -- sad ---------------------------------------------------------------------


def test_sad_without_qtpdf_the_pdf_falls_back_to_hex_and_says_why(pane, monkeypatch, caplog):
    monkeypatch.setattr(MV, "pdf_supported", lambda: False)
    with (
        caplog.at_level(logging.INFO),
        mock.patch.object(type(pane), "_open_hex_editor") as hex_editor,
    ):
        pane._on_double_click(_index_of(pane, "report.pdf"))
    hex_editor.assert_called_once()
    assert hex_editor.call_args.args[0].endswith("report.pdf")
    assert not _dialogs()
    assert any("QtPdf" in r.getMessage() for r in caplog.records)


def test_sad_a_blocking_security_mode_falls_back_to_hex_and_says_why(pane, caplog):
    assert not security_mode.PARANOID.allow_auto_preview
    security_mode.set_policy("paranoid")
    with (
        caplog.at_level(logging.INFO),
        mock.patch.object(type(pane), "_open_hex_editor") as hex_editor,
    ):
        pane._on_double_click(_index_of(pane, "report.pdf"))
    hex_editor.assert_called_once()
    assert not _dialogs()
    assert any("security mode" in r.getMessage() for r in caplog.records)


# -- edge --------------------------------------------------------------------


def test_edge_an_upper_case_extension_is_a_pdf_too(pane, folder):
    write_pdf(folder / "SCAN.PDF", pages=2)
    pane.refresh()
    with mock.patch.object(type(pane), "_open_hex_editor") as hex_editor:
        pane._on_double_click(_index_of(pane, "SCAN.PDF"))
    hex_editor.assert_not_called()
    assert wait_until(lambda: len(_dialogs()) == 1)
    dlg = _dialogs()[0]
    assert wait_until(lambda: dlg.scan_finished)
    assert [i.name for i in dlg.viewer.items()] == ["SCAN.PDF"]


def test_edge_other_binaries_still_open_in_hex(pane):
    with mock.patch.object(type(pane), "_open_hex_editor") as hex_editor:
        pane._on_double_click(_index_of(pane, "blob.bin"))
    hex_editor.assert_called_once()
    assert not _dialogs()


def test_happy_the_page_keys_are_documented_where_the_viewer_keys_are():
    from ui.shortcuts_dialog import SHORTCUTS

    viewer_keys = {k for section, keys, _d in SHORTCUTS if section == "Viewers" for k in keys}
    assert {"Up", "Down", "Left", "Right"} <= viewer_keys
    root = Path(__file__).resolve().parents[1]
    for guide, words in (
        ("docs/USAGE.md", "Up / Down"),
        ("docs/USAGE_de.md", "Hoch / Runter"),
        ("docs/USAGE_es.md", "Arriba / Abajo"),
    ):
        text = (root / guide).read_text(encoding="utf-8")
        assert words in text, guide
        assert "inside a PDF they turn pages" not in text, guide
