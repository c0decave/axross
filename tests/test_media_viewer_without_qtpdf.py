"""The media viewer on a system where QtPdf cannot load.

QtPdf needs libatomic.so.1 from the host; the one-file binary does not
bundle it, so on a minimal system (seen in an AlmaLinux 9 container)
``import PyQt6.QtPdf`` fails. The viewer then offered PDFs anyway and
showed the loader's raw error ("libatomic.so.1: cannot open shared object
file") for each one. Video already had this check; PDF gets the same.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import media_load as ML  # noqa: E402
from core.media_collect import PDF  # noqa: E402
from tests.media_testkit import requires_qtpdf, write_pdf  # noqa: E402
from ui import media_viewer as MV  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def no_qtpdf(monkeypatch):
    """Make every import of QtPdf fail, as a missing libatomic does."""
    monkeypatch.setitem(sys.modules, "PyQt6.QtPdf", None)
    monkeypatch.setitem(sys.modules, "PyQt6.QtPdfWidgets", None)
    monkeypatch.setattr(MV, "_pdf_ok", None)
    yield
    MV._pdf_ok = None


@requires_qtpdf
def test_happy_pdf_is_supported_where_qtpdf_loads(monkeypatch) -> None:
    monkeypatch.setattr(MV, "_pdf_ok", None)
    assert MV.pdf_supported() is True
    dlg = MV.MediaViewOptionsDialog()
    assert dlg.pdf_box.isEnabled()
    assert PDF in dlg.options().kinds


def test_sad_without_qtpdf_the_options_offer_no_pdfs(no_qtpdf) -> None:
    assert MV.pdf_supported() is False
    dlg = MV.MediaViewOptionsDialog()
    assert not dlg.pdf_box.isEnabled()
    assert not dlg.pdf_box.isChecked()
    assert "QtPdf" in dlg.pdf_box.toolTip()
    assert PDF not in dlg.options().kinds


def test_sad_without_qtpdf_a_pdf_says_why_it_cannot_be_shown(no_qtpdf, tmp_path) -> None:
    pdf = write_pdf(tmp_path / "doc.pdf", pages=1)
    with pytest.raises(ML.MediaUnavailable) as caught:
        ML.pdf_page_count(str(pdf))
    text = str(caught.value)
    assert text.startswith("PDF viewing needs QtPdf")


def test_edge_the_answer_is_cached_and_never_raises(no_qtpdf) -> None:
    assert MV.pdf_supported() is False
    assert MV.pdf_supported() is False


# -- PyQt6 6.12 moved QtPdf to the separate PyQt6-Pdf package ----------------------


@pytest.fixture
def pyqt_version(monkeypatch):
    from PyQt6 import QtCore

    def set_to(version: int) -> None:
        monkeypatch.setattr(QtCore, "PYQT_VERSION", version)

    return set_to


def test_happy_from_6_12_on_the_hint_names_pyqt6_pdf(pyqt_version) -> None:
    pyqt_version(0x060C00)
    assert "PyQt6-Pdf" in ML.qtpdf_install_hint()


def test_edge_below_6_12_there_is_no_package_to_name(pyqt_version) -> None:
    """Up to 6.11 QtPdf comes with PyQt6 itself: a missing one is a host
    library, so naming PyQt6-Pdf there would send the user the wrong way."""
    pyqt_version(0x060B00)
    assert ML.qtpdf_install_hint() == ""


def test_sad_on_6_12_a_pdf_names_the_package_to_install(no_qtpdf, pyqt_version,
                                                         tmp_path) -> None:
    pyqt_version(0x060C00)
    pdf = write_pdf(tmp_path / "doc.pdf", pages=1)
    with pytest.raises(ML.MediaUnavailable) as caught:
        ML.pdf_page_count(str(pdf))
    assert str(caught.value).startswith("PDF viewing needs QtPdf")
    assert "PyQt6-Pdf" in str(caught.value)


def test_sad_on_6_12_the_disabled_pdf_box_names_the_package(no_qtpdf, pyqt_version) -> None:
    pyqt_version(0x060C00)
    dlg = MV.MediaViewOptionsDialog()
    assert not dlg.pdf_box.isEnabled()
    assert "PyQt6-Pdf" in dlg.pdf_box.toolTip()
    pyqt_version(0x060B00)
    assert "PyQt6-Pdf" not in MV.MediaViewOptionsDialog().pdf_box.toolTip()
