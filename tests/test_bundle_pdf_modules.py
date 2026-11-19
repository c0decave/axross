"""The bundle carries QtPdf for the --pdf-worker child and not QtPdfWidgets.

The PDF child (core.pdf_worker) draws with QtPdf from source run as a
string, which PyInstaller cannot trace: the spec names PyQt6.QtPdf itself.
QPdfView (QtPdfWidgets) is no longer used anywhere - the media viewer shows
the pages the child draws - so the spec leaves it out, and the tests no
longer skip every PDF test on a host whose QtPdfWidgets does not load.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _sources():
    for top in ("core", "ui", "resources", "models"):
        yield from (ROOT / top).rglob("*.py")
    yield ROOT / "main.py"


def test_happy_nothing_of_axross_uses_qtpdfwidgets():
    users = [str(p.relative_to(ROOT)) for p in _sources()
             if "QtPdfWidgets" in p.read_text(encoding="utf-8", errors="replace")
             or "QPdfView" in p.read_text(encoding="utf-8", errors="replace")]
    assert users == []


def test_sad_the_spec_names_qtpdf_and_leaves_out_qtpdfwidgets():
    spec = (ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
    hidden = spec[spec.index("hiddenimports += [\n    \"PyQt6.QtCore\""):]
    hidden = hidden[:hidden.index("]")]
    assert '"PyQt6.QtPdf"' in hidden
    assert '"PyQt6.QtPdfWidgets"' not in hidden
    unconditional = spec[spec.index("# Unconditional excludes"):]
    unconditional = unconditional[:unconditional.index("]")]
    assert '"PyQt6.QtPdfWidgets"' in unconditional


def test_edge_the_pdf_tests_need_qtpdf_only():
    kit = (ROOT / "tests" / "media_testkit.py").read_text(encoding="utf-8")
    body = kit[kit.index("def qtpdf_missing"):kit.index("requires_qtpdf =")]
    assert "import PyQt6.QtPdf " in body or "import PyQt6.QtPdf  #" in body
    assert "import PyQt6.QtPdfWidgets" not in body
