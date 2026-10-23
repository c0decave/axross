"""An archive with a huge number of entries is refused before they are all read.

Measured before (2026-10-22): a 918 KiB tar.gz holding 200 000 empty
folder headers took 33 s and +133 MiB to list (the archive preview,
opening an archive nested in another, MCP list_archive) and 30 s to be
refused by extract(): ``tarfile.getmembers()`` built every header first,
and the entry cap (MAX_EXTRACT_FILES) was compared afterwards. Headers
compress to almost nothing, so a 100 MiB download could hold tens of
millions of them - more memory than the machine has. A ZIP's central
directory was likewise built whole before its entries were counted.

Now tar headers are read one by one and the read stops past the cap
(MAX_EXTRACT_FILES for extract, MAX_LIST_ENTRIES for listing and for
extracting a selection); a ZIP's declared entry count is checked before
its directory is parsed.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import archive as AR  # noqa: E402


def _tar_of_headers(path: Path, n: int, files: int = 0) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for i in range(n):
            ti = tarfile.TarInfo(f"d{i}/")
            ti.type = tarfile.DIRTYPE
            tf.addfile(ti)
        for i in range(files):
            data = f"file {i}\n".encode()
            ti = tarfile.TarInfo(f"f{i}.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return path


@pytest.fixture
def counted_next(monkeypatch):
    """How many tar headers were read (TarFile.next calls)."""
    calls = {"n": 0}
    real = tarfile.TarFile.next

    def counting(self):
        calls["n"] += 1
        return real(self)

    monkeypatch.setattr(tarfile.TarFile, "next", counting)
    return calls


def test_happy_a_normal_tar_lists_and_extracts(tmp_path):
    archive = _tar_of_headers(tmp_path / "ok.tar.gz", 2, files=3)
    assert len(AR.list_archive(str(archive))) == 5
    assert AR.extract(str(archive), str(tmp_path / "out")) == 3
    assert (tmp_path / "out" / "f2.txt").read_text() == "file 2\n"


def test_sad_listing_stops_reading_past_the_cap(tmp_path, monkeypatch, counted_next):
    monkeypatch.setattr(AR, "MAX_LIST_ENTRIES", 50)
    archive = _tar_of_headers(tmp_path / "many.tar.gz", 5000)
    with pytest.raises(AR.UnsafeArchive, match="more than 50 entries"):
        AR.list_archive(str(archive))
    assert counted_next["n"] <= 52


def test_sad_extract_stops_reading_past_the_cap_and_leaves_nothing(
    tmp_path, monkeypatch, counted_next
):
    monkeypatch.setattr(AR, "MAX_EXTRACT_FILES", 20)
    archive = _tar_of_headers(tmp_path / "many.tar.gz", 5000)
    with pytest.raises(AR.UnsafeArchive, match="more than 20 entries"):
        AR.extract(str(archive), str(tmp_path / "out"))
    assert counted_next["n"] <= 22
    assert not (tmp_path / "out").exists()


def test_edge_extracting_a_selection_is_bounded_by_the_listing_cap(
    tmp_path, monkeypatch, counted_next
):
    monkeypatch.setattr(AR, "MAX_LIST_ENTRIES", 30)
    archive = _tar_of_headers(tmp_path / "many.tar.gz", 5000, files=1)
    with pytest.raises(AR.UnsafeArchive, match="more than 30 entries"):
        AR.extract_members(str(archive), str(tmp_path / "out"), ["d1/"])
    assert counted_next["n"] <= 32
    small = _tar_of_headers(tmp_path / "small.tar.gz", 5, files=2)
    assert AR.extract_members(str(small), str(tmp_path / "out2"), ["f1.txt"]) == 1


def test_edge_exactly_the_cap_is_still_fine(tmp_path, monkeypatch):
    monkeypatch.setattr(AR, "MAX_LIST_ENTRIES", 40)
    archive = _tar_of_headers(tmp_path / "forty.tar.gz", 40)
    assert len(AR.list_archive(str(archive))) == 40


def test_sad_a_zip_declaring_too_many_entries_is_refused_before_parsing(tmp_path, monkeypatch):
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(60):
            zf.writestr(f"e{i}.txt", b"")
    monkeypatch.setattr(AR, "MAX_LIST_ENTRIES", 50)
    monkeypatch.setattr(AR, "MAX_EXTRACT_FILES", 50)
    with mock.patch.object(zipfile.ZipFile, "infolist",
                           side_effect=AssertionError("directory parsed")):
        with pytest.raises(AR.UnsafeArchive, match="60 entries"):
            AR.list_archive(str(archive))
        with pytest.raises(AR.UnsafeArchive, match="60 entries"):
            AR.extract(str(archive), str(tmp_path / "out"))
    assert not (tmp_path / "out").exists()


def test_e2e_the_archive_preview_shows_the_refusal(tmp_path, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from ui.archive_pane import ArchivePaneWidget

    app = QApplication.instance() or QApplication([])  # kept: the widget needs it alive
    monkeypatch.setattr(AR, "MAX_LIST_ENTRIES", 50)
    archive = _tar_of_headers(tmp_path / "many.tar.gz", 5000)
    pane = ArchivePaneWidget(str(archive))
    try:
        assert pane.load_error is not None
        assert "more than 50 entries" in pane.load_error
    finally:
        pane.deleteLater()
        app.processEvents()
