"""Skipped archive links are shown wherever an extract is reported.

core.archive's extract() / extract_members() leave symbolic links out and
name them in ``ExtractResult.skipped_links`` - but every caller only
showed the count ("Extracted 1 files to ..."), so the user took the
folder for the whole archive. The pane's Extract Archive, the archive
view's Extract All / Selected (message and status line), opening a
member that is a link, the MCP archive_extract tool and scripting's
extract_archive now say which links were left out:
"3 symbolic links were not extracted: a, b, c" (German in de.json).
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox  # noqa: E402

from core import archive as ARCH  # noqa: E402
from core import i18n  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _zip(path: Path, links=("pkg/link",)) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("pkg/a.txt", b"abc")
        for name in links:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, b"a.txt")
    return path


def _note():
    from ui.file_pane import skipped_links_note

    return skipped_links_note


# -- happy -------------------------------------------------------------------


def test_happy_the_pane_extract_names_the_skipped_link(tmp_path):
    from ui.file_pane import FilePaneWidget

    archive = _zip(tmp_path / "pack.zip")
    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    shown, status = [], []
    try:
        with mock.patch.object(QMessageBox, "information", lambda *a: shown.append(a[2])), \
                mock.patch.object(pane, "status_message", status.append):
            pane._extract_archive(FileItem(name="pack.zip", size=archive.stat().st_size))
    finally:
        pane.shutdown()
        pane.deleteLater()
    assert shown and "1 symbolic link was not extracted: pkg/link" in shown[0]
    assert "Extracted 1 file to" in shown[0]
    assert status == ["1 symbolic link was not extracted: pkg/link"]


def test_happy_the_mcp_tool_returns_the_skipped_links(tmp_path):
    from tests import mcp_group_testkit as T
    from tests.test_mcp_group_packer_archive import _ar

    _zip(tmp_path / "x.zip", links=("pkg/l1", "pkg/l2"))
    out = T.call(_ar(tmp_path), "archive_extract", {"path": str(tmp_path / "x.zip")})
    assert out["files"] == 1
    assert out["skipped_links"] == ["pkg/l1", "pkg/l2"]
    assert out["note"] == "2 symbolic links were not extracted: pkg/l1, pkg/l2"
    json.dumps(out)


# -- sad ---------------------------------------------------------------------


def test_sad_scripting_warns_about_the_skipped_links(tmp_path, caplog):
    from core import scripting

    _zip(tmp_path / "x.zip")
    with caplog.at_level(logging.WARNING, logger="core.scripting"):
        scripting.extract_archive(str(tmp_path / "x.zip"), str(tmp_path / "out"))
    assert any("1 symbolic link was not extracted: pkg/link" in r.getMessage()
               for r in caplog.records)


class _Window(QMainWindow):
    """The archive view's extract driver on a bare main window."""

    from ui.main_window import MainWindow as _MW

    _run_archive_extraction = _MW._run_archive_extraction
    _extract_member_into = _MW._extract_member_into
    _extract_off_the_gui_thread = _MW._extract_off_the_gui_thread

    def __init__(self):
        super().__init__()
        self._archive_member_tempdirs = []

    def _refresh_panes_for_dir(self, directory):
        pass


def test_sad_the_archive_view_shows_the_note_in_message_and_status_line(tmp_path):
    archive = _zip(tmp_path / "pack.zip", links=("a", "b", "c"))
    shown = []
    window = _Window()
    try:
        with mock.patch.object(QMessageBox, "information", lambda *a: shown.append(a[2])):
            window._run_archive_extraction(str(archive), str(tmp_path / "out"), None,
                                           title="Extract All")
        status = window.statusBar().currentMessage()
    finally:
        window.deleteLater()
    assert shown and "3 symbolic links were not extracted: a, b, c" in shown[0]
    assert status == "3 symbolic links were not extracted: a, b, c"


def test_sad_opening_a_member_that_is_a_link_says_so(tmp_path):
    archive = _zip(tmp_path / "pack.zip")
    shown, warned = [], []
    window = _Window()
    base = tmp_path / "tmp"
    base.mkdir()
    try:
        with mock.patch.object(QMessageBox, "information", lambda *a: shown.append(a[2])), \
                mock.patch.object(QMessageBox, "warning", lambda *a: warned.append(a[2])):
            assert window._extract_member_into(str(base), str(archive), "pkg/link") is None
    finally:
        window.deleteLater()
    assert shown == ["1 symbolic link was not extracted: pkg/link"] and warned == []


# -- edge --------------------------------------------------------------------


def test_edge_no_skipped_link_no_note():
    assert _note()(ARCH.ExtractResult(3)) == ""
    assert _note()(3) == ""


def test_edge_hostile_names_are_shown_as_codes_and_the_list_is_cut():
    names = ["evil\u202etxt.exe"] + [f"l{i}" for i in range(12)]
    note = _note()(ARCH.ExtractResult(0, names))
    assert "\u202e" not in note and "\\u202e" in note
    assert note.startswith("13 symbolic links") and note.endswith(", …")


def test_edge_the_note_is_german_in_german(monkeypatch):
    german = i18n.Translator("de", Path(__file__).resolve().parent.parent / "resources/i18n")
    monkeypatch.setattr(i18n, "_ACTIVE", german)
    assert _note()(ARCH.ExtractResult(0, ["a"])) == "1 symbolischer Link wurde nicht entpackt: a"
    assert _note()(ARCH.ExtractResult(0, ["a", "b"])).startswith("2 symbolische Links wurden")
