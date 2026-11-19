"""Review B, item 11: an archive member went to the desktop's default
application (xdg-open) unless its extension was on a block list - a PE
without an extension, a .scr or a .lnk was handed over and may have run.

Now only a document whose content the type detection (core.file_type)
recognises - an office document, a PDF, an e-book, a picture, sound or
video - is handed over by Open; anything else opens in the hex view, and
the archive's "Open with the System Application…" asks first.
"""

from __future__ import annotations

import io
import os
import sys
import zipfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from ui import file_pane as FP  # noqa: E402

APP = QApplication.instance() or QApplication([])

PE = b"MZ" + b"\x90" * 58 + (64).to_bytes(4, "little") + b"PE\0\0" + b"\0" * 200
LNK = bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\0" * 60


def _zip(*entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buf.getvalue()


DOCX = _zip(("[Content_Types].xml", "<Types/>"), ("word/document.xml", "<w/>"))


@pytest.fixture
def opened(monkeypatch):
    from core import desktop_open
    from core.security_mode import current_policy

    assert current_policy().allow_external_viewer
    seen: list[str] = []
    monkeypatch.setattr(desktop_open, "spawn_opener", lambda p: seen.append(p) or True)
    return seen


@pytest.mark.parametrize("name,data", [
    ("setup", PE), ("screensaver.scr", PE), ("invoice.pdf.scr", PE), ("shortcut.lnk", LNK),
    ("tool.jar", _zip(("META-INF/MANIFEST.MF", "Main-Class: x\n"))),
    ("macros.docm", _zip(("[Content_Types].xml", "<Types/>"), ("word/vbaProject.bin", "x"))),
    ("report.docx", PE),  # a program named like a document
    ("blob.bin", b"\x00\x01\x02\x03" * 64),
])
def test_sad_no_program_or_unknown_binary_goes_to_the_system_app(tmp_path, opened, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    assert FP._open_with_system_app(str(path), name) is False
    assert opened == []


@pytest.mark.parametrize("name,data", [
    ("report.docx", DOCX),
    ("letter.odt", _zip(("mimetype", "application/vnd.oasis.opendocument.text"),
                        ("content.xml", "<x/>"))),
    ("old.doc", bytes.fromhex("d0cf11e0a1b11ae1") + b"\0" * 504),
    ("song.mp3", b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\xff\xfb\x90\x00" * 20),
])
def test_happy_a_recognised_document_goes_to_the_system_app(tmp_path, opened, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    assert FP._open_with_system_app(str(path), name) is True
    assert opened == [str(path)]


def test_sad_open_with_asks_first_for_anything_else(tmp_path, opened, monkeypatch):
    path = tmp_path / "setup"
    path.write_bytes(PE)
    asked = []
    monkeypatch.setattr(FP, "_ask_system_app", lambda parent, name, what: asked.append(
        (name, what)) or False)
    assert FP.open_local_file_in_viewer(None, str(path), view="system") == ""
    assert asked and asked[0][0] == "setup" and opened == []
    monkeypatch.setattr(FP, "_ask_system_app", lambda parent, name, what: True)
    assert FP.open_local_file_in_viewer(None, str(path), view="system") == "system"
    assert opened == [str(path)]
    assert not os.stat(path).st_mode & 0o111


def test_happy_open_with_a_document_asks_nothing(tmp_path, opened, monkeypatch):
    path = tmp_path / "report.docx"
    path.write_bytes(DOCX)
    monkeypatch.setattr(FP, "_ask_system_app", lambda *a: pytest.fail("asked"))
    assert FP.open_local_file_in_viewer(None, str(path), view="system") == "system"


def test_sad_a_launcher_is_never_handed_over_even_when_asked(tmp_path, opened, monkeypatch):
    path = tmp_path / "evil.desktop"
    path.write_bytes(b"[Desktop Entry]\nExec=sh -c id\n")
    monkeypatch.setattr(FP, "_ask_system_app", lambda *a: True)
    assert FP.open_local_file_in_viewer(None, str(path), view="system") == ""
    assert opened == []


def test_happy_the_archive_menu_offers_it(tmp_path):
    from ui.archive_pane import ArchivePaneWidget

    archive = tmp_path / "a.zip"
    archive.write_bytes(_zip(("setup", PE)))
    pane = ArchivePaneWidget(str(archive))
    try:
        emitted = []
        pane.open_member_as.connect(lambda m, v: emitted.append((m, v)))
        pane._tree.selectAll()
        APP.processEvents()
        menu = pane.build_context_menu()
        action = next(a for a in menu.actions() if a.property("axCommand") == "open-with")
        action.trigger()
        assert emitted == [("setup", "system")]
    finally:
        pane.deleteLater()


def test_edge_the_question_names_what_the_file_is(monkeypatch):
    shown = {}

    class Box:
        Icon = QMessageBox.Icon
        StandardButton = QMessageBox.StandardButton

        def __init__(self, *a, **k):
            pass

        def __getattr__(self, name):
            def record(*args):
                shown[name] = args
                return QMessageBox.StandardButton.No
            return record

    monkeypatch.setattr(FP, "QMessageBox", Box, raising=False)
    assert FP._ask_system_app(None, "setup", "DOS/Windows executable") is False
    text = " ".join(str(v) for args in shown.values() for v in args)
    assert "setup" in text and "DOS/Windows executable" in text
