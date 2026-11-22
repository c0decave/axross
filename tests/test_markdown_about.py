"""Help > About axross-markdown…: the viewer of the program of its own has a Help button whose About
window shows the name, the version, the licence statement and the licences of what the one-file
programs contain (ui.markdown_about) - read-only. In axross's tree the texts are axross's
THIRD_PARTY_LICENSES.md; in the export its package's THIRD_PARTY_LICENSES.txt."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it")

from PyQt6.QtWidgets import QApplication, QPlainTextEdit  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _closed_after():
    yield
    for widget in APP.topLevelWidgets():
        widget.close()
        widget.deleteLater()
    APP.processEvents()


def test_happy_help_about_shows_the_name_the_version_and_the_licences():
    from core.markdown_cli import program_version
    from ui import markdown_about as MA
    from ui.markdown_app import NAME, MarkdownApp

    viewer = MarkdownApp().open_paths([""])[0]
    assert viewer.help_button is not None and viewer.help_button.text() == "&Help"
    assert viewer.help_button in [viewer._bar.itemAt(i).widget() for i in range(viewer._bar.count())]  # noqa: SLF001
    actions = [a for a in viewer.help_button.menu().actions() if not a.isSeparator()]
    # (0.17.0: the updates first - Check for Updates…, Updates -, About last)
    assert [a.text() for a in actions][-1] == f"About {NAME}…"
    actions[-1].trigger()
    about = [w for w in APP.topLevelWidgets() if isinstance(w, MA.AboutDialog) and w.isVisible()]
    assert len(about) == 1 and about[0].parentWidget() is viewer
    dialog = about[0]
    assert dialog.windowTitle() == f"About {NAME}"
    assert dialog.title.text() == f"{NAME} {program_version()}"
    assert "Apache License 2.0" in dialog.statement.text() and "GPL-3.0" in dialog.statement.text()
    text = dialog.findChild(QPlainTextEdit, "licences")
    assert text.isReadOnly()
    path = MA.licences_path()
    assert path is not None and text.toPlainText() == path.read_text(encoding="utf-8")
    assert "GPL-3.0" in text.toPlainText() and "PyQt6" in text.toPlainText()


def test_sad_no_licence_file_is_said_not_an_empty_window(monkeypatch):
    from ui import markdown_about as MA

    monkeypatch.setattr(MA, "licences_path", lambda: None)
    assert "THIRD_PARTY_LICENSES.txt" in MA.licences_text()
    dialog = MA.AboutDialog("1.2.3")
    assert dialog.title.text() == "axross-markdown 1.2.3"
    assert "THIRD_PARTY_LICENSES.txt" in dialog.licences.toPlainText()


def test_edge_a_viewer_without_a_help_menu_has_no_help_button():
    from core.local_fs import LocalFS
    from ui.markdown_viewer import open_markdown_viewer

    viewer = open_markdown_viewer(LocalFS(), "")
    assert viewer.help_button is None
