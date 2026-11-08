"""Help > Handbook (F1): the user guide inside the app, at the right section.

The user asked for "a help that walks through all functions". The handbook is
docs/USAGE.md (or USAGE_de.md / USAGE_es.md for the interface language) in a
window with a contents tree, find-in-page and a safe view. Covered here:

- **Which file.** The interface language's guide, English when that language
  has none (or its file is missing), a built-in note when no file is there;
  the packaged copy (resources/handbook, a wheel and the bundle) before docs/.
- **Shipping.** A wheel and the bundle carried no docs/ before: pyproject
  maps the package resources.handbook onto docs/ and takes only the handbook
  files, the PyInstaller spec collects the same names - all from
  core.handbook.HANDBOOK_FILES, nothing copied by hand.
- **F1 goes to the section.** Every help topic names a heading that USAGE.md
  has, and the translations' heading at the same place; the file pane, the
  Transfers dock, Connect to Server, the Settings page shown and the Agent
  dock open theirs; an unknown area opens the contents.
- **The window.** Contents, find (with "Not found"), links between sections
  and languages, links to other documents to GitHub, nothing else opened,
  no resource loaded, raw HTML shown as text.
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
import time
import tomllib
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt, QUrl  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from core import handbook as H  # noqa: E402
from tests.bundle_sources import have_bundle_sources  # noqa: E402
from tests.bundle_sources import read as read_build  # noqa: E402

APP = QApplication.instance() or QApplication([])
DOCS = ROOT / "docs"
LANGUAGES = tuple(H.HANDBOOK_FILES)


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while True:
        APP.processEvents()
        if time.time() >= end:
            return
        time.sleep(0.01)


def _text(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def _module_book():
    from ui.handbook import HandbookDialog

    dialog = HandbookDialog(language="en")
    dialog.show()
    pump()
    yield dialog
    dialog.close()
    dialog.deleteLater()


@pytest.fixture
def book(_module_book):
    """One handbook window for the module (rendering the guide takes a
    while), back at the English guide's start for each test."""
    _module_book._show(H.load("en"))
    _module_book.search.clear()
    _module_book.search_hint.clear()
    _module_book.show_contents()
    _module_book.show()
    return _module_book


@pytest.fixture(scope="module")
def _module_window(tmp_path_factory):
    from core import open_limits as OL
    from ui import main_window as MW

    tmp = tmp_path_factory.mktemp("handbook-window")
    patches = [
        mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp / "session.json"),
        mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp / "recents.json"),
        mock.patch.object(OL, "SETTINGS_PATH", tmp / "settings.json"),
    ]
    for patch in patches:
        patch.start()
    win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.resize(1280, 800)
    win.show()
    win.activateWindow()
    pump(0.1)
    try:
        yield win
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        pump()
        for patch in reversed(patches):
            patch.stop()


@pytest.fixture
def window(_module_window):
    """The module's window; what a test opened (the handbook, dialogs) is
    closed again."""
    _module_window.activateWindow()  # F1 is a shortcut of the active window
    pump()
    yield _module_window
    for widget in APP.topLevelWidgets():
        if widget is not _module_window and widget.isVisible():
            widget.close()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


# ---------------------------------------------------------------------------
# Which file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("language", LANGUAGES)
def test_happy_each_language_gets_its_own_guide(language):
    book = H.load(language)
    assert book.language == language
    assert Path(book.source) == DOCS / H.HANDBOOK_FILES[language]
    assert book.text == _text(H.HANDBOOK_FILES[language])


def test_happy_the_interface_language_decides(monkeypatch):
    from core import i18n

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    assert H.load().source.endswith("USAGE_de.md")


def test_sad_a_language_without_a_guide_gets_the_english_one():
    book = H.load("fr")
    assert book.language == "en" and book.source.endswith("USAGE.md")


def test_sad_a_missing_language_variant_falls_back_to_english(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "USAGE.md").write_text("# Using\n\n## Transfers\n\ntext\n")
    book = H.load("de", root=str(tmp_path))
    assert book.language == "en"
    assert book.source == str(tmp_path / "docs" / "USAGE.md")


def test_sad_no_file_at_all_gives_the_built_in_note_with_the_online_guide(tmp_path):
    book = H.load("de", root=str(tmp_path))
    assert book.source == H.BUILT_IN_SOURCE
    assert "github.com/c0decave/axross/blob/" in book.text and "docs/USAGE.md" in book.text


def test_edge_the_packaged_copy_wins_over_a_docs_folder(tmp_path):
    """In an installed tree a docs/ beside the packages is another package's."""
    for folder, text in (("docs", "# Other\n"), (H.PACKAGED_DIR, "# Ours\n")):
        (tmp_path / folder).mkdir(parents=True)
        (tmp_path / folder / "USAGE.md").write_text(text)
    assert H.load("en", root=str(tmp_path)).text == "# Ours\n"
    assert H.handbook_dirs(str(tmp_path))[0].endswith(os.path.join("resources", "handbook"))


def test_edge_an_oversized_or_broken_file_is_skipped(tmp_path):
    from core.guide_text import MAX_GUIDE_BYTES

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "USAGE_de.md").write_bytes(b"\xff\xfe broken")
    (tmp_path / "docs" / "USAGE.md").write_text("x" * (MAX_GUIDE_BYTES + 1))
    assert H.load("de", root=str(tmp_path)).source == H.BUILT_IN_SOURCE


# ---------------------------------------------------------------------------
# Shipping: one copy, docs/, in the wheel and the bundle
# ---------------------------------------------------------------------------


def _manifest_docs() -> list[str]:
    text = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    return [word for line in text.splitlines() if line.startswith("include ")
            for word in line.split()[1:] if word.startswith("docs/")]


def test_happy_pyproject_maps_the_handbook_package_onto_docs():
    setuptools = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "setuptools"]
    assert "resources.handbook" in setuptools["packages"]
    assert setuptools["package-dir"] == {"resources.handbook": "docs"}
    assert setuptools["package-data"]["resources.handbook"] == list(H.HANDBOOK_FILES.values())
    assert not (ROOT / "resources" / "handbook").exists(), "a second copy beside docs/"


def test_happy_the_wheel_takes_only_the_handbook_files_of_docs():
    """include-package-data takes every docs/ file MANIFEST.in lists; the
    exclusions (as setuptools applies them: fnmatch on the path below the
    package's directory) leave exactly the handbook."""
    setuptools = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "setuptools"]
    patterns = [f"docs/{p}" for p in setuptools["exclude-package-data"]["resources.handbook"]]
    listed = _manifest_docs()
    assert {f"docs/{name}" for name in H.HANDBOOK_FILES.values()} <= set(listed)
    kept = [path for path in listed
            if not any(fnmatch.fnmatch(path, pattern) for pattern in patterns)]
    assert sorted(kept) == sorted(f"docs/{name}" for name in H.HANDBOOK_FILES.values())


def test_sad_the_exclusions_would_catch_a_new_document():
    setuptools = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "setuptools"]
    patterns = [f"docs/{p}" for p in setuptools["exclude-package-data"]["resources.handbook"]]
    for path in ("docs/NEW.md", "docs/UPGRADE.md", "docs/x.json", "docs/patterns/P.md"):
        assert any(fnmatch.fnmatch(path, p) for p in patterns), path


@pytest.mark.skipif(not have_bundle_sources(), reason="build/ is not in an sdist")
def test_happy_the_bundle_collects_the_same_names_from_docs():
    spec = read_build("axross.spec")
    assert "from core.handbook import HANDBOOK_FILES" in spec
    assert re.search(r'os\.path\.join\(PROJECT_ROOT, "docs", _name\), "resources/handbook"\)',
                     spec)


def test_edge_every_handbook_file_is_a_tracked_public_document():
    for name in H.HANDBOOK_FILES.values():
        assert (DOCS / name).is_file(), name
        assert f"docs/{name}" in _manifest_docs(), name


# ---------------------------------------------------------------------------
# Sections: every mapped anchor exists, in every language
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("topic", sorted(H.SECTIONS))
def test_happy_every_topic_names_a_heading_of_the_english_guide(topic):
    assert H.SECTIONS[topic] in H.outline(_text("USAGE.md")), topic


@pytest.mark.parametrize("language", [lang for lang in LANGUAGES if lang != "en"])
def test_happy_every_topic_has_its_section_in_each_translation(language):
    book = H.load(language)
    english = H.outline(_text("USAGE.md"))
    own = H.outline(book.text)
    for topic, heading in H.SECTIONS.items():
        found = H.section_for(topic, book)
        assert found is not None, (language, topic)
        assert found == own[english.index(heading)], (language, topic)


def test_edge_a_translated_section_is_the_one_at_the_same_place():
    de = H.load("de")
    assert H.section_for("connections", de) == "Verbindungen"
    assert H.section_for("settings.logging", de) == "Logging"
    assert H.section_for("handbook", de) == "Handbuch und Touren"
    assert H.section_for("handbook", H.load("es")) == "Manual y tours"


def test_happy_the_window_names_only_topics_the_handbook_knows():
    from ui.main_window import MainWindow

    names = set(MainWindow.HELP_TOPICS.values()) | {"panes", "path-bar", "connections"}
    assert names <= set(H.SECTIONS), names - set(H.SECTIONS)


def test_happy_every_settings_page_opens_a_section():
    from ui.settings_dialog import CATEGORY_ORDER

    english = H.load("en")
    for page in CATEGORY_ORDER:
        assert H.section_for(f"settings.{page}", english), page


def test_sad_an_unknown_topic_or_a_vanished_heading_opens_the_contents(book):
    assert H.topic_heading("no-such-area") is None and H.topic_heading(None) is None
    assert H.section_in("A heading nobody wrote", book.handbook.text, None) is None
    book.go_to_heading("Transfers")
    assert book.go_to_topic("no-such-area") is False
    assert book.view.verticalScrollBar().value() == 0
    assert book.contents.currentItem() is None


def test_edge_a_translation_with_another_outline_matches_by_name_only():
    english = "## Transfers\n\n## Settings\n"
    other = "## Settings\n"  # one section short: places do not line up
    assert H.section_in("Settings", other, english) == "Settings"
    assert H.section_in("Transfers", other, english) is None


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------


def test_happy_the_handbook_opens_with_its_contents_and_finds_a_heading(book):
    assert book.source.endswith("USAGE.md")
    tops = [book.contents.topLevelItem(i).text(0)
            for i in range(book.contents.topLevelItemCount())]
    assert tops[:2] == ["At a glance", "Handbook and tours"] and "Settings" in tops
    settings = book.contents.findItems("Settings", Qt.MatchFlag.MatchExactly)[0]
    assert [settings.child(i).text(0) for i in range(settings.childCount())] == ["Logging"]
    book.contents.itemClicked.emit(settings.child(0), 0)
    assert book.current_heading() == "Logging"
    assert book.go_to_heading("Find Files and sift")
    assert book.current_heading() == "Find Files and sift"


def test_happy_find_selects_the_next_match_and_wraps(book):
    book.search.setText("Retry Failed")
    assert book.find_next()
    first = book.view.textCursor().position()
    assert book.view.textCursor().selectedText() == "Retry Failed"
    hits = 1
    while book.find_next() and book.view.textCursor().position() != first:
        hits += 1
        assert hits < 50
    assert book.view.textCursor().position() == first


def test_sad_find_without_a_match_says_not_found(book):
    book.search.setText("no-such-text-anywhere-xyz")
    assert book.find_next() is False
    assert book.search_hint.text() == "Not found"
    book.search.clear()
    assert book.find_next() is False and book.search_hint.text() == ""


def test_happy_links_scroll_switch_language_and_send_documents_to_github(book):
    book.on_link(QUrl("#logging"))
    assert book.current_heading() == "Logging"
    with mock.patch("core.desktop_open.open_url") as opened:
        book.on_link(QUrl("MCP.md#tools"))
        book.on_link(QUrl("../INSTALL.md"))
        book.on_link(QUrl("https://example.org/page"))
    urls = [call.args[0].toString() for call in opened.call_args_list]
    from axross._version import __version__

    assert urls == [
        f"https://github.com/c0decave/axross/blob/v{__version__}/docs/MCP.md#tools",
        f"https://github.com/c0decave/axross/blob/v{__version__}/INSTALL.md",
        "https://example.org/page",
    ]
    book.on_link(QUrl("USAGE_de.md"))
    assert book.source.endswith("USAGE_de.md") and book.handbook.language == "de"
    assert "Verbindungen" in book.section_names()
    book.on_link(QUrl("USAGE.md#transfers"))
    assert book.source.endswith("USAGE.md") and book.current_heading() == "Transfers"


@pytest.mark.parametrize("href", ["file:///etc/passwd", "javascript:alert(1)",
                                  "mailto:a@example.org", "/etc/passwd", "../../../etc/passwd",
                                  "http:///nohost", "ftp://example.org/x"])
def test_sad_other_links_open_nothing(book, href):
    with mock.patch("core.desktop_open.open_url") as opened:
        book.on_link(QUrl(href))
    opened.assert_not_called()
    assert H.classify_link(href)[0] == "none", href


def test_sad_no_resource_is_loaded_and_raw_html_is_text(book):
    book.view.set_guide_markdown(
        "# T\n\n![logo](https://example.org/logo.png)\n\n"
        "<img src='file:///etc/hostname'> <b>bold</b>\n")
    book.view.document().adjustSize()
    pump()
    plain = book.view.toPlainText()
    assert "<b>bold</b>" in plain and "<img" in plain
    assert "https://example.org/logo.png" in book.view.refused_resources
    assert book.view.loadResource(2, QUrl("file:///etc/hostname")) is None


def test_edge_return_in_the_find_field_does_not_close_the_handbook(book):
    book.search.setFocus()
    book.search.setText("Transfers")
    QTest.keyClick(book.search, Qt.Key.Key_Return)
    assert book.isVisible()


# ---------------------------------------------------------------------------
# F1 from the real window
# ---------------------------------------------------------------------------


def _help_entry(win, text: str):
    menu = next(a.menu() for a in win.menuBar().actions() if a.text() == "&Help")
    return next(a for a in menu.actions() if a.text() == text)


def test_happy_help_has_the_handbook_on_f1_and_the_tours(window):
    assert _help_entry(window, "&Handbook").shortcut().toString() == "F1"
    assert _help_entry(window, "&Keyboard Shortcuts").shortcut().toString() == "Ctrl+F1"
    _help_entry(window, "&Handbook").trigger()
    pump()
    assert window._handbook.isVisible()
    _help_entry(window, "T&ours…").trigger()
    pump()
    assert window._tours_dialog.isVisible()


def test_happy_f1_in_a_file_pane_opens_multi_pane_layout(window):
    table = window._active_pane._table
    table.setFocus()
    pump()
    QTest.keyClick(table, Qt.Key.Key_F1)
    pump()
    assert window._handbook.current_heading() == "Multi-pane layout"


def test_happy_f1_in_the_address_bar_opens_path_bar(window):
    edit = window._active_pane.findChild(QWidget, "axPathEdit")
    assert window.show_context_help(edit).current_heading() == "Path bar"


def test_happy_f1_in_the_transfer_dock_opens_transfers(window):
    dock = window._transfer_dock
    inner = dock.findChildren(QWidget)[-1]
    assert window.show_context_help(inner).current_heading() == "Transfers"


def test_happy_f1_in_the_agent_dock_opens_its_section(window):
    window._agent_dock.show()
    pump()
    tab = window._agent_dock.current_tab()
    target = tab.mode_combo if tab is not None else window._agent_dock
    assert window.show_context_help(target).current_heading() == H.SECTIONS["agent"]


def test_happy_f1_in_connect_to_server_opens_connections(window):
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    dialog = ConnectionDialog(ProfileManager(), window)
    dialog.setModal(True)  # as exec() opens it; a non-modal window uses the window's handbook
    dialog.show()
    dialog.activateWindow()
    pump()
    try:
        dialog._profile_name.setFocus()
        pump()
        QTest.keyClick(dialog._profile_name, Qt.Key.Key_F1)
        pump()
        book = dialog._ax_handbook
        assert book is not None and book.parent() is dialog  # usable beside the modal dialog
        assert book.current_heading() == "Connections"
    finally:
        dialog.close()
        dialog.deleteLater()


@pytest.mark.parametrize("page, heading", [("logging", "Logging"), ("updates", "Updates"),
                                           ("agent", H.SECTIONS["agent"]),
                                           ("appearance", "Settings")])
def test_happy_f1_in_settings_opens_the_part_of_the_page_shown(window, page, heading):
    from ui.handbook import help_topic_of, open_handbook_for
    from ui.settings_dialog import SettingsDialog

    dialog = SettingsDialog(window, window=window)
    dialog.show()
    pump()
    try:
        dialog.show_page(page)
        assert help_topic_of(dialog.tree) == f"settings.{page}"
        assert open_handbook_for(dialog, help_topic_of(dialog.tree)).current_heading() == heading
    finally:
        dialog.close()
        dialog.deleteLater()


def test_sad_f1_outside_a_known_area_opens_the_contents(window):
    book = window.show_context_help(QWidget())  # not in the window
    assert book.contents.currentItem() is None
    assert book.view.verticalScrollBar().value() == 0
    toolbar = window.findChild(QWidget, "axMainToolbar")
    assert window.show_context_help(toolbar).contents.currentItem() is None


def test_edge_f1_again_raises_the_one_handbook_at_the_new_section(window):
    first = window.show_handbook("transfers")
    second = window.show_handbook("settings.logging")
    assert first is second and second.current_heading() == "Logging"
    second.close()
    pump()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert window._handbook is None


def test_edge_the_handbook_follows_a_german_interface(window, monkeypatch):
    from core import i18n

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    book = window.show_handbook("connections")
    assert book.source.endswith("USAGE_de.md")
    assert book.current_heading() == "Verbindungen"
